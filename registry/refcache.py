"""A release's digest and Sigstore reference bundle, per (repo, tag).

    <root>/<owner>/<name>/<url-encoded tag>/tinfoil.hash               exactly as fetched
                                          /attestation.sigstore.json  exactly as fetched

Nothing fetched proves anything on its own: check 4's verify_attestation checks the bundle
is signed by the repo's release workflow at refs/tags/<tag> and that its subject is the digest,
every time, cached or not. A tampered response can only make check 4 FAIL. The cache is
written only after check 4 PASSes, so a bad fetch can't poison it, and rebuilds don't need GitHub.
"""

import logging
import re
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import quote

import requests
from tinfoil.github import GITHUB_PROXY, fetch_attestation_bundle

from registry import spec
from registry.store import write_atomic

log = logging.getLogger(__name__)

HASH_FILE = "tinfoil.hash"
BUNDLE_FILE = "attestation.sigstore.json"
TIMEOUT_SECONDS = 15  # as the SDK's own GitHub fetches


class NoReleaseAsset(Exception):
    """The release has no tinfoil.hash for this tag (HTTP 404): check 4 FAILs."""


@dataclass(frozen=True)
class Reference:
    digest: str  # the release digest, from tinfoil.hash
    hash_file: bytes  # tinfoil.hash, exactly as fetched
    bundle: bytes  # the Sigstore reference bundle, exactly as fetched
    cached: bool


class RefCache:
    def __init__(self, root: Path):
        self.root = root

    def get(self, repo: str, tag: str) -> Reference:
        """The cached reference for (repo, tag), or a fresh fetch, which is not cached until put()."""
        folder = self._folder(repo, tag)
        if (folder / HASH_FILE).is_file() and (folder / BUNDLE_FILE).is_file():
            hash_file = (folder / HASH_FILE).read_bytes()
            log.debug("refcache hit %s@%s", repo, tag)
            return Reference(_digest(hash_file), hash_file, (folder / BUNDLE_FILE).read_bytes(), cached=True)

        # The SDK resolves only the latest release; this is the one fetch the registry writes itself.
        url = f"{GITHUB_PROXY}/{repo}/releases/download/{quote(tag, safe='')}/{HASH_FILE}"
        response = requests.get(url, timeout=TIMEOUT_SECONDS)
        if response.status_code == 404:
            raise NoReleaseAsset(f"{repo}@{tag}")
        response.raise_for_status()  # any other failure is a network error: 503
        hash_file = response.content
        digest = _digest(hash_file)
        bundle = fetch_attestation_bundle(repo, digest)
        log.debug("refcache fetched %s@%s: digest %s, bundle %d bytes", repo, tag, digest, len(bundle))
        return Reference(digest, hash_file, bundle, cached=False)

    def put(self, repo: str, tag: str, reference: Reference) -> None:
        """Cache a reference. Call only after check 4 PASSed with it."""
        if reference.cached:
            return
        folder = self._folder(repo, tag)
        folder.mkdir(parents=True, exist_ok=True)
        write_atomic(folder / HASH_FILE, reference.hash_file)
        write_atomic(folder / BUNDLE_FILE, reference.bundle)
        log.debug("refcache stored %s@%s", repo, tag)

    def _folder(self, repo: str, tag: str) -> Path:
        # repo is from trusted_code, so owner/name is safe. The tag is the receipt's: url-encoding
        # removes every "/", but leaves "." and "..", which would climb out of the tag's folder.
        segment = quote(tag, safe="")
        if segment in (".", ".."):
            raise ValueError(f"not a release tag: {tag!r}")
        owner, name = repo.split("/")
        return self.root / owner / name / segment


def _digest(hash_file: bytes) -> str:
    # The release asset is the digest and a newline; strip whitespace as the SDK does for latest releases.
    digest = hash_file.decode("ascii", errors="replace").strip()
    if not re.fullmatch(spec.HEX64, digest):
        raise ValueError("tinfoil.hash is not one sha256 digest")
    return digest
