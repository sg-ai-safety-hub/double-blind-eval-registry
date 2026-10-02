#!/usr/bin/env python3
"""Capture live SEV-SNP reports from Tinfoil for the checks 2-4 fixtures. Needs the network.

    uv run python scripts/capture_tinfoil_reports.py

A dev tool that only produces fixtures: the registry never uses Tinfoil's bundle service.
From each bundle it keeps only the raw attestation report, as base64, in
fixtures/tinfoil/<name>.quote, plus a <name>.meta.json sidecar with the repo, the release tag
and the capture time. The tag is the repo's latest release, kept only if its digest is the
bundle's digest; otherwise the capture stops.

An existing capture is never overwritten.
"""

import base64
import gzip
import json
import sys
from datetime import UTC, datetime
from pathlib import Path

from tinfoil.attestation import PredicateType, fetch_bundle_from
from tinfoil.client import DEFAULT_CONFIG_REPO
from tinfoil.github import fetch_latest_release

from registry.evalresult import TIMESTAMP_FORMAT

ROOT = Path(__file__).resolve().parents[1]
TINFOIL = ROOT / "fixtures/tinfoil"
BUNDLE_SERVICE = "https://atc.tinfoil.sh"
# name -> (enclave host, repo). The router's is the bundle service's default bundle, fetched with a GET.
ENCLAVES = {
    "dbe": ("dbe.tinfoil.containers.tinfoil.dev", "tinfoilsh/double-blind-eval"),
    "router": ("", DEFAULT_CONFIG_REPO),
}


class CaptureError(Exception):
    """The capture can't be trusted as a fixture: stop, and find out why."""


def capture(name: str, enclave: str, repo: str, folder: Path = TINFOIL) -> bool:
    """Capture one enclave's report into `folder`. False if a capture is already there."""
    quote_path, meta_path = folder / f"{name}.quote", folder / f"{name}.meta.json"
    if quote_path.exists() or meta_path.exists():
        print(f"kept {name}: an existing capture is never overwritten")
        return False

    bundle = fetch_bundle_from(BUNDLE_SERVICE, enclave=enclave, repo=repo) if enclave else fetch_bundle_from(BUNDLE_SERVICE)
    report = bundle.enclave_attestation_report
    if report.format is not PredicateType.SEV_GUEST_V2:
        raise CaptureError(f"{name}: the report is {report.format.value}, not SEV-SNP")
    release = fetch_latest_release(repo)
    if release.digest != bundle.digest:
        raise CaptureError(f"{name}: {repo}'s latest release {release.tag} has digest {release.digest}, but the "
                           f"bundle's is {bundle.digest}: stop, and find out why")

    raw = gzip.decompress(base64.b64decode(report.body))  # the bundle carries base64(gzip(report))
    folder.mkdir(parents=True, exist_ok=True)
    quote_path.write_text(base64.b64encode(raw).decode())
    meta = {"repo": repo, "tag": release.tag, "capturedAt": datetime.now(UTC).strftime(TIMESTAMP_FORMAT)}
    meta_path.write_text(json.dumps(meta, indent=2) + "\n")
    print(f"captured {name}: {bundle.domain}, {repo} {release.tag}, report {len(raw)} bytes")
    return True


def main() -> int:
    try:
        for name, (enclave, repo) in ENCLAVES.items():
            capture(name, enclave, repo)
    except CaptureError as e:
        print(e, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
