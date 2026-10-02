"""The per-(repo, tag) reference cache. The fetches are replaced, so nothing here needs the network."""

import pytest
import requests

from registry import refcache as refcache_module
from registry.refcache import NoReleaseAsset, RefCache, Reference

REPO = "tinfoilsh/double-blind-eval"
TAG = "v0.0.4"
DIGEST = "fe" * 32
HASH_FILE = DIGEST.encode() + b"\n"  # the live release asset ends with a newline
BUNDLE = b'{"mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json"}'


class FakeResponse:
    def __init__(self, status_code: int, content: bytes = b""):
        self.status_code, self.content = status_code, content

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.HTTPError(f"{self.status_code}")


@pytest.fixture
def fetches(monkeypatch):
    """Record every fetch; serve HASH_FILE and BUNDLE unless a test changes `served`."""
    log = {"hash": [], "bundle": [], "served": FakeResponse(200, HASH_FILE)}

    def get(url, timeout):
        log["hash"].append(url)
        return log["served"]

    def bundle(repo, digest):
        log["bundle"].append((repo, digest))
        return BUNDLE

    monkeypatch.setattr(refcache_module.requests, "get", get)
    monkeypatch.setattr(refcache_module, "fetch_attestation_bundle", bundle)
    return log


@pytest.fixture
def cache(tmp_path):
    return RefCache(tmp_path / "refcache")


def test_a_miss_fetches_the_tag_hash_then_the_bundle_for_its_digest(cache, fetches):
    reference = cache.get(REPO, TAG)
    assert reference == Reference(digest=DIGEST, hash_file=HASH_FILE, bundle=BUNDLE, cached=False)
    assert fetches["hash"] == [f"https://github-proxy.tinfoil.sh/{REPO}/releases/download/{TAG}/tinfoil.hash"]
    assert fetches["bundle"] == [(REPO, DIGEST)]


def test_get_alone_writes_nothing(cache, fetches):
    cache.get(REPO, TAG)
    assert not cache.root.exists()


def test_after_put_the_same_repo_and_tag_make_no_request(cache, fetches):
    cache.put(REPO, TAG, cache.get(REPO, TAG))
    again = cache.get(REPO, TAG)
    assert again == Reference(digest=DIGEST, hash_file=HASH_FILE, bundle=BUNDLE, cached=True)
    assert len(fetches["hash"]) == len(fetches["bundle"]) == 1


def test_the_cache_keeps_the_bytes_exactly_as_fetched(cache, fetches, tmp_path):
    cache.put(REPO, TAG, cache.get(REPO, TAG))
    folder = tmp_path / "refcache" / "tinfoilsh" / "double-blind-eval" / TAG
    assert (folder / "tinfoil.hash").read_bytes() == HASH_FILE
    assert (folder / "attestation.sigstore.json").read_bytes() == BUNDLE


def test_another_tag_is_another_entry(cache, fetches):
    cache.put(REPO, TAG, cache.get(REPO, TAG))
    assert cache.get(REPO, "v0.0.5").cached is False


def test_a_404_means_the_tag_has_no_release_asset(cache, fetches):
    fetches["served"] = FakeResponse(404)
    with pytest.raises(NoReleaseAsset):
        cache.get(REPO, TAG)
    assert fetches["bundle"] == []


def test_other_http_errors_propagate_as_request_errors(cache, fetches):
    # A RequestException is a network error, so check 4 turns it into a 503.
    fetches["served"] = FakeResponse(502)
    with pytest.raises(requests.RequestException):
        cache.get(REPO, TAG)


@pytest.mark.parametrize("body", [b"", b"not a digest\n", DIGEST.upper().encode(), (DIGEST + "00").encode()])
def test_a_hash_file_that_is_not_one_sha256_digest_is_refused(cache, fetches, body):
    fetches["served"] = FakeResponse(200, body)
    with pytest.raises(ValueError, match="tinfoil.hash"):
        cache.get(REPO, TAG)
    assert fetches["bundle"] == []


@pytest.mark.parametrize("tag, segment", [("release/v1", "release%2Fv1"), ("v1?x=1", "v1%3Fx%3D1")])
def test_the_tag_is_url_encoded_in_the_url_and_the_folder(cache, fetches, tmp_path, tag, segment):
    cache.put(REPO, tag, cache.get(REPO, tag))
    assert fetches["hash"][0].endswith(f"/releases/download/{segment}/tinfoil.hash")
    assert (tmp_path / "refcache" / "tinfoilsh" / "double-blind-eval" / segment / "tinfoil.hash").exists()


@pytest.mark.parametrize("tag", [".", ".."])
def test_a_dot_tag_is_refused_before_any_request(cache, fetches, tag):
    # URL-encoding leaves dots alone, so these would climb out of the tag's folder.
    with pytest.raises(ValueError, match="not a release tag"):
        cache.get(REPO, tag)
    assert fetches["hash"] == []
