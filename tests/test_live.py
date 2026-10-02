"""Checks 2-4 on the live captures, through the real SDK. Needs the network: AMD's VCEK
via Tinfoil's proxy, Sigstore's TUF root and GitHub. The fixture-driven tests in test_ingest.py and
test_api.py cover every live fixture's verdict; these cover the refcache and the enclave facts."""

import base64
import json

import pytest
import requests
from fixture_data import ROOT, record
from tinfoil.attestation.abi_sev import Report
from tinfoil.github import GITHUB_PROXY

from registry import refcache as refcache_module
from registry.config import Policy, TrustedCode
from registry.envelope import parse_receipt
from registry.evalresult import parse_statement
from registry.ingest import verify
from registry.model import Status
from registry.refcache import RefCache

pytestmark = pytest.mark.network

DBE = json.loads((ROOT / "fixtures/tinfoil/dbe.meta.json").read_text())
OLDER_TAG = "v0.0.3"  # an earlier DBE release, so a real but wrong tinfoil.hash
POLICY = Policy(trusted_code=[TrustedCode(repo=DBE["repo"])], benchmark_owners=[])


@pytest.fixture
def refcache(tmp_path):
    return RefCache(tmp_path / "refcache")


def run(name: str, refcache: RefCache):
    receipt = parse_receipt(record(name))
    return verify(receipt, parse_statement(receipt.statement), POLICY, refcache)


def statuses(result) -> dict:
    return {c.id: c.status for c in result.checks}


def test_stapled_b_passes_checks_3_and_4_and_yields_the_verified_enclave_facts(refcache):
    result = run("stapled_B", refcache)
    assert statuses(result)["key_binding"] is Status.FAIL  # key A isn't the key the enclave's report binds
    assert statuses(result)["hardware"] is statuses(result)["measurement"] is Status.PASS
    enclave = result.enclave
    report = Report(base64.b64decode((ROOT / "fixtures/tinfoil/dbe.quote").read_text()))
    assert (enclave.type, enclave.repo, enclave.release_tag) == ("AMD SEV-SNP", DBE["repo"], DBE["tag"])
    assert enclave.measurement == report.measurement.hex()


def test_after_check_4_passes_the_reference_is_cached_and_reused_without_github(refcache, monkeypatch):
    run("stapled_B", refcache)
    folder = refcache.root / DBE["repo"] / DBE["tag"]
    assert sorted(p.name for p in folder.iterdir()) == ["attestation.sigstore.json", "tinfoil.hash"]

    def no_github(*args, **kwargs):
        raise AssertionError("a cached (repo, tag) must not be fetched again")
    monkeypatch.setattr(refcache_module.requests, "get", no_github)
    monkeypatch.setattr(refcache_module, "fetch_attestation_bundle", no_github)
    assert statuses(run("stapled_B", refcache))["measurement"] is Status.PASS


@pytest.mark.parametrize("name", ["C12_repo_mismatch", "C13_tag_missing"])
def test_a_failed_check_4_caches_nothing(refcache, name):
    assert statuses(run(name, refcache))["measurement"] is Status.FAIL
    assert not refcache.root.exists()


def test_a_wrong_tinfoil_hash_from_the_proxy_fails_check_4(refcache, monkeypatch):
    # The proxy serves an earlier release's (real) digest for the receipt's tag: that bundle was
    # signed from refs/tags/v0.0.3, so verify_attestation refuses it for the receipt's tag.
    older = requests.get(f"{GITHUB_PROXY}/{DBE['repo']}/releases/download/{OLDER_TAG}/tinfoil.hash", timeout=15)
    older.raise_for_status()
    real_get = refcache_module.requests.get
    monkeypatch.setattr(refcache_module.requests, "get",
                        lambda url, timeout: older if url.endswith(f"/{DBE['tag']}/tinfoil.hash") else real_get(url, timeout=timeout))
    result = run("stapled_B", refcache)
    check = next(c for c in result.checks if c.id == "measurement")
    assert check.status is Status.FAIL
    assert check.detail.startswith("the release's reference does not verify")
    assert result.enclave is None
    assert not refcache.root.exists()
