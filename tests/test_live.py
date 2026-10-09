"""OpenMined's receipt and the live captures, through the real SDK with nothing replaced. Needs the network:
AMD's VCEK via Tinfoil's proxy, Sigstore's TUF root, GitHub and Rekor. The fixture-driven tests in test_ingest.py
and test_api.py cover every live fixture's verdict; these cover the refcache and the enclave facts."""

import base64
import json

import pytest
import requests
from fixture_data import record
from tinfoil.attestation.abi_sev import Report
from tinfoil.github import GITHUB_PROXY

from registry import refcache as refcache_module
from registry.config import BenchmarkOwner, Policy, TrustedCode
from registry.envelope import parse_receipt
from registry.ingest import verify
from registry import spec
from registry.model import CHECK_IDS, Publication, Status
from registry.refcache import RefCache
from registry.syft_receipt import parse_statement

pytestmark = pytest.mark.network

RELEASE = {"repo": "OpenMined/syft-enclave-tinfoil", "tag": "v0.1.28"}  # the release OpenMined's report measures
OLDER_TAG = "v0.1.27"  # an earlier release of the same repo, so a real but wrong tinfoil.hash
POLICY = Policy(trusted_code=[TrustedCode(repo=RELEASE["repo"])],
                benchmark_owners=[BenchmarkOwner(email="benchmark_owner@openmined.org", display="OpenMined")])


@pytest.fixture
def refcache(tmp_path):
    return RefCache(tmp_path / "refcache")


def run(name: str, refcache: RefCache):
    receipt = parse_receipt(record(name))
    return verify(receipt, parse_statement(receipt.statement), POLICY, refcache)


def statuses(result) -> dict:
    return {c.id: c.status for c in result.checks}


def test_openmined_s_receipt_passes_every_check_and_yields_the_verified_enclave_facts(refcache):
    result = run("om_receipt", refcache)
    assert statuses(result) == {check_id: Status.PASS for check_id in CHECK_IDS}
    enclave = result.enclave
    key_binding = json.loads(base64.b64decode(json.loads(record("om_receipt"))["payload"]))[
        "predicate"]["execution"]["attestation"]["keyBinding"]
    report = Report(base64.b64decode(key_binding["cpu_evidence"]["report_base64"]))
    assert (enclave.type, enclave.repo, enclave.release_tag) == ("AMD SEV-SNP", RELEASE["repo"], RELEASE["tag"])
    assert enclave.measurement == report.measurement.hex()


def test_openmined_s_receipt_is_found_on_the_real_rekor(refcache):
    # As captured in fixtures/rekor: Rekor's log is append-only, so the entry stays where it is.
    assert run("om_receipt", refcache).publication == Publication(
        uuid="108e9186e8c5677a90985c71d8a25a4de23d6f7e17e8d0cb40089161de9a6ed3cc14072c0d1a5a6f",
        log_index=3129204433, integrated_time=1791368875, url=spec.REKOR_SEARCH_LINK.format(3129204433))


def test_a_receipt_with_a_real_report_that_nobody_logged_fails_check_7(refcache):
    result = run("stapled_B", refcache)
    assert (statuses(result)["publication"], result.publication) == (Status.FAIL, None)


def test_stapled_b_passes_checks_3_and_4_but_not_2(refcache):
    result = run("stapled_B", refcache)
    assert statuses(result)["key_binding"] is Status.FAIL  # the report commits to OpenMined's key, not B's
    assert statuses(result)["hardware"] is statuses(result)["measurement"] is Status.PASS


def test_after_check_4_passes_the_reference_is_cached_and_reused_without_github(refcache, monkeypatch):
    run("om_receipt", refcache)
    folder = refcache.root / RELEASE["repo"] / RELEASE["tag"]
    assert sorted(p.name for p in folder.iterdir()) == ["attestation.sigstore.json", "tinfoil.hash"]

    def no_github(*args, **kwargs):
        raise AssertionError("a cached (repo, tag) must not be fetched again")
    monkeypatch.setattr(refcache_module.requests, "get", no_github)
    monkeypatch.setattr(refcache_module, "fetch_attestation_bundle", no_github)
    assert statuses(run("om_receipt", refcache))["measurement"] is Status.PASS


@pytest.mark.parametrize("name", ["C12_repo_mismatch", "C13_tag_missing"])
def test_a_failed_check_4_caches_nothing(refcache, name):
    assert statuses(run(name, refcache))["measurement"] is Status.FAIL
    assert not refcache.root.exists()


def test_a_wrong_tinfoil_hash_from_the_proxy_fails_check_4(refcache, monkeypatch):
    # The proxy serves an earlier release's (real) digest for the receipt's tag: that bundle was
    # signed from refs/tags/v0.1.27, so verify_attestation refuses it for the receipt's tag.
    older = requests.get(f"{GITHUB_PROXY}/{RELEASE['repo']}/releases/download/{OLDER_TAG}/tinfoil.hash", timeout=15)
    older.raise_for_status()
    real_get = refcache_module.requests.get
    monkeypatch.setattr(refcache_module.requests, "get",
                        lambda url, timeout: older if url.endswith(f"/{RELEASE['tag']}/tinfoil.hash") else real_get(url, timeout=timeout))
    result = run("om_receipt", refcache)
    check = next(c for c in result.checks if c.id == "measurement")
    assert check.status is Status.FAIL
    assert check.detail.startswith("the release's reference does not verify")
    assert result.enclave is None
    assert not refcache.root.exists()
