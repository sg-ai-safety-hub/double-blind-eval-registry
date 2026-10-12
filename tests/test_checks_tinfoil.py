"""Checks 2-4. The SDK boundary is replaced, so nothing here needs the network;
test_live.py runs the same path against the live captures."""

import base64
import copy
import gzip
import json
from pathlib import Path

import pytest
import requests
import urllib3
from sigstore.errors import NetworkError, TUFError
from tinfoil.attestation import Document, Measurement, PredicateType, Verification
from tuf.api.exceptions import DownloadError

from registry import checks_tinfoil, spec
from registry.checks_tinfoil import check_attestation
from registry.config import TrustedCode
from registry.model import Check, Enclave, Status, VerificationUnavailable
from registry.refcache import NoReleaseAsset, Reference
from registry.syft_receipt import Attestation

OPENMINED = Path(__file__).resolve().parents[1] / "fixtures/openmined/receipt.dsse.json"
HARDWARE_CHECKS = ["key_binding", "hardware", "measurement"]
REPO = "OpenMined/syft-enclave-tinfoil"
TAG = "v0.1.28"
TRUSTED = [TrustedCode(repo=REPO)]
REPORT = b"a raw SEV-SNP report"
# OpenMined's key binding, and the report_data[0:32] that Tinfoil's code put in its hardware report: a test vector.
KEY_BINDING = json.loads(base64.b64decode(json.loads(OPENMINED.read_bytes())["payload"]))[
    "predicate"]["execution"]["attestation"]["keyBinding"]
REPORT_DATA = KEY_BINDING["challenge"]["report_data"][:64]
MEASUREMENT = "6d" * 48
DIGEST = "fe" * 32
REFERENCE = Reference(digest=DIGEST, hash_file=DIGEST.encode() + b"\n", bundle=b"{}", cached=False)
DEPENDENT = "needs check 3, which failed"


def attestation(report: str = base64.b64encode(REPORT).decode(), type_: str = "sev-snp", repo: str = REPO,
                tag: str = TAG, **key_binding) -> Attestation:
    """OpenMined's attestation with `report` as its hardware report, and any keyBinding fields replaced."""
    binding = {**copy.deepcopy(KEY_BINDING), **key_binding}
    binding["cpu_evidence"]["report_base64"] = report
    return Attestation.model_validate({
        "type": type_,
        "referenceValue": {"source": spec.REFERENCE_SOURCE, "repo": spec.REFERENCE_REPO_PREFIX + repo, "tag": tag},
        "keyBinding": binding,
    })


def verification(report_data: str = REPORT_DATA, measurement: str = MEASUREMENT) -> Verification:
    """What Document.verify returns for a report whose report_data[0:32] is `report_data`."""
    return Verification(measurement=Measurement(type=PredicateType.SEV_GUEST_V2, registers=[measurement]),
                        public_key_fp=report_data)


def signed_reference(measurement: str = MEASUREMENT) -> Measurement:
    """What verify_attestation returns for a release whose SEV-SNP measurement is `measurement`."""
    return Measurement(type=PredicateType.SNP_TDX_MULTIPLATFORM_v1, registers=[measurement, "11" * 48, "22" * 48])


class FakeRefCache:
    def __init__(self, reference=REFERENCE, error: Exception | None = None):
        self.reference, self.error, self.gets, self.puts = reference, error, [], []

    def get(self, repo, tag):
        self.gets.append((repo, tag))
        if self.error:
            raise self.error
        return self.reference

    def put(self, repo, tag, reference):
        self.puts.append((repo, tag, reference))


@pytest.fixture
def sdk(monkeypatch):
    """Replace Document.verify and verify_attestation; record what they were called with."""
    calls = {"documents": [], "attestations": [], "verification": verification(), "reference": signed_reference()}

    def verify(document, vcek_der=None):
        calls["documents"].append(document)
        if isinstance(calls["verification"], Exception):
            raise calls["verification"]
        return calls["verification"]

    def verify_attestation(bundle, digest, repo, expected_release_tag=None):
        calls["attestations"].append((bundle, digest, repo, expected_release_tag))
        if isinstance(calls["reference"], Exception):
            raise calls["reference"]
        return calls["reference"]

    monkeypatch.setattr(Document, "verify", verify)
    monkeypatch.setattr(checks_tinfoil, "verify_attestation", verify_attestation)
    return calls


def run(att: Attestation | None = None, cache: FakeRefCache | None = None):
    return check_attestation(att or attestation(), TRUSTED, cache or FakeRefCache())


def statuses(checks) -> list:
    return [(c.id, c.status) for c in checks]


# --- PENDING and the attestation type ------------------------------------------

@pytest.mark.parametrize("prefix", spec.SENTINEL_PREFIXES)
def test_a_sentinel_report_leaves_checks_2_to_4_pending(prefix, sdk):
    checks, enclave = run(attestation(report=prefix + "anything"))
    assert [(c.id, c.status, c.detail) for c in checks] == [
        (check_id, Status.PENDING, "no hardware report in this receipt") for check_id in HARDWARE_CHECKS]
    assert enclave is None
    assert sdk["documents"] == []


@pytest.mark.parametrize("report", ["AAAA" + spec.SIMULATED_PREFIX, spec.SIMULATED_PREFIX.lower() + "x"],
                         ids=["not-a-prefix", "lowercase"])
def test_only_a_sentinel_prefix_counts_as_no_report(report, sdk):
    checks, _ = run(attestation(report=report))
    assert statuses(checks) == [("key_binding", Status.FAIL), ("hardware", Status.FAIL), ("measurement", Status.FAIL)]


@pytest.mark.parametrize("report", ["AAAA", spec.SIMULATED_PREFIX + "anything"], ids=["real", "sentinel"])
def test_any_type_but_sev_snp_fails_check_3_even_without_a_report(report, sdk):
    checks, enclave = run(attestation(report=report, type_="tdx"))
    assert [(c.id, c.status, c.detail) for c in checks] == [
        ("key_binding", Status.FAIL, DEPENDENT),
        ("hardware", Status.FAIL, "SEV-SNP only in this MVP"),
        ("measurement", Status.FAIL, DEPENDENT),
    ]
    assert enclave is None
    assert sdk["documents"] == []


# --- check 3: hardware -----------------------------------------------------------

def test_the_sdk_gets_the_raw_report_gzipped(sdk):
    # The report is base64 of the raw report, but Document wants base64(gzip(report)).
    run()
    document, = sdk["documents"]
    assert document.format is PredicateType.SEV_GUEST_V2
    assert gzip.decompress(base64.b64decode(document.body)) == REPORT


def test_a_verified_report_passes_check_3(sdk):
    checks, _ = run()
    assert checks[1] == Check(
        "hardware", Status.PASS, "the report verifies against AMD's certificate chain and the SDK's TCB policy")


@pytest.mark.parametrize("report", ["not base64!", base64.b64encode(REPORT).decode() + "!"])
def test_a_report_that_is_not_standard_base64_fails_check_3(report, sdk):
    checks, enclave = run(attestation(report=report))
    assert statuses(checks) == [("key_binding", Status.FAIL), ("hardware", Status.FAIL), ("measurement", Status.FAIL)]
    assert enclave is None
    assert sdk["documents"] == []


def test_a_report_the_sdk_rejects_fails_check_3_and_so_checks_2_and_4(sdk):
    sdk["verification"] = ValueError("SEV attestation verification failed: bad signature")
    cache = FakeRefCache()
    checks, enclave = run(cache=cache)
    assert [(c.id, c.status, c.detail) for c in checks] == [
        ("key_binding", Status.FAIL, DEPENDENT),
        ("hardware", Status.FAIL, "the hardware report does not verify: "
                                  "SEV attestation verification failed: bad signature"),
        ("measurement", Status.FAIL, DEPENDENT),
    ]
    assert enclave is None
    assert cache.gets == []  # no GitHub traffic for a report that didn't verify


# --- check 2: key binding ---------------------------------------------------------

def test_key_binding_passes_when_report_data_commits_to_this_key_binding(sdk):
    # Tinfoil's report-data/v1 over OpenMined's nonce, crypto_material and device_evidence.
    checks, _ = run()
    assert checks[0] == Check("key_binding", Status.PASS,
                              "the attested report_data commits to crypto_material, and so to the signing key")


def reencoded(field: str) -> str:
    """OpenMined's section, with the same JSON content but other bytes."""
    return base64.b64encode(base64.b64decode(KEY_BINDING[field]) + b" ").decode()


@pytest.mark.parametrize("changes", [
    {"crypto_material": reencoded("crypto_material")},
    {"device_evidence": reencoded("device_evidence")},
    {"challenge": {**KEY_BINDING["challenge"], "nonce": "00" * 32}},
], ids=["crypto-material", "device-evidence", "nonce"])
def test_key_binding_fails_when_any_input_to_report_data_differs(sdk, changes):
    # The bytes count, not just the JSON they decode to: a hardware report commits to exact bytes.
    checks, _ = run(attestation(**changes))
    assert (checks[0].status, checks[0].detail) == (
        Status.FAIL, "the hardware report does not commit to this receipt's crypto_material")


def test_a_stapled_report_fails_check_2_but_passes_checks_3_and_4(sdk):
    sdk["verification"] = verification(report_data="cd" * 32)  # a real report, bound to some other key binding
    checks, _ = run()
    assert checks[0].status is Status.FAIL
    assert checks[1].status is checks[2].status is Status.PASS


# --- check 4: measurement --------------------------------------------------------------

def test_a_measurement_matching_the_signed_reference_passes_and_is_cached(sdk):
    cache = FakeRefCache()
    checks, enclave = run(cache=cache)
    assert checks[2].status is Status.PASS
    assert sdk["attestations"] == [(REFERENCE.bundle, DIGEST, REPO, TAG)]  # the tag is the expected release tag
    assert cache.gets == [(REPO, TAG)]
    assert cache.puts == [(REPO, TAG, REFERENCE)]
    assert enclave == Enclave(measurement=MEASUREMENT, repo=REPO, release_tag=TAG, release_digest=DIGEST)


def test_a_repo_not_in_trusted_code_fails_without_fetching(sdk):
    cache = FakeRefCache()
    checks, enclave = run(attestation(repo="tinfoilsh/confidential-model-router"), cache)
    assert (checks[2].status, checks[2].detail) == (Status.FAIL, "the receipt's repo is not in this registry's trusted_code")
    assert enclave is None
    assert cache.gets == []


@pytest.mark.parametrize("problem, detail", [
    ("no-asset", "no release asset for this tag"),
    ("bad-hash", "the release's reference does not verify: tinfoil.hash is not one sha256 digest"),
    ("bad-bundle", "the release's reference does not verify: Attestation processing failed: digest mismatch"),
    ("other-measurement", "the attested measurement is not the release's signed reference"),
])
def test_check_4_fails_and_caches_nothing(sdk, problem, detail):
    cache = FakeRefCache()
    if problem == "no-asset":
        cache.error = NoReleaseAsset(f"{REPO}@{TAG}")
    elif problem == "bad-hash":
        cache.error = ValueError("tinfoil.hash is not one sha256 digest")
    elif problem == "bad-bundle":
        sdk["reference"] = ValueError("Attestation processing failed: digest mismatch")
    else:
        sdk["reference"] = signed_reference(measurement="99" * 48)
    checks, enclave = run(cache=cache)
    assert (checks[2].status, checks[2].detail) == (Status.FAIL, detail)
    assert enclave is None
    assert cache.puts == []


# --- network errors: 503, not a verdict ------------------------------------------------------------

def chained(outer: Exception, *inner: Exception, via: str = "__cause__") -> Exception:
    """outer, raised from inner[0], raised from inner[1], ... as the SDK wraps errors."""
    error = outer
    for cause in inner:
        setattr(error, via, cause)
        error = cause
    return outer


NETWORK = {
    "requests": requests.ConnectionError("connection refused"),
    "urllib3": urllib3.exceptions.ProtocolError("connection aborted"),
    "sigstore-network": NetworkError(),
    "tuf": TUFError("Failed to refresh TUF metadata"),
    "tuf-download": DownloadError("Failed to download 16.root.json"),
    "connection": ConnectionError("reset"),
    "timeout": TimeoutError("timed out"),
}


@pytest.mark.parametrize("network", NETWORK.values(), ids=NETWORK.keys())
@pytest.mark.parametrize("step", ["hardware", "refcache", "reference"])
def test_a_network_error_anywhere_in_the_chain_is_verification_unavailable(sdk, step, network):
    error = chained(ValueError("Attestation processing failed"), RuntimeError("wrapped"), network)
    cache = FakeRefCache()
    if step == "hardware":
        sdk["verification"] = error
    elif step == "refcache":
        cache.error = network  # refcache's own fetch raises it unwrapped
    else:
        sdk["reference"] = error
    with pytest.raises(VerificationUnavailable):
        run(cache=cache)
    assert cache.puts == []


def test_the_chain_is_followed_through_context_as_well_as_cause(sdk):
    sdk["verification"] = chained(ValueError("while handling"), TimeoutError("timed out"), via="__context__")
    with pytest.raises(VerificationUnavailable):
        run()


def test_a_chain_without_a_network_error_is_a_fail_not_a_503(sdk):
    sdk["verification"] = chained(ValueError("SEV attestation verification failed"), KeyError("x"), OSError("disk"))
    checks, _ = run()
    assert checks[1].status is Status.FAIL
