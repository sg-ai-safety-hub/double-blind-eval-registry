"""The verified path, end to end through the API: OpenMined's receipt, whose checks all PASS, is listed
as verified.

Offline, so the SDK boundary is replaced. Document.verify answers with what the receipt's real hardware
report says, read by the SDK's own report parser, without checking AMD's signature over it.
verify_attestation and RefCache.get answer as OpenMined's release would. Checks 1, 2, 5 and 6 run for
real. The network tests run the same receipt with nothing replaced."""

import base64
import io
from contextlib import contextmanager
from pathlib import Path
from unittest import mock

import pytest
from fixture_data import EXPECTED, ROOT, record
from tinfoil.attestation import Document, Measurement, PredicateType, Verification
from tinfoil.attestation.abi_sev import Report

from registry import checks_tinfoil
from registry.app import create_app
from registry.envelope import parse_receipt
from registry.index import MODEL_ROLE
from registry.model import CHECK_IDS
from registry.refcache import RefCache, Reference
from registry.syft_receipt import parse_statement

OPENMINED = ROOT / "fixtures/openmined/receipt.dsse.json"
EMAIL = "benchmark_owner@openmined.org"
DISPLAY = "Verified-path owner"
# tinfoil.hash of OpenMined/syft-enclave-tinfoil v0.1.28, the release the receipt's report measures.
RELEASE_DIGEST = "747df14f65121b5d8042bd6be493a269bfbf5471e8b5d704a811aa1e29953be2"
ALL_PASS = {check_id: "PASS" for check_id in CHECK_IDS}


@contextmanager
def verified_hardware():
    """Make checks 3 and 4 PASS for OpenMined's report without the network, as the SDK would answer."""
    statement = parse_statement(parse_receipt(OPENMINED.read_bytes()).statement)
    report = Report(base64.b64decode(statement.predicate.execution.attestation.keyBinding.cpu_evidence.report_base64))
    measurement = Measurement(type=PredicateType.SEV_GUEST_V2, registers=[report.measurement.hex()])
    verification = Verification(measurement=measurement, public_key_fp=report.report_data[:32].hex())
    # cached=True, so RefCache.put writes nothing: no made-up reference reaches a refcache.
    reference = Reference(digest=RELEASE_DIGEST, hash_file=RELEASE_DIGEST.encode() + b"\n", bundle=b"", cached=True)
    with (mock.patch.object(Document, "verify", return_value=verification),
          mock.patch.object(checks_tinfoil, "verify_attestation", return_value=measurement),
          mock.patch.object(RefCache, "get", return_value=reference)):
        yield


def post(client, raw: bytes):
    return client.post("/api/records", data={"record": (io.BytesIO(raw), "record.dsse.json")})


def statuses(body: dict) -> dict:
    return {c["id"]: c["status"] for c in body["checks"]}


def strict_client(monkeypatch, listed: bool = True):
    """A strict-mode registry whose policy lists OpenMined's sample benchmark owner, or nobody."""
    owners = f'\n  - email: "{EMAIL}"\n    display: {DISPLAY}\n' if listed else " []\n"
    Path("policy.yaml").write_text(f"trusted_code:\n  - repo: OpenMined/syft-enclave-tinfoil\nbenchmark_owners:{owners}")
    monkeypatch.setenv("REGISTRY_POLICY", "policy.yaml")
    return create_app().test_client()


@pytest.fixture
def strict(monkeypatch):
    return strict_client(monkeypatch)


def test_openmined_s_receipt_is_listed_as_verified_in_strict_mode(strict):
    with verified_hardware():
        response = post(strict, OPENMINED.read_bytes())
    assert response.status_code == 201, response.get_json()
    body = response.get_json()
    assert body["recordId"] == EXPECTED["om_receipt"]["recordId"]
    assert body["state"] == "verified"
    assert statuses(body) == ALL_PASS
    assert body["benchmarkOwner"] == {"email": EMAIL, "display": DISPLAY}
    enclave = body["enclave"]
    assert (enclave["type"], enclave["repo"], enclave["releaseTag"], enclave["releaseDigest"]) == (
        "AMD SEV-SNP", "OpenMined/syft-enclave-tinfoil", "v0.1.28", RELEASE_DIGEST)


def test_its_system_eval_and_model_roll_up_as_verified(strict):
    with verified_hardware():
        body = post(strict, OPENMINED.read_bytes()).get_json()
    weights = next(c["digest"] for c in body["components"] if c["role"] == MODEL_ROLE)
    for page in (f"/api/systems/{body['systemDigest']}", f"/api/evals/{body['eval']['digest']}",
                 f"/api/models/{weights}"):
        assert strict.get(page).get_json()["state"] == "verified", page


def test_the_same_receipt_is_refused_when_no_approver_is_listed(monkeypatch):
    with verified_hardware():
        response = post(strict_client(monkeypatch, listed=False), OPENMINED.read_bytes())
    assert response.status_code == 422
    assert response.get_json()["detail"] == "failed: consent"
    assert statuses(response.get_json()) == {**ALL_PASS, "consent": "FAIL"}


def test_its_real_report_stapled_onto_another_key_fails_check_2(strict):
    # stapled_B carries the same report, but its crypto_material names fixture key B.
    with verified_hardware():
        response = post(strict, record("stapled_B"))
    assert response.status_code == 422
    assert statuses(response.get_json()) == {**ALL_PASS, "key_binding": "FAIL"}
