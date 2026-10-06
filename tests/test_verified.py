"""The verified path, end to end through the API: a receipt whose checks all PASS is listed as verified.

Nothing that can be produced today passes checks 2-4, because Tinfoil's hardware report has no slot for
the run key. So the SDK boundary is replaced by demo_verified.verified_hardware. tests/demo_verified.py
runs the same ingest into data/demo* so the verified UI can be seen."""

import copy
import hashlib
import io
import runpy
import shutil
from pathlib import Path

import pytest
import rfc8785
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from demo_verified import RECEIPT, RELEASE_DIGEST, main, verified_hardware
from fixture_data import DEV_POLICY, ROOT

from registry import spec
from registry.app import create_app
from registry.envelope import parse_receipt
from registry.evalresult import parse_statement
from registry.index import MODEL_ROLE
from registry.model import CHECK_IDS

FIXTURES = runpy.run_path(str(ROOT / "scripts/make_fixtures.py"))
DISPLAY = "Verified-path owner"
ALL_PASS = {**{check_id: "PASS" for check_id in CHECK_IDS}, "publication": "N/A"}


def owner_key(raw: bytes) -> str:
    return parse_statement(parse_receipt(raw).statement).predicate.owner_key(spec.BENCHMARK_OWNER)


def post(client, raw: bytes):
    return client.post("/api/records", data={"record": (io.BytesIO(raw), "record.dsse.json")})


def statuses(body: dict) -> dict:
    return {c["id"]: c["status"] for c in body["checks"]}


@pytest.fixture
def strict(monkeypatch):
    """A strict-mode registry whose policy lists the receipt's benchmark owner."""
    Path("policy.yaml").write_text("trusted_code:\n  - repo: tinfoilsh/double-blind-eval\nbenchmark_owners:\n"
                                   f'  - public_key: "{owner_key(RECEIPT.read_bytes())}"\n    display: {DISPLAY}\n')
    monkeypatch.setenv("REGISTRY_POLICY", "policy.yaml")
    return create_app().test_client()


def test_a_receipt_whose_checks_all_pass_is_listed_as_verified_in_strict_mode(strict):
    with verified_hardware():
        response = post(strict, RECEIPT.read_bytes())
    assert response.status_code == 201, response.get_json()
    body = response.get_json()
    assert body["state"] == "verified"
    assert statuses(body) == ALL_PASS
    assert body["benchmarkOwner"] == {"publicKey": owner_key(RECEIPT.read_bytes()), "display": DISPLAY}
    enclave = body["enclave"]
    assert (enclave["type"], enclave["repo"], enclave["releaseTag"], enclave["releaseDigest"]) == (
        "AMD SEV-SNP", "tinfoilsh/double-blind-eval", "v0.0.4", RELEASE_DIGEST)


def test_its_system_eval_and_model_roll_up_as_verified(strict):
    with verified_hardware():
        body = post(strict, RECEIPT.read_bytes()).get_json()
    weights = next(c["digest"] for c in body["components"] if c["role"] == MODEL_ROLE)
    for page in (f"/api/systems/{body['systemDigest']}", f"/api/evals/{body['eval']['digest']}",
                 f"/api/models/{weights}"):
        assert strict.get(page).get_json()["state"] == "verified", page


def test_the_same_receipt_without_consent_is_refused(strict):
    # Re-signed with key A, which signed the receipt: only the benchmark owner's approval is missing.
    statement = copy.deepcopy(parse_receipt(RECEIPT.read_bytes()).statement)
    del statement["predicate"]["consent"]
    raw = FIXTURES["envelope"](rfc8785.dumps(statement), Ed25519PrivateKey.from_private_bytes(FIXTURES["seed"]("A")))
    with verified_hardware():
        response = post(strict, raw)
    assert response.status_code == 403
    assert response.get_json()["detail"] == f"{spec.BENCHMARK_OWNER} approval required"
    assert statuses(response.get_json()) == {**ALL_PASS, "consent": "N/A"}


# --- the demo ----------------------------------------------------------------

def test_the_demo_indexes_a_verified_record_a_dev_server_can_serve(monkeypatch, capsys):
    shutil.copy(DEV_POLICY, DEV_POLICY.name)  # the dev server copies it into place, as from a checkout
    assert main(["--out", "data/demo"]) == 0
    assert "REGISTRY_MODE=dev REGISTRY_DATA_DIR=" in capsys.readouterr().out
    monkeypatch.setenv("REGISTRY_MODE", "dev")
    monkeypatch.setenv("REGISTRY_DATA_DIR", "data/demo")
    records = create_app().test_client().get("/api/records").get_json()["records"]
    assert [(r["recordId"], r["state"]) for r in records] == [(hashlib.sha256(RECEIPT.read_bytes()).hexdigest(),
                                                               "verified")]


@pytest.mark.parametrize("out", ["data/dev", "data", "data/demo/../dev", "elsewhere/demo"])
def test_the_demo_refuses_to_write_outside_data_demo(out, capsys):
    shutil.copy(DEV_POLICY, DEV_POLICY.name)
    assert main(["--out", out]) == 2
    assert "data/demo" in capsys.readouterr().err
    assert not Path("data").exists() and not Path("elsewhere").exists()
