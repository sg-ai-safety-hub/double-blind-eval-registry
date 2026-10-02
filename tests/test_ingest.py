"""Ingest: checks in order, the gate, and storing only what was accepted.
test_api.py drives every fixture through POST and compares its status with expected.json."""

import base64
import copy
import hashlib
import runpy
from datetime import datetime

import pytest
import rfc8785
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fixture_data import CHECKED, DEV_POLICY, EXPECTED, ROOT, STRICT_POLICY, params, record

from registry import checks_tinfoil, spec
from registry.config import load_config
from registry.envelope import parse_receipt
from registry.evalresult import TIMESTAMP_FORMAT, parse_statement
from registry.ingest import ingest, verify
from registry.model import CHECK_IDS, Check, Enclave, Status, VerificationUnavailable
from registry.refcache import RefCache
from registry.store import Store

FIXTURES = runpy.run_path(str(ROOT / "scripts/make_fixtures.py"))


@pytest.fixture
def store(tmp_path):
    return Store(tmp_path / "store")


@pytest.fixture
def refcache(tmp_path):
    return RefCache(tmp_path / "refcache")


def config(mode: str):
    policy = DEV_POLICY if mode == "dev" else STRICT_POLICY
    return load_config({"REGISTRY_MODE": mode, "REGISTRY_POLICY": str(policy)})


def statuses(body: dict) -> dict:
    return {c["id"]: c["status"] for c in body["checks"]}


def owner_key(name: str) -> str:
    return parse_statement(parse_receipt(record(name)).statement).predicate.owner_key(spec.BENCHMARK_OWNER)


@pytest.mark.parametrize("name", params(CHECKED))
def test_checks_run_in_order_and_match_expected(name, refcache):
    receipt = parse_receipt(record(name))
    result = verify(receipt, parse_statement(receipt.statement), config("dev").policy, refcache)
    assert tuple(c.id for c in result.checks) == CHECK_IDS
    assert {c.id: c.status for c in result.checks} == EXPECTED[name]["checks"]


def test_an_accepted_record_is_stored_exactly_as_received(store, refcache):
    raw = record("sim_A")
    result = ingest(raw, config("dev"), store, refcache)
    assert result.status == 201
    record_id = result.body["recordId"]
    assert record_id == hashlib.sha256(raw).hexdigest() == EXPECTED["sim_A"]["recordId"]
    assert store.read_record(record_id) == raw
    assert store.read_meta(record_id) == {"receivedAt": result.body["receivedAt"]}


def test_the_accepted_answer_names_the_state_checks_and_listed_owner(store, refcache):
    body = ingest(record("sim_A"), config("dev"), store, refcache).body
    assert set(body) == {"recordId", "state", "checks", "benchmarkOwner", "receivedAt"}
    assert body["state"] == "incomplete"
    assert statuses(body) == EXPECTED["sim_A"]["checks"]
    assert body["benchmarkOwner"] == {"publicKey": owner_key("sim_A"), "display": "DBE sample benchmark owner"}
    datetime.strptime(body["receivedAt"], TIMESTAMP_FORMAT)  # the registry's own clock, in the receipts' format


def test_ingesting_again_answers_200_with_the_first_receipt_time(store, refcache):
    first = ingest(record("sim_A"), config("dev"), store, refcache)
    again = ingest(record("sim_A"), config("dev"), store, refcache)
    assert (first.status, again.status) == (201, 200)
    assert again.body == first.body


@pytest.mark.parametrize("name", ["U1_predicate_type", "S1_no_reference_value", "C1_edit_after_sign",
                                  "C14_unlisted_bo", "sim_A_noconsent"])
def test_a_refused_record_is_not_stored(store, refcache, name):
    assert ingest(record(name), config("dev"), store, refcache).status >= 400
    assert not store.root.exists()


def test_strict_mode_stores_nothing_incomplete(store, refcache):
    assert ingest(record("sim_A"), config("strict"), store, refcache).status == 422
    assert not store.root.exists()


def test_an_unrecognized_receipt_says_why(store, refcache):
    body = ingest(record("U5_two_signatures"), config("dev"), store, refcache).body
    assert body == {"recordId": EXPECTED["U5_two_signatures"]["recordId"],
                    "detail": "unrecognized receipt: signatures must hold exactly one signature, got 2"}


def test_a_schema_violation_lists_every_error(store, refcache):
    result = ingest(record("S1_no_reference_value"), config("dev"), store, refcache)
    assert result.status == 422
    assert result.body["detail"] == "the statement violates the schema"
    assert "predicate.execution.attestation.referenceValue: Field required" in result.body["schemaErrors"]


def test_a_failed_check_is_refused_with_the_checks(store, refcache):
    result = ingest(record("C1_edit_after_sign"), config("dev"), store, refcache)
    assert (result.status, result.body["detail"]) == (422, "failed: signature")
    assert statuses(result.body) == EXPECTED["C1_edit_after_sign"]["checks"]


def test_strict_mode_refuses_pending_checks(store, refcache):
    result = ingest(record("sim_A"), config("strict"), store, refcache)
    assert (result.status, result.body["detail"]) == (422, "incomplete records are accepted only in dev mode")
    assert statuses(result.body) == EXPECTED["sim_A"]["checks"]


def test_an_unlisted_owner_is_refused_with_the_checks_and_the_key(store, refcache):
    result = ingest(record("C14_unlisted_bo"), config("dev"), store, refcache)
    assert result.status == 403
    assert result.body["detail"] == f"the {spec.BENCHMARK_OWNER} key is not on this registry's list"
    assert result.body["benchmarkOwner"] == {"publicKey": owner_key("C14_unlisted_bo")}
    # The gate never changes a check result: consent still PASSes.
    assert statuses(result.body) == EXPECTED["C14_unlisted_bo"]["checks"]


def test_no_consent_is_refused_with_the_checks(store, refcache):
    result = ingest(record("sim_A_noconsent"), config("dev"), store, refcache)
    assert (result.status, result.body["detail"]) == (403, f"{spec.BENCHMARK_OWNER} approval required")
    assert statuses(result.body) == EXPECTED["sim_A_noconsent"]["checks"]


def test_a_listed_owner_whose_own_approval_fails_is_refused_with_422(store, refcache):
    # Check 7 FAILs before the gate runs. Tamper the benchmark owner's approval, then re-sign with key A.
    statement = copy.deepcopy(parse_receipt(record("sim_A")).statement)
    approval, = (a for a in statement["predicate"]["consent"]["approvals"] if a["party"] == spec.BENCHMARK_OWNER)
    signature = bytearray(base64.b64decode(approval["signature"]))
    signature[0] ^= 1
    approval["signature"] = base64.b64encode(bytes(signature)).decode()
    raw = FIXTURES["envelope"](rfc8785.dumps(statement), Ed25519PrivateKey.from_private_bytes(FIXTURES["seed"]("A")))

    result = ingest(raw, config("dev"), store, refcache)
    assert (result.status, result.body["detail"]) == (422, "failed: consent")
    assert statuses(result.body)["signature"] == "PASS"


def hardware(status: Status, enclave: Enclave | None = None):
    """A stand-in for checks 2-4: all three with `status`, and these enclave facts."""
    def check_attestation(attestation, run_public_key, trusted_code, refcache):
        return tuple(Check(check_id, status, "stand-in") for check_id in CHECK_IDS[1:4]), enclave
    return check_attestation


def test_a_network_failure_during_the_checks_is_a_503_and_stores_nothing(store, refcache, monkeypatch):
    def unavailable(*args):
        raise VerificationUnavailable("check 3 could not reach the network: connection refused")
    monkeypatch.setattr(checks_tinfoil, "check_attestation", unavailable)
    result = ingest(record("sim_A"), config("dev"), store, refcache)
    assert result.status == 503
    assert result.body == {"recordId": EXPECTED["sim_A"]["recordId"],
                           "detail": "verification unavailable, try again later: "
                                     "check 3 could not reach the network: connection refused"}
    assert not store.root.exists()


def test_a_verified_answer_carries_the_verified_enclave_facts(store, refcache, monkeypatch):
    enclave = Enclave(measurement="6d" * 48, repo="tinfoilsh/double-blind-eval", release_tag="v0.0.4",
                      release_digest="fe" * 32)
    monkeypatch.setattr(checks_tinfoil, "check_attestation", hardware(Status.PASS, enclave))
    body = ingest(record("sim_A"), config("dev"), store, refcache).body
    assert body["state"] == "verified"
    assert body["enclave"] == {"type": "AMD SEV-SNP", "measurement": "6d" * 48, "repo": "tinfoilsh/double-blind-eval",
                               "releaseTag": "v0.0.4", "releaseDigest": "fe" * 32}


def test_an_incomplete_answer_has_no_enclave_facts(store, refcache):
    assert "enclave" not in ingest(record("sim_A"), config("dev"), store, refcache).body
