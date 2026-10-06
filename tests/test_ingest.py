"""Ingest: checks in order, the gate, storing and indexing only what was accepted, and rebuilds.
test_api.py drives every fixture through POST and compares its status with expected.json."""

import base64
import copy
import hashlib
import json
import runpy
import sqlite3
from contextlib import closing
from datetime import datetime
from pathlib import Path

import pytest
import rfc8785
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fixture_data import CHECKED, DEV_POLICY, EXPECTED, ROOT, STRICT_POLICY, params, record

from registry import checks_tinfoil, spec
from registry.config import load_config
from registry.envelope import parse_receipt
from registry.evalresult import TIMESTAMP_FORMAT, parse_statement
from registry.index import Index
from registry.ingest import ingest, rebuild, verify
from registry.model import CHECK_IDS, Check, Enclave, Status, VerificationUnavailable
from registry.refcache import RefCache
from registry.store import Store

FIXTURES = runpy.run_path(str(ROOT / "scripts/make_fixtures.py"))
DEV_ACCEPTED = [name for name, entry in EXPECTED.items() if entry["dev"]["status"] == 201]
EARLIER = "2026-09-01T00:00:00Z"


@pytest.fixture
def store(tmp_path):
    return Store(tmp_path / "store")


@pytest.fixture
def index(tmp_path):
    return Index.create(tmp_path / "index.sqlite3", "00" * 32, "dev")


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


def test_an_accepted_record_is_stored_exactly_as_received(store, index, refcache):
    raw = record("sim_A")
    result = ingest(raw, config("dev"), store, index, refcache)
    assert result.status == 201
    record_id = result.body["recordId"]
    assert record_id == hashlib.sha256(raw).hexdigest() == EXPECTED["sim_A"]["recordId"]
    assert store.read_record(record_id) == raw
    assert store.read_meta(record_id) == {"receivedAt": result.body["receivedAt"]}


def test_the_accepted_answer_is_the_indexed_record(store, index, refcache):
    body = ingest(record("sim_A"), config("dev"), store, index, refcache).body
    assert body == index.get(EXPECTED["sim_A"]["recordId"]).to_json()
    assert body["state"] == "incomplete"
    assert statuses(body) == EXPECTED["sim_A"]["checks"]
    assert body["benchmarkOwner"] == {"publicKey": owner_key("sim_A"), "display": "DBE sample benchmark owner"}
    assert body["size"] == len(record("sim_A"))
    datetime.strptime(body["receivedAt"], TIMESTAMP_FORMAT)  # the registry's own clock, in the receipts' format


def test_ingesting_again_answers_200_with_the_first_receipt_time(store, index, refcache):
    first = ingest(record("sim_A"), config("dev"), store, index, refcache)
    again = ingest(record("sim_A"), config("dev"), store, index, refcache)
    assert (first.status, again.status) == (201, 200)
    assert again.body == first.body


def test_a_stored_record_missing_from_the_index_is_indexed_as_new_with_its_first_receipt_time(store, index, refcache):
    # A rebuild under an earlier policy may have left it out of the index.
    store.put_record(record("sim_A"), EARLIER)
    result = ingest(record("sim_A"), config("dev"), store, index, refcache)
    assert (result.status, result.body["receivedAt"]) == (201, EARLIER)
    assert index.get(EXPECTED["sim_A"]["recordId"]).received_at == EARLIER


@pytest.mark.parametrize("name", ["U1_predicate_type", "S1_no_reference_value", "C1_edit_after_sign",
                                  "C14_unlisted_bo", "sim_A_noconsent"])
def test_a_refused_record_is_not_stored(store, index, refcache, name):
    assert ingest(record(name), config("dev"), store, index, refcache).status >= 400
    assert not store.root.exists()
    assert index.recent(100) == []


def test_strict_mode_stores_nothing_incomplete(store, index, refcache):
    assert ingest(record("sim_A"), config("strict"), store, index, refcache).status == 422
    assert not store.root.exists()


def test_an_unrecognized_receipt_says_why(store, index, refcache):
    body = ingest(record("U5_two_signatures"), config("dev"), store, index, refcache).body
    assert body == {"recordId": EXPECTED["U5_two_signatures"]["recordId"],
                    "detail": "unrecognized receipt: signatures must hold exactly one signature, got 2"}


def test_a_schema_violation_lists_every_error(store, index, refcache):
    result = ingest(record("S1_no_reference_value"), config("dev"), store, index, refcache)
    assert result.status == 422
    assert result.body["detail"] == "the statement violates the schema"
    assert "predicate.execution.attestation.referenceValue: Field required" in result.body["schemaErrors"]


def test_a_failed_check_is_refused_with_the_checks(store, index, refcache):
    result = ingest(record("C1_edit_after_sign"), config("dev"), store, index, refcache)
    assert (result.status, result.body["detail"]) == (422, "failed: signature")
    assert statuses(result.body) == EXPECTED["C1_edit_after_sign"]["checks"]


def test_strict_mode_refuses_pending_checks(store, index, refcache):
    result = ingest(record("sim_A"), config("strict"), store, index, refcache)
    assert (result.status, result.body["detail"]) == (422, "incomplete records are accepted only in dev mode")
    assert statuses(result.body) == EXPECTED["sim_A"]["checks"]


def test_an_unlisted_owner_is_refused_with_the_checks_and_the_key(store, index, refcache):
    result = ingest(record("C14_unlisted_bo"), config("dev"), store, index, refcache)
    assert result.status == 403
    assert result.body["detail"] == f"the {spec.BENCHMARK_OWNER} key is not on this registry's list"
    assert result.body["benchmarkOwner"] == {"publicKey": owner_key("C14_unlisted_bo")}
    # The gate never changes a check result: consent still PASSes.
    assert statuses(result.body) == EXPECTED["C14_unlisted_bo"]["checks"]


def test_no_consent_is_refused_with_the_checks(store, index, refcache):
    result = ingest(record("sim_A_noconsent"), config("dev"), store, index, refcache)
    assert (result.status, result.body["detail"]) == (403, f"{spec.BENCHMARK_OWNER} approval required")
    assert statuses(result.body) == EXPECTED["sim_A_noconsent"]["checks"]


def test_a_listed_owner_whose_own_approval_fails_is_refused_with_422(store, index, refcache):
    # Check 7 FAILs before the gate runs. Tamper the benchmark owner's approval, then re-sign with key A.
    statement = copy.deepcopy(parse_receipt(record("sim_A")).statement)
    approval, = (a for a in statement["predicate"]["consent"]["approvals"] if a["party"] == spec.BENCHMARK_OWNER)
    signature = bytearray(base64.b64decode(approval["signature"]))
    signature[0] ^= 1
    approval["signature"] = base64.b64encode(bytes(signature)).decode()
    raw = FIXTURES["envelope"](rfc8785.dumps(statement), Ed25519PrivateKey.from_private_bytes(FIXTURES["seed"]("A")))

    result = ingest(raw, config("dev"), store, index, refcache)
    assert (result.status, result.body["detail"]) == (422, "failed: consent")
    assert statuses(result.body)["signature"] == "PASS"


def hardware(status: Status, enclave: Enclave | None = None):
    """A stand-in for checks 2-4: all three with `status`, and these enclave facts."""
    def check_attestation(attestation, run_public_key, trusted_code, refcache):
        return tuple(Check(check_id, status, "stand-in") for check_id in CHECK_IDS[1:4]), enclave
    return check_attestation


def test_a_network_failure_during_the_checks_is_a_503_and_stores_nothing(store, index, refcache, monkeypatch):
    def unavailable(*args):
        raise VerificationUnavailable("check 3 could not reach the network: connection refused")
    monkeypatch.setattr(checks_tinfoil, "check_attestation", unavailable)
    result = ingest(record("sim_A"), config("dev"), store, index, refcache)
    assert result.status == 503
    assert result.body == {"recordId": EXPECTED["sim_A"]["recordId"],
                           "detail": "verification unavailable, try again later: "
                                     "check 3 could not reach the network: connection refused"}
    assert not store.root.exists()
    assert index.recent(100) == []


def test_a_verified_answer_carries_the_verified_enclave_facts(store, index, refcache, monkeypatch):
    enclave = Enclave(measurement="6d" * 48, repo="tinfoilsh/double-blind-eval", release_tag="v0.0.4",
                      release_digest="fe" * 32)
    monkeypatch.setattr(checks_tinfoil, "check_attestation", hardware(Status.PASS, enclave))
    body = ingest(record("sim_A"), config("dev"), store, index, refcache).body
    assert body["state"] == "verified"
    assert body["enclave"] == {"type": "AMD SEV-SNP", "measurement": "6d" * 48, "repo": "tinfoilsh/double-blind-eval",
                               "releaseTag": "v0.0.4", "releaseDigest": "fe" * 32}


def test_an_incomplete_answer_has_no_enclave_facts(store, index, refcache):
    assert ingest(record("sim_A"), config("dev"), store, index, refcache).body["enclave"] is None


# --- rebuild -----------------------------------------------------------------

def dev_config(policy: Path = DEV_POLICY):
    return load_config({"REGISTRY_MODE": "dev", "REGISTRY_POLICY": str(policy), "REGISTRY_DATA_DIR": "data"})


@pytest.fixture
def seeded():
    """A dev registry in ./data holding every fixture dev mode accepts: its config, store and refcache."""
    cfg = dev_config()
    store, refcache = Store(cfg.store_dir), RefCache(cfg.refcache_dir)
    index = Index.open(cfg.index_path, cfg.policy_sha256, cfg.mode)
    for name in DEV_ACCEPTED:
        assert ingest(record(name), cfg, store, index, refcache).status == 201
    return cfg, store, refcache


def rows(path: Path) -> tuple:
    """Every row of the index at `path`, in a fixed order."""
    with closing(sqlite3.connect(path)) as conn:
        return tuple(conn.execute(sql).fetchall() for sql in ("SELECT * FROM meta ORDER BY key",
                                                              "SELECT * FROM records ORDER BY record_id",
                                                              "SELECT * FROM components ORDER BY record_id, rowid"))


def test_a_rebuild_reproduces_the_same_rows(seeded):
    cfg, store, refcache = seeded
    before = rows(cfg.index_path)
    cfg.index_path.unlink()
    assert rebuild(cfg, store, refcache) == (len(DEV_ACCEPTED), [])
    assert rows(cfg.index_path) == before


def test_a_rebuild_under_a_new_policy_leaves_out_what_it_now_refuses(seeded):
    cfg, store, refcache = seeded
    narrower = Path("narrower.yaml")
    narrower.write_text("trusted_code:\n  - repo: tinfoilsh/double-blind-eval\nbenchmark_owners:\n"
                        f'  - public_key: "{owner_key("sim_A")}"\n    display: The worked example\'s owner only\n')
    new = dev_config(narrower)
    indexed, skipped = rebuild(new, store, refcache)
    synthetic = [name for name in DEV_ACCEPTED if name.startswith("D")]
    assert indexed == len(DEV_ACCEPTED) - len(synthetic)
    assert sorted(record_id for record_id, _ in skipped) == sorted(EXPECTED[name]["recordId"] for name in synthetic)
    assert {why for _, why in skipped} == {f"403 the {spec.BENCHMARK_OWNER} key is not on this registry's list"}
    assert len(store.record_ids()) == len(DEV_ACCEPTED)  # refused now, but still stored
    index = Index.open(new.index_path, new.policy_sha256, new.mode)  # built under the new policy
    assert sorted(r.record_id for r in index.recent(100)) == sorted(EXPECTED[name]["recordId"]
                                                                   for name in ("sim_A", "sim_A_ec"))


def test_a_rebuild_leaves_out_a_record_whose_stored_bytes_no_longer_match_its_id(seeded):
    cfg, store, refcache = seeded
    record_id = EXPECTED["sim_A"]["recordId"]
    stored = cfg.store_dir / "sha256" / record_id[:2] / record_id[2:] / "record.dsse.json"
    stored.write_text(json.dumps(json.loads(stored.read_bytes()), indent=4))  # as an editor's format-on-save would
    indexed, skipped = rebuild(cfg, store, refcache)
    assert indexed == len(DEV_ACCEPTED) - 1
    assert skipped == [(record_id, "its stored bytes no longer hash to its id")]
    assert Index.open(cfg.index_path, cfg.policy_sha256, cfg.mode).get(record_id) is None


def test_a_rebuild_keeps_the_old_index_when_verification_is_unavailable(seeded, monkeypatch):
    cfg, store, refcache = seeded
    before = cfg.index_path.read_bytes()

    def unavailable(*args):
        raise VerificationUnavailable("check 3 could not reach the network: connection refused")
    monkeypatch.setattr(checks_tinfoil, "check_attestation", unavailable)
    with pytest.raises(VerificationUnavailable):
        rebuild(cfg, store, refcache)
    assert cfg.index_path.read_bytes() == before
    assert sorted(p.name for p in cfg.data_dir.iterdir()) == ["index.sqlite3", "store"]  # no temporary index left


def test_a_rebuild_of_an_empty_store_makes_an_empty_index():
    cfg = dev_config()
    assert rebuild(cfg, Store(cfg.store_dir), RefCache(cfg.refcache_dir)) == (0, [])
    assert Index.open(cfg.index_path, cfg.policy_sha256, cfg.mode).recent(100) == []
