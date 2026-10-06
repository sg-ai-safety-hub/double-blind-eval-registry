"""The index: its own record shape, SQLite round trips, the startup guard and the read views.

Records come from the fixtures dev mode accepts, through the EvalResult/v0.1 adapter."""

import hashlib
import sqlite3
from contextlib import closing

import pytest
from fixture_data import EXPECTED, record
from pydantic import ValidationError

from registry import spec
from registry.envelope import parse_receipt
from registry.evalresult import parse_statement, to_index
from registry.index import MODEL_ROLE, Index, IndexedRecord, StaleIndex
from registry.model import CHECK_IDS, Accepted, Check, Enclave, Status

POLICY_SHA256 = "00" * 32
T0, T1 = "2026-10-01T00:00:00Z", "2026-10-01T00:00:01Z"
DEV_ACCEPTED = [name for name, entry in EXPECTED.items() if entry["dev"]["status"] == 201]
ENCLAVE = Enclave(measurement="6d" * 48, repo="tinfoilsh/double-blind-eval", release_tag="v0.0.4",
                  release_digest="fe" * 32)


def indexed(name: str, received_at: str = T0, state: str = "incomplete", enclave: Enclave | None = None) -> IndexedRecord:
    """Fixture `name` as the adapter indexes it once accepted, with its expected check results."""
    raw = record(name)
    checks = tuple(Check(check_id, Status(EXPECTED[name]["checks"][check_id]), "stand-in") for check_id in CHECK_IDS)
    accepted = Accepted(hashlib.sha256(raw).hexdigest(), len(raw), received_at, state, checks, enclave,
                        f"owner of {name}")
    return to_index(parse_statement(parse_receipt(raw).statement), accepted)


def ids(*names: str) -> list[str]:
    return [EXPECTED[name]["recordId"] for name in names]


def weights(name: str) -> str:
    return next(c.digest for c in indexed(name).components if c.role == MODEL_ROLE)


def runtime(name: str) -> str:
    """The fixture's runtime image digest: an OCI digest, so it carries a sha256: prefix."""
    return next(c.digest for c in indexed(name).components if c.scheme == spec.OCI_SCHEME)


@pytest.fixture
def index(tmp_path):
    return Index.create(tmp_path / "index.sqlite3", POLICY_SHA256, "dev")


@pytest.fixture
def seeded(index):
    """Every fixture dev mode accepts, received one second apart in expected.json's order (D8 newest)."""
    for second, name in enumerate(DEV_ACCEPTED):
        assert index.add(indexed(name, f"2026-10-01T00:00:{second:02d}Z"))
    return index


# --- open: the startup guard -------------------------------------------------

def test_open_creates_a_missing_index_under_this_policy_and_mode(tmp_path):
    path = tmp_path / "data" / "dev" / "index.sqlite3"
    Index.open(path, POLICY_SHA256, "dev")
    assert Index(path).meta() == {"policy_sha256": POLICY_SHA256, "mode": "dev"}


def test_open_reuses_an_index_built_under_the_same_policy_and_mode(index):
    index.add(indexed("sim_A"))
    assert Index.open(index.path, POLICY_SHA256, "dev").get(EXPECTED["sim_A"]["recordId"]) is not None


@pytest.mark.parametrize("policy_sha256, mode", [("11" * 32, "dev"), (POLICY_SHA256, "strict")], ids=["policy", "mode"])
def test_open_refuses_an_index_built_under_another_policy_or_mode(index, policy_sha256, mode):
    # Its records were accepted under rules that no longer hold.
    with pytest.raises(StaleIndex):
        Index.open(index.path, policy_sha256, mode)


# --- add and get --------------------------------------------------------------

@pytest.mark.parametrize("name", DEV_ACCEPTED)
def test_a_record_reads_back_exactly_as_added(index, name):
    added = indexed(name)
    assert index.add(added)
    assert index.get(added.record_id) == added


def test_verified_enclave_facts_read_back(index):
    added = indexed("sim_A", state="verified", enclave=ENCLAVE)
    index.add(added)
    assert index.get(added.record_id).enclave == ENCLAVE


def test_adding_an_indexed_record_again_changes_nothing(index):
    first = indexed("sim_A", T0)
    assert index.add(first)
    assert not index.add(indexed("sim_A", T1))
    assert index.get(first.record_id) == first


def test_an_unknown_record_is_none(index):
    assert index.get("ab" * 32) is None


def test_only_the_two_states_are_indexed():
    with pytest.raises(ValidationError):
        indexed("sim_A", state="refused")


def test_components_are_rows_of_their_own_in_receipt_order(index):
    added = indexed("D5")  # two adapter components, listed against their sort order
    index.add(added)
    with closing(sqlite3.connect(index.path)) as conn:
        rows = conn.execute("SELECT role, scheme, digest, name FROM components WHERE record_id = ? ORDER BY rowid",
                            (added.record_id,)).fetchall()
    assert rows == [(c.role, c.scheme, c.digest, c.name) for c in added.components]


def test_recent_records_are_newest_first_and_limited(seeded):
    assert [r.record_id for r in seeded.recent(3)] == ids("D8", "D7", "D6")


# --- systems ------------------------------------------------------------------

def test_a_system_lists_its_records_newest_first(seeded):
    # D1, D2 and D8 run the same components; D8 only gives its sampling settings another name.
    view = seeded.system(indexed("D1").system_digest)
    assert view["digest"] == indexed("D1").system_digest
    assert [r["recordId"] for r in view["records"]] == ids("D8", "D2", "D1")
    assert view["records"][0] == seeded.get(EXPECTED["D8"]["recordId"]).to_json()
    assert view["subjectNames"] == ["synthetic-alpha-7b (synthetic)"]
    assert view["state"] == "incomplete"


def test_a_system_shows_every_label_its_records_gave_a_component(seeded):
    view = seeded.system(indexed("D1").system_digest)
    assert [(c["role"], c["scheme"], c["digest"]) for c in view["components"]] == [
        (c.role, c.scheme, c.digest) for c in indexed("D1").components]
    sampling = view["components"][2]
    assert sampling["names"] == ["<script>alert(1)</script>", "temperature=0.0 (synthetic)"]
    assert sampling["alsoKnownAs"] == [] and sampling["akaConflicts"] is False


def test_an_unknown_system_is_none(seeded):
    assert seeded.system("ab" * 32) is None


# --- components and models ----------------------------------------------------

def test_a_component_is_found_by_its_hex_digest_without_the_sha256_prefix(seeded):
    digest = runtime("D1")
    assert digest.startswith("sha256:")
    view = seeded.component(digest.removeprefix("sha256:"))
    assert (view["roles"], view["schemes"], view["names"]) == (["runtime_image"], [spec.OCI_SCHEME],
                                                               ["synthetic-runtime 1.0"])
    assert [r["recordId"] for r in view["records"]] == ids("D8", "D5", "D4", "D3", "D2", "D1")
    assert [s["digest"] for s in view["systems"]] == [indexed(name).system_digest for name in ("D8", "D5", "D4", "D3")]
    assert view["systems"][0]["subjectNames"] == ["synthetic-alpha-7b (synthetic)"]


def test_an_unknown_component_is_none(seeded):
    assert seeded.component("ab" * 32) is None


def test_models_are_the_base_weights_newest_first(seeded):
    assert [m["names"] for m in seeded.models()] == [
        ["synthetic-alpha-7b"], ["synthetic-gamma-70b"], ["synthetic-beta-13b"], ["gemma-4-31b"]]


def test_a_model_shows_its_aliases_systems_records_and_state(seeded):
    view = seeded.model(weights("D1"))
    assert view["digest"] == weights("D1") and view["roles"] == [MODEL_ROLE]
    alias, = next(c for c in indexed("D1").components if c.role == MODEL_ROLE).also_known_as
    assert view["alsoKnownAs"] == [{"scheme": alias.scheme, "value": alias.value}]
    assert view["akaConflicts"] is False
    assert [s["digest"] for s in view["systems"]] == [indexed(name).system_digest for name in ("D8", "D3")]
    assert [r["recordId"] for r in view["records"]] == ids("D8", "D3", "D2", "D1")
    assert view["state"] == "incomplete"


def test_conflicting_aliases_for_the_same_weights_are_flagged(seeded):
    # D6 and D7 claim different OpenSSF Model Signing digests for the same weights.
    view = seeded.model(weights("D6"))
    assert [a["scheme"] for a in view["alsoKnownAs"]] == ["oms/1", "oms/1"]
    assert view["akaConflicts"] is True


def test_a_model_is_a_base_weights_digest_only(seeded):
    assert seeded.model(runtime("D1").removeprefix("sha256:")) is None
    assert seeded.model("ab" * 32) is None


# --- evals ----------------------------------------------------------------------

def test_evals_are_listed_newest_first(seeded):
    # The worked example's eval has no name.
    assert [e["names"] for e in seeded.evaluations()] == [
        ["Synthetic honesty probe (synthetic)"], ["Synthetic refusal eval (synthetic)"],
        ["Synthetic bio-risk screen (synthetic)"], []]


def test_an_eval_shows_its_set_harness_version_public_flag_and_records(seeded):
    eval_ = indexed("D1").eval
    view = seeded.evaluation(eval_.digest)
    assert view["digest"] == eval_.digest
    assert (view["evalSet"], view["harness"]) == (eval_.eval_set.model_dump(), eval_.harness.model_dump())
    assert (view["harnessVersions"], view["publicFlags"]) == (["1.0.0"], [True])
    assert [r["recordId"] for r in view["records"]] == ids("D7", "D4", "D3", "D1")


def test_an_unknown_eval_is_none(seeded):
    assert seeded.evaluation("ab" * 32) is None


# --- rollups and lookup ---------------------------------------------------------

def test_a_rollup_takes_the_worst_state_of_its_records(index):
    # sim_A and sim_A_ec share their system, eval and model.
    index.add(indexed("sim_A", T0, state="verified", enclave=ENCLAVE))
    system, eval_ = indexed("sim_A").system_digest, indexed("sim_A").eval.digest
    assert [index.system(system)["state"], index.evaluation(eval_)["state"], index.model(weights("sim_A"))["state"]] == [
        "verified"] * 3
    index.add(indexed("sim_A_ec", T1))
    assert [index.system(system)["state"], index.evaluation(eval_)["state"], index.model(weights("sim_A"))["state"]] == [
        "incomplete"] * 3


@pytest.mark.parametrize("kind", ["system", "eval", "record", "model", "component"])
def test_lookup_names_the_kind_of_a_digest(seeded, kind):
    d1 = indexed("D1")
    digest = {"system": d1.system_digest, "eval": d1.eval.digest, "record": d1.record_id, "model": weights("D1"),
              "component": runtime("D1").removeprefix("sha256:")}[kind]
    assert seeded.lookup(digest) == {"kind": kind, "id": digest}


def test_lookup_of_an_unknown_digest_is_none(seeded):
    assert seeded.lookup("ab" * 32) is None
