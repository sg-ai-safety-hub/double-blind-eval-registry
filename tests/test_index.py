"""The index: its own record shape, SQLite round trips, the startup guard and the read views.

Records come from the fixtures dev mode accepts, through the receipt's adapter."""

import hashlib
import sqlite3
from contextlib import closing

import pytest
from fixture_data import EXPECTED, record
from pydantic import ValidationError

from registry import spec
from registry.envelope import parse_receipt
from registry.index import MODEL_ROLE, Component, Index, IndexedRecord, StaleIndex
from registry.model import CHECK_IDS, Accepted, Check, Enclave, Publication, Status
from registry.syft_receipt import parse_statement, to_index

POLICY_SHA256 = "00" * 32
T0, T1 = "2026-10-01T00:00:00Z", "2026-10-01T00:00:01Z"
DEV_ACCEPTED = [name for name, entry in EXPECTED.items() if entry["dev"]["status"] == 201]
ENCLAVE = Enclave(measurement="33" * 48, repo="OpenMined/syft-enclave-tinfoil", release_tag="v0.1.28",
                  release_digest="74" * 32)
PUBLICATION = Publication(uuid="10" * 40, log_index=3129204433, integrated_time=1791368875,
                          url=spec.REKOR_SEARCH_LINK.format(3129204433))


def indexed(name: str, received_at: str = T0, state: str = "incomplete", enclave: Enclave | None = None,
            publication: Publication | None = None) -> IndexedRecord:
    """Fixture `name` as the adapter indexes it once accepted, with its expected check results."""
    raw = record(name)
    checks = tuple(Check(check_id, Status(EXPECTED[name]["checks"][check_id]), "stand-in") for check_id in CHECK_IDS)
    accepted = Accepted(hashlib.sha256(raw).hexdigest(), len(raw), received_at, state, checks, enclave, publication,
                        f"approver-of-{name}@example.org", f"owner of {name}")
    return to_index(parse_statement(parse_receipt(raw).statement), accepted)


def ids(*names: str) -> list[str]:
    return [EXPECTED[name]["recordId"] for name in names]


def weights(name: str) -> str:
    return next(c.digest for c in indexed(name).components if c.role == MODEL_ROLE)


def sampling(name: str) -> str:
    """The fixture's sampling config digest: a component that is neither a model nor a system."""
    return next(c.digest for c in indexed(name).components if c.role == "sampling")


@pytest.fixture
def index(tmp_path):
    return Index.create(tmp_path / "index.sqlite3", POLICY_SHA256, "dev")


@pytest.fixture
def seeded(index):
    """Every fixture dev mode accepts, received one second apart in expected.json's order (D7 newest)."""
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
    added = indexed("om_receipt", state="verified", enclave=ENCLAVE)
    index.add(added)
    assert index.get(added.record_id).enclave == ENCLAVE


def test_publication_facts_read_back_and_the_api_shows_them(index):
    added = indexed("om_receipt", state="verified", enclave=ENCLAVE, publication=PUBLICATION)
    index.add(added)
    read = index.get(added.record_id)
    assert read.publication == PUBLICATION
    assert read.to_json()["publication"] == {"uuid": "10" * 40, "logIndex": 3129204433, "integratedTime": 1791368875,
                                             "url": spec.REKOR_SEARCH_LINK.format(3129204433)}


def test_a_record_with_no_publication_reads_back_none(index):
    added = indexed("sim_A")
    index.add(added)
    assert index.get(added.record_id).publication is None


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
    added = indexed("om_receipt")  # three models, then a sampling config
    index.add(added)
    with closing(sqlite3.connect(index.path)) as conn:
        rows = conn.execute("SELECT role, scheme, digest, name FROM components WHERE record_id = ? ORDER BY rowid",
                            (added.record_id,)).fetchall()
    assert rows == [(c.role, c.scheme, c.digest, c.name) for c in added.components]
    assert [row[0] for row in rows] == [MODEL_ROLE, "adapter", "safety_classifier", "sampling"]


def test_recent_records_are_newest_first_and_limited(seeded):
    assert [r.record_id for r in seeded.recent(3)] == ids("D7", "D6", "D5")


# --- systems ------------------------------------------------------------------

def test_a_system_lists_its_records_newest_first(seeded):
    # D1 and D2 run the same pipeline on different eval datasets.
    view = seeded.system(indexed("D1").system_digest)
    assert view["digest"] == indexed("D1").system_digest
    assert [r["recordId"] for r in view["records"]] == ids("D2", "D1")
    assert view["records"][0] == seeded.get(EXPECTED["D2"]["recordId"]).to_json()
    assert view["subjectNames"] == ["synthetic-alpha-7b (synthetic)"]
    assert view["state"] == "incomplete"


def test_a_system_shows_its_components_with_their_labels(seeded):
    view = seeded.system(indexed("D1").system_digest)
    assert [(c["role"], c["scheme"], c["digest"], c["names"]) for c in view["components"]] == [
        (c.role, c.scheme, c.digest, [c.name]) for c in indexed("D1").components]
    base = view["components"][0]
    assert [a["scheme"] for a in base["alsoKnownAs"]] == ["hf-revision/1"] and base["akaConflicts"] is False


def test_an_unknown_system_is_none(seeded):
    assert seeded.system("ab" * 32) is None


# --- components and models ----------------------------------------------------

def test_a_component_lists_the_systems_and_records_that_use_it(seeded):
    view = seeded.component(sampling("D1"))
    assert (view["roles"], view["names"]) == (["sampling"], ["sampling-greedy"])
    assert [r["recordId"] for r in view["records"]] == ids("D7", "D6", "D5", "D3", "D2", "D1")
    assert [s["digest"] for s in view["systems"]] == [indexed(name).system_digest for name in ("D7", "D6", "D5", "D3", "D2")]


def test_a_component_is_found_by_its_hex_digest_without_the_sha256_prefix(index):
    # OCI digests carry a sha256: prefix; a lookup is by the bare hex.
    d1 = indexed("D1")
    oci = Component(role="runtime", scheme=spec.OCI_SCHEME, digest="sha256:" + "cd" * 32, name="runtime 1.0",
                    also_known_as=())
    index.add(d1.model_copy(update={"components": (*d1.components, oci)}))
    view = index.component("cd" * 32)
    assert (view["roles"], view["schemes"], view["names"]) == (["runtime"], [spec.OCI_SCHEME], ["runtime 1.0"])
    assert index.lookup("cd" * 32) == {"kind": "component", "id": "cd" * 32}


def test_an_unknown_component_is_none(seeded):
    assert seeded.component("ab" * 32) is None


def test_models_are_the_base_models_newest_first(seeded):
    assert [m["names"] for m in seeded.models()] == [
        ["synthetic-alpha-7b"], ["synthetic-gamma-70b"], ["synthetic-beta-13b"], ["TinyLlama/TinyLlama-1.1B-Chat-v1.0"]]


def test_a_model_shows_its_aliases_systems_records_and_state(seeded):
    view = seeded.model(weights("D1"))
    assert view["digest"] == weights("D1") and view["roles"] == [MODEL_ROLE]
    alias, = next(c for c in indexed("D1").components if c.role == MODEL_ROLE).also_known_as
    assert view["alsoKnownAs"] == [{"scheme": alias.scheme, "value": alias.value}]
    assert view["akaConflicts"] is False
    assert [s["digest"] for s in view["systems"]] == [indexed(name).system_digest for name in ("D7", "D3", "D2")]
    assert [r["recordId"] for r in view["records"]] == ids("D7", "D3", "D2", "D1")
    assert view["state"] == "incomplete"


def test_conflicting_aliases_for_the_same_weights_are_flagged(seeded):
    # D5 and D6 claim different Hugging Face revisions for the same weights.
    view = seeded.model(weights("D5"))
    assert [a["scheme"] for a in view["alsoKnownAs"]] == ["hf-revision/1", "hf-revision/1"]
    assert view["akaConflicts"] is True


def test_a_model_is_a_base_model_digest_only(seeded):
    assert seeded.model(sampling("D1")) is None
    assert seeded.model("ab" * 32) is None


# --- evals ----------------------------------------------------------------------

def test_evals_are_listed_newest_first(seeded):
    assert [e["names"] for e in seeded.evaluations()] == [
        ["synthetic-honesty-probe"], ["synthetic-refusal-prompts"], ["synthetic-bio-risk-screen"], ["dbe_prompts"]]


def test_an_eval_is_its_dataset_with_its_records(seeded):
    eval_ = indexed("D1").eval
    view = seeded.evaluation(eval_.digest)
    assert view["digest"] == eval_.digest
    assert (view["evalSet"], view["harness"]) == (eval_.eval_set.model_dump(), None)
    assert (view["harnessVersions"], view["publicFlags"]) == ([], [])
    assert [r["recordId"] for r in view["records"]] == ids("D6", "D4", "D3", "D1")


def test_an_unknown_eval_is_none(seeded):
    assert seeded.evaluation("ab" * 32) is None


# --- rollups and lookup ---------------------------------------------------------

def test_a_rollup_takes_the_worst_state_of_its_records(index):
    # sim_A is OpenMined's statement re-signed, so it shares om_receipt's system, eval and model.
    om = indexed("om_receipt")

    def states() -> list[str]:
        return [index.system(om.system_digest)["state"], index.evaluation(om.eval.digest)["state"],
                index.model(weights("om_receipt"))["state"]]

    index.add(indexed("om_receipt", T0, state="verified", enclave=ENCLAVE))
    assert states() == ["verified"] * 3
    index.add(indexed("sim_A", T1))
    assert states() == ["incomplete"] * 3


@pytest.mark.parametrize("kind", ["system", "eval", "record", "model", "component"])
def test_lookup_names_the_kind_of_a_digest(seeded, kind):
    d1 = indexed("D1")
    digest = {"system": d1.system_digest, "eval": d1.eval.digest, "record": d1.record_id, "model": weights("D1"),
              "component": sampling("D1")}[kind]
    assert seeded.lookup(digest) == {"kind": kind, "id": digest}


def test_lookup_of_an_unknown_digest_is_none(seeded):
    assert seeded.lookup("ab" * 32) is None
