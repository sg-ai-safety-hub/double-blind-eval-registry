"""The index: what the registry lists. It is derived from the store and can be rebuilt from it.

The store keeps each accepted record's bytes and never parses them. The index keeps IndexedRecord,
the registry's own shape for an accepted record. That shape names no receipt format's fields: each
receipt format has an adapter that maps its receipts into it (EvalResult/v0.1: evalresult.to_index).
A changed or added format needs only its adapter and a rebuild (scripts/rebuild_index.py); this module
and the store stay as they are.

SQLite through the standard library, one connection per call.
"""

import json
import logging
import sqlite3
from collections.abc import Callable, Iterable
from contextlib import closing, contextmanager
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict
from pydantic.alias_generators import to_camel

from registry.model import Check, Enclave

log = logging.getLogger(__name__)

MODEL_ROLE = "base_weights"  # the component role whose digest identifies a model
DIGEST_PREFIX = "sha256:"  # OCI digests carry it; a component is looked up by its hex, with or without it
STATES = ("incomplete", "verified")  # worst first: a rollup takes the worst state of its records
NEWEST_FIRST = "ORDER BY received_at DESC, record_id"

SCHEMA = """
CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE records (
  record_id TEXT PRIMARY KEY, predicate_type TEXT NOT NULL, adapter_version TEXT NOT NULL,
  state TEXT NOT NULL CHECK (state IN ('verified','incomplete')),
  checks_json TEXT NOT NULL,
  subject_name TEXT, system_digest TEXT NOT NULL, eval_digest TEXT NOT NULL,
  eval_name TEXT, eval_public INTEGER, eval_set_json TEXT NOT NULL, harness_json TEXT NOT NULL,
  harness_version TEXT, metrics_json TEXT NOT NULL, counts_json TEXT, scored INTEGER,
  parties_json TEXT NOT NULL, consent_json TEXT NOT NULL,
  benchmark_owner_key TEXT NOT NULL,
  benchmark_owner_display TEXT NOT NULL,
  enclave_json TEXT,
  reported_json TEXT NOT NULL,
  received_at TEXT NOT NULL,
  size INTEGER NOT NULL);
CREATE TABLE components (record_id TEXT NOT NULL REFERENCES records ON DELETE CASCADE,
  role TEXT NOT NULL, scheme TEXT NOT NULL, digest TEXT NOT NULL, name TEXT, aka_json TEXT);
CREATE INDEX ix_rec_sys ON records(system_digest);
CREATE INDEX ix_rec_eval ON records(eval_digest);
CREATE INDEX ix_rec_bo ON records(benchmark_owner_key);
CREATE INDEX ix_comp_digest ON components(digest);
CREATE INDEX ix_comp_role ON components(role, digest);
"""
INSERT_RECORD = """
INSERT INTO records (record_id, predicate_type, adapter_version, state, checks_json, subject_name, system_digest,
  eval_digest, eval_name, eval_public, eval_set_json, harness_json, harness_version, metrics_json, counts_json, scored,
  parties_json, consent_json, benchmark_owner_key, benchmark_owner_display, enclave_json, reported_json,
  received_at, size)
VALUES (:record_id, :predicate_type, :adapter_version, :state, :checks_json, :subject_name, :system_digest,
  :eval_digest, :eval_name, :eval_public, :eval_set_json, :harness_json, :harness_version, :metrics_json, :counts_json,
  :scored, :parties_json, :consent_json, :benchmark_owner_key, :benchmark_owner_display, :enclave_json, :reported_json,
  :received_at, :size)
ON CONFLICT (record_id) DO NOTHING
"""
INSERT_COMPONENT = "INSERT INTO components (record_id, role, scheme, digest, name, aka_json) VALUES (?, ?, ?, ?, ?, ?)"
COMPONENT_RECORDS = ("SELECT * FROM records WHERE record_id IN (SELECT record_id FROM components "
                     f"WHERE digest IN (:digest, :prefixed) AND (:role IS NULL OR role = :role)) {NEWEST_FIRST}")
LOOKUPS = (  # tried in this order
    ("system", "SELECT 1 FROM records WHERE system_digest = :digest"),
    ("eval", "SELECT 1 FROM records WHERE eval_digest = :digest"),
    ("record", "SELECT 1 FROM records WHERE record_id = :digest"),
    ("model", "SELECT 1 FROM components WHERE role = :role AND digest IN (:digest, :prefixed)"),
    ("component", "SELECT 1 FROM components WHERE digest IN (:digest, :prefixed)"),
)


class StaleIndex(Exception):
    """The index was built under another policy or mode, so its records were accepted under other rules."""


# --- the index's own shape ---------------------------------------------------

class Shape(BaseModel):
    """The index's vocabulary. The API returns it as JSON, with camelCase names."""

    model_config = ConfigDict(frozen=True, extra="forbid", alias_generator=to_camel, validate_by_name=True)


class SchemedDigest(Shape):
    scheme: str
    digest: str


class Alias(Shape):
    """Another identity for a component's bytes, such as an OpenSSF Model Signing digest or a Hugging Face revision."""

    scheme: str
    value: str  # a digest or a reference


class Component(Shape):
    role: str
    scheme: str
    digest: str
    name: str | None  # a label, shown only next to its digest
    also_known_as: tuple[Alias, ...]


class Eval(Shape):
    digest: str
    eval_set: SchemedDigest
    harness: SchemedDigest
    name: str | None
    harness_version: str | None
    public: bool | None


class Counts(Shape):
    submitted: int
    completed: int
    failed: int


class Results(Shape):
    metrics: tuple[Any, ...]  # opaque items, shown as given
    counts: Counts | None
    scored: bool | None


class Party(Shape):
    role: str
    scheme: str
    public_key: str | None
    name: str | None


class Approval(Shape):
    party: str
    public_key: str


class Consent(Shape):
    manifest_digest: str
    approvals: tuple[Approval, ...]


class Reported(Shape):
    """What the receipt says about its run that no check verifies. The enclave's clock is set by the host."""

    platform: str | None
    cvm_version: str | None
    run_id: str | None
    config_digest: str | None
    started_at: str | None
    finished_at: str | None


class Owner(Shape):
    public_key: str  # from the receipt
    display: str  # from this registry's policy, when the record was indexed


class IndexedRecord(Shape):
    """One accepted record, in the index's own shape."""

    # What the registry established, the same for every receipt format.
    record_id: str
    size: int
    received_at: str
    state: Literal["verified", "incomplete"]
    checks: tuple[Check, ...]
    enclave: Enclave | None  # verified facts only: None unless checks 3 and 4 PASSed
    benchmark_owner: Owner
    # What the receipt says, mapped by its format's adapter.
    predicate_type: str
    adapter_version: str
    subject_name: str | None
    system_digest: str
    components: tuple[Component, ...]
    eval: Eval
    results: Results
    parties: tuple[Party, ...]
    consent: Consent
    reported: Reported

    def to_json(self) -> dict:
        """The record as the API returns it."""
        return {**self.model_dump(mode="json", by_alias=True), "links": {
            "download": f"/api/records/{self.record_id}/record.dsse.json",
            "system": f"/api/systems/{self.system_digest}",
            "eval": f"/api/evals/{self.eval.digest}",
        }}


# --- the index ---------------------------------------------------------------

class Index:
    def __init__(self, path: Path):
        self.path = path

    @classmethod
    def create(cls, path: Path, policy_sha256: str, mode: str) -> "Index":
        """A new, empty index at `path`, built under this policy and mode. `path` may be an empty file."""
        path.parent.mkdir(parents=True, exist_ok=True)
        index = cls(path)
        with index._connect() as conn:
            conn.executescript(SCHEMA)
            conn.executemany("INSERT INTO meta (key, value) VALUES (?, ?)",
                             [("policy_sha256", policy_sha256), ("mode", mode)])
        log.debug("created index %s: mode %s, policy sha256=%s", path, mode, policy_sha256)
        return index

    @classmethod
    def open(cls, path: Path, policy_sha256: str, mode: str) -> "Index":
        """The index at `path`, created if there is none. Refuses one built under another policy or mode."""
        if not path.exists():
            return cls.create(path, policy_sha256, mode)
        index = cls(path)
        built_under = index.meta()
        if built_under != {"policy_sha256": policy_sha256, "mode": mode}:
            log.debug("REJECT index %s: built under %s", path, built_under)
            raise StaleIndex(f"the index {path} was built under another policy or mode")
        log.debug("ACCEPT index %s: built under this policy and mode", path)
        return index

    def meta(self) -> dict[str, str]:
        with self._connect() as conn:
            return {row["key"]: row["value"] for row in conn.execute("SELECT key, value FROM meta")}

    def add(self, record: IndexedRecord) -> bool:
        """Index `record`. False, changing nothing, if a record with its id is already indexed."""
        with self._connect() as conn:
            added = conn.execute(INSERT_RECORD, _record_row(record)).rowcount == 1
            if added:
                conn.executemany(INSERT_COMPONENT, _component_rows(record))
        log.debug("index %s %s, %s, %d component(s)", "added" if added else "already had", record.record_id,
                  record.state, len(record.components))
        return added

    def get(self, record_id: str) -> IndexedRecord | None:
        with self._connect() as conn:
            records = _load(conn, "SELECT * FROM records WHERE record_id = ?", (record_id,))
        return records[0] if records else None

    def recent(self, limit: int) -> list[IndexedRecord]:
        with self._connect() as conn:
            return _load(conn, f"SELECT * FROM records {NEWEST_FIRST} LIMIT ?", (limit,))

    def system(self, digest: str) -> dict | None:
        """A system (pipelineDigest): its components, with every label its records gave them, and its records."""
        with self._connect() as conn:
            records = _load(conn, f"SELECT * FROM records WHERE system_digest = ? {NEWEST_FIRST}", (digest,))
        if not records:
            return None
        components = _grouped((c for r in records for c in r.components), lambda c: (c.role, c.scheme, c.digest))
        return {"digest": digest, "subjectNames": _distinct(r.subject_name for r in records), "state": _rollup(records),
                "components": [{"role": role, "scheme": scheme, "digest": digest_, **_labels(same)}
                               for (role, scheme, digest_), same in components.items()],
                "records": [r.to_json() for r in records]}

    def component(self, digest: str) -> dict | None:
        """A component by its hex digest, in any role: the systems that contain it and their records."""
        return self._component(digest, None)

    def model(self, digest: str) -> dict | None:
        """A model: a base weights component by its hex digest."""
        return self._component(digest, MODEL_ROLE)

    def models(self) -> list[dict]:
        """Every model, the one with the newest record first."""
        with self._connect() as conn:
            records = _load(conn, f"SELECT * FROM records WHERE record_id IN "
                                  f"(SELECT record_id FROM components WHERE role = ?) {NEWEST_FIRST}", (MODEL_ROLE,))
        by_weights: dict[str, list[IndexedRecord]] = {}
        for r in records:
            for digest in _distinct(c.digest.removeprefix(DIGEST_PREFIX) for c in r.components if c.role == MODEL_ROLE):
                by_weights.setdefault(digest, []).append(r)
        return [_component_view(digest, MODEL_ROLE, same) for digest, same in by_weights.items()]

    def evaluation(self, digest: str) -> dict | None:
        with self._connect() as conn:
            records = _load(conn, f"SELECT * FROM records WHERE eval_digest = ? {NEWEST_FIRST}", (digest,))
        return _eval_view(digest, records) if records else None

    def evaluations(self) -> list[dict]:
        """Every eval, the one with the newest record first."""
        with self._connect() as conn:
            records = _load(conn, f"SELECT * FROM records {NEWEST_FIRST}")
        return [_eval_view(digest, same) for digest, same in _grouped(records, lambda r: r.eval.digest).items()]

    def lookup(self, digest: str) -> dict | None:
        """What a 64-hex digest names: a system, eval, record, model or component, tried in that order."""
        params = {"digest": digest, "prefixed": DIGEST_PREFIX + digest, "role": MODEL_ROLE}
        with self._connect() as conn:
            for kind, sql in LOOKUPS:
                if conn.execute(sql, params).fetchone() is not None:
                    return {"kind": kind, "id": digest}
        return None

    def _component(self, digest: str, role: str | None) -> dict | None:
        with self._connect() as conn:
            records = _load(conn, COMPONENT_RECORDS, {"digest": digest, "prefixed": DIGEST_PREFIX + digest, "role": role})
        return _component_view(digest, role, records) if records else None

    @contextmanager
    def _connect(self):
        """One connection and one transaction: committed if the block succeeds, rolled back if it raises."""
        with closing(sqlite3.connect(self.path)) as conn:
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA foreign_keys = ON")
            with conn:
                yield conn


# --- rows --------------------------------------------------------------------

def _record_row(record: IndexedRecord) -> dict:
    """The records row for `record`. Its nested parts are stored as JSON, with the API's names."""
    data = record.model_dump(mode="json", by_alias=True)
    eval_, results = data["eval"], data["results"]
    return {
        "record_id": record.record_id, "predicate_type": record.predicate_type,
        "adapter_version": record.adapter_version, "state": record.state, "checks_json": _dumps(data["checks"]),
        "subject_name": record.subject_name, "system_digest": record.system_digest,
        "eval_digest": eval_["digest"], "eval_name": eval_["name"], "eval_public": eval_["public"],
        "eval_set_json": _dumps(eval_["evalSet"]), "harness_json": _dumps(eval_["harness"]),
        "harness_version": eval_["harnessVersion"], "metrics_json": _dumps(results["metrics"]),
        "counts_json": _dumps(results["counts"]), "scored": results["scored"],
        "parties_json": _dumps(data["parties"]), "consent_json": _dumps(data["consent"]),
        "benchmark_owner_key": record.benchmark_owner.public_key,
        "benchmark_owner_display": record.benchmark_owner.display,
        "enclave_json": _dumps(data["enclave"]), "reported_json": _dumps(data["reported"]),
        "received_at": record.received_at, "size": record.size,
    }


def _component_rows(record: IndexedRecord) -> list[tuple]:
    return [(record.record_id, c.role, c.scheme, c.digest, c.name,
             _dumps([alias.model_dump(by_alias=True) for alias in c.also_known_as])) for c in record.components]


def _record(row: sqlite3.Row, components: list[sqlite3.Row]) -> IndexedRecord:
    """The IndexedRecord that _record_row and _component_rows stored."""
    return IndexedRecord.model_validate({
        "recordId": row["record_id"], "size": row["size"], "receivedAt": row["received_at"], "state": row["state"],
        "checks": _loads(row["checks_json"]), "enclave": _loads(row["enclave_json"]),
        "benchmarkOwner": {"publicKey": row["benchmark_owner_key"], "display": row["benchmark_owner_display"]},
        "predicateType": row["predicate_type"], "adapterVersion": row["adapter_version"],
        "subjectName": row["subject_name"], "systemDigest": row["system_digest"],
        "components": [{"role": c["role"], "scheme": c["scheme"], "digest": c["digest"], "name": c["name"],
                        "alsoKnownAs": _loads(c["aka_json"])} for c in components],
        "eval": {"digest": row["eval_digest"], "evalSet": _loads(row["eval_set_json"]),
                 "harness": _loads(row["harness_json"]), "name": row["eval_name"],
                 "harnessVersion": row["harness_version"], "public": row["eval_public"]},
        "results": {"metrics": _loads(row["metrics_json"]), "counts": _loads(row["counts_json"]),
                    "scored": row["scored"]},
        "parties": _loads(row["parties_json"]), "consent": _loads(row["consent_json"]),
        "reported": _loads(row["reported_json"]),
    })


def _load(conn: sqlite3.Connection, sql: str, params=()) -> list[IndexedRecord]:
    """The records `sql` selects, in its order. `sql` is always one of this module's, never built from a request."""
    return [_record(row, conn.execute("SELECT * FROM components WHERE record_id = ? ORDER BY rowid",
                                      (row["record_id"],)).fetchall())
            for row in conn.execute(sql, params).fetchall()]


def _dumps(value) -> str | None:
    return None if value is None else json.dumps(value)


def _loads(text: str | None):
    return None if text is None else json.loads(text)


# --- views -------------------------------------------------------------------

def _component_view(digest: str, role: str | None, records: list[IndexedRecord]) -> dict:
    """A component's content digest and the records that list it, under any role (or only `role`).

    `digest` is bare hex. It matches a component's digest with any "sha256:" prefix removed, so one
    view can gather entries that records gave different roles or schemes.
    """
    same = [c for r in records for c in r.components
            if c.digest.removeprefix(DIGEST_PREFIX) == digest and role in (None, c.role)]
    return {"digest": digest, "roles": _distinct(c.role for c in same), "schemes": _distinct(c.scheme for c in same),
            **_labels(same), "state": _rollup(records),
            "systems": [{"digest": system, "subjectNames": _distinct(r.subject_name for r in group),
                         "state": _rollup(group)}
                        for system, group in _grouped(records, lambda r: r.system_digest).items()],
            "records": [r.to_json() for r in records]}


def _eval_view(digest: str, records: list[IndexedRecord]) -> dict:
    # All records here share this evalDigest. Check 5 recomputed it for each, so they all name the same
    # eval set and harness.
    first = records[0].eval
    return {"digest": digest, "evalSet": first.eval_set.model_dump(by_alias=True),
            "harness": first.harness.model_dump(by_alias=True),
            "names": _distinct(r.eval.name for r in records),
            "harnessVersions": _distinct(r.eval.harness_version for r in records),
            "publicFlags": _distinct(r.eval.public for r in records),
            "state": _rollup(records), "records": [r.to_json() for r in records]}


def _labels(components: list[Component]) -> dict:
    """Merge the labels that different records gave one component (the same role, scheme and digest).

    No digest covers names or aliases, so records can disagree on them. akaConflicts is true when one
    alias scheme was given more than one value, e.g. two OpenSSF Model Signing digests for the same weights.
    """
    aliases = _distinct(alias for c in components for alias in c.also_known_as)
    values: dict[str, set[str]] = {}
    for alias in aliases:
        values.setdefault(alias.scheme, set()).add(alias.value)
    return {"names": _distinct(c.name for c in components),
            "alsoKnownAs": [alias.model_dump(by_alias=True) for alias in aliases],
            "akaConflicts": any(len(same) > 1 for same in values.values())}


def _rollup(records: list[IndexedRecord]) -> str:
    """The worst state among the records: "verified" only if every record is verified."""
    return min((r.state for r in records), key=STATES.index)


def _distinct(values: Iterable) -> list:
    """The values in first-seen order, once each, without None.

    Not a set: its order varies between runs (string hashing is randomised), so the API output would too.
    """
    return list(dict.fromkeys(value for value in values if value is not None))


def _grouped(items: Iterable, key: Callable) -> dict:
    """{key: [items with that key]}, keys in first-seen order."""
    groups: dict = {}
    for item in items:
        groups.setdefault(key(item), []).append(item)
    return groups
