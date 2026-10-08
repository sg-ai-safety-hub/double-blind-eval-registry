"""Ingest one receipt: recognise, validate, check, decide, store, index. And rebuild the index from the store.

Nothing is stored unless the receipt is accepted, and what is stored is exactly the bytes received.
"""

import hashlib
import logging
import os
import tempfile
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path

from registry import checks_software, checks_tinfoil, evalresult, policy, spec
from registry.config import Config, Policy
from registry.envelope import Receipt, Unrecognized, parse_receipt
from registry.evalresult import TIMESTAMP_FORMAT, SchemaError, Statement, parse_statement
from registry.index import Index, IndexedRecord
from registry.model import Accepted, IngestResult, VerificationResult, VerificationUnavailable
from registry.refcache import RefCache
from registry.store import Corrupt, Store

log = logging.getLogger(__name__)


def verify(receipt: Receipt, statement: Statement, trust: Policy, refcache: RefCache) -> VerificationResult:
    """Checks 1-7, in order. Raises VerificationUnavailable on a network error."""
    predicate = statement.predicate
    execution = predicate.execution
    hardware, enclave = checks_tinfoil.check_attestation(execution.attestation, execution.runPublicKey,
                                                         trust.trusted_code, refcache)
    checks = (
        checks_software.check_signature(receipt.envelope, execution.runPublicKey),
        *hardware,
        checks_software.check_digests(statement),
        checks_software.check_publication(),
        checks_software.check_consent(predicate),
    )
    return VerificationResult(checks, enclave)


def assess(raw: bytes, config: Config, refcache: RefCache, received_at: str) -> IngestResult | IndexedRecord:
    """The record to index, or the refusal. Stores nothing.

    Raises VerificationUnavailable on a network error: then there is no verdict at all.
    """
    record_id = hashlib.sha256(raw).hexdigest()
    try:
        receipt = parse_receipt(raw)
    except Unrecognized as e:
        return IngestResult(400, {"recordId": record_id, "detail": f"unrecognized receipt: {e}"})
    try:
        statement = parse_statement(receipt.statement)
    except SchemaError as e:
        return IngestResult(422, {"recordId": record_id, "detail": "the statement violates the schema",
                                  "schemaErrors": e.errors})

    result = verify(receipt, statement, config.policy, refcache)
    checks = result.checks
    for c in checks:
        log.debug("record %s: %s %s (%s)", record_id, c.id, c.status, c.detail)
    # The acceptance gate matches the benchmark owner's key, not the model owner's: the registry lists
    # evaluations run by benchmark owners on its list. The model owner's key only counts in check 7.
    owner_key = statement.predicate.owner_key(spec.BENCHMARK_OWNER)
    decision = policy.decide(config.mode, config.policy, owner_key, checks)
    if decision.state is None:
        return IngestResult(decision.status, {"recordId": record_id, "checks": [asdict(c) for c in checks],
                                              "benchmarkOwner": {"publicKey": owner_key}, "detail": decision.detail})
    accepted = Accepted(record_id=record_id, size=len(raw), received_at=received_at, state=decision.state,
                        checks=checks, enclave=result.enclave, benchmark_owner_display=decision.display)
    return evalresult.to_index(statement, accepted)


def ingest(raw: bytes, config: Config, store: Store, index: Index, refcache: RefCache) -> IngestResult:
    """POST /api/records: assess the receipt, then store and index it if it is accepted."""
    record_id = hashlib.sha256(raw).hexdigest()
    # A record stored before keeps its first receipt time, even if a rebuild has since left it out of the index.
    meta = store.read_meta(record_id)
    received_at = meta["receivedAt"] if meta else datetime.now(UTC).strftime(TIMESTAMP_FORMAT)
    try:
        assessed = assess(raw, config, refcache, received_at)
    except VerificationUnavailable as e:
        return IngestResult(503, {"recordId": record_id, "detail": f"verification unavailable, try again later: {e}"})
    if isinstance(assessed, IngestResult):
        return assessed

    store.put_record(raw, received_at)
    if index.add(assessed):
        log.debug("ACCEPT record %s (%d bytes): %s, 201", record_id, len(raw), assessed.state)
        return IngestResult(201, assessed.to_json())
    log.debug("ACCEPT record %s (%d bytes): already indexed, 200", record_id, len(raw))
    return IngestResult(200, index.get(record_id).to_json())


def rebuild(config: Config, store: Store, refcache: RefCache) -> tuple[int, list[tuple[str, str]]]:
    """Re-assess every stored record under the current policy and mode into a new index, then swap it in.

    Returns how many records were indexed, and (record id, why) for each one left out: one the policy now
    refuses, or one whose stored bytes no longer hash to its id. Either stays in the store but leaves the
    index. If anything raises, VerificationUnavailable included, the old index stays.
    """
    path = config.index_path
    path.parent.mkdir(parents=True, exist_ok=True)
    indexed, skipped = 0, []
    # Built beside the old index, then moved over it, so a reader never sees a half-built index.
    with tempfile.NamedTemporaryFile(dir=path.parent, prefix=f".{path.name}.", delete_on_close=False) as f:
        f.close()
        new = Index.create(Path(f.name), config.policy_sha256, config.mode)
        for record_id in store.record_ids():
            try:
                raw = store.read_record(record_id)
            except Corrupt:  # not the bytes received, so never listed; one such file mustn't block the rest
                why = "its stored bytes no longer hash to its id"
            else:
                assessed = assess(raw, config, refcache, store.read_meta(record_id)["receivedAt"])
                if not isinstance(assessed, IngestResult):
                    new.add(assessed)
                    indexed += 1
                    continue
                why = f"{assessed.status} {assessed.body['detail']}"
            log.debug("REJECT record %s on rebuild: %s", record_id, why)
            skipped.append((record_id, why))
        os.replace(f.name, path)  # a temp file that wasn't moved is deleted when the block exits
    log.debug("rebuilt index %s: %d indexed, %d left out", path, indexed, len(skipped))
    return indexed, skipped
