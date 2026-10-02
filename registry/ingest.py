"""Ingest one receipt: recognise, validate, check, decide, store.

Nothing is stored unless the receipt is accepted, and what is stored is exactly the bytes received.
"""

import hashlib
import logging
from dataclasses import asdict
from datetime import UTC, datetime

from registry import checks_software, checks_tinfoil, policy, spec
from registry.config import Config, Policy
from registry.envelope import Receipt, Unrecognized, parse_receipt
from registry.evalresult import TIMESTAMP_FORMAT, SchemaError, Statement, parse_statement
from registry.model import IngestResult, VerificationResult, VerificationUnavailable
from registry.refcache import RefCache
from registry.store import Store

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


def ingest(raw: bytes, config: Config, store: Store, refcache: RefCache) -> IngestResult:
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

    try:
        result = verify(receipt, statement, config.policy, refcache)
    except VerificationUnavailable as e:
        return IngestResult(503, {"recordId": record_id, "detail": f"verification unavailable, try again later: {e}"})
    checks = result.checks
    for c in checks:
        log.debug("record %s: %s %s (%s)", record_id, c.id, c.status, c.detail)
    # The acceptance gate matches the benchmark owner's key, not the model owner's: the registry lists
    # evaluations run by benchmark owners on its list. The model owner's key only counts in check 7.
    owner_key = statement.predicate.owner_key(spec.BENCHMARK_OWNER)
    decision = policy.decide(config.mode, config.policy, owner_key, checks)
    owner = {"publicKey": owner_key}
    if decision.display is not None:
        owner["display"] = decision.display
    body = {"recordId": record_id, "checks": [asdict(c) for c in checks], "benchmarkOwner": owner}
    if decision.state is None:
        return IngestResult(decision.status, {**body, "detail": decision.detail})

    # No index yet, so the store says whether this record is already on file.
    status = 200 if store.read_meta(record_id) is not None else 201
    store.put_record(raw, datetime.now(UTC).strftime(TIMESTAMP_FORMAT))  # keeps the first receivedAt
    log.debug("ACCEPT record %s (%d bytes): %s, %d", record_id, len(raw), decision.state, status)
    body = {**body, "state": decision.state, "receivedAt": store.read_meta(record_id)["receivedAt"]}
    if result.enclave is not None:  # verified facts only, once checks 3 and 4 PASS
        enclave = result.enclave
        body["enclave"] = {"type": enclave.type, "measurement": enclave.measurement, "repo": enclave.repo,
                           "releaseTag": enclave.release_tag, "releaseDigest": enclave.release_digest}
    return IngestResult(status, body)
