"""Receipt recognition: is this a syft-enclave receipt v3 statement in a DSSE envelope?

Anything unrecognised is a 400. Nothing here checks a signature (that is check 1), and
nothing is re-serialised: the receipt keeps the raw bytes exactly as received.
"""

import base64
import logging
import reprlib
from dataclasses import dataclass
from typing import Literal

import jiter
from pydantic import BaseModel, ConfigDict, Field, ValidationError
from sigstore_models.intoto import Envelope
from tinfoil.sigstore import reject_unknown_intoto_fields

from registry import spec

log = logging.getLogger(__name__)
_short = reprlib.Repr(maxstring=80).repr  # a received value, quoted back in a rejection message


class Unrecognized(ValueError):
    """Not a receipt this registry recognises (HTTP 400)."""


@dataclass(frozen=True)
class Receipt:
    raw: bytes  # the envelope exactly as received
    envelope: dict  # as parsed; check 1 verifies it with securesystemslib
    payload: bytes  # the statement bytes the signature covers
    statement: dict


class StatementHeader(BaseModel):
    """What makes a statement a syft-enclave receipt v3. The schema (syft_receipt.py) checks the rest."""

    model_config = ConfigDict(strict=True)
    type_: Literal[spec.STATEMENT_TYPE] = Field(alias="_type")
    predicateType: Literal[spec.PREDICATE_TYPE]
    predicate: dict


def parse_receipt(raw: bytes) -> Receipt:
    try:
        receipt = _parse(raw)
    except Unrecognized as e:
        log.debug("REJECT unrecognized receipt (%d bytes): %s", len(raw), e)
        raise
    log.debug("ACCEPT recognized receipt (%d bytes, payload %d bytes)", len(raw), len(receipt.payload))
    return receipt


def _parse(raw: bytes) -> Receipt:
    # 1. Envelope shape, with the upstream DSSE model. by_name=False insists on DSSE's own
    #    spellings (payloadType), which the model would otherwise also accept as payload_type.
    obj = _json(raw, "envelope")
    try:
        envelope = Envelope.model_validate(obj, by_alias=True, by_name=False)
    except ValidationError as e:
        raise _invalid("envelope", e) from e
    # The model allows several signatures; the MVP takes exactly one. keyid is an ignored hint.
    if len(envelope.signatures) != 1:
        raise Unrecognized(f"signatures must hold exactly one signature, got {len(envelope.signatures)}")

    # 2. Payload type.
    if envelope.payload_type != spec.PAYLOAD_TYPE:
        raise Unrecognized(f"payloadType must be {spec.PAYLOAD_TYPE!r}, got {_short(envelope.payload_type)}")

    # 3. Payload bytes. The model decodes base64 leniently (it drops invalid characters),
    #    so the payload must also be standard base64 as written.
    try:
        base64.b64decode(obj["payload"], validate=True)
    except ValueError as e:
        raise Unrecognized(f"payload is not standard base64: {e}") from e
    statement = _json(envelope.payload, "payload")

    # 5. Statement values, checked before 4 so a statement that isn't an object gets a clear error.
    try:
        StatementHeader.model_validate(statement)
    except ValidationError as e:
        raise _invalid("statement", e) from e

    # 4. Statement fields: only _type, subject, predicateType and predicate.
    try:
        reject_unknown_intoto_fields(statement)
    except Exception as e:  # it raises sigstore-python's VerificationError; we use sigstore only through tinfoil
        raise Unrecognized(str(e)) from e

    return Receipt(raw=raw, envelope=obj, payload=envelope.payload, statement=statement)


def _json(data: bytes, what: str) -> object:
    """Strict JSON: duplicate keys, NaN/Infinity, invalid UTF-8 and runaway nesting are all rejected."""
    try:
        return jiter.from_json(data, allow_inf_nan=False, catch_duplicate_keys=True)
    except ValueError as e:
        raise Unrecognized(f"{what} is not valid JSON: {e}") from e


def _invalid(what: str, error: ValidationError) -> Unrecognized:
    problems = []
    for e in error.errors():
        where = ".".join(str(part) for part in e["loc"])
        problem = f"{where}: {e['msg']}" if where else e["msg"]
        if e["type"] == "literal_error":  # name the value we got, not just the one we wanted
            problem += f", got {_short(e['input'])}"
        problems.append(problem)
    return Unrecognized(f"{what}: {'; '.join(problems)}")
