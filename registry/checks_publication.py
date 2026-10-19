"""Check 7: the receipt is logged on Rekor, Sigstore's public transparency log.

OpenMined's benchmark owner logs each receipt right after the run, as a Rekor v1 dsse entry whose verifier
is the enclave signing key (PySyft syft_enclaves/receipt/rekor.py). Rekor keeps the payload's hash, the
envelope's hash, the signature and the key, but not the receipt. The submitter gives the entry's log index
with the receipt; this check fetches that entry, and PASSes when it holds this receipt's payload hash,
signature and signing key. The envelope hash isn't compared: OpenMined logs the envelope re-serialised, so
it isn't the record id. Rekor's search API isn't used: it is best-effort, and Rekor v2 drops it.

It trusts Rekor's answer over HTTPS. The entry's signed timestamp and inclusion proof are not verified:
sigstore-python verifies them only inside certificate-signed bundles, and the rest of its code for them is
private. Nor does it say who logged the receipt: anyone holding it could have.

A network error raises VerificationUnavailable; any other failure is a FAIL.
"""

import base64
import hashlib
import logging
from typing import Annotated, Literal

import jiter
import requests
from cryptography.hazmat.primitives import serialization
from pydantic import BaseModel, ConfigDict, Field, TypeAdapter

from registry import spec
from registry.checks_tinfoil import raise_if_network
from registry.envelope import Receipt
from registry.model import Check, Publication, Status
from registry.syft_receipt import KeyBinding

log = logging.getLogger(__name__)

CHECK_ID = "publication"
TIMEOUT_SECONDS = 15  # as refcache's fetch
NOT_FOUND = 404  # Rekor has no entry at that index: a FAIL, not a network error
# An entry's UUID: its leaf hash, after the tree id of its log shard when Rekor gives one.
UUID = r"^(?:[0-9a-f]{16})?[0-9a-f]{64}$"


class _Model(BaseModel):
    model_config = ConfigDict(strict=True, extra="allow")  # Rekor's other fields are never read


class LogEntry(_Model):
    body: str  # standard base64 of the entry's JSON
    integratedTime: int  # Rekor's clock, in Unix seconds
    logIndex: int


class PayloadHash(_Model):
    algorithm: Literal["sha256"]
    value: str


class Signature(_Model):
    signature: str  # standard base64
    verifier: str  # standard base64 of a PEM public key


class DsseSpec(_Model):
    payloadHash: PayloadHash
    signatures: list[Signature] = Field(min_length=1, max_length=1)


class DsseBody(_Model):
    apiVersion: Literal[spec.REKOR_ENTRY_API_VERSION]
    kind: Literal[spec.REKOR_ENTRY_KIND]
    dsse: DsseSpec = Field(alias="spec")


ENTRY_ANSWER = TypeAdapter(dict[Annotated[str, Field(pattern=UUID)], LogEntry])


def fetch_rekor_entry(log_index: int) -> bytes | None:
    """Fetch the entry at `log_index` from Rekor: the answer as received, or None if Rekor has none there."""
    response = requests.get(f"{spec.REKOR_URL}/api/v1/log/entries", params={"logIndex": log_index},
                            timeout=TIMEOUT_SECONDS)
    if response.status_code == NOT_FOUND:
        return None
    response.raise_for_status()  # any other failure is a network error: 503
    return response.content


def check_publication(receipt: Receipt, key_binding: KeyBinding, log_index: int | None) -> tuple[Check, Publication | None]:
    """Check 7, on the entry at the submitted `log_index`, and where Rekor logs the receipt when it PASSes."""
    if key_binding.cpu_evidence.report_base64.startswith(spec.SENTINEL_PREFIXES):
        # Test data: never logged on the public Rekor, so never looked up there.
        return Check(CHECK_ID, Status.PENDING, "no hardware report in this receipt, so it is not looked up on Rekor"), None
    if log_index is None:  # ingest refuses this with a 400 before any check runs
        return Check(CHECK_ID, Status.FAIL, "no Rekor log index was given"), None
    try:
        answer = fetch_rekor_entry(log_index)
        if answer is None:
            return Check(CHECK_ID, Status.FAIL, f"Rekor has no entry at index {log_index}"), None
        publication = _holding(answer, log_index, receipt, key_binding)
    except Exception as e:
        raise_if_network(e, "check 7")
        return Check(CHECK_ID, Status.FAIL, f"Rekor's entry at index {log_index} could not be read: {e}"), None
    if publication is None:
        return Check(CHECK_ID, Status.FAIL, f"Rekor's entry at index {log_index} does not hold this receipt's "
                                            "signature and signing key"), None
    return Check(CHECK_ID, Status.PASS, f"logged on Rekor at index {log_index}"), publication


def _holding(answer: bytes, log_index: int, receipt: Receipt, key_binding: KeyBinding) -> Publication | None:
    """Where Rekor logs the receipt, if its `answer` is the dsse entry at `log_index` and holds this receipt's
    payload hash, its one signature and its signing key; None if the entry holds something else.

    Raises ValueError for an answer that isn't one readable dsse entry at that index.
    """
    entries = ENTRY_ANSWER.validate_python(_json(answer))
    if len(entries) != 1:
        raise ValueError(f"expected one entry, got {len(entries)}")
    (uuid, entry), = entries.items()
    if entry.logIndex != log_index:
        raise ValueError(f"Rekor answered with the entry at index {entry.logIndex}")
    body = DsseBody.model_validate(_json(base64.b64decode(entry.body, validate=True)))
    logged, = body.dsse.signatures
    verifier = serialization.load_pem_public_key(base64.b64decode(logged.verifier, validate=True))
    holds = (body.dsse.payloadHash.value == hashlib.sha256(receipt.payload).hexdigest()
             and base64.b64decode(logged.signature, validate=True)
             == base64.b64decode(receipt.envelope["signatures"][0]["sig"], validate=True)
             and verifier.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
             == bytes.fromhex(key_binding.signing_key))  # SPKI DER: the key check 1 verifies under
    log.debug("check 7: Rekor entry %s at index %d %s this receipt", uuid, log_index,
              "holds" if holds else "does not hold")
    if not holds:
        return None
    return Publication(uuid=uuid, log_index=entry.logIndex, integrated_time=entry.integratedTime,
                       url=spec.REKOR_SEARCH_LINK.format(entry.logIndex))


def _json(data: bytes) -> object:
    """Strict JSON: duplicate keys and NaN/Infinity are rejected."""
    return jiter.from_json(data, allow_inf_nan=False, catch_duplicate_keys=True)
