"""Check 7: the receipt is logged on Rekor, Sigstore's public transparency log.

OpenMined's benchmark owner logs each receipt right after the run, as a Rekor v1 dsse entry whose verifier
is the enclave signing key (PySyft syft_enclaves/receipt/rekor.py). Rekor keeps the payload's hash, the
envelope's hash, the signature and the key, but not the receipt. This check searches Rekor by the payload's
hash, and PASSes when an entry holds this receipt's signature and signing key. The envelope hash isn't
compared: OpenMined logs the envelope re-serialised, so it isn't the record id.

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
# An entry's UUID: its leaf hash, after the tree id of its log shard when Rekor gives one. Checked before it
# goes into a URL.
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


SEARCH_ANSWER = TypeAdapter(list[Annotated[str, Field(strict=True, pattern=UUID)]])
ENTRY_ANSWER = TypeAdapter(dict[str, LogEntry])


def search_rekor(payload_sha256: str) -> bytes:
    """Ask Rekor's search index for the entries recording this payload hash. The answer, as received."""
    response = requests.post(f"{spec.REKOR_URL}/api/v1/index/retrieve", json={"hash": f"sha256:{payload_sha256}"},
                             timeout=TIMEOUT_SECONDS)
    response.raise_for_status()  # any failure is a network error: 503
    return response.content


def fetch_rekor_entry(uuid: str) -> bytes:
    """Fetch one entry from Rekor. The answer, as received."""
    response = requests.get(f"{spec.REKOR_URL}/api/v1/log/entries/{uuid}", timeout=TIMEOUT_SECONDS)
    response.raise_for_status()
    return response.content


def check_publication(receipt: Receipt, key_binding: KeyBinding) -> tuple[Check, Publication | None]:
    """Check 7, and where Rekor logs the receipt when it PASSes: the earliest entry that holds it."""
    if key_binding.cpu_evidence.report_base64.startswith(spec.SENTINEL_PREFIXES):
        # Test data: never logged on the public Rekor, so never looked up there.
        return Check(CHECK_ID, Status.PENDING, "no hardware report in this receipt, so it is not looked up on Rekor"), None
    payload_sha256 = hashlib.sha256(receipt.payload).hexdigest()
    try:
        signature = base64.b64decode(receipt.envelope["signatures"][0]["sig"], validate=True)
        key = bytes.fromhex(key_binding.signing_key)  # SPKI DER: the key check 1 verifies under
        uuids = SEARCH_ANSWER.validate_python(_json(search_rekor(payload_sha256)))
        log.debug("check 7: Rekor has %d entr(ies) for payload %s", len(uuids), payload_sha256)
        found = [publication for uuid in uuids
                 if (publication := _holding(fetch_rekor_entry(uuid), uuid, payload_sha256, signature, key))]
    except Exception as e:
        raise_if_network(e, "check 7")
        return Check(CHECK_ID, Status.FAIL, f"Rekor's answer could not be read: {e}"), None

    if not uuids:
        return Check(CHECK_ID, Status.FAIL, "Rekor has no entry for this receipt's payload"), None
    if not found:
        return Check(CHECK_ID, Status.FAIL, f"none of Rekor's {len(uuids)} entries for this payload holds this "
                                            "receipt's signature and signing key"), None
    earliest = min(found, key=lambda publication: publication.integrated_time)
    return Check(CHECK_ID, Status.PASS, f"logged on Rekor at index {earliest.log_index}"), earliest


def _holding(answer: bytes, uuid: str, payload_sha256: str, signature: bytes, key: bytes) -> Publication | None:
    """Where Rekor logs the receipt, if its `answer` for `uuid` is a dsse entry holding this receipt's payload
    hash, its one signature and its signing key. None otherwise, including for an answer that doesn't parse."""
    try:
        entries = ENTRY_ANSWER.validate_python(_json(answer))
        if list(entries) != [uuid]:
            log.debug("check 7: Rekor's answer for %s is keyed by %s", uuid, list(entries))
            return None
        entry = entries[uuid]
        body = DsseBody.model_validate(_json(base64.b64decode(entry.body, validate=True)))
        logged, = body.dsse.signatures
        verifier = serialization.load_pem_public_key(base64.b64decode(logged.verifier, validate=True))
        holds = (body.dsse.payloadHash.value == payload_sha256
                 and base64.b64decode(logged.signature, validate=True) == signature
                 and verifier.public_bytes(serialization.Encoding.DER,
                                           serialization.PublicFormat.SubjectPublicKeyInfo) == key)
    except ValueError as e:  # not a dsse entry this check can read; another entry may still hold the receipt
        log.debug("check 7: skipped Rekor entry %s: %s", uuid, e)
        return None
    log.debug("check 7: Rekor entry %s (index %d) %s this receipt", uuid, entry.logIndex,
              "holds" if holds else "does not hold")
    if not holds:
        return None
    return Publication(uuid=uuid, log_index=entry.logIndex, integrated_time=entry.integratedTime,
                       url=spec.REKOR_SEARCH_LINK.format(entry.logIndex))


def _json(data: bytes) -> object:
    """Strict JSON: duplicate keys and NaN/Infinity are rejected."""
    return jiter.from_json(data, allow_inf_nan=False, catch_duplicate_keys=True)
