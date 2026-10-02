"""Checks 1, 5, 6 (always N/A) and 7.

Each check returns (status, detail) and the @check decorator makes it fail closed.
"""

import base64
import copy
import hashlib

import rfc8785
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from securesystemslib.dsse import Envelope
from securesystemslib.exceptions import VerificationError
from securesystemslib.signer import SSlibKey

from registry import spec
from registry.evalresult import Predicate, Statement
from registry.model import Status, check

# securesystemslib matches signatures to keys by keyid, and the receipt's keyid is an unauthenticated
# hint, so both the signature and the key get this constant one.
KEYID = "k"


# --- check 1 -----------------------------------------------------------------

@check("signature")
def check_signature(envelope: dict, run_public_key: str):
    """Check 1: the DSSE signature over PAE(payloadType, payload) verifies under runPublicKey."""
    key = _run_key(bytes.fromhex(run_public_key))
    if key is None:
        return Status.FAIL, "runPublicKey must be an Ed25519, EC P-256 or EC P-384 key"
    signed = copy.deepcopy(envelope)  # Envelope.from_dict rewrites each sig in place
    signed["signatures"][0]["keyid"] = KEYID  # recognition allows exactly one signature
    try:
        Envelope.from_dict(signed).verify([SSlibKey.from_crypto(key, keyid=KEYID)], 1)
    except VerificationError:
        return Status.FAIL, "the envelope signature does not verify under runPublicKey"
    return Status.PASS, "envelope signature over PAE verifies under runPublicKey"


def _run_key(key_bytes: bytes):
    """runPublicKey as a key: 32 bytes are a raw Ed25519 key, anything else SPKI DER.

    None for any key type but Ed25519, EC P-256 and EC P-384, even ones securesystemslib supports.
    """
    if len(key_bytes) == 32:
        return Ed25519PublicKey.from_public_bytes(key_bytes)
    key = serialization.load_der_public_key(key_bytes)
    if isinstance(key, Ed25519PublicKey):
        return key
    if isinstance(key, ec.EllipticCurvePublicKey) and isinstance(key.curve, (ec.SECP256R1, ec.SECP384R1)):
        return key
    return None


# --- check 5 -----------------------------------------------------------------

@check("digests")
def check_digests(statement: Statement):
    """Check 5: pipelineDigest and evalDigest recompute, and the subject is the pipelineDigest."""
    system, eval_ = statement.predicate.system, statement.predicate.eval
    problems = []
    if pipeline_digest([c.model_dump() for c in system.components]) != system.pipelineDigest:
        problems.append("pipelineDigest does not recompute")
    if statement.subject[0].digest.sha256 != system.pipelineDigest:
        problems.append("the subject digest is not the pipelineDigest")
    if eval_digest(eval_.evalSet.model_dump(), eval_.harness.model_dump()) != eval_.evalDigest:
        problems.append("evalDigest does not recompute")
    if problems:
        return Status.FAIL, "; ".join(problems)
    return Status.PASS, "pipelineDigest and evalDigest recompute, and the subject is the pipelineDigest"


def pipeline_digest(components: list[dict]) -> str:
    """sha256(JCS) over every component, each reduced to {role, scheme, digest}.

    Sorted by (role, scheme, digest) as UTF-8 bytes. Sorting by role only gives the same result
    whenever roles are unique, but leaves two same-role components unordered.
    """
    reduced = sorted(
        ({"role": c["role"], "scheme": c["scheme"], "digest": c["digest"]} for c in components),
        key=lambda c: (c["role"].encode(), c["scheme"].encode(), c["digest"].encode()),
    )
    return _jcs_sha256({"schema": spec.PIPELINE_SCHEMA, "components": reduced})


def eval_digest(eval_set: dict, harness: dict) -> str:
    """sha256(JCS) over the eval set and harness, each reduced to {scheme, digest}."""
    return _jcs_sha256({
        "schema": spec.EVAL_SCHEMA,
        "evalSet": {"scheme": eval_set["scheme"], "digest": eval_set["digest"]},
        "harness": {"scheme": harness["scheme"], "digest": harness["digest"]},
    })


def _jcs_sha256(obj: dict) -> str:
    return hashlib.sha256(rfc8785.dumps(obj)).hexdigest()  # rfc8785.dumps returns bytes


# --- check 6 -----------------------------------------------------------------

@check("publication")
def check_publication():
    """Check 6 is deferred: the MVP verifies no Sigstore publication."""
    return Status.NA, "publication not verified in this version"


# --- check 7 -----------------------------------------------------------------

@check("consent")
def check_consent(predicate: Predicate):
    """Check 7, in DBE's format: one approval from each owner, signed with that owner's key.

    Exactly these two approvals, nothing else. The schema guarantees one party per
    owner role, each with its own Ed25519 key.
    """
    consent = predicate.consent
    if consent is None:
        return Status.NA, "no consent in this receipt"  # the acceptance gate then refuses it

    owners = (spec.MODEL_OWNER, spec.BENCHMARK_OWNER)
    parties = [approval.party for approval in consent.approvals]
    if sorted(parties) != sorted(owners):
        return Status.FAIL, (f"needs exactly one approval from each of {owners[0]} and {owners[1]}, "
                             f"got {', '.join(parties) or 'none'}")

    message = spec.CONSENT_PREFIX + consent.manifestDigest.encode("ascii")
    problems = []
    for approval in consent.approvals:
        key = predicate.owner_key(approval.party)
        if approval.publicKey != key:
            problems.append(f"the {approval.party} approval's key is not the {approval.party} party's key")
        elif not _approval_verifies(key, approval.signature, message):
            problems.append(f"the {approval.party} approval's signature does not verify")
    if problems:
        return Status.FAIL, "; ".join(problems)
    return Status.PASS, (f"{spec.CONSENT_ALGORITHM} approvals from {spec.MODEL_OWNER} and {spec.BENCHMARK_OWNER} "
                         "verify over manifestDigest")


def _approval_verifies(public_key: str, signature: str, message: bytes) -> bool:
    try:
        key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key))
        key.verify(base64.b64decode(signature, validate=True), message)
    except (ValueError, InvalidSignature):  # bad base64 (binascii.Error is a ValueError), or a bad signature
        return False
    return True
