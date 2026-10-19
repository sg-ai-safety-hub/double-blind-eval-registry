"""Checks 1, 5 and 6.

Each check returns (status, detail) and the @check decorator makes it fail closed.
"""

import copy
import hashlib

import rfc8785
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from securesystemslib.dsse import Envelope
from securesystemslib.exceptions import VerificationError
from securesystemslib.signer import SSlibKey

from registry.config import Policy
from registry.model import Status, check
from registry.syft_receipt import Consent

# securesystemslib matches signatures to keys by keyid, and the receipt's keyid is an unauthenticated
# hint, so both the signature and the key get this constant one.
KEYID = "k"


# --- check 1 -----------------------------------------------------------------

@check("signature")
def check_signature(envelope: dict, signing_key: str):
    """Check 1: the DSSE signature over PAE(payloadType, payload) verifies under the enclave signing key.

    `signing_key` is crypto_material's signing key item (spec.SIGNING_KEY_ID), SPKI DER as hex. Check 2
    shows the hardware report binds it.
    """
    key = serialization.load_der_public_key(bytes.fromhex(signing_key))
    if not isinstance(key, Ed25519PublicKey):
        return Status.FAIL, "the enclave signing key must be an Ed25519 key"
    signed = copy.deepcopy(envelope)  # Envelope.from_dict rewrites each sig in place
    signed["signatures"][0]["keyid"] = KEYID  # recognition allows exactly one signature
    try:
        Envelope.from_dict(signed).verify([SSlibKey.from_crypto(key, keyid=KEYID)], 1)
    except VerificationError:
        return Status.FAIL, "the envelope signature does not verify under the enclave signing key"
    return Status.PASS, "envelope signature over PAE verifies under the enclave signing key"


# --- check 5 -----------------------------------------------------------------

@check("digests")
def check_digests(statement: dict):
    """Check 5: the subject digest is sha256(JCS) of predicate.evalPipeline.

    `statement` is the statement as parsed, not the schema's model, so every field counts as received,
    including ones the schema doesn't model. A list's order counts too.
    """
    pipeline = rfc8785.dumps(statement["predicate"]["evalPipeline"])  # rfc8785.dumps returns bytes
    if hashlib.sha256(pipeline).hexdigest() != statement["subject"][0]["digest"]["sha256"]:
        return Status.FAIL, "the subject digest is not sha256(JCS(evalPipeline))"
    return Status.PASS, "the subject digest is sha256(JCS(evalPipeline))"


# --- check 6 -----------------------------------------------------------------

@check("consent")
def check_consent(consent: Consent, policy: Policy):
    """Check 6: an approval comes from an email on this registry's list.

    Approvals carry no signature: OpenMined checks who owns each email before recording an approval,
    and the enclave signs the receipt. A listed email's owner is trusted to have approved with care.
    """
    owner = policy.first_listed(approval.party for approval in consent.approvals)
    if owner is None:
        return Status.FAIL, "no approval from an email on this registry's list"
    return Status.PASS, f"approved by {owner.email}, on this registry's list"
