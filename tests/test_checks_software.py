"""Checks 1, 5 and 6, on OpenMined's signed receipt and edits of it."""

import base64
import copy
import hashlib
import json
from pathlib import Path

import pytest
import rfc8785
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from securesystemslib.dsse import Envelope
from securesystemslib.signer import Signature

from registry import spec
from registry.checks_software import check_consent, check_digests, check_signature
from registry.config import Policy
from registry.envelope import parse_receipt
from registry.model import Status
from registry.syft_receipt import parse_statement

OPENMINED = Path(__file__).resolve().parents[1] / "fixtures/openmined/receipt.dsse.json"
LISTED = "benchmark_owner@openmined.org"  # OpenMined's sample benchmark owner, the receipt's first approver
SUBJECT = "a93b956ccd36eedcf5f0b3d40eb86f8e7ab7c0c4b320a88f9fbdf74f5ea3ff4c"  # computed by OpenMined, not by us


def openmined():
    receipt = parse_receipt(OPENMINED.read_bytes())
    return receipt, parse_statement(receipt.statement)


def signing_key() -> str:
    return openmined()[1].predicate.execution.attestation.keyBinding.signing_key


def spki_hex(private_key) -> str:
    return private_key.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo).hex()


def signed_envelope(sign, payload: bytes = b"{}") -> dict:
    """A DSSE envelope over `payload`, signed by `sign(pae)`. Check 1 never parses the payload."""
    env = Envelope(payload=payload, payload_type=spec.PAYLOAD_TYPE, signatures={})
    env.signatures["hint"] = Signature("hint", sign(env.pae()).hex())
    return env.to_dict()


# --- check 1: signature ------------------------------------------------------------

def test_signature_verifies_under_the_enclave_signing_key():
    receipt, statement = openmined()
    check = check_signature(receipt.envelope, signing_key())
    assert (check.id, check.status) == ("signature", Status.PASS)
    assert check.detail == "envelope signature over PAE verifies under the enclave signing key"


def test_signature_fails_when_the_payload_was_edited_after_signing():
    receipt, _ = openmined()
    edited = copy.deepcopy(receipt.envelope)
    statement = copy.deepcopy(receipt.statement)
    statement["predicate"]["results"]["metrics"][2]["value"] = 0.0
    edited["payload"] = base64.b64encode(json.dumps(statement).encode()).decode()
    check = check_signature(edited, signing_key())
    assert (check.status, check.detail) == (
        Status.FAIL, "the envelope signature does not verify under the enclave signing key")


def test_signature_fails_for_another_signer():
    receipt, _ = openmined()
    other = Ed25519PrivateKey.generate()
    envelope = signed_envelope(other.sign, base64.b64decode(receipt.envelope["payload"]))
    assert check_signature(envelope, signing_key()).status is Status.FAIL
    assert check_signature(envelope, spki_hex(other)).status is Status.PASS  # the envelope itself is fine


def test_signature_needs_an_ed25519_key():
    key = ec.generate_private_key(ec.SECP256R1())
    check = check_signature(signed_envelope(lambda pae: key.sign(pae, ec.ECDSA(hashes.SHA256()))), spki_hex(key))
    assert (check.status, check.detail) == (Status.FAIL, "the enclave signing key must be an Ed25519 key")


def test_signature_needs_the_key_as_spki_der_not_raw_bytes():
    key = Ed25519PrivateKey.generate()
    check = check_signature(signed_envelope(key.sign), key.public_key().public_bytes_raw().hex())
    assert check.status is Status.FAIL


def test_signature_fails_closed_on_a_signing_key_that_is_no_key():
    receipt, _ = openmined()
    check = check_signature(receipt.envelope, "00" * 40)
    assert (check.id, check.status) == ("signature", Status.FAIL)


@pytest.mark.parametrize("keyid", ["something else", None])
def test_signature_ignores_the_keyid_hint(keyid):
    receipt, _ = openmined()
    envelope = copy.deepcopy(receipt.envelope)
    if keyid is None:
        del envelope["signatures"][0]["keyid"]
    else:
        envelope["signatures"][0]["keyid"] = keyid
    assert check_signature(envelope, signing_key()).status is Status.PASS


def test_signature_leaves_the_envelope_unchanged():
    # securesystemslib's Envelope.from_dict rewrites each sig in place; the receipt's dict must not change.
    receipt, _ = openmined()
    before = copy.deepcopy(receipt.envelope)
    check_signature(receipt.envelope, signing_key())
    assert receipt.envelope == before


# --- check 5: digests ----------------------------------------------------------------

def statement() -> dict:
    return copy.deepcopy(openmined()[0].statement)


def test_the_subject_digest_is_sha256_of_jcs_of_the_eval_pipeline():
    # OpenMined computed the subject digest independently of this code, so it is a test vector.
    check = check_digests(statement())
    assert (check.id, check.status) == ("digests", Status.PASS)
    assert check.detail == "the subject digest is sha256(JCS(evalPipeline))"
    assert statement()["subject"][0]["digest"]["sha256"] == SUBJECT


@pytest.mark.parametrize("edit", ["model-digest", "extra-field", "model-order", "subject"])
def test_digests_fail_when_the_pipeline_or_subject_differs(edit):
    s = statement()
    pipeline = s["predicate"]["evalPipeline"]
    if edit == "model-digest":
        pipeline["models"][1]["digest"] = "00" * 32
    elif edit == "extra-field":  # every field counts, including ones the schema doesn't model
        pipeline["config"][0]["params"]["temperature"] = 0.0
    elif edit == "model-order":  # a list: order counts
        pipeline["models"].reverse()
    else:
        s["subject"][0]["digest"]["sha256"] = "00" * 32
    check = check_digests(s)
    assert (check.status, check.detail) == (Status.FAIL, "the subject digest is not sha256(JCS(evalPipeline))")


def test_digests_hash_jcs_not_another_serialisation():
    pipeline = statement()["predicate"]["evalPipeline"]
    assert hashlib.sha256(rfc8785.dumps(pipeline)).hexdigest() == SUBJECT
    assert hashlib.sha256(json.dumps(pipeline, sort_keys=True).encode()).hexdigest() != SUBJECT


# --- check 6: consent ------------------------------------------------------------------

def policy(*emails: str) -> Policy:
    return Policy.model_validate({
        "trusted_code": [{"repo": "OpenMined/syft-enclave-tinfoil"}],
        "benchmark_owners": [{"email": email, "display": f"{email} on the list"} for email in emails],
    })


def consent(*parties: str):
    s = statement()
    s["predicate"]["consent"]["approvals"] = [{"party": party} for party in parties]
    return parse_statement(s).predicate.consent


def test_consent_passes_for_an_approval_from_a_listed_email():
    check = check_consent(openmined()[1].predicate.consent, policy(LISTED))
    assert (check.id, check.status) == ("consent", Status.PASS)
    assert check.detail == f"approved by {LISTED}, on this registry's list"


def test_consent_names_the_first_listed_approver_in_receipt_order():
    check = check_consent(consent("x@example.org", "b@example.org", "a@example.org"),
                          policy("a@example.org", "b@example.org"))
    assert check.detail == "approved by b@example.org, on this registry's list"


@pytest.mark.parametrize("parties", [("x@example.org",), (LISTED.upper(),), (f" {LISTED}",), (LISTED + ".evil",)],
                         ids=["unlisted", "other-case", "padded", "longer"])
def test_consent_fails_without_an_approval_from_a_listed_email(parties):
    # Matched exactly: OpenMined vouches for the exact string it recorded.
    check = check_consent(consent(*parties), policy(LISTED))
    assert (check.status, check.detail) == (Status.FAIL, "no approval from an email on this registry's list")


def test_consent_fails_when_nobody_is_listed():
    assert check_consent(openmined()[1].predicate.consent, policy()).status is Status.FAIL
