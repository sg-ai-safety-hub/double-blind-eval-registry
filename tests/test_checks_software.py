import copy
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from fixture_data import record
from securesystemslib.dsse import Envelope
from securesystemslib.signer import Signature

from registry import spec
from registry.checks_software import (
    check_consent,
    check_digests,
    check_publication,
    check_signature,
    eval_digest,
    pipeline_digest,
)
from registry.envelope import parse_receipt
from registry.evalresult import parse_statement
from registry.model import Status

WORKED_EXAMPLE = Path(__file__).resolve().parents[1] / "fixtures/evalresult/worked_example.statement.json"
ADAPTERS = [
    {"role": "adapter", "scheme": "dirhash-sha256/1", "digest": "bb" * 32},
    {"role": "adapter", "scheme": "dirhash-sha256/1", "digest": "aa" * 32},
]


def predicate() -> dict:
    return json.loads(WORKED_EXAMPLE.read_text())["predicate"]


def test_worked_example_digests_recompute():
    # The worked example's digests were computed independently of this code, so they are a test vector.
    p = predicate()
    assert pipeline_digest(p["system"]["components"]) == p["system"]["pipelineDigest"]
    assert eval_digest(p["eval"]["evalSet"], p["eval"]["harness"]) == p["eval"]["evalDigest"]


def test_two_components_with_the_same_role_hash_the_same_in_either_order():
    # Sorting by role alone leaves these two unordered; (role, scheme, digest) does not.
    components = predicate()["system"]["components"]
    assert pipeline_digest(components + ADAPTERS) == pipeline_digest(components + ADAPTERS[::-1])
    assert pipeline_digest(components + ADAPTERS) == pipeline_digest((components + ADAPTERS)[::-1])


def test_labels_do_not_change_the_pipeline_digest():
    components = predicate()["system"]["components"]
    relabelled = copy.deepcopy(components)
    relabelled[0]["name"] = "another label"
    relabelled[1]["alsoKnownAs"].append({"scheme": "oms/1", "digest": "cc" * 32})
    assert pipeline_digest(relabelled) == pipeline_digest(components)


def test_every_component_counts_even_an_unregistered_role():
    components = predicate()["system"]["components"]
    extra = components + [{"role": "something-new", "scheme": "file-sha256/1", "digest": "dd" * 32}]
    assert pipeline_digest(extra) != pipeline_digest(components)


def test_eval_digest_reduces_eval_set_and_harness_to_scheme_and_digest():
    # evalDigest hashes only {scheme, digest}; extra fields such as a name must not count.
    p = predicate()
    named_set = {**p["eval"]["evalSet"], "name": "a label"}
    assert eval_digest(named_set, p["eval"]["harness"]) == p["eval"]["evalDigest"]


# --- helpers for checks 1, 5 and 7 ----------------------------------------------

def parsed(name: str):
    receipt = parse_receipt(record(name))
    return receipt, parse_statement(receipt.statement)


def statement_of(name: str) -> dict:
    """A fixture's statement as a dict, to change and re-validate (checks 5 and 7 never look at the signature)."""
    return copy.deepcopy(parse_receipt(record(name)).statement)


def signature_check(name: str):
    receipt, statement = parsed(name)
    return check_signature(receipt.envelope, statement.predicate.execution.runPublicKey)


def consent_check(statement: dict):
    return check_consent(parse_statement(statement).predicate)


def signed_envelope(sign) -> dict:
    """A DSSE envelope over an arbitrary payload, signed by `sign(pae)`. Check 1 never parses the payload."""
    env = Envelope(payload=b"{}", payload_type=spec.PAYLOAD_TYPE, signatures={})
    env.signatures["hint"] = Signature("hint", sign(env.pae()).hex())
    return env.to_dict()


def spki_hex(private_key) -> str:
    return private_key.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo).hex()


# --- check 1: signature ------------------------------------------------------------

@pytest.mark.parametrize("name", ["sim_A", "sim_A_ec"])
def test_signature_verifies_under_run_public_key(name):
    # sim_A's runPublicKey is a raw Ed25519 key; sim_A_ec's is EC P-256 as SPKI DER, with a DER ECDSA signature.
    check = signature_check(name)
    assert (check.id, check.status) == ("signature", Status.PASS)
    assert check.detail == "envelope signature over PAE verifies under runPublicKey"


@pytest.mark.parametrize("name", ["C1_edit_after_sign", "C2_other_signer"])
def test_signature_fails_when_the_payload_or_signer_differs(name):
    check = signature_check(name)
    assert check.status is Status.FAIL
    assert "does not verify under runPublicKey" in check.detail


def test_signature_verifies_an_ec_p384_key():
    key = ec.generate_private_key(ec.SECP384R1())
    envelope = signed_envelope(lambda pae: key.sign(pae, ec.ECDSA(hashes.SHA384())))
    assert check_signature(envelope, spki_hex(key)).status is Status.PASS


def test_signature_verifies_an_ed25519_key_given_as_spki_der():
    key = Ed25519PrivateKey.generate()
    assert check_signature(signed_envelope(key.sign), spki_hex(key)).status is Status.PASS


@pytest.mark.parametrize("key, sign", [
    (ec.generate_private_key(ec.SECP521R1()), lambda key, pae: key.sign(pae, ec.ECDSA(hashes.SHA512()))),
    (rsa.generate_private_key(public_exponent=65537, key_size=2048),
     lambda key, pae: key.sign(pae, padding.PSS(padding.MGF1(hashes.SHA256()), padding.PSS.MAX_LENGTH), hashes.SHA256())),
], ids=["p521", "rsa"])
def test_signature_fails_for_key_types_other_than_ed25519_p256_p384(key, sign):
    # securesystemslib would verify both; the registry allows only Ed25519, P-256 and P-384.
    check = check_signature(signed_envelope(lambda pae: sign(key, pae)), spki_hex(key))
    assert check.status is Status.FAIL
    assert "must be an Ed25519, EC P-256 or EC P-384 key" in check.detail


def test_signature_fails_closed_on_a_run_public_key_that_is_no_key():
    receipt, _ = parsed("sim_A")
    check = check_signature(receipt.envelope, "00" * 40)
    assert (check.id, check.status) == ("signature", Status.FAIL)


@pytest.mark.parametrize("keyid", ["something else", None])
def test_signature_ignores_the_keyid_hint(keyid):
    receipt, statement = parsed("sim_A")
    envelope = copy.deepcopy(receipt.envelope)
    if keyid is None:
        del envelope["signatures"][0]["keyid"]
    else:
        envelope["signatures"][0]["keyid"] = keyid
    assert check_signature(envelope, statement.predicate.execution.runPublicKey).status is Status.PASS


def test_signature_leaves_the_envelope_unchanged():
    # securesystemslib's Envelope.from_dict rewrites each sig in place; the receipt's dict must not change.
    receipt, statement = parsed("sim_A")
    before = copy.deepcopy(receipt.envelope)
    check_signature(receipt.envelope, statement.predicate.execution.runPublicKey)
    assert receipt.envelope == before


# --- check 5: digests ----------------------------------------------------------------

def test_digests_pass_when_everything_recomputes():
    _, statement = parsed("sim_A")
    check = check_digests(statement)
    assert (check.id, check.status) == ("digests", Status.PASS)


@pytest.mark.parametrize("name, problems", [
    ("C3_pipeline", ["pipelineDigest does not recompute", "the subject digest is not the pipelineDigest"]),
    ("C4_subject", ["the subject digest is not the pipelineDigest"]),
    ("C5_eval", ["evalDigest does not recompute"]),
])
def test_digests_fail_and_say_which_digest(name, problems):
    _, statement = parsed(name)
    check = check_digests(statement)
    assert check.status is Status.FAIL
    assert check.detail == "; ".join(problems)


def test_two_same_role_components_in_either_order_both_pass_check_5():
    # Sort tie-break: fixture D5 has two adapter components; listing them the other way round is the same system.
    statement = statement_of("D5")
    components = statement["predicate"]["system"]["components"]
    adapters = [i for i, c in enumerate(components) if c["role"] == "adapter"]
    assert len(adapters) == 2
    swapped = copy.deepcopy(statement)
    first, second = adapters
    swapped_components = swapped["predicate"]["system"]["components"]
    swapped_components[first], swapped_components[second] = components[second], components[first]
    for s in (statement, swapped):
        assert check_digests(parse_statement(s)).status is Status.PASS


# --- check 6: publication ------------------------------------------------------------

def test_publication_is_always_not_applicable():
    check = check_publication()
    assert (check.id, check.status, check.detail) == (
        "publication", Status.NA, "publication not verified in this version")


# --- check 7: consent ------------------------------------------------------------------

def test_consent_passes_when_both_parties_approved():
    _, statement = parsed("sim_A")
    check = check_consent(statement.predicate)
    assert (check.id, check.status) == ("consent", Status.PASS)


def test_consent_is_not_applicable_without_consent():
    _, statement = parsed("sim_A_noconsent")
    check = check_consent(statement.predicate)
    assert (check.status, check.detail) == (Status.NA, "no consent in this receipt")


@pytest.mark.parametrize("name, problem", [
    ("C6_consent_sig", f"the {spec.MODEL_OWNER} approval's signature does not verify"),
    ("C7_consent_party", f"the {spec.BENCHMARK_OWNER} approval's key is not the {spec.BENCHMARK_OWNER} party's key"),
    ("C7b_party_mismatch", f"the {spec.MODEL_OWNER} approval's key is not the {spec.MODEL_OWNER} party's key"),
    ("C7c_one_party", f"needs exactly one approval from each of {spec.MODEL_OWNER} and {spec.BENCHMARK_OWNER}, "
                      f"got {spec.MODEL_OWNER}"),
    ("C7d_duplicate_approval", f"needs exactly one approval from each of {spec.MODEL_OWNER} and "
                               f"{spec.BENCHMARK_OWNER}, got {spec.MODEL_OWNER}, {spec.BENCHMARK_OWNER}, {spec.MODEL_OWNER}"),
    ("C7e_third_party_approval", f"needs exactly one approval from each of {spec.MODEL_OWNER} and "
                                 f"{spec.BENCHMARK_OWNER}, got {spec.MODEL_OWNER}, {spec.BENCHMARK_OWNER}, compute"),
])
def test_consent_fails_and_says_why(name, problem):
    _, statement = parsed(name)
    check = check_consent(statement.predicate)
    assert check.status is Status.FAIL
    assert check.detail == problem


def approvals_of(statement: dict) -> dict:
    """The worked example's two approvals, by party."""
    return {a["party"]: a for a in statement["predicate"]["consent"]["approvals"]}


@pytest.mark.parametrize("extra", ["duplicate", "compute"])
def test_consent_fails_on_any_approval_beyond_one_per_owner(extra):
    # Exactly two approvals, one from each owner.
    statement = statement_of("sim_A")
    model_owner = approvals_of(statement)[spec.MODEL_OWNER]
    statement["predicate"]["consent"]["approvals"].append(
        model_owner if extra == "duplicate" else {**model_owner, "party": "compute"})
    check = consent_check(statement)
    assert check.status is Status.FAIL
    assert check.detail.startswith(f"needs exactly one approval from each of {spec.MODEL_OWNER} and ")


def test_consent_fails_without_any_approvals():
    statement = statement_of("sim_A")
    statement["predicate"]["consent"]["approvals"] = []
    check = consent_check(statement)
    assert check.status is Status.FAIL
    assert check.detail == (f"needs exactly one approval from each of {spec.MODEL_OWNER} and {spec.BENCHMARK_OWNER}, "
                            "got none")


def test_consent_compares_the_approval_key_exactly():
    # The same key in uppercase hex is still not the party's key as written: fail closed.
    statement = statement_of("sim_A")
    approval = approvals_of(statement)[spec.BENCHMARK_OWNER]
    approval["publicKey"] = approval["publicKey"].upper()
    check = consent_check(statement)
    assert check.status is Status.FAIL
    assert check.detail == f"the {spec.BENCHMARK_OWNER} approval's key is not the {spec.BENCHMARK_OWNER} party's key"


@pytest.mark.parametrize("signature", ["not base64!", "!{valid}"], ids=["garbage", "valid-with-junk"])
def test_consent_needs_standard_base64_signatures(signature):
    # A lenient decoder would drop the "!" from "!<valid signature>", and it would verify.
    statement = statement_of("sim_A")
    approval = approvals_of(statement)[spec.MODEL_OWNER]
    approval["signature"] = signature.format(valid=approval["signature"])
    check = consent_check(statement)
    assert check.status is Status.FAIL
    assert check.detail == f"the {spec.MODEL_OWNER} approval's signature does not verify"


def test_consent_prefix_comes_from_spec(monkeypatch):
    # Swapping the prefix in spec.py must break the worked example's approvals, so nothing else hardcodes it.
    _, statement = parsed("sim_A")
    monkeypatch.setattr(spec, "CONSENT_PREFIX", b"another-prefix\n")
    assert check_consent(statement.predicate).status is Status.FAIL
