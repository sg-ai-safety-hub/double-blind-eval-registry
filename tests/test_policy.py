"""Acceptance, on check vectors written like "PFPPPP" (one letter per check, 1-6)."""

import pytest

from registry.config import Policy
from registry.model import CHECK_IDS, Check, Status
from registry.policy import decide

LISTED = "listed@example.org"
POLICY = Policy.model_validate({
    "trusted_code": [{"repo": "OpenMined/syft-enclave-tinfoil"}],
    "benchmark_owners": [{"email": LISTED, "display": "Listed owner"}],
})
APPROVERS = ["unlisted@example.org", LISTED]
VECTOR = {"P": Status.PASS, "F": Status.FAIL, "-": Status.PENDING}
MODES = ["strict", "dev"]
DEV_ONLY = "incomplete records are accepted only in dev mode"


def checks(vector: str) -> tuple[Check, ...]:
    return tuple(Check(check_id, VECTOR[v], "") for check_id, v in zip(CHECK_IDS, vector, strict=True))


def outcome(mode: str, vector: str, approvers: list[str] = APPROVERS) -> tuple:
    decision = decide(mode, POLICY, approvers, checks(vector))
    owner = decision.owner and (decision.owner.email, decision.owner.display)
    return decision.status, decision.detail, decision.state, owner


@pytest.mark.parametrize("mode", MODES)
def test_everything_passing_is_verified_and_names_the_listed_approver(mode):
    assert outcome(mode, "PPPPPP") == (201, "", "verified", (LISTED, "Listed owner"))


def test_pending_hardware_checks_are_incomplete_in_dev():
    assert outcome("dev", "P---PP") == (201, "", "incomplete", (LISTED, "Listed owner"))


def test_pending_hardware_checks_are_refused_in_strict():
    assert outcome("strict", "P---PP") == (422, DEV_ONLY, None, None)


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("vector, failed", [
    ("F---PP", "signature"),
    ("PFPPPP", "key_binding"),
    ("P---FF", "digests, consent"),
    ("PPPPPF", "consent"),  # no approval from a listed email
])
def test_any_fail_is_refused_in_both_modes(mode, vector, failed):
    assert outcome(mode, vector) == (422, f"failed: {failed}", None, None)


def test_a_fail_comes_before_pending_in_strict():
    assert outcome("strict", "F---PP")[:2] == (422, "failed: signature")


@pytest.mark.parametrize("vector", ["P-PPPP", "-PPPPP", "PPPP-P"])
def test_any_other_combination_is_refused(vector):
    # Fail closed: accept only the exact verified and incomplete vectors.
    assert outcome("dev", vector) == (422, "unexpected check results", None, None)


def test_a_passed_consent_check_with_no_listed_approver_is_refused():
    # Can't happen, as check 6 PASSes only for a listed approver; if it ever did, fail closed.
    assert outcome("dev", "PPPPPP", ["unlisted@example.org"]) == (422, "unexpected check results", None, None)
