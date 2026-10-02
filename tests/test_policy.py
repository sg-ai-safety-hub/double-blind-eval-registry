"""The acceptance gate, on check vectors written like "PFPPPnP" (one letter per check, 1-7)."""

import pytest

from registry import spec
from registry.config import Policy
from registry.model import CHECK_IDS, Check, Status
from registry.policy import decide

LISTED = "11" * 32
UNLISTED = "22" * 32
POLICY = Policy.model_validate({
    "trusted_code": [{"repo": "tinfoilsh/double-blind-eval"}],
    "benchmark_owners": [{"public_key": LISTED, "display": "Listed owner"}],
})
VECTOR = {"P": Status.PASS, "F": Status.FAIL, "-": Status.PENDING, "n": Status.NA}
MODES = ["strict", "dev"]
NOT_LISTED = f"the {spec.BENCHMARK_OWNER} key is not on this registry's list"
APPROVAL_REQUIRED = f"{spec.BENCHMARK_OWNER} approval required"
DEV_ONLY = "incomplete records are accepted only in dev mode"


def checks(vector: str) -> tuple[Check, ...]:
    return tuple(Check(check_id, VECTOR[v], "") for check_id, v in zip(CHECK_IDS, vector, strict=True))


def outcome(mode: str, key: str, vector: str) -> tuple:
    decision = decide(mode, POLICY, key, checks(vector))
    return decision.status, decision.detail, decision.state, decision.display


@pytest.mark.parametrize("mode", MODES)
def test_everything_passing_from_a_listed_owner_is_verified(mode):
    assert outcome(mode, LISTED, "PPPPPnP") == (201, "", "verified", "Listed owner")


def test_pending_hardware_checks_are_incomplete_in_dev():
    assert outcome("dev", LISTED, "P---PnP") == (201, "", "incomplete", "Listed owner")


def test_pending_hardware_checks_are_refused_in_strict():
    assert outcome("strict", LISTED, "P---PnP") == (422, DEV_ONLY, None, None)


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("vector, failed", [
    ("F---PnP", "signature"),
    ("PFPPPnP", "key_binding"),
    ("P---FnF", "digests, consent"),
])
def test_any_fail_is_refused_in_both_modes(mode, vector, failed):
    assert outcome(mode, LISTED, vector) == (422, f"failed: {failed}", None, None)


def test_a_listed_owner_whose_approval_fails_is_refused_by_check_7_not_the_gate():
    assert outcome("dev", LISTED, "P---PnF") == (422, "failed: consent", None, None)


def test_an_unlisted_owner_is_refused_with_403():
    assert outcome("dev", UNLISTED, "P---PnP") == (403, NOT_LISTED, None, None)


def test_no_consent_is_refused_with_403():
    # Check 7 is N/A without consent, so the listed key's approval was never verified.
    assert outcome("dev", LISTED, "P---Pnn") == (403, APPROVAL_REQUIRED, None, None)


@pytest.mark.parametrize("mode, key, vector, expected", [
    ("dev", UNLISTED, "F---PnP", (422, "failed: signature")),  # a FAIL comes before the gate
    ("strict", UNLISTED, "P---PnP", (422, DEV_ONLY)),  # so does PENDING in strict mode
    ("dev", UNLISTED, "P---Pnn", (403, NOT_LISTED)),  # the key comes before the approval
])
def test_refusals_come_in_order(mode, key, vector, expected):
    assert outcome(mode, key, vector)[:2] == expected


@pytest.mark.parametrize("vector", ["PPPPPPP", "nPPPPnP", "P-PPPnP", "PPPPnnP"])
def test_any_other_combination_is_refused(vector):
    # Fail closed: accept only the exact verified and incomplete vectors.
    assert outcome("dev", LISTED, vector) == (422, "unexpected check results", None, None)
