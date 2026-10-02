"""Acceptance: which checked receipts this registry lists.

It reads the check results and never changes them. Who POSTed is irrelevant.
"""

import logging
from dataclasses import dataclass

from registry import spec
from registry.config import Policy
from registry.model import Check, Status

log = logging.getLogger(__name__)

# The two acceptable results, check by check. Anything else is refused.
VERIFIED = {
    "signature": Status.PASS,
    "key_binding": Status.PASS,
    "hardware": Status.PASS,
    "measurement": Status.PASS,
    "digests": Status.PASS,
    "publication": Status.NA,  # always, in this version
    "consent": Status.PASS,
}
INCOMPLETE = {**VERIFIED, "key_binding": Status.PENDING, "hardware": Status.PENDING, "measurement": Status.PENDING}
STATES = {"verified": VERIFIED, "incomplete": INCOMPLETE}


@dataclass(frozen=True)
class Decision:
    status: int  # 201 accepted; 403 or 422 refused
    detail: str = ""  # why it was refused
    state: str | None = None  # "verified" or "incomplete", when accepted
    display: str | None = None  # the benchmark owner's name on this registry's list, when listed


def decide(mode: str, policy: Policy, owner_key: str, checks: tuple[Check, ...]) -> Decision:
    """Apply the refusals in order, then accept only an exact verified or incomplete result.

    `owner_key` is the key of the receipt's one benchmark owner, which the schema guarantees.
    """
    statuses = {c.id: c.status for c in checks}
    failed = [check_id for check_id, status in statuses.items() if status is Status.FAIL]
    if failed:
        return _refuse(422, f"failed: {', '.join(failed)}")
    if Status.PENDING in statuses.values() and mode != "dev":
        return _refuse(422, "incomplete records are accepted only in dev mode")

    # The key alone proves nothing, since public keys are public. Check 7 PASSing proves its
    # approval verified: it needs the benchmark owner's approval, signed with owner_key.
    display = next((owner.display for owner in policy.benchmark_owners if owner.public_key == owner_key), None)
    if display is None:
        return _refuse(403, f"the {spec.BENCHMARK_OWNER} key is not on this registry's list")
    if statuses["consent"] is not Status.PASS:
        return _refuse(403, f"{spec.BENCHMARK_OWNER} approval required")  # N/A: no consent

    for state, expected in STATES.items():
        if statuses == expected:
            log.debug("ACCEPT %s, %s %s", state, spec.BENCHMARK_OWNER, owner_key)
            return Decision(201, state=state, display=display)
    return _refuse(422, "unexpected check results")  # fail closed: no check produces these


def _refuse(status: int, detail: str) -> Decision:
    log.debug("REJECT %d: %s", status, detail)
    return Decision(status, detail)
