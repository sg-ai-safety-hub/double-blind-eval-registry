"""Acceptance: which checked receipts this registry lists.

It reads the check results and never changes them. Who POSTed is irrelevant.
"""

import logging
from dataclasses import dataclass

from registry.config import BenchmarkOwner, Policy
from registry.model import CHECK_IDS, Check, Status

log = logging.getLogger(__name__)

# The two acceptable results, check by check. Anything else is refused.
VERIFIED = {check_id: Status.PASS for check_id in CHECK_IDS}
INCOMPLETE = {**VERIFIED, "key_binding": Status.PENDING, "hardware": Status.PENDING, "measurement": Status.PENDING,
              "publication": Status.PENDING}  # no hardware report: test data, so not on Rekor either
STATES = {"verified": VERIFIED, "incomplete": INCOMPLETE}


@dataclass(frozen=True)
class Decision:
    status: int  # 201 accepted; 422 refused
    detail: str = ""  # why it was refused
    state: str | None = None  # "verified" or "incomplete", when accepted
    owner: BenchmarkOwner | None = None  # the first approver on this registry's list, when accepted


def decide(mode: str, policy: Policy, approvers: list[str], checks: tuple[Check, ...]) -> Decision:
    """Apply the refusals in order, then accept only an exact verified or incomplete result.

    `approvers` are the receipt's approval emails, in receipt order. A receipt with no listed approver
    FAILs check 6, so it is refused with the other FAILs.
    """
    statuses = {c.id: c.status for c in checks}
    failed = [check_id for check_id, status in statuses.items() if status is Status.FAIL]
    if failed:
        return _refuse(422, f"failed: {', '.join(failed)}")
    if Status.PENDING in statuses.values() and mode != "dev":
        return _refuse(422, "incomplete records are accepted only in dev mode")

    owner = policy.first_listed(approvers)  # check 6 PASSed, so there is one
    for state, expected in STATES.items():
        if statuses == expected and owner is not None:
            log.debug("ACCEPT %s, approved by %s", state, owner.email)
            return Decision(201, state=state, owner=owner)
    return _refuse(422, "unexpected check results")  # fail closed: no check produces these


def _refuse(status: int, detail: str) -> Decision:
    log.debug("REJECT %d: %s", status, detail)
    return Decision(status, detail)
