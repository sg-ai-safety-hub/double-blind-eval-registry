"""Verification vocabulary shared by the checks, ingest, the index and the fixtures."""

import functools
import logging
from dataclasses import dataclass
from enum import StrEnum

log = logging.getLogger(__name__)


class Status(StrEnum):
    PASS = "PASS"
    FAIL = "FAIL"
    PENDING = "PENDING"  # required input absent: the hardware report is a sentinel


# The seven checks, in order.
CHECK_IDS = ("signature", "key_binding", "hardware", "measurement", "digests", "consent", "publication")


@dataclass(frozen=True)
class Check:
    id: str
    status: Status
    detail: str


def check(check_id: str):
    """Make a check function fail closed.

    The function returns (status, detail); the decorated function returns a Check, and any
    exception raised inside it becomes a FAIL.
    """
    def decorate(run):
        @functools.wraps(run)
        def checked(*args, **kwargs) -> Check:
            try:
                status, detail = run(*args, **kwargs)
            except Exception as e:
                log.debug("check %s raised %s", check_id, type(e).__name__)
                return Check(check_id, Status.FAIL, f"error while checking: {type(e).__name__}: {e}")
            return Check(check_id, status, detail)
        return checked
    return decorate


class VerificationUnavailable(Exception):
    """A check couldn't reach the network: the POST gets 503 and nothing is stored."""


@dataclass(frozen=True)
class Enclave:
    """The verified enclave facts: only values the SDK returned, once checks 3 and 4 PASS."""

    measurement: str
    repo: str
    release_tag: str
    release_digest: str
    type: str = "AMD SEV-SNP"


@dataclass(frozen=True)
class Publication:
    """Where Rekor logs the receipt, as Rekor answered when check 7 PASSed."""

    uuid: str
    log_index: int
    integrated_time: int  # Rekor's clock, in Unix seconds
    url: str  # the entry on search.sigstore.dev


@dataclass(frozen=True)
class VerificationResult:
    checks: tuple[Check, ...]  # all seven, in order
    enclave: Enclave | None  # None unless checks 3 and 4 PASS
    publication: Publication | None  # None unless check 7 PASSes


@dataclass(frozen=True)
class Accepted:
    """What the registry established about a receipt it accepts, the same for every receipt format.

    A format's adapter adds what the receipt itself says, to make the record the index holds.
    """

    record_id: str
    size: int  # bytes, as received
    received_at: str  # the registry's own clock
    state: str  # "verified" or "incomplete"
    checks: tuple[Check, ...]
    enclave: Enclave | None
    publication: Publication | None
    benchmark_owner_email: str  # the first approver on this registry's list
    benchmark_owner_display: str  # the name the list gives that email


@dataclass(frozen=True)
class IngestResult:
    """The answer to a POST: an HTTP status and its JSON body."""

    status: int
    body: dict
