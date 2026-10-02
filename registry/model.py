"""Verification vocabulary shared by the checks, ingest, the index and the fixtures."""

import functools
import logging
from dataclasses import dataclass
from enum import StrEnum

log = logging.getLogger(__name__)


class Status(StrEnum):
    PASS = "PASS"
    FAIL = "FAIL"
    PENDING = "PENDING"  # required input absent: the quote is a sentinel
    NA = "N/A"  # check 6 always (publication deferred); check 7 when consent is absent


# The seven checks, in order.
CHECK_IDS = ("signature", "key_binding", "hardware", "measurement", "digests", "publication", "consent")


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
class VerificationResult:
    checks: tuple[Check, ...]  # all seven, in order
    enclave: Enclave | None  # None unless checks 3 and 4 PASS


@dataclass(frozen=True)
class IngestResult:
    """The answer to a POST: an HTTP status and its JSON body."""

    status: int
    body: dict
