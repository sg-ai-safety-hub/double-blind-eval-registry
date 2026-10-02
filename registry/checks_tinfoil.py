"""Checks 2, 3 and 4: key binding, hardware and measurement, via the Tinfoil SDK.

The SDK calls follow SecureClient's direct verification path: Document.verify, then
verify_attestation and assert_equal. Intended deviations:
- the report is the receipt's quote, not fetched from a live enclave;
- the release is referenceValue.tag, not the latest, so refcache resolves the digest per tag;
- check 3 runs on its own, without check 4;
- SEV-SNP only: no TDX branch.

Any failure is a FAIL, except a network or TUF error, which raises VerificationUnavailable.
"""

import base64
import gzip
import hashlib
import logging

import requests
import urllib3
from sigstore.errors import NetworkError, TUFError
from tinfoil.attestation import (
    Document,
    FormatMismatchError,
    MeasurementMismatchError,
    PredicateType,
    Verification,
)
from tinfoil.sigstore import verify_attestation
from tuf.api.exceptions import DownloadError

from registry import spec
from registry.config import TrustedCode
from registry.evalresult import Attestation, ReferenceValue
from registry.model import Check, Enclave, Status, VerificationUnavailable, check
from registry.refcache import NoReleaseAsset, RefCache

log = logging.getLogger(__name__)

HARDWARE_CHECKS = ("key_binding", "hardware", "measurement")
SEV_SNP = "sev-snp"  # the only execution.attestation.type in the MVP
NETWORK_ERRORS = (  # these mean no verdict: VerificationUnavailable, so a 503
    requests.exceptions.RequestException,
    urllib3.exceptions.HTTPError,
    NetworkError,
    TUFError,
    DownloadError,
    ConnectionError,
    TimeoutError,
)
NEEDS_CHECK_3 = "needs check 3, which failed"


def check_attestation(attestation: Attestation, run_public_key: str, trusted_code: list[TrustedCode],
                      refcache: RefCache) -> tuple[tuple[Check, Check, Check], Enclave | None]:
    """Checks 2, 3 and 4, and the verified enclave facts when checks 3 and 4 PASS.

    Check 3 runs first: checks 2 and 4 both need the report it verifies.
    """
    if attestation.type != SEV_SNP:  # before the sentinel test: no report makes another type acceptable
        return _hardware_failed("SEV-SNP only in this MVP"), None
    if attestation.quote.startswith(spec.SENTINEL_PREFIXES):
        pending = "no hardware report in this receipt"  # the only absent input that allows PENDING
        return tuple(Check(check_id, Status.PENDING, pending) for check_id in HARDWARE_CHECKS), None

    try:
        verification = _verify_report(attestation.quote)
    except Exception as e:
        _raise_if_network(e, "check 3")
        return _hardware_failed(f"the hardware report does not verify: {e}"), None
    hardware = Check("hardware", Status.PASS, "the report verifies against AMD's certificate chain and the SDK's TCB policy")
    measurement, enclave = _check_measurement(attestation.referenceValue, verification, trusted_code, refcache)
    return (check_key_binding(run_public_key, verification), hardware, measurement), enclave


def _verify_report(quote: str) -> Verification:
    """Check 3. The quote is base64 of the raw report, but Document wants base64(gzip(report)).

    No VCEK is passed: the SDK fetches it from Tinfoil's proxy of AMD's key server, validates it
    against AMD's roots, and keeps it in its own disk cache.
    """
    raw = base64.b64decode(quote, validate=True)
    body = base64.b64encode(gzip.compress(raw, mtime=0)).decode()
    return Document(format=PredicateType.SEV_GUEST_V2, body=body).verify()


@check("key_binding")
def check_key_binding(run_public_key: str, verification: Verification):
    """Check 2: sha256 of runPublicKey's bytes is the verified report_data[0:32]."""
    if hashlib.sha256(bytes.fromhex(run_public_key)).hexdigest() == verification.public_key_fp:
        return Status.PASS, "sha256(runPublicKey) equals the attested report_data[0:32]"
    return Status.FAIL, "sha256(runPublicKey) is not the key the hardware report binds"


def _check_measurement(reference_value: ReferenceValue, verification: Verification,
                       trusted_code: list[TrustedCode], refcache: RefCache) -> tuple[Check, Enclave | None]:
    """Check 4: the attested measurement is the Sigstore-signed reference of a trusted
    repo, signed from the receipt's tag."""
    repo = reference_value.repo.removeprefix(spec.REFERENCE_REPO_PREFIX)
    tag = reference_value.tag
    if repo not in {trusted.repo for trusted in trusted_code}:
        return Check("measurement", Status.FAIL, "the receipt's repo is not in this registry's trusted_code"), None
    try:
        reference = refcache.get(repo, tag)
        # The tag is the expected release tag: the signing workflow must be refs/tags/<tag>.
        code = verify_attestation(reference.bundle, reference.digest, repo, tag)
        code.assert_equal(verification.measurement)
    except NoReleaseAsset:
        return Check("measurement", Status.FAIL, "no release asset for this tag"), None
    except (MeasurementMismatchError, FormatMismatchError):
        return Check("measurement", Status.FAIL, "the attested measurement is not the release's signed reference"), None
    except Exception as e:
        _raise_if_network(e, "check 4")
        return Check("measurement", Status.FAIL, f"the release's reference does not verify: {e}"), None

    refcache.put(repo, tag, reference)  # only after a PASS, so a bad fetch can't poison the cache
    enclave = Enclave(measurement=verification.measurement.fingerprint(), repo=repo, release_tag=tag,
                      release_digest=reference.digest)
    return Check("measurement", Status.PASS, "the attested measurement equals the release's Sigstore-signed "
                                             "reference"), enclave


def _hardware_failed(detail: str) -> tuple[Check, Check, Check]:
    return (Check("key_binding", Status.FAIL, NEEDS_CHECK_3), Check("hardware", Status.FAIL, detail),
            Check("measurement", Status.FAIL, NEEDS_CHECK_3))


def _raise_if_network(error: Exception, where: str) -> None:
    """If a network or TUF error is anywhere in the error's cause or context chain,
    there is no verdict. The SDK wraps every error (verify_attestation in a ValueError)."""
    seen, pending = set(), [error]
    while pending:
        e = pending.pop()
        if e is None or id(e) in seen:
            continue
        seen.add(id(e))
        if isinstance(e, NETWORK_ERRORS):
            log.debug("UNAVAILABLE %s: %s", where, type(e).__name__)
            raise VerificationUnavailable(f"{where} could not reach the network: {e}") from error
        pending += [e.__cause__, e.__context__]
