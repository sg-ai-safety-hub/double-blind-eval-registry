"""Check 7: the receipt's entry on Rekor, at the log index the submitter gave, answered offline from Rekor's
captured answer (fixtures/rekor). test_live.py looks OpenMined's receipt up on the real Rekor."""

import base64
import json

import pytest
import requests
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fixture_data import OPENMINED_LOG_INDEX, REKOR_ENTRY, record, rekor

from registry import checks_publication, spec
from registry.checks_publication import check_publication, fetch_rekor_entry
from registry.envelope import parse_receipt
from registry.model import Publication, Status, VerificationUnavailable
from registry.syft_receipt import parse_statement

UUID, = json.loads(REKOR_ENTRY)
INTEGRATED_TIME = 1791368875  # when Rekor logged OpenMined's receipt
OTHER_UUID = "0" * 16 + "ab" * 32
DOES_NOT_HOLD = f"Rekor's entry at index {OPENMINED_LOG_INDEX} does not hold this receipt's signature and signing key"
UNREADABLE = f"Rekor's entry at index {OPENMINED_LOG_INDEX} could not be read: "
OTHER_KEY_PEM = Ed25519PrivateKey.from_private_bytes(bytes(32)).public_key().public_bytes(
    serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)


def run(name: str = "om_receipt", log_index: int | None = OPENMINED_LOG_INDEX):
    receipt = parse_receipt(record(name))
    key_binding = parse_statement(receipt.statement).predicate.execution.attestation.keyBinding
    return check_publication(receipt, key_binding, log_index)


def entry(edit=None, *, uuid: str = UUID, body: str | None = None, **fields) -> bytes:
    """The captured entry as Rekor would answer under `uuid`: `edit` changes its decoded body, `body` replaces
    the encoded body, and `fields` replace its other fields."""
    (_, captured), = json.loads(REKOR_ENTRY).items()
    decoded = json.loads(base64.b64decode(captured["body"]))
    if edit:
        edit(decoded)
    encoded = base64.b64encode(json.dumps(decoded).encode()).decode() if body is None else body
    return json.dumps({uuid: {**captured, "body": encoded, **fields}}).encode()


def signature(body: dict) -> dict:
    return body["spec"]["signatures"][0]


def answering(answer: bytes):
    """Rekor answering `answer` at OpenMined's log index."""
    return rekor({OPENMINED_LOG_INDEX: answer})


def test_openmined_s_receipt_is_found_at_its_log_index():
    with rekor() as fetched:
        check, publication = run()
    assert (check.id, check.status, check.detail) == (
        "publication", Status.PASS, f"logged on Rekor at index {OPENMINED_LOG_INDEX}")
    assert publication == Publication(uuid=UUID, log_index=OPENMINED_LOG_INDEX, integrated_time=INTEGRATED_TIME,
                                      url=spec.REKOR_SEARCH_LINK.format(OPENMINED_LOG_INDEX))
    fetched.assert_called_once_with(OPENMINED_LOG_INDEX)


@pytest.mark.parametrize("log_index", [None, OPENMINED_LOG_INDEX])
def test_a_receipt_without_a_hardware_report_is_pending_and_rekor_is_not_asked(log_index):
    with rekor() as fetched:
        check, publication = run("sim_A", log_index)
    assert (check.status, check.detail, publication) == (
        Status.PENDING, "no hardware report in this receipt, so it is not looked up on Rekor", None)
    fetched.assert_not_called()


def test_a_receipt_with_a_report_and_no_log_index_fails():
    # Ingest refuses it with 400 before the checks; called directly, the check fails closed.
    with rekor() as fetched:
        check, publication = run(log_index=None)
    assert (check.status, check.detail, publication) == (Status.FAIL, "no Rekor log index was given", None)
    fetched.assert_not_called()


def test_an_index_rekor_has_no_entry_at_fails():
    with rekor() as fetched:
        check, publication = run(log_index=OPENMINED_LOG_INDEX + 1)
    assert (check.status, check.detail, publication) == (
        Status.FAIL, f"Rekor has no entry at index {OPENMINED_LOG_INDEX + 1}", None)
    fetched.assert_called_once_with(OPENMINED_LOG_INDEX + 1)


@pytest.mark.parametrize("edit", [
    pytest.param(lambda body: body["spec"]["payloadHash"].update(value="00" * 32), id="another payload hash"),
    pytest.param(lambda body: signature(body).update(signature=base64.b64encode(bytes(64)).decode()),
                 id="another signature"),
    pytest.param(lambda body: signature(body).update(verifier=base64.b64encode(OTHER_KEY_PEM).decode()),
                 id="another key"),
])
def test_an_entry_that_holds_another_receipt_fails(edit):
    with answering(entry(edit)):
        check, publication = run()
    assert (check.status, check.detail, publication) == (Status.FAIL, DOES_NOT_HOLD, None)


@pytest.mark.parametrize("answer", [
    pytest.param(b"{", id="not JSON"),
    pytest.param(b"[]", id="not an object"),
    pytest.param(b'{"%s": {}, "%s": {}}' % (UUID.encode(), UUID.encode()), id="duplicate keys"),
    pytest.param(entry()[:-1] + b', "%s": {}}' % OTHER_UUID.encode(), id="two entries"),
    pytest.param(entry(uuid="../../" + UUID), id="malformed uuid"),
    pytest.param(entry(logIndex=OPENMINED_LOG_INDEX + 1), id="another log index"),
    pytest.param(entry(body="not base64!"), id="body not base64"),
    pytest.param(entry(body=base64.b64encode(
        f'{{"kind": "{spec.REKOR_ENTRY_KIND}", "kind": "{spec.REKOR_ENTRY_KIND}"}}'.encode()).decode()),
                 id="body with duplicate keys"),
    pytest.param(entry(lambda body: body.update(kind="hashedrekord")), id="another kind"),
    pytest.param(entry(lambda body: body.update(apiVersion="0.0.2")), id="another apiVersion"),
    pytest.param(entry(lambda body: body["spec"]["payloadHash"].update(algorithm="sha512")),
                 id="another hash algorithm"),
    pytest.param(entry(lambda body: body["spec"]["signatures"].append(signature(body))), id="two signatures"),
    pytest.param(entry(lambda body: signature(body).update(verifier=base64.b64encode(b"not a key").decode())),
                 id="verifier not a key"),
])
def test_an_answer_that_is_not_one_dsse_entry_at_that_index_fails(answer):
    with answering(answer):
        check, publication = run()
    assert (check.status, publication) == (Status.FAIL, None)
    assert check.detail.startswith(UNREADABLE), check.detail


def test_a_network_error_means_no_verdict(monkeypatch):
    def unreachable(log_index):
        raise requests.ConnectionError("connection refused")
    monkeypatch.setattr(checks_publication, "fetch_rekor_entry", unreachable)
    with pytest.raises(VerificationUnavailable, match="check 7 could not reach the network"):
        run()


# --- the lookup --------------------------------------------------------------

class Answer:
    """What the lookup uses of a requests.Response."""

    def __init__(self, content: bytes, status: int = 200):
        self.content, self.status_code = content, status

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.HTTPError(f"{self.status_code} from Rekor")


def test_an_entry_is_fetched_by_its_log_index_and_returned_as_received(monkeypatch):
    calls = []
    monkeypatch.setattr(checks_publication.requests, "get",
                        lambda url, params, timeout: calls.append((url, params)) or Answer(REKOR_ENTRY))
    assert fetch_rekor_entry(OPENMINED_LOG_INDEX) == REKOR_ENTRY
    assert calls == [(f"{spec.REKOR_URL}/api/v1/log/entries", {"logIndex": OPENMINED_LOG_INDEX})]


def test_a_404_means_no_entry_at_that_index(monkeypatch):
    monkeypatch.setattr(checks_publication.requests, "get", lambda url, params, timeout: Answer(b"", status=404))
    assert fetch_rekor_entry(OPENMINED_LOG_INDEX) is None


def test_any_other_http_error_from_rekor_is_raised_so_the_check_reports_no_verdict(monkeypatch):
    monkeypatch.setattr(checks_publication.requests, "get", lambda url, params, timeout: Answer(b"", status=502))
    with pytest.raises(requests.HTTPError):
        fetch_rekor_entry(OPENMINED_LOG_INDEX)
