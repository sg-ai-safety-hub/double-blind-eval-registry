"""Check 7: the receipt's entry on Rekor, answered offline from Rekor's captured answers (fixtures/rekor).
test_live.py looks OpenMined's receipt up on the real Rekor."""

import base64
import hashlib
import json

import pytest
import requests
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fixture_data import REKOR_ENTRY, REKOR_SEARCH, record, rekor

from registry import checks_publication, spec
from registry.checks_publication import check_publication, fetch_rekor_entry, search_rekor
from registry.envelope import parse_receipt
from registry.model import Publication, Status, VerificationUnavailable
from registry.syft_receipt import parse_statement

UUID = json.loads(REKOR_SEARCH)[0]
OTHER_UUID = "0" * 16 + "ab" * 32
LOG_INDEX, INTEGRATED_TIME = 3129204433, 1791368875  # where and when Rekor logged OpenMined's receipt
NOT_FOUND = "Rekor has no entry for this receipt's payload"
NO_MATCH = "none of Rekor's 1 entries for this payload holds this receipt's signature and signing key"
OTHER_KEY_PEM = Ed25519PrivateKey.from_private_bytes(bytes(32)).public_key().public_bytes(
    serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)


def run(name: str = "om_receipt"):
    receipt = parse_receipt(record(name))
    return check_publication(receipt, parse_statement(receipt.statement).predicate.execution.attestation.keyBinding)


def entry(edit=None, *, uuid: str = UUID, body: str | None = None, **fields) -> bytes:
    """The captured entry as Rekor would answer for `uuid`: `edit` changes its decoded body, `body` replaces
    the encoded body, and `fields` replace its other fields."""
    (_, captured), = json.loads(REKOR_ENTRY).items()
    decoded = json.loads(base64.b64decode(captured["body"]))
    if edit:
        edit(decoded)
    encoded = base64.b64encode(json.dumps(decoded).encode()).decode() if body is None else body
    return json.dumps({uuid: {**captured, "body": encoded, **fields}}).encode()


def signature(body: dict) -> dict:
    return body["spec"]["signatures"][0]


def test_openmined_s_receipt_is_found_on_rekor():
    with rekor():
        check, publication = run()
    assert (check.id, check.status, check.detail) == ("publication", Status.PASS, f"logged on Rekor at index {LOG_INDEX}")
    assert publication == Publication(uuid=UUID, log_index=LOG_INDEX, integrated_time=INTEGRATED_TIME,
                                      url=spec.REKOR_SEARCH_LINK.format(LOG_INDEX))


def test_rekor_is_searched_by_the_sha256_of_the_payload_and_each_entry_found_is_fetched():
    with rekor() as (searched, fetched):
        run()
    searched.assert_called_once_with(hashlib.sha256(parse_receipt(record("om_receipt")).payload).hexdigest())
    fetched.assert_called_once_with(UUID)


def test_a_receipt_without_a_hardware_report_is_pending_and_rekor_is_not_asked():
    with rekor() as (searched, fetched):
        check, publication = run("sim_A")
    assert (check.status, check.detail, publication) == (
        Status.PENDING, "no hardware report in this receipt, so it is not looked up on Rekor", None)
    searched.assert_not_called()


def test_a_receipt_rekor_has_no_entry_for_fails():
    with rekor(search=b"[]\n") as (_, fetched):
        check, publication = run()
    assert (check.status, check.detail, publication) == (Status.FAIL, NOT_FOUND, None)
    fetched.assert_not_called()


@pytest.mark.parametrize("edit", [
    pytest.param(lambda body: body["spec"]["payloadHash"].update(value="00" * 32), id="another payload hash"),
    pytest.param(lambda body: body["spec"]["payloadHash"].update(algorithm="sha512"), id="another hash algorithm"),
    pytest.param(lambda body: signature(body).update(signature=base64.b64encode(bytes(64)).decode()),
                 id="another signature"),
    pytest.param(lambda body: signature(body).update(verifier=base64.b64encode(OTHER_KEY_PEM).decode()),
                 id="another key"),
    pytest.param(lambda body: body["spec"]["signatures"].append(signature(body)), id="two signatures"),
    pytest.param(lambda body: body.update(kind="hashedrekord"), id="another kind"),
    pytest.param(lambda body: body.update(apiVersion="0.0.2"), id="another apiVersion"),
])
def test_an_entry_that_does_not_hold_this_receipt_does_not_count(edit):
    with rekor(entries={UUID: entry(edit)}):
        check, publication = run()
    assert (check.status, check.detail, publication) == (Status.FAIL, NO_MATCH, None)


def test_an_answer_keyed_by_another_uuid_does_not_count():
    with rekor(entries={UUID: entry(uuid=OTHER_UUID)}):
        check, publication = run()
    assert (check.status, check.detail, publication) == (Status.FAIL, NO_MATCH, None)


@pytest.mark.parametrize("malformed", [
    pytest.param(b"{", id="not JSON"),
    pytest.param(b'{"%s": {}, "%s": {}}' % (OTHER_UUID.encode(), OTHER_UUID.encode()), id="duplicate keys"),
    pytest.param(entry(uuid=OTHER_UUID, body="not base64!"), id="body not base64"),
    pytest.param(entry(uuid=OTHER_UUID, body=base64.b64encode(
        f'{{"kind": "{spec.REKOR_ENTRY_KIND}", "kind": "{spec.REKOR_ENTRY_KIND}"}}'.encode()).decode()),
                 id="body with duplicate keys"),
    pytest.param(entry(lambda body: signature(body).update(verifier=base64.b64encode(b"not a key").decode()),
                       uuid=OTHER_UUID), id="verifier not a key"),
])
def test_a_malformed_entry_is_skipped_and_a_good_one_still_passes(malformed):
    with rekor(search=json.dumps([OTHER_UUID, UUID]).encode(), entries={OTHER_UUID: malformed, UUID: REKOR_ENTRY}):
        check, publication = run()
    assert (check.status, publication.uuid) == (Status.PASS, UUID)


@pytest.mark.parametrize("order", [[OTHER_UUID, UUID], [UUID, OTHER_UUID]], ids=["later first", "later last"])
def test_the_earliest_matching_entry_is_kept(order):
    later = entry(uuid=OTHER_UUID, integratedTime=INTEGRATED_TIME + 60, logIndex=LOG_INDEX + 1000)
    with rekor(search=json.dumps(order).encode(), entries={OTHER_UUID: later, UUID: REKOR_ENTRY}):
        check, publication = run()
    assert (check.status, publication.uuid, publication.log_index) == (Status.PASS, UUID, LOG_INDEX)


@pytest.mark.parametrize("search", [
    pytest.param(b"not JSON", id="not JSON"),
    pytest.param(b'{"uuids": []}', id="not a list"),
    pytest.param(b"[1]", id="not strings"),
    pytest.param(b'["../../index/retrieve"]', id="a path"),
    pytest.param(json.dumps([UUID.upper()]).encode(), id="uppercase"),
    pytest.param(json.dumps([UUID[:-1]]).encode(), id="too short"),
])
def test_a_search_answer_that_is_not_a_list_of_uuids_fails_before_any_fetch(search):
    with rekor(search=search) as (_, fetched):
        check, publication = run()
    assert (check.status, publication) == (Status.FAIL, None)
    assert check.detail.startswith("Rekor's answer could not be read: ")
    fetched.assert_not_called()


@pytest.mark.parametrize("call", ["search_rekor", "fetch_rekor_entry"])
def test_a_network_error_in_either_call_means_no_verdict(call, monkeypatch):
    def unreachable(*args):
        raise requests.ConnectionError("connection refused")
    monkeypatch.setattr(checks_publication, "search_rekor", lambda sha256: REKOR_SEARCH)
    monkeypatch.setattr(checks_publication, "fetch_rekor_entry", lambda uuid: REKOR_ENTRY)
    monkeypatch.setattr(checks_publication, call, unreachable)
    with pytest.raises(VerificationUnavailable, match="check 7 could not reach the network"):
        run()


# --- the two calls -----------------------------------------------------------

class Answer:
    """What the two calls use of a requests.Response."""

    def __init__(self, content: bytes, status: int = 200):
        self.content, self.status_code = content, status

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.HTTPError(f"{self.status_code} from Rekor")


def test_the_search_posts_the_payload_hash_to_rekor_s_index_and_returns_the_answer_as_received(monkeypatch):
    calls = []
    monkeypatch.setattr(checks_publication.requests, "post",
                        lambda url, json, timeout: calls.append((url, json)) or Answer(REKOR_SEARCH))
    assert search_rekor("ab" * 32) == REKOR_SEARCH
    assert calls == [(f"{spec.REKOR_URL}/api/v1/index/retrieve", {"hash": "sha256:" + "ab" * 32})]


def test_an_entry_is_fetched_by_its_uuid_and_returned_as_received(monkeypatch):
    calls = []
    monkeypatch.setattr(checks_publication.requests, "get", lambda url, timeout: calls.append(url) or Answer(REKOR_ENTRY))
    assert fetch_rekor_entry(UUID) == REKOR_ENTRY
    assert calls == [f"{spec.REKOR_URL}/api/v1/log/entries/{UUID}"]


def test_an_http_error_from_rekor_is_raised_so_the_check_reports_no_verdict(monkeypatch):
    monkeypatch.setattr(checks_publication.requests, "post", lambda url, json, timeout: Answer(b"", status=502))
    with pytest.raises(requests.HTTPError):
        search_rekor("ab" * 32)
