"""POST /api/records over HTTP: every fixture's status, plus the HTTP-level rules."""

import hashlib
import io
from pathlib import Path

import pytest
from fixture_data import DEV_POLICY, EXPECTED, STRICT_POLICY, params, record

from registry import checks_tinfoil, spec
from registry.app import create_app
from registry.model import VerificationUnavailable

BUNDLE_IGNORED = "bundle ignored: publication is not verified in this version"
STRICT = [name for name, entry in EXPECTED.items() if "strict" in entry]


@pytest.fixture
def dev(monkeypatch):
    monkeypatch.setenv("REGISTRY_MODE", "dev")
    monkeypatch.setenv("REGISTRY_POLICY", str(DEV_POLICY))
    return create_app().test_client()


@pytest.fixture
def strict(monkeypatch):
    monkeypatch.setenv("REGISTRY_POLICY", str(STRICT_POLICY))
    return create_app().test_client()


def part(data: bytes, filename: str = "record.dsse.json"):
    return io.BytesIO(data), filename, "application/json"


def post(client, raw: bytes, **kwargs):
    """POST `raw` as the multipart file part `record`, as `curl -F record=@file` sends it."""
    return client.post("/api/records", data={"record": part(raw)}, **kwargs)


def stored_files(mode: str) -> list[Path]:
    store = Path("data", mode, "store")
    return sorted(p for p in store.rglob("*") if p.is_file()) if store.exists() else []


@pytest.mark.parametrize("name", params(EXPECTED))
def test_every_fixture_gets_its_expected_dev_status(dev, name):
    response = post(dev, record(name))
    expected = EXPECTED[name]
    assert response.status_code == expected["dev"]["status"], response.get_json()
    body = response.get_json()
    assert body["recordId"] == expected["recordId"]
    if expected["checks"] is not None:
        assert {c["id"]: c["status"] for c in body["checks"]} == expected["checks"]
    if response.status_code == 201:
        assert body["state"] == expected["dev"]["state"]


@pytest.mark.parametrize("name", params(STRICT))
def test_strict_fixtures_get_their_expected_strict_status(strict, name):
    assert post(strict, record(name)).status_code == EXPECTED[name]["strict"]["status"]


def test_refusals_are_json_with_error_and_detail(dev):
    body = post(dev, record("C14_unlisted_bo")).get_json()
    assert body["error"] == "Forbidden"
    assert "not on this registry's list" in body["detail"]


def test_a_scripted_post_with_a_bundle_part_ignores_it_with_a_warning(dev):
    # As a script would send it: requests.post(url, files={"record": (...), "bundle": (...)}); no Origin header.
    response = dev.post("/api/records", data={
        "record": part(record("sim_A")),
        "bundle": part(b'{"mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json"}', "record.sigstore.json"),
    })
    assert response.status_code == 201
    assert response.get_json()["warnings"] == [BUNDLE_IGNORED]
    record_id = EXPECTED["sim_A"]["recordId"]
    folder = Path("data/dev/store/sha256", record_id[:2], record_id[2:])
    assert stored_files("dev") == [folder / "meta.json", folder / "record.dsse.json"]


def test_the_bundle_warning_comes_with_refusals_too(dev):
    response = dev.post("/api/records", data={"record": part(record("C14_unlisted_bo")), "bundle": "{}"})
    assert response.status_code == 403
    assert response.get_json()["warnings"] == [BUNDLE_IGNORED]


def test_no_warnings_without_a_bundle(dev):
    assert "warnings" not in post(dev, record("sim_A")).get_json()


@pytest.mark.parametrize("origin", ["http://localhost:5173", "https://evil.example", "null", ""])
def test_a_post_with_an_origin_header_is_refused_and_not_stored(dev, origin):
    response = post(dev, record("sim_A"), headers={"Origin": origin})
    assert response.status_code == 403
    assert response.is_json
    assert stored_files("dev") == []


@pytest.mark.parametrize("data", [
    {},
    {"other": part(b"{}")},
    {"record": "sent as a text field, not a file"},  # a text field would be decoded, so its bytes aren't as sent
    {"record": [part(b"{}"), part(b"{}")]},
], ids=["nothing", "other-part", "text-field", "two-records"])
def test_anything_but_one_record_file_part_is_a_400(dev, data):
    response = dev.post("/api/records", data=data)
    assert response.status_code == 400
    assert response.get_json()["detail"] == "send the receipt as one multipart file part named 'record'"


def test_a_json_body_is_a_400(dev):
    response = dev.post("/api/records", data=record("sim_A"), content_type="application/json")
    assert response.status_code == 400


def test_a_body_over_1_mib_is_a_413(dev):
    response = post(dev, b" " * (1024 * 1024 + 1))
    assert response.status_code == 413
    assert response.is_json
    assert stored_files("dev") == []


def test_posting_again_answers_200_with_the_same_record(dev):
    first = post(dev, record("sim_A"))
    again = post(dev, record("sim_A"))
    assert (first.status_code, again.status_code) == (201, 200)
    assert again.get_json() == first.get_json()


def test_the_stored_bytes_are_exactly_the_part_sent(dev):
    # JSON allows trailing whitespace, so this is the same receipt as different bytes: a different record.
    raw = record("sim_A") + b"\r\n"
    body = post(dev, raw).get_json()
    assert body["recordId"] == hashlib.sha256(raw).hexdigest()
    folder = Path("data/dev/store/sha256", body["recordId"][:2], body["recordId"][2:])
    assert (folder / "record.dsse.json").read_bytes() == raw


def test_a_network_failure_is_a_503_and_stores_nothing(dev, monkeypatch):
    def unavailable(*args):
        raise VerificationUnavailable("check 4 could not reach the network: timed out")
    monkeypatch.setattr(checks_tinfoil, "check_attestation", unavailable)
    response = post(dev, record("sim_A"))
    assert response.status_code == 503
    assert response.get_json()["error"] == "Service Unavailable"
    assert stored_files("dev") == []


# --- reads -------------------------------------------------------------------

DEV_ACCEPTED = [name for name, entry in EXPECTED.items() if entry["dev"]["status"] == 201]
ROUTES_WITH_AN_ID = ["/api/records/{}", "/api/records/{}/record.dsse.json", "/api/systems/{}", "/api/components/{}",
                     "/api/models/{}", "/api/evals/{}", "/api/lookup/{}"]


@pytest.fixture
def seeded(dev):
    for name in DEV_ACCEPTED:
        assert post(dev, record(name)).status_code == 201
    return dev


def test_a_record_reads_back_as_it_was_accepted(dev):
    posted = post(dev, record("D1")).get_json()
    assert dev.get(f"/api/records/{posted['recordId']}").get_json() == posted


@pytest.mark.parametrize("name", DEV_ACCEPTED)
def test_a_download_is_the_stored_bytes_and_hashes_to_its_id(seeded, name):
    record_id = EXPECTED[name]["recordId"]
    response = seeded.get(f"/api/records/{record_id}/record.dsse.json")
    assert response.status_code == 200
    assert response.data == record(name)
    assert hashlib.sha256(response.data).hexdigest() == record_id
    assert response.headers["Content-Disposition"] == "attachment; filename=record.dsse.json"
    assert seeded.get(f"/api/records/{record_id}").get_json()["size"] == len(response.data)


def test_recent_records_take_a_limit(seeded):
    assert len(seeded.get("/api/records").get_json()["records"]) == len(DEV_ACCEPTED)  # fewer than the default 20
    assert len(seeded.get("/api/records?limit=2").get_json()["records"]) == 2


@pytest.mark.parametrize("limit", ["0", "-1", "101"])
def test_a_limit_out_of_range_is_a_400(dev, limit):
    response = dev.get(f"/api/records?limit={limit}")
    assert response.status_code == 400
    assert response.get_json()["detail"] == "limit must be from 1 to 100"


def test_the_read_endpoints_answer_from_the_index(seeded):
    d1 = seeded.get(f"/api/records/{EXPECTED['D1']['recordId']}").get_json()
    weights, runtime = d1["components"][0], d1["components"][1]
    runtime_hex = runtime["digest"].removeprefix("sha256:")  # an OCI digest
    assert seeded.get(f"/api/systems/{d1['systemDigest']}").get_json()["digest"] == d1["systemDigest"]
    assert seeded.get(f"/api/evals/{d1['eval']['digest']}").get_json()["names"] == [d1["eval"]["name"]]
    assert seeded.get(f"/api/models/{weights['digest']}").get_json()["names"] == [weights["name"]]
    assert seeded.get(f"/api/components/{runtime_hex}").get_json()["names"] == [runtime["name"]]
    assert len(seeded.get("/api/models").get_json()["models"]) == 4
    assert len(seeded.get("/api/evals").get_json()["evals"]) == 4
    assert seeded.get(f"/api/lookup/{d1['systemDigest']}").get_json() == {"kind": "system", "id": d1["systemDigest"]}


@pytest.mark.parametrize("route", ROUTES_WITH_AN_ID)
@pytest.mark.parametrize("bad", ["AB" * 32, "ab" * 31, "ab" * 33, "sha256:" + "ab" * 32, "g" * 64],
                         ids=["uppercase", "short", "long", "prefixed", "not-hex"])
def test_ids_in_paths_must_be_64_lowercase_hex(seeded, route, bad):
    response = seeded.get(route.format(bad))
    assert response.status_code == 404
    assert response.is_json


@pytest.mark.parametrize("route", ROUTES_WITH_AN_ID)
def test_an_unknown_id_is_a_404(seeded, route):
    response = seeded.get(route.format("ab" * 32))
    assert response.status_code == 404
    assert response.get_json()["detail"] == "nothing on file for that"


def test_no_answer_shows_a_quote_sentinel(seeded):
    # Their quotes are sentinels, and nothing from execution.attestation is ever shown.
    d1 = seeded.get(f"/api/records/{EXPECTED['D1']['recordId']}").get_json()
    pages = ["/api/records", "/api/models", "/api/evals", f"/api/systems/{d1['systemDigest']}",
             f"/api/evals/{d1['eval']['digest']}", f"/api/models/{d1['components'][0]['digest']}"]
    for page in pages:
        text = seeded.get(page).get_data(as_text=True)
        assert spec.SIMULATED_PREFIX not in text and spec.PLACEHOLDER_PREFIX not in text, page
