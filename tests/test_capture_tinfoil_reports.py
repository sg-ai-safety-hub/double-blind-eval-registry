"""scripts/capture_tinfoil_reports.py, with Tinfoil's bundle service and GitHub replaced."""

import base64
import gzip
import importlib.util
import json

import pytest
from fixture_data import ROOT
from tinfoil.attestation import Bundle, Document, PredicateType
from tinfoil.github import Release

REPORT = b"a raw SEV-SNP report"
DIGEST = "fe" * 32


def load_script():
    spec = importlib.util.spec_from_file_location("capture", ROOT / "scripts/capture_tinfoil_reports.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def script(monkeypatch):
    module = load_script()
    calls = {"bundles": [], "releases": [], "release": Release(tag="v0.0.4", digest=DIGEST),
             "format": PredicateType.SEV_GUEST_V2}

    def fetch_bundle_from(url, enclave="", repo=""):
        calls["bundles"].append((url, enclave, repo))
        body = base64.b64encode(gzip.compress(REPORT)).decode()
        return Bundle(domain="enclave.example", enclave_attestation_report=Document(format=calls["format"], body=body),
                      digest=DIGEST, sigstore_bundle=b"{}", vcek="", enclave_cert="")

    def fetch_latest_release(repo):
        calls["releases"].append(repo)
        return calls["release"]

    monkeypatch.setattr(module, "fetch_bundle_from", fetch_bundle_from)
    monkeypatch.setattr(module, "fetch_latest_release", fetch_latest_release)
    module.calls = calls
    return module


def test_a_capture_keeps_only_the_raw_report_and_a_sidecar(script, tmp_path):
    assert script.capture("dbe", "dbe.example", "owner/name", tmp_path) is True
    assert base64.b64decode((tmp_path / "dbe.quote").read_text(), validate=True) == REPORT
    meta = json.loads((tmp_path / "dbe.meta.json").read_text())
    assert set(meta) == {"repo", "tag", "capturedAt"}
    assert (meta["repo"], meta["tag"]) == ("owner/name", "v0.0.4")
    assert script.calls["bundles"] == [(script.BUNDLE_SERVICE, "dbe.example", "owner/name")]


def test_the_router_capture_asks_for_the_default_bundle(script, tmp_path):
    script.capture("router", "", "owner/router", tmp_path)
    assert script.calls["bundles"] == [(script.BUNDLE_SERVICE, "", "")]
    assert script.calls["releases"] == ["owner/router"]


def test_a_latest_release_with_another_digest_stops_the_capture(script, tmp_path):
    script.calls["release"] = Release(tag="v0.0.5", digest="ab" * 32)
    with pytest.raises(script.CaptureError, match="stop, and find out why"):
        script.capture("dbe", "dbe.example", "owner/name", tmp_path)
    assert list(tmp_path.iterdir()) == []


def test_a_report_that_is_not_sev_snp_stops_the_capture(script, tmp_path):
    script.calls["format"] = PredicateType.TDX_GUEST_V2
    with pytest.raises(script.CaptureError, match="SEV-SNP"):
        script.capture("dbe", "dbe.example", "owner/name", tmp_path)
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("existing", ["dbe.quote", "dbe.meta.json"])
def test_an_existing_capture_is_never_overwritten(script, tmp_path, existing):
    (tmp_path / existing).write_text("captured earlier")
    assert script.capture("dbe", "dbe.example", "owner/name", tmp_path) is False
    assert (tmp_path / existing).read_text() == "captured earlier"
    assert script.calls["bundles"] == []
