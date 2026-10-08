"""scripts/rebuild_index.py: the same settings as the server, and the old index kept on failure."""

import hashlib
import importlib.util
import io
import json
from pathlib import Path

import pytest
from fixture_data import DEV_POLICY, ROOT, record

from registry import checks_tinfoil
from registry.app import create_app
from registry.model import VerificationUnavailable


def load_script():
    spec = importlib.util.spec_from_file_location("rebuild_index", ROOT / "scripts/rebuild_index.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def dev(monkeypatch):
    """A dev registry holding sim_A and D1."""
    monkeypatch.setenv("REGISTRY_MODE", "dev")
    monkeypatch.setenv("REGISTRY_POLICY", str(DEV_POLICY))
    client = create_app().test_client()
    for name in ("sim_A", "D1"):
        assert client.post("/api/records", data={"record": (io.BytesIO(record(name)), "r.json")}).status_code == 201
    return client


def test_the_script_rebuilds_the_index_from_the_store(dev, capsys):
    Path("data/dev/index.sqlite3").unlink()
    assert load_script().main() == 0
    assert "indexed 2 record(s)" in capsys.readouterr().out
    assert len(create_app().test_client().get("/api/records").get_json()["records"]) == 2


def test_the_script_reports_a_record_whose_stored_bytes_no_longer_match_its_id(dev, capsys):
    record_id = hashlib.sha256(record("D1")).hexdigest()
    stored = Path("data/dev/store/sha256", record_id[:2], record_id[2:], "record.dsse.json")
    stored.write_text(json.dumps(json.loads(stored.read_bytes()), indent=4))  # as an editor's format-on-save would
    assert load_script().main() == 0
    out = capsys.readouterr().out
    assert f"not indexed {record_id}: its stored bytes no longer hash to its id" in out
    assert "indexed 1 record(s)" in out


def test_the_script_keeps_the_old_index_when_verification_is_unavailable(dev, monkeypatch, capsys):
    before = Path("data/dev/index.sqlite3").read_bytes()

    def unavailable(*args):
        raise VerificationUnavailable("check 3 could not reach the network: connection refused")
    monkeypatch.setattr(checks_tinfoil, "check_attestation", unavailable)
    assert load_script().main() == 1
    assert "the old index is unchanged" in capsys.readouterr().err
    assert Path("data/dev/index.sqlite3").read_bytes() == before
