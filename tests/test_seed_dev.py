"""scripts/seed_dev.py, with the dev server replaced."""

import importlib.util

import pytest
import requests
from fixture_data import EXPECTED, ROOT, record

DEV_ACCEPTED = [name for name, entry in EXPECTED.items() if entry["dev"]["status"] == 201]


class Answer:
    def __init__(self, status_code: int, body: dict):
        self.status_code, self.body = status_code, body

    def json(self):
        return self.body


def load_script():
    spec = importlib.util.spec_from_file_location("seed_dev", ROOT / "scripts/seed_dev.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def server(monkeypatch):
    """Replace requests.post; record each POST and answer with server["answer"]."""
    calls = {"posts": [], "answer": Answer(201, {"state": "incomplete"})}

    def post(url, files=None, timeout=None, **kwargs):
        calls["posts"].append((url, files, kwargs))
        if isinstance(calls["answer"], Exception):
            raise calls["answer"]
        return calls["answer"]

    monkeypatch.setattr(requests, "post", post)
    return calls


def test_seeding_posts_every_fixture_dev_mode_accepts_as_a_record_file_part(server):
    assert load_script().main() == 0
    assert [files["record"][1] for _, files, _ in server["posts"]] == [record(name) for name in DEV_ACCEPTED]
    for url, files, kwargs in server["posts"]:
        assert url == "http://127.0.0.1:5050/api/records"
        assert set(files) == {"record"}
        assert "headers" not in kwargs  # no Origin header: the registry refuses a POST that carries one


def test_seeding_again_is_fine(server):
    server["answer"] = Answer(200, {"state": "incomplete"})
    assert load_script().main() == 0


def test_seeding_fails_if_a_fixture_is_refused(server, capsys):
    server["answer"] = Answer(422, {"detail": "incomplete records are accepted only in dev mode"})
    assert load_script().main() == 1
    assert "incomplete records are accepted only in dev mode" in capsys.readouterr().out


def test_seeding_says_when_no_server_is_running(server, capsys):
    server["answer"] = requests.ConnectionError("connection refused")
    assert load_script().main() == 1
    assert "is the dev server running" in capsys.readouterr().err
