import hashlib
import importlib.metadata
import logging
from pathlib import Path

import pytest

from registry.app import create_app
from registry.config import ConfigError

POLICY = b"""\
trusted_code:
  - repo: tinfoilsh/double-blind-eval
benchmark_owners: []
"""


@pytest.fixture
def client():
    Path("registry-policy.yaml").write_bytes(POLICY)
    return create_app().test_client()


@pytest.fixture
def registry_logger():
    """The "registry" logger, restored after the test so debug logging can't leak."""
    logger = logging.getLogger("registry")
    level, handlers = logger.level, list(logger.handlers)
    yield logger
    logger.setLevel(level)
    logger.handlers[:] = handlers


def test_health_reports_mode_policy_hash_and_version(client):
    response = client.get("/api/health")
    assert response.status_code == 200
    assert response.get_json() == {
        "mode": "strict",
        "policyHash": hashlib.sha256(POLICY).hexdigest(),
        "version": importlib.metadata.version("double-blind-eval-registry"),
    }


def test_health_in_dev_mode(monkeypatch):
    Path("registry-policy.dev.yaml").write_bytes(POLICY)
    monkeypatch.setenv("REGISTRY_MODE", "dev")
    assert create_app().test_client().get("/api/health").get_json()["mode"] == "dev"


def test_refuses_to_start_with_empty_trusted_code():
    Path("registry-policy.yaml").write_text("trusted_code: []\nbenchmark_owners: []\n")
    with pytest.raises(ConfigError, match="trusted_code"):
        create_app()


def test_untrusted_host_header_is_rejected(client):
    # TRUSTED_HOSTS stops DNS rebinding: a page served from evil.example can't read the API.
    response = client.get("/api/health", headers={"Host": "evil.example"})
    assert response.status_code == 400
    assert response.is_json


@pytest.mark.parametrize("host", ["localhost:5050", "127.0.0.1:5050"])
def test_local_host_headers_are_accepted(client, host):
    assert client.get("/api/health", headers={"Host": host}).status_code == 200


def test_errors_are_json(client):
    response = client.get("/api/no-such-route")
    assert response.status_code == 404
    assert response.is_json


def test_request_bodies_are_capped_at_1_mib(client):
    # Flask enforces this when a route reads the body; the POST route's tests cover the 413.
    assert client.application.config["MAX_CONTENT_LENGTH"] == 1024 * 1024


def test_debug_logging_is_off_by_default(client, registry_logger):
    assert registry_logger.level == logging.NOTSET
    assert registry_logger.handlers == []


def test_registry_debug_env_enables_debug_logging(monkeypatch, registry_logger, caplog):
    monkeypatch.setenv("REGISTRY_DEBUG", "1")
    Path("registry-policy.yaml").write_bytes(POLICY)
    create_app()
    assert registry_logger.isEnabledFor(logging.DEBUG)
    assert any(
        record.name == "registry.config" and record.getMessage().startswith("ACCEPT policy")
        for record in caplog.records
    )
