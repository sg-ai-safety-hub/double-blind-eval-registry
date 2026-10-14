import hashlib
import importlib.metadata
import logging
from pathlib import Path

import pytest

from registry import app as app_module
from registry import spec
from registry.app import create_app
from registry.config import ConfigError, load_config
from registry.ingest import rebuild
from registry.refcache import RefCache
from registry.store import Store

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


def test_health_reports_mode_policy_hash_version_and_the_model_role(client):
    # modelRole tells the UI which component is the model, so the UI hardcodes no spec constant.
    response = client.get("/api/health")
    assert response.status_code == 200
    assert response.get_json() == {
        "mode": "strict",
        "policyHash": hashlib.sha256(POLICY).hexdigest(),
        "version": importlib.metadata.version("double-blind-eval-registry"),
        "modelRole": spec.BASE_MODEL_ROLE,
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


def test_a_deployment_adds_its_own_hostname(monkeypatch):
    # A deployment is reached at its own hostname (e.g. its *.up.railway.app domain); every other host stays out.
    Path("registry-policy.yaml").write_bytes(POLICY)
    monkeypatch.setenv("REGISTRY_PUBLIC_HOST", "registry.example")
    client = create_app().test_client()
    assert client.get("/api/health", headers={"Host": "registry.example"}).status_code == 200
    assert client.get("/api/health", headers={"Host": "localhost:5050"}).status_code == 200
    assert client.get("/api/health", headers={"Host": "evil.example"}).status_code == 400


def test_errors_are_json(client):
    response = client.get("/api/no-such-route")
    assert response.status_code == 404
    assert response.is_json


@pytest.fixture
def web_dist(monkeypatch, tmp_path):
    """A built UI: web/dist's index.html and one asset."""
    dist = tmp_path / "web-dist"
    (dist / "assets").mkdir(parents=True)
    (dist / "index.html").write_text("<!doctype html><title>ui</title>")
    (dist / "assets" / "app.js").write_text("console.log(1)")
    monkeypatch.setattr(app_module, "WEB_DIST", dist)
    return dist


def test_the_ui_is_served_from_the_built_web_dist(client, web_dist):
    response = client.get("/")
    assert response.status_code == 200
    assert (response.mimetype, response.data) == ("text/html", (web_dist / "index.html").read_bytes())


def test_the_ui_page_allows_only_its_own_origin(client, web_dist):
    # Defence in depth against XSS: no inline or third-party script, style, frame or form target.
    policy = client.get("/").headers["Content-Security-Policy"]
    assert "default-src 'self'" in policy and "frame-ancestors 'none'" in policy


def test_the_ui_s_assets_are_served(client, web_dist):
    response = client.get("/assets/app.js")
    assert (response.status_code, response.data) == (200, b"console.log(1)")


def test_nothing_outside_the_assets_folder_is_served(client, web_dist):
    (web_dist / "secret.txt").write_text("x")
    for path in ("/secret.txt", "/assets/../secret.txt", "/assets/%2e%2e/secret.txt"):
        assert client.get(path).status_code == 404, path


def test_an_unbuilt_ui_is_a_json_404_that_says_how_to_build_it(client, monkeypatch, tmp_path):
    monkeypatch.setattr(app_module, "WEB_DIST", tmp_path / "missing")
    response = client.get("/")
    assert (response.status_code, response.is_json) == (404, True)
    assert "pnpm build" in response.get_json()["detail"]


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


# --- the startup guard -------------------------------------------------------

def test_the_first_start_creates_the_index(client):
    assert Path("data/strict/index.sqlite3").is_file()


def test_refuses_to_serve_an_index_built_under_another_policy():
    Path("registry-policy.yaml").write_bytes(POLICY)
    create_app()
    Path("registry-policy.yaml").write_bytes(POLICY + b"# edited\n")
    with pytest.raises(ConfigError, match="another policy or mode"):
        create_app()


def test_refuses_to_serve_an_index_built_in_another_mode(monkeypatch):
    monkeypatch.setenv("REGISTRY_DATA_DIR", "data/shared")
    for name in ("registry-policy.yaml", "registry-policy.dev.yaml"):
        Path(name).write_bytes(POLICY)
    create_app()
    monkeypatch.setenv("REGISTRY_MODE", "dev")
    with pytest.raises(ConfigError, match="another policy or mode"):
        create_app()


def test_the_refusal_gives_the_exact_rebuild_command(tmp_path):
    Path("registry-policy.yaml").write_bytes(POLICY)
    create_app()
    Path("registry-policy.yaml").write_bytes(POLICY + b"# edited\n")
    with pytest.raises(ConfigError) as e:
        create_app()
    assert str(e.value).endswith(
        f"Rebuild it, then restart: REGISTRY_MODE=strict REGISTRY_DATA_DIR={tmp_path / 'data' / 'strict'} "
        f"REGISTRY_POLICY={tmp_path / 'registry-policy.yaml'} uv run python scripts/rebuild_index.py")


def test_serves_again_after_a_rebuild():
    Path("registry-policy.yaml").write_bytes(POLICY)
    create_app()
    Path("registry-policy.yaml").write_bytes(POLICY + b"# edited\n")
    config = load_config({})
    rebuild(config, Store(config.store_dir), RefCache(config.refcache_dir))
    assert create_app().test_client().get("/api/health").status_code == 200
