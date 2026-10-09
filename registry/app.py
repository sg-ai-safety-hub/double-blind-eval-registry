"""Flask app factory for the registry's JSON API.

Run with `flask --app registry.app run --port 5050`, which binds to 127.0.0.1.
Never add --host 0.0.0.0 or --debug: the Werkzeug debugger allows remote code execution.
"""

import importlib.metadata
import io
import json
import logging
import os
import shlex

from flask import Flask, abort, jsonify, request, send_file
from werkzeug.exceptions import HTTPException
from werkzeug.http import HTTP_STATUS_CODES
from werkzeug.routing import BaseConverter

from registry.config import DEBUG_ENV, ConfigError, enable_debug_logging, load_config
from registry.index import Index, StaleIndex
from registry.ingest import ingest
from registry.refcache import RefCache
from registry.store import Store

log = logging.getLogger(__name__)

TRUSTED_HOSTS = ["localhost", "127.0.0.1"]  # rejects other Host headers: stops DNS rebinding
MAX_BODY_BYTES = 1024 * 1024  # 1 MiB
BUNDLE_IGNORED = "bundle ignored: check 7 looks the receipt up on Rekor"
NOT_FOUND = "nothing on file for that"
DEFAULT_LIMIT, MAX_LIMIT = 20, 100  # recent records


class Hex64(BaseConverter):
    """A path segment that is a record id or a digest: 64 lowercase hex. Anything else is a 404."""

    regex = "[0-9a-f]{64}"


def create_app() -> Flask:
    if os.environ.get(DEBUG_ENV) == "1":
        enable_debug_logging()
    config = load_config(os.environ)
    version = importlib.metadata.version("double-blind-eval-registry")
    store = Store(config.store_dir)
    refcache = RefCache(config.refcache_dir)
    try:
        index = Index.open(config.index_path, config.policy_sha256, config.mode)
    except StaleIndex as e:
        rebuild = (f"REGISTRY_MODE={config.mode} REGISTRY_DATA_DIR={shlex.quote(str(config.data_dir))} "
                   f"REGISTRY_POLICY={shlex.quote(str(config.policy_path))} uv run python scripts/rebuild_index.py")
        raise ConfigError(f"{e}. Rebuild it, then restart: {rebuild}") from e

    app = Flask(__name__)
    app.config.update(TRUSTED_HOSTS=TRUSTED_HOSTS, MAX_CONTENT_LENGTH=MAX_BODY_BYTES)
    app.url_map.converters["hex64"] = Hex64

    @app.errorhandler(HTTPException)
    def json_error(e: HTTPException):
        # Flask's documented pattern: keep the status and headers (e.g. Allow on 405), swap the HTML body for JSON.
        response = e.get_response()
        response.data = json.dumps({"error": e.name, "detail": e.description})
        response.content_type = "application/json"
        return response

    def found(value):
        if value is None:
            abort(404, NOT_FOUND)
        return value

    @app.get("/api/health")
    def health():
        return jsonify(mode=config.mode, policyHash=config.policy_sha256, version=version)

    @app.post("/api/records")
    def post_record():
        # Browsers always send Origin on a cross-site POST; curl and Python's requests never do, and
        # the UI never POSTs. Refused before the body is read.
        if "Origin" in request.headers:
            log.debug("REJECT POST: it carries an Origin header")
            abort(403, "a POST with an Origin header is refused")
        # Only a file part keeps the bytes as sent: a text field is decoded first.
        records = request.files.getlist("record")
        if len(records) != 1:
            abort(400, "send the receipt as one multipart file part named 'record'")
        result = ingest(records[0].read(), config, store, index, refcache)

        body = dict(result.body)
        if result.status >= 400:
            body["error"] = HTTP_STATUS_CODES[result.status]
        if "bundle" in request.files or "bundle" in request.form:  # never read or stored
            body["warnings"] = [BUNDLE_IGNORED]
        return jsonify(body), result.status

    @app.get("/api/records")
    def recent_records():
        limit = request.args.get("limit", DEFAULT_LIMIT, type=int)
        if not 1 <= limit <= MAX_LIMIT:
            abort(400, f"limit must be from 1 to {MAX_LIMIT}")
        return jsonify(records=[record.to_json() for record in index.recent(limit)])

    @app.get("/api/records/<hex64:record_id>")
    def get_record(record_id):
        return jsonify(found(index.get(record_id)).to_json())

    @app.get("/api/records/<hex64:record_id>/record.dsse.json")
    def download_record(record_id):
        found(index.get(record_id))  # only what this registry lists
        raw = found(store.read_record(record_id))  # exactly the bytes received; read_record checks they hash to the id
        return send_file(io.BytesIO(raw), mimetype="application/json", as_attachment=True,
                         download_name="record.dsse.json")

    @app.get("/api/systems/<hex64:digest>")
    def get_system(digest):
        return jsonify(found(index.system(digest)))

    @app.get("/api/components/<hex64:digest>")
    def get_component(digest):
        return jsonify(found(index.component(digest)))

    @app.get("/api/models")
    def list_models():
        return jsonify(models=index.models())

    @app.get("/api/models/<hex64:digest>")
    def get_model(digest):
        return jsonify(found(index.model(digest)))

    @app.get("/api/evals")
    def list_evals():
        return jsonify(evals=index.evaluations())

    @app.get("/api/evals/<hex64:digest>")
    def get_eval(digest):
        return jsonify(found(index.evaluation(digest)))

    @app.get("/api/lookup/<hex64:digest>")
    def lookup(digest):
        return jsonify(found(index.lookup(digest)))

    return app
