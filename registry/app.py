"""Flask app factory for the registry's JSON API.

Run with `flask --app registry.app run --port 5050`, which binds to 127.0.0.1.
Never add --host 0.0.0.0 or --debug: the Werkzeug debugger allows remote code execution.
"""

import importlib.metadata
import json
import logging
import os

from flask import Flask, abort, jsonify, request
from werkzeug.exceptions import HTTPException
from werkzeug.http import HTTP_STATUS_CODES

from registry.config import DEBUG_ENV, enable_debug_logging, load_config
from registry.ingest import ingest
from registry.refcache import RefCache
from registry.store import Store

log = logging.getLogger(__name__)

TRUSTED_HOSTS = ["localhost", "127.0.0.1"]  # rejects other Host headers: stops DNS rebinding
MAX_BODY_BYTES = 1024 * 1024  # 1 MiB
BUNDLE_IGNORED = "bundle ignored: publication is not verified in this version"


def create_app() -> Flask:
    if os.environ.get(DEBUG_ENV) == "1":
        enable_debug_logging()
    config = load_config(os.environ)
    version = importlib.metadata.version("double-blind-eval-registry")
    store = Store(config.data_dir / "store")
    refcache = RefCache(config.data_dir / "refcache")

    app = Flask(__name__)
    app.config.update(TRUSTED_HOSTS=TRUSTED_HOSTS, MAX_CONTENT_LENGTH=MAX_BODY_BYTES)

    @app.errorhandler(HTTPException)
    def json_error(e: HTTPException):
        # Flask's documented pattern: keep the status and headers (e.g. Allow on 405), swap the HTML body for JSON.
        response = e.get_response()
        response.data = json.dumps({"error": e.name, "detail": e.description})
        response.content_type = "application/json"
        return response

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
        result = ingest(records[0].read(), config, store, refcache)

        body = dict(result.body)
        if result.status >= 400:
            body["error"] = HTTP_STATUS_CODES[result.status]
        if "bundle" in request.files or "bundle" in request.form:  # never read or stored
            body["warnings"] = [BUNDLE_IGNORED]
        return jsonify(body), result.status

    return app
