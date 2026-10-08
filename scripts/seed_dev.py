#!/usr/bin/env python3
"""POST every fixture that dev mode accepts to a running dev registry.

    REGISTRY_MODE=dev uv run flask --app registry.app run --port 5050   # in another terminal
    uv run python scripts/seed_dev.py

Exits non-zero if any fixture isn't accepted (201, or 200 if it is already indexed).
"""

import json
import sys
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parents[1]
EXPECTED = ROOT / "fixtures/expected.json"
URL = "http://127.0.0.1:5050/api/records"
TIMEOUT_SECONDS = 60
ACCEPTED = (200, 201)


def main() -> int:
    failed = 0
    for name, entry in json.loads(EXPECTED.read_text()).items():
        if entry["dev"]["status"] != 201:
            continue
        path = ROOT / entry["record"]
        try:
            # A multipart file part named "record", as curl -F sends it; requests sends no Origin header.
            response = requests.post(URL, files={"record": (path.name, path.read_bytes(), "application/json")},
                                     timeout=TIMEOUT_SECONDS)
        except requests.ConnectionError as e:
            print(f"cannot reach {URL}: is the dev server running? {e}", file=sys.stderr)
            return 1
        body = response.json()
        print(f"{name:24} {response.status_code} {body.get('state') or body.get('detail', '')}")
        failed += response.status_code not in ACCEPTED
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
