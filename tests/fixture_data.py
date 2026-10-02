"""The generated fixtures and their expected results (fixtures/expected.json)."""

import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
EXPECTED = json.loads((ROOT / "fixtures/expected.json").read_text())
CHECKED = sorted(name for name, entry in EXPECTED.items() if entry["checks"] is not None)
DEV_POLICY = ROOT / "registry-policy.dev.example.yaml"
STRICT_POLICY = ROOT / "registry-policy.yaml"


def record(name: str) -> bytes:
    return (ROOT / EXPECTED[name]["record"]).read_bytes()


def params(names) -> list:
    """Fixture names for parametrize. Those built from live captures need the network for checks 3 and 4."""
    return [pytest.param(name, id=name, marks=pytest.mark.network) if EXPECTED[name].get("network") else name
            for name in names]
