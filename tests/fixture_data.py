"""The generated fixtures and their expected results (fixtures/expected.json), and Rekor's captured answer."""

import json
from contextlib import contextmanager
from pathlib import Path
from unittest import mock

import pytest

from registry import checks_publication

ROOT = Path(__file__).resolve().parents[1]
EXPECTED = json.loads((ROOT / "fixtures/expected.json").read_text())
CHECKED = sorted(name for name, entry in EXPECTED.items() if entry["checks"] is not None)
DEV_POLICY = ROOT / "registry-policy.dev.example.yaml"
STRICT_POLICY = ROOT / "registry-policy.yaml"
# Rekor's answer for OpenMined's receipt: its entry, fetched by its log index.
REKOR_ENTRY = (ROOT / "fixtures/rekor/om_receipt.entry.json").read_bytes()
OPENMINED_LOG_INDEX = next(iter(json.loads(REKOR_ENTRY).values()))["logIndex"]


def record(name: str) -> bytes:
    return (ROOT / EXPECTED[name]["record"]).read_bytes()


def log_index(name: str) -> int | None:
    """The Rekor log index fixture `name` is POSTed with: OpenMined's, for every fixture with a report."""
    return EXPECTED[name].get("logIndex")


def params(names) -> list:
    """Fixture names for parametrize. Those with a hardware report need the network, for checks 3, 4 and 7."""
    return [pytest.param(name, id=name, marks=pytest.mark.network) if EXPECTED[name].get("network") else name
            for name in names]


@contextmanager
def rekor(entries: dict[int, bytes] | None = None):
    """Rekor as captured, in place of check 7's lookup. Yields the mock.

    OpenMined's log index answers with its entry, and any other index with a 404. `entries`
    ({log index: answer}) replaces the captured answer.
    """
    entries = {OPENMINED_LOG_INDEX: REKOR_ENTRY} if entries is None else entries
    with mock.patch.object(checks_publication, "fetch_rekor_entry", side_effect=entries.get) as fetched:
        yield fetched
