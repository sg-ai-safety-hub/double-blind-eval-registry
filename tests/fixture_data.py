"""The generated fixtures and their expected results (fixtures/expected.json), and Rekor's captured answers."""

import hashlib
import json
from contextlib import contextmanager
from pathlib import Path
from unittest import mock

import pytest

from registry import checks_publication
from registry.envelope import parse_receipt

ROOT = Path(__file__).resolve().parents[1]
EXPECTED = json.loads((ROOT / "fixtures/expected.json").read_text())
CHECKED = sorted(name for name, entry in EXPECTED.items() if entry["checks"] is not None)
DEV_POLICY = ROOT / "registry-policy.dev.example.yaml"
STRICT_POLICY = ROOT / "registry-policy.yaml"
# Rekor's answers for OpenMined's receipt: the search by its payload hash, and the one entry it found.
REKOR_SEARCH = (ROOT / "fixtures/rekor/om_receipt.search.json").read_bytes()
REKOR_ENTRY = (ROOT / "fixtures/rekor/om_receipt.entry.json").read_bytes()


def record(name: str) -> bytes:
    return (ROOT / EXPECTED[name]["record"]).read_bytes()


def params(names) -> list:
    """Fixture names for parametrize. Those with a hardware report need the network, for checks 3, 4 and 7."""
    return [pytest.param(name, id=name, marks=pytest.mark.network) if EXPECTED[name].get("network") else name
            for name in names]


OPENMINED_PAYLOAD_SHA256 = hashlib.sha256(parse_receipt(record("om_receipt")).payload).hexdigest()


@contextmanager
def rekor(search: bytes = REKOR_SEARCH, entries: dict[str, bytes] | None = None):
    """Rekor as captured, in place of check 7's two calls. Yields the two mocks.

    OpenMined's payload hash finds its entry, and any other payload hash finds nothing. `search` and
    `entries` ({uuid: answer}) replace the captured answers.
    """
    entries = {json.loads(REKOR_SEARCH)[0]: REKOR_ENTRY} if entries is None else entries
    with (mock.patch.object(checks_publication, "search_rekor",
                            side_effect=lambda sha256: search if sha256 == OPENMINED_PAYLOAD_SHA256 else b"[]") as searched,
          mock.patch.object(checks_publication, "fetch_rekor_entry", side_effect=entries.__getitem__) as fetched):
        yield searched, fetched
