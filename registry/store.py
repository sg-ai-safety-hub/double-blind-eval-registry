"""The content-addressed file store: the source of truth, holding raw bytes only.

    <root>/sha256/<id[0:2]>/<id[2:]>/record.dsse.json  exactly as received; id = sha256(bytes)
                                    /meta.json         {"receivedAt": ...}

It never parses a record. Every write goes to a temp file in the same folder, then os.replace,
so a concurrent reader (the dev server is multithreaded) or a crash never sees a half-written
file under a final name. No fsync: surviving power loss is out of MVP scope.
"""

import hashlib
import json
import logging
import os
import re
import tempfile
from pathlib import Path

from registry import spec

log = logging.getLogger(__name__)

RECORD = "record.dsse.json"
META = "meta.json"
RECORD_ID = re.compile(spec.HEX64)  # sha256 of the record's bytes


class Corrupt(Exception):
    """A stored record's bytes no longer hash to its id."""


class Store:
    def __init__(self, root: Path):
        self.root = root

    def put_record(self, raw: bytes, received_at: str) -> str:
        """Store `raw` under sha256(raw) and return that id. Storing it again changes nothing."""
        record_id = hashlib.sha256(raw).hexdigest()
        folder = self._folder(record_id)
        folder.mkdir(parents=True, exist_ok=True)
        if (folder / RECORD).exists():
            log.debug("record %s already stored", record_id)
        else:
            write_atomic(folder / RECORD, raw)
            log.debug("stored record %s (%d bytes)", record_id, len(raw))
        if not (folder / META).exists():
            write_atomic(folder / META, _json({"receivedAt": received_at}))
        return record_id

    def read_record(self, record_id: str) -> bytes | None:
        raw = _read(self._folder(record_id) / RECORD)
        if raw is not None and hashlib.sha256(raw).hexdigest() != record_id:
            raise Corrupt(record_id)
        return raw

    def read_meta(self, record_id: str) -> dict | None:
        raw = _read(self._folder(record_id) / META)
        return None if raw is None else json.loads(raw)

    def record_ids(self) -> list[str]:
        """The id of every stored record, sorted."""
        return sorted(path.parent.parent.name + path.parent.name for path in self.root.glob(f"sha256/*/*/{RECORD}"))

    def _folder(self, record_id: str) -> Path:
        # Validating first also keeps any path outside the store unreachable.
        if not RECORD_ID.match(record_id):
            raise ValueError(f"not a record id: {record_id[:80]!r}")
        return self.root / "sha256" / record_id[:2] / record_id[2:]


def write_atomic(path: Path, data: bytes) -> None:
    with tempfile.NamedTemporaryFile(dir=path.parent, prefix=f".{path.name}.", delete_on_close=False) as f:
        f.write(data)
        f.close()
        os.replace(f.name, path)  # a temp file that wasn't moved is deleted when the block exits


def _read(path: Path) -> bytes | None:
    try:
        return path.read_bytes()
    except FileNotFoundError:
        return None


def _json(obj: dict) -> bytes:
    return json.dumps(obj, sort_keys=True).encode()
