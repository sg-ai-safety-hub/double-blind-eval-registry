import hashlib

import pytest

from registry import store as store_module
from registry.store import Corrupt, Store

RECORD = b'{"payloadType": "x", "payload": "e30=", "signatures": []}'  # the store never parses it
RECORD_ID = hashlib.sha256(RECORD).hexdigest()
T0 = "2026-09-25T01:00:00Z"
T1 = "2026-09-25T02:00:00Z"


@pytest.fixture
def store(tmp_path):
    return Store(tmp_path / "store")


def folder(tmp_path, record_id=RECORD_ID):
    return tmp_path / "store" / "sha256" / record_id[:2] / record_id[2:]


def test_record_is_stored_under_its_sha256_exactly_as_received(store, tmp_path):
    assert store.put_record(RECORD, T0) == RECORD_ID
    stored = (folder(tmp_path) / "record.dsse.json").read_bytes()
    assert stored == RECORD
    assert hashlib.sha256(stored).hexdigest() == RECORD_ID
    assert store.read_record(RECORD_ID) == RECORD
    assert store.read_meta(RECORD_ID) == {"receivedAt": T0}


def test_bytes_are_never_normalised(store):
    variants = [RECORD, RECORD.replace(b", ", b","), RECORD + b"\n"]
    ids = [store.put_record(v, T0) for v in variants]
    assert len(set(ids)) == 3
    assert [store.read_record(i) for i in ids] == variants


def test_storing_a_record_again_keeps_the_first_receipt_time(store):
    store.put_record(RECORD, T0)
    store.put_record(RECORD, T1)
    assert store.read_meta(RECORD_ID) == {"receivedAt": T0}


def test_record_ids_lists_every_stored_record_in_order(store):
    ids = [store.put_record(raw, T0) for raw in (RECORD, RECORD + b"\n", RECORD + b" ")]
    assert store.record_ids() == sorted(ids)


def test_an_empty_store_has_no_record_ids(store):
    assert store.record_ids() == []


def test_unknown_records_read_as_none(store):
    assert store.read_record(RECORD_ID) is None
    assert store.read_meta(RECORD_ID) is None


@pytest.mark.parametrize("bad", ["../" * 21 + "etc", "A" * 64, "ab" * 31, "g" * 64, ""])
def test_record_ids_must_be_64_lowercase_hex(store, bad):
    with pytest.raises(ValueError):
        store.read_record(bad)


def test_bytes_that_no_longer_match_their_id_are_refused(store, tmp_path):
    store.put_record(RECORD, T0)
    (folder(tmp_path) / "record.dsse.json").write_bytes(RECORD + b" ")
    with pytest.raises(Corrupt):
        store.read_record(RECORD_ID)


def test_writes_leave_only_the_record_and_its_meta(store, tmp_path):
    store.put_record(RECORD, T0)
    assert sorted(p.name for p in folder(tmp_path).iterdir()) == ["meta.json", "record.dsse.json"]


def test_a_failed_write_leaves_no_partial_file(store, tmp_path, monkeypatch):
    def fail(src, dst):
        raise OSError("disk full")

    monkeypatch.setattr(store_module.os, "replace", fail)
    with pytest.raises(OSError):
        store.put_record(RECORD, T0)
    assert list(folder(tmp_path).iterdir()) == []
