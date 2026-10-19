import base64
import json

import pytest

from registry import spec
from registry.envelope import Unrecognized, parse_receipt

STATEMENT = {
    "_type": spec.STATEMENT_TYPE,
    "subject": [{"name": "s", "digest": {"sha256": "ab" * 32}}],
    "predicateType": spec.PREDICATE_TYPE,
    "predicate": {},  # recognition reads no predicate field: that is the schema's job
}


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def envelope(payload: bytes | str | None = None, **fields) -> dict:
    """A DSSE envelope around `payload` (default: STATEMENT). Recognition never checks the signature."""
    if payload is None:
        payload = json.dumps(STATEMENT).encode()
    env = {
        "payloadType": spec.PAYLOAD_TYPE,
        "payload": payload if isinstance(payload, str) else b64(payload),
        "signatures": [{"keyid": "anything", "sig": b64(b"not checked here")}],
    }
    env.update(fields)
    return env


def unpadded_payload() -> str:
    """Base64 of a statement whose encoding needs '=' padding, with the padding stripped."""
    body = json.dumps(STATEMENT).encode()
    while len(body) % 3 == 0:
        body += b" "  # trailing whitespace is valid JSON
    return b64(body).rstrip("=")


def raw(obj) -> bytes:
    return json.dumps(obj).encode()


def statement(**changes) -> bytes:
    return json.dumps({**STATEMENT, **changes}).encode()


def rejected(body: bytes, match: str) -> None:
    with pytest.raises(Unrecognized, match=match):
        parse_receipt(body)


def test_recognises_a_receipt_envelope():
    body = raw(envelope())
    receipt = parse_receipt(body)
    assert receipt.raw is body
    assert receipt.payload == json.dumps(STATEMENT).encode()
    assert receipt.statement == STATEMENT


def test_keyid_is_optional():
    env = envelope(signatures=[{"sig": b64(b"s")}])
    assert parse_receipt(raw(env)).statement == STATEMENT


@pytest.mark.parametrize(
    "body, match",
    [
        (b"\xff\xfe", "envelope is not valid JSON"),
        (b"not json", "envelope is not valid JSON"),
        (b'{"payload": "a", "payload": "b"}', 'duplicate key "payload"'),
        (b'{"payloadType": NaN}', "envelope is not valid JSON"),
        (b"[]", "envelope: Input should be a valid dictionary"),
        (b"[" * 10_000 + b"]" * 10_000, "envelope is not valid JSON"),
    ],
    ids=["not-utf8", "not-json", "duplicate-key", "nan", "not-object", "deeply-nested"],
)
def test_envelope_must_be_strict_json_object(body, match):
    rejected(body, match)


def test_envelope_keys_must_be_exact():
    rejected(raw(envelope(extra="x")), "extra: Extra inputs are not permitted")
    env = envelope()
    del env["signatures"]
    rejected(raw(env), "signatures: Field required")


def test_envelope_keys_must_use_the_dsse_spelling():
    # The upstream model would also accept its snake_case field names; DSSE's JSON uses payloadType.
    env = envelope()
    env["payload_type"] = env.pop("payloadType")
    rejected(raw(env), "payloadType: Field required")


@pytest.mark.parametrize(
    "signatures, match",
    [
        ([], "exactly one signature, got 0"),
        ([{"sig": "YQ=="}, {"sig": "Yg=="}], "exactly one signature, got 2"),
        ("YQ==", "signatures: Input should be a valid list"),
        ([{"keyid": "k"}], r"signatures\.0\.sig: Field required"),
        ([{"sig": 1}], r"signatures\.0\.sig"),
        ([{"sig": "YQ==", "keyid": 1}], r"signatures\.0\.keyid"),
        ([{"sig": "YQ==", "cert": "x"}], r"signatures\.0\.cert: Extra inputs are not permitted"),
    ],
    ids=["none", "two", "not-a-list", "no-sig", "sig-not-string", "keyid-not-string", "extra-field"],
)
def test_exactly_one_well_formed_signature(signatures, match):
    rejected(raw(envelope(signatures=signatures)), match)


def test_payload_type_must_be_in_toto():
    rejected(raw(envelope(payloadType="application/json")), "payloadType must be")


@pytest.mark.parametrize(
    "payload",
    [
        unpadded_payload(),
        b64(json.dumps(STATEMENT).encode())[:-4] + "\n" + b64(json.dumps(STATEMENT).encode())[-4:],
        base64.urlsafe_b64encode(b"\xfb\xff" + json.dumps(STATEMENT).encode()).decode(),  # '-' and '_'
        "ünïcode",
        7,
        "!!!!",  # the upstream model's lenient decoding would turn this into empty bytes
    ],
    ids=["no-padding", "embedded-newline", "urlsafe-alphabet", "non-ascii", "not-a-string", "not-base64"],
)
def test_payload_must_be_standard_base64(payload):
    # Rejected either by the upstream model ("payload: ...") or by our strict check on top of it.
    env = envelope()
    env["payload"] = payload
    rejected(raw(env), "payload(: | is not standard base64)")


@pytest.mark.parametrize(
    "payload, match",
    [
        (b"not json", "payload is not valid JSON"),
        (b'{"_type": "a", "_type": "b"}', 'duplicate key "_type"'),
        (statement(predicate={"evalPipeline": {"a": 1}}).replace(b'{"a": 1}', b'{"a": 1, "a": 2}'),
         'duplicate key "a"'),
        (b"[1]", "statement: Input should be a valid dictionary"),
        (statement(comment="x"), "unknown top-level field"),
        (statement(_type="https://in-toto.io/Statement/v0.1"), "_type: Input should be"),
        (statement(predicateType="https://slsa.dev/provenance/v1"),
         r"predicateType: Input should be .*, got 'https://slsa\.dev/provenance/v1'"),
        (statement(predicate=[]), "predicate: Input should be a valid dictionary"),
    ],
    ids=["not-json", "duplicate-key", "nested-duplicate-key", "not-object", "extra-field", "wrong-type",
         "wrong-predicate-type", "predicate-not-object"],
)
def test_statement_must_be_a_syft_receipt(payload, match):
    rejected(raw(envelope(payload)), match)


@pytest.mark.parametrize("field", ["_type", "predicateType", "predicate"])
def test_missing_statement_fields_are_rejected(field):
    body = {k: v for k, v in STATEMENT.items() if k != field}
    rejected(raw(envelope(json.dumps(body).encode())), f"{field}: Field required")
