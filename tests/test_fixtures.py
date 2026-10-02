"""The committed fixtures agree with scripts/make_fixtures.py, with expected.json, and with recognition
and the schema. Check verdicts beyond recognition and schema are tested with the checks."""

import base64
import hashlib
import json
import re
import runpy

import pytest
from fixture_data import CHECKED, DEV_POLICY, EXPECTED, ROOT, record

from registry import spec
from registry.checks_software import eval_digest, pipeline_digest
from registry.config import load_config
from registry.envelope import Unrecognized, parse_receipt
from registry.evalresult import SchemaError, parse_statement
from registry.model import Status

WORKED_EXAMPLE = ROOT / "fixtures/evalresult/worked_example.statement.json"
UNRECOGNIZED = {name for name, e in EXPECTED.items() if e["dev"]["status"] == 400}
SCHEMA_INVALID = {name for name, e in EXPECTED.items() if e["dev"]["status"] == 422 and e["checks"] is None}
# What each unrecognised fixture's rejection must say.
REASONS = {
    "U1_predicate_type": "statement: predicateType: Input should be",
    "U2_payload_type": "payloadType must be",
    "U3_extra_field": "unknown top-level field(s): comment",
    "U4_duplicate_key": 'duplicate key "predicateType"',
    "U5_two_signatures": "exactly one signature, got 2",
    "U6_dbe_sample": "envelope: payload: Field required",
    "S1_no_reference_value": "referenceValue: Field required",
    "S2_worked_example_roles": "exactly one party with role",
    "S3_two_benchmark_owners": "exactly one party with role",
    "S4_two_model_owners": f"exactly one party with role {spec.MODEL_OWNER!r}, got 2",
    "S5_same_owner_key": f"the {spec.MODEL_OWNER!r} and {spec.BENCHMARK_OWNER!r} parties must have different keys",
}
UNLISTED = "C14_unlisted_bo"  # its benchmark-owner key must stay off the dev policy (403)


def test_regenerating_reproduces_the_committed_fixtures():
    files, expected = runpy.run_path(str(ROOT / "scripts/make_fixtures.py"))["build"]()
    generated = ROOT / "fixtures/generated"
    assert sorted(p.name for p in generated.iterdir()) == sorted(files)
    for name, data in files.items():
        assert (generated / name).read_bytes() == data, name
    assert json.loads(json.dumps(expected)) == EXPECTED


@pytest.mark.parametrize("name", EXPECTED)
def test_record_id_is_sha256_of_the_file(name):
    assert hashlib.sha256(record(name)).hexdigest() == EXPECTED[name]["recordId"]


def test_every_rejected_fixture_has_a_reason():
    assert UNRECOGNIZED | SCHEMA_INVALID == set(REASONS)


@pytest.mark.parametrize("name", sorted(UNRECOGNIZED))
def test_unrecognized_fixtures_are_rejected_with_their_reason(name):
    with pytest.raises(Unrecognized, match=re.escape(REASONS[name])):
        parse_receipt(record(name))


@pytest.mark.parametrize("name", sorted(SCHEMA_INVALID))
def test_schema_invalid_fixtures_are_recognized_then_rejected_with_their_reason(name):
    receipt = parse_receipt(record(name))
    with pytest.raises(SchemaError, match=re.escape(REASONS[name])):
        parse_statement(receipt.statement)


def test_dev_example_policy_lists_every_fixture_benchmark_owner_except_the_unlisted_one():
    listed = {owner.public_key for owner in
              load_config({"REGISTRY_POLICY": str(DEV_POLICY)}).policy.benchmark_owners}
    used = {}
    for name in CHECKED:
        parties = parse_statement(parse_receipt(record(name)).statement).predicate.parties
        owner, = (party for party in parties if party.role == spec.BENCHMARK_OWNER)
        used.setdefault(owner.identity.publicKey, set()).add(name)
    unlisted_key, = (key for key, names in used.items() if UNLISTED in names)
    assert used[unlisted_key] == {UNLISTED}
    assert listed == set(used) - {unlisted_key}


@pytest.mark.parametrize("name", sorted(CHECKED))
def test_checked_fixtures_pass_recognition_and_schema(name):
    parse_statement(parse_receipt(record(name)).statement)


@pytest.mark.parametrize("name", sorted(CHECKED))
def test_derived_digests_match_the_expected_check_5(name):
    predicate = parse_receipt(record(name)).statement["predicate"]
    subject = parse_receipt(record(name)).statement["subject"][0]["digest"]["sha256"]
    recomputed = pipeline_digest(predicate["system"]["components"])
    holds = (recomputed == predicate["system"]["pipelineDigest"] == subject
             and eval_digest(predicate["eval"]["evalSet"], predicate["eval"]["harness"]) == predicate["eval"]["evalDigest"])
    assert holds == (EXPECTED[name]["checks"]["digests"] == Status.PASS)


def test_sim_a_differs_from_the_worked_example_only_in_execution_and_party_roles():
    envelope = json.loads(record("sim_A"))
    sim_a = json.loads(base64.b64decode(envelope["payload"], validate=True))
    example = json.loads(WORKED_EXAMPLE.read_text())
    differences = set(_diff(example, sim_a))
    assert differences == {
        "predicate.execution.runPublicKey",
        "predicate.execution.attestation.quote",
        "predicate.execution.attestation.measurement",
        "predicate.execution.attestation.reportData",
        "predicate.parties.0.role",
        "predicate.parties.1.role",
    }
    roles = [party["role"] for party in sim_a["predicate"]["parties"]]
    assert roles[:2] == [spec.MODEL_OWNER, spec.BENCHMARK_OWNER]


def _diff(a, b, path=""):
    if isinstance(a, dict) and isinstance(b, dict):
        for key in a.keys() | b.keys():
            yield from _diff(a.get(key), b.get(key), f"{path}.{key}" if path else key)
    elif isinstance(a, list) and isinstance(b, list) and len(a) == len(b):
        for i, (x, y) in enumerate(zip(a, b)):
            yield from _diff(x, y, f"{path}.{i}")
    elif a != b:
        yield path
