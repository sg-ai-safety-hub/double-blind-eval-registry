"""The committed fixtures agree with scripts/make_fixtures.py, with expected.json, and with recognition
and the schema. Check verdicts beyond recognition and schema are tested with the checks."""

import base64
import hashlib
import json
import re
import runpy

import pytest
import rfc8785
from fixture_data import CHECKED, DEV_POLICY, EXPECTED, ROOT, record

from registry import spec
from registry.config import load_config
from registry.envelope import Unrecognized, parse_receipt
from registry.model import Status
from registry.syft_receipt import SchemaError, parse_statement

UNRECOGNIZED = {name for name, e in EXPECTED.items() if e["dev"]["status"] == 400}
SCHEMA_INVALID = {name for name, e in EXPECTED.items() if e["dev"]["status"] == 422 and e["checks"] is None}
# What each rejected fixture's rejection must say.
REASONS = {
    "U1_predicate_type": "statement: predicateType: Input should be",
    "U2_payload_type": "payloadType must be",
    "U3_extra_field": "unknown top-level field(s): comment",
    "U4_duplicate_key": 'duplicate key "predicateType"',
    "U5_two_signatures": "exactly one signature, got 2",
    "U6_dbe_sample": "envelope: payload: Field required",
    "U7_unsigned_statement": "signatures: Field required",
    "S1_no_reference_value": "referenceValue: Field required",
    "S2_no_consent": "predicate.consent: Field required",
    "S3_no_signing_key": f"exactly one {spec.SIGNING_KEY_ID!r} item, got 0",
}
UNLISTED = "C6_unlisted_approver"  # no approver of it may be on the dev policy


def statement(name: str) -> dict:
    return parse_receipt(record(name)).statement


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


def test_dev_example_policy_lists_an_approver_of_every_fixture_except_the_unlisted_one():
    listed = {owner.email for owner in load_config({"REGISTRY_POLICY": str(DEV_POLICY)}).policy.benchmark_owners}
    used = set()
    for name in CHECKED:
        approvers = {approval["party"] for approval in statement(name)["predicate"]["consent"]["approvals"]}
        assert bool(approvers & listed) == (name != UNLISTED), name
        used |= approvers
    assert listed <= used  # nothing listed that no fixture needs


@pytest.mark.parametrize("name", sorted(CHECKED))
def test_checked_fixtures_pass_recognition_and_schema(name):
    parse_statement(statement(name))


@pytest.mark.parametrize("name", sorted(CHECKED))
def test_the_subject_digest_matches_the_expected_check_5(name):
    s = statement(name)
    holds = hashlib.sha256(rfc8785.dumps(s["predicate"]["evalPipeline"])).hexdigest() == s["subject"][0]["digest"]["sha256"]
    assert holds == (EXPECTED[name]["checks"]["digests"] == Status.PASS)


def test_sim_a_differs_from_openmined_s_statement_only_in_its_key_binding_and_unread_parts():
    sim_a = statement("sim_A")
    openmined = statement("om_receipt")
    assert set(_diff(openmined, sim_a)) == {
        "predicate.execution.attestation.keyBinding.crypto_material",  # names fixture key A
        "predicate.execution.attestation.keyBinding.cpu_evidence.report_base64",  # SIMULATED
        "predicate.execution.attestation.keyBinding.collateral",  # left out: bulky, never read
        "predicate.job.code.0.content",
        "predicate.outputs.0.content",
    }
    material = json.loads(base64.b64decode(sim_a["predicate"]["execution"]["attestation"]["keyBinding"]["crypto_material"]))
    assert [item["id"] for item in material["items"]] == ["tls", "hpke", spec.SIGNING_KEY_ID]


def _diff(a, b, path=""):
    if isinstance(a, dict) and isinstance(b, dict):
        for key in a.keys() | b.keys():
            yield from _diff(a.get(key), b.get(key), f"{path}.{key}" if path else key)
    elif isinstance(a, list) and isinstance(b, list) and len(a) == len(b):
        for i, (x, y) in enumerate(zip(a, b)):
            yield from _diff(x, y, f"{path}.{i}")
    elif a != b:
        yield path
