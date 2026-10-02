import copy
import json
from pathlib import Path

import pytest

from registry import spec
from registry.evalresult import SchemaError, parse_statement

WORKED_EXAMPLE = Path(__file__).resolve().parents[1] / "fixtures/evalresult/worked_example.statement.json"
WORKED_EXAMPLE_ROLES = {"model_provider": spec.MODEL_OWNER, "evaluator": spec.BENCHMARK_OWNER}  # to DBE's names
OWNERS = {spec.MODEL_OWNER: 0, spec.BENCHMARK_OWNER: 1}  # each owner's index in the worked example's parties


def worked_example() -> dict:
    """The worked example with DBE's party names; it meets the schema as it stands."""
    statement = json.loads(WORKED_EXAMPLE.read_text())
    for party in statement["predicate"]["parties"]:
        party["role"] = WORKED_EXAMPLE_ROLES.get(party["role"], party["role"])
    return statement


def changed(path: str, value=None, *, delete: bool = False) -> dict:
    """The worked example with one field (dotted path, list indices allowed) set or deleted."""
    statement = worked_example()
    *parents, last = path.split(".")
    node = statement
    for key in parents:
        node = node[int(key)] if isinstance(node, list) else node[key]
    if delete:
        del node[int(last) if isinstance(node, list) else last]
    else:
        node[int(last) if isinstance(node, list) else last] = value
    return statement


def invalid(statement: dict, match: str) -> None:
    with pytest.raises(SchemaError, match=match):
        parse_statement(statement)


def test_worked_example_meets_the_schema():
    parsed = parse_statement(worked_example())
    assert parsed.predicate.system.pipelineDigest == parsed.subject[0].digest.sha256
    assert parsed.predicate.execution.attestation.referenceValue.tag == "v0.1.0"
    assert [c.role for c in parsed.predicate.system.components][0] == "adapter"


def test_the_worked_example_role_names_alone_are_rejected():
    statement = json.loads(WORKED_EXAMPLE.read_text())  # its own two role names, and no benchmark owner
    invalid(statement, "exactly one party with role")


def test_each_owner_key_is_readable_from_the_model():
    predicate = parse_statement(worked_example()).predicate
    for role, index in OWNERS.items():
        assert predicate.owner_key(role) == worked_example()["predicate"]["parties"][index]["identity"]["publicKey"]


@pytest.mark.parametrize("role", OWNERS)
def test_two_parties_with_the_same_owner_role_are_rejected(role):
    statement = worked_example()
    statement["predicate"]["parties"].append(copy.deepcopy(statement["predicate"]["parties"][OWNERS[role]]))
    invalid(statement, f"exactly one party with role {role!r}, got 2")


@pytest.mark.parametrize("role", OWNERS)
def test_a_missing_owner_is_rejected(role):
    invalid(changed(f"predicate.parties.{OWNERS[role]}", delete=True), f"exactly one party with role {role!r}, got 0")


@pytest.mark.parametrize("role", OWNERS)
@pytest.mark.parametrize(
    "identity",
    [
        {"scheme": "named/1", "name": "Some Lab"},
        {"scheme": spec.ED25519_KEY_SCHEME},
        {"scheme": spec.ED25519_KEY_SCHEME, "publicKey": "3888833EB8844B23A79A5A4BF258B3C718FD0CC3997B8D000F29F88855252D9C"},
        {"scheme": spec.ED25519_KEY_SCHEME, "publicKey": "3888833e"},
    ],
    ids=["named", "no-key", "uppercase-key", "short-key"],
)
def test_each_owner_is_identified_by_an_ed25519_key(role, identity):
    # The acceptance gate matches the benchmark owner's key against the policy; check 7 verifies both owners'.
    invalid(changed(f"predicate.parties.{OWNERS[role]}.identity", identity), f"the {role!r} party's identity must be")


def test_the_two_owners_need_different_keys():
    # One key can't stand for both owners, so consent always comes from two keys.
    statement = worked_example()
    parties = statement["predicate"]["parties"]
    parties[OWNERS[spec.MODEL_OWNER]]["identity"] = copy.deepcopy(parties[OWNERS[spec.BENCHMARK_OWNER]]["identity"])
    invalid(statement, f"the {spec.MODEL_OWNER!r} and {spec.BENCHMARK_OWNER!r} parties must have different keys")


def test_errors_name_the_field():
    with pytest.raises(SchemaError) as e:
        parse_statement(changed("predicate.execution.attestation.referenceValue", delete=True))
    assert e.value.errors == ["predicate.execution.attestation.referenceValue: Field required"]


@pytest.mark.parametrize(
    "path, value",
    [
        ("predicate.execution.attestation.referenceValue.source", "github"),
        ("predicate.execution.attestation.referenceValue.repo", "tinfoilsh/double-blind-eval"),
        ("predicate.execution.attestation.referenceValue.repo", "github.com/tinfoilsh/double-blind-eval/x"),
        ("predicate.execution.attestation.referenceValue.repo", "https://github.com/tinfoilsh/double-blind-eval"),
        ("predicate.execution.attestation.referenceValue.tag", ""),
        ("predicate.execution.attestation.referenceValue.tag", 1),
    ],
    ids=["source-not-sigstore", "repo-no-host", "repo-extra-path", "repo-url", "tag-empty", "tag-not-string"],
)
def test_reference_value_is_a_sigstore_github_release(path, value):
    invalid(changed(path, value), "referenceValue")


def test_reference_value_bundle_ref_is_optional_and_ignored():
    statement = changed("predicate.execution.attestation.referenceValue.bundleRef", "anything")
    parse_statement(statement)


@pytest.mark.parametrize(
    "path, value",
    [
        ("predicate.system.pipelineDigest", "9358688C07C087FBB1E602DC64F0B02A3424121975F982B2F5070CD4446BFBC5"),
        ("predicate.system.pipelineDigest", "9358688c"),
        ("predicate.eval.evalDigest", "sha256:639c3a535d8327abee97d729e0a16245605333924709b03c3a4a4a845c771375"),
        ("subject.0.digest.sha256", "not-hex"),
        ("predicate.system.components.0.digest", "sha256:932e9f48f32c1eb067829136e7bd7cd5d07372b18cef469509c49b0921a42604"),
        ("predicate.system.components.2.digest", "ac6360062cf08cd039f09225e745e699bb021d21b8ac26a1eac20df725d0e134"),
        ("predicate.eval.harness.digest", "ac6360062cf08cd039f09225e745e699bb021d21b8ac26a1eac20df725d0e134"),
        ("predicate.eval.evalSet.digest", "254082E2808A4AF8AE1B55965759801B3F4C32EFE8A19C057F1310C2FAE338EA"),
        ("predicate.consent.manifestDigest", "8112aa"),
    ],
    ids=["uppercase", "short", "prefixed-bare-digest", "subject-not-hex", "non-oci-with-prefix",
         "oci-without-prefix", "oci-harness-without-prefix", "eval-set-uppercase", "manifest-short"],
)
def test_digests_are_lowercase_hex_and_oci_is_prefixed(path, value):
    invalid(changed(path, value), path.split(".")[-1])


@pytest.mark.parametrize("value", ["3A1F29D3B41787AD", "3a1", "", "zz"], ids=["uppercase", "odd", "empty", "not-hex"])
def test_run_public_key_is_lowercase_hex(value):
    invalid(changed("predicate.execution.runPublicKey", value), "runPublicKey")


@pytest.mark.parametrize(
    "value",
    ["2026-09-14T02:42:58.5Z", "2026-09-14T02:42:58+00:00", "2026-09-14 02:42:58Z", "2026-02-30T02:42:58Z",
     "2026-9-14T2:42:58Z", 1757817778],
    ids=["fractional", "offset", "space", "no-such-day", "unpadded", "number"],
)
def test_times_are_rfc3339_utc_seconds(value):
    invalid(changed("predicate.execution.startedAt", value), "startedAt")


@pytest.mark.parametrize(
    "path, value, delete",
    [
        ("subject", [], False),
        ("subject.1", {"name": "b", "digest": {"sha256": "ab" * 32}}, False),
        ("subject.0.digest.sha256", None, True),
    ],
    ids=["none", "two", "no-sha256"],
)
def test_subject_is_exactly_one_sha256_digest(path, value, delete):
    if path == "subject.1":
        statement = worked_example()
        statement["subject"].append(value)
    else:
        statement = changed(path, value, delete=delete)
    invalid(statement, "subject")


@pytest.mark.parametrize(
    "path",
    ["predicate.system", "predicate.system.components.0.role", "predicate.eval.harness", "predicate.results.metrics",
     "predicate.execution.attestation.quote", "predicate.execution.attestation.measurement",
     "predicate.execution.attestation.reportData", "predicate.execution.attestation.type",
     "predicate.execution.finishedAt", "predicate.execution.runPublicKey", "predicate.parties",
     "predicate.parties.2.identity.scheme", "predicate.consent.approvals.0.signature", "predicate.version"],
)
def test_required_fields(path):
    invalid(changed(path, delete=True), "Field required")


def test_system_has_at_least_one_component():
    invalid(changed("predicate.system.components", []), "components")


@pytest.mark.parametrize(
    "path, value",
    [
        ("predicate.eval.public", "false"),
        ("predicate.results.counts.submitted", "10"),
        ("predicate.results.scored", 0),
        ("predicate.results.metrics", {"accuracy": 1}),
        ("predicate.execution.attestation.quote", 7),
        ("predicate.parties.0.role", None),
    ],
    ids=["bool-as-string", "int-as-string", "bool-as-int", "metrics-not-a-list", "quote-not-string", "role-null"],
)
def test_values_are_not_coerced(path, value):
    invalid(changed(path, value), path.split(".")[-1])


def test_metric_items_are_opaque():
    parse_statement(changed("predicate.results.metrics", [{"name": "x", "value": 1}, "free text", [1, 2], None]))


def test_optional_parts_may_be_absent():
    statement = worked_example()
    predicate = statement["predicate"]
    for key in ("consent", "policy"):
        del predicate[key]
    for key in ("platform", "cvmVersion", "runId", "configDigest"):
        del predicate["execution"][key]
    del predicate["results"]["counts"]
    del predicate["eval"]["harnessVersion"]
    parse_statement(statement)


def test_extra_predicate_fields_are_allowed():
    statement = worked_example()
    statement["predicate"]["notes"] = {"anything": [1, 2]}
    statement["predicate"]["execution"]["attestation"]["gpu"] = {"type": "nvidia-cc"}
    statement["predicate"]["system"]["components"][0]["license"] = "x"
    parse_statement(statement)


def test_also_known_as_needs_a_digest_or_ref():
    statement = worked_example()
    component = statement["predicate"]["system"]["components"][1]
    component["alsoKnownAs"].append({"scheme": "oms/1"})
    invalid(statement, "alsoKnownAs")


def test_parse_does_not_modify_its_input():
    statement = worked_example()
    before = copy.deepcopy(statement)
    parse_statement(statement)
    assert statement == before
