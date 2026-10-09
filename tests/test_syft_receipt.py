import base64
import copy
import dataclasses
import json
from pathlib import Path

import pytest

from registry import spec
from registry.model import CHECK_IDS, Accepted, Check, Enclave, Publication, Status
from registry.syft_receipt import ADAPTER_VERSION, SchemaError, parse_statement, to_index

OPENMINED = Path(__file__).resolve().parents[1] / "fixtures/openmined/receipt.dsse.json"
KEY_BINDING = "predicate.execution.attestation.keyBinding"


def receipt() -> dict:
    """The statement OpenMined's enclave signed: it meets the schema as it stands."""
    return json.loads(base64.b64decode(json.loads(OPENMINED.read_bytes())["payload"]))


def changed(path: str, value=None, *, delete: bool = False, statement: dict | None = None) -> dict:
    """The statement (default: OpenMined's) with one field (dotted path, list indices allowed) set or deleted."""
    statement = copy.deepcopy(statement or receipt())
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


def crypto_material(*items: dict, format_: str = spec.CRYPTO_MATERIAL_FORMAT) -> str:
    return base64.b64encode(json.dumps({"format": format_, "items": list(items)}).encode()).decode()


def item(id_: str = spec.SIGNING_KEY_ID, format_: str = spec.SPKI_KEY_FORMAT, data: str = "302a" + "ab" * 40) -> dict:
    return {"id": id_, "format": format_, "data": data}


def test_openmined_s_receipt_meets_the_schema():
    parsed = parse_statement(receipt())
    assert [m.role for m in parsed.predicate.evalPipeline.models] == [spec.BASE_MODEL_ROLE, "adapter", "safety_classifier"]
    assert parsed.predicate.execution.attestation.referenceValue.tag == "v0.1.28"
    assert parsed.predicate.consent.approvals[0].party == "benchmark_owner@openmined.org"


def test_the_signing_key_is_crypto_material_s_enclave_signing_key_item():
    material = receipt()["predicate"]["execution"]["attestation"]["keyBinding"]["crypto_material"]
    signing_key, = (i["data"] for i in json.loads(base64.b64decode(material))["items"] if i["id"] == spec.SIGNING_KEY_ID)
    assert parse_statement(receipt()).predicate.execution.attestation.keyBinding.signing_key == signing_key


def test_errors_name_the_field():
    with pytest.raises(SchemaError) as e:
        parse_statement(changed("predicate.execution.attestation.referenceValue", delete=True))
    assert e.value.errors == ["predicate.execution.attestation.referenceValue: Field required"]


@pytest.mark.parametrize(
    "path, value",
    [
        ("predicate.execution.attestation.referenceValue.source", "github"),
        ("predicate.execution.attestation.referenceValue.repo", "OpenMined/syft-enclave-tinfoil"),
        ("predicate.execution.attestation.referenceValue.repo", "github.com/OpenMined/syft-enclave-tinfoil/x"),
        ("predicate.execution.attestation.referenceValue.repo", "https://github.com/OpenMined/syft-enclave-tinfoil"),
        ("predicate.execution.attestation.referenceValue.tag", ""),
        ("predicate.execution.attestation.referenceValue.tag", 1),
    ],
    ids=["source-not-sigstore", "repo-no-host", "repo-extra-path", "repo-url", "tag-empty", "tag-not-string"],
)
def test_reference_value_is_a_sigstore_github_release(path, value):
    invalid(changed(path, value), "referenceValue")


@pytest.mark.parametrize(
    "path, value",
    [
        ("subject.0.digest.sha256", "not-hex"),
        ("predicate.evalPipeline.models.0.digest", "D1E29A1AD2EF057D7D4EBFE3C435A43E015D8B202C8ACE1719A5B1EB5B17EB15"),
        ("predicate.evalPipeline.models.0.digest",
         "sha256:d1e29a1ad2ef057d7d4ebfe3c435a43e015d8b202c8ace1719a5b1eb5b17eb15"),
        ("predicate.evalPipeline.config.0.digest", "d1c95238"),
        ("predicate.evalDataset.digest", "sha256:3e1abebd6dbf673bf11027e4c0aec0fce9fa55a5c82cabba715ae3c90b9c6d38"),
        ("predicate.consent.manifestDigest", "1dd67b"),
        (f"{KEY_BINDING}.challenge.nonce", "7C579C8A8CD413B9FD9D0A111D1978CA3E5FE62E9F6B5984522B4B8836D29608"),
    ],
    ids=["subject-not-hex", "uppercase", "non-oci-with-prefix", "short", "dataset-with-prefix", "manifest-short",
         "nonce-uppercase"],
)
def test_digests_are_lowercase_hex(path, value):
    invalid(changed(path, value), path.split(".")[-1])


def test_an_oci_digest_needs_its_prefix():
    statement = receipt()
    models = statement["predicate"]["evalPipeline"]["models"]
    models.append({"role": "runtime", "scheme": spec.OCI_SCHEME, "digest": "ab" * 32})
    invalid(statement, f"{spec.OCI_SCHEME} digest must match")
    models[-1]["digest"] = "sha256:" + "ab" * 32
    parse_statement(statement)


@pytest.mark.parametrize(
    "path, value",
    [
        (f"{KEY_BINDING}.format", "https://tinfoil.sh/predicate/attestation/v4"),
        (f"{KEY_BINDING}.challenge.report_data_algorithm", "https://tinfoil.sh/report-data/v2"),
        (f"{KEY_BINDING}.cpu_evidence.format", "https://tinfoil.sh/format/tdx-quote/v1"),
    ],
    ids=["key-binding", "report-data", "cpu-evidence"],
)
def test_tinfoil_formats_are_pinned(path, value):
    # Fail closed: another version may mean something else.
    invalid(changed(path, value), path.split(".")[-1])


def test_subject_is_exactly_one_sha256_digest():
    statement = receipt()
    two = changed("subject", statement["subject"] * 2)
    for wrong in (changed("subject", []), two, changed("subject.0.digest.sha256", delete=True)):
        invalid(wrong, "subject")


@pytest.mark.parametrize(
    "path",
    ["predicate.evalPipeline", "predicate.evalPipeline.models", "predicate.evalPipeline.models.0.role",
     "predicate.evalPipeline.models.0.digest", "predicate.evalPipeline.config.0.kind", "predicate.evalDataset",
     "predicate.evalDataset.digest", "predicate.results", "predicate.results.metrics",
     "predicate.execution.attestation.type", f"{KEY_BINDING}", f"{KEY_BINDING}.challenge.nonce",
     f"{KEY_BINDING}.crypto_material", f"{KEY_BINDING}.device_evidence", f"{KEY_BINDING}.cpu_evidence.report_base64",
     "predicate.execution.startedAt", "predicate.execution.finishedAt", "predicate.parties",
     "predicate.parties.0.email", "predicate.consent", "predicate.consent.manifestDigest",
     "predicate.consent.approvals.0.party"],
)
def test_required_fields(path):
    invalid(changed(path, delete=True), "Field required")


@pytest.mark.parametrize("path", ["predicate.evalPipeline.models", "predicate.consent.approvals"])
def test_at_least_one_model_and_one_approval(path):
    invalid(changed(path, []), path.split(".")[-1])


@pytest.mark.parametrize(
    "path, value",
    [
        ("predicate.results.counts.submitted", "5"),
        ("predicate.results.metrics", {"accuracy": 1}),
        (f"{KEY_BINDING}.cpu_evidence.report_base64", 7),
        ("predicate.parties.0.role", None),
        ("predicate.execution.startedAt", 1791209530),
        ("predicate.consent.approvals.0.party", 1),
    ],
    ids=["int-as-string", "metrics-not-a-list", "report-not-string", "role-null", "time-as-number", "party-not-string"],
)
def test_values_are_not_coerced(path, value):
    invalid(changed(path, value), path.split(".")[-1])


def test_metric_items_are_opaque():
    parse_statement(changed("predicate.results.metrics", [{"name": "x", "value": 1}, "free text", [1, 2], None]))


@pytest.mark.parametrize("value", ["2026-10-07T10:12:10.436375Z", "2026-10-07T10:12:10+00:00", "whenever"])
def test_times_are_kept_as_reported(value):
    # They are the enclave's own clock, set by the host: shown as reported, never relied on.
    parse_statement(changed("predicate.execution.startedAt", value))


def test_optional_parts_may_be_absent():
    statement = receipt()
    predicate = statement["predicate"]
    del statement["subject"][0]["name"]
    for model in predicate["evalPipeline"]["models"]:
        model.pop("name"), model.pop("alsoKnownAs", None)
    del predicate["evalPipeline"]["config"]
    del predicate["evalDataset"]["name"]
    del predicate["results"]["counts"]
    for key in ("platform", "cvmVersion", "runId", "configDigest"):
        del predicate["execution"][key]
    for approval in predicate["consent"]["approvals"]:
        del approval["approvedAt"]
    parse_statement(statement)


def test_extra_fields_are_allowed():
    statement = receipt()
    statement["predicate"]["notes"] = {"anything": [1, 2]}
    statement["predicate"]["execution"]["attestation"]["gpu"] = {"type": "nvidia-cc"}
    statement["predicate"]["evalPipeline"]["models"][0]["license"] = "x"
    parse_statement(statement)


def test_also_known_as_needs_a_digest_or_ref():
    statement = receipt()
    statement["predicate"]["evalPipeline"]["models"][0]["alsoKnownAs"].append({"scheme": "oms/1"})
    invalid(statement, "alsoKnownAs")


def test_parse_does_not_modify_its_input():
    statement = receipt()
    before = copy.deepcopy(statement)
    parse_statement(statement)
    assert statement == before


# --- crypto_material and device_evidence -----------------------------------------------

@pytest.mark.parametrize("field", ["crypto_material", "device_evidence"])
@pytest.mark.parametrize("value", ["not base64!", "e30", "e30=\n"], ids=["garbage", "unpadded", "newline"])
def test_attested_sections_must_be_standard_base64(field, value):
    # check 2 hashes their decoded bytes, so a lenient decoder must not get to choose them.
    invalid(changed(f"{KEY_BINDING}.{field}", value), field)


@pytest.mark.parametrize(
    "material, match",
    [
        (base64.b64encode(b"not json").decode(), "not valid JSON"),
        (base64.b64encode(b'{"format": "a", "format": "b"}').decode(), 'duplicate key "format"'),
        (crypto_material(item(), format_="https://tinfoil.sh/crypto-material/v2"), "format"),
        (crypto_material(item(id_="tls")), f"exactly one {spec.SIGNING_KEY_ID!r} item, got 0"),
        (crypto_material(item(), item()), f"exactly one {spec.SIGNING_KEY_ID!r} item, got 2"),
        (crypto_material(item(format_="https://tinfoil.sh/key/spki-fp-sha256/v1")), spec.SPKI_KEY_FORMAT),
        (crypto_material(item(data="302A")), "lowercase hex"),
        (crypto_material(item(data="")), "lowercase hex"),
        (crypto_material({"id": spec.SIGNING_KEY_ID, "format": spec.SPKI_KEY_FORMAT}), "data"),
    ],
    ids=["not-json", "duplicate-key", "wrong-format", "no-signing-key", "two-signing-keys", "key-not-spki",
         "key-uppercase", "key-empty", "key-no-data"],
)
def test_crypto_material_names_exactly_one_spki_signing_key(material, match):
    invalid(changed(f"{KEY_BINDING}.crypto_material", material), match)


def test_other_crypto_material_items_are_not_read():
    material = crypto_material({"id": "tls", "format": "anything", "data": "ANY"}, item(data="abcd"))
    parsed = parse_statement(changed(f"{KEY_BINDING}.crypto_material", material))
    assert parsed.predicate.execution.attestation.keyBinding.signing_key == "abcd"


def test_the_signing_key_id_comes_from_spec(monkeypatch):
    # Swapping it in spec.py must leave OpenMined's receipt with no signing key, so nothing else hardcodes it.
    monkeypatch.setattr(spec, "SIGNING_KEY_ID", "another-key")
    invalid(receipt(), "exactly one 'another-key' item, got 0")


# --- the index adapter -------------------------------------------------------

ACCEPTED = Accepted(record_id="ab" * 32, size=2048, received_at="2026-10-08T01:02:03Z", state="incomplete",
                    checks=tuple(Check(check_id, Status.PASS, "stand-in") for check_id in CHECK_IDS),
                    enclave=None, publication=None, benchmark_owner_email="benchmark_owner@openmined.org",
                    benchmark_owner_display="OpenMined sample benchmark owner")


def indexed(statement: dict | None = None, accepted: Accepted = ACCEPTED) -> dict:
    """The adapter's record for `statement` (default: OpenMined's), as the API's JSON."""
    return to_index(parse_statement(statement or receipt()), accepted).to_json()


def test_the_adapter_keeps_what_the_registry_established():
    record = indexed()
    assert (record["recordId"], record["size"], record["receivedAt"]) == ("ab" * 32, 2048, "2026-10-08T01:02:03Z")
    assert record["state"] == "incomplete"
    assert record["checks"] == [{"id": check_id, "status": "PASS", "detail": "stand-in"} for check_id in CHECK_IDS]
    assert record["enclave"] is None
    assert (record["predicateType"], record["adapterVersion"]) == (spec.PREDICATE_TYPE, ADAPTER_VERSION)


def test_the_adapter_carries_the_verified_enclave_facts():
    enclave = Enclave(measurement="33" * 48, repo="OpenMined/syft-enclave-tinfoil", release_tag="v0.1.28",
                      release_digest="74" * 32)
    record = indexed(accepted=dataclasses.replace(ACCEPTED, state="verified", enclave=enclave))
    assert record["state"] == "verified"
    assert record["enclave"] == {"type": "AMD SEV-SNP", "measurement": "33" * 48,
                                 "repo": "OpenMined/syft-enclave-tinfoil", "releaseTag": "v0.1.28",
                                 "releaseDigest": "74" * 32}


def test_the_adapter_carries_where_rekor_logs_the_receipt():
    publication = Publication(uuid="10" * 40, log_index=3129204433, integrated_time=1791368875,
                              url=spec.REKOR_SEARCH_LINK.format(3129204433))
    record = indexed(accepted=dataclasses.replace(ACCEPTED, publication=publication))
    assert record["publication"] == {"uuid": "10" * 40, "logIndex": 3129204433, "integratedTime": 1791368875,
                                     "url": spec.REKOR_SEARCH_LINK.format(3129204433)}
    assert indexed()["publication"] is None


def test_the_adapter_pairs_the_listed_approver_with_the_registry_s_display_name():
    assert indexed()["benchmarkOwner"] == {"email": "benchmark_owner@openmined.org",
                                           "display": "OpenMined sample benchmark owner"}


def test_the_adapter_maps_the_pipeline_s_models_then_its_config_as_components():
    statement = receipt()
    pipeline = statement["predicate"]["evalPipeline"]
    record = indexed(statement)
    assert record["subjectName"] == statement["subject"][0]["name"]
    assert record["systemDigest"] == statement["subject"][0]["digest"]["sha256"]
    assert [(c["role"], c["scheme"], c["digest"], c["name"]) for c in record["components"]] == [
        *((m["role"], m["scheme"], m["digest"], m["name"]) for m in pipeline["models"]),
        *((c["kind"], c["scheme"], c["digest"], c["id"]) for c in pipeline["config"])]
    assert record["components"][0]["alsoKnownAs"] == [
        {"scheme": a["scheme"], "value": a["ref"]} for a in pipeline["models"][0]["alsoKnownAs"]]
    assert record["components"][1]["alsoKnownAs"] == []


def test_an_also_known_as_digest_becomes_its_value():
    statement = changed("predicate.evalPipeline.models.1.alsoKnownAs", [{"scheme": "oms/1", "digest": "cd" * 32}])
    assert indexed(statement)["components"][1]["alsoKnownAs"] == [{"scheme": "oms/1", "value": "cd" * 32}]


def test_the_adapter_maps_the_eval_dataset_as_the_eval():
    dataset = receipt()["predicate"]["evalDataset"]
    assert indexed()["eval"] == {"digest": dataset["digest"],
                                 "evalSet": {"scheme": dataset["scheme"], "digest": dataset["digest"]},
                                 "harness": None, "name": dataset["name"], "harnessVersion": None, "public": None}


def test_the_adapter_maps_the_results_with_metric_items_as_given():
    results = receipt()["predicate"]["results"]
    assert indexed()["results"] == {"metrics": results["metrics"], "counts": results["counts"], "scored": None}


def test_the_adapter_maps_each_party_by_role_and_email():
    assert indexed()["parties"] == [{"role": p["role"], "email": p["email"]} for p in receipt()["predicate"]["parties"]]


def test_the_adapter_maps_consent():
    consent = receipt()["predicate"]["consent"]
    assert indexed()["consent"] == {"manifestDigest": consent["manifestDigest"], "approvals": [
        {"party": a["party"], "approvedAt": a["approvedAt"]} for a in consent["approvals"]]}


def test_the_adapter_maps_the_run_values_the_receipt_reports():
    execution = receipt()["predicate"]["execution"]
    keys = ("platform", "cvmVersion", "runId", "configDigest", "startedAt", "finishedAt")
    assert indexed()["reported"] == {key: execution[key] for key in keys}


def test_nothing_the_receipt_claims_about_its_attestation_reaches_the_index():
    # Only the enclave facts that checks 3 and 4 verified are ever shown.
    statement = receipt()
    attestation = statement["predicate"]["execution"]["attestation"]
    key_binding = attestation["keyBinding"]
    text = json.dumps(indexed(statement))
    for value in (attestation["quote"], attestation["referenceValue"]["repo"], key_binding["crypto_material"],
                  key_binding["challenge"]["report_data"], key_binding["cpu_evidence"]["report_base64"],
                  key_binding["cpu_evidence"]["endorsed"]["crypto_material_hash"]):
        assert value not in text


def test_the_record_json_links_its_download_system_and_eval():
    statement = receipt()
    assert indexed()["links"] == {"download": f"/api/records/{'ab' * 32}/record.dsse.json",
                                  "system": f"/api/systems/{statement['subject'][0]['digest']['sha256']}",
                                  "eval": f"/api/evals/{statement['predicate']['evalDataset']['digest']}"}
