#!/usr/bin/env python3
"""Write fixtures/generated/*.dsse.json and fixtures/expected.json.

    uv run python scripts/make_fixtures.py

Deterministic, so running it again rewrites identical bytes: every key is derived from
sha256(b"fpr-fixture:" + name), Ed25519 and ECDSA (RFC 6979) signatures are deterministic, and
statements and envelopes are serialised with JCS.

Every generated receipt starts from the statement OpenMined's enclave signed
(fixtures/openmined/receipt.dsse.json), which is itself fixture om_receipt. It prints the approver
emails the fixtures use, for registry-policy.dev.example.yaml.

THESE ARE NOT TRUSTWORTHY RECORDS: every key comes from a public name, and every hardware report is a
SIMULATED sentinel, a real report stapled onto a receipt it doesn't belong to, or random bytes.
"""

import base64
import copy
import hashlib
import json
import sys
from pathlib import Path

import rfc8785
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from securesystemslib.dsse import Envelope
from securesystemslib.signer import Signature
from tinfoil.attestation.abi_sev import Report

from registry import spec
from registry.model import CHECK_IDS, Status

ROOT = Path(__file__).resolve().parents[1]
GENERATED = ROOT / "fixtures/generated"
EXPECTED = ROOT / "fixtures/expected.json"
OPENMINED = ROOT / "fixtures/openmined/receipt.dsse.json"  # signed by OpenMined's enclave, as received
UNSIGNED = ROOT / "fixtures/openmined/sample-receipt.json"  # the same statement, without its envelope
DBE_SAMPLE = ROOT / "fixtures/dbe/sample-receipt.json"
TINFOIL = ROOT / "fixtures/tinfoil"  # live captures from scripts/capture_tinfoil_reports.py
MISSING_TAG = "v0.0.0-does-not-exist"

SIMULATED = spec.SIMULATED_PREFIX + "not-from-a-real-enclave"  # the sentinel a simulated enclave writes
FOREIGN_PREDICATE_TYPE = "https://slsa.dev/provenance/v1"
UNLISTED = "unlisted@example.org"  # C6's approver: must never be listed in registry-policy.dev.example.yaml
P256_ORDER = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551  # n of SECP256R1
# A check vector such as "PFPPPPF" has one letter per check, 1-7 in order.
VECTOR = {"P": Status.PASS, "F": Status.FAIL, "-": Status.PENDING}
DELETE = object()


# --- keys and signatures -----------------------------------------------------

def seed(name: str) -> bytes:
    return hashlib.sha256(b"fpr-fixture:" + name.encode()).digest()


def ed25519(name: str) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(seed(name))


def p256(name: str) -> ec.EllipticCurvePrivateKey:
    return ec.derive_private_key(int.from_bytes(seed(name), "big") % P256_ORDER, ec.SECP256R1())


def spki(key) -> bytes:
    return key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


def sign(key, message: bytes) -> bytes:
    if isinstance(key, Ed25519PrivateKey):
        return key.sign(message)
    return key.sign(message, ec.ECDSA(hashes.SHA256(), deterministic_signing=True))  # DER-encoded


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def synthetic_digest(label: str) -> str:
    return hashlib.sha256(b"fpr-fixture-digest:" + label.encode()).hexdigest()


def jcs_digest(obj) -> str:
    return hashlib.sha256(rfc8785.dumps(obj)).hexdigest()


# --- envelopes ---------------------------------------------------------------

def envelope(payload: bytes, *signers, payload_type: str = spec.PAYLOAD_TYPE) -> bytes:
    """A JCS-serialised DSSE envelope with one signature per signer over PAE(payload_type, payload)."""
    env = Envelope(payload=payload, payload_type=payload_type, signatures={})
    for key in signers:
        keyid = hashlib.sha256(spki(key)).hexdigest()
        env.signatures[keyid] = Signature(keyid, sign(key, env.pae()).hex())
    return rfc8785.dumps(env.to_dict())


def key_binding(statement: dict) -> dict:
    return statement["predicate"]["execution"]["attestation"]["keyBinding"]


def signed_by(statement: dict, key, report: str = SIMULATED) -> dict:
    """The statement with `key` as crypto_material's enclave signing key and `report` as its hardware report.

    The other crypto_material items stay. With a SIMULATED report nothing binds the key, so checks 2-4
    are PENDING; with a real one, the report commits to another crypto_material, so check 2 FAILs.
    """
    statement = copy.deepcopy(statement)
    binding = key_binding(statement)
    material = json.loads(base64.b64decode(binding["crypto_material"]))
    material["items"] = [item for item in material["items"] if item["id"] != spec.SIGNING_KEY_ID] + [
        {"id": spec.SIGNING_KEY_ID, "format": spec.SPKI_KEY_FORMAT, "data": spki(key).hex()}]
    binding["crypto_material"] = b64(rfc8785.dumps(material))
    binding["cpu_evidence"]["report_base64"] = report
    return statement


def sealed(statement: dict, key, signer=None, report: str = SIMULATED) -> bytes:
    """The statement signed_by `key`, in an envelope signed by `signer` (default: the same key)."""
    return envelope(rfc8785.dumps(signed_by(statement, key, report)), signer or key)


def live_capture(name: str) -> tuple[bytes, dict] | None:
    """(raw report, {repo, tag, capturedAt}) from fixtures/tinfoil, or None if the capture is missing."""
    quote, meta = TINFOIL / f"{name}.quote", TINFOIL / f"{name}.meta.json"
    if not (quote.exists() and meta.exists()):
        return None
    return base64.b64decode(quote.read_text(), validate=True), json.loads(meta.read_text())


# --- statements --------------------------------------------------------------

def openmined() -> dict:
    """The statement OpenMined's enclave signed, without the bulky parts the registry never reads:
    file contents and the attestation's collateral. The file itself is never changed."""
    statement = json.loads(base64.b64decode(json.loads(OPENMINED.read_bytes())["payload"], validate=True))
    predicate = statement["predicate"]
    for part in (*predicate["job"]["code"], *predicate["outputs"]):
        del part["content"]
    del key_binding(statement)["collateral"]
    return statement


def changed(statement: dict, changes: dict) -> dict:
    """A copy with each dotted path (list indices allowed) set to its value, or removed for DELETE."""
    statement = copy.deepcopy(statement)
    for path, value in changes.items():
        *parents, last = path.split(".")
        node = statement
        for key in parents:
            node = node[int(key)] if isinstance(node, list) else node[key]
        key = int(last) if isinstance(node, list) else last
        if value is DELETE:
            del node[key]
        else:
            node[key] = value
    return statement


def flipped(hex_digest: str) -> str:
    """The same digest with its last hex digit changed."""
    return hex_digest[:-1] + ("0" if hex_digest[-1] != "0" else "1")


def model(role: str, label: str, name: str, **extra) -> dict:
    return {"id": label, "role": role, "scheme": "dirhash-sha256/1", "digest": synthetic_digest(f"{role}:{label}"),
            "name": name, **extra}


def sampling(label: str, **params) -> dict:
    return {"id": f"sampling-{label}", "kind": "sampling", "scheme": "jcs-sha256/1", "digest": jcs_digest(params),
            "params": params, "appliesTo": [spec.BASE_MODEL_ROLE]}


def dataset(label: str, name: str) -> dict:
    return {"scheme": "file-sha256/1", "digest": synthetic_digest(f"dataset:{label}"), "name": name}


def synthetic(n: int, subject: str, models: list, config: list, eval_dataset: dict, approvers: tuple,
              results: dict, base: dict) -> dict:
    """Record Dn: a made-up pipeline, dataset, parties and consent, run in base's (simulated) enclave."""
    pipeline = {"config": config, "models": models}
    judge, weights_owner = approvers
    execution = {**base["predicate"]["execution"], "platform": "synthetic", "cvmVersion": "0.0.0-synthetic",
                 "runId": synthetic_digest(f"run:D{n}")[:32], "configDigest": synthetic_digest(f"config:D{n}"),
                 "startedAt": f"2026-10-0{n}T10:00:00Z", "finishedAt": f"2026-10-0{n}T10:05:00Z"}
    predicate = {
        "evalPipeline": pipeline,
        "evalDataset": eval_dataset,
        "results": results,
        "execution": execution,
        "parties": [{"role": "submitter", "email": judge}, {"role": "data_owner", "email": judge},
                    {"role": "data_owner", "email": weights_owner}],
        "consent": {"manifestDigest": synthetic_digest(f"manifest:D{n}"), "approvals": [
            {"approvedAt": f"2026-10-0{n}T09:00:00Z", "party": judge},
            {"approvedAt": f"2026-10-0{n}T09:30:00Z", "party": weights_owner}]},
    }
    return {"_type": spec.STATEMENT_TYPE, "subject": [{"name": subject, "digest": {"sha256": jcs_digest(pipeline)}}],
            "predicateType": spec.PREDICATE_TYPE, "predicate": predicate}


# --- the fixtures ------------------------------------------------------------

def build() -> tuple[dict[str, bytes], dict]:
    """Return ({file name: bytes}, expected.json) without writing anything."""
    files, expected = {}, {}

    def add(name, data, description, vector=None, dev=201, state="incomplete", strict=None, path=None,
            network=False):
        if path is None:
            path = f"fixtures/generated/{name}.dsse.json"
            files[f"{name}.dsse.json"] = data
        entry = {"record": path, "recordId": hashlib.sha256(data).hexdigest(), "description": description,
                 "checks": None if vector is None else dict(zip(CHECK_IDS, (VECTOR[c] for c in vector), strict=True))}
        entry["dev"] = {"status": dev, "state": state} if dev == 201 else {"status": dev}
        if network:  # a real or random report: checks 3-4 fetch AMD's VCEK and Sigstore's root, check 7 asks Rekor
            entry["network"] = True
        if strict is not None:
            entry["strict"] = {"status": strict}
        expected[name] = entry

    add("om_receipt", OPENMINED.read_bytes(), "OpenMined's receipt, as their enclave signed it", "PPPPPPP",
        state="verified", strict=422, path=str(OPENMINED.relative_to(ROOT)), network=True)

    key_a = ed25519("A")
    base = openmined()
    reference = base["predicate"]["execution"]["attestation"]["referenceValue"]
    release = {"repo": reference["repo"].removeprefix(spec.REFERENCE_REPO_PREFIX), "tag": reference["tag"]}

    def re_signed(changes: dict) -> bytes:
        return sealed(changed(base, changes), key_a)

    sim_a = signed_by(base, key_a)
    sim_a_bytes = envelope(rfc8785.dumps(sim_a), key_a)
    add("sim_A", sim_a_bytes, "OpenMined's statement, simulated: fixture key A signs, and no hardware report",
        "P---PP-", strict=422)

    edited_after_signing = json.loads(sim_a_bytes)
    edited_after_signing["payload"] = b64(rfc8785.dumps(changed(sim_a, {"subject.0.name": "renamed after signing"})))
    add("C1_edit_after_sign", rfc8785.dumps(edited_after_signing),
        "sim_A with subject[0].name changed after signing", "F---PP-", dev=422)
    add("C2_other_signer", sealed(base, key_a, signer=ed25519("X")),
        "crypto_material names key A, but key X signed", "F---PP-", dev=422)
    add("C3_pipeline", re_signed({"predicate.evalPipeline.models.1.digest":
                                  flipped(base["predicate"]["evalPipeline"]["models"][1]["digest"])}),
        "An evalPipeline model digest altered, the subject not, re-signed", "P---FP-", dev=422)
    add("C4_subject", re_signed({"subject.0.digest.sha256": flipped(base["subject"][0]["digest"]["sha256"])}),
        "Subject digest altered, re-signed", "P---FP-", dev=422)
    add("C5_p256_key", sealed(base, p256("A-p256")),
        "The enclave signing key is EC P-256, not Ed25519, and signs", "F---PP-", dev=422)
    approvals = base["predicate"]["consent"]["approvals"]
    add("C6_unlisted_approver", re_signed({"predicate.consent.approvals": [{**approvals[0], "party": UNLISTED},
                                                                           *approvals[1:]]}),
        "Like sim_A, but no approval comes from an email on the dev list", "P---PF-", dev=422)

    # OpenMined's real hardware report, stapled onto receipts signed with fixture key B: checks 3 and 4
    # can PASS, but the report commits to OpenMined's crypto_material, not B's, so check 2 FAILs. Nobody logged
    # these receipts on Rekor, so check 7 FAILs them all.
    report = key_binding(base)["cpu_evidence"]["report_base64"]
    raw_report = base64.b64decode(report, validate=True)

    def stapled(report_b64: str, repo: str, tag: str) -> bytes:
        statement = changed(base, {"predicate.execution.attestation.referenceValue.repo": spec.REFERENCE_REPO_PREFIX + repo,
                                   "predicate.execution.attestation.referenceValue.tag": tag})
        return sealed(statement, ed25519("B"), report=report_b64)

    add("stapled_B", stapled(report, **release),
        "OpenMined's statement with its real report, but crypto_material names fixture key B, which signs",
        "PFPPPPF", dev=422, strict=422, network=True)
    flipped_report = bytearray(raw_report)
    flipped_report[raw_report.index(Report(raw_report).measurement)] ^= 1
    add("C8_report_flip", stapled(b64(bytes(flipped_report)), **release),
        "stapled_B with one measurement byte flipped in the report", "PFFFPPF", dev=422, network=True)
    garbage = hashlib.shake_256(b"fpr-fixture:garbage-report").digest(len(raw_report))
    add("C9_garbage_report", stapled(b64(garbage), **release),  # check 3 rejects it before any fetch; check 7 asks Rekor
        "stapled_B with report_base64 = base64 of random bytes (not a sentinel)", "PFFFPPF", dev=422, network=True)
    router = live_capture("router")
    if router is None:
        print(f"skipped C11, C12: {TINFOIL.relative_to(ROOT)}/router.* is missing; "
              "run scripts/capture_tinfoil_reports.py", file=sys.stderr)
    else:
        router_report, router_release = router
        add("C11_untrusted_repo", stapled(b64(router_report), router_release["repo"], router_release["tag"]),
            "Tinfoil's live router report, with referenceValue naming the router repo (not in trusted_code)",
            "PFPFPPF", dev=422, network=True)
        add("C12_repo_mismatch", stapled(b64(router_report), **release),
            "Tinfoil's live router report, with referenceValue naming OpenMined's repo and tag", "PFPFPPF", dev=422,
            network=True)
    add("C13_tag_missing", stapled(report, release["repo"], MISSING_TAG),
        f"stapled_B with referenceValue.tag {MISSING_TAG}: no release asset", "PFPFPPF", dev=422, network=True)

    add("U1_predicate_type", re_signed({"predicateType": FOREIGN_PREDICATE_TYPE}),
        "predicateType changed, re-signed", dev=400)
    add("U2_payload_type", envelope(rfc8785.dumps(sim_a), key_a, payload_type="application/json"),
        "payloadType changed, re-signed", dev=400)
    add("U3_extra_field", re_signed({"comment": "not an in-toto statement field"}),
        "Extra top-level statement field, re-signed", dev=400)
    # JCS can't write a duplicate key, so splice one in: a lenient parser keeps the last predicateType.
    duplicated = rfc8785.dumps(sim_a)
    duplicated = b'{"predicateType":' + json.dumps(FOREIGN_PREDICATE_TYPE).encode() + b"," + duplicated[1:]
    add("U4_duplicate_key", envelope(duplicated, key_a),
        "Statement with two predicateType keys (another type first, the receipt's last), signed", dev=400)
    add("U5_two_signatures", envelope(rfc8785.dumps(sim_a), key_a, ed25519("X")),
        "sim_A's statement signed by two keys", dev=400)
    if DBE_SAMPLE.exists():
        add("U6_dbe_sample", DBE_SAMPLE.read_bytes(), "DBE's sample receipt, in its own format (dbe-receipt-v1)",
            dev=400, path=str(DBE_SAMPLE.relative_to(ROOT)))
    else:
        print(f"skipped U6_dbe_sample: {DBE_SAMPLE.relative_to(ROOT)} is missing", file=sys.stderr)
    add("U7_unsigned_statement", UNSIGNED.read_bytes(), "OpenMined's statement without its DSSE envelope",
        dev=400, path=str(UNSIGNED.relative_to(ROOT)))

    add("S1_no_reference_value", re_signed({"predicate.execution.attestation.referenceValue": DELETE}),
        "No referenceValue, re-signed", dev=422)
    add("S2_no_consent", re_signed({"predicate.consent": DELETE}), "No consent, re-signed", dev=422)
    material = json.loads(base64.b64decode(key_binding(sim_a)["crypto_material"]))
    material["items"] = [item for item in material["items"] if item["id"] != spec.SIGNING_KEY_ID]
    no_signing_key = changed(sim_a, {"predicate.execution.attestation.keyBinding.crypto_material":
                                     b64(rfc8785.dumps(material))})
    add("S3_no_signing_key", envelope(rfc8785.dumps(no_signing_key), key_a),
        f"sim_A with no {spec.SIGNING_KEY_ID} in crypto_material, signed with key A", dev=422)

    # D1-D7: synthetic variety (3 base models, 6 systems, 3 eval datasets). Every subject says "synthetic".
    def hf(label: str) -> list:
        return [{"scheme": "hf-revision/1", "ref": f"example-org/{label}@" + synthetic_digest(f"hf:{label}")[:40]}]

    alpha = model(spec.BASE_MODEL_ROLE, "alpha", "synthetic-alpha-7b", alsoKnownAs=hf("synthetic-alpha-7b"))
    beta = model(spec.BASE_MODEL_ROLE, "beta", "synthetic-beta-13b")

    def gamma(revision: str) -> dict:  # D5 and D6 share these weights but claim different revisions
        return model(spec.BASE_MODEL_ROLE, "gamma", "synthetic-gamma-70b", alsoKnownAs=hf(revision))

    adapter = model("adapter", "refusal-tuned", "synthetic-refusal-adapter", appliesTo=[spec.BASE_MODEL_ROLE])
    script_adapter = model("adapter", "script", "<script>alert(1)</script>", appliesTo=[spec.BASE_MODEL_ROLE])
    greedy = sampling("greedy", max_new_tokens=64, temperature=0.0)
    warm = sampling("warm", max_new_tokens=64, temperature=0.7, top_k=40)

    refusal = dataset("refusal", "synthetic-refusal-prompts")
    bio = dataset("bio", "synthetic-bio-risk-screen")
    honesty = dataset("honesty", "synthetic-honesty-probe")
    # The dev policy lists the judges' emails; the weights owners' are never listed.
    judge = {name: f"{name}-evals@example.org" for name in ("refusal", "bio", "honesty")}
    owner = {name: f"{name}-weights@example.org" for name in ("alpha", "beta", "gamma")}
    counts = {"submitted": 1200, "completed": 1200, "failed": 0}

    def metric(name: str, value, unit: str, higher_is_better: bool) -> dict:
        return {"name": name, "value": value, "unit": unit, "n": 1200, "higherIsBetter": higher_is_better}

    records = [
        synthetic(1, "synthetic-alpha-7b (synthetic)", [alpha], [greedy], refusal, (judge["refusal"], owner["alpha"]),
                  {"metrics": [metric("refusal_rate", 0.97, "fraction", True),
                               metric("unsafe_completion_rate", 0.004, "fraction", False)], "counts": counts}, sim_a),
        synthetic(2, "synthetic-alpha-7b (synthetic)", [alpha], [greedy], bio, (judge["bio"], owner["alpha"]),
                  {"metrics": [], "counts": counts}, sim_a),
        synthetic(3, "synthetic-alpha-7b + synthetic-refusal-adapter (synthetic)", [alpha, adapter], [greedy],
                  refusal, (judge["refusal"], owner["alpha"]), {"metrics": []}, sim_a),
        synthetic(4, "synthetic-beta-13b (synthetic)", [beta], [warm], refusal, (judge["refusal"], owner["beta"]),
                  {"metrics": []}, sim_a),
        synthetic(5, "synthetic-gamma-70b (synthetic)", [gamma("synthetic-gamma-70b-a")], [greedy], honesty,
                  (judge["honesty"], owner["gamma"]),
                  {"metrics": [{"name": "honesty_score", "value": "0.79"},
                               {"name": "calibration", "value": {"ece": 0.05, "bins": 10}}]}, sim_a),
        synthetic(6, "synthetic-gamma-70b (synthetic)", [gamma("synthetic-gamma-70b-b")], [greedy], refusal,
                  (judge["refusal"], owner["gamma"]), {"metrics": []}, sim_a),
        synthetic(7, "synthetic-alpha-7b + a scripted adapter (synthetic)", [alpha, script_adapter], [greedy],
                  honesty, (judge["honesty"], owner["alpha"]), {"metrics": []}, sim_a),
    ]
    descriptions = {
        1: "Synthetic; two metrics",
        2: "Synthetic; same system as D1, another eval dataset; no metrics",
        3: "Synthetic; D1's model with an adapter",
        4: "Synthetic; a second base model",
        5: "Synthetic; metrics incl. a non-{name,value,unit} item; hf-revision alias A",
        6: "Synthetic; same weights as D5 with a conflicting hf-revision alias",
        7: "Synthetic; a component named <script>alert(1)</script>",
    }
    for n, statement in enumerate(records, start=1):
        add(f"D{n}", sealed(statement, ed25519(f"run:D{n}")), descriptions[n], "P---PP-")

    return files, expected


def approver_emails(files: dict[str, bytes], expected: dict) -> dict[str, list[str]]:
    """{approver email: the fixtures whose consent lists it}, over the schema-valid fixtures."""
    emails = {}
    for name, entry in expected.items():
        if entry["checks"] is None:
            continue
        data = files.get(f"{name}.dsse.json") or (ROOT / entry["record"]).read_bytes()
        statement = json.loads(base64.b64decode(json.loads(data)["payload"]))
        for approval in statement["predicate"]["consent"]["approvals"]:
            emails.setdefault(approval["party"], []).append(name)
    return emails


def main() -> int:
    files, expected = build()
    GENERATED.mkdir(parents=True, exist_ok=True)
    for file_name, data in files.items():
        (GENERATED / file_name).write_bytes(data)
    EXPECTED.write_text(json.dumps(expected, indent=2) + "\n")
    for name, entry in expected.items():
        print(f"{name:24} {entry['recordId'][:16]}  dev {entry['dev']['status']}")
    print(f"wrote {len(files)} fixtures to {GENERATED.relative_to(ROOT)} and {EXPECTED.relative_to(ROOT)}")
    print(f"\napprover emails, for registry-policy.dev.example.yaml (list one per fixture, never {UNLISTED}):")
    for email, names in approver_emails(files, expected).items():
        print(f"  {email}  {', '.join(names)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
