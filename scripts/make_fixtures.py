#!/usr/bin/env python3
"""Write fixtures/generated/*.dsse.json and fixtures/expected.json.

    uv run python scripts/make_fixtures.py

Deterministic, so running it again rewrites identical bytes: every key is derived from
sha256(b"fpr-fixture:" + name), Ed25519 and ECDSA (RFC 6979) signatures are deterministic, and
statements and envelopes are serialised with JCS.

It prints the benchmark owners' keys the fixtures use, for registry-policy.dev.example.yaml.

THESE ARE NOT TRUSTWORTHY RECORDS: every key comes from a public name, and every quote is a SIMULATED
sentinel, a live Tinfoil report stapled onto a receipt it doesn't belong to, or random bytes.
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
from registry.checks_software import eval_digest, pipeline_digest
from registry.model import CHECK_IDS, Status

ROOT = Path(__file__).resolve().parents[1]
GENERATED = ROOT / "fixtures/generated"
EXPECTED = ROOT / "fixtures/expected.json"
WORKED_EXAMPLE = ROOT / "fixtures/evalresult/worked_example.statement.json"
DBE_SAMPLE = ROOT / "fixtures/dbe/sample-receipt.json"
TINFOIL = ROOT / "fixtures/tinfoil"  # live captures from scripts/capture_tinfoil_reports.py
MISSING_TAG = "v0.0.0-does-not-exist"

SIMULATED = spec.SIMULATED_PREFIX + "not-from-a-real-enclave"  # the sentinel a simulated enclave writes
WORKED_EXAMPLE_ROLES = {"model_provider": spec.MODEL_OWNER, "evaluator": spec.BENCHMARK_OWNER}  # to DBE's names
FOREIGN_PREDICATE_TYPE = "https://slsa.dev/provenance/v1"
TRUSTED_REPO = spec.REFERENCE_REPO_PREFIX + "tinfoilsh/double-blind-eval"  # as in the worked example
P256_ORDER = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551  # n of SECP256R1
# A check vector such as "PFPPPnP" has one letter per check, 1-7 in order.
VECTOR = {"P": Status.PASS, "F": Status.FAIL, "-": Status.PENDING, "n": Status.NA}
DELETE = object()


# --- keys and signatures -----------------------------------------------------

def seed(name: str) -> bytes:
    return hashlib.sha256(b"fpr-fixture:" + name.encode()).digest()


def ed25519(name: str) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(seed(name))


def p256(name: str) -> ec.EllipticCurvePrivateKey:
    return ec.derive_private_key(int.from_bytes(seed(name), "big") % P256_ORDER, ec.SECP256R1())


def public_bytes(key) -> bytes:
    """runPublicKey's bytes: the raw key for Ed25519, SPKI DER for EC."""
    if isinstance(key, Ed25519PrivateKey):
        return key.public_key().public_bytes_raw()
    return key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


def sign(key, message: bytes) -> bytes:
    if isinstance(key, Ed25519PrivateKey):
        return key.sign(message)
    return key.sign(message, ec.ECDSA(hashes.SHA256(), deterministic_signing=True))  # DER-encoded


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def synthetic_digest(label: str) -> str:
    return hashlib.sha256(b"fpr-fixture-digest:" + label.encode()).hexdigest()


# --- envelopes ---------------------------------------------------------------

def envelope(payload: bytes, *signers, payload_type: str = spec.PAYLOAD_TYPE) -> bytes:
    """A JCS-serialised DSSE envelope with one signature per signer over PAE(payload_type, payload)."""
    env = Envelope(payload=payload, payload_type=payload_type, signatures={})
    for key in signers:
        keyid = hashlib.sha256(public_bytes(key)).hexdigest()
        env.signatures[keyid] = Signature(keyid, sign(key, env.pae()).hex())
    return rfc8785.dumps(env.to_dict())


def in_simulated_enclave(statement: dict, run_key) -> dict:
    """A run in a simulated enclave: bind the run key for real, leave quote and measurement SIMULATED."""
    statement = copy.deepcopy(statement)
    execution = statement["predicate"]["execution"]
    pub = public_bytes(run_key)
    execution["runPublicKey"] = pub.hex()
    execution["attestation"]["reportData"] = hashlib.sha256(pub).hexdigest()
    execution["attestation"]["quote"] = SIMULATED
    execution["attestation"]["measurement"] = SIMULATED
    return statement


def sealed(statement: dict, run_key, signer=None) -> bytes:
    """The statement run in the simulated enclave under `run_key`, signed by `signer` (default: the run key)."""
    return envelope(rfc8785.dumps(in_simulated_enclave(statement, run_key)), signer or run_key)


def approval(party: str, key: Ed25519PrivateKey, manifest_digest: str) -> dict:
    """A consent approval as DBE signs it."""
    message = spec.CONSENT_PREFIX + manifest_digest.encode("ascii")
    return {"party": party, "publicKey": public_bytes(key).hex(), "signature": b64(key.sign(message))}


def live_capture(name: str) -> tuple[bytes, dict] | None:
    """(raw report, {repo, tag, capturedAt}) from fixtures/tinfoil, or None if the capture is missing."""
    quote, meta = TINFOIL / f"{name}.quote", TINFOIL / f"{name}.meta.json"
    if not (quote.exists() and meta.exists()):
        return None
    return base64.b64decode(quote.read_text(), validate=True), json.loads(meta.read_text())


# --- statements --------------------------------------------------------------

def worked_example() -> dict:
    """The worked example with DBE's party names. The file itself is never changed."""
    statement = json.loads(WORKED_EXAMPLE.read_text())
    for party in statement["predicate"]["parties"]:
        party["role"] = WORKED_EXAMPLE_ROLES.get(party["role"], party["role"])
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


def component(role: str, scheme: str, label: str, name: str, **extra) -> dict:
    digest = synthetic_digest(f"{role}:{label}")
    if scheme == spec.OCI_SCHEME:
        digest = "sha256:" + digest
    return {"role": role, "scheme": scheme, "digest": digest, "name": name, **extra}


def evaluation(label: str, name: str, public: bool, harness_version: str) -> dict:
    eval_set = {"scheme": "file-sha256/1", "digest": synthetic_digest(f"eval-set:{label}")}
    harness = {"scheme": spec.OCI_SCHEME, "digest": "sha256:" + synthetic_digest(f"harness:{label}")}
    return {"evalDigest": eval_digest(eval_set, harness), "evalSet": eval_set, "harness": harness,
            "name": name, "harnessVersion": harness_version, "public": public}


def synthetic(n: int, subject: str, components: list, eval_: dict, owners: tuple, results: dict) -> dict:
    """Record Dn: made-up components, eval and parties with valid consent; the enclave sim fills in the quote."""
    model_owner, benchmark_owner = owners
    pipeline = pipeline_digest(components)
    manifest = synthetic_digest(f"manifest:D{n}")
    predicate = {
        "version": spec.PREDICATE_VERSION,
        "system": {"pipelineDigest": pipeline, "components": components},
        "eval": eval_,
        "results": results,
        "execution": {
            "platform": "synthetic",
            "cvmVersion": "0.0.0-synthetic",
            "runId": synthetic_digest(f"run:D{n}")[:32],
            "configDigest": synthetic_digest(f"config:D{n}"),
            "attestation": {
                "type": "sev-snp",
                "referenceValue": {"source": spec.REFERENCE_SOURCE, "repo": TRUSTED_REPO, "tag": "v0.1.0"},
            },
            "startedAt": f"2026-09-0{n}T10:00:00Z",
            "finishedAt": f"2026-09-0{n}T10:05:00Z",
        },
        "parties": [
            {"role": spec.MODEL_OWNER,
             "identity": {"scheme": spec.ED25519_KEY_SCHEME, "publicKey": public_bytes(model_owner).hex()}},
            {"role": spec.BENCHMARK_OWNER,
             "identity": {"scheme": spec.ED25519_KEY_SCHEME, "publicKey": public_bytes(benchmark_owner).hex()}},
            {"role": "compute", "identity": {"scheme": "named/1", "name": "Synthetic Compute"}},
        ],
        "consent": {"manifestDigest": manifest, "approvals": [
            approval(spec.MODEL_OWNER, model_owner, manifest),
            approval(spec.BENCHMARK_OWNER, benchmark_owner, manifest),
        ]},
    }
    return {"_type": spec.STATEMENT_TYPE, "subject": [{"name": subject, "digest": {"sha256": pipeline}}],
            "predicateType": spec.PREDICATE_TYPE, "predicate": predicate}


# --- the fixtures ------------------------------------------------------------

def build() -> tuple[dict[str, bytes], dict]:
    """Return ({file name: bytes}, expected.json) without writing anything."""
    files, expected = {}, {}

    def add(name, data, description, vector=None, dev=201, strict=None, path=None, network=False):
        if path is None:
            path = f"fixtures/generated/{name}.dsse.json"
            files[f"{name}.dsse.json"] = data
        entry = {"record": path, "recordId": hashlib.sha256(data).hexdigest(), "description": description,
                 "checks": None if vector is None else dict(zip(CHECK_IDS, (VECTOR[c] for c in vector)))}
        entry["dev"] = {"status": dev, "state": "incomplete"} if dev == 201 else {"status": dev}
        if network:  # checks 3 and 4 fetch AMD's VCEK and Sigstore's trust root, so its tests need the network
            entry["network"] = True
        if strict is not None:
            entry["strict"] = {"status": strict}
        expected[name] = entry

    key_a = ed25519("A")
    base = worked_example()
    approvals = {a["party"]: a for a in base["predicate"]["consent"]["approvals"]}
    model_owner_approval, benchmark_owner_approval = approvals[spec.MODEL_OWNER], approvals[spec.BENCHMARK_OWNER]
    manifest = base["predicate"]["consent"]["manifestDigest"]
    owner_index = [p["role"] for p in base["predicate"]["parties"]].index(spec.BENCHMARK_OWNER)

    def re_signed(changes: dict) -> bytes:
        return sealed(changed(base, changes), key_a)

    sim_a = in_simulated_enclave(base, key_a)
    sim_a_bytes = envelope(rfc8785.dumps(sim_a), key_a)
    add("sim_A", sim_a_bytes, "Worked example, re-signed with fixture key A", "P---PnP", strict=422)
    key_a_ec = p256("A-p256")
    add("sim_A_ec", sealed(base, key_a_ec), "Same statement; EC P-256 key; runPublicKey is SPKI DER hex", "P---PnP")
    add("sim_A_noconsent", re_signed({"predicate.consent": DELETE}),
        f"sim_A without consent, re-signed: no {spec.BENCHMARK_OWNER} approval for the gate", "P---Pnn", dev=403)

    edited_after_signing = json.loads(sim_a_bytes)
    edited_after_signing["payload"] = b64(rfc8785.dumps(changed(sim_a, {"subject.0.name": "renamed after signing"})))
    add("C1_edit_after_sign", rfc8785.dumps(edited_after_signing),
        "sim_A with subject[0].name changed after signing", "F---PnP", dev=422)
    add("C2_other_signer", sealed(base, ed25519("Y"), signer=ed25519("X")),
        "Signed with key X, while runPublicKey names key Y", "F---PnP", dev=422)
    add("C3_pipeline", re_signed({"predicate.system.pipelineDigest": flipped(base["predicate"]["system"]["pipelineDigest"])}),
        "pipelineDigest altered, re-signed", "P---FnP", dev=422)
    add("C4_subject", re_signed({"subject.0.digest.sha256": flipped(base["subject"][0]["digest"]["sha256"])}),
        "Subject digest differs from pipelineDigest, re-signed", "P---FnP", dev=422)
    add("C5_eval", re_signed({"predicate.eval.evalDigest": flipped(base["predicate"]["eval"]["evalDigest"])}),
        "evalDigest altered, re-signed", "P---FnP", dev=422)

    tampered = bytearray(base64.b64decode(model_owner_approval["signature"]))
    tampered[0] ^= 1
    add("C6_consent_sig", re_signed({"predicate.consent.approvals": [
            {**model_owner_approval, "signature": b64(bytes(tampered))}, benchmark_owner_approval]}),
        "One approval signature altered, re-signed", "P---PnF", dev=422)
    add("C7_consent_party", re_signed({"predicate.consent.approvals": [
            model_owner_approval, approval(spec.BENCHMARK_OWNER, ed25519("outsider"), manifest)]}),
        "Approval by a key not listed in parties, re-signed", "P---PnF", dev=422)
    add("C7b_party_mismatch", re_signed({"predicate.consent.approvals": [
            {**benchmark_owner_approval, "party": spec.MODEL_OWNER}, benchmark_owner_approval]}),
        f"Approval with party {spec.MODEL_OWNER}, signed by the {spec.BENCHMARK_OWNER} party's key, re-signed",
        "P---PnF", dev=422)
    add("C7c_one_party", re_signed({"predicate.consent.approvals": [model_owner_approval]}),
        f"Only the {spec.MODEL_OWNER} approval present, re-signed", "P---PnF", dev=422)
    # Consent is exactly two approvals, one per owner: a third FAILs even when it verifies.
    add("C7d_duplicate_approval", re_signed({"predicate.consent.approvals": [
            model_owner_approval, benchmark_owner_approval, model_owner_approval]}),
        f"The {spec.MODEL_OWNER} approval listed twice, re-signed", "P---PnF", dev=422)
    add("C7e_third_party_approval", re_signed({"predicate.consent.approvals": [
            model_owner_approval, benchmark_owner_approval, approval("compute", ed25519("compute"), manifest)]}),
        "Both owners' approvals plus a valid one from the compute party, re-signed", "P---PnF", dev=422)
    unlisted = ed25519("eval-owner:unlisted")  # must never be listed in registry-policy.dev.example.yaml
    add("C14_unlisted_bo", re_signed({
            f"predicate.parties.{owner_index}.identity.publicKey": public_bytes(unlisted).hex(),
            "predicate.consent.approvals": [model_owner_approval, approval(spec.BENCHMARK_OWNER, unlisted, manifest)]}),
        f"Like sim_A, but the {spec.BENCHMARK_OWNER} party and its approval use a key not in the dev policy",
        "P---PnP", dev=403)

    # Real SEV-SNP reports, stapled onto receipts signed with fixture key A: checks 3 and 4 can PASS,
    # but nothing binds key A to the report, so check 2 FAILs (the replay/stapling test).
    dbe, router = live_capture("dbe"), live_capture("router")
    if dbe is None or router is None:
        print(f"skipped stapled_B, C8, C9, C11, C12, C13: a capture in {TINFOIL.relative_to(ROOT)} is missing; "
              "run scripts/capture_tinfoil_reports.py", file=sys.stderr)
    else:
        (dbe_report, dbe_release), (router_report, router_release) = dbe, router

        def stapled(report: bytes, release: dict) -> bytes:
            statement = in_simulated_enclave(base, key_a)
            attestation = statement["predicate"]["execution"]["attestation"]
            attestation["quote"] = b64(report)
            attestation["referenceValue"] = {**attestation["referenceValue"],
                                             "repo": spec.REFERENCE_REPO_PREFIX + release["repo"],
                                             "tag": release["tag"]}
            return envelope(rfc8785.dumps(statement), key_a)

        add("stapled_B", stapled(dbe_report, dbe_release),
            "Worked example with the live DBE report as its quote and the live release's tag, signed with key A",
            "PFPPPnP", dev=422, strict=422, network=True)
        flipped_report = bytearray(dbe_report)
        flipped_report[dbe_report.index(Report(dbe_report).measurement)] ^= 1
        add("C8_report_flip", stapled(bytes(flipped_report), dbe_release),
            "stapled_B with one measurement byte flipped in the raw report, re-signed", "PFFFPnP", dev=422, network=True)
        garbage = hashlib.shake_256(b"fpr-fixture:garbage-quote").digest(len(dbe_report))
        add("C9_garbage_quote", stapled(garbage, dbe_release),  # rejected while parsing, before any fetch
            "stapled_B with quote = base64 of random bytes (not a sentinel), re-signed", "PFFFPnP", dev=422)
        add("C11_untrusted_repo", stapled(router_report, router_release),
            "The live router report, with referenceValue naming the router repo (not in trusted_code)",
            "PFPFPnP", dev=422, network=True)
        add("C12_repo_mismatch", stapled(router_report, dbe_release),
            "The live router report, with referenceValue naming DBE and DBE's live tag", "PFPFPnP", dev=422,
            network=True)
        add("C13_tag_missing", stapled(dbe_report, {**dbe_release, "tag": MISSING_TAG}),
            f"stapled_B with referenceValue.tag {MISSING_TAG}: no release asset", "PFPFPnP", dev=422, network=True)

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
        "Statement with two predicateType keys (another type first, EvalResult last), signed", dev=400)
    add("U5_two_signatures", envelope(rfc8785.dumps(sim_a), key_a, ed25519("X")),
        "sim_A's statement signed by two keys", dev=400)
    if DBE_SAMPLE.exists():
        add("U6_dbe_sample", DBE_SAMPLE.read_bytes(), "DBE's sample receipt, in its own format (dbe-receipt-v1)",
            dev=400, path=str(DBE_SAMPLE.relative_to(ROOT)))
    else:
        print(f"skipped U6_dbe_sample: {DBE_SAMPLE.relative_to(ROOT)} is missing", file=sys.stderr)

    add("S1_no_reference_value", re_signed({"predicate.execution.attestation.referenceValue": DELETE}),
        "No referenceValue, re-signed", dev=422)
    add("S2_worked_example_roles", sealed(json.loads(WORKED_EXAMPLE.read_text()), key_a),
        f"The worked example's role names only (no {spec.MODEL_OWNER} or {spec.BENCHMARK_OWNER}), re-signed", dev=422)
    second_owner = {"role": spec.BENCHMARK_OWNER,
                    "identity": {"scheme": spec.ED25519_KEY_SCHEME,
                                 "publicKey": public_bytes(ed25519("eval-owner:second")).hex()}}
    add("S3_two_benchmark_owners", re_signed({"predicate.parties": base["predicate"]["parties"] + [second_owner]}),
        f"Two {spec.BENCHMARK_OWNER} parties, re-signed", dev=422)
    second_model_owner = {"role": spec.MODEL_OWNER,
                          "identity": {"scheme": spec.ED25519_KEY_SCHEME,
                                       "publicKey": public_bytes(ed25519("weights-owner:second")).hex()}}
    add("S4_two_model_owners", re_signed({"predicate.parties": base["predicate"]["parties"] + [second_model_owner]}),
        f"Two {spec.MODEL_OWNER} parties, re-signed", dev=422)
    model_owner_index = [p["role"] for p in base["predicate"]["parties"]].index(spec.MODEL_OWNER)
    add("S5_same_owner_key", re_signed({
            f"predicate.parties.{model_owner_index}.identity": base["predicate"]["parties"][owner_index]["identity"]}),
        f"The {spec.MODEL_OWNER} party given the {spec.BENCHMARK_OWNER} party's key, re-signed", dev=422)

    # D1-D8: synthetic variety (3 base weights, 5 systems, 3 evals). Every label says "synthetic".
    alpha = component("base_weights", "modelwrap/2", "alpha", "synthetic-alpha-7b", alsoKnownAs=[
        {"scheme": "hf-revision/1", "ref": "example-org/synthetic-alpha-7b@" + synthetic_digest("hf:alpha")[:40]}])
    beta = component("base_weights", "modelwrap/2", "beta", "synthetic-beta-13b")
    gamma_digest = component("base_weights", "modelwrap/2", "gamma", "synthetic-gamma-70b")

    def gamma(oms_label):  # D6 and D7 share these weights but claim different OpenSSF Model Signing digests
        return {**gamma_digest, "alsoKnownAs": [{"scheme": "oms/1", "digest": synthetic_digest(oms_label)}]}

    runtime = component("runtime_image", spec.OCI_SCHEME, "runtime-1", "synthetic-runtime 1.0")
    runtime_2 = component("runtime_image", spec.OCI_SCHEME, "runtime-2", "synthetic-runtime 2.0")
    greedy = component("sampling", "jcs-sha256/1", "greedy", "temperature=0.0 (synthetic)")
    warm = component("sampling", "jcs-sha256/1", "warm", "temperature=0.7 (synthetic)")
    guard = component("safeguard", "dirhash-sha256/1", "filter", "synthetic-filter")
    # Two adapters, listed against their sort order, so a role-only sort would hash them differently.
    adapters = sorted([component("adapter", "dirhash-sha256/1", f"adapter-{i}", f"synthetic-adapter-{i}")
                       for i in (1, 2)], key=lambda c: c["digest"], reverse=True)

    refusal = evaluation("refusal", "Synthetic refusal eval (synthetic)", True, "1.0.0")
    bio = evaluation("bio", "Synthetic bio-risk screen (synthetic)", False, "2.1.0")
    honesty = evaluation("honesty", "Synthetic honesty probe (synthetic)", False, "0.3.0")
    # Fixed key labels, deliberately not built from spec names: the dev policy lists these keys,
    # so they must survive a party rename.
    owner = {name: ed25519(f"weights-owner:{name}") for name in ("alpha", "beta", "gamma")}
    judge = {name: ed25519(f"eval-owner:{name}") for name in ("refusal", "bio", "honesty")}
    counts = {"submitted": 1200, "completed": 1200, "failed": 0}
    script_name = "<script>alert(1)</script>"

    records = [
        synthetic(1, "synthetic-alpha-7b (synthetic)", [alpha, runtime, greedy], refusal,
                  (owner["alpha"], judge["refusal"]),
                  {"metrics": [{"name": "refusal_rate", "value": 0.97, "unit": "fraction"},
                               {"name": "unsafe_rate", "value": 0.004, "unit": "fraction"}],
                   "counts": counts, "scored": True}),
        synthetic(2, "synthetic-alpha-7b (synthetic)", [alpha, runtime, greedy], bio,
                  (owner["alpha"], judge["bio"]), {"metrics": [], "counts": counts, "scored": False}),
        synthetic(3, "synthetic-alpha-7b + synthetic-filter (synthetic)", [alpha, guard, runtime, greedy], refusal,
                  (owner["alpha"], judge["refusal"]), {"metrics": []}),
        synthetic(4, "synthetic-beta-13b (synthetic)", [beta, runtime, warm], refusal,
                  (owner["beta"], judge["refusal"]), {"metrics": [], "scored": True}),
        synthetic(5, "synthetic-beta-13b + two adapters (synthetic)", [beta, *adapters, runtime, warm], bio,
                  (owner["beta"], judge["bio"]), {"metrics": [], "scored": False}),
        synthetic(6, "synthetic-gamma-70b (synthetic)", [gamma("oms:gamma-a"), runtime_2, greedy], honesty,
                  (owner["gamma"], judge["honesty"]),
                  {"metrics": [{"name": "honesty_score", "value": "0.79"},
                               {"name": "calibration", "value": {"ece": 0.05, "bins": 10}}],
                   "scored": True}),
        synthetic(7, "synthetic-gamma-70b (synthetic)", [gamma("oms:gamma-b"), runtime_2, greedy], refusal,
                  (owner["gamma"], judge["refusal"]), {"metrics": []}),
        synthetic(8, "synthetic-alpha-7b (synthetic)", [alpha, runtime, {**greedy, "name": script_name}], honesty,
                  (owner["alpha"], judge["honesty"]), {"metrics": []}),
    ]
    descriptions = {
        1: "Synthetic; two metrics",
        2: "Synthetic; same system as D1, another eval; not scored",
        3: "Synthetic; D1's model behind a safeguard",
        4: "Synthetic; a second base model; scored, but no metrics reported",
        5: "Synthetic; two adapter components (sort tie-break)",
        6: "Synthetic; metrics incl. a non-{name,value} item; oms/1 alias A",
        7: "Synthetic; same weights as D6 with a conflicting oms/1 alias",
        8: "Synthetic; a component named <script>alert(1)</script>",
    }
    for n, statement in enumerate(records, start=1):
        add(f"D{n}", sealed(statement, ed25519(f"run:D{n}")), descriptions[n], "P---PnP")

    return files, expected


def benchmark_owner_keys(files: dict[str, bytes], expected: dict) -> dict[str, list[str]]:
    """{benchmark owner's public key: the fixtures that use it}, over the schema-valid fixtures."""
    keys = {}
    for name, entry in expected.items():
        if entry["checks"] is None:
            continue
        payload = base64.b64decode(json.loads(files[f"{name}.dsse.json"])["payload"])
        parties = json.loads(payload)["predicate"]["parties"]
        key, = (p["identity"]["publicKey"] for p in parties if p["role"] == spec.BENCHMARK_OWNER)
        keys.setdefault(key, []).append(name)
    return keys


def main() -> int:
    files, expected = build()
    GENERATED.mkdir(parents=True, exist_ok=True)
    for file_name, data in files.items():
        (GENERATED / file_name).write_bytes(data)
    EXPECTED.write_text(json.dumps(expected, indent=2) + "\n")
    for name, entry in expected.items():
        print(f"{name:24} {entry['recordId'][:16]}  dev {entry['dev']['status']}")
    print(f"wrote {len(files)} fixtures to {GENERATED.relative_to(ROOT)} and {EXPECTED.relative_to(ROOT)}")
    print(f"\n{spec.BENCHMARK_OWNER} keys, for registry-policy.dev.example.yaml (list all but C14_unlisted_bo's):")
    for key, names in benchmark_owner_keys(files, expected).items():
        print(f"  {key}  {', '.join(names)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
