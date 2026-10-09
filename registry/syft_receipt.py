"""OpenMined's syft-enclave receipt v3 as strict pydantic models. A violation is a 422.

The receipt is an in-toto Statement whose predicate records the pipeline evaluated (its models and
config), the eval dataset, the results, how the run was executed (including Tinfoil's hardware
attestation, whose key binding names the key that signed the receipt), the parties and their
consent. README.md describes the fields the registry reads.

strict: every value must already have its JSON type; nothing is coerced.
Extra fields are allowed everywhere, but only the modelled fields are ever read or displayed.
"""

import base64
import logging
import re
from typing import Annotated, Any, Literal

import jiter
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from registry import index, spec
from registry.model import Accepted

log = logging.getLogger(__name__)

ADAPTER_VERSION = "syft-receipt-v3/1"  # stored with each indexed record: which version of to_index mapped it
OCI_DIGEST = r"^sha256:[0-9a-f]{64}$"
REPO = rf"^{re.escape(spec.REFERENCE_REPO_PREFIX)}{spec.GITHUB_OWNER_NAME}$"
LOWER_HEX_BYTES = r"^(?:[0-9a-f]{2})+$"


class SchemaError(ValueError):
    """The statement violates the receipt schema (HTTP 422)."""

    def __init__(self, errors: list[str]):
        super().__init__("; ".join(errors))
        self.errors = errors


def _check_digest(scheme: str, digest: str) -> None:
    pattern = OCI_DIGEST if scheme == spec.OCI_SCHEME else spec.HEX64
    if not re.fullmatch(pattern, digest):
        raise ValueError(f"a {scheme} digest must match {pattern}")


Hex64 = Annotated[str, Field(pattern=spec.HEX64)]
NonEmpty = Annotated[str, Field(min_length=1)]


class _Model(BaseModel):
    model_config = ConfigDict(strict=True, extra="allow")


class SchemedDigest(_Model):
    scheme: NonEmpty
    digest: str

    @model_validator(mode="after")
    def _digest_matches_scheme(self):
        _check_digest(self.scheme, self.digest)
        return self


class AlsoKnownAs(_Model):
    scheme: NonEmpty
    digest: str | None = None
    ref: str | None = None

    @model_validator(mode="after")
    def _digest_or_ref(self):
        if (self.digest is None) == (self.ref is None):
            raise ValueError("needs exactly one of digest or ref")
        if self.digest is not None:
            _check_digest(self.scheme, self.digest)
        return self


class PipelineModel(SchemedDigest):
    role: NonEmpty
    name: str | None = None
    alsoKnownAs: list[AlsoKnownAs] | None = None


class PipelineConfig(SchemedDigest):
    kind: NonEmpty
    id: str | None = None


class EvalPipeline(_Model):
    models: list[PipelineModel] = Field(min_length=1)
    config: list[PipelineConfig] = []


class EvalDataset(SchemedDigest):
    name: str | None = None


class Counts(_Model):
    submitted: int
    completed: int
    failed: int


class Results(_Model):
    metrics: list[Any]  # items stay opaque: shown as given, never interpreted
    counts: Counts | None = None


class ReferenceValue(_Model):
    source: str
    repo: str = Field(pattern=REPO)
    tag: NonEmpty

    @field_validator("source")
    @classmethod
    def _sigstore_only(cls, value: str) -> str:
        if value != spec.REFERENCE_SOURCE:
            raise ValueError(f"must be {spec.REFERENCE_SOURCE!r}")
        return value


class CryptoMaterialItem(_Model):
    id: str
    format: str
    data: str


class CryptoMaterial(_Model):
    format: Literal[spec.CRYPTO_MATERIAL_FORMAT]
    items: list[CryptoMaterialItem]


def _signing_key(crypto_material: str) -> str:
    """The data of crypto_material's one spec.SIGNING_KEY_ID item: the key's SPKI DER, as lowercase hex."""
    raw = base64.b64decode(crypto_material, validate=True)
    try:
        decoded = jiter.from_json(raw, allow_inf_nan=False, catch_duplicate_keys=True)
    except ValueError as e:
        raise ValueError(f"not valid JSON: {e}") from None
    try:
        material = CryptoMaterial.model_validate(decoded)
    except ValidationError as e:  # re-raised as a ValueError, so it reads as one problem with crypto_material
        raise ValueError("; ".join(_problems(e))) from None
    keys = [item for item in material.items if item.id == spec.SIGNING_KEY_ID]
    if len(keys) != 1:
        raise ValueError(f"needs exactly one {spec.SIGNING_KEY_ID!r} item, got {len(keys)}")
    key, = keys
    if key.format != spec.SPKI_KEY_FORMAT or not re.fullmatch(LOWER_HEX_BYTES, key.data):
        raise ValueError(f"the {spec.SIGNING_KEY_ID!r} item must be {spec.SPKI_KEY_FORMAT!r} with lowercase hex data")
    return key.data


class Challenge(_Model):
    nonce: Hex64  # 32 bytes, hashed into report_data by check 2
    report_data_algorithm: Literal[spec.REPORT_DATA_ALGORITHM]
    # report_data is never read: it only restates what check 3 verifies and check 2 recomputes.


class CpuEvidence(_Model):
    format: Literal[spec.SEV_SNP_REPORT_FORMAT]
    report_base64: str  # input to checks 2-4: standard base64 of the raw SEV-SNP report, or a sentinel
    # endorsed is never read: check 2 recomputes its hashes from the sections themselves.


class KeyBinding(_Model):
    format: Literal[spec.KEY_BINDING_FORMAT]
    challenge: Challenge
    crypto_material: str  # input to checks 1 and 2: standard base64 of crypto-material/v1 JSON
    device_evidence: str  # input to check 2, which hashes it; its content is never read
    cpu_evidence: CpuEvidence
    # collateral is never read: the SDK fetches the VCEK itself and refcache the release reference.

    @field_validator("device_evidence")
    @classmethod
    def _standard_base64(cls, value: str) -> str:
        base64.b64decode(value, validate=True)
        return value

    @field_validator("crypto_material")
    @classmethod
    def _names_one_signing_key(cls, value: str) -> str:
        _signing_key(value)
        return value

    @property
    def signing_key(self) -> str:
        """The enclave signing key as SPKI DER hex: check 1 verifies under it, check 2 binds it to the report."""
        return _signing_key(self.crypto_material)


class Attestation(_Model):
    type: str
    referenceValue: ReferenceValue  # a claim check 4 confirms
    keyBinding: KeyBinding
    # quote is never read: a second report, binding only the TLS and HPKE keys, with the same measurement.


class Execution(_Model):
    attestation: Attestation
    startedAt: str  # as reported: the enclave's clock is set by the host
    finishedAt: str
    platform: str | None = None
    cvmVersion: str | None = None
    runId: str | None = None
    configDigest: str | None = None


class Party(_Model):
    role: NonEmpty
    email: NonEmpty


class Approval(_Model):
    party: NonEmpty  # an email; check 6 matches it against this registry's list
    approvedAt: str | None = None


class Consent(_Model):
    manifestDigest: Hex64
    approvals: list[Approval] = Field(min_length=1)


class Predicate(_Model):
    evalPipeline: EvalPipeline
    evalDataset: EvalDataset
    results: Results
    execution: Execution
    parties: list[Party]
    consent: Consent


class SubjectDigest(_Model):
    sha256: Hex64


class Subject(_Model):
    name: str | None = None
    digest: SubjectDigest


class Statement(_Model):
    type_: str = Field(alias="_type")
    subject: list[Subject] = Field(min_length=1, max_length=1)
    predicateType: str
    predicate: Predicate


def parse_statement(statement: dict) -> Statement:
    """Validate a recognised statement against the schema; raise SchemaError listing every violation."""
    try:
        parsed = Statement.model_validate(statement)
    except ValidationError as e:
        errors = _problems(e)
        log.debug("REJECT schema: %d error(s): %s", len(errors), "; ".join(errors))
        raise SchemaError(errors) from e
    log.debug("ACCEPT schema: %d model(s), %d config(s), %d approval(s)", len(parsed.predicate.evalPipeline.models),
              len(parsed.predicate.evalPipeline.config), len(parsed.predicate.consent.approvals))
    return parsed


def _problems(error: ValidationError) -> list[str]:
    return [f"{'.'.join(str(part) for part in e['loc'])}: {e['msg']}" for e in error.errors()]


def to_index(statement: Statement, accepted: Accepted) -> index.IndexedRecord:
    """The adapter: an accepted receipt in the index's own shape.

    The only place that maps this format's fields into the index. execution.attestation is left out:
    the index shows only the enclave facts checks 3 and 4 verified, never the receipt's own claims.
    """
    predicate = statement.predicate
    pipeline, dataset, results, execution = (predicate.evalPipeline, predicate.evalDataset, predicate.results,
                                             predicate.execution)
    return index.IndexedRecord(
        record_id=accepted.record_id,
        size=accepted.size,
        received_at=accepted.received_at,
        state=accepted.state,
        checks=accepted.checks,
        enclave=accepted.enclave,
        benchmark_owner=index.Owner(email=accepted.benchmark_owner_email, display=accepted.benchmark_owner_display),
        predicate_type=statement.predicateType,
        adapter_version=ADAPTER_VERSION,
        subject_name=statement.subject[0].name,
        system_digest=statement.subject[0].digest.sha256,  # check 5: sha256(JCS(evalPipeline))
        components=(
            *(index.Component(role=m.role, scheme=m.scheme, digest=m.digest, name=m.name,
                              also_known_as=tuple(index.Alias(scheme=a.scheme, value=a.ref if a.digest is None else a.digest)
                                                  for a in m.alsoKnownAs or ()))
              for m in pipeline.models),
            *(index.Component(role=c.kind, scheme=c.scheme, digest=c.digest, name=c.id, also_known_as=())
              for c in pipeline.config),
        ),
        eval=index.Eval(digest=dataset.digest,
                        eval_set=index.SchemedDigest(scheme=dataset.scheme, digest=dataset.digest),
                        harness=None, name=dataset.name, harness_version=None, public=None),
        results=index.Results(
            metrics=tuple(results.metrics),
            counts=None if results.counts is None else index.Counts(
                submitted=results.counts.submitted, completed=results.counts.completed, failed=results.counts.failed),
            scored=None),
        parties=tuple(index.Party(role=p.role, email=p.email) for p in predicate.parties),
        consent=index.Consent(manifest_digest=predicate.consent.manifestDigest,
                              approvals=tuple(index.Approval(party=a.party, approved_at=a.approvedAt)
                                              for a in predicate.consent.approvals)),
        reported=index.Reported(platform=execution.platform, cvm_version=execution.cvmVersion,
                                run_id=execution.runId, config_digest=execution.configDigest,
                                started_at=execution.startedAt, finished_at=execution.finishedAt),
    )
