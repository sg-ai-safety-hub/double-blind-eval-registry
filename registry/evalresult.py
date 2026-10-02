"""The EvalResult/v0.1 statement schema as strict pydantic models. A violation is a 422.

EvalResult/v0.1 is the Four Pillars receipt for one AI evaluation run: an in-toto Statement whose
predicate records the system evaluated, the eval, its results, how it was executed (including a
hardware attestation), the parties, and their consent. README.md describes each field.

strict: every value must already have its JSON type; nothing is coerced.
Extra predicate fields are allowed, but only the modelled fields are ever read or displayed.
"""

import logging
import re
from datetime import datetime
from typing import Annotated, Any

from pydantic import AfterValidator, BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from registry import spec

log = logging.getLogger(__name__)

OCI_DIGEST = r"^sha256:[0-9a-f]{64}$"
REPO = rf"^{re.escape(spec.REFERENCE_REPO_PREFIX)}{spec.GITHUB_OWNER_NAME}$"
LOWER_HEX_BYTES = r"^(?:[0-9a-f]{2})+$"
TIMESTAMP_FORMAT = "%Y-%m-%dT%H:%M:%SZ"  # RFC 3339, UTC, second precision


class SchemaError(ValueError):
    """The statement violates the EvalResult/v0.1 schema (HTTP 422)."""

    def __init__(self, errors: list[str]):
        super().__init__("; ".join(errors))
        self.errors = errors


def _utc_seconds(value: str) -> str:
    # strptime alone accepts unpadded fields, so formatting back must reproduce the input exactly.
    try:
        exact = datetime.strptime(value, TIMESTAMP_FORMAT).strftime(TIMESTAMP_FORMAT) == value
    except ValueError:
        exact = False
    if not exact:
        raise ValueError("must be RFC 3339 UTC with second precision, like 2026-09-14T02:42:58Z")
    return value


def _check_digest(scheme: str, digest: str) -> None:
    pattern = OCI_DIGEST if scheme == spec.OCI_SCHEME else spec.HEX64
    if not re.fullmatch(pattern, digest):
        raise ValueError(f"a {scheme} digest must match {pattern}")


Hex64 = Annotated[str, Field(pattern=spec.HEX64)]
NonEmpty = Annotated[str, Field(min_length=1)]
Timestamp = Annotated[str, AfterValidator(_utc_seconds)]


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


class Component(SchemedDigest):
    role: NonEmpty
    name: str | None = None
    alsoKnownAs: list[AlsoKnownAs] | None = None


class System(_Model):
    pipelineDigest: Hex64
    components: list[Component] = Field(min_length=1)


class Eval(_Model):
    evalDigest: Hex64
    evalSet: SchemedDigest
    harness: SchemedDigest
    name: str | None = None
    harnessVersion: str | None = None
    public: bool | None = None


class Counts(_Model):
    submitted: int
    completed: int
    failed: int


class Results(_Model):
    metrics: list[Any]  # items stay opaque until OpenMined's metric schema lands
    counts: Counts | None = None
    scored: bool | None = None


class ReferenceValue(_Model):
    source: str
    repo: str = Field(pattern=REPO)
    tag: NonEmpty
    # bundleRef is optional and ignored: it passes as an extra field.

    @field_validator("source")
    @classmethod
    def _sigstore_only(cls, value: str) -> str:
        if value != spec.REFERENCE_SOURCE:
            raise ValueError(f"must be {spec.REFERENCE_SOURCE!r}")
        return value


class Attestation(_Model):
    type: str
    quote: str  # input to checks 2-4
    referenceValue: ReferenceValue  # required; a claim check 4 confirms
    # Required by the schema, but never used or displayed: they only restate what the verified quote contains.
    measurement: str
    reportData: str


class Execution(_Model):
    attestation: Attestation
    startedAt: Timestamp
    finishedAt: Timestamp
    runPublicKey: str = Field(pattern=LOWER_HEX_BYTES)
    platform: str | None = None
    cvmVersion: str | None = None
    runId: str | None = None
    configDigest: str | None = None


class Identity(_Model):
    scheme: NonEmpty
    publicKey: str | None = None  # the key of an ed25519-key/1 identity


class Party(_Model):
    role: NonEmpty
    identity: Identity


class Approval(_Model):
    party: str
    publicKey: str
    signature: str


class Consent(_Model):
    manifestDigest: Hex64
    approvals: list[Approval]


class Predicate(_Model):
    version: str
    system: System
    eval: Eval
    results: Results
    execution: Execution
    parties: list[Party]
    consent: Consent | None = None  # optional

    @field_validator("parties")
    @classmethod
    def _one_of_each_owner_with_its_own_key(cls, parties: list[Party]) -> list[Party]:
        # Each owner is identified by its Ed25519 key. The acceptance gate matches the benchmark
        # owner's; check 7 verifies both owners' approvals against them. The two keys must differ,
        # so consent always comes from two keys.
        if _owner_key(parties, spec.MODEL_OWNER) == _owner_key(parties, spec.BENCHMARK_OWNER):
            raise ValueError(f"the {spec.MODEL_OWNER!r} and {spec.BENCHMARK_OWNER!r} parties must have different keys")
        return parties

    def owner_key(self, role: str) -> str:
        """The Ed25519 key of the one party with this owner role, which the validator above guarantees."""
        return _owner_key(self.parties, role)


def _owner_key(parties: list[Party], role: str) -> str:
    owners = [party for party in parties if party.role == role]
    if len(owners) != 1:
        raise ValueError(f"needs exactly one party with role {role!r}, got {len(owners)}")
    identity = owners[0].identity
    if identity.scheme != spec.ED25519_KEY_SCHEME or not re.fullmatch(spec.HEX64, identity.publicKey or ""):
        raise ValueError(f"the {role!r} party's identity must be {spec.ED25519_KEY_SCHEME!r} "
                         "with a publicKey of 64 lowercase hex")
    return identity.publicKey


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
        errors = [f"{'.'.join(str(part) for part in error['loc'])}: {error['msg']}" for error in e.errors()]
        log.debug("REJECT schema: %d error(s): %s", len(errors), "; ".join(errors))
        raise SchemaError(errors) from e
    log.debug("ACCEPT schema: %d component(s), %d part(ies)", len(parsed.predicate.system.components),
              len(parsed.predicate.parties))
    return parsed
