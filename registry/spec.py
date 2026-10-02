"""Format constants for EvalResult/v0.1 receipts (see README.md), with the consent format and party
names of DBE (Tinfoil's double-blind-eval).

No other file, test or script may hardcode these. Several sit inside
hashed or signed bytes, so changing one changes every digest or signature built from it.
"""

# in-toto Statement inside a DSSE envelope.
STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
PAYLOAD_TYPE = "application/vnd.in-toto+json"

# EvalResult/v0.1.
PREDICATE_TYPE = "https://www.aisafety.sg/fourpillars/EvalResult/v0.1"
PREDICATE_VERSION = "fourpillars-evalresult-v0.1"
PIPELINE_SCHEMA = "fourpillars/pipeline/v0.1"  # inside the pipelineDigest preimage
EVAL_SCHEMA = "fourpillars/eval/v0.1"  # inside the evalDigest preimage

# Consent follows DBE: each approval signs CONSENT_PREFIX + manifestDigest (ASCII lowercase hex).
CONSENT_ALGORITHM = "ed25519"
CONSENT_PREFIX = b"dbe-approve-v1\n"
# DBE's party names, used in both consent.approvals[].party and parties[].role.
MODEL_OWNER = "model-owner"
BENCHMARK_OWNER = "benchmark-owner"

# Formats EvalResult/v0.1 defines, as regexes for pydantic's Field(pattern=...).
HEX64 = r"^[0-9a-f]{64}$"  # a SHA-256 digest or an Ed25519 key: lowercase hex, no prefix
GITHUB_OWNER_NAME = r"[A-Za-z0-9-]+/[A-Za-z0-9._-]+"  # unanchored: referenceValue.repo prefixes it

ED25519_KEY_SCHEME = "ed25519-key/1"  # parties[].identity.scheme of a party identified by its key
OCI_SCHEME = "oci/1"  # its digests are "sha256:" + 64 hex; every other scheme's are bare 64 hex
REFERENCE_SOURCE = "sigstore"  # the only referenceValue.source accepted
REFERENCE_REPO_PREFIX = "github.com/"  # referenceValue.repo is github.com/<owner>/<name>

# A quote starting with one of these counts as absent, so checks 2-4 are PENDING.
SIMULATED_PREFIX = "SIMULATED-"  # written by a simulated enclave
PLACEHOLDER_PREFIX = "PLACEHOLDER-"  # used by the worked example
SENTINEL_PREFIXES = (SIMULATED_PREFIX, PLACEHOLDER_PREFIX)
