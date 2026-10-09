"""Format constants for OpenMined's syft-enclave receipt v3 (see README.md), and for the Tinfoil
attestation formats inside it.

No other file, test or script may hardcode these. Several sit inside hashed or signed bytes, so
changing one changes every digest or signature built from it.
"""

# in-toto Statement inside a DSSE envelope.
STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
PAYLOAD_TYPE = "application/vnd.in-toto+json"

# OpenMined's syft-enclave receipt v3.
PREDICATE_TYPE = "https://openmined.org/syft-enclave/receipt/v3"
BASE_MODEL_ROLE = "base"  # evalPipeline.models[].role of the base model, whose digest identifies a model

# Tinfoil's attested keys: the hardware report's report_data commits to crypto_material, which lists
# the keys the enclave generated, among them the one that signs the receipt.
KEY_BINDING_FORMAT = "https://tinfoil.sh/predicate/attestation/v3"
REPORT_DATA_ALGORITHM = "https://tinfoil.sh/report-data/v1"
CRYPTO_MATERIAL_FORMAT = "https://tinfoil.sh/crypto-material/v1"
SEV_SNP_REPORT_FORMAT = "https://tinfoil.sh/format/sev-snp-report/v1"
SPKI_KEY_FORMAT = "https://tinfoil.sh/key/spki/v1"  # its data is the SPKI DER public key, as lowercase hex
SIGNING_KEY_ID = "enclave-signing-key"  # the crypto_material item that signs the receipt, as OpenMined names it

# Formats the schema checks, as regexes for pydantic's Field(pattern=...).
HEX64 = r"^[0-9a-f]{64}$"  # a SHA-256 digest: lowercase hex, no prefix
GITHUB_OWNER_NAME = r"[A-Za-z0-9-]+/[A-Za-z0-9._-]+"  # unanchored: referenceValue.repo prefixes it

OCI_SCHEME = "oci/1"  # its digests are "sha256:" + 64 hex; every other scheme's are bare 64 hex
REFERENCE_SOURCE = "sigstore"  # the only referenceValue.source accepted
REFERENCE_REPO_PREFIX = "github.com/"  # referenceValue.repo is github.com/<owner>/<name>

# A hardware report starting with one of these counts as absent, so checks 2-4 are PENDING.
SIMULATED_PREFIX = "SIMULATED-"  # written by a simulated enclave
PLACEHOLDER_PREFIX = "PLACEHOLDER-"
SENTINEL_PREFIXES = (SIMULATED_PREFIX, PLACEHOLDER_PREFIX)
