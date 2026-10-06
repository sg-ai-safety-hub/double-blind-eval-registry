"""The verified path, run into a throwaway dev data directory so the verified UI can be seen.

    uv run python -m tests.demo_verified --out data/demo
    REGISTRY_MODE=dev REGISTRY_DATA_DIR=data/demo uv run flask --app registry.app run --port 5050

THE TINFOIL SDK IS REPLACED HERE, so the record this makes proves nothing. Nothing that can be produced
today passes checks 2-4, because Tinfoil's hardware report has no slot for the receipt's run key.
verified_hardware() answers for the SDK as a report binding that key would: Document.verify,
verify_attestation and RefCache.get return canned results built from the live DBE capture. Only the
tests and this demo use it, and the demo writes only to data/demo*.
"""

import argparse
import base64
import hashlib
import shlex
import sys
from contextlib import contextmanager
from pathlib import Path
from unittest import mock

from tinfoil.attestation import Document, Measurement, PredicateType, Verification
from tinfoil.attestation.abi_sev import Report

from registry import checks_tinfoil
from registry.config import load_config
from registry.envelope import parse_receipt
from registry.evalresult import parse_statement
from registry.index import Index, StaleIndex
from registry.ingest import ingest
from registry.refcache import RefCache, Reference
from registry.store import Store

ROOT = Path(__file__).resolve().parents[1]
RECEIPT = ROOT / "fixtures/generated/stapled_B.dsse.json"  # the worked example, with the live DBE report as its quote
REPORT = ROOT / "fixtures/tinfoil/dbe.quote"  # that report: base64 of the raw SEV-SNP report
# tinfoil.hash of tinfoilsh/double-blind-eval v0.0.4, the release the report was captured from.
RELEASE_DIGEST = "feb7322639f793fac30043422138a6543a98d5d8065fce52d0f2c4f208a12684"


@contextmanager
def verified_hardware():
    """Make checks 2-4 PASS for RECEIPT: the SDK answers as if its report bound the receipt's run key."""
    run_key = parse_statement(parse_receipt(RECEIPT.read_bytes()).statement).predicate.execution.runPublicKey
    measurement = Measurement(type=PredicateType.SEV_GUEST_V2,
                              registers=[Report(base64.b64decode(REPORT.read_text())).measurement.hex()])
    verification = Verification(measurement=measurement,
                                public_key_fp=hashlib.sha256(bytes.fromhex(run_key)).hexdigest())
    # cached=True, so RefCache.put writes nothing: no made-up reference reaches a refcache.
    reference = Reference(digest=RELEASE_DIGEST, hash_file=RELEASE_DIGEST.encode() + b"\n", bundle=b"", cached=True)
    with (mock.patch.object(Document, "verify", return_value=verification),
          mock.patch.object(checks_tinfoil, "verify_attestation", return_value=measurement),
          mock.patch.object(RefCache, "get", return_value=reference)):
        yield


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Index one verified record into data/demo*, with the SDK replaced.")
    parser.add_argument("--out", required=True, help="the data directory to write: data/demo or data/demo-<name>")
    out = Path(parser.parse_args(argv).out).resolve()
    if out.parent != Path("data").resolve() or not out.name.startswith("demo"):
        print(f"refusing to write to {out}: --out must be data/demo or data/demo-<name>", file=sys.stderr)
        return 2
    # The default dev policy, as the dev server will load it, so the index is built under the same policy.
    config = load_config({"REGISTRY_MODE": "dev", "REGISTRY_DATA_DIR": str(out)})
    try:
        index = Index.open(config.index_path, config.policy_sha256, config.mode)
    except StaleIndex as e:
        print(f"{e}: delete {out} and run this again", file=sys.stderr)
        return 1
    with verified_hardware():
        result = ingest(RECEIPT.read_bytes(), config, Store(config.store_dir), index, RefCache(config.refcache_dir))
    print(f"{result.status} {result.body.get('state') or result.body.get('detail')}: {result.body['recordId']}")
    print(f"serve it: REGISTRY_MODE=dev REGISTRY_DATA_DIR={shlex.quote(str(out))} "
          "uv run flask --app registry.app run --port 5050")
    return 0 if result.status in (200, 201) else 1


if __name__ == "__main__":
    raise SystemExit(main())
