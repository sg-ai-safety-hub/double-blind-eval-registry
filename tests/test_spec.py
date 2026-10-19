"""Spec constants live only in registry/spec.py, so they are easy to swap."""

import ast
from pathlib import Path

import pytest

from registry import spec

ROOT = Path(__file__).resolve().parents[1]
# BASE_MODEL_ROLE ("base") isn't guarded: it is a substring of too many unrelated words, such as base64.
GUARDED = [
    spec.PREDICATE_TYPE, spec.PAYLOAD_TYPE, spec.KEY_BINDING_FORMAT, spec.REPORT_DATA_ALGORITHM,
    spec.CRYPTO_MATERIAL_FORMAT, spec.SEV_SNP_REPORT_FORMAT, spec.SPKI_KEY_FORMAT, spec.SIGNING_KEY_ID,
    *spec.SENTINEL_PREFIXES, spec.REKOR_URL, spec.REKOR_SEARCH_LINK,
]
# REKOR_ENTRY_KIND ("dsse") and REKOR_ENTRY_API_VERSION ("0.0.1") aren't guarded either: "dsse" is in record.dsse.json.
SOURCES = sorted(
    path for folder in ("registry", "scripts", "tests") for path in (ROOT / folder).rglob("*.py")
    if path != ROOT / "registry/spec.py"
)


def string_literals(path: Path):
    for node in ast.walk(ast.parse(path.read_text(), filename=str(path))):
        if isinstance(node, ast.Constant) and isinstance(node.value, (str, bytes)):
            value = node.value if isinstance(node.value, str) else node.value.decode(errors="replace")
            yield node.lineno, value


@pytest.mark.parametrize("path", SOURCES, ids=lambda p: str(p.relative_to(ROOT)))
def test_no_spec_constant_is_hardcoded(path):
    found = [f"line {line}: {value!r}" for line, value in string_literals(path)
             for constant in GUARDED if constant in value]
    assert found == []
