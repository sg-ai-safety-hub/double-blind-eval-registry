"""Spec constants live only in registry/spec.py, so they are easy to swap."""

import ast
from pathlib import Path

import pytest

from registry import spec

ROOT = Path(__file__).resolve().parents[1]
GUARDED = [
    spec.PREDICATE_TYPE, spec.PREDICATE_VERSION, spec.PIPELINE_SCHEMA, spec.EVAL_SCHEMA, spec.PAYLOAD_TYPE,
    spec.CONSENT_ALGORITHM, spec.CONSENT_PREFIX.decode(), spec.MODEL_OWNER, spec.BENCHMARK_OWNER,
    *spec.SENTINEL_PREFIXES,
]
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
