import os

import pytest


@pytest.fixture(autouse=True)
def isolated_env(monkeypatch, tmp_path):
    """Run each test in an empty directory, with none of the registry's env vars set."""
    for name in list(os.environ):
        if name.startswith("REGISTRY_"):
            monkeypatch.delenv(name)
    monkeypatch.chdir(tmp_path)
