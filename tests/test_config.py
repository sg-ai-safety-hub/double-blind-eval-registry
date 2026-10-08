import hashlib
from pathlib import Path

import pytest

from registry.config import ConfigError, load_config

REPO_ROOT = Path(__file__).resolve().parents[1]
POLICY = """\
trusted_code:
  - repo: tinfoilsh/double-blind-eval
benchmark_owners: []
"""
KEY = "3888833eb8844b23a79a5a4bf258b3c718fd0cc3997b8d000f29f88855252d9c"


def owners(entries: str) -> str:
    """POLICY with the given YAML list items as its benchmark_owners."""
    return POLICY.replace("benchmark_owners: []", "benchmark_owners:\n" + entries)


def write(name, text=POLICY):
    path = Path(name)
    path.write_text(text)
    return path


def test_defaults_to_strict_mode(tmp_path):
    write("registry-policy.yaml")
    config = load_config({})
    assert config.mode == "strict"
    assert config.data_dir == tmp_path / "data" / "strict"
    assert config.policy_path == tmp_path / "registry-policy.yaml"


def test_dev_mode_has_its_own_data_dir_and_policy(tmp_path):
    write("registry-policy.dev.yaml")
    config = load_config({"REGISTRY_MODE": "dev"})
    assert config.mode == "dev"
    assert config.data_dir == tmp_path / "data" / "dev"
    assert config.policy_path == tmp_path / "registry-policy.dev.yaml"


def test_the_store_refcache_and_index_live_in_the_data_dir(tmp_path):
    write("registry-policy.yaml")
    config = load_config({})
    assert config.store_dir == tmp_path / "data" / "strict" / "store"
    assert config.refcache_dir == tmp_path / "data" / "strict" / "refcache"
    assert config.index_path == tmp_path / "data" / "strict" / "index.sqlite3"


def test_env_overrides_data_dir_and_policy_path(tmp_path):
    write("custom.yaml")
    config = load_config({"REGISTRY_DATA_DIR": "elsewhere", "REGISTRY_POLICY": "custom.yaml"})
    assert config.data_dir == tmp_path / "elsewhere"
    assert config.policy_path == tmp_path / "custom.yaml"


@pytest.mark.parametrize(
    "env",
    [{"REGISTRY_MODE": "production"}, {"REGISTRY_MODE": ""}],
    ids=["unknown-mode", "empty-mode"],
)
def test_bad_environment_refuses_to_start(env):
    write("registry-policy.yaml")
    with pytest.raises(ConfigError):
        load_config(env)


def test_missing_policy_refuses_to_start():
    with pytest.raises(ConfigError, match="registry-policy.yaml"):
        load_config({})


def test_dev_mode_copies_the_example_when_its_policy_is_missing():
    example = write("registry-policy.dev.example.yaml")
    config = load_config({"REGISTRY_MODE": "dev"})
    assert Path("registry-policy.dev.yaml").read_bytes() == example.read_bytes()
    assert config.policy_sha256 == hashlib.sha256(example.read_bytes()).hexdigest()


def test_dev_mode_never_copies_the_example_to_an_explicit_policy_path():
    write("registry-policy.dev.example.yaml")
    with pytest.raises(ConfigError, match="missing.yaml"):
        load_config({"REGISTRY_MODE": "dev", "REGISTRY_POLICY": "missing.yaml"})
    assert not Path("missing.yaml").exists()
    assert not Path("registry-policy.dev.yaml").exists()


def test_policy_hash_is_sha256_of_the_raw_file_bytes():
    raw = write("registry-policy.yaml", "# comments count too\n" + POLICY).read_bytes()
    assert load_config({}).policy_sha256 == hashlib.sha256(raw).hexdigest()


@pytest.mark.parametrize(
    "text",
    [
        "",
        "trusted_code: [\n",
        "benchmark_owners: []\n",
        "trusted_code: []\nbenchmark_owners: []\n",
        "trusted_code:\n  - repo: github.com/tinfoilsh/double-blind-eval\nbenchmark_owners: []\n",
        "trusted_code:\n  - repo: tinfoilsh\nbenchmark_owners: []\n",
        "trusted_code:\n  - repo: tinfoilsh/double-blind-eval\n    tag: v0.1.0\nbenchmark_owners: []\n",
        "trusted_code:\n  - repo: tinfoilsh/double-blind-eval\n",
        POLICY + "trusted_domains: []\n",
        POLICY.replace("benchmark_owners: []", "publishers: []"),
        owners(f'  - public_key: "{KEY}"\n'),
        owners(f'  - public_key: "{KEY.upper()}"\n    display: X\n'),
        owners('  - public_key: "3888833e"\n    display: X\n'),
        owners(f'  - public_key: "{KEY}"\n    display: X\n  - public_key: "{KEY}"\n    display: Y\n'),
        owners(f'  - public_key: "{KEY}"\n    display: yes\n'),
        owners(f'  - public_key: "{KEY}"\n    display: !!binary WA==\n'),
    ],
    ids=[
        "empty-file",
        "not-yaml",
        "trusted-code-missing",
        "trusted-code-empty",
        "repo-with-github-prefix",
        "repo-without-name",
        "unknown-key-in-trusted-code",
        "owner-list-missing",
        "unknown-top-level-key",
        "publishers-instead-of-owners",
        "owner-without-display",
        "owner-key-uppercase",
        "owner-key-short",
        "owner-key-listed-twice",
        "owner-display-yaml-bool",
        "owner-display-yaml-binary",
    ],
)
def test_invalid_policy_refuses_to_start(text):
    write("registry-policy.yaml", text)
    with pytest.raises(ConfigError):
        load_config({})


def test_benchmark_owners_load_with_their_display_names():
    write("registry-policy.yaml", owners(f'  - public_key: "{KEY}"\n    display: DBE sample\n'))
    owner, = load_config({}).policy.benchmark_owners
    assert (owner.public_key, owner.display) == (KEY, "DBE sample")


@pytest.mark.parametrize("name", ["registry-policy.yaml", "registry-policy.dev.example.yaml"])
def test_committed_policies_trust_only_dbe_code(name):
    config = load_config({"REGISTRY_POLICY": str(REPO_ROOT / name)})
    assert [entry.repo for entry in config.policy.trusted_code] == ["tinfoilsh/double-blind-eval"]


def test_committed_strict_policy_lists_no_benchmark_owner():
    # Strict accepts no one until a real owner is added. The dev example's list is checked in test_fixtures.
    assert load_config({"REGISTRY_POLICY": str(REPO_ROOT / "registry-policy.yaml")}).policy.benchmark_owners == []
