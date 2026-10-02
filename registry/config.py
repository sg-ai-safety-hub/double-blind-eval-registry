"""Runtime configuration: mode, paths and the trust policy.

Trust comes only from the policy file, so anything unexpected
here stops the app from starting rather than falling back to a default.
"""

import hashlib
import logging
import shutil
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from registry import spec

log = logging.getLogger(__name__)

MODES = ("strict", "dev")
DEFAULT_POLICY_PATHS = {"strict": Path("registry-policy.yaml"), "dev": Path("registry-policy.dev.yaml")}
DEV_POLICY_EXAMPLE = Path("registry-policy.dev.example.yaml")
DEBUG_ENV = "REGISTRY_DEBUG"


class ConfigError(Exception):
    """The registry must not start with this configuration."""


class _PolicyModel(BaseModel):
    # strict: no coercion, e.g. a YAML `!!binary` value stays bytes instead of being decoded into a string;
    # forbid: a misspelt or unsupported key is an error, never silently ignored.
    model_config = ConfigDict(strict=True, extra="forbid")


class TrustedCode(_PolicyModel):
    # owner/name only: check 4 strips the "github.com/" prefix from the receipt's repo.
    repo: str = Field(pattern=rf"^{spec.GITHUB_OWNER_NAME}$")


class BenchmarkOwner(_PolicyModel):
    # The Ed25519 key the receipt's benchmark-owner party carries, as 64 lowercase hex.
    public_key: str = Field(pattern=spec.HEX64)
    display: str = Field(min_length=1)


class Policy(_PolicyModel):
    trusted_code: list[TrustedCode] = Field(min_length=1)
    benchmark_owners: list[BenchmarkOwner]

    @field_validator("benchmark_owners")
    @classmethod
    def _each_key_once(cls, owners: list[BenchmarkOwner]) -> list[BenchmarkOwner]:
        keys = [owner.public_key for owner in owners]
        if len(keys) != len(set(keys)):
            raise ValueError("a public_key is listed more than once")
        return owners


@dataclass(frozen=True)
class Config:
    mode: str
    data_dir: Path
    policy_path: Path
    policy_sha256: str
    policy: Policy


def load_config(environ: Mapping[str, str]) -> Config:
    """Build the config from `environ`; raise ConfigError if the registry must not start."""
    mode = environ.get("REGISTRY_MODE", "strict")
    if mode not in MODES:
        raise _refuse(f"REGISTRY_MODE must be one of {MODES}, got {mode!r}")

    data_dir = Path(environ.get("REGISTRY_DATA_DIR", f"data/{mode}")).resolve()
    policy_path = Path(environ.get("REGISTRY_POLICY", DEFAULT_POLICY_PATHS[mode]))
    # Only the default dev policy is created from the example; an explicit path must exist.
    copy_example = mode == "dev" and "REGISTRY_POLICY" not in environ and not policy_path.exists()
    try:
        if copy_example:
            shutil.copyfile(DEV_POLICY_EXAMPLE, policy_path)
            log.info("copied %s to %s", DEV_POLICY_EXAMPLE, policy_path)
        raw = policy_path.read_bytes()
    except OSError as e:
        raise _refuse(f"cannot load policy file {policy_path}: {e}") from e

    try:
        policy = Policy.model_validate(yaml.safe_load(raw))
    except (yaml.YAMLError, ValidationError) as e:
        raise _refuse(f"invalid policy file {policy_path}: {e}") from e

    digest = hashlib.sha256(raw).hexdigest()
    log.debug(
        "ACCEPT policy %s sha256=%s trusted_code=%d benchmark_owners=%d",
        policy_path, digest, len(policy.trusted_code), len(policy.benchmark_owners),
    )
    log.debug("config: mode=%s data_dir=%s", mode, data_dir)
    return Config(mode, data_dir, policy_path.resolve(), digest, policy)


def enable_debug_logging() -> None:
    """Send the registry's own DEBUG logs to stderr.

    Touches only the "registry" logger. Never use Flask's debug mode for this: it
    enables the Werkzeug debugger, which allows remote code execution.
    """
    logger = logging.getLogger("registry")
    logger.setLevel(logging.DEBUG)
    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
        logger.addHandler(handler)


def _refuse(reason: str) -> ConfigError:
    log.debug("REJECT config: %s", reason)
    return ConfigError(reason)
