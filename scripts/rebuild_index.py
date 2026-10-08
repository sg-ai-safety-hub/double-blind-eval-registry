#!/usr/bin/env python3
"""Rebuild the index from the store, under the current policy and mode, and swap it in.

    REGISTRY_MODE=dev uv run python scripts/rebuild_index.py

Run it with the server's REGISTRY_* settings after editing the policy, then restart the server.
Every stored record is checked again. One the policy now refuses, or one whose stored bytes no longer
hash to its id (say, reformatted by an editor), stays in the store but leaves the index. Checks 3 and 4
need the network for records with a hardware report; if it can't be reached, the old index stays.
"""

import os
import sys

from registry.config import DEBUG_ENV, ConfigError, enable_debug_logging, load_config
from registry.ingest import rebuild
from registry.model import VerificationUnavailable
from registry.refcache import RefCache
from registry.store import Store


def main() -> int:
    if os.environ.get(DEBUG_ENV) == "1":
        enable_debug_logging()
    try:
        config = load_config(os.environ)
        indexed, skipped = rebuild(config, Store(config.store_dir), RefCache(config.refcache_dir))
    except (ConfigError, VerificationUnavailable) as e:
        print(f"rebuild failed, the old index is unchanged: {e}", file=sys.stderr)
        return 1
    for record_id, why in skipped:
        print(f"not indexed {record_id}: {why}")
    print(f"indexed {indexed} record(s) into {config.index_path}; restart the server")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
