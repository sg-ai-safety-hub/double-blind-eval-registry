# Fixtures

Nothing here is a trustworthy record. Fixture keys are derived from public names. Most fixture quotes
are `SIMULATED-` sentinels; the rest never bind the receipt's key: a live Tinfoil report stapled onto a
receipt it doesn't belong to (stapled_B, C11–C13; C8 with one byte flipped), or random bytes (C9).
Never publish a fixture to production Sigstore.

| Path | Contents | Made by |
|---|---|---|
| `evalresult/worked_example.statement.json` | The worked example: a complete, unsigned EvalResult/v0.1 statement. It predates DBE's party names (`model_provider`, `evaluator`), so `make_fixtures.py` renames those roles to `model-owner` and `benchmark-owner`. | Given. Never edit. |
| `generated/`, `expected.json` | A signed receipt for each test case, and the verdict each one should get. | `uv run python scripts/make_fixtures.py` (deterministic). Never hand-edit. |
| `dbe/sample-receipt.json` | A sample of DBE's own receipt format, dbe-receipt-v1, which the registry does not accept (fixture U6). | Captured once; see below. Never regenerate. |
| `tinfoil/` | Live SEV-SNP reports (`<name>.quote`: base64 of the raw report) with a sidecar (`<name>.meta.json`: repo, release tag, capture time). The live fixtures (stapled_B, C8, C9, C11–C13) are built from them. | Captured once; see below. `scripts/capture_tinfoil_reports.py` never overwrites a capture. Never regenerate. |

The benchmark-owner keys the fixtures use are listed in `registry-policy.dev.example.yaml`, except
`C14_unlisted_bo`'s, which must stay off it. `make_fixtures.py` prints them.

## `dbe/sample-receipt.json`

- Source: `docs/sample-receipt.json` in https://github.com/tinfoilsh/double-blind-eval
- Pinned commit: `c573c8a3013206c4a31f887e2f892fe7ee1e4fc8`. The file was last
  changed in `01609152bb26694f2052030dd79021346a8c8074`, "Add a real receipt from the v0.0.3 deployment
  for offline verification".
- Git blob `dca8df89527b4d54a3eed99a33d02a42e1f1f332`, 2655 bytes: `git hash-object fixtures/dbe/sample-receipt.json`
  prints it.

## `tinfoil/`

Captured by `scripts/capture_tinfoil_reports.py` from Tinfoil's bundle service
(`https://atc.tinfoil.sh`); each `.meta.json` records when. Only the raw report is kept, never the VCEK or the Sigstore bundle:
checks 3 and 4 fetch those themselves.

| Capture | Enclave | Repo | Release | Report |
|---|---|---|---|---|
| `dbe` | `dbe.tinfoil.containers.tinfoil.dev` | `tinfoilsh/double-blind-eval` | `v0.0.4` (digest `feb73226…`) | 1184 bytes |
| `router` | the service's default router (`inference.tinfoil.sh`) | `tinfoilsh/confidential-model-router` | `v0.0.155` (digest `ad95d02b…`) | 1184 bytes |

Each release was the repo's latest at capture, and its digest matched the bundle's.
