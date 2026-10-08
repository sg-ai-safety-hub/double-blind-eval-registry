# Double Blind Eval Registry

A local web app that verifies and indexes AI-evaluation receipts for SASH's Four Pillars project.
The design is described in the Google Doc *Building the Four Pillars Registry*.

The registry runs seven checks on each submitted receipt, stores the exact bytes it received for each
accepted receipt, and lists what it accepted. Work in progress: receipt ingestion, the index and the
read API work; the UI is still being built.

## Receipts

**EvalResult/v0.1** is the Four Pillars receipt format for one AI evaluation run. A receipt is an
[in-toto Statement v1](https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md) with
`predicateType` `https://www.aisafety.sg/fourpillars/EvalResult/v0.1`, signed by the run's key and wrapped in a
[DSSE envelope](https://github.com/secure-systems-lab/dsse). Its predicate records:

| Field | What it says |
|---|---|
| `system` | the components evaluated (base weights, adapters, runtime image, sampling settings…), each by digest, and `pipelineDigest` over them. The statement's subject is this digest. |
| `eval` | the eval set and the harness, each by digest, and `evalDigest` over them |
| `results` | the metrics and item counts |
| `execution` | when it ran; `runPublicKey`, the key that signed the receipt; and the hardware attestation: an AMD SEV-SNP report (`quote`) and `referenceValue`, the GitHub release whose Sigstore-signed measurement the report should match |
| `parties` | who took part: exactly one `model-owner` and one `benchmark-owner`, each identified by an Ed25519 key |
| `consent` | optional: both owners' Ed25519 approvals of the run's `manifestDigest` |

Consent and the party names follow DBE, Tinfoil's
[double-blind-eval](https://github.com/tinfoilsh/double-blind-eval), which runs evaluations inside a
confidential enclave. `registry/evalresult.py` is the schema the registry enforces.
`fixtures/evalresult/worked_example.statement.json` (the *worked example*) is a complete, unsigned
statement, and most test fixtures are built from it.

## Checks

| # | Check | Passes when |
|---|---|---|
| 1 | signature | the DSSE signature verifies under the receipt's `runPublicKey` |
| 2 | key binding | the hardware report binds `runPublicKey` |
| 3 | hardware | the AMD SEV-SNP report verifies against AMD's certificate chain (via the Tinfoil SDK) |
| 4 | measurement | the attested measurement is the Sigstore-signed release of a trusted repo |
| 5 | digests | `pipelineDigest` and `evalDigest` recompute |
| 6 | publication | not verified in this version (always N/A) |
| 7 | consent | the model owner's and the benchmark owner's Ed25519 approvals verify |

A receipt is accepted only if its benchmark owner's key is on the registry's policy list and check 7
passes. It is listed as **verified** when every check passes. A receipt with no hardware report
(checks 2–4 pending) is accepted as **incomplete**, in dev mode only. Anything else is refused.

Out of scope: Sigstore publication bundles, publisher identity, a PKI for benchmark-owner keys,
TDX/GPU attestation, auth and deployment beyond localhost.

## Run it

Needs Python 3.12 with [uv](https://docs.astral.sh/uv/), and Node with pnpm 11 (via corepack).

```bash
uv sync
uv run pytest -m "not network"      # offline tests
uv run pytest                       # also the network tests (AMD via Tinfoil, Sigstore, GitHub)

REGISTRY_MODE=dev uv run flask --app registry.app run --port 5050 --reload
curl -X POST http://127.0.0.1:5050/api/records -F 'record=@fixtures/generated/sim_A.dsse.json'
uv run python scripts/seed_dev.py   # POSTs every fixture dev mode accepts to the dev server

REGISTRY_MODE=dev uv run python scripts/rebuild_index.py   # after editing the policy; then restart
uv run python -m tests.demo_verified --out data/demo      # one verified record, with the Tinfoil SDK replaced

cd web && pnpm install && pnpm dev  # UI at http://localhost:5173
```

- **Modes.** Strict is the default. Dev mode (`REGISTRY_MODE=dev`) also accepts incomplete receipts and
  keeps its own data directory.
- **Trust.** Trust comes only from the policy file (`registry-policy.yaml`, or `registry-policy.dev.yaml`
  in dev mode, copied from the example on first run). `trusted_code` lists the repos check 4 trusts, and
  `benchmark_owners` lists the accepted benchmark-owner keys.
- **Network.** Checks 3 and 4 need the network. If it can't be reached, the POST returns 503 and
  nothing is stored.
- **Index.** The store (`data/<mode>/store`) holds the exact bytes of each accepted receipt; the index
  (`data/<mode>/index.sqlite3`) is derived from it. The server refuses to start on an index built under
  another policy or mode, and prints the `scripts/rebuild_index.py` command that rebuilds it.
- **Localhost only.** Never run with `--host 0.0.0.0` or `--debug`.

## API

JSON on `http://127.0.0.1:5050`. Ids and digests in paths are 64 lowercase hex.

| Endpoint | Returns |
|---|---|
| `POST /api/records` | Submit a receipt as the multipart file part `record`: 201 (accepted), 200 (already listed), or the refusal |
| `GET /api/records?limit=20` | The newest records |
| `GET /api/records/<id>` and `/api/records/<id>/record.dsse.json` | One record, and its exact bytes (sha256 = id) |
| `GET /api/systems/<pipelineDigest>` | A system's components and records |
| `GET /api/components/<digest>` | A component's roles, labels, systems and records |
| `GET /api/models`, `GET /api/models/<digest>` | Models, by base weights digest |
| `GET /api/evals`, `GET /api/evals/<evalDigest>` | Evals and their records |
| `GET /api/lookup/<digest>` | What a digest names: system, eval, record, model or component |
| `GET /api/health` | Mode, policy hash and version |

Test fixtures are described in [fixtures/README.md](fixtures/README.md).
