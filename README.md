# Double Blind Eval Registry

A registry web app that verifies and indexes model evaluation receipts for SASH's Four Pillars project.

The registry runs seven checks on each submitted receipt, stores the exact bytes it received for each
accepted receipt, and lists what it accepted in a read API and a web UI.

## Run it

Needs Python 3.12 with [uv](https://docs.astral.sh/uv/), and Node with pnpm 11 (via corepack).

```bash
uv sync                                                # backend dependencies
cd web && pnpm install && pnpm build && cd ..          # frontend, built into web/dist
uv run flask --app registry.app run --port 5050        # backend and UI at http://127.0.0.1:5050
```

Add `REGISTRY_MODE=dev` before `uv run flask` to run in dev mode, which also accepts test data. To work on
the UI with live reload, keep the backend running and run `cd web && pnpm dev` for http://localhost:5173.

### Deploy on Railway

`railpack.json` builds the UI and starts the registry under gunicorn, in strict mode.

**The policy's benchmark owner is a sample.** `registry-policy.yaml` lists `benchmark_owner@openmined.org`,
the approver of OpenMined's sample receipt, so that the demo has a receipt to accept. Replace it with the real
benchmark owners' emails before the registry is used for anything but a demo.

In the Railway service:

1. Attach a volume at `/data` and set `REGISTRY_DATA_DIR=/data`, so accepted receipts survive redeploys.
2. Under Settings → Networking, generate a domain and set `REGISTRY_PUBLIC_HOST` to it (such as
   `name.up.railway.app`). The registry refuses requests addressed to any other host.
3. Submit receipts to `https://<domain>/api/records`, as in [Commands](#commands).

## Receipts

The registry accepts OpenMined's **syft-enclave receipt v3**: the record of one model evaluation run inside a
[Tinfoil](https://tinfoil.sh) confidential enclave. A receipt is an
[in-toto Statement v1](https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md) with
`predicateType` `https://openmined.org/syft-enclave/receipt/v3`, signed by the enclave's attested key and
wrapped in a [DSSE envelope](https://github.com/secure-systems-lab/dsse). The registry reads these predicate
fields and allows any others:

| Field | What it says |
|---|---|
| `evalPipeline` | what was evaluated: `models` (the `base` model, adapters, classifiers…) and `config` (sampling settings…), each by digest, with optional `params` (such as sampling's temperature) shown as given. The statement's subject is sha256 of this object's JCS. |
| `evalDataset` | the eval dataset, by digest |
| `results` | the metrics and item counts |
| `execution` | when it ran, and the hardware attestation: `referenceValue`, the GitHub release whose Sigstore-signed measurement the enclave should match, and `keyBinding`, Tinfoil's [attested keys](https://docs.tinfoil.sh/containers/attested-keys): an AMD SEV-SNP report whose `report_data` commits to `crypto_material`, which holds the enclave's Ed25519 signing key |
| `parties` | who took part, by role and email |
| `consent` | the emails that approved the run |

`registry/syft_receipt.py` is the schema the registry enforces. `fixtures/openmined/receipt.dsse.json` is a
real receipt from OpenMined's enclave, and most test fixtures are built from its statement.

## Checks

| # | Check | Passes when |
|---|---|---|
| 1 | signature | the DSSE signature verifies under the enclave signing key named in `crypto_material` |
| 2 | key binding | the hardware report's `report_data` commits to `crypto_material` (Tinfoil's `report-data/v1`) |
| 3 | hardware | the AMD SEV-SNP report verifies against AMD's certificate chain (via the Tinfoil SDK) |
| 4 | measurement | the attested measurement is the Sigstore-signed release of a trusted repo |
| 5 | digests | the subject digest is sha256 of `evalPipeline`'s JCS |
| 6 | consent | an approval comes from an email on the registry's policy list |
| 7 | publication | the receipt is logged on [Rekor](https://docs.sigstore.dev/logging/overview/), Sigstore's public transparency log: the entry at the submitted log index holds the receipt's signature and signing key |

A receipt is listed as **verified** when every check passes. A receipt with no hardware report
(checks 2–4 and 7 pending) is accepted as **incomplete**, in dev mode only. Anything else is refused.
OpenMined checks who owns each approver email; the registry only matches emails against its list.

OpenMined's benchmark owner logs each receipt on Rekor v1 right after the run, and gets back the entry's log
index. Submit that index with the receipt, as the `logIndex` form field: it is required for any receipt with
a hardware report. Check 7 fetches that one entry. It trusts Rekor's answer: it doesn't verify the entry's
signed timestamp or inclusion proof, and it doesn't say who logged the receipt.


## Commands

```bash
uv sync
uv run pytest -m "not network"      # offline tests
uv run pytest                       # also the network tests (AMD via Tinfoil, Sigstore, GitHub, Rekor)

REGISTRY_MODE=dev uv run flask --app registry.app run --port 5050 --reload
curl -X POST http://127.0.0.1:5050/api/records -F 'record=@fixtures/generated/sim_A.dsse.json'
curl -X POST http://127.0.0.1:5050/api/records -F 'record=@fixtures/openmined/receipt.dsse.json' -F 'logIndex=3129204433'
uv run python scripts/seed_dev.py   # POSTs every fixture dev mode accepts, OpenMined's real receipt included

REGISTRY_MODE=dev uv run python scripts/rebuild_index.py   # after editing the policy; then restart

cd web && pnpm install && pnpm dev  # UI at http://localhost:5173
cd web && pnpm build                # Flask then serves the UI at http://127.0.0.1:5050
cd web && pnpm test                 # the UI's formatting and routing tests (Node's built-in runner)
```

- **Modes.** Strict is the default. Dev mode (`REGISTRY_MODE=dev`) also accepts incomplete receipts and
  keeps its own data directory.
- **Trust.** Trust comes only from the policy file (`registry-policy.yaml`, or `registry-policy.dev.yaml`
  in dev mode, copied from the example on first run). `trusted_code` lists the repos check 4 trusts, and
  `benchmark_owners` lists the approver emails check 6 accepts.
- **Network.** Checks 3, 4 and 7 need the network. If it can't be reached, the POST returns 503 and
  nothing is stored.
- **Index.** The store (`data/<mode>/store`) holds the exact bytes of each accepted receipt; the index
  (`data/<mode>/index.sqlite3`) is derived from it. The server refuses to start on an index built under
  another policy or mode, and prints the `scripts/rebuild_index.py` command that rebuilds it.
- **Flask on 127.0.0.1 only.** Never run it with `--host 0.0.0.0` or `--debug`. A deployment runs gunicorn
  instead (see [Deploy on Railway](#deploy-on-railway)).

## API

JSON on `http://127.0.0.1:5050`, or on a deployment's domain. Ids and digests in paths are 64 lowercase hex.

| Endpoint | Returns |
|---|---|
| `POST /api/records` | Submit a receipt as the multipart file part `record`: 201 (accepted), 200 (already listed), or the refusal |
| `GET /api/records?limit=20` | The newest records |
| `GET /api/records/<id>` and `/api/records/<id>/record.dsse.json` | One record, and its exact bytes (sha256 = id) |
| `GET /api/systems/<subjectDigest>` | A system's components and records |
| `GET /api/components/<digest>` | A component's roles, labels, systems and records |
| `GET /api/models`, `GET /api/models/<digest>` | Models, by base model digest |
| `GET /api/evals`, `GET /api/evals/<datasetDigest>` | Evals (eval datasets) and their records |
| `GET /api/lookup/<digest>` | What a digest names: system, eval, record, model or component |
| `GET /api/health` | Mode, policy hash and version |

Test fixtures are described in [fixtures/README.md](fixtures/README.md).
