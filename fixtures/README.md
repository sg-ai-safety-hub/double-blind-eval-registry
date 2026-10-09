# Fixtures

Apart from OpenMined's receipt (`openmined/`), nothing here is a trustworthy record. Fixture keys are
derived from public names. Most fixtures' hardware reports are `SIMULATED-` sentinels; the rest never bind
the receipt's key: a real report stapled onto a receipt it doesn't belong to (stapled_B, C11–C13; C8 with
one byte flipped), or random bytes (C9). Never publish a fixture to production Sigstore, and never log one on Rekor.

| Path | Contents | Made by |
|---|---|---|
| `openmined/receipt.dsse.json` | A real syft-enclave receipt v3 from OpenMined's enclave (fixture om_receipt). Every generated fixture starts from its statement. | Given by OpenMined; see below. Never edit. |
| `openmined/sample-receipt.json` | The same statement, without its DSSE envelope, so unsigned (fixture U7). | Given by OpenMined. Never edit. |
| `generated/`, `expected.json` | A signed receipt for each test case, and the verdict each one should get. | `uv run python scripts/make_fixtures.py` (deterministic). Never hand-edit. |
| `dbe/sample-receipt.json` | A sample of DBE's own receipt format, dbe-receipt-v1, which the registry does not accept (fixture U6). | Captured once; see below. Never regenerate. |
| `rekor/` | Rekor's answers for OpenMined's receipt: `om_receipt.search.json`, the search by its payload hash, and `om_receipt.entry.json`, its entry (log index 3129204433). Offline tests answer check 7 with them. | Captured once with curl; see below. Never edit. |
| `tinfoil/` | Live SEV-SNP reports (`<name>.quote`: base64 of the raw report) with a sidecar (`<name>.meta.json`: repo, release tag, capture time). C11 and C12 are built from the router capture. | Captured once; see below. `scripts/capture_tinfoil_reports.py` never overwrites a capture. Never regenerate. |

`registry-policy.dev.example.yaml` lists an approver email of every fixture except `C6_unlisted_approver`,
none of whose approvers may be listed. `make_fixtures.py` prints the emails.

## `openmined/`

| File | sha256 | Bytes |
|---|---|---|
| `receipt.dsse.json` | `3bc3aabb8473df45e75ab91e624cca1a5588a3ff6e4a39215e7c0f6f8f96fd31` | 147162 |
| `sample-receipt.json` | `0bcd509ffc1d5406c7d4f26450ceff298bc4b8bfb09e8d05ca906bea385c6bc0` | 120224 |

The receipt's report measures `OpenMined/syft-enclave-tinfoil` `v0.1.28` (digest `747df14f…`). The generated
fixtures leave out its statement's bulky parts the registry never reads: file contents and the attestation's
`collateral`.

## `dbe/sample-receipt.json`

- Source: `docs/sample-receipt.json` in https://github.com/tinfoilsh/double-blind-eval
- Pinned commit: `c573c8a3013206c4a31f887e2f892fe7ee1e4fc8`. The file was last
  changed in `01609152bb26694f2052030dd79021346a8c8074`, "Add a real receipt from the v0.0.3 deployment
  for offline verification".
- Git blob `dca8df89527b4d54a3eed99a33d02a42e1f1f332`, 2655 bytes: `git hash-object fixtures/dbe/sample-receipt.json`
  prints it.

## `rekor/`

Rekor's answers, saved byte for byte. The first is the search by the sha256 of the receipt's payload
(`06337ce7…`); the second is the one entry it found, which OpenMined's benchmark owner logged:

```bash
curl -X POST https://rekor.sigstore.dev/api/v1/index/retrieve -H 'Content-Type: application/json' \
  -d '{"hash":"sha256:06337ce74612a8afa9774f0435cdef2f2227958107c259e8ab4d751ea5a5e051"}' -o om_receipt.search.json
curl https://rekor.sigstore.dev/api/v1/log/entries/108e9186e8c5677a90985c71d8a25a4de23d6f7e17e8d0cb40089161de9a6ed3cc14072c0d1a5a6f \
  -o om_receipt.entry.json
```

| File | sha256 | Bytes |
|---|---|---|
| `om_receipt.search.json` | `3efaa1b1a55208a0ccc71cff3e6d2e6f645293d9b5b29e55b8bbd53fca3a1e55` | 85 |
| `om_receipt.entry.json` | `a29b58f766b2c5d95c1091e70eaabd6b6b4a386cdb189e4e5296c7e06b65e254` | 3510 |

The entry is Rekor v1 `dsse` entry 3129204433. Its payload hash and signature
are the receipt's; its envelope hash isn't sha256 of `receipt.dsse.json`, because the envelope was
re-serialised before it was logged.

## `tinfoil/`

Captured by `scripts/capture_tinfoil_reports.py` from Tinfoil's bundle service
(`https://atc.tinfoil.sh`); each `.meta.json` records when. Only the raw report is kept, never the VCEK or the Sigstore bundle:
checks 3 and 4 fetch those themselves.

| Capture | Enclave | Repo | Release | Report |
|---|---|---|---|---|
| `dbe` (no longer used by the fixtures) | `dbe.tinfoil.containers.tinfoil.dev` | `tinfoilsh/double-blind-eval` | `v0.0.4` (digest `feb73226…`) | 1184 bytes |
| `router` | the service's default router (`inference.tinfoil.sh`) | `tinfoilsh/confidential-model-router` | `v0.0.155` (digest `ad95d02b…`) | 1184 bytes |

Each release was the repo's latest at capture, and its digest matched the bundle's.
