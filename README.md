# go-zkid-verifier

A Go server that issues challenges and verifies zero-knowledge proofs of Taiwan CDC card identity, over REST and gRPC. Proofs come from the [zkID](https://github.com/zkmopro/zkID) circuits on top of [Spartan2](https://github.com/therealyingtong/Spartan2.git) with Hyrax commitments.

Every `/link-verify` call checks one cert-chain proof (RSA-2048 or RSA-4096) plus one device-signature proof (RSA-2048) and enforces three things server-side:

1. The FFI accepts both proofs and their `pk_commit` linkage holds.
2. The `smt_root` public input matches the current revocation-list root for the issuer ([moica-revocation-smt](https://github.com/moven0831/moica-revocation-smt)).
3. The `issuer_rsa_modulus` public input matches the RSA modulus of the published MOICA-G2 (RS2048) or MOICA-G3 (RS4096) certificate — i.e. the proof was actually signed by MOICA, not an impostor.

## Quickstart

```bash
git clone https://github.com/zkmopro/go-zkid-verifier.git
git clone https://github.com/zkmopro/zkID.git
cd go-zkid-verifier

make serve            # builds Rust + Go, downloads verifying keys, runs server
```

- HTTP on `:8080`, gRPC on `:9090`
- SQLite at `./zkid.db`
- SMT root fetched from Arbitrum Sepolia, falling back to a pinned GitHub release
- MOICA issuer certs shipped embedded; refreshed in background from `moica.nat.gov.tw`

Test a round-trip:

```bash
# Issue a challenge
curl -s -X POST http://localhost:8080/challenge | jq .

# Submit proofs (device-signs the challenge, then produces both ZK proofs)
curl -s -X POST http://localhost:8080/link-verify \
  -H "Content-Type: application/json" \
  -d '{"cert_chain_type":"rs2048","cert_chain_proof":"<base64>","device_sig_proof":"<base64>"}' | jq .

# Inspect trust-anchor caches
curl -s http://localhost:8080/smt-root/status    | jq .
curl -s http://localhost:8080/issuer-cert/status | jq .
```

### Prerequisites

- Go 1.25+ and Rust (stable)
- macOS or Linux
  - macOS: `xcode-select --install`
  - Linux: `sudo apt-get install -y g++ libstdc++-12-dev nasm libgmp-dev`
- `protoc` only if you regenerate `.pb.go` via `make proto`

## HTTP API

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/challenge` | Issue a 16-byte challenge. Returns `{challenge_id, challenge_bytes, expires_at}`, TTL 5 min. |
| `GET`  | `/challenge/{id}` | Fetch a challenge by ID. |
| `POST` | `/link-verify` | Verify a cert-chain + device-sig proof pair. Body limit 2 MB. |
| `GET`  | `/smt-root/status` | Trusted revocation-root cache snapshot. |
| `GET`  | `/issuer-cert/status` | Trusted MOICA issuer-cert cache snapshot. |

### `POST /link-verify`

Request — the challenge and nullifier are derived from the proof's public signals and are **not** in the request body:

```json
{
  "cert_chain_type": "rs2048",
  "cert_chain_proof": "<base64>",
  "device_sig_proof": "<base64>"
}
```

`cert_chain_type` is `"rs2048"` (default) or `"rs4096"`.

Success body (200):

```json
{
  "verified": true,
  "nullifier": "<subject_dn_hash hex>",
  "id_verified": true,
  "persisted": true,
  "public_signals": { "cert_chain": ["..."], "device_sig": ["..."] },
  "parsed_inputs": {
    "challenge": "...",
    "pk_commit": "...",
    "subject_dn_hash": "...",
    "issuer_rsa_modulus": ["...", "..."],
    "smt_root": "0x..."
  },
  "smt_root":       { "issuer": "g2", "match": true, "expected": "0x…", "observed": "0x…", "trust_source": "onchain",  "trusted_at": "…" },
  "issuer_modulus": { "issuer": "g2", "match": true, "expected_sha256": "0xc4c4…", "trust_source": "embedded", "trusted_at": "…" }
}
```

Both `smt_root` and `issuer_modulus` blocks are present whenever their respective checks ran. Only the first failing check populates `reason`; the other block still reports its outcome.

### `/link-verify` response codes

| Code | Reason / meaning | Notes |
|---|---|---|
| `200` | `verified=true` — proof accepted, record persisted, challenge consumed. |  |
| `200` | `verified=false, reason="proof_invalid"` — FFI rejected the proof. | Record **not** persisted, challenge **not** consumed. |
| `400` | Request body malformed or missing `cert_chain_proof` / `device_sig_proof` / valid `cert_chain_type`. |  |
| `404` | Challenge not found. | Proof's challenge doesn't match any live challenge, or it already expired. |
| `409` | `reason="smt_root_mismatch"` | Prover's `smt_root` disagrees with the trusted root — stale client. |
| `409` | `reason="issuer_modulus_mismatch"` | Prover's issuer modulus doesn't match MOICA-G2/G3 — wrong-issuer proof. |
| `409` | Duplicate nullifier. | Same `subject_dn_hash` already verified. Response echoes `nullifier`. |
| `410` | Challenge already consumed. |  |
| `503` | Trust-anchor provider unavailable. | SMT root or issuer cert not cached — transient; retry. |
| `500` | FFI crash or other infrastructure failure. |  |

## gRPC API

`proto/zkid/v1/zkid.proto` defines `ZkIDVerifier` with the same verify semantics as HTTP (including `smt_root_mismatch` and `issuer_modulus_mismatch` fail modes). Messages up to 2 MB. Regenerate with `make proto`.

## Configuration

All via environment variables.

| Variable | Default | Purpose |
|---|---|---|
| `PORT` | `8080` | HTTP listen port |
| `GRPC_PORT` | `9090` | gRPC listen port |
| `DB_PATH` | `./zkid.db` | SQLite database path |
| `KEYS_DIR` | `./keys` | Verifying-key directory (auto-downloaded) |
| `CORS_ORIGIN` | `*` | `Access-Control-Allow-Origin` |
| `SMT_ROOT_ENFORCE` | `strict` | `strict` = hard-fail on mismatch; `disabled` = skip (dev only) |
| `SMT_ROOT_RPC_URL` | `https://sepolia-rollup.arbitrum.io/rpc` | Arbitrum Sepolia JSON-RPC |
| `SMT_ROOT_CONTRACT` | `0xc461326eb6e46F10A276B0F14BFFf8b256A43FFA` | `SMTRootStorage` address |
| `SMT_ROOT_GITHUB_REPO` | `moven0831/moica-revocation-smt` | Fallback repo |
| `SMT_ROOT_GITHUB_TAG` | `snapshot-latest` | Fallback release tag |
| `SMT_ROOT_REFRESH_INTERVAL` | `10m` | SMT refresh cadence |
| `SMT_ROOT_FETCH_TIMEOUT` | `5s` | Per-source fetch timeout |
| `ISSUER_CERT_ENFORCE` | `strict` | `strict` = hard-fail on modulus mismatch; `disabled` = skip (dev only) |
| `ISSUER_CERT_G2_URL` | `https://moica.nat.gov.tw/repository/Certs/MOICA2.cer` | MOICA-G2 source (override for tests) |
| `ISSUER_CERT_G3_URL` | `https://moica.nat.gov.tw/repository/Certs/MOICA-G3.cer` | MOICA-G3 source (override for tests) |
| `ISSUER_CERT_REFRESH_INTERVAL` | `24h` | Issuer-cert refresh cadence |
| `ISSUER_CERT_FETCH_TIMEOUT` | `10s` | Per-source fetch timeout |

### Trust anchors

Both `smt_root` and `issuer_modulus` use the same pattern: pinned trust anchors, background refresh, stale-on-error.

**SMT revocation root.** Primary: `SMTRootStorage.getRoot(bytes32)` on Arbitrum Sepolia. Fallback: `snapshot-latest` GitHub release body. Startup is fail-closed — if neither source responds, the server refuses to boot. Set `SMT_ROOT_ENFORCE=disabled` for local dev.

**Issuer certificates.** MOICA-G2, MOICA-G3, and both of their GRCA parents ship **embedded** in the binary, with pinned SHA-256 fingerprints. A background fetch from `moica.nat.gov.tw` is *best-effort*: fetched certs must match the pinned fingerprint AND chain-validate to embedded GRCA before they replace the cached record. Fingerprint drift keeps the embedded copy in place and increments `consecutive_fail`. Rotating a cert requires a code release (new embedded bytes + new pinned fingerprint).

## Architecture

```
cmd/server ── HTTP (:8080)  /challenge  /link-verify  /smt-root/status  /issuer-cert/status
           ── gRPC (:9090)  ZkIDVerifier
           ── SQLite (challenges + verification records)
           ── smtroot/     revocation SMT root cache (onchain + GitHub)
           ── issuercert/  MOICA cert cache (embedded + HTTPS, GRCA-chained)
           └── verifier/   CGO → lib/<target>/libzk_verifier.a (Rust + ecdsa-spartan2)
```

The Rust static lib is selected by CGO per platform:

| Platform | Library directory |
|---|---|
| macOS Apple Silicon | `lib/aarch64-apple-darwin/` |
| Linux x86_64 | `lib/x86_64-unknown-linux-gnu/` |

### Package layout

```
cmd/server          REST + gRPC server entrypoint
cmd/verifier        Link-verify CLI (FFI smoke test)
httpapi/            HTTP transport (router, handlers, DTOs, error mapping)
grpc/               gRPC adapter over linkverify.Service
linkverify/         Orchestrator: FFI → parse → SMT check → issuer-modulus check → record
verifier/           CGO FFI + public-signals parser
smtroot/            Trusted revocation-root cache (onchain + GitHub fallback)
issuercert/         Trusted MOICA issuer-cert cache (embedded + HTTPS, GRCA-chained)
store/              SQLite (pure-Go modernc.org/sqlite)
keymanager/         Verifying-key auto-download
proto/zkid/v1/      zkid.proto + generated *.pb.go
rust/               Cargo.toml, Cross.toml, src/lib.rs (FFI shim)
lib/                Native libs per target (gitignored)
tests/artifacts/    Proof fixtures for RS2048 + RS4096
```

## Using the Go packages

`linkverify.Service` is the transport-agnostic orchestrator:

```go
v := &linkverify.Verifier{
    KeysDir:    keysDir,
    SmtRoot:    smtProvider,    // nil disables SMT check (dev/tests only)
    IssuerCert: issuerProvider, // nil disables issuer-modulus check (dev/tests only)
    Logger:     smtroot.DefaultLogger{},
}
service := linkverify.NewService(v, sqliteStore)

// HTTP path — challenge and nullifier derived from the proof:
res, err := service.VerifyAndRecordByProof(ctx, linkverify.Request{...})

// gRPC path — caller supplies challenge ID and nullifier:
res, err := service.VerifyAndRecordByID(ctx, challengeID, nullifier, linkverify.Request{...})
```

Sentinel errors bubble unwrapped so each transport picks its own status code: `store.ErrChallengeNotFound`, `ErrChallengeExpired`, `ErrChallengeConsumed`, `ErrDuplicateNullifier`, `linkverify.ErrSmtRootUnavailable`, `linkverify.ErrIssuerCertUnavailable`.

`linkverify.Verify` caps concurrent ZK verifications at 10 (semaphore) and stages each proof in a temp dir with symlinked verifying keys.

## Development

| Target | Description |
|---|---|
| `make build` | Server + verifier CLI |
| `make serve` | Build + run the server |
| `make verify` | Run the verifier CLI against `./keys/` |
| `make test` | Full test suite |
| `make test-verifier` | FFI fixture tests (requires `./keys/`) |
| `make test-linkverify` | Orchestration tests |
| `make download-keys` | Fetch verifying keys from the zkID GitHub release |
| `make proto` | Regenerate `.pb.go` |
| `make clean` | Remove build artifacts |

Integration tests gated by `//go:build integration` (currently `./issuercert/...`) run with:

```bash
go test -tags integration ./issuercert/...
```

### Cross-compile for Linux from macOS

```bash
cargo install cross --git https://github.com/cross-rs/cross

CROSS_CONTAINER_OPTS="-v /path/to/zkID:/path/to/zkID" \
  cross build --target x86_64-unknown-linux-gnu --release

mkdir -p lib/x86_64-unknown-linux-gnu
cp rust/target/x86_64-unknown-linux-gnu/release/libzk_verifier.a lib/x86_64-unknown-linux-gnu/
cp $(find rust/target/x86_64-unknown-linux-gnu/release/build -name "libwitnesscalc_rs256.so" -path "*/package/lib/*" | head -1) \
   lib/x86_64-unknown-linux-gnu/
```

`rust/Cross.toml` pre-installs `nasm` and `libgmp-dev`.

### CI

`.github/workflows/ci.yml` runs a pure-Go `challenge-server` job (CGO off, `./store/`) and a `verifier` matrix (macOS + Linux) that clones zkID at a pinned commit, builds the Rust lib, downloads verifying keys, and runs the full test suite including RS2048 / RS4096 FFI fixtures. Trust-anchor packages use injected static providers so CI never hits live endpoints.
