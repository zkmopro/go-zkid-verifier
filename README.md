# go-zkid-verifier

A Go server that issues challenges and verifies zero-knowledge proofs of Taiwan CDC card identity, over REST and gRPC. Proofs come from the [zkID](https://github.com/privacy-ethereum/zkID/tree/RSA-X.509-Cert) circuits on top of [Spartan2](https://github.com/therealyingtong/Spartan2.git) with Hyrax commitments.

Every `/link-verify` call checks one cert-chain proof (RSA-2048 or RSA-4096) plus one user-signature proof (RSA-2048) and enforces five things server-side:

1. The FFI accepts both proofs and their `pk_commit` linkage holds.
2. The `smt_root` public input matches the current revocation-list root for the issuer ([moica-revocation-smt](https://github.com/privacy-ethereum/moica-revocation-smt)).
3. The `issuer_rsa_modulus` public input matches the RSA modulus of the published MOICA-G2 (RS2048) or MOICA-G3 (RS4096) certificate — i.e. the proof was actually signed by MOICA, not an impostor.
4. The `app_id` reconstructed from user_sig public values matches the configured `APP_ID` env value (constant-time compare). The prover signs `APP_ID`; the resulting RSA signature derives the cardholder-bound `nullifier` inside the same circuit.
5. The per-session `challenge` bound into the user-sig proof matches the value `/challenge` issued. The binding is a Semaphore-style dummy square (`challengeSquared <== challenge * challenge`) — see [PR#60 follow-on](https://github.com/zkmopro/zkID/pull/60). Stops replay of pre-generated proofs across sessions.

`APP_ID` is one 31-character lowercase hex string per relying party, set via env at server startup (e.g. `APP_ID=$(LC_ALL=C tr -dc '0-9a-f' </dev/urandom | head -c 31)`). `challenge` is per-session — a fresh 254-bit decimal field element issued by `/challenge`, bound into the user-sig proof by the prover, and extracted server-side from the proof's public inputs at `/link-verify`. The server looks up the challenge from the proof (normalising hex to decimal if needed) and consumes it on success.

## Quickstart

The Rust crate fetches the zkID source via Cargo. The C++ witness-calculator artifacts are bundled inside the dependency — no local zkID clone or Yarn/circom toolchain required.

```bash
git clone https://github.com/privacy-ethereum/go-zkid-verifier.git
cd go-zkid-verifier
make build            # downloads artifacts, builds Rust + Go binaries
cp .env.example .env
echo "APP_ID=$(LC_ALL=C tr -dc '0-9a-f' </dev/urandom | head -c 31)" >> .env
make serve
```

- HTTP on `:8080`, gRPC on `:9090`
- SQLite at `./zkid.db`
- SMT root fetched from Arbitrum Sepolia, falling back to a pinned GitHub release
- MOICA issuer certs shipped embedded; refreshed in background from `moica.nat.gov.tw`

Test a round-trip:

```bash
# Issue a challenge
curl -s -X POST http://localhost:8080/challenge | jq .

# Submit proofs (user-signs the challenge, then produces both ZK proofs)
curl -s -X POST http://localhost:8080/link-verify \
  -H "Content-Type: application/json" \
  -d '{"cert_chain_type":"rs2048","cert_chain_proof":"<base64>","user_sig_proof":"<base64>"}' | jq .

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
| `POST` | `/challenge` | Issue a fresh `challenge`. Returns `{challenge, app_id, expires_at}`, TTL 5 min. |
| `GET`  | `/challenge/{challenge}` | Fetch a challenge by value. |
| `POST` | `/link-verify` | Verify a cert-chain + user-sig proof pair. Body limit 2 MB. |
| `GET`  | `/smt-root/status` | Trusted revocation-root cache snapshot. |
| `GET`  | `/issuer-cert/status` | Trusted MOICA issuer-cert cache snapshot. |
| `POST` | `/debug/db/clean` | **Dev only.** Wipes `challenges` + `verifications`. Requires `DEBUG_TOKEN` env var and `Authorization: Bearer <token>` header. Route is unregistered (404) when `DEBUG_TOKEN` is unset. |

### `POST /challenge`

No request body — call as a bare `POST`. Success body (200):

```json
{
  "challenge": "<decimal field element>",
  "app_id": "<31-char UTF-8 string>",
  "expires_at": "2026-04-29T12:34:56Z"
}
```

`challenge` is a fresh 254-bit decimal field element (32 random bytes, top 2 bits cleared, big-endian), with a 5-minute TTL. The prover folds it into the user-sig proof; the server later extracts it from the proof's public inputs to bind the proof to this session. `app_id` echoes the server's configured `APP_ID` env so the prover knows which bytes to sign.

### `GET /challenge/{challenge}`

Re-fetches a still-live challenge by value. Response shape is identical to `POST /challenge`. Useful for clients that want to confirm a challenge is still in TTL before kicking off proof generation.

### `/challenge` response codes

| Code | Reason / meaning | Notes |
|---|---|---|
| `200` | Success — body is `{challenge, app_id, expires_at}`. | Both `POST /challenge` and `GET /challenge/{challenge}`. |
| `400` | Challenge expired. | `GET /challenge/{challenge}` only — challenge exists but passed its 5-minute TTL. |
| `404` | Challenge not found. | `GET /challenge/{challenge}` only — no live challenge with that value. |
| `500` | Store error. | SQLite read/write failed during create or lookup. |

### `POST /link-verify`

Request — no `challenge` field; the challenge is extracted server-side from the user_sig proof's public inputs:

```json
{
  "cert_chain_type": "rs2048",
  "cert_chain_proof": "<base64>",
  "user_sig_proof": "<base64>"
}
```

`cert_chain_type` is `"rs2048"` (default) or `"rs4096"`.

Success body (200):

```json
{
  "verified": true,
  "nullifier": "<nullifier hex>",
  "id_verified": true,
  "persisted": true,
  "public_signals": { "cert_chain": ["..."], "user_sig": ["..."] },
  "parsed_inputs": {
    "pk_commit": "...",
    "nullifier": "...",
    "app_id": "<31-char UTF-8 string>",
    "challenge": "<decimal>",
    "issuer_rsa_modulus": ["...", "..."],
    "smt_root": "0x..."
  },
  "smt_root":       { "issuer": "g2", "match": true, "expected": "0x…", "observed": "0x…", "trust_source": "onchain",  "trusted_at": "…" },
  "issuer_modulus": { "issuer": "g2", "match": true, "expected_sha256": "0xc4c4…", "trust_source": "embedded", "trusted_at": "…" },
  "app_id":         { "match": true, "expected": "<APP_ID env>", "observed": "<proof app_id>" },
  "challenge":      { "match": true, "expected": "<decimal>", "observed": "<decimal>" }
}
```

The `smt_root`, `issuer_modulus`, and `app_id` blocks are each present whenever their respective checks ran. Only the first failing check populates `reason`; later blocks still report their outcome.

### `/link-verify` response codes

| Code | Reason / meaning | Notes |
|---|---|---|
| `200` | `verified=true` — proof accepted, record persisted, challenge consumed. |  |
| `400` | Request body malformed or missing `cert_chain_proof` / `user_sig_proof` / valid `cert_chain_type`. |  |
| `400` | Challenge expired. | Challenge exists but passed its 5-minute TTL. |
| `404` | Challenge not found or already consumed. | The challenge extracted from the proof's public inputs doesn't match any issued challenge. |
| `409` | `reason="smt_root_mismatch"` | Prover's `smt_root` disagrees with the trusted root — stale client. |
| `409` | `reason="issuer_modulus_mismatch"` | Prover's issuer modulus doesn't match MOICA-G2/G3 — wrong-issuer proof. |
| `409` | `reason="app_id_mismatch"` | The proof's `app_id` doesn't match the server's configured `APP_ID` — proof was minted for a different application. |
| `409` | Duplicate nullifier. | Same `nullifier` already verified. Response echoes `nullifier`. |
| `410` | Challenge already consumed. |  |
| `503` | Trust-anchor provider unavailable. | SMT root or issuer cert not cached — transient; retry. |
| `500` | `"proof verification failed"` — FFI error or other infrastructure failure. |  |

### Debug endpoint (dev only)

`POST /debug/db/clean` resets the verifier's SQLite state by deleting every row from `challenges` and `verifications` in a single transaction. It exists for manual / scripted integration testing against a running file-backed server — unit tests already use in-memory SQLite. The endpoint is **off by default**: the route is only registered when `DEBUG_TOKEN` is set, and even then every request must carry `Authorization: Bearer <DEBUG_TOKEN>` (constant-time compared). There is no gRPC equivalent — the proto surface stays product-only.

**Option A — `.env` file (recommended for local dev):**

```bash
# Generate a token and write it to .env
echo "DEBUG_TOKEN=$(openssl rand -hex 32)" >> .env

make serve   # godotenv loads .env automatically on startup

curl -X POST \
     -H "Authorization: Bearer $DEBUG_TOKEN" \
     http://localhost:8080/debug/db/clean
# → {"challenges_deleted":3,"verifications_deleted":2}
```

**Option B — inline environment variable:**

```bash
DEBUG_TOKEN=$(openssl rand -hex 32) make serve

curl -X POST -H "Authorization: Bearer $DEBUG_TOKEN" \
     http://localhost:8080/debug/db/clean
# → {"challenges_deleted":3,"verifications_deleted":2}
```

Copy `.env.example` to `.env` to get started:

```bash
cp .env.example .env
# then fill in DEBUG_TOKEN (and any other overrides you need)
```

| Code | Meaning |
|---|---|
| `200` | Cleanup succeeded; body is `{"challenges_deleted": N, "verifications_deleted": M}`. |
| `401` | `Authorization` header missing, not `Bearer`, or token mismatch. |
| `404` | `DEBUG_TOKEN` is unset on the server, so the route is not registered. |
| `500` | DB error during cleanup. |

> **Never set `DEBUG_TOKEN` in production.** This endpoint destroys verification history.

## gRPC API

`proto/zkid/v1/zkid.proto` defines `ZkIDVerifier` with the same verify semantics as HTTP (including `smt_root_mismatch`, `issuer_modulus_mismatch`, and `app_id_mismatch` fail modes). Messages up to 2 MB. Regenerate with `make proto`.

## Configuration

All via environment variables.

| Variable | Default | Purpose |
|---|---|---|
| `PORT` | `8080` | HTTP listen port |
| `GRPC_PORT` | `9090` | gRPC listen port |
| `DB_PATH` | `./zkid.db` | SQLite database path |
| `KEYS_DIR` | `./keys` | Verifying-key directory (auto-downloaded) |
| `CORS_ORIGIN` | `*` | `Access-Control-Allow-Origin` |
| `APP_ID` | _(required)_ | Exactly 31-character lowercase hex string identifying the relying party. The prover signs these bytes; the verifier hard-fails on mismatch. Generate with: `APP_ID=$(LC_ALL=C tr -dc '0-9a-f' </dev/urandom \| head -c 31)` |
| `SMT_ROOT_ENFORCE` | `strict` | `strict` = hard-fail on mismatch; `disabled` = skip (dev only) |
| `SMT_ROOT_RPC_URL` | `https://sepolia-rollup.arbitrum.io/rpc` | Arbitrum Sepolia JSON-RPC |
| `SMT_ROOT_CONTRACT` | `0xc461326eb6e46F10A276B0F14BFFf8b256A43FFA` | `SMTRootStorage` address |
| `SMT_ROOT_GITHUB_REPO` | `privacy-ethereum/moica-revocation-smt` | Fallback repo |
| `SMT_ROOT_GITHUB_TAG` | `snapshot-latest` | Fallback release tag |
| `SMT_ROOT_REFRESH_INTERVAL` | `10m` | SMT refresh cadence |
| `SMT_ROOT_FETCH_TIMEOUT` | `5s` | Per-source fetch timeout |
| `ISSUER_CERT_ENFORCE` | `strict` | `strict` = hard-fail on modulus mismatch; `disabled` = skip (dev only) |
| `ISSUER_CERT_G2_URL` | `https://moica.nat.gov.tw/repository/Certs/MOICA2.cer` | MOICA-G2 source (override for tests) |
| `ISSUER_CERT_G3_URL` | `https://moica.nat.gov.tw/repository/Certs/MOICA-G3.cer` | MOICA-G3 source (override for tests) |
| `ISSUER_CERT_REFRESH_INTERVAL` | `24h` | Issuer-cert refresh cadence |
| `ISSUER_CERT_FETCH_TIMEOUT` | `10s` | Per-source fetch timeout |
| `DEBUG_TOKEN` | _(unset)_ | When set, exposes `POST /debug/db/clean`. Requests must carry `Authorization: Bearer <DEBUG_TOKEN>`. Leave unset in production. |

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
linkverify/         Orchestrator: FFI → parse → SMT check → issuer-modulus check → app_id check → challenge lookup → record
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
    KeysDir:       keysDir,
    SmtRoot:       smtProvider,    // nil disables SMT check (dev/tests only)
    IssuerCert:    issuerProvider, // nil disables issuer-modulus check (dev/tests only)
    ExpectedAppID: appID,          // 31-char UTF-8 string; empty disables app_id check (dev/tests only)
    Logger:        smtroot.DefaultLogger{},
}
service := linkverify.NewService(v, sqliteStore)

// Both transports route through the same call. Challenge and nullifier are
// both extracted server-side from the user_sig proof's public inputs.
res, err := service.VerifyAndRecord(ctx, linkverify.Request{...})
```

Sentinel errors bubble unwrapped so each transport picks its own status code: `store.ErrChallengeNotFound`, `ErrChallengeExpired`, `ErrChallengeConsumed`, `ErrDuplicateNullifier`, `linkverify.ErrSmtRootUnavailable`, `linkverify.ErrIssuerCertUnavailable`.

`linkverify.Verify` caps concurrent ZK verifications at 10 (semaphore) and stages each proof in a temp dir with symlinked verifying keys.

## Updating the server

```bash
# update git
git pull origin main

# clean
make clean

# build
make download-keys
make build
```

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
cross build --manifest-path rust/Cargo.toml --target x86_64-unknown-linux-gnu --release

mkdir -p lib/x86_64-unknown-linux-gnu
cp rust/target/x86_64-unknown-linux-gnu/release/libzk_verifier.a lib/x86_64-unknown-linux-gnu/
```

`rust/Cross.toml` pre-installs `nasm` and `libgmp-dev`.

### CI

`.github/workflows/ci.yml` runs a pure-Go `challenge-server` job (CGO off, `./store/`) and a `verifier` matrix (macOS + Linux) that downloads pre-built circom artifacts from the zkID GitHub release, builds the Rust lib, downloads verifying keys, and runs the full test suite including RS2048 / RS4096 FFI fixtures. Trust-anchor packages use injected static providers so CI never hits live endpoints.
