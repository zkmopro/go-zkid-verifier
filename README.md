# go-zkid-verifier

A Go server that issues challenges and verifies zero-knowledge proofs of identity from a CDC card over both REST and gRPC. The ZK proof system is built on [Spartan2](https://github.com/therealyingtong/Spartan2.git) using the Hyrax polynomial commitment scheme, with circuits from [zkID](https://github.com/zkmopro/zkID).

Link-verify checks two independent ZK proofs — a **cert-chain** proof (RSA-2048 or RSA-4096) and a **device-signature** proof (RSA-2048) — and enforces that both proofs share the same `pk_commit` (i.e. both reference the same device public key). It additionally enforces that the cert-chain proof's `smt_root` public input equals the current revocation-list root published by [moven0831/moica-revocation-smt](https://github.com/moven0831/moica-revocation-smt) (onchain on Arbitrum Sepolia, with a GitHub-release fallback). Proofs carrying a stale or forged root are rejected.

## Architecture

```
Go server (cmd/server)
├── HTTP (:8080) ─ challenge, verify-tbs, link-verify, status, smt-root/status
├── gRPC (:9090) ─ ZkIDVerifier service
├── SQLite       ─ challenges + verification records (modernc.org/sqlite, pure Go)
├── smtroot/     ─ trusted SMT root cache (Arbitrum Sepolia RPC + GitHub releases)
└── verifier/    ─ CGO → lib/<target>/libzk_verifier.a (Rust staticlib)
                         └── ecdsa-spartan2 (Spartan2 ZK circuit)
                               └── lib/<target>/libwitnesscalc_rs256.{dylib,so}
```

CGO selects the correct library directory per platform at compile time:

| Platform | CGO tag | Library directory |
|---|---|---|
| macOS Apple Silicon | `darwin,arm64` | `lib/aarch64-apple-darwin/` |
| Linux x86_64 | `linux` | `lib/x86_64-unknown-linux-gnu/` |

## Prerequisites

- Go 1.25+
- Rust (stable)
- macOS or Linux
  - macOS: Xcode Command Line Tools (`xcode-select --install`)
  - Linux: `g++`, `libstdc++`, `nasm`, `libgmp-dev`
    ```bash
    sudo apt-get install -y g++ libstdc++-12-dev nasm libgmp-dev
    ```
- `protoc` (only needed if regenerating `.pb.go` files via `make proto`)

## Setup

### 1. Clone dependencies

Both this repo and [zkID](https://github.com/zkmopro/zkID) must be checked out as siblings:

```
parent/
  go-zkid-verifier/
  zkID/
```

```bash
git clone https://github.com/zkmopro/go-zkid-verifier.git
git clone https://github.com/zkmopro/zkID.git
cd go-zkid-verifier
```

### 2. Build

```bash
# Server (REST + gRPC)
make build-server

# Verifier CLI
make build-verifier

# Both
make build
```

Detects the current platform, runs `cargo build --release`, and copies `libzk_verifier.a` into `lib/<target>/`. The witness-calculation library (`libwitnesscalc_rs256.{dylib,so}`) is produced as a side effect of the Rust build and expected in the same directory at runtime.

**Cross-compile for Linux from macOS** (requires Docker):

```bash
cargo install cross --git https://github.com/cross-rs/cross

CROSS_CONTAINER_OPTS="-v /path/to/zkID:/path/to/zkID" \
  cross build --target x86_64-unknown-linux-gnu --release

mkdir -p lib/x86_64-unknown-linux-gnu
cp rust/target/x86_64-unknown-linux-gnu/release/libzk_verifier.a lib/x86_64-unknown-linux-gnu/
cp $(find rust/target/x86_64-unknown-linux-gnu/release/build -name "libwitnesscalc_rs256.so" -path "*/package/lib/*" | head -1) lib/x86_64-unknown-linux-gnu/
```

`rust/Cross.toml` configures the cross-compilation container with `nasm` and `libgmp-dev` pre-installed.

### 3. Verifying keys

Three verifying keys are required for link-verify, downloaded from the `zkmopro/zkID` GitHub release:

- `cert_chain_rs2048_verifying.key`
- `cert_chain_rs4096_verifying.key`
- `device_sig_rs2048_verifying.key`

The server downloads missing keys automatically on startup via `keymanager.EnsureKeys`. To pre-populate them manually:

```bash
make download-keys
```

## Server

```bash
make serve
# or:
go run ./cmd/server
```

Startup prints the HTTP and gRPC listeners, the SQLite path, and the keys directory. Missing verifying keys are downloaded before serving traffic.

### Environment variables

| Variable | Default | Description |
|---|---|---|
| `PORT` | `8080` | HTTP listen port |
| `GRPC_PORT` | `9090` | gRPC listen port |
| `DB_PATH` | `./zkid.db` | SQLite database path |
| `KEYS_DIR` | `./keys` | Directory holding verifying keys |
| `CORS_ORIGIN` | `*` | `Access-Control-Allow-Origin` value |
| `SMT_ROOT_ENFORCE` | `strict` | `strict` = hard-fail on mismatch; `disabled` = skip the SMT root check (local dev only) |
| `SMT_ROOT_RPC_URL` | `https://sepolia-rollup.arbitrum.io/rpc` | Arbitrum Sepolia JSON-RPC used for the `SMTRootStorage.getRoot` call |
| `SMT_ROOT_CONTRACT` | `0xc461326eb6e46F10A276B0F14BFFf8b256A43FFA` | `SMTRootStorage` address (from moica-revocation-smt) |
| `SMT_ROOT_GITHUB_REPO` | `moven0831/moica-revocation-smt` | Fallback source repository |
| `SMT_ROOT_GITHUB_TAG` | `snapshot-latest` | Fallback source release tag |
| `SMT_ROOT_REFRESH_INTERVAL` | `10m` | Background refresh cadence |
| `SMT_ROOT_FETCH_TIMEOUT` | `5s` | Per-source fetch timeout |

When `SMT_ROOT_ENFORCE=strict` (default), the server refuses to start if neither the onchain RPC nor the GitHub release can be reached at boot. This is fail-closed by design — see **Revocation enforcement** below.

### REST endpoints

| Method | Path | Description |
|---|---|---|
| `POST` | `/challenge` | Issue a new 16-byte challenge. Returns `{challenge_id, challenge_bytes, expires_at}` (5-minute TTL). |
| `GET` | `/challenge/{id}` | Retrieve a challenge by ID. 404 if not found, 400 if expired. |
| `POST` | `/verify-tbs` | Verify a 256-bit TBS hash against the challenge's `SHA256(challenge_bytes)`. Records the verification. |
| `POST` | `/link-verify` | Verify cert-chain + device-sig ZK proofs, their `pk_commit` linkage, **and the cert-chain proof's `smt_root` against the trusted root for the mapped issuer (RS2048 → MOICA-G2, RS4096 → MOICA-G3).** Records the verification on success. |
| `GET` | `/users/{nullifier}/status` | Return the persisted verification record for a nullifier. |
| `GET` | `/smt-root/status` | Return the in-memory trusted-root cache: source used, per-issuer roots, last successful refresh, last error, consecutive failures, and per-source attempt stats. |

`/verify-tbs` request:
```json
{
  "challenge_id": "<hex string>",
  "tbs_hash_bits": [0, 1, 0, 1, ...],
  "nullifier": "<string>"
}
```
`tbs_hash_bits` is 256 integers (0/1) in big-endian bit order, matching the circuit's `tbs_hash[256]` output.

`/link-verify` request (body limit 2MB):
```json
{
  "challenge_id": "<hex string>",
  "cert_chain_type": "rs2048",
  "cert_chain_proof": "<base64>",
  "device_sig_proof": "<base64>",
  "nullifier": "<string>"
}
```
`cert_chain_type` is `"rs2048"` (default) or `"rs4096"`. Both proof fields are binary, base64-encoded in JSON.

`/link-verify` response on success (HTTP 200):
```json
{
  "verified": true,
  "nullifier": "<subject_dn_hash hex>",
  "id_verified": true,
  "persisted": true,
  "public_signals": { "cert_chain": [...], "device_sig": [...] },
  "parsed_inputs": { "challenge": "...", "pk_commit": "...", "smt_root": "0x..." },
  "smt_root": {
    "issuer": "g2",
    "match": true,
    "expected": "0x9c70…",
    "observed": "0x9c70…",
    "trust_source": "onchain",
    "trusted_at": "2026-04-22T05:10:00Z"
  }
}
```

`/link-verify` response on SMT-root mismatch (HTTP 200 + `verified: false`, matching the existing `pk_commit`-mismatch pattern):
```json
{
  "verified": false,
  "reason": "smt_root_mismatch",
  "smt_root": {
    "issuer": "g2",
    "match": false,
    "expected": "0x9c70…",
    "observed": "0xabcd…",
    "trust_source": "onchain",
    "trusted_at": "2026-04-22T05:10:00Z"
  }
}
```
Nothing is written to the nullifier table on mismatch, and the challenge is not consumed — the client can retry with a fresh proof once their SMT inclusion path is rebuilt against the current root.

A successful verification atomically records `{nullifier, proof_type, challenge_id, verified_at}` and consumes the challenge. Re-using a challenge returns `410 Gone`; re-registering a nullifier returns `409 Conflict`.

### Revocation enforcement

Every valid cert-chain ZK proof carries an `smt_root` public input — the root of the revocation Sparse Merkle Tree the prover used to prove non-inclusion of their certificate's serial number. The circuit only proves consistency with *some* root; it cannot attest that the root is the *current, legitimate* one. Without a server-side check, a revoked certificate could keep verifying indefinitely by reusing a pre-revocation root.

This server fixes that by fetching the trusted root from [moven0831/moica-revocation-smt](https://github.com/moven0831/moica-revocation-smt) and hard-rejecting any proof whose `smt_root` does not match.

**Issuer mapping** — the proof's cert-chain variant selects the issuer:
- `cert_chain_type=rs2048` → `MOICA-G2`
- `cert_chain_type=rs4096` → `MOICA-G3`

**Dual source, onchain primary** — the provider tries the `SMTRootStorage.getRoot(bytes32 issuerId)` call on Arbitrum Sepolia first, falling back to parsing the `snapshot-latest` release body on GitHub when the RPC is unreachable. Both sources are polled on a refresh interval (default 10 min); the last known roots are retained if a refresh fails (stale-on-error, logged as `smt_root_fetch_failed`).

**Fail-closed startup** — when `SMT_ROOT_ENFORCE=strict` (the default), the server refuses to start if neither source can be reached at boot. Set `SMT_ROOT_ENFORCE=disabled` for local development with fixture proofs that reference a historical root — this bypasses the check entirely and should never be used in production.

**Operational observability** — `GET /smt-root/status` returns the in-memory cache including per-source attempt stats. Every fetch attempt emits a structured log line (`smt_root_fetch_start`, `smt_root_fetch_attempt`, `smt_root_refreshed`, `smt_root_fetch_failed`), and every `/link-verify` that consults the provider emits `smt_root_check` (or `smt_root_mismatch` at WARN level on reject). Example startup trace:

```
level=info event=smt_root_fetch_start trigger=startup
level=info event=smt_root_fetch_attempt trigger=startup source=onchain ok=true latency_ms=184
level=info event=smt_root_refreshed trigger=startup source=onchain g2=0x9c70… g3=0xc011… g2_changed=true g3_changed=true total_latency_ms=184
```

Example mismatch line (single WARN, one per rejected request):
```
level=warn event=smt_root_mismatch issuer=MOICA-G2 expected=0x9c70… observed=0xabcd… match=false trust_source=onchain cache_age_s=42
```

### gRPC service

`proto/zkid/v1/zkid.proto` defines the `ZkIDVerifier` service with five RPCs mirroring the REST surface:

- `CreateChallenge`, `GetChallenge`
- `VerifyTBS`, `LinkVerify`
- `GetVerificationStatus`

The gRPC server accepts messages up to 2MB (matching the HTTP body limit). The `LinkVerify` RPC applies the same SMT-root enforcement as the HTTP endpoint. On mismatch the response is `LinkVerifyResponse{verified: false, reason: "smt_root_mismatch", smt_root: <SmtRootOutcome>}` with no server-side error, matching the HTTP shape. On success the `smt_root` field is still populated so clients can log the trust source and freshness. Regenerate the `.pb.go` files after editing the proto:

```bash
make proto
```

### Example flow

```bash
# 1. Get a challenge
CHALLENGE=$(curl -s -X POST http://localhost:8080/challenge)
echo "$CHALLENGE" | jq .

# 2. (Client signs the challenge with their CDC card and generates ZK proofs)

# 3. Submit proofs
curl -s -X POST http://localhost:8080/link-verify \
  -H "Content-Type: application/json" \
  -d '{
    "challenge_id": "...",
    "cert_chain_type": "rs2048",
    "cert_chain_proof": "<base64>",
    "device_sig_proof": "<base64>",
    "nullifier": "..."
  }'

# 4. Query status
curl -s http://localhost:8080/users/<nullifier>/status
```

## Verifier CLI

`cmd/verifier` runs link-verify against proof files on disk. Useful for testing the FFI directly without the server.

```bash
make build-verifier

# Defaults to rs2048
DYLD_LIBRARY_PATH=./lib/aarch64-apple-darwin ./zkid-verifier         # macOS
LD_LIBRARY_PATH=./lib/x86_64-unknown-linux-gnu ./zkid-verifier       # Linux

# rs4096 variant
./zkid-verifier --cert-chain-4096
```

Reads from `$ZK_BASE_DIR/keys/` (defaults to the current directory):

- `cert_chain_rs{2048,4096}_proof.bin`
- `device_sig_rs2048_proof.bin`
- matching `*_verifying.key`

## Using the Go packages

```go
import (
    "context"
    "github.com/zkmopro/go-zkid-verifier/linkverify"
    "github.com/zkmopro/go-zkid-verifier/smtroot"
    "github.com/zkmopro/go-zkid-verifier/verifier"
)

// Recommended: construct a Verifier with an smtroot.Provider so the cert-chain
// proof's smt_root is checked against the current revocation-list root.
provider := smtroot.NewProvider(smtroot.Config{
    Primary:  smtroot.NewOnchainSource("", "", 5*time.Second),
    Fallback: smtroot.NewGitHubReleaseSource("", "", 5*time.Second),
})
if err := provider.FetchNow(context.Background(), "startup"); err != nil {
    log.Fatalf("startup fetch: %v", err)
}
provider.Start(context.Background())
defer provider.Stop()

v := linkverify.NewVerifier(keysDir, provider)
result, err := v.Verify(linkverify.Request{
    CertChainProof: ccBytes,
    DeviceSigProof: dsBytes,
    ProofType:      linkverify.ProofTypeRS2048,
})
// result.Verified, result.Parsed, result.SmtRoot.Match, result.Reason

// Pass nil instead of provider to disable SMT root enforcement (tests / local):
vNoEnforce := linkverify.NewVerifier(keysDir, nil)

// Low-level FFI: point at a directory containing keys/*.
valid, _, err := verifier.LinkVerify(baseDir, verifier.CertChainRS2048)
```

`linkverify.Verify` bounds concurrent ZK verifications via a semaphore (10 parallel) and writes proofs into a temp dir with symlinked verifying keys; the low-level `verifier.LinkVerify` expects the caller to lay out `keys/` itself.

## Makefile targets

| Target | Description |
|---|---|
| `make build` | Build both the server and the verifier CLI |
| `make build-server` | Build the server binary (`zkid-server`) |
| `make build-verifier` | Build the verifier CLI (`zkid-verifier`) |
| `make serve` | Build and run the server |
| `make verify` | Build and run the verifier CLI against `./keys/` |
| `make test` | Run all tests (challenge + verifier + linkverify) |
| `make test-challenge` | Test store + challenge packages |
| `make test-verifier` | Test the verifier FFI (requires keys + proofs in `$BASE_DIR/keys/`) |
| `make test-linkverify` | Test the high-level link-verify orchestration |
| `make download-keys` | Download verifying keys from the zkID GitHub release |
| `make proto` | Regenerate gRPC/protobuf Go files |
| `make clean` | Remove build artifacts |

The Makefile auto-detects OS/arch via `uname`, sets `RUST_TARGET`, and chooses `DYLD_LIBRARY_PATH` (macOS) or `LD_LIBRARY_PATH` (Linux).

## CI

`.github/workflows/ci.yml` runs two jobs on every push / PR to `main`:

**`challenge-server`** (Linux, no CGO): tests the pure-Go `store/` package with `CGO_ENABLED=0`.

**`verifier`** (macOS + Linux matrix):
1. Clones `zkID` at a pinned commit as a sibling (see `.github/workflows/ci.yml` for the exact SHA)
2. Installs Rust and the Linux C++ toolchain as needed
3. Caches `~/.cargo` and `rust/target`
4. Builds the Rust library + Go binaries (`make build`)
5. Downloads verifying keys (`make download-keys`)
6. Runs `challenge/` and `linkverify/` tests
7. Runs the FFI test twice — once with RS2048 fixtures, once with RS4096 — using proofs checked in under `tests/artifacts/`

The `smtroot/` package tests and the `linkverify/verifier_test.go` suite are CGO-free and exercise the Verifier with an injected static `smtroot.Provider` — they do not reach any live RPC or GitHub endpoint. This keeps CI deterministic and independent of Arbitrum Sepolia / upstream release availability.

## Project layout

```
.
├── cmd/
│   ├── server/main.go              # REST + gRPC server entry point
│   └── verifier/main.go            # Link-verify CLI
├── challenge/                      # HTTP handlers + TBS-hash helpers
│   ├── challenge.go
│   ├── handler.go
│   └── challenge_test.go
├── grpc/server.go                  # gRPC service implementation
├── linkverify/                     # High-level link-verify orchestrator (temp dirs, semaphore, SMT root enforcement)
│   ├── linkverify.go
│   ├── verifier.go                 # Verifier struct — FFI + parse + smt_root check
│   ├── errors.go
│   ├── verifier_test.go
│   └── linkverify_test.go
├── smtroot/                        # Trusted SMT root cache (onchain + GitHub release)
│   ├── smtroot.go                  # Provider, Status, IssuerID, Root
│   ├── onchain.go                  # Arbitrum Sepolia JSON-RPC eth_call
│   ├── github.go                   # GitHub Releases body parser (fallback)
│   ├── refresh.go                  # Background refresher + structured logs
│   ├── log.go                      # Logger interface + DefaultLogger
│   └── smtroot_test.go
├── verifier/                       # CGO FFI bindings
│   ├── verifier.go
│   ├── public_inputs.go            # Parse cert_chain + device_sig public signals
│   └── verifier_test.go
├── store/                          # Challenge + verification persistence
│   ├── store.go                    # Store interface + sentinel errors
│   ├── sqlite.go                   # modernc.org/sqlite implementation (pure Go)
│   └── sqlite_test.go
├── keymanager/keymanager.go        # Auto-download verifying keys from GitHub release
├── proto/zkid/v1/
│   ├── zkid.proto                  # gRPC service definition
│   ├── zkid.pb.go                  # generated
│   └── zkid_grpc.pb.go             # generated
├── rust/
│   ├── Cargo.toml                  # Path dep: ../../zkID/wallet-unit-poc/ecdsa-spartan2
│   ├── Cross.toml                  # cross config with nasm + libgmp-dev
│   └── src/lib.rs                  # C FFI: zk_link_verify, zk_last_error
├── lib/                            # Native libraries (gitignored)
│   ├── aarch64-apple-darwin/
│   │   ├── libzk_verifier.a
│   │   └── libwitnesscalc_rs256.dylib
│   └── x86_64-unknown-linux-gnu/
│       ├── libzk_verifier.a
│       └── libwitnesscalc_rs256.so
├── keys/                           # Verifying keys (gitignored, auto-downloaded)
│   ├── cert_chain_rs2048_verifying.key
│   ├── cert_chain_rs4096_verifying.key
│   └── device_sig_rs2048_verifying.key
├── tests/artifacts/                # Test proof fixtures (checked in)
│   ├── cc2048_ds2048/
│   └── cc4096_ds2048/
├── scripts/download_keys.sh
├── Makefile
└── .github/workflows/ci.yml
```
