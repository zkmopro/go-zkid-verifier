# go-zkid-verifier

A Go server that issues challenges and verifies zero-knowledge proofs of identity from a CDC card, over REST and gRPC. Proofs are produced by the [zkID](https://github.com/zkmopro/zkID) circuits on top of [Spartan2](https://github.com/therealyingtong/Spartan2.git) with Hyrax commitments.

Every verification checks two ZK proofs in one call — a **cert-chain** proof (RSA-2048 or RSA-4096) and a **device-signature** proof (RSA-2048) — and enforces that (a) both carry the same `pk_commit` and (b) the cert-chain proof's `smt_root` matches the current revocation-list root published by [moica-revocation-smt](https://github.com/moven0831/moica-revocation-smt) (Arbitrum Sepolia onchain, GitHub release as fallback).

## Quickstart

```bash
# Clone this repo and zkID as siblings
git clone https://github.com/zkmopro/go-zkid-verifier.git
git clone https://github.com/zkmopro/zkID.git
cd go-zkid-verifier

# Build (Rust + Go) and run. Verifying keys auto-download on first boot.
make serve
```

Server boots on `:8080` (HTTP) and `:9090` (gRPC). Hit it:

```bash
curl -X POST http://localhost:8080/challenge | jq .
```

## Prerequisites

- Go 1.25+
- Rust (stable)
- macOS or Linux
  - macOS: `xcode-select --install`
  - Linux: `sudo apt-get install -y g++ libstdc++-12-dev nasm libgmp-dev`
- `protoc` — only if you regenerate `.pb.go` via `make proto`

## How it works

```
Go server (cmd/server)
├── HTTP (:8080) ── /challenge, /link-verify, /smt-root/status
├── gRPC (:9090) ── ZkIDVerifier service (same surface as HTTP)
├── SQLite       ── challenges + verification records (pure-Go driver)
├── smtroot/     ── trusted revocation-list root cache
└── verifier/    ── CGO → lib/<target>/libzk_verifier.a (Rust)
                          └── ecdsa-spartan2 ZK circuit
                                └── lib/<target>/libwitnesscalc_rs256.{dylib,so}
```

The Rust static lib is selected by CGO per platform:

| Platform | Library directory |
|---|---|
| macOS Apple Silicon | `lib/aarch64-apple-darwin/` |
| Linux x86_64 | `lib/x86_64-unknown-linux-gnu/` |

### Revocation enforcement

Each cert-chain proof carries an `smt_root` public input — the revocation SMT root the prover used to prove non-inclusion. The circuit proves consistency with *some* root, not that it's the current one; without a server-side check, a revoked certificate could keep verifying forever by reusing a pre-revocation root.

The server fetches the trusted root per issuer (RS2048 → MOICA-G2, RS4096 → MOICA-G3) and rejects any mismatched proof. Sources, in order: `SMTRootStorage.getRoot(bytes32)` on Arbitrum Sepolia (primary), the `snapshot-latest` GitHub release body (fallback). Both refresh on `SMT_ROOT_REFRESH_INTERVAL` (default 10 min); the last known roots are retained on a failed refresh.

**Startup is fail-closed.** If neither source responds at boot, the server refuses to start. Set `SMT_ROOT_ENFORCE=disabled` to skip the check entirely — local dev only.

## Configuration

All configuration is via environment variables:

| Variable | Default | Description |
|---|---|---|
| `PORT` | `8080` | HTTP listen port |
| `GRPC_PORT` | `9090` | gRPC listen port |
| `DB_PATH` | `./zkid.db` | SQLite database path |
| `KEYS_DIR` | `./keys` | Directory holding verifying keys |
| `CORS_ORIGIN` | `*` | `Access-Control-Allow-Origin` |
| `SMT_ROOT_ENFORCE` | `strict` | `strict` = hard-fail on mismatch; `disabled` = skip the SMT root check (dev only) |
| `SMT_ROOT_RPC_URL` | `https://sepolia-rollup.arbitrum.io/rpc` | Arbitrum Sepolia JSON-RPC |
| `SMT_ROOT_CONTRACT` | `0xc461326eb6e46F10A276B0F14BFFf8b256A43FFA` | `SMTRootStorage` address |
| `SMT_ROOT_GITHUB_REPO` | `moven0831/moica-revocation-smt` | Fallback repo |
| `SMT_ROOT_GITHUB_TAG` | `snapshot-latest` | Fallback release tag |
| `SMT_ROOT_REFRESH_INTERVAL` | `10m` | Background refresh cadence |
| `SMT_ROOT_FETCH_TIMEOUT` | `5s` | Per-source fetch timeout |

## HTTP API

| Method | Path | Description |
|---|---|---|
| `POST` | `/challenge` | Issue a 16-byte challenge. Returns `{challenge_id, challenge_bytes, expires_at}`. TTL 5 min. |
| `GET` | `/challenge/{id}` | Fetch a challenge by ID. `404` if missing, `400` if expired. |
| `POST` | `/link-verify` | Verify a cert-chain + device-sig proof pair, check `pk_commit` linkage and `smt_root`. Body limit 2 MB. |
| `GET` | `/smt-root/status` | Trusted-root cache snapshot (source, per-issuer roots, refresh stats). |

### `/link-verify`

Request — the server extracts both the challenge and the nullifier from the proof's public signals, so they are **not** part of the request body:

```json
{
  "cert_chain_type": "rs2048",
  "cert_chain_proof": "<base64>",
  "device_sig_proof": "<base64>"
}
```

`cert_chain_type` is `"rs2048"` (default) or `"rs4096"`. Both proofs are binary, base64-encoded in JSON.

Success response (HTTP 200):

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

On SMT root mismatch (HTTP 409 Conflict — the proof's root disagrees with the current trusted root, likely because the client is stale):

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

A proof-invalid failure (cert-chain or device-sig rejected by the circuit) returns HTTP 200 with `verified: false` and `reason: "proof_invalid"` — the pipeline ran to completion, the proof just didn't pass. If the server can't fetch a trusted root for the issuer (startup incomplete or all sources failing), `/link-verify` returns HTTP 503 so the client retries rather than interpreting a transient outage as a bad proof.

Nothing is written on a non-success outcome and the challenge is **not** consumed — the client can retry once the underlying issue is resolved. A successful verify atomically records `{nullifier, proof_type, challenge_id, verified_at}` and consumes the challenge. Reusing a challenge returns `410 Gone`; reusing a nullifier returns `409 Conflict`.

### Example

```bash
# 1. Get a challenge
curl -s -X POST http://localhost:8080/challenge | jq .

# 2. Client signs the challenge on a CDC card and generates both ZK proofs.

# 3. Submit proofs
curl -s -X POST http://localhost:8080/link-verify \
  -H "Content-Type: application/json" \
  -d '{
    "cert_chain_type": "rs2048",
    "cert_chain_proof": "<base64>",
    "device_sig_proof": "<base64>"
  }' | jq .
```

## gRPC API

`proto/zkid/v1/zkid.proto` defines the `ZkIDVerifier` service with three RPCs:

- `CreateChallenge` / `GetChallenge` — same semantics as their HTTP counterparts.
- `LinkVerify` — same enforcement as HTTP (`pk_commit` linkage + `smt_root` check), including the `"smt_root_mismatch"` fail mode. The server accepts messages up to 2 MB.

Regenerate `.pb.go` after editing the proto:

```bash
make proto
```

## Using the Go packages

```go
import (
    "context"
    "time"

    "github.com/zkmopro/go-zkid-verifier/linkverify"
    "github.com/zkmopro/go-zkid-verifier/smtroot"
    "github.com/zkmopro/go-zkid-verifier/verifier"
)

// Production path: build an smtroot.Provider so the cert-chain proof's
// smt_root is enforced against the current revocation root.
provider := smtroot.NewProvider(smtroot.Config{
    Primary:  smtroot.NewOnchainSource("", "", 5*time.Second),
    Fallback: smtroot.NewGitHubReleaseSource("", "", 5*time.Second),
})
if err := provider.FetchNow(context.Background(), "startup"); err != nil {
    log.Fatalf("startup fetch: %v", err)
}
provider.Start(context.Background())
defer provider.Stop()

v := &linkverify.Verifier{
    KeysDir: keysDir,
    SmtRoot: provider,
    Logger:  smtroot.DefaultLogger{},
}
result, err := v.Verify(linkverify.Request{
    CertChainProof: ccBytes,
    DeviceSigProof: dsBytes,
    ProofType:      linkverify.ProofTypeRS2048,
})
// result.Verified, result.Parsed, result.SmtRoot.Match, result.Reason
```

`linkverify.Service` is the transport-agnostic orchestrator that both HTTP and gRPC call — it runs verify → challenge lookup → expiry check → record atomically and maps the two transport semantics:

```go
service := linkverify.NewService(v, sqliteStore)

// HTTP path — challenge and nullifier derived from the proof:
res, err := service.VerifyAndRecordByProof(ctx, linkverify.Request{...})

// gRPC path — caller supplies challenge ID and nullifier:
res, err := service.VerifyAndRecordByID(ctx, challengeID, nullifier, linkverify.Request{...})
```

Store sentinels (`ErrChallengeNotFound`, `ErrChallengeExpired`, `ErrChallengeConsumed`, `ErrDuplicateNullifier`) and `linkverify.ErrSmtRootUnavailable` bubble unwrapped so each transport picks its own status code.

For tests and local dev with historical fixtures, leave `SmtRoot: nil` — SMT root enforcement is skipped. The low-level `verifier.LinkVerify(baseDir, verifier.CertChainRS2048)` is also available if you want to manage the `keys/` directory yourself.

`linkverify.Verify` caps concurrent ZK verifications at 10 (semaphore) and stages each proof in a temp dir with symlinked verifying keys.

## Verifier CLI

`cmd/verifier` runs link-verify against proof files on disk — handy for testing the FFI without a server:

```bash
make build-verifier

# macOS, defaults to rs2048
DYLD_LIBRARY_PATH=./lib/aarch64-apple-darwin ./zkid-verifier

# Linux
LD_LIBRARY_PATH=./lib/x86_64-unknown-linux-gnu ./zkid-verifier

# rs4096 variant
./zkid-verifier --cert-chain-4096
```

Reads from `$ZK_BASE_DIR/keys/` (defaults to `.`): `cert_chain_rs{2048,4096}_proof.bin`, `device_sig_rs2048_proof.bin`, and the matching `*_verifying.key`.

## Development

| Target | Description |
|---|---|
| `make build` | Build the server and the verifier CLI |
| `make build-server` | Build `zkid-server` |
| `make build-verifier` | Build `zkid-verifier` |
| `make serve` | Build and run the server |
| `make verify` | Build and run the verifier CLI against `./keys/` |
| `make test` | All tests (challenge + verifier + linkverify) |
| `make test-challenge` | Store + challenge package tests |
| `make test-verifier` | Verifier FFI tests (needs keys + proofs under `$BASE_DIR/keys/`) |
| `make test-linkverify` | Link-verify orchestration tests |
| `make download-keys` | Download verifying keys from the zkID GitHub release |
| `make proto` | Regenerate gRPC / protobuf Go files |
| `make clean` | Remove build artifacts |

The Makefile auto-detects OS/arch and sets `RUST_TARGET` + `DYLD_LIBRARY_PATH`/`LD_LIBRARY_PATH` accordingly.

### CI

`.github/workflows/ci.yml` has two jobs on every push / PR to `main`: a pure-Go `challenge-server` job that tests `./store/` with `CGO_ENABLED=0`, and a `verifier` matrix (macOS + Linux) that clones zkID at a pinned commit, builds the Rust lib + Go binaries, downloads verifying keys, and runs the full test suite including the RS2048 and RS4096 FFI fixture tests from `tests/artifacts/`. The `smtroot/` tests and `linkverify/verifier_test.go` use an injected static `smtroot.Provider` — they never reach a live RPC or GitHub endpoint, keeping CI deterministic.

### Cross-compile for Linux from macOS

Requires Docker:

```bash
cargo install cross --git https://github.com/cross-rs/cross

CROSS_CONTAINER_OPTS="-v /path/to/zkID:/path/to/zkID" \
  cross build --target x86_64-unknown-linux-gnu --release

mkdir -p lib/x86_64-unknown-linux-gnu
cp rust/target/x86_64-unknown-linux-gnu/release/libzk_verifier.a lib/x86_64-unknown-linux-gnu/
cp $(find rust/target/x86_64-unknown-linux-gnu/release/build -name "libwitnesscalc_rs256.so" -path "*/package/lib/*" | head -1) \
   lib/x86_64-unknown-linux-gnu/
```

`rust/Cross.toml` pre-installs `nasm` and `libgmp-dev` in the container.

## Project layout

`httpapi/` owns all HTTP transport; `grpc/` and `httpapi/` both call into `linkverify.Service` for the shared verify → lookup → record flow.

```
.
├── cmd/
│   ├── server/main.go          # REST + gRPC server (wires Service + Router)
│   └── verifier/main.go        # Link-verify CLI
├── challenge/challenge.go      # Challenge-domain constants (DefaultTTL)
├── httpapi/                    # HTTP transport
│   ├── router.go               # NewRouter(service, store, provider) http.Handler
│   ├── challenge.go            # /challenge CRUD handlers
│   ├── linkverify.go           # /link-verify handler (409 on smt_root_mismatch, 503 on provider unavailable)
│   ├── smtroot.go              # /smt-root/status handler
│   ├── dto.go                  # LinkVerifyRequest + Verify{Success,Fail}Response
│   └── errors.go               # jsonError, writeStoreError
├── grpc/server.go              # Thin gRPC adapter over linkverify.Service
├── linkverify/                 # High-level link-verify orchestrator
│   ├── linkverify.go           # FFI wrapper, bounded concurrency, ParseProofType
│   ├── verifier.go             # Verifier struct: FFI + parse + smt_root check
│   ├── service.go              # Service: verify → lookup → record (HTTP + gRPC share this)
│   └── errors.go               # ErrSmtRootUnavailable + Reason constants
├── smtroot/                    # Trusted SMT root cache (onchain + GitHub release)
│   ├── smtroot.go              # Provider, Status, IssuerID, Root
│   ├── onchain.go              # Arbitrum Sepolia JSON-RPC eth_call
│   ├── github.go               # GitHub Releases body parser (fallback)
│   ├── refresh.go              # Background refresher + structured logs
│   └── log.go                  # Logger interface + DefaultLogger
├── verifier/                   # CGO FFI bindings
│   ├── verifier.go
│   └── public_inputs.go        # Parse cert_chain + device_sig public signals
├── store/                      # Challenge + verification persistence (pure Go)
│   ├── store.go                # Store interface + sentinel errors
│   └── sqlite.go               # modernc.org/sqlite implementation
├── keymanager/keymanager.go    # Auto-download verifying keys
├── proto/zkid/v1/              # zkid.proto + generated *.pb.go files
├── rust/                       # Cargo.toml (path dep on ../../zkID), Cross.toml, src/lib.rs
├── lib/                        # Native libraries per target (gitignored)
├── keys/                       # Verifying keys (gitignored, auto-downloaded)
├── tests/artifacts/            # Proof fixtures for RS2048 + RS4096
├── scripts/download_keys.sh
├── Makefile
└── .github/workflows/ci.yml
```
