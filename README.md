# go-zkid-verifier

A Go server that issues challenges and verifies zero-knowledge proofs of identity from a CDC card over both REST and gRPC. The ZK proof system is built on [Spartan2](https://github.com/therealyingtong/Spartan2.git) using the Hyrax polynomial commitment scheme, with circuits from [zkID](https://github.com/zkmopro/zkID).

Link-verify checks two independent ZK proofs — a **cert-chain** proof (RSA-2048 or RSA-4096) and a **device-signature** proof (RSA-2048) — and enforces that both proofs share the same `pk_commit` (i.e. both reference the same device public key).

## Architecture

```
Go server (cmd/server)
├── HTTP (:8080) ─ challenge, verify-tbs, link-verify, status
├── gRPC (:9090) ─ ZkIDVerifier service
├── SQLite       ─ challenges + verification records (modernc.org/sqlite, pure Go)
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

### REST endpoints

| Method | Path | Description |
|---|---|---|
| `POST` | `/challenge` | Issue a new 16-byte challenge. Returns `{challenge_id, challenge_bytes, expires_at}` (5-minute TTL). |
| `GET` | `/challenge/{id}` | Retrieve a challenge by ID. 404 if not found, 400 if expired. |
| `POST` | `/verify-tbs` | Verify a 256-bit TBS hash against the challenge's `SHA256(challenge_bytes)`. Records the verification. |
| `POST` | `/link-verify` | Verify cert-chain + device-sig ZK proofs and their `pk_commit` linkage. Records the verification. |
| `GET` | `/users/{nullifier}/status` | Return the persisted verification record for a nullifier. |

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

A successful verification atomically records `{nullifier, proof_type, challenge_id, verified_at}` and consumes the challenge. Re-using a challenge returns `410 Gone`; re-registering a nullifier returns `409 Conflict`.

### gRPC service

`proto/zkid/v1/zkid.proto` defines the `ZkIDVerifier` service with five RPCs mirroring the REST surface:

- `CreateChallenge`, `GetChallenge`
- `VerifyTBS`, `LinkVerify`
- `GetVerificationStatus`

The gRPC server accepts messages up to 2MB (matching the HTTP body limit). Regenerate the `.pb.go` files after editing the proto:

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
    "github.com/zkmopro/go-zkid-verifier/linkverify"
    "github.com/zkmopro/go-zkid-verifier/verifier"
)

// High-level: feed proof bytes, get a verified bool.
valid, err := linkverify.Verify(linkverify.Request{
    CertChainProof: ccBytes,
    DeviceSigProof: dsBytes,
    ProofType:      linkverify.ProofTypeRS2048,
}, keysDir)

// Low-level FFI: point at a directory containing keys/*.
valid, err = verifier.LinkVerify(baseDir, verifier.CertChainRS2048)
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
1. Clones `zkID` at commit `c6652de9…` as a sibling (pinned for reproducibility)
2. Installs Rust and the Linux C++ toolchain as needed
3. Caches `~/.cargo` and `rust/target`
4. Builds the Rust library + Go binaries (`make build`)
5. Downloads verifying keys (`make download-keys`)
6. Runs `challenge/` and `linkverify/` tests
7. Runs the FFI test twice — once with RS2048 fixtures, once with RS4096 — using proofs checked in under `tests/artifacts/`

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
├── linkverify/                     # High-level link-verify orchestrator (temp dirs, semaphore)
│   ├── linkverify.go
│   └── linkverify_test.go
├── verifier/                       # CGO FFI bindings
│   ├── verifier.go
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
