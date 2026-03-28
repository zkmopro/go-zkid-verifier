# go-zkid-verifier

A Go package that verifies RS256 JWT zero-knowledge proofs via Rust FFI. The ZK proof system is built on [Spartan2](https://github.com/therealyingtong/Spartan2.git) using the Hyrax polynomial commitment scheme, with the circuit implementation from [zkID](https://github.com/zkmopro/zkID).

## Architecture

```
Go (verifier package)
  └── CGO → lib/<target>/libzk_verifier.a (Rust staticlib)
                └── ecdsa-spartan2 (Spartan2 ZK circuit)
                      └── lib/<target>/libwitnesscalc_rs256.{dylib,so} (C++ witness generator)
```

The Rust layer exposes a C-compatible FFI that Go calls via CGO. The verifier reads pre-generated proof artifacts from a `keys/` directory and verifies them using Spartan2's ZK-SNARK verifier.

CGO selects the correct library directory per platform at compile time:

| Platform | CGO tag | Library directory |
|---|---|---|
| macOS Apple Silicon | `darwin,arm64` | `lib/aarch64-apple-darwin/` |
| Linux x86_64 | `linux` | `lib/x86_64-unknown-linux-gnu/` |

## Prerequisites

**Challenge server only:** Go 1.22+ (no Rust or native toolchain needed).

**Full build (including ZK verifier):**

- Go 1.22+
- Rust (stable)
- macOS or Linux
  - macOS: Xcode Command Line Tools (`xcode-select --install`)
  - Linux: `g++`, `libstdc++`, `nasm`, `libgmp-dev`
    ```bash
    sudo apt-get install -y g++ libstdc++-12-dev nasm libgmp-dev
    ```

## Setup

### 1. Clone dependencies

Both this repo and [zkID](https://github.com/zkmopro/zkID) must be checked out as siblings (only needed for the verifier):

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
# Challenge server only (no Rust required)
make build-server

# Verifier only (requires Rust + native libs)
make build-verifier

# Both
make build
```

Detects the current platform, runs `cargo build --release`, and copies artifacts into `lib/<target>/`:

- macOS arm64 → `lib/aarch64-apple-darwin/`
- Linux x86_64 → `lib/x86_64-unknown-linux-gnu/`

**Cross-compile for Linux from macOS** (requires Docker):

```bash
# Install tools (once)
cargo install cross --git https://github.com/cross-rs/cross

# Build — mounts the zkID directory into the cross container
CROSS_CONTAINER_OPTS="-v /path/to/zkID:/path/to/zkID" \
  cross build --target x86_64-unknown-linux-gnu --release

# Copy artifacts
mkdir -p lib/x86_64-unknown-linux-gnu
cp rust/target/x86_64-unknown-linux-gnu/release/libzk_verifier.a lib/x86_64-unknown-linux-gnu/
cp $(find rust/target/x86_64-unknown-linux-gnu/release/build -name "libwitnesscalc_rs256.so" -path "*/package/lib/*" | head -1) lib/x86_64-unknown-linux-gnu/
```

`rust/Cross.toml` configures the cross-compilation container with `nasm` and `libgmp-dev` pre-installed.

### 3. Download the verifying key

```bash
make download-keys
```

Downloads `keys/rs256_verifying.key` from Cloudflare R2.

## Challenge Server

The challenge server generates random nonces for the ZK identity verification flow. A client fetches a challenge, signs it with their CDC card via HiPKI, generates a ZK proof, and submits the proof back for verification.

### Start the server

```bash
make serve
# or directly:
go run ./cmd/server
# with custom port:
PORT=9090 go run ./cmd/server
```

### API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `POST /challenge` | Generate a 32-byte random challenge nonce | Returns `{challenge_id, challenge_bytes, expires_at}` |
| `GET /challenge/{id}` | Retrieve a challenge by ID | 404 if expired (5-min TTL) or not found |
| `POST /verify` | Verify proof against a challenge | Compares `tbs_hash_bits` against `SHA256(challenge_bytes)` |

### Verify endpoint

The `/verify` endpoint accepts:
```json
{
  "challenge_id": "<hex string>",
  "tbs_hash_bits": [0, 1, 0, 1, ...],
  "nullifier": "<string>"
}
```

`tbs_hash_bits` is a 256-element array of 0/1 integers representing the SHA-256 hash in big-endian bit order (matching the circuit's `tbs_hash[256]` output). The server reconstructs the SHA-256 digest from these bits and compares against `SHA256(challenge_bytes)`.

### Example flow

```bash
# 1. Get a challenge
CHALLENGE=$(curl -s -X POST http://localhost:8080/challenge)
echo $CHALLENGE | jq .

# 2. (Client signs challenge with HiPKI, generates ZK proof)

# 3. Submit proof for verification
curl -s -X POST http://localhost:8080/verify \
  -H "Content-Type: application/json" \
  -d '{"challenge_id":"...", "tbs_hash_bits":[...], "nullifier":"..."}'
```

## Proof Verification

### As a Go package

```go
import "github.com/zkmopro/go-zkid-verifier/verifier"

// baseDir must contain:
//   keys/rs256_proof.bin
//   keys/rs256_verifying.key
valid, err := verifier.Verify(baseDir)
```

### CLI

```bash
# Build
make build-verifier

# Run from the directory containing keys/
# macOS
DYLD_LIBRARY_PATH=./lib/aarch64-apple-darwin ./zkid-verifier

# Linux
LD_LIBRARY_PATH=./lib/x86_64-unknown-linux-gnu ./zkid-verifier
```

## Makefile targets

| Target | Description |
|---|---|
| `make build` | Build both server and verifier |
| `make build-server` | Build challenge server (Go only, no Rust needed) |
| `make build-verifier` | Build Rust library + verifier binary |
| `make serve` | Build and run the challenge server |
| `make test` | Run all tests |
| `make test-challenge` | Run challenge server tests (Go only) |
| `make test-verifier` | Run verifier tests (requires Rust libs + keys) |
| `make download-keys` | Download verifying key from R2 into `keys/` |
| `make verify` | Build and run the verifier against `./keys/` |
| `make clean` | Remove build artifacts |

The Makefile auto-detects the OS and architecture via `uname -s`/`uname -m`, sets the correct `RUST_TARGET`, and uses `DYLD_LIBRARY_PATH` (macOS) or `LD_LIBRARY_PATH` (Linux).

## CI

GitHub Actions runs two independent jobs on every push and pull request to `main`:

**Challenge server** (Go only, fast):
1. Installs Go
2. Builds the challenge server (`make build-server`)
3. Runs challenge tests (`make test-challenge`)

**Verifier** (macOS + Linux matrix):
1. Checks out this repo and clones `zkID` at commit `cc21edd` as siblings
2. Installs `g++`, `nasm`, `libgmp-dev` on Linux
3. Builds the verifier (`make build-verifier`)
4. Downloads the verifying key from R2 (`make download-keys`)
5. Runs verifier tests (`make test-verifier`)
6. Runs the verifier (`make verify`)

## Project structure

```
.
├── cmd/
│   ├── server/main.go              # Challenge server entry point (pure Go)
│   └── verifier/main.go            # ZK verifier CLI entry point (CGO)
├── challenge/
│   ├── challenge.go                # Challenge store + TBS hash verification
│   ├── challenge_test.go
│   └── handler.go                  # HTTP handlers
├── verifier/
│   ├── verifier.go                 # CGO bindings (per-platform -L flags)
│   └── verifier_test.go
├── lib/
│   ├── aarch64-apple-darwin/       # macOS Apple Silicon (gitignored)
│   │   ├── libzk_verifier.a
│   │   └── libwitnesscalc_rs256.dylib
│   └── x86_64-unknown-linux-gnu/   # Linux x86_64 (gitignored)
│       ├── libzk_verifier.a
│       └── libwitnesscalc_rs256.so
├── keys/                           # Proof artifacts (gitignored)
│   ├── rs256_proof.bin
│   └── rs256_verifying.key
├── rust/
│   ├── Cargo.toml                  # Path dep: ../../zkID/wallet-unit-poc/ecdsa-spartan2
│   ├── Cross.toml                  # cross config: nasm + libgmp-dev pre-build
│   └── src/lib.rs                  # C FFI: zk_rs256_verify, zk_last_error
├── scripts/
│   └── download_keys.sh            # Downloads verifying key from R2
└── .github/workflows/ci.yml
```
