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

### 2. Build the Rust library

```bash
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

## Usage

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
# Run from the directory containing keys/
# macOS
DYLD_LIBRARY_PATH=./lib/aarch64-apple-darwin ./zk-verifier

# Linux
LD_LIBRARY_PATH=./lib/x86_64-unknown-linux-gnu ./zk-verifier
```

## Makefile targets

| Target | Description |
|---|---|
| `make build` | Build Rust library + Go binary for current platform |
| `make download-keys` | Download verifying key from R2 into `keys/` |
| `make verify` | Run the verifier against `./keys/` |
| `make test` | Run Go tests |
| `make clean` | Remove build artifacts |

The Makefile auto-detects the OS and architecture via `uname -s`/`uname -m`, sets the correct `RUST_TARGET`, and uses `DYLD_LIBRARY_PATH` (macOS) or `LD_LIBRARY_PATH` (Linux).

## CI

GitHub Actions runs on both `macos-latest` and `ubuntu-latest` on every push and pull request to `main`:

1. Checks out this repo and clones `zkID` at commit `cc21edd` as siblings
2. Installs `g++`, `nasm`, `libgmp-dev` on Linux
3. Builds the Rust static library and Go binary (`make build`)
4. Downloads the verifying key from R2 (`make download-keys`)
5. Runs the test suite (`make test`)
6. Runs the verifier (`make verify`)

## Project structure

```
.
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
├── verifier/
│   ├── verifier.go                 # CGO bindings (per-platform -L flags)
│   └── verifier_test.go
├── scripts/
│   └── download_keys.sh            # Downloads verifying key from R2
├── main.go
└── .github/workflows/ci.yml
```
