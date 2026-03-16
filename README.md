# go-zkid-verifier

A Go package that verifies RS256 JWT zero-knowledge proofs via Rust FFI. The ZK proof system is built on [Spartan2](https://github.com/therealyingtong/Spartan2.git) using the Hyrax polynomial commitment scheme, with the circuit implementation from [zkID](https://github.com/zkmopro/zkID).

## Architecture

```
Go (verifier package)
  └── CGO → libzk_verifier.a (Rust staticlib)
               └── ecdsa-spartan2 (Spartan2 ZK circuit)
                     └── libwitnesscalc_rs256.{dylib,so} (C++ witness generator)
```

The Rust layer exposes a C-compatible FFI that Go calls via CGO. The verifier reads pre-generated proof artifacts from a `keys/` directory and verifies them using Spartan2's ZK-SNARK verifier.

## Prerequisites

- Go 1.22+
- Rust (stable)
- macOS or Linux (amd64 / arm64)
  - macOS: Xcode Command Line Tools (`xcode-select --install`)
  - Linux: `g++` and `libstdc++` (`sudo apt-get install -y g++ libstdc++-12-dev`)

The `lib/` directory must contain:
- `libzk_verifier.a` — built from `rust/`
- `libwitnesscalc_rs256.dylib` (macOS) or `libwitnesscalc_rs256.so` (Linux) — built as a side effect of the Rust build

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

This runs `cargo build --release` and copies `libzk_verifier.a` and `libwitnesscalc_rs256.{dylib,so}` into `lib/`.

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
# macOS — run from the directory containing keys/
DYLD_LIBRARY_PATH=./lib ./zk-verifier

# Linux
LD_LIBRARY_PATH=./lib ./zk-verifier
```

## Makefile targets

| Target | Description |
|---|---|
| `make build` | Build Rust library + Go binary |
| `make download-keys` | Download verifying key from R2 into `keys/` |
| `make verify` | Run the verifier against `./keys/` |
| `make test` | Run Go tests |
| `make clean` | Remove build artifacts |

The Makefile auto-detects the OS and sets `DYLD_LIBRARY_PATH` (macOS) or `LD_LIBRARY_PATH` (Linux) and the correct shared library extension (`.dylib` / `.so`).

## CI

GitHub Actions runs on both `macos-latest` and `ubuntu-latest` on every push and pull request to `main`:

1. Checks out this repo and clones `zkID` at commit `cc21edd` as siblings
2. Installs `g++` / `libstdc++` on Linux
3. Builds the Rust static library and Go binary (`make build`)
4. Downloads the verifying key from R2 (`make download-keys`)
5. Runs the test suite (`make test`)
6. Runs the verifier (`make verify`)

## Project structure

```
.
├── lib/                        # Built libraries (gitignored, populated by make build)
│   ├── libzk_verifier.a
│   └── libwitnesscalc_rs256.{dylib,so}
├── keys/                       # Proof artifacts (gitignored, populated by make download-keys)
│   ├── rs256_proof.bin
│   └── rs256_verifying.key
├── rust/                       # Rust FFI wrapper
│   ├── Cargo.toml              # Depends on ecdsa-spartan2 via path (../../zkID/...)
│   └── src/lib.rs              # C-compatible FFI: zk_rs256_verify, zk_last_error
├── verifier/                   # Go package
│   ├── verifier.go             # CGO bindings (platform-specific: -lc++ / -lstdc++)
│   └── verifier_test.go
├── scripts/
│   └── download_keys.sh        # Downloads verifying key from R2
├── main.go                     # CLI entry point
└── .github/workflows/ci.yml
```
