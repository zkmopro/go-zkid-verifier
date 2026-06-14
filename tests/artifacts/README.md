# Test fixtures

`cc{2048,4096}_us2048/*.bin` are spartan2 proof binaries paired with the verifying keys auto-downloaded by `keymanager` from the [zkID `RSA-X.509-Cert-latest` release](https://github.com/privacy-ethereum/zkID/releases/tag/RSA-X.509-Cert-latest). Whenever the cert-chain or user-sig circuit changes (and the upstream release is rebuilt) the fixtures must be regenerated against the new keys, otherwise integration tests fail loudly with a public-input count mismatch.

## Regenerating

```bash
# 1. Make sure circom + node + yarn + cargo are installed.
git clone https://github.com/privacy-ethereum/zkID.git ../../zkID
git -C ../../zkID checkout RSA-X.509-Cert

# 2. Recompile the circuits (writes R1CS + wasm + cpp under wallet-unit-poc/circom/build/).
cd ../../zkID/wallet-unit-poc/circom
yarn install
yarn compile:all

# 3. Generate split inputs (RSA-2048 issuer + RSA-2048 user).
cd ../ecdsa-spartan2
RUST_LOG=info cargo run --release -- generate-split-input

# 4. Setup + prove cert-chain RS2048 and user-sig RS2048.
cargo run --release --features cert_chain_rs2048 -- cert-chain setup --input ../circom/inputs/cert_chain_rs2048/input.json
cargo run --release --features cert_chain_rs2048 -- cert-chain prove --input ../circom/inputs/cert_chain_rs2048/input.json
cargo run --release -- user-sig setup --input ../circom/inputs/user_sig_rs2048/input.json
cargo run --release -- user-sig prove --input ../circom/inputs/user_sig_rs2048/input.json

# 5. Repeat for RS4096.
RUST_LOG=info cargo run --release -- generate-split-input --cert-chain-4096
cargo run --release --features cert_chain_rs4096 -- cert-chain setup --cert-chain-4096 --input ../circom/inputs/cert_chain_rs4096/input.json
cargo run --release --features cert_chain_rs4096 -- cert-chain prove --cert-chain-4096 --input ../circom/inputs/cert_chain_rs4096/input.json
cargo run --release --features user_sig_rs2048 -- user-sig setup --input ../circom/inputs/user_sig_rs2048_chain_rs4096/input.json
cargo run --release --features user_sig_rs2048 -- user-sig prove --input ../circom/inputs/user_sig_rs2048_chain_rs4096/input.json

# 6. Copy the resulting proofs into this directory.
cp keys/cert_chain_rs2048_proof.bin /path/to/go-zkid-verifier/tests/artifacts/cc2048_us2048/
cp keys/user_sig_rs2048_proof.bin /path/to/go-zkid-verifier/tests/artifacts/cc2048_us2048/
cp keys/cert_chain_rs4096_proof.bin /path/to/go-zkid-verifier/tests/artifacts/cc4096_us2048/
# The RS4096 chain pairs with a DIFFERENT user-sig fixture (chain_rs4096 input), so re-run user-sig
# prove against that input before copying. The committed cc4096_us2048/user_sig_rs2048_proof.bin
# was produced from user_sig_rs2048_chain_rs4096/input.json.
cp keys/user_sig_rs2048_proof.bin /path/to/go-zkid-verifier/tests/artifacts/cc4096_us2048/

# 7. Refresh local verifying keys so the FFI matches the proofs.
rm -rf ../../../go-zkid-verifier/keys/
# Keys auto-download from the zkID `RSA-X.509-Cert-latest` release on next `make serve` / test run.
```

The verifying keys at `https://github.com/privacy-ethereum/zkID/releases/tag/RSA-X.509-Cert-latest` are auto-rebuilt by zkID's `rust-tests.yaml` workflow on every `RSA-X.509-Cert` push, so a freshly-merged circuit change normally lands new keys within minutes. If `keymanager` keeps downloading stale keys, sanity-check `RSA-X.509-Cert-latest` was actually rebuilt after the offending circuit commit.
