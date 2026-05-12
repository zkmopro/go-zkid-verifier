# Test fixtures

`cc{2048,4096}_ds2048/*.bin` are spartan2 proof binaries paired with the verifying keys auto-downloaded by `keymanager` from the [zkID `latest` release](https://github.com/zkmopro/zkID/releases/tag/latest). Whenever the cert-chain or device-sig circuit changes (and the upstream release is rebuilt) the fixtures must be regenerated against the new keys, otherwise integration tests fail loudly with a public-input count mismatch.

## Regenerating

```bash
# 1. Make sure circom + node + yarn + cargo are installed.
git clone https://github.com/zkmopro/zkID.git ../../zkID

# 2. Recompile the circuits (writes R1CS + wasm + cpp under wallet-unit-poc/circom/build/).
cd ../../zkID/wallet-unit-poc/circom
yarn install
yarn compile:all

# 3. Generate split inputs (RSA-2048 issuer + RSA-2048 user).
cd ../ecdsa-spartan2
RUST_LOG=info cargo run --release -- generate-split-input

# 4. Setup + prove cert-chain RS2048 and device-sig RS2048.
cargo run --release --features cert_chain_rs2048 -- cert-chain setup --input ../circom/inputs/cert_chain_rs2048/input.json
cargo run --release --features cert_chain_rs2048 -- cert-chain prove --input ../circom/inputs/cert_chain_rs2048/input.json
cargo run --release -- device-sig setup --input ../circom/inputs/user_sig_rs2048/input.json
cargo run --release -- device-sig prove --input ../circom/inputs/user_sig_rs2048/input.json

# 5. Repeat for RS4096.
RUST_LOG=info cargo run --release -- generate-split-input --cert-chain-4096
cargo run --release --features cert_chain_rs4096 -- cert-chain setup --cert-chain-4096 --input ../circom/inputs/cert_chain_rs4096/input.json
cargo run --release --features cert_chain_rs4096 -- cert-chain prove --cert-chain-4096 --input ../circom/inputs/cert_chain_rs4096/input.json
cargo run --release --features user_sig_rs2048 -- device-sig setup --input ../circom/inputs/user_sig_rs2048_chain_rs4096/input.json
cargo run --release --features user_sig_rs2048 -- device-sig prove --input ../circom/inputs/user_sig_rs2048_chain_rs4096/input.json

# 6. Copy the resulting proofs into this directory.
cp keys/cert_chain_rs2048_proof.bin /path/to/go-zkid-verifier/tests/artifacts/cc2048_ds2048/
cp keys/user_sig_rs2048_proof.bin /path/to/go-zkid-verifier/tests/artifacts/cc2048_ds2048/
cp keys/cert_chain_rs4096_proof.bin /path/to/go-zkid-verifier/tests/artifacts/cc4096_ds2048/
# The RS4096 chain pairs with a DIFFERENT device-sig fixture (chain_rs4096 input), so re-run device-sig
# prove against that input before copying. The committed cc4096_ds2048/user_sig_rs2048_proof.bin
# was produced from user_sig_rs2048_chain_rs4096/input.json.
cp keys/user_sig_rs2048_proof.bin /path/to/go-zkid-verifier/tests/artifacts/cc4096_ds2048/

# 7. Refresh local verifying keys so the FFI matches the proofs.
rm -rf ../../../go-zkid-verifier/keys/
# Keys auto-download from the zkID `latest` release on next `make serve` / test run.
```

The verifying keys at `https://github.com/zkmopro/zkID/releases/tag/latest` are auto-rebuilt by zkID's `rust-tests.yaml` workflow on every `main` push, so a freshly-merged circuit change normally lands new keys within minutes. If `keymanager` keeps downloading stale keys, sanity-check `latest` was actually rebuilt after the offending circuit commit.
