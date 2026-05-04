/// Full ZK proof pipeline e2e test: generate inputs → setup keys → prove → verify → link-verify.
///
/// Prerequisites:
///   cd ../../zkID/wallet-unit-poc/circom
///   yarn compile:cert_chain_rs4096   # writes circom/build/cert_chain_rs4096/…/cert_chain_rs4096.r1cs
///   yarn compile:device_sig_rs2048   # writes circom/build/device_sig_rs2048/…/device_sig_rs2048.r1cs
///
/// Optionally place a G3-tree snapshot at /tmp/g3-tree-snapshot.json.gz for SMT inclusion.
///
/// Run:
///   cargo test --release --features proof-e2e -- --nocapture

const BASE_URL: &str = "http://localhost:8080";

const OUTDATED_G2_SNAPSHOT_PATH: &str = "./data/g3-tree-snapshot.json.gz";
const OUTDATED_G3_SNAPSHOT_PATH: &str = "./data/g3-tree-snapshot.json.gz";
const LATEST_G2_SNAPSHOT_URL: &str = "https://github.com/moven0831/moica-revocation-smt/releases/download/snapshot-latest/g2-tree-snapshot.json.gz";
const LATEST_G3_SNAPSHOT_URL: &str = "https://github.com/moven0831/moica-revocation-smt/releases/download/snapshot-latest/g3-tree-snapshot.json.gz";

const FAKE_CERT_RESPONSE_PATH: &str =
    "../../zkID/wallet-unit-poc/ecdsa-spartan2/tests/testdata/rs4096_response_sign.json";
const FAKE_ISSUER_CERT_PATH: &str =
    "../../zkID/wallet-unit-poc/ecdsa-spartan2/tests/testdata/test_ca_rs4096.der";

#[cfg(feature = "proof-e2e")]
mod proof_e2e {

    use std::path::PathBuf;

    use base64::{engine::general_purpose::STANDARD, Engine as _};
    use ecdsa_spartan2::{circuits::types::Rs4096SignResponse, DEFAULT_CHALLENGE, DEFAULT_TBS};
    use openac_mobile_app::{
        generate_cert_chain_rs4096_input, link_verify, prove_cert_chain_rs4096,
        prove_device_sig_rs2048, setup_keys, verify_cert_chain_rs4096, verify_device_sig_rs2048,
    };

    fn generate_proof() {
        let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));

        let response_path = manifest.join(
            "../../zkID/wallet-unit-poc/ecdsa-spartan2/tests/testdata/rs4096_response_sign.json",
        );
        let response_str = std::fs::read_to_string(&response_path).unwrap();
        let response: Rs4096SignResponse = serde_json::from_str(&response_str).unwrap();
        let certb64 = response.result.cert;
        let signed_response = response.result.signed_response;
        let tbs = std::str::from_utf8(DEFAULT_TBS).unwrap().to_string();
        let issuer_cert_path = manifest
            .join("../../zkID/wallet-unit-poc/ecdsa-spartan2/tests/testdata/test_ca_rs4096.der");

        // Use a temp dir as documents_path so input + key files stay isolated.
        let tmp = tempfile::tempdir().unwrap();
        let documents_path = tmp.path().to_string_lossy().to_string();
        std::fs::create_dir_all(tmp.path().join("keys")).unwrap();

        // Copy R1CS files — built by `yarn compile:cert_chain_rs4096/device_sig_rs2048`.
        let cc_r1cs_src = manifest.join(
                "../../zkID/wallet-unit-poc/circom/build/cert_chain_rs4096/cert_chain_rs4096_js/cert_chain_rs4096.r1cs",
            );
        let ds_r1cs_src = manifest.join(
                "../../zkID/wallet-unit-poc/circom/build/device_sig_rs2048/device_sig_rs2048_js/device_sig_rs2048.r1cs",
            );
        assert!(
            cc_r1cs_src.exists(),
            "cert_chain_rs4096 R1CS not found at {}. Run `yarn compile:cert_chain_rs4096` first.",
            cc_r1cs_src.display()
        );
        assert!(
            ds_r1cs_src.exists(),
            "device_sig_rs2048 R1CS not found at {}. Run `yarn compile:device_sig_rs2048` first.",
            ds_r1cs_src.display()
        );
        std::fs::copy(&cc_r1cs_src, tmp.path().join("cert_chain_rs4096.r1cs")).unwrap();
        std::fs::copy(&ds_r1cs_src, tmp.path().join("device_sig_rs2048.r1cs")).unwrap();

        // Use G3-tree snapshot for SMT if present.
        let snapshot_path = "/tmp/g3-tree-snapshot.json.gz";
        let smt_snapshot = std::path::Path::new(snapshot_path)
            .exists()
            .then(|| snapshot_path.to_string());

        let challenge = DEFAULT_CHALLENGE.to_string();
        let result = generate_cert_chain_rs4096_input(
            certb64,
            signed_response,
            tbs,
            issuer_cert_path.to_string_lossy().to_string(),
            smt_snapshot,
            documents_path.clone(),
            challenge,
        )
        .unwrap();
        assert!(result.contains("cert_chain"));
        assert!(result.contains("device_sig"));

        // Setup, prove, verify both circuits.
        setup_keys(documents_path.clone()).unwrap();

        let cc_result = prove_cert_chain_rs4096(documents_path.clone()).unwrap();
        println!("cert_chain proved in {}ms", cc_result.prove_ms);
        let cc_ok = verify_cert_chain_rs4096(documents_path.clone()).unwrap();
        assert!(cc_ok, "cert_chain_rs4096 verification failed");

        let ds_result = prove_device_sig_rs2048(documents_path.clone()).unwrap();
        println!("device_sig proved in {}ms", ds_result.prove_ms);
        let ds_ok = verify_device_sig_rs2048(documents_path.clone()).unwrap();
        assert!(ds_ok, "device_sig_rs2048 verification failed");

        let linked = link_verify(documents_path.clone()).unwrap();
        assert!(linked, "link verification failed");

        let cc_proof = std::fs::read(tmp.path().join("keys/cert_chain_rs4096_proof.bin")).unwrap();
        let ds_proof = std::fs::read(tmp.path().join("keys/device_sig_rs2048_proof.bin")).unwrap();
        let body = serde_json::json!({
            "cert_chain_type": "rs4096",
            "cert_chain_proof": STANDARD.encode(&cc_proof),
            "device_sig_proof": STANDARD.encode(&ds_proof),
        });
        let resp = reqwest::blocking::Client::new()
            .post(format!("{}/linkverify", super::BASE_URL))
            .json(&body)
            .send()
            .expect("POST /linkverify failed");
        assert!(resp.status().is_success(), "/linkverify returned {}", resp.status());
        let resp_body: serde_json::Value = resp.json().expect("/linkverify response is not valid JSON");
        assert_eq!(resp_body["verified"], true, "/linkverify body: {resp_body}");
        println!("HTTP /linkverify nullifier: {}", resp_body["nullifier"]);
        println!("All proofs verified successfully");
    }

    #[test]
    fn test_generate_cert_chain_rs4096_input_e2e() {
        generate_proof();
    }
}
