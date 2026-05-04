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

const OUTDATED_G2_SNAPSHOT_PATH: &str = "tests/data/outdated-g3-tree-snapshot.json.gz";
const OUTDATED_G3_SNAPSHOT_PATH: &str = "tests/data/outdated-g3-tree-snapshot.json.gz";
const LATEST_G2_SNAPSHOT_URL: &str = "https://github.com/moven0831/moica-revocation-smt/releases/download/snapshot-latest/g2-tree-snapshot.json.gz";
const LATEST_G3_SNAPSHOT_URL: &str = "https://github.com/moven0831/moica-revocation-smt/releases/download/snapshot-latest/g3-tree-snapshot.json.gz";
const CERT_CHAIN_RS4096_PROVING_KEY_URL: &str =
    "https://github.com/zkmopro/zkID/releases/download/latest/cert_chain_rs4096_proving.key.gz";
const CERT_CHAIN_RS4096_VERIFYING_KEY_URL: &str =
    "https://github.com/zkmopro/zkID/releases/download/latest/cert_chain_rs4096_verifying.key.gz";
const DEVICE_SIG_RS2048_PROVING_KEY_URL: &str =
    "https://github.com/zkmopro/zkID/releases/download/latest/device_sig_rs2048_proving.key.gz";
const DEVICE_SIG_RS2048_VERIFYING_KEY_URL: &str =
    "https://github.com/zkmopro/zkID/releases/download/latest/device_sig_rs2048_verifying.key.gz";

const FAKE_CERT_RESPONSE_PATH: &str =
    "../../zkID/wallet-unit-poc/ecdsa-spartan2/tests/testdata/rs4096_response_sign.json";
const FAKE_ISSUER_CERT_PATH: &str =
    "../../zkID/wallet-unit-poc/ecdsa-spartan2/tests/testdata/test_ca_rs4096.der";

const REAL_TW_FIDO_SIGN_RESPONSE_PATH: &str = "tests/data/tw_fido_sign_response.json";
const REAL_RS4096_SIGN_RESPONSE_PATH: &str = "tests/data/rs4096_sign_response.json";

#[cfg(feature = "proof-e2e")]
mod proof_e2e {

    use std::path::PathBuf;

    use base64::{engine::general_purpose::STANDARD, Engine as _};
    use ecdsa_spartan2::{DEFAULT_CHALLENGE, DEFAULT_TBS};
    use openac_mobile_app::{
        generate_cert_chain_rs4096_input, link_verify, prove_cert_chain_rs4096,
        prove_device_sig_rs2048, verify_cert_chain_rs4096, verify_device_sig_rs2048,
    };

    fn download_and_gunzip(url: &str, dest: &std::path::Path) {
        let bytes = reqwest::blocking::get(url)
            .unwrap_or_else(|e| panic!("GET {url} failed: {e}"))
            .bytes()
            .unwrap_or_else(|e| panic!("reading {url}: {e}"));
        let mut decoder = flate2::read::GzDecoder::new(bytes.as_ref());
        let mut file = std::fs::File::create(dest)
            .unwrap_or_else(|e| panic!("create {}: {e}", dest.display()));
        std::io::copy(&mut decoder, &mut file).unwrap_or_else(|e| panic!("decompress {url}: {e}"));
    }

    // Two distinct API shapes that both carry a cert + signature:
    //
    //   Moica  (MOICA G3 / TW FIDO API):
    //     { "error_code": "0", "result": { "cert": "…", "signed_response": "…" } }
    //
    //   Hipki  (HiPKI PKCS#11 card-reader API):
    //     { "certb64": "…", "signature": "…", "cardSN": "…", … }
    //
    // `#[serde(untagged)]` tries Moica first; falls back to Hipki if `result` is absent.
    #[derive(serde::Deserialize)]
    #[serde(untagged)]
    enum AnySignResponse {
        Moica(MoicaSignResponse),
        Hipki(HipkiSignResponse),
    }

    #[derive(serde::Deserialize)]
    struct MoicaSignResponse {
        result: MoicaSignResult,
    }

    #[derive(serde::Deserialize)]
    struct MoicaSignResult {
        cert: String,
        signed_response: String,
    }

    #[derive(serde::Deserialize)]
    struct HipkiSignResponse {
        #[serde(rename = "certb64")]
        cert: String,
        #[serde(rename = "signature")]
        signed_response: String,
    }

    impl AnySignResponse {
        fn into_cert_and_sig(self) -> (String, String) {
            match self {
                AnySignResponse::Moica(r) => (r.result.cert, r.result.signed_response),
                AnySignResponse::Hipki(r) => (r.cert, r.signed_response),
            }
        }
    }

    fn generate_proof() {
        let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));

        // Load RS4096 sign response: file → env var → fake testdata.
        let real_rs4096_path = manifest.join(super::REAL_RS4096_SIGN_RESPONSE_PATH);
        let response_str = if real_rs4096_path.exists() {
            std::fs::read_to_string(&real_rs4096_path).unwrap()
        } else if let Ok(content) = std::env::var("RS4096_SIGN_RESPONSE") {
            content
        } else {
            std::fs::read_to_string(manifest.join(super::FAKE_CERT_RESPONSE_PATH)).unwrap()
        };

        // Load TW FIDO sign response: file → env var.
        let real_tw_fido_path = manifest.join(super::REAL_TW_FIDO_SIGN_RESPONSE_PATH);
        let _tw_fido_response_str = if real_tw_fido_path.exists() {
            Some(std::fs::read_to_string(&real_tw_fido_path).unwrap())
        } else {
            std::env::var("TW_FIDO_SIGN_RESPONSE").ok()
        };
        let (certb64, signed_response) = serde_json::from_str::<AnySignResponse>(&response_str)
            .expect("response JSON must be a MOICA G3 or HiPKI sign response")
            .into_cert_and_sig();
        let tbs = std::str::from_utf8(DEFAULT_TBS).unwrap().to_string();
        let issuer_cert_path = manifest
            .join("../../zkID/wallet-unit-poc/ecdsa-spartan2/tests/testdata/test_ca_rs4096.der");

        // Use a temp dir as documents_path so input + key files stay isolated.
        let tmp = tempfile::tempdir().unwrap();
        let documents_path = tmp.path().to_string_lossy().to_string();
        std::fs::create_dir_all(tmp.path().join("keys")).unwrap();

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

        // Download pre-built proving + verifying keys into documents_path/keys/.
        let keys_dir = tmp.path().join("keys");
        for (url, filename) in [
            (
                super::CERT_CHAIN_RS4096_PROVING_KEY_URL,
                "cert_chain_rs4096_proving.key",
            ),
            (
                super::CERT_CHAIN_RS4096_VERIFYING_KEY_URL,
                "cert_chain_rs4096_verifying.key",
            ),
            (
                super::DEVICE_SIG_RS2048_PROVING_KEY_URL,
                "device_sig_rs2048_proving.key",
            ),
            (
                super::DEVICE_SIG_RS2048_VERIFYING_KEY_URL,
                "device_sig_rs2048_verifying.key",
            ),
        ] {
            download_and_gunzip(url, &keys_dir.join(filename));
        }

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
            .post(format!("{}/link-verify", super::BASE_URL))
            .header("ngrok-skip-browser-warning", "true")
            .json(&body)
            .send()
            .expect("POST /link-verify failed");
        let status = resp.status();
        let raw = resp
            .text()
            .unwrap_or_else(|e| format!("<failed to read body: {e}>"));
        assert!(status.is_success(), "/link-verify returned {status}: {raw}");
        let resp_body: serde_json::Value = serde_json::from_str(&raw)
            .unwrap_or_else(|e| panic!("/link-verify response is not valid JSON ({e}): {raw}"));
        assert_eq!(
            resp_body["verified"], true,
            "/link-verify body: {resp_body}"
        );
        println!("HTTP /linkverify nullifier: {}", resp_body["nullifier"]);
        println!("All proofs verified successfully");
    }

    #[test]
    fn test_generate_cert_chain_rs4096_input_e2e() {
        generate_proof();
    }
}
