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
#[cfg(feature = "proof-e2e")]
mod proof_e2e {

    const BASE_URL: &str = "http://localhost:8080";

    const OUTDATED_G2_SNAPSHOT_PATH: &str = "tests/data/outdated-g2-tree-snapshot.json.gz";
    const OUTDATED_G3_SNAPSHOT_PATH: &str = "tests/data/outdated-g3-tree-snapshot.json.gz";
    const G2_SNAPSHOT_PATH: &str = "tests/data/g2-tree-snapshot.json.gz";
    const G3_SNAPSHOT_PATH: &str = "tests/data/g3-tree-snapshot.json.gz";
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

    const ISSUER_CERT_G3: &str = "tests/data/moica-g3.cer";

    use std::path::PathBuf;

    use base64::{engine::general_purpose::STANDARD, Engine as _};
    use ecdsa_spartan2::DEFAULT_TBS;
    use openac_mobile_app::{
        generate_cert_chain_rs4096_input, link_verify, prove_cert_chain_rs4096,
        prove_device_sig_rs2048, verify_cert_chain_rs4096, verify_device_sig_rs2048,
    };
    use std::time::Duration;

    #[derive(serde::Deserialize)]
    struct ChallengeResponse {
        challenge: String,
        app_id: String,
        expires_at: chrono::DateTime<chrono::Utc>,
    }

    fn client() -> reqwest::blocking::Client {
        reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .expect("build HTTP client")
    }

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

    struct ProofRequest {
        challenge: String,
        app_id: String,
        certb64: String,
        signed_response: String,
        issuer_cert: String,
        smt_snapshot: Option<String>,
    }

    impl ProofRequest {
        fn new(challenge: impl Into<String>) -> Self {
            let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
            let real_tw_fido_path = manifest.join(REAL_TW_FIDO_SIGN_RESPONSE_PATH);
            let tw_fido_str = if real_tw_fido_path.exists() {
                Some(std::fs::read_to_string(&real_tw_fido_path).unwrap())
            } else {
                std::env::var("TW_FIDO_SIGN_RESPONSE").ok()
            };
            let tw_fido_str = tw_fido_str.expect("TW_FIDO_SIGN_RESPONSE env var or file must be set");
            let (certb64, signed_response) = serde_json::from_str::<AnySignResponse>(&tw_fido_str)
                .expect("response JSON must be a MOICA G3 or HiPKI sign response")
                .into_cert_and_sig();
            Self {
                challenge: challenge.into(),
                app_id: std::str::from_utf8(DEFAULT_TBS).unwrap().to_string(),
                certb64,
                signed_response,
                issuer_cert: manifest.join(ISSUER_CERT_G3).to_string_lossy().to_string(),
                smt_snapshot: None,
            }
        }

        fn app_id(mut self, id: impl Into<String>) -> Self {
            self.app_id = id.into();
            self
        }

        fn issuer_cert(mut self, path: impl Into<String>) -> Self {
            self.issuer_cert = path.into();
            self
        }

        fn cert_response(mut self, certb64: impl Into<String>, signed_response: impl Into<String>) -> Self {
            self.certb64 = certb64.into();
            self.signed_response = signed_response.into();
            self
        }

        fn smt_snapshot(mut self, path: impl Into<String>) -> Self {
            self.smt_snapshot = Some(path.into());
            self
        }

        fn prove(self) -> (Vec<u8>, Vec<u8>) {
            let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));

            let tmp = tempfile::tempdir().unwrap();
            let documents_path = tmp.path().to_string_lossy().to_string();
            std::fs::create_dir_all(tmp.path().join("keys")).unwrap();

            let smt_snapshot = self.smt_snapshot.or_else(|| {
                let g3_path = manifest.join(G3_SNAPSHOT_PATH);
                if !g3_path.exists() {
                    if let Some(parent) = g3_path.parent() {
                        std::fs::create_dir_all(parent)
                            .unwrap_or_else(|e| panic!("create {}: {e}", parent.display()));
                    }
                    let bytes = reqwest::blocking::get(LATEST_G3_SNAPSHOT_URL)
                        .unwrap_or_else(|e| panic!("GET {} failed: {e}", LATEST_G3_SNAPSHOT_URL))
                        .bytes()
                        .unwrap_or_else(|e| panic!("reading snapshot: {e}"));
                    std::fs::write(&g3_path, &bytes)
                        .unwrap_or_else(|e| panic!("write {}: {e}", g3_path.display()));
                }
                g3_path.exists().then(|| g3_path.to_string_lossy().to_string())
            });

            let result = generate_cert_chain_rs4096_input(
                self.certb64,
                self.signed_response,
                self.app_id,
                self.issuer_cert,
                smt_snapshot,
                documents_path.clone(),
                self.challenge,
            )
            .unwrap();
            assert!(result.contains("cert_chain"));
            assert!(result.contains("device_sig"));

            let keys_dir = tmp.path().join("keys");
            for (url, filename) in [
                (CERT_CHAIN_RS4096_PROVING_KEY_URL, "cert_chain_rs4096_proving.key"),
                (CERT_CHAIN_RS4096_VERIFYING_KEY_URL, "cert_chain_rs4096_verifying.key"),
                (DEVICE_SIG_RS2048_PROVING_KEY_URL, "device_sig_rs2048_proving.key"),
                (DEVICE_SIG_RS2048_VERIFYING_KEY_URL, "device_sig_rs2048_verifying.key"),
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
            (cc_proof, ds_proof)
        }

        fn run(self) -> reqwest::blocking::Response {
            let (cc_proof, ds_proof) = self.prove();
            submit_proofs(&cc_proof, &ds_proof)
        }
    }

    fn submit_proofs(cc_proof: &[u8], ds_proof: &[u8]) -> reqwest::blocking::Response {
        let body = serde_json::json!({
            "cert_chain_type": "rs4096",
            "cert_chain_proof": STANDARD.encode(cc_proof),
            "device_sig_proof": STANDARD.encode(ds_proof),
        });
        reqwest::blocking::Client::new()
            .post(format!("{}/link-verify", BASE_URL))
            .header("ngrok-skip-browser-warning", "true")
            .json(&body)
            .send()
            .expect("POST /link-verify failed")
    }

    #[test]
    fn test_generate_cert_chain_rs4096_input_e2e() {
        let body: ChallengeResponse = client()
            .post(format!("{BASE_URL}/challenge"))
            .send()
            .expect("POST /challenge")
            .json()
            .expect("parse ChallengeResponse JSON");

        let (cc_proof, ds_proof) = ProofRequest::new(&body.challenge)
            .app_id(&body.app_id)
            .prove();

        // First submission: success
        let resp = submit_proofs(&cc_proof, &ds_proof);
        let status = resp.status();
        let raw = resp
            .text()
            .unwrap_or_else(|e| format!("<failed to read body: {e}>"));
        assert!(status.is_success(), "/link-verify returned {status}: {raw}");
        let resp_body: serde_json::Value = serde_json::from_str(&raw)
            .unwrap_or_else(|e| panic!("/link-verify response is not valid JSON ({e}): {raw}"));
        assert_eq!(resp_body["verified"], true, "/link-verify body: {resp_body}");
        println!("HTTP /linkverify nullifier: {}", resp_body["nullifier"]);

        let body2: ChallengeResponse = client()
            .post(format!("{BASE_URL}/challenge"))
            .send()
            .expect("POST /challenge")
            .json()
            .expect("parse ChallengeResponse JSON");

        let (cc_proof2, ds_proof2) = ProofRequest::new(&body2.challenge)
            .app_id(&body.app_id)
            .prove();

        // Second submission with the same proof must be rejected (duplicate nullifier).
        let resp2 = submit_proofs(&cc_proof2, &ds_proof2);
        let status2 = resp2.status();
        let raw2 = resp2
            .text()
            .unwrap_or_else(|e| format!("<failed to read body: {e}>"));
        assert_eq!(
            status2,
            reqwest::StatusCode::CONFLICT,
            "expected 409 for untrusted CA, got {status2}: {raw2}"
        );
        assert!(
            raw2.contains("nullifier already registered"),
            "unexpected error body: {raw2}"
        );
    }

    #[test]
    fn test_untrusted_ca() {
        let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));

        let body: ChallengeResponse = client()
            .post(format!("{BASE_URL}/challenge"))
            .send()
            .expect("POST /challenge")
            .json()
            .expect("parse ChallengeResponse JSON");

        let fake_cert_str = std::fs::read_to_string(manifest.join(FAKE_CERT_RESPONSE_PATH))
            .expect("FAKE_CERT_RESPONSE_PATH must exist");
        let (certb64, signed_response) = serde_json::from_str::<AnySignResponse>(&fake_cert_str)
            .expect("fake cert response must be valid AnySignResponse JSON")
            .into_cert_and_sig();

        let resp = ProofRequest::new(&body.challenge)
            .app_id(&body.app_id)
            .cert_response(certb64, signed_response)
            .issuer_cert(manifest.join(FAKE_ISSUER_CERT_PATH).to_string_lossy())
            .run();
        let status = resp.status();
        let raw = resp.text().unwrap_or_else(|e| format!("<failed to read body: {e}>"));
        assert_eq!(
            status,
            reqwest::StatusCode::CONFLICT,
            "expected 409 for untrusted CA, got {status}: {raw}"
        );
        assert!(
            raw.contains("issuer_modulus_mismatch"),
            "unexpected error body: {raw}"
        );
    }

    #[test]
    fn test_invalid_challenge() {
        let resp = ProofRequest::new("1234567890").run();
        let status = resp.status();
        let raw = resp.text().unwrap_or_else(|e| format!("<failed to read body: {e}>"));
        assert_eq!(
            status,
            reqwest::StatusCode::NOT_FOUND,
            "expected 404 for invalid challenge, got {status}: {raw}"
        );
        assert!(
            raw.contains("challenge not found or already consumed"),
            "unexpected error body: {raw}"
        );
    }

    #[test]
    fn test_tampered_certificate() {
        let body: ChallengeResponse = client()
            .post(format!("{BASE_URL}/challenge"))
            .send()
            .expect("POST /challenge")
            .json()
            .expect("parse ChallengeResponse JSON");

        // Generate a valid proof, then flip a byte in the cert_chain_proof binary before
        // submission. The ZK verifier encodes the certificate data inside the proof, so
        // tampering with its bytes is equivalent to submitting a proof built from a
        // modified certificate — RSA verification inside the verifier will fail.
        let (mut cc_proof, ds_proof) = ProofRequest::new(&body.challenge)
            .app_id(&body.app_id)
            .prove();

        cc_proof[0] ^= 0xFF;

        let resp = submit_proofs(&cc_proof, &ds_proof);
        let status = resp.status();
        let raw = resp.text().unwrap_or_else(|e| format!("<failed to read body: {e}>"));
        assert!(
            !status.is_success(),
            "expected rejection for tampered proof, got {status}: {raw}"
        );
        assert!(
            raw.contains("proof verification failed"),
            "unexpected error body: {raw}"
        );
    }

    #[test]
    fn test_outdated_smt_root() {
        let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let outdated_path = manifest.join(OUTDATED_G3_SNAPSHOT_PATH);
        if !outdated_path.exists() {
            println!("skipping: outdated G3 snapshot not present at {}", outdated_path.display());
            return;
        }

        let body: ChallengeResponse = client()
            .post(format!("{BASE_URL}/challenge"))
            .send()
            .expect("POST /challenge")
            .json()
            .expect("parse ChallengeResponse JSON");

        let resp = ProofRequest::new(&body.challenge)
            .app_id(&body.app_id)
            .smt_snapshot(outdated_path.to_string_lossy())
            .run();
        let status = resp.status();
        let raw = resp.text().unwrap_or_else(|e| format!("<failed to read body: {e}>"));
        assert_eq!(
            status,
            reqwest::StatusCode::CONFLICT,
            "expected 409 for outdated SMT root, got {status}: {raw}"
        );
        assert!(
            raw.contains("smt_root_mismatch"),
            "unexpected error body: {raw}"
        );
    }

    #[test]
    fn test_expired_challenge() {
        let body: ChallengeResponse = client()
            .post(format!("{BASE_URL}/challenge"))
            .send()
            .expect("POST /challenge")
            .json()
            .expect("parse ChallengeResponse JSON");

        let wait = (body.expires_at - chrono::Utc::now())
            .to_std()
            .unwrap_or(Duration::ZERO)
            + Duration::from_secs(1);
        println!("waiting {wait:?} for challenge to expire…");
        std::thread::sleep(wait);

        let resp = ProofRequest::new(&body.challenge).run();
        let status = resp.status();
        let raw = resp.text().unwrap_or_else(|e| format!("<failed to read body: {e}>"));
        assert_eq!(
            status,
            reqwest::StatusCode::BAD_REQUEST,
            "expected 400 for challenge expired, got {status}: {raw}"
        );
        assert!(
            raw.contains("challenge expired"),
            "unexpected error body: {raw}"
        );
    }
}
