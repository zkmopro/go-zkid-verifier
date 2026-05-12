/// Full ZK proof pipeline e2e test: generate inputs → setup keys → prove → verify → link-verify.
///
/// Prerequisites:
///   cd ../../zkID/wallet-unit-poc/circom
///   yarn compile:cert_chain_rs4096   # writes circom/build/cert_chain_rs4096/…/cert_chain_rs4096.r1cs
///   yarn compile:user_sig_rs2048   # writes circom/build/user_sig_rs2048/…/user_sig_rs2048.r1cs
///
/// Run:
///   cargo test --release --features proof-e2e -- --test-threads=1 --nocapture
#[cfg(feature = "proof-e2e")]
mod proof_e2e {

    const BASE_URL: &str = "http://localhost:8080";

    // SMT snapshot paths and download URLs.
    const OUTDATED_G3_SNAPSHOT_PATH: &str = "tests/data/outdated-g3-tree-snapshot.json.gz";
    const G3_SNAPSHOT_PATH: &str = "tests/data/g3-tree-snapshot.json.gz";
    const LATEST_G3_SNAPSHOT_URL: &str = "https://github.com/moven0831/moica-revocation-smt/releases/download/snapshot-latest/g3-tree-snapshot.json.gz";

    // Proving / verifying key download URLs.
    const CERT_CHAIN_RS4096_PROVING_KEY_URL: &str =
        "https://github.com/zkmopro/zkID/releases/download/latest/cert_chain_rs4096_proving.key.gz";
    const CERT_CHAIN_RS4096_VERIFYING_KEY_URL: &str =
        "https://github.com/zkmopro/zkID/releases/download/latest/cert_chain_rs4096_verifying.key.gz";
    const USER_SIG_RS2048_PROVING_KEY_URL: &str =
        "https://github.com/zkmopro/zkID/releases/download/latest/user_sig_rs2048_proving.key.gz";
    const USER_SIG_RS2048_VERIFYING_KEY_URL: &str =
        "https://github.com/zkmopro/zkID/releases/download/latest/user_sig_rs2048_verifying.key.gz";

    // Test fixture paths.
    const FAKE_CERT_RESPONSE_PATH: &str =
        "../../zkID/wallet-unit-poc/ecdsa-spartan2/tests/testdata/rs4096_response_sign.json";
    const FAKE_ISSUER_CERT_PATH: &str =
        "../../zkID/wallet-unit-poc/ecdsa-spartan2/tests/testdata/test_ca_rs4096.der";
    const REAL_TW_FIDO_SIGN_RESPONSE_PATH: &str = "tests/data/tw_fido_sign_response.json";
    const REAL_TW_FIDO_SIGN_RESPONSE_WRONG_APP_ID_PATH: &str =
        "tests/data/tw_fido_sign_response_wrong_app_id.json";
    const ISSUER_CERT_G3: &str = "tests/data/moica-g3.cer";

    use std::path::PathBuf;

    use base64::{engine::general_purpose::STANDARD, Engine as _};
    use ecdsa_spartan2::DEFAULT_TBS;
    use openac_mobile_app::{
        generate_cert_chain_rs4096_input, link_verify, prove_cert_chain_rs4096,
        prove_user_sig_rs2048, verify_cert_chain_rs4096, verify_user_sig_rs2048,
    };
    use std::time::Duration;

    // ── Shared types ────────────────────────────────────────────────────────────

    #[derive(serde::Deserialize)]
    struct ChallengeResponse {
        challenge: String,
        app_id: String,
        expires_at: chrono::DateTime<chrono::Utc>,
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

    // ── Helpers ─────────────────────────────────────────────────────────────────

    fn client() -> reqwest::blocking::Client {
        reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .expect("build HTTP client")
    }

    fn fresh_challenge() -> ChallengeResponse {
        client()
            .post(format!("{BASE_URL}/challenge"))
            .send()
            .expect("POST /challenge")
            .json()
            .expect("parse ChallengeResponse JSON")
    }

    fn submit_proofs(cc_proof: &[u8], ds_proof: &[u8]) -> reqwest::blocking::Response {
        let body = serde_json::json!({
            "cert_chain_type": "rs4096",
            "cert_chain_proof": STANDARD.encode(cc_proof),
            "user_sig_proof": STANDARD.encode(ds_proof),
        });
        reqwest::blocking::Client::new()
            .post(format!("{BASE_URL}/link-verify"))
            .header("ngrok-skip-browser-warning", "true")
            .json(&body)
            .send()
            .expect("POST /link-verify failed")
    }

    /// Assert that a response is rejected with the expected status and body fragment.
    fn assert_rejected(
        resp: reqwest::blocking::Response,
        expected_status: reqwest::StatusCode,
        expected_fragment: &str,
    ) {
        let status = resp.status();
        let raw = resp.text().unwrap_or_else(|e| format!("<failed to read body: {e}>"));
        assert_eq!(status, expected_status, "got {status}: {raw}");
        assert!(raw.contains(expected_fragment), "expected {expected_fragment:?} in body: {raw}");
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

    // ── ProofRequest builder ─────────────────────────────────────────────────────

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

        /// Generate ZK proofs locally; return raw cert-chain and device-sig proof bytes.
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
            assert!(result.contains("user_sig"));

            let keys_dir = tmp.path().join("keys");
            for (url, filename) in [
                (CERT_CHAIN_RS4096_PROVING_KEY_URL, "cert_chain_rs4096_proving.key"),
                (CERT_CHAIN_RS4096_VERIFYING_KEY_URL, "cert_chain_rs4096_verifying.key"),
                (USER_SIG_RS2048_PROVING_KEY_URL, "user_sig_rs2048_proving.key"),
                (USER_SIG_RS2048_VERIFYING_KEY_URL, "user_sig_rs2048_verifying.key"),
            ] {
                download_and_gunzip(url, &keys_dir.join(filename));
            }

            let cc_result = prove_cert_chain_rs4096(documents_path.clone()).unwrap();
            println!("cert_chain proved in {}ms", cc_result.prove_ms);
            let cc_ok = verify_cert_chain_rs4096(documents_path.clone()).unwrap();
            assert!(cc_ok, "cert_chain_rs4096 verification failed");

            let ds_result = prove_user_sig_rs2048(documents_path.clone()).unwrap();
            println!("user_sig proved in {}ms", ds_result.prove_ms);
            let ds_ok = verify_user_sig_rs2048(documents_path.clone()).unwrap();
            assert!(ds_ok, "user_sig_rs2048 verification failed");

            let linked = link_verify(documents_path.clone()).unwrap();
            assert!(linked, "link verification failed");

            let cc_proof = std::fs::read(tmp.path().join("keys/cert_chain_rs4096_proof.bin")).unwrap();
            let ds_proof = std::fs::read(tmp.path().join("keys/user_sig_rs2048_proof.bin")).unwrap();
            (cc_proof, ds_proof)
        }

        /// Prove then submit to the server; return the HTTP response.
        fn run(self) -> reqwest::blocking::Response {
            let (cc_proof, ds_proof) = self.prove();
            submit_proofs(&cc_proof, &ds_proof)
        }
    }

    // ── Tests ────────────────────────────────────────────────────────────────────

    #[test]
    fn test_generate_cert_chain_rs4096_input_e2e() {
        let body = fresh_challenge();
        let (cc_proof, ds_proof) = ProofRequest::new(&body.challenge)
            .app_id(&body.app_id)
            .prove();

        // First submission must succeed. If the nullifier was already registered by a
        // prior run the duplicate check still confirms correct server behavior.
        let resp = submit_proofs(&cc_proof, &ds_proof);
        let status = resp.status();
        let raw = resp.text().unwrap_or_else(|e| format!("<failed to read body: {e}>"));
        if status == reqwest::StatusCode::CONFLICT && raw.contains("nullifier already registered") {
            println!("nullifier already registered from a prior run — duplicate detection confirmed");
        }
        assert!(status.is_success(), "/link-verify returned {status}: {raw}");
        let resp_body: serde_json::Value = serde_json::from_str(&raw)
            .unwrap_or_else(|e| panic!("/link-verify response is not valid JSON ({e}): {raw}"));
        assert_eq!(resp_body["verified"], true, "/link-verify body: {resp_body}");
        println!("nullifier: {}", resp_body["nullifier"]);

        // Resubmitting the same proof must fail: challenge already consumed.
        assert_rejected(
            submit_proofs(&cc_proof, &ds_proof),
            reqwest::StatusCode::GONE,
            "challenge already consumed",
        );

        // A fresh proof from the same cert embeds the same nullifier and must be rejected.
        let body2 = fresh_challenge();
        let (cc_proof2, ds_proof2) = ProofRequest::new(&body2.challenge)
            .app_id(&body.app_id)
            .prove();
        assert_rejected(
            submit_proofs(&cc_proof2, &ds_proof2),
            reqwest::StatusCode::CONFLICT,
            "nullifier already registered",
        );
    }

    // Precondition: test_generate_cert_chain_rs4096_input_e2e ran and recorded
    // the nullifier. The server is then stopped and restarted with the same DB
    // file (see the "Restart server" step in e2e.yml). A fresh proof from the
    // same certificate must still be rejected — confirming that duplicate
    // rejection relies on persisted DB state, not in-memory state.
    #[test]
    fn test_nullifier_persisted_after_restart() {
        let body = fresh_challenge();
        assert_rejected(
            ProofRequest::new(&body.challenge)
                .app_id(&body.app_id)
                .run(),
            reqwest::StatusCode::CONFLICT,
            "nullifier already registered",
        );
    }

    #[test]
    fn test_untrusted_ca() {
        let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let fake_cert_str = std::fs::read_to_string(manifest.join(FAKE_CERT_RESPONSE_PATH))
            .expect("FAKE_CERT_RESPONSE_PATH must exist");
        let (certb64, signed_response) = serde_json::from_str::<AnySignResponse>(&fake_cert_str)
            .expect("fake cert response must be valid AnySignResponse JSON")
            .into_cert_and_sig();

        let body = fresh_challenge();
        assert_rejected(
            ProofRequest::new(&body.challenge)
                .app_id(&body.app_id)
                .cert_response(certb64, signed_response)
                .issuer_cert(manifest.join(FAKE_ISSUER_CERT_PATH).to_string_lossy())
                .run(),
            reqwest::StatusCode::CONFLICT,
            "issuer_modulus_mismatch",
        );
    }

    #[test]
    fn test_tampered_certificate() {
        let body = fresh_challenge();
        let (mut cc_proof, ds_proof) = ProofRequest::new(&body.challenge)
            .app_id(&body.app_id)
            .prove();

        // Flip a byte in the proof binary — the ZK verifier will reject it.
        cc_proof[0] ^= 0xFF;

        assert_rejected(
            submit_proofs(&cc_proof, &ds_proof),
            reqwest::StatusCode::INTERNAL_SERVER_ERROR,
            "proof verification failed",
        );
    }

    #[test]
    fn test_invalid_challenge() {
        assert_rejected(
            ProofRequest::new("1234567890").run(),
            reqwest::StatusCode::NOT_FOUND,
            "challenge not found or already consumed",
        );
    }

    #[test]
    fn test_wrong_app_id() {
        let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let wrong_app_id_path = manifest.join(REAL_TW_FIDO_SIGN_RESPONSE_WRONG_APP_ID_PATH);
        let response_str = if wrong_app_id_path.exists() {
            Some(std::fs::read_to_string(&wrong_app_id_path).unwrap())
        } else {
            std::env::var("TW_FIDO_SIGN_RESPONSE_WRONG_APP_ID").ok()
        };
        let Some(response_str) = response_str else {
            println!("skipping: TW_FIDO_SIGN_RESPONSE_WRONG_APP_ID not set and file not present");
            return;
        };
        let (certb64, signed_response) = serde_json::from_str::<AnySignResponse>(&response_str)
            .expect("response JSON must be a MOICA G3 or HiPKI sign response")
            .into_cert_and_sig();

        let body = fresh_challenge();
        assert_rejected(
            ProofRequest::new(&body.challenge)
                .app_id("0000000000000000000000000000000")
                .cert_response(certb64, signed_response)
                .run(),
            reqwest::StatusCode::CONFLICT,
            "app_id_mismatch",
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

        let body = fresh_challenge();
        assert_rejected(
            ProofRequest::new(&body.challenge)
                .app_id(&body.app_id)
                .smt_snapshot(outdated_path.to_string_lossy())
                .run(),
            reqwest::StatusCode::CONFLICT,
            "smt_root_mismatch",
        );
    }

    #[test]
    fn test_expired_challenge() {
        let body = fresh_challenge();

        let wait = (body.expires_at - chrono::Utc::now())
            .to_std()
            .unwrap_or(Duration::ZERO)
            + Duration::from_secs(1);
        println!("waiting {wait:?} for challenge to expire…");
        std::thread::sleep(wait);

        assert_rejected(
            ProofRequest::new(&body.challenge).run(),
            reqwest::StatusCode::BAD_REQUEST,
            "challenge expired",
        );
    }

    #[test]
    fn test_malformed_json_body() {
        assert_rejected(
            client()
                .post(format!("{BASE_URL}/link-verify"))
                .header("Content-Type", "application/json")
                .body("{not valid json}")
                .send()
                .expect("POST /link-verify"),
            reqwest::StatusCode::BAD_REQUEST,
            "invalid request body",
        );
    }

    #[test]
    fn test_missing_proof_fields() {
        assert_rejected(
            client()
                .post(format!("{BASE_URL}/link-verify"))
                .json(&serde_json::json!({ "cert_chain_type": "rs4096" }))
                .send()
                .expect("POST /link-verify"),
            reqwest::StatusCode::BAD_REQUEST,
            "cert_chain_proof and user_sig_proof are required",
        );
    }

    #[test]
    fn test_invalid_cert_chain_type() {
        assert_rejected(
            client()
                .post(format!("{BASE_URL}/link-verify"))
                .json(&serde_json::json!({
                    "cert_chain_type": "rs1024",
                    "cert_chain_proof": STANDARD.encode(b"dummy"),
                    "user_sig_proof": STANDARD.encode(b"dummy"),
                }))
                .send()
                .expect("POST /link-verify"),
            reqwest::StatusCode::BAD_REQUEST,
            "invalid cert_chain_type",
        );
    }
}
