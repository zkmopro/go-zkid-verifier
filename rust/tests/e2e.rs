/// E2E tests against a running server at http://localhost:8080.
///
/// Start the server before running:
///   make serve   (or: go run ./cmd/server)
///
/// Run:
///   cargo test --test e2e
use std::time::Duration;

use chrono::{DateTime, FixedOffset};
use serde::Deserialize;

const BASE_URL: &str = "http://localhost:8080";

fn client() -> reqwest::blocking::Client {
    reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("build HTTP client")
}

#[derive(Debug, Deserialize)]
struct ChallengeResponse {
    challenge: String,
    app_id: String,
    expires_at: String,
}

#[derive(Debug, Deserialize)]
struct ErrorResponse {
    error: String,
}

// POST /challenge → 200 with a non-empty decimal challenge string.
#[test]
fn create_challenge_returns_200() {
    let resp = client()
        .post(format!("{BASE_URL}/challenge"))
        .send()
        .expect("POST /challenge");

    assert_eq!(resp.status(), 200, "expected 200, body: {}", resp.text().unwrap_or_default());
}

// POST /challenge → response body has challenge, app_id, expires_at fields.
#[test]
fn create_challenge_body_fields() {
    let body: ChallengeResponse = client()
        .post(format!("{BASE_URL}/challenge"))
        .send()
        .expect("POST /challenge")
        .json()
        .expect("parse ChallengeResponse JSON");

    assert!(!body.challenge.is_empty(), "challenge must be non-empty");
    assert!(!body.app_id.is_empty(), "app_id must be non-empty");
    assert!(!body.expires_at.is_empty(), "expires_at must be non-empty");
}

// POST /challenge → challenge is a decimal string (254-bit field element).
#[test]
fn create_challenge_is_decimal() {
    let body: ChallengeResponse = client()
        .post(format!("{BASE_URL}/challenge"))
        .send()
        .expect("POST /challenge")
        .json()
        .expect("parse ChallengeResponse JSON");

    body.challenge
        .parse::<u128>() // at least parseable as a big integer; use str check for digits
        .ok(); // large values exceed u128 — just assert all chars are digits
    assert!(
        body.challenge.chars().all(|c| c.is_ascii_digit()),
        "challenge must be a decimal string, got: {}",
        body.challenge
    );
}

// Two consecutive POST /challenge calls must produce distinct challenges.
#[test]
fn create_challenge_is_unique() {
    let c = client();
    let a: ChallengeResponse = c
        .post(format!("{BASE_URL}/challenge"))
        .send()
        .expect("first POST /challenge")
        .json()
        .expect("parse first response");
    let b: ChallengeResponse = c
        .post(format!("{BASE_URL}/challenge"))
        .send()
        .expect("second POST /challenge")
        .json()
        .expect("parse second response");

    assert_ne!(a.challenge, b.challenge, "consecutive challenges must differ");
}

// GET /challenge/{id} → retrieves the challenge that was just created.
#[test]
fn get_challenge_round_trip() {
    let c = client();
    let created: ChallengeResponse = c
        .post(format!("{BASE_URL}/challenge"))
        .send()
        .expect("POST /challenge")
        .json()
        .expect("parse create response");

    let fetched: ChallengeResponse = c
        .get(format!("{BASE_URL}/challenge/{}", created.challenge))
        .send()
        .expect("GET /challenge/{id}")
        .json()
        .expect("parse get response");

    assert_eq!(fetched.challenge, created.challenge);
    assert_eq!(fetched.app_id, created.app_id);
    // Compare as UTC unix seconds: the server may format the same instant with
    // different timezone offsets or sub-second precision across create vs. get.
    let created_ts = created.expires_at.parse::<DateTime<FixedOffset>>()
        .expect("parse created expires_at")
        .timestamp();
    let fetched_ts = fetched.expires_at.parse::<DateTime<FixedOffset>>()
        .expect("parse fetched expires_at")
        .timestamp();
    assert_eq!(fetched_ts, created_ts, "expires_at instants must be equal (created={}, fetched={})", created.expires_at, fetched.expires_at);
}

// GET /challenge/{id} with an unknown id → 404.
#[test]
fn get_challenge_not_found_returns_404() {
    let resp = client()
        .get(format!("{BASE_URL}/challenge/00000000000000000000"))
        .send()
        .expect("GET /challenge/nonexistent");

    assert_eq!(resp.status(), 404);

    let body: ErrorResponse = resp.json().expect("parse error JSON");
    assert!(!body.error.is_empty(), "error field must be non-empty");
}
