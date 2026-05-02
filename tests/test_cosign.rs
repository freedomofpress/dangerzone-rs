//! Integration-style tests using fixtures captured from real cosign signed
//! images. The unit-level tests for parsers, log-index handling, and digest
//! plumbing live in the `mod tests` block of `src/cosign.rs`; this file
//! exercises the full verify path against on-disk fixtures.
//!
//! The fixtures are arranged as:
//!   - tests/assets/signatures/valid/<digest>.json     — must verify
//!   - tests/assets/signatures/invalid/<digest>.json   — must NOT verify
//!   - tests/assets/signatures/tampered/<digest>.json  — must NOT verify
//!
//! The filename's stem is the image digest the signature claims to cover,
//! which means the fixtures also exercise the `docker-manifest-digest` ←→
//! filename binding that the on-disk format relies on.

use std::fs;
use std::path::{Path, PathBuf};

use dangerzone_rs::cosign::{verify_signatures, CosignSignature};

const ASSETS_PATH: &str = "tests/assets";
const TEST_PUBKEY_FILENAME: &str = "test.pub.key";

fn test_pubkey_pem() -> String {
    fs::read_to_string(Path::new(ASSETS_PATH).join(TEST_PUBKEY_FILENAME))
        .expect("Failed to read test public key")
}

fn fixture_dir(name: &str) -> PathBuf {
    Path::new(ASSETS_PATH).join("signatures").join(name)
}

fn find_signature_files(dir: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                files.extend(find_signature_files(&path));
            } else if path.extension().and_then(|s| s.to_str()) == Some("json") {
                files.push(path);
            }
        }
    }
    files.sort();
    files
}

fn load_signature(path: &Path) -> Vec<CosignSignature> {
    let data = fs::read_to_string(path).expect("Failed to read signature file");
    serde_json::from_str(&data).expect("Failed to parse signature JSON")
}

/// Every fixture in `valid/` must verify against the test public key, and
/// the digest encoded in the filename must be the digest the signature
/// payload covers. If either of these regresses the test fails.
#[test]
fn valid_fixtures_all_verify() {
    let pubkey_pem = test_pubkey_pem();
    let files = find_signature_files(&fixture_dir("valid"));
    assert!(!files.is_empty(), "No valid signature fixtures present");

    for file in &files {
        let sigs = load_signature(file);
        assert!(!sigs.is_empty(), "Empty signature file: {:?}", file);
        let digest = file.file_stem().unwrap().to_string_lossy();
        verify_signatures(&sigs, &digest, &pubkey_pem)
            .unwrap_or_else(|e| panic!("Valid fixture {file:?} failed to verify: {e}"));
    }
}

/// Format-malformed fixtures in `invalid/` must FAIL to verify.
///
/// The fixture suite contains two distinct categories of "invalid":
///   1. Format-malformed fixtures (non-base64 signature bytes, non-base64
///      payload, etc.) — these MUST be rejected by an offline verifier.
///   2. Fixtures with a valid offline signature but invalid Rekor metadata
///      (e.g. tampered `SignedEntryTimestamp`, malformed bundle body).
///      These are detectable only by an *online* Rekor-backed verifier.
///      Since this codebase deliberately performs offline verification, we
///      do not require the offline verifier to reject them. They still
///      provide value: the rollback-detection / log-index code paths
///      consume them.
///
/// The previous version of this test used `.any(...)`, which would silently
/// accept a regression that made a malformed-format fixture verify. We now
/// enumerate the malformed-format files explicitly and assert each fails.
#[test]
fn malformed_format_invalid_fixtures_fail() {
    let pubkey_pem = test_pubkey_pem();
    let files = find_signature_files(&fixture_dir("invalid"));
    assert!(!files.is_empty(), "No invalid signature fixtures present");

    // Stems of fixtures whose *format* (not just Rekor metadata) is broken.
    // These must all fail offline verification.
    let format_broken: &[&str] = &[
        // Base64Signature is the literal text "Invalid base64 signature".
        "19e8eacd75879d05f6621c2ea8dd955e68ee3e07b41b9d53f4c8cc9929a68a67",
        // Payload is the literal text "Invalid base64 payload".
        "220b52200e3e47b1b42010667fcaa9338681e64dd3e34a34873866cb051d694e",
    ];

    let mut checked = 0;
    for stem in format_broken {
        let file = files
            .iter()
            .find(|f| f.file_stem().and_then(|s| s.to_str()) == Some(stem))
            .unwrap_or_else(|| panic!("missing fixture for stem {stem}"));
        let sigs = load_signature(file);
        let digest = file.file_stem().unwrap().to_string_lossy();
        let result = verify_signatures(&sigs, &digest, &pubkey_pem);
        assert!(
            result.is_err(),
            "Format-broken fixture {file:?} unexpectedly verified — \
             this would be a security regression"
        );
        checked += 1;
    }
    assert_eq!(checked, format_broken.len());
}

/// Tampered fixtures must all fail verification.
#[test]
fn tampered_fixtures_all_fail() {
    let pubkey_pem = test_pubkey_pem();
    let files = find_signature_files(&fixture_dir("tampered"));
    assert!(!files.is_empty(), "No tampered signature fixtures present");

    for file in &files {
        let sigs = load_signature(file);
        let digest = file.file_stem().unwrap().to_string_lossy();
        let result = verify_signatures(&sigs, &digest, &pubkey_pem);
        assert!(
            result.is_err(),
            "Tampered fixture {file:?} verified successfully — security regression"
        );
    }
}

/// A valid fixture, verified against the *wrong* digest, must still fail.
/// This pins the `payload.docker-manifest-digest` ↔ caller-provided digest
/// binding so a regression that ever skipped that check would be caught.
#[test]
fn valid_fixture_fails_with_wrong_digest() {
    let pubkey_pem = test_pubkey_pem();
    let files = find_signature_files(&fixture_dir("valid"));
    let file = files.first().expect("need at least one valid fixture");
    let sigs = load_signature(file);
    let wrong_digest = "0000000000000000000000000000000000000000000000000000000000000000";
    let err = verify_signatures(&sigs, wrong_digest, &pubkey_pem)
        .expect_err("verification with wrong digest must fail");
    // Walk the anyhow error chain looking for the digest-mismatch cause.
    let chain: Vec<String> = err.chain().map(|e| e.to_string()).collect();
    assert!(
        chain.iter().any(|s| s.contains("Digest mismatch")),
        "expected digest-mismatch in error chain, got: {chain:?}"
    );
}

/// A valid fixture, verified against the *wrong* public key, must fail with
/// a cryptographic error (not, say, a parse error that's silently treated
/// as success).
#[test]
fn valid_fixture_fails_with_wrong_key() {
    use p256::{
        ecdsa::SigningKey,
        pkcs8::{EncodePublicKey, LineEnding},
    };
    use rand_core::OsRng;

    let other_pem = SigningKey::random(&mut OsRng)
        .verifying_key()
        .to_public_key_pem(LineEnding::LF)
        .unwrap();

    let files = find_signature_files(&fixture_dir("valid"));
    let file = files.first().expect("need at least one valid fixture");
    let sigs = load_signature(file);
    let digest = file.file_stem().unwrap().to_string_lossy();
    assert!(
        verify_signatures(&sigs, &digest, &other_pem).is_err(),
        "verification with wrong key must fail"
    );
}
