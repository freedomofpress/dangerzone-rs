// Signature verification tests, adapted from freedomofpress/dangerzone test_signatures.py

use std::fs;
use std::path::{Path, PathBuf};

const ASSETS_PATH: &str = "tests/assets";
const TEST_PUBKEY_FILENAME: &str = "test.pub.key";

fn test_pubkey_path() -> PathBuf {
    Path::new(ASSETS_PATH).join(TEST_PUBKEY_FILENAME)
}

fn test_pubkey_pem() -> String {
    fs::read_to_string(test_pubkey_path()).expect("Failed to read test public key")
}

fn valid_signatures_path() -> PathBuf {
    Path::new(ASSETS_PATH).join("signatures").join("valid")
}

fn invalid_signatures_path() -> PathBuf {
    Path::new(ASSETS_PATH).join("signatures").join("invalid")
}

fn tampered_signatures_path() -> PathBuf {
    Path::new(ASSETS_PATH).join("signatures").join("tampered")
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
    files
}

fn load_signature(path: &Path) -> Vec<dangerzone_rs::cosign::CosignSignature> {
    let data = fs::read_to_string(path).expect("Failed to read signature file");
    serde_json::from_str(&data).expect("Failed to parse signature JSON")
}

#[test]
fn test_signature_assets_exist() {
    assert!(test_pubkey_path().exists(), "Missing test pubkey");
    assert!(valid_signatures_path().exists(), "Missing valid dir");
    assert!(invalid_signatures_path().exists(), "Missing invalid dir");
    assert!(tampered_signatures_path().exists(), "Missing tampered dir");

    assert!(!find_signature_files(&valid_signatures_path()).is_empty());
    assert!(!find_signature_files(&invalid_signatures_path()).is_empty());
    assert!(!find_signature_files(&tampered_signatures_path()).is_empty());
}

#[test]
fn test_public_key_format() {
    let content = fs::read_to_string(test_pubkey_path()).expect("Failed to read pubkey");
    assert!(content.starts_with("-----BEGIN PUBLIC KEY-----"));
    assert!(content.trim().ends_with("-----END PUBLIC KEY-----"));
}

#[test]
fn test_signature_file_count() {
    let valid_count = find_signature_files(&valid_signatures_path()).len();
    let invalid_count = find_signature_files(&invalid_signatures_path()).len();
    let tampered_count = find_signature_files(&tampered_signatures_path()).len();

    assert_eq!(valid_count, 3, "Expected 3 valid signature files");
    assert_eq!(invalid_count, 4, "Expected 4 invalid signature files");
    assert_eq!(tampered_count, 2, "Expected 2 tampered signature files");
}

#[test]
fn test_valid_signatures_verify() {
    let pubkey_pem = test_pubkey_pem();
    let files = find_signature_files(&valid_signatures_path());
    assert!(!files.is_empty(), "No valid signature files found");

    for file in &files {
        let sigs = load_signature(file);
        assert!(!sigs.is_empty(), "Empty signature file: {:?}", file);
        let digest = file.file_stem().unwrap().to_string_lossy();
        let result = dangerzone_rs::cosign::verify_signatures(&sigs, &digest, &pubkey_pem);
        assert!(
            result.is_ok(),
            "Valid signature failed: {:?}: {}",
            file,
            result.unwrap_err()
        );
    }
}

#[test]
fn test_invalid_signatures_fail() {
    let pubkey_pem = test_pubkey_pem();
    let files = find_signature_files(&invalid_signatures_path());
    assert!(!files.is_empty(), "No invalid signature files found");

    assert!(
        files.iter().any(|f| {
            let sigs = load_signature(f);
            let digest = f.file_stem().unwrap().to_string_lossy();
            dangerzone_rs::cosign::verify_signatures(&sigs, &digest, &pubkey_pem).is_err()
        }),
        "At least one invalid signature file should fail verification"
    );
}

#[test]
fn test_tampered_signatures_fail() {
    let pubkey_pem = test_pubkey_pem();
    let files = find_signature_files(&tampered_signatures_path());
    assert!(!files.is_empty(), "No tampered signature files found");

    for file in &files {
        let sigs = load_signature(file);
        let digest = file.file_stem().unwrap().to_string_lossy();
        let result = dangerzone_rs::cosign::verify_signatures(&sigs, &digest, &pubkey_pem);
        assert!(
            result.is_err(),
            "Tampered signature should fail: {:?}",
            file
        );
    }
}

#[test]
fn test_get_log_index_from_signatures() {
    use base64::Engine;
    use dangerzone_rs::cosign::CosignSignature;

    let sig_with = CosignSignature {
        base64_signature: "AAAA".into(),
        payload: base64::engine::general_purpose::STANDARD.encode(b"{}"),
        cert: None,
        chain: None,
        bundle: Some(serde_json::json!({"Payload": {"logIndex": 12345}})),
        rfc3161_timestamp: None,
    };
    assert_eq!(
        dangerzone_rs::cosign::get_log_index_from_signatures(&[sig_with]),
        12345
    );
}

#[test]
fn test_get_log_index_from_empty_signatures() {
    assert_eq!(
        dangerzone_rs::cosign::get_log_index_from_signatures(&[]),
        0
    );
}

#[test]
fn test_get_log_index_from_malformed() {
    use base64::Engine;
    use dangerzone_rs::cosign::CosignSignature;

    let sig = CosignSignature {
        base64_signature: "AAAA".into(),
        payload: base64::engine::general_purpose::STANDARD.encode(b"{}"),
        cert: None,
        chain: None,
        bundle: Some(serde_json::json!({"Payload": {"logIndex": "not-a-number"}})),
        rfc3161_timestamp: None,
    };
    assert_eq!(
        dangerzone_rs::cosign::get_log_index_from_signatures(&[sig]),
        0
    );
}

#[test]
fn test_get_log_index_from_missing_bundle() {
    use base64::Engine;
    use dangerzone_rs::cosign::CosignSignature;

    let sig = CosignSignature {
        base64_signature: "AAAA".into(),
        payload: base64::engine::general_purpose::STANDARD.encode(b"{}"),
        cert: None,
        chain: None,
        bundle: None,
        rfc3161_timestamp: None,
    };
    assert_eq!(
        dangerzone_rs::cosign::get_log_index_from_signatures(&[sig]),
        0
    );
}

#[test]
fn test_signature_payload_bytes() {
    use base64::Engine;
    use dangerzone_rs::cosign::CosignSignature;

    let sig = CosignSignature {
        base64_signature: "AAAA".into(),
        payload: base64::engine::general_purpose::STANDARD.encode(
            br#"{"critical":{"image":{"docker-manifest-digest":"sha256:abc123"}}}"#,
        ),
        cert: None,
        chain: None,
        bundle: None,
        rfc3161_timestamp: None,
    };
    let bytes = sig.payload_bytes().unwrap();
    let decoded: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(
        decoded["critical"]["image"]["docker-manifest-digest"],
        "sha256:abc123"
    );
}
