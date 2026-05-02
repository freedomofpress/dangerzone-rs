//! Cosign signature verification for Dangerzone container images.
//!
//! This module verifies container image signatures offline using the `sigstore`
//! crate. It is compatible with the Python Dangerzone implementation's
//! signature format and storage layout (`$XDG_DATA_HOME/dangerzone/signatures/`).
//!
//! # Threat model
//!
//! All registry-supplied data is treated as untrusted. The trusted root is the
//! caller-provided public key (typically embedded at compile time). The flow:
//!
//! 1. Resolve the remote digest (still untrusted).
//! 2. Fetch the signature manifest pointing to a layer blob.
//! 3. Fetch the blob and verify its SHA-256 matches the manifest descriptor
//!    (prevents a registry from serving a different blob than is referenced).
//! 4. Verify the signature over the blob with the trusted public key.
//! 5. Verify the payload's `docker-manifest-digest` matches the resolved digest.
//! 6. Pull the image **by digest** so podman cannot resolve a different image
//!    from the same tag.
//! 7. Persist signatures alongside a monotonically advancing Rekor log index;
//!    on reload, compare against the stored index to detect rollback.

use anyhow::{anyhow, bail, Context, Result};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use sigstore::crypto::{CosignVerificationKey, Signature as SigstoreSignature};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::registry::{
    download_signatures_from_registry, get_remote_image_digest, ImageRef,
};

/// 1 MiB.
const MIB: u64 = 1024 * 1024;
/// Maximum size of a stored signature file we will read from disk.
const MAX_STORED_SIG_BYTES: u64 = MIB;
/// Maximum size of `podman image inspect` stdout we are willing to parse.
/// Podman is locally trusted, but bounding the read keeps a runaway/garbled
/// process from eating arbitrary memory.
const MAX_PODMAN_INSPECT_BYTES: usize = MIB as usize;
/// Suffix used for the per-image Rekor log-index high-water mark file.
const LAST_LOG_INDEX_SUFFIX: &str = ".last_log_index";

/// A validated SHA-256 digest in lowercase hex form (no `sha256:` prefix).
///
/// Constructing this type guarantees the value is exactly 64 lowercase hex
/// characters; downstream callers can therefore safely use it in filenames
/// without further validation.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Sha256Digest(String);

impl Sha256Digest {
    /// Parse a hex string as a SHA-256 digest. Accepts an optional `sha256:`
    /// prefix and rejects anything that is not exactly 64 lowercase hex chars.
    pub fn parse(s: &str) -> Result<Self> {
        let stripped = s.strip_prefix("sha256:").unwrap_or(s);
        if stripped.len() != 64 || !stripped.bytes().all(|b| b.is_ascii_hexdigit()) {
            bail!("Invalid SHA-256 digest: {s:?}");
        }
        Ok(Self(stripped.to_ascii_lowercase()))
    }

    /// The bare 64-character hex representation.
    pub fn as_hex(&self) -> &str {
        &self.0
    }

    /// The canonical OCI form `sha256:<hex>`.
    pub fn prefixed(&self) -> String {
        format!("sha256:{}", self.0)
    }
}

impl std::fmt::Display for Sha256Digest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// A cosign signature in the format produced by `cosign download signature`.
///
/// Field names use `PascalCase` to match the on-disk format produced by the
/// upstream `cosign` CLI. New optional fields may be added in the future, so
/// callers are encouraged to construct values via [`CosignSignature::new`]
/// (and the `..Default::default()` style update syntax) rather than relying
/// on the exact set of fields.
#[derive(Debug, Deserialize, Serialize, Clone, Default)]
#[serde(rename_all = "PascalCase")]
pub struct CosignSignature {
    pub base64_signature: String,
    pub payload: String,
    pub cert: Option<String>,
    pub chain: Option<String>,
    pub bundle: Option<serde_json::Value>,
    #[serde(rename = "RFC3161Timestamp")]
    pub rfc3161_timestamp: Option<serde_json::Value>,
}

impl CosignSignature {
    /// Construct a new signature with no certificate / bundle / timestamp.
    pub fn new(base64_signature: String, payload: String) -> Self {
        Self {
            base64_signature,
            payload,
            cert: None,
            chain: None,
            bundle: None,
            rfc3161_timestamp: None,
        }
    }

    /// Decode the base64-encoded payload into raw bytes.
    pub fn payload_bytes(&self) -> Result<Vec<u8>> {
        BASE64
            .decode(&self.payload)
            .context("Decoding cosign signature payload as base64")
    }

    /// Extract the Rekor log index from the bundle, if present.
    /// Rekor indices are unsigned, but historical fixtures may serialize them
    /// in surprising ways; we accept any non-negative integer.
    pub fn log_index(&self) -> Option<u64> {
        let payload = self.bundle.as_ref()?.get("Payload")?;
        payload
            .get("logIndex")
            .and_then(|v| v.as_u64())
            .or_else(|| {
                payload
                    .get("logIndex")
                    .and_then(|v| v.as_i64())
                    .and_then(|i| u64::try_from(i).ok())
            })
    }
}

// Internal payload structures (cosign "simple signing" envelope).

#[derive(Debug, Deserialize)]
struct SignaturePayload {
    critical: PayloadCritical,
}

#[derive(Debug, Deserialize)]
struct PayloadCritical {
    image: PayloadImage,
}

#[derive(Debug, Deserialize)]
struct PayloadImage {
    #[serde(rename = "docker-manifest-digest")]
    docker_manifest_digest: String,
}

/// Verify a single cosign signature against a public key and expected image
/// digest. Performs offline verification only, no network calls to Rekor.
pub fn verify_signature(
    signature: &CosignSignature,
    image_digest: &str,
    pubkey_pem: &str,
) -> Result<()> {
    let expected = Sha256Digest::parse(image_digest)?;
    verify_signature_inner(signature, &expected, pubkey_pem)
}

fn verify_signature_inner(
    signature: &CosignSignature,
    expected_digest: &Sha256Digest,
    pubkey_pem: &str,
) -> Result<()> {
    let payload_bytes = signature.payload_bytes()?;
    let payload: SignaturePayload = serde_json::from_slice(&payload_bytes)
        .context("Parsing cosign signature payload as JSON")?;

    let payload_digest = Sha256Digest::parse(&payload.critical.image.docker_manifest_digest)
        .context("Parsing payload docker-manifest-digest")?;
    if &payload_digest != expected_digest {
        bail!(
            "Digest mismatch: payload says '{}', expected '{}'",
            payload_digest,
            expected_digest
        );
    }

    let key = CosignVerificationKey::try_from_pem(pubkey_pem.as_bytes())
        .context("Parsing trusted public key from PEM")?;
    key.verify_signature(
        SigstoreSignature::Base64Encoded(signature.base64_signature.as_bytes()),
        &payload_bytes,
    )
    .context("Cryptographic signature verification failed")?;

    Ok(())
}

/// Verify a list of cosign signatures, requiring **all** to be valid.
///
/// Note: cosign policy is typically "at least one valid signature". We require
/// all of them because in this codebase we only persist signatures that were
/// previously fully verified, so any failure on reload indicates tampering.
pub fn verify_signatures(
    signatures: &[CosignSignature],
    image_digest: &str,
    pubkey_pem: &str,
) -> Result<()> {
    if signatures.is_empty() {
        bail!("No signatures provided");
    }
    let expected = Sha256Digest::parse(image_digest)?;
    for (i, sig) in signatures.iter().enumerate() {
        verify_signature_inner(sig, &expected, pubkey_pem)
            .with_context(|| format!("Signature {i} failed"))?;
    }
    Ok(())
}

/// Decode the DER SPKI bytes from a PEM-encoded public key. Hashing the DER
/// (rather than the PEM text) means cosmetic differences in the PEM file
/// (line endings, whitespace) do not change the fingerprint.
fn pem_to_der(pem: &str) -> Result<Vec<u8>> {
    const BEGIN: &str = "-----BEGIN PUBLIC KEY-----";
    const END: &str = "-----END PUBLIC KEY-----";
    let begin = pem
        .find(BEGIN)
        .ok_or_else(|| anyhow!("Public key PEM is missing BEGIN marker"))?;
    let after_begin = begin + BEGIN.len();
    let end = pem[after_begin..]
        .find(END)
        .ok_or_else(|| anyhow!("Public key PEM is missing END marker"))?;
    let body: String = pem[after_begin..after_begin + end]
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    BASE64
        .decode(body.as_bytes())
        .context("Decoding public key PEM body as base64")
}

/// Compute the trust-root fingerprint for a public key by hashing its DER
/// SubjectPublicKeyInfo bytes.
fn pubkey_fingerprint(pubkey_pem: &str) -> Result<String> {
    let der = pem_to_der(pubkey_pem)?;
    Ok(hex::encode(Sha256::digest(&der)))
}

/// Resolve the dangerzone data directory according to platform conventions.
///
/// On macOS this is `$HOME/Library/Application Support/dangerzone`. On other
/// platforms it follows the XDG basedir spec: `$XDG_DATA_HOME/dangerzone` if
/// set, otherwise `$HOME/.local/share/dangerzone`. If neither variable is
/// set we return an error rather than silently falling back to `/tmp`.
fn data_dir() -> Result<PathBuf> {
    #[cfg(target_os = "macos")]
    {
        if let Some(home) = std::env::var_os("HOME") {
            return Ok(PathBuf::from(home).join("Library/Application Support/dangerzone"));
        }
        bail!("Cannot determine data directory: $HOME is not set");
    }

    #[cfg(not(target_os = "macos"))]
    {
        if let Some(xdg) = std::env::var_os("XDG_DATA_HOME") {
            let p = PathBuf::from(xdg);
            if p.is_absolute() {
                return Ok(p.join("dangerzone"));
            }
        }
        if let Some(home) = std::env::var_os("HOME") {
            return Ok(PathBuf::from(home).join(".local/share/dangerzone"));
        }
        bail!("Cannot determine data directory: neither $XDG_DATA_HOME nor $HOME is set");
    }
}

/// Return the directory for storing signatures for a given public key.
/// Uses SHA-256(DER SPKI) as directory name.
pub fn signatures_dir(pubkey_pem: &str) -> Result<PathBuf> {
    let fingerprint = pubkey_fingerprint(pubkey_pem)?;
    Ok(data_dir()?.join("signatures").join(fingerprint))
}

/// Atomically write `contents` to `path` by writing to a sibling temp file
/// and renaming. On Unix the rename is atomic within the same filesystem.
///
/// The tmp file name embeds the process id and a per-call counter so that
/// two concurrent writers targeting the same final path do not race on the
/// same tmp file (which could otherwise leave a partial write visible if
/// one writer's `rename` ran while the other was still writing).
fn atomic_write(path: &Path, contents: &[u8]) -> Result<()> {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);

    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("Path has no parent: {}", path.display()))?;
    std::fs::create_dir_all(parent)
        .with_context(|| format!("Creating directory {}", parent.display()))?;
    let basename = path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("dangerzone");
    let pid = std::process::id();
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let tmp = parent.join(format!(".{basename}.{pid}.{n}.tmp"));
    std::fs::write(&tmp, contents)
        .with_context(|| format!("Writing temp file {}", tmp.display()))?;
    std::fs::rename(&tmp, path)
        .with_context(|| format!("Renaming {} to {}", tmp.display(), path.display()))?;
    Ok(())
}

/// Per-image high-water-mark file path. Keying on the image digest means
/// two different images signed by the same key don't share a counter:
/// otherwise image A's logIndex would lock out image B forever.
fn last_log_index_path(key_dir: &Path, digest: &Sha256Digest) -> PathBuf {
    key_dir.join(format!("{}{}", digest.as_hex(), LAST_LOG_INDEX_SUFFIX))
}

/// Read the persisted Rekor log-index high-water mark for a given image.
fn read_last_log_index(key_dir: &Path, digest: &Sha256Digest) -> u64 {
    std::fs::read_to_string(last_log_index_path(key_dir, digest))
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0)
}

/// Persist the Rekor log-index high-water mark for a given image,
/// only advancing it forward.
fn advance_last_log_index(key_dir: &Path, digest: &Sha256Digest, new_index: u64) -> Result<()> {
    let current = read_last_log_index(key_dir, digest);
    if new_index > current {
        atomic_write(
            &last_log_index_path(key_dir, digest),
            new_index.to_string().as_bytes(),
        )?;
    }
    Ok(())
}

/// Store verified signatures to disk and advance the last-seen Rekor log
/// index. The caller is responsible for ensuring the signatures have already
/// been verified.
pub fn store_signatures(
    signatures: &[CosignSignature],
    image_digest: &str,
    pubkey_pem: &str,
) -> Result<()> {
    let digest = Sha256Digest::parse(image_digest)?;
    let key_dir = signatures_dir(pubkey_pem)?;
    std::fs::create_dir_all(&key_dir)
        .with_context(|| format!("Creating signatures directory {}", key_dir.display()))?;

    let path = key_dir.join(format!("{}.json", digest.as_hex()));
    let body = serde_json::to_vec_pretty(signatures).context("Serializing signatures to JSON")?;
    atomic_write(&path, &body)?;

    if let Some(idx) = signatures.iter().filter_map(|s| s.log_index()).max() {
        advance_last_log_index(&key_dir, &digest, idx)?;
    }

    Ok(())
}

/// Load and re-verify stored signatures for an image digest. Also enforces
/// that the persisted Rekor log-index high-water mark has not regressed,
/// which detects offline rollback attacks where a local attacker replaces
/// stored signatures with an older (still validly signed) set.
pub fn load_signatures(image_digest: &str, pubkey_pem: &str) -> Result<Vec<CosignSignature>> {
    let key_dir = signatures_dir(pubkey_pem)?;
    load_signatures_from(image_digest, pubkey_pem, &key_dir)
}

/// Load and re-verify stored signatures from a specific directory.
///
/// Crate-internal: callers that go through [`load_signatures`] always use a
/// directory derived from the public key's fingerprint, so the on-disk path
/// is bound to the trust root. Exposing this function publicly would let a
/// caller pass an arbitrary directory and break that binding, so it stays
/// crate-private.
pub(crate) fn load_signatures_from(
    image_digest: &str,
    pubkey_pem: &str,
    key_dir: &Path,
) -> Result<Vec<CosignSignature>> {
    let digest = Sha256Digest::parse(image_digest)?;
    let path = key_dir.join(format!("{}.json", digest.as_hex()));
    if !path.exists() {
        bail!(
            "No signatures found for digest 'sha256:{}'. Run `dangerzone-rs upgrade` first.",
            digest
        );
    }

    let file = std::fs::File::open(&path)
        .with_context(|| format!("Opening signature file {}", path.display()))?;
    let mut data = Vec::new();
    file.take(MAX_STORED_SIG_BYTES)
        .read_to_end(&mut data)
        .with_context(|| format!("Reading signature file {}", path.display()))?;

    let signatures: Vec<CosignSignature> =
        serde_json::from_slice(&data).context("Parsing stored signatures as JSON")?;
    verify_signatures(&signatures, image_digest, pubkey_pem)?;

    // Rollback protection (per image): once we've seen *any* signature with
    // a logIndex for this image, every subsequent loaded signature for this
    // image must also carry a logIndex, and the maximum loaded logIndex
    // must be at least the persisted high-water mark.
    //
    // The earlier permissive form ("ignore sigs without a logIndex") opened
    // a downgrade vector: an attacker who could write the on-disk file
    // could replace a bundled set with an older bundle-less set and we'd
    // happily accept it. Cosign has emitted bundles for years and our own
    // download path requires them, so failing closed here costs us nothing
    // and removes the downgrade.
    let stored_high = read_last_log_index(key_dir, &digest);
    if stored_high > 0 {
        let loaded_high = max_log_index(&signatures);
        let all_have_index = signatures.iter().all(|s| s.log_index().is_some());
        if !all_have_index {
            bail!(
                "Stored signatures for image sha256:{digest} are missing Rekor log-index \
                 metadata, but a high-water mark ({stored_high}) is on file. This may \
                 indicate a rollback attack."
            );
        }
        if loaded_high < stored_high {
            bail!(
                "Rekor log index regressed for image sha256:{digest}: stored high-water mark \
                 is {stored_high}, loaded signatures top out at {loaded_high}. This may \
                 indicate a rollback attack."
            );
        }
    }

    Ok(signatures)
}

/// Return the maximum Rekor log index across a set of signatures, or 0 if
/// none of them carry a bundle / log index.
fn max_log_index(signatures: &[CosignSignature]) -> u64 {
    signatures
        .iter()
        .filter_map(|s| s.log_index())
        .max()
        .unwrap_or(0)
}

/// Get the SHA-256 digest of a locally cached container image via
/// `podman image inspect`. Selects the `RepoDigest` that matches the parsed
/// `<registry>/<repository>` of `image_name`. We refuse to fall back to any
/// other entry: returning the digest of an unrelated repository's image
/// would let a local attacker who pre-populated podman storage influence
/// which image we then claim to have verified.
pub fn get_local_image_digest(image_name: &str) -> Result<Sha256Digest> {
    let parsed = ImageRef::parse(image_name)?;
    let expected_prefix = format!("{}/{}@sha256:", parsed.registry, parsed.repository);

    let mut child = std::process::Command::new("podman")
        .args([
            "image",
            "inspect",
            "--format",
            "{{json .RepoDigests}}",
            image_name,
        ])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .context("Running `podman image inspect`")?;

    let mut stdout_buf = Vec::new();
    if let Some(mut s) = child.stdout.take() {
        s.by_ref()
            .take(MAX_PODMAN_INSPECT_BYTES as u64 + 1)
            .read_to_end(&mut stdout_buf)
            .context("Reading podman inspect stdout")?;
        if stdout_buf.len() > MAX_PODMAN_INSPECT_BYTES {
            // Kill the child so we don't leak it; ignore errors here.
            let _ = child.kill();
            bail!("podman inspect output exceeds maximum allowed size");
        }
    }
    let output = child
        .wait_with_output()
        .context("Waiting for podman inspect")?;

    if !output.status.success() {
        bail!(
            "podman inspect failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }

    let stdout =
        String::from_utf8(stdout_buf).context("podman inspect output was not valid UTF-8")?;
    let repo_digests: Vec<String> =
        serde_json::from_str(stdout.trim()).context("Parsing RepoDigests from podman inspect")?;

    let matching = repo_digests
        .iter()
        .find(|d| d.starts_with(&expected_prefix))
        .ok_or_else(|| {
            anyhow!(
                "Image '{image_name}' has no RepoDigest for {}/{}. Run `dangerzone-rs upgrade` first.",
                parsed.registry,
                parsed.repository
            )
        })?;

    let (_, hex) = matching
        .split_once("@sha256:")
        .ok_or_else(|| anyhow!("Unexpected RepoDigest format: {matching}"))?;
    Sha256Digest::parse(hex)
}

/// Verify that a locally cached image has valid stored signatures.
pub fn verify_image(image_name: &str, pubkey_pem: &str) -> Result<()> {
    let digest = get_local_image_digest(image_name)?;
    let sigs = load_signatures(digest.as_hex(), pubkey_pem)?;
    crate::debugprint!(
        "Container image verified: {} signature(s) valid for sha256:{}",
        sigs.len(),
        &digest.as_hex()[..12]
    );
    Ok(())
}

/// Pull a container image **by digest** via podman, ensuring podman cannot
/// resolve a different image than the one whose signatures we just verified.
fn pull_image_by_digest(image: &ImageRef, digest: &Sha256Digest) -> Result<()> {
    let pull_ref = format!(
        "{}/{}@{}",
        image.registry,
        image.repository,
        digest.prefixed()
    );
    let mut cmd = std::process::Command::new("podman");
    cmd.args(["pull", &pull_ref]);
    if !crate::is_debug() {
        // Suppress podman's progress output ("Getting image source signatures",
        // "Copying blob ...", etc.) unless the user asked for verbose output.
        cmd.stdout(std::process::Stdio::null());
        cmd.stderr(std::process::Stdio::null());
    }
    let status = cmd.status().context("Running `podman pull`")?;
    if !status.success() {
        bail!("podman pull failed for '{pull_ref}'");
    }

    // Best-effort: also tag the pulled image with the original tag so that
    // subsequent runs can refer to it by name. Failure here is non-fatal.
    let tagged_ref = if let Some(tag) = &image.tag {
        format!("{}/{}:{tag}", image.registry, image.repository)
    } else {
        format!("{}/{}", image.registry, image.repository)
    };
    let mut tag_cmd = std::process::Command::new("podman");
    tag_cmd.args(["tag", &pull_ref, &tagged_ref]);
    if !crate::is_debug() {
        tag_cmd.stdout(std::process::Stdio::null());
        tag_cmd.stderr(std::process::Stdio::null());
    }
    let _ = tag_cmd.status();
    Ok(())
}

/// Download and verify signatures, then pull the image **by digest**, then
/// store the verified signatures. Pulling by digest after verification means
/// a registry compromise cannot serve unsigned content under the same tag.
pub fn upgrade_image(image_name: &str, pubkey_pem: &str) -> Result<()> {
    let image = ImageRef::parse(image_name)?;

    crate::debugprint!("Fetching remote digest...");
    let digest = get_remote_image_digest(image_name)?;
    crate::debugprint!("  sha256:{digest}");

    // Detect whether the locally cached image is already at the remote digest.
    // If `get_local_image_digest` errors (e.g. image not pulled yet), treat as
    // "not present" and proceed with the full pull.
    let already_up_to_date = match get_local_image_digest(image_name) {
        Ok(local) => local.as_hex() == digest.as_hex(),
        Err(_) => false,
    };

    crate::debugprint!("Downloading signatures...");
    let signatures = download_signatures_from_registry(image_name, &digest)?;
    crate::debugprint!("  {} signature(s)", signatures.len());

    crate::debugprint!("Verifying signatures...");
    verify_signatures(&signatures, digest.as_hex(), pubkey_pem)?;
    if crate::is_debug() {
        eprintln!(
            "  {} signature(s) verified against trusted key",
            signatures.len()
        );
    } else {
        let hex = digest.as_hex();
        let short = &hex[..hex.len().min(12)];
        eprintln!(
            "Verified {} signature(s) for sha256:{}…",
            signatures.len(),
            short
        );
    }

    if already_up_to_date {
        crate::debugprint!("Local image already matches remote digest, skipping pull.");
    } else {
        crate::debugprint!("Pulling image by digest...");
        pull_image_by_digest(&image, &digest)?;
    }

    // Re-store signatures unconditionally, even when the local image already
    // matches the remote digest. In the steady state this is a no-op rewrite
    // of the same bytes, but it covers three useful cases:
    //
    //   1. Repair: the on-disk signature file may be missing or corrupted,
    //      in which case `convert` would fail with "No signatures found...".
    //      Re-storing restores it from a freshly verified source.
    //
    //   2. Rollback high-water mark advancement: the registry may have
    //      gained additional signatures for the same digest carrying higher
    //      Rekor logIndex values. Re-storing advances the persisted
    //      high-water mark used for rollback detection.
    //
    //   3. Defense-in-depth: if a local attacker swapped or tampered with
    //      the stored signature JSON, an explicit upgrade re-establishes it
    //      from a freshly downloaded and verified source.
    //
    // Users don't need to know about any of this; the user-facing message
    // below stays focused on what they care about (image freshness and the
    // fact that signatures were re-verified against the trusted key).
    crate::debugprint!("Storing signatures...");
    store_signatures(&signatures, digest.as_hex(), pubkey_pem)?;

    if crate::is_debug() {
        eprintln!("Done");
    } else if already_up_to_date {
        eprintln!("Image already up to date, signatures re-verified");
    } else {
        eprintln!("Pulled image and stored signatures");
    }

    Ok(())
}

/// Default maximum age before an automatic freshness check is triggered
/// before a `convert`. 12 hours is a balance between catching new releases
/// quickly and not hitting the registry on every conversion.
pub const DEFAULT_UPGRADE_CHECK_INTERVAL: Duration = Duration::from_secs(12 * 60 * 60);

/// Path of the "last upgrade check" timestamp file. Lives next to the stored
/// signatures (under the public-key fingerprint directory) so it's bound to
/// the same trust root.
fn last_checked_path(pubkey_pem: &str) -> Result<PathBuf> {
    Ok(signatures_dir(pubkey_pem)?.join("last-checked"))
}

/// Read the last upgrade-check timestamp (Unix seconds). Missing or
/// malformed file is treated as "never checked".
fn read_last_checked(pubkey_pem: &str) -> Option<SystemTime> {
    let path = last_checked_path(pubkey_pem).ok()?;
    let raw = std::fs::read_to_string(&path).ok()?;
    let secs: u64 = raw.trim().parse().ok()?;
    Some(UNIX_EPOCH + Duration::from_secs(secs))
}

/// Persist the current time as the "last checked" timestamp. Best-effort:
/// failures to write are non-fatal (the next convert will simply re-check).
fn write_last_checked_now(pubkey_pem: &str) -> Result<()> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("System clock is before UNIX epoch")?;
    let path = last_checked_path(pubkey_pem)?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("Creating directory {}", parent.display()))?;
    }
    atomic_write(&path, now.as_secs().to_string().as_bytes())
}

/// Run [`upgrade_image`] if the last successful check is older than
/// `max_age`. Intended to be called before `convert` so that conversions
/// pick up new image versions automatically.
///
/// Behavior:
/// - If the last-checked timestamp is fresh (within `max_age`), this is a
///   no-op.
/// - Otherwise [`upgrade_image`] is invoked. On success, the timestamp is
///   advanced.
/// - On failure (e.g. no network, registry down), a warning is printed and
///   `Ok(())` is returned so the caller can continue with the locally
///   cached image. The timestamp is **not** advanced on failure, so a
///   subsequent run will retry.
pub fn maybe_upgrade_image_if_stale(
    image_name: &str,
    pubkey_pem: &str,
    max_age: Duration,
) -> Result<()> {
    if let Some(last) = read_last_checked(pubkey_pem) {
        match SystemTime::now().duration_since(last) {
            Ok(age) if age < max_age => {
                crate::debugprint!(
                    "Last upgrade check was {}s ago (< {}s); skipping.",
                    age.as_secs(),
                    max_age.as_secs()
                );
                return Ok(());
            }
            _ => {}
        }
    }

    crate::debugprint!("Running scheduled upgrade check...");
    match upgrade_image(image_name, pubkey_pem) {
        Ok(()) => {
            // Best-effort timestamp update; not advancing it just means the
            // next run will redo a (cheap) digest check.
            if let Err(e) = write_last_checked_now(pubkey_pem) {
                crate::debugprint!("Warning: failed to record last-checked timestamp: {e}");
            }
            Ok(())
        }
        Err(e) => {
            eprintln!(
                "Warning: upgrade check failed: {e}. Proceeding with locally cached image."
            );
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::{
        ecdsa::{signature::Signer, DerSignature, SigningKey},
        pkcs8::{EncodePublicKey, LineEnding},
    };
    use rand_core::OsRng;

    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn generate_test_keypair() -> (SigningKey, String) {
        let signing_key = SigningKey::random(&mut OsRng);
        let pem = signing_key
            .verifying_key()
            .to_public_key_pem(LineEnding::LF)
            .expect("PEM encode failed");
        (signing_key, pem)
    }

    fn sample_digest() -> &'static str {
        "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
    }

    fn make_signature(signing_key: &SigningKey, image_digest: &str) -> CosignSignature {
        let payload_bytes = serde_json::to_vec(&serde_json::json!({
            "critical": {
                "image": {"docker-manifest-digest": format!("sha256:{image_digest}")},
                "identity": {"docker-reference": "ghcr.io/freedomofpress/dangerzone/v1"},
                "type": "cosign container image signature"
            },
            "optional": null
        }))
        .unwrap();
        let sig: DerSignature = signing_key.sign(&payload_bytes);
        CosignSignature {
            base64_signature: BASE64.encode(sig.as_bytes()),
            payload: BASE64.encode(&payload_bytes),
            cert: None,
            chain: None,
            bundle: None,
            rfc3161_timestamp: None,
        }
    }

    #[test]
    fn digest_parse_accepts_valid() {
        assert!(Sha256Digest::parse(sample_digest()).is_ok());
        assert!(Sha256Digest::parse(&format!("sha256:{}", sample_digest())).is_ok());
    }

    #[test]
    fn digest_parse_rejects_invalid() {
        assert!(Sha256Digest::parse("").is_err());
        assert!(Sha256Digest::parse("../etc/passwd").is_err());
        assert!(Sha256Digest::parse("XYZ").is_err());
        // Wrong length:
        assert!(Sha256Digest::parse("abcd").is_err());
        // Non-hex chars:
        assert!(Sha256Digest::parse(&"g".repeat(64)).is_err());
    }

    #[test]
    fn digest_parse_normalizes_uppercase_to_lowercase() {
        // Uppercase hex is valid input but is canonicalized to lowercase so
        // the same content always produces the same on-disk filename.
        let upper = sample_digest().to_uppercase();
        let d = Sha256Digest::parse(&upper).unwrap();
        assert_eq!(d.as_hex(), sample_digest());
    }

    #[test]
    fn verify_valid_signature() {
        let (sk, pk_pem) = generate_test_keypair();
        let sig = make_signature(&sk, sample_digest());
        assert!(verify_signature(&sig, sample_digest(), &pk_pem).is_ok());
    }

    #[test]
    fn verify_wrong_image_digest() {
        let (sk, pk_pem) = generate_test_keypair();
        let sig = make_signature(&sk, sample_digest());
        let other = "0000000000000000000000000000000000000000000000000000000000000000";
        let err = verify_signature(&sig, other, &pk_pem).unwrap_err();
        assert!(err.to_string().contains("Digest mismatch"));
    }

    #[test]
    fn verify_wrong_key() {
        let (sk, _) = generate_test_keypair();
        let (_, pk_pem_other) = generate_test_keypair();
        let sig = make_signature(&sk, sample_digest());
        assert!(verify_signature(&sig, sample_digest(), &pk_pem_other).is_err());
    }

    #[test]
    fn verify_tampered_payload() {
        let (sk, pk_pem) = generate_test_keypair();
        let mut sig = make_signature(&sk, sample_digest());
        let mut bytes = BASE64.decode(&sig.payload).unwrap();
        *bytes.last_mut().unwrap() ^= 0xff;
        sig.payload = BASE64.encode(&bytes);
        assert!(verify_signature(&sig, sample_digest(), &pk_pem).is_err());
    }

    #[test]
    fn verify_tampered_signature_bytes() {
        let (sk, pk_pem) = generate_test_keypair();
        let mut sig = make_signature(&sk, sample_digest());
        let mut bytes = BASE64.decode(&sig.base64_signature).unwrap();
        *bytes.last_mut().unwrap() ^= 0xff;
        sig.base64_signature = BASE64.encode(&bytes);
        assert!(verify_signature(&sig, sample_digest(), &pk_pem).is_err());
    }

    #[test]
    fn verify_signatures_empty_list() {
        let (_, pk_pem) = generate_test_keypair();
        assert!(verify_signatures(&[], sample_digest(), &pk_pem).is_err());
    }

    #[test]
    fn verify_signatures_one_invalid_among_valid() {
        let (sk, pk_pem) = generate_test_keypair();
        let (sk2, _) = generate_test_keypair();
        let sigs = vec![
            make_signature(&sk, sample_digest()),
            make_signature(&sk2, sample_digest()),
        ];
        assert!(verify_signatures(&sigs, sample_digest(), &pk_pem).is_err());
    }

    #[test]
    fn store_and_load_signatures() {
        let (sk, pk_pem) = generate_test_keypair();
        let sigs = vec![make_signature(&sk, sample_digest())];
        let tmp = tempfile::tempdir().unwrap();

        let _guard = ENV_LOCK.lock().unwrap();
        let saved_xdg = std::env::var_os("XDG_DATA_HOME");
        let saved_home = std::env::var_os("HOME");
        std::env::set_var("XDG_DATA_HOME", tmp.path());
        std::env::set_var("HOME", tmp.path());

        store_signatures(&sigs, sample_digest(), &pk_pem).unwrap();
        let loaded = load_signatures(sample_digest(), &pk_pem).unwrap();
        assert_eq!(loaded.len(), 1);

        match saved_xdg {
            Some(v) => std::env::set_var("XDG_DATA_HOME", v),
            None => std::env::remove_var("XDG_DATA_HOME"),
        }
        match saved_home {
            Some(v) => std::env::set_var("HOME", v),
            None => std::env::remove_var("HOME"),
        }
    }

    #[test]
    fn load_signatures_missing_file() {
        let (_, pk_pem) = generate_test_keypair();
        let tmp = tempfile::tempdir().unwrap();

        let _guard = ENV_LOCK.lock().unwrap();
        let saved_xdg = std::env::var_os("XDG_DATA_HOME");
        let saved_home = std::env::var_os("HOME");
        std::env::set_var("XDG_DATA_HOME", tmp.path());
        std::env::set_var("HOME", tmp.path());

        // Use a syntactically valid digest that simply has no stored file.
        assert!(load_signatures(sample_digest(), &pk_pem).is_err());

        match saved_xdg {
            Some(v) => std::env::set_var("XDG_DATA_HOME", v),
            None => std::env::remove_var("XDG_DATA_HOME"),
        }
        match saved_home {
            Some(v) => std::env::set_var("HOME", v),
            None => std::env::remove_var("HOME"),
        }
    }

    #[test]
    fn log_index_extraction() {
        let sig_with_index = CosignSignature {
            base64_signature: "AAAA".to_string(),
            payload: BASE64.encode(b"{}"),
            cert: None,
            chain: None,
            bundle: Some(serde_json::json!({"Payload": {"logIndex": 42}})),
            rfc3161_timestamp: None,
        };
        let sig_no_index = CosignSignature {
            bundle: None,
            ..sig_with_index.clone()
        };
        assert_eq!(max_log_index(&[sig_with_index]), 42);
        assert_eq!(max_log_index(&[sig_no_index]), 0);
        assert_eq!(max_log_index(&[]), 0);
    }

    #[test]
    fn fingerprint_ignores_pem_whitespace() {
        let (_, pem) = generate_test_keypair();
        let fp1 = pubkey_fingerprint(&pem).unwrap();
        // Re-flow whitespace in the PEM body: should produce the same hash.
        let pem2 = pem.replace('\n', "\r\n");
        let fp2 = pubkey_fingerprint(&pem2).unwrap();
        assert_eq!(fp1, fp2);
    }

    #[test]
    fn trusted_pubkey_parses() {
        let pem = include_str!("../trusted-key.pub");
        assert!(CosignVerificationKey::try_from_pem(pem.as_bytes()).is_ok());
        assert!(pubkey_fingerprint(pem).is_ok());
    }

    #[test]
    fn advance_log_index_only_forward() {
        let tmp = tempfile::tempdir().unwrap();
        let d = Sha256Digest::parse(sample_digest()).unwrap();
        advance_last_log_index(tmp.path(), &d, 5).unwrap();
        assert_eq!(read_last_log_index(tmp.path(), &d), 5);
        advance_last_log_index(tmp.path(), &d, 3).unwrap();
        assert_eq!(read_last_log_index(tmp.path(), &d), 5);
        advance_last_log_index(tmp.path(), &d, 10).unwrap();
        assert_eq!(read_last_log_index(tmp.path(), &d), 10);
    }

    #[test]
    fn advance_log_index_is_per_image() {
        // Two different images signed by the same key must not share a
        // counter: image A with a high logIndex must not lock out image B.
        let tmp = tempfile::tempdir().unwrap();
        let a = Sha256Digest::parse(sample_digest()).unwrap();
        let b = Sha256Digest::parse(&"f".repeat(64)).unwrap();
        advance_last_log_index(tmp.path(), &a, 1000).unwrap();
        assert_eq!(read_last_log_index(tmp.path(), &a), 1000);
        assert_eq!(read_last_log_index(tmp.path(), &b), 0);
    }

    #[test]
    fn rollback_detection_triggers() {
        // Store signatures with a high logIndex, then load a fixture with a
        // lower logIndex: must fail with a rollback message.
        let (sk, pk_pem) = generate_test_keypair();
        let tmp = tempfile::tempdir().unwrap();

        let high = CosignSignature {
            bundle: Some(serde_json::json!({"Payload": {"logIndex": 9999}})),
            ..make_signature(&sk, sample_digest())
        };
        let low = CosignSignature {
            bundle: Some(serde_json::json!({"Payload": {"logIndex": 1}})),
            ..make_signature(&sk, sample_digest())
        };

        let _guard = ENV_LOCK.lock().unwrap();
        let saved_xdg = std::env::var_os("XDG_DATA_HOME");
        let saved_home = std::env::var_os("HOME");
        std::env::set_var("XDG_DATA_HOME", tmp.path());
        std::env::set_var("HOME", tmp.path());

        store_signatures(&[high], sample_digest(), &pk_pem).unwrap();
        // Now overwrite the on-disk signature file with a lower-index sig.
        let dir = signatures_dir(&pk_pem).unwrap();
        let path = dir.join(format!("{}.json", sample_digest()));
        std::fs::write(&path, serde_json::to_vec(&vec![low]).unwrap()).unwrap();

        let err = load_signatures(sample_digest(), &pk_pem).unwrap_err();
        assert!(
            err.to_string().contains("regressed"),
            "expected rollback error, got: {err}"
        );

        match saved_xdg {
            Some(v) => std::env::set_var("XDG_DATA_HOME", v),
            None => std::env::remove_var("XDG_DATA_HOME"),
        }
        match saved_home {
            Some(v) => std::env::set_var("HOME", v),
            None => std::env::remove_var("HOME"),
        }
    }

    #[test]
    fn bundle_stripping_downgrade_is_rejected() {
        // If we have a recorded high-water mark, an attacker who replaces
        // the on-disk signature file with a (cryptographically valid) sig
        // that lacks a Rekor bundle must be rejected: that's a downgrade,
        // not a "legacy" upgrade path.
        let (sk, pk_pem) = generate_test_keypair();
        let tmp = tempfile::tempdir().unwrap();
        let _guard = ENV_LOCK.lock().unwrap();
        let saved_xdg = std::env::var_os("XDG_DATA_HOME");
        let saved_home = std::env::var_os("HOME");
        std::env::set_var("XDG_DATA_HOME", tmp.path());
        std::env::set_var("HOME", tmp.path());

        // Write a high-water mark file directly.
        let dir = signatures_dir(&pk_pem).unwrap();
        std::fs::create_dir_all(&dir).unwrap();
        let d = Sha256Digest::parse(sample_digest()).unwrap();
        atomic_write(&last_log_index_path(&dir, &d), b"42").unwrap();

        // Now store sigs that have no logIndex and try to load.
        let no_index = make_signature(&sk, sample_digest());
        store_signatures(&[no_index], sample_digest(), &pk_pem).unwrap();
        let err = load_signatures(sample_digest(), &pk_pem).unwrap_err();
        assert!(
            err.to_string().contains("missing Rekor log-index"),
            "expected bundle-stripping rejection, got: {err}"
        );

        match saved_xdg {
            Some(v) => std::env::set_var("XDG_DATA_HOME", v),
            None => std::env::remove_var("XDG_DATA_HOME"),
        }
        match saved_home {
            Some(v) => std::env::set_var("HOME", v),
            None => std::env::remove_var("HOME"),
        }
    }

}
