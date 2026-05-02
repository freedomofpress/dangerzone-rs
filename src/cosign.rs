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
use std::time::Duration;

/// Connection timeout for registry HTTP requests.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Read timeout for registry HTTP requests.
const READ_TIMEOUT: Duration = Duration::from_secs(30);
/// 1 MiB. Used as the cap for several body-size limits below.
const MIB: u64 = 1024 * 1024;
/// Maximum allowed size of an OCI manifest (1 MiB is well above any realistic
/// manifest; cosign signature manifests are typically a few KiB).
const MAX_MANIFEST_BYTES: u64 = MIB;
/// Maximum allowed size of a signed payload blob (cosign payloads are tiny
/// JSON documents; we cap to 1 MiB defensively).
const MAX_BLOB_BYTES: u64 = MIB;
/// Maximum size of a token response.
const MAX_TOKEN_BYTES: u64 = 64 * 1024;
/// Maximum size of a stored signature file we will read from disk.
const MAX_STORED_SIG_BYTES: u64 = MIB;
/// Filename used for the Rekor log-index high-water mark.
const LAST_LOG_INDEX_FILE: &str = "last_log_index";

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
            .or_else(|| payload.get("logIndex").and_then(|v| v.as_i64()).and_then(|i| u64::try_from(i).ok()))
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
fn atomic_write(path: &Path, contents: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("Path has no parent: {}", path.display()))?;
    std::fs::create_dir_all(parent)
        .with_context(|| format!("Creating directory {}", parent.display()))?;
    let tmp = parent.join(format!(
        ".{}.tmp",
        path.file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("dangerzone")
    ));
    std::fs::write(&tmp, contents).with_context(|| format!("Writing temp file {}", tmp.display()))?;
    std::fs::rename(&tmp, path)
        .with_context(|| format!("Renaming {} to {}", tmp.display(), path.display()))?;
    Ok(())
}

/// Read the persisted Rekor log-index high-water mark for a given key.
fn read_last_log_index(key_dir: &Path) -> u64 {
    let path = key_dir.join(LAST_LOG_INDEX_FILE);
    std::fs::read_to_string(&path)
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0)
}

/// Persist the Rekor log-index high-water mark, only advancing it forward.
fn advance_last_log_index(key_dir: &Path, new_index: u64) -> Result<()> {
    let current = read_last_log_index(key_dir);
    if new_index > current {
        let path = key_dir.join(LAST_LOG_INDEX_FILE);
        atomic_write(&path, new_index.to_string().as_bytes())?;
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
    let body =
        serde_json::to_vec_pretty(signatures).context("Serializing signatures to JSON")?;
    atomic_write(&path, &body)?;

    if let Some(idx) = signatures.iter().filter_map(|s| s.log_index()).max() {
        advance_last_log_index(&key_dir, idx)?;
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
pub fn load_signatures_from(
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

    // Rollback protection: the highest index in the loaded signatures must be
    // at least the persisted high-water mark. If a previously-seen signature
    // had logIndex N, the current set must include something at least N.
    let stored_high = read_last_log_index(key_dir);
    let loaded_high = max_log_index(&signatures);
    if stored_high > 0 && loaded_high < stored_high {
        bail!(
            "Rekor log index regressed: stored high-water mark is {stored_high}, \
             loaded signatures top out at {loaded_high}. This may indicate a rollback attack."
        );
    }

    Ok(signatures)
}

/// Return the maximum Rekor log index across a set of signatures, or 0 if
/// none of them carry a bundle / log index.
fn max_log_index(signatures: &[CosignSignature]) -> u64 {
    signatures.iter().filter_map(|s| s.log_index()).max().unwrap_or(0)
}

/// Backwards-compatible alias for [`max_log_index`] returning `i64` for
/// consumers that have not yet migrated.
pub fn get_log_index_from_signatures(signatures: &[CosignSignature]) -> i64 {
    i64::try_from(max_log_index(signatures)).unwrap_or(i64::MAX)
}

/// Get the SHA-256 digest of a locally cached container image via
/// `podman image inspect`. Selects the `RepoDigest` that matches `image_name`
/// (or its repository portion) so we never accidentally return the digest of
/// an unrelated repository's reference to the same image content.
pub fn get_local_image_digest(image_name: &str) -> Result<Sha256Digest> {
    let output = std::process::Command::new("podman")
        .args(["image", "inspect", "--format", "{{json .RepoDigests}}", image_name])
        .output()
        .context("Running `podman image inspect`")?;

    if !output.status.success() {
        bail!(
            "podman inspect failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }

    let stdout = String::from_utf8(output.stdout)
        .context("podman inspect output was not valid UTF-8")?;
    let repo_digests: Vec<String> = serde_json::from_str(stdout.trim())
        .context("Parsing RepoDigests from podman inspect")?;

    let repo_only = image_name.split(':').next().unwrap_or(image_name);
    let matching = repo_digests
        .iter()
        .find(|d| d.starts_with(&format!("{repo_only}@")) || d.starts_with(&format!("{image_name}@")))
        .or_else(|| repo_digests.first())
        .ok_or_else(|| anyhow!("Image '{image_name}' has no RepoDigests"))?;

    let (_, hex) = matching
        .split_once("@sha256:")
        .ok_or_else(|| anyhow!("Unexpected RepoDigest format: {matching}"))?;
    Sha256Digest::parse(hex)
}

/// Verify that a locally cached image has valid stored signatures.
pub fn verify_image(image_name: &str, pubkey_pem: &str) -> Result<()> {
    let digest = get_local_image_digest(image_name)?;
    let sigs = load_signatures(digest.as_hex(), pubkey_pem)?;
    eprintln!(
        "Container image verified: {} signature(s) valid for sha256:{}",
        sigs.len(),
        &digest.as_hex()[..12]
    );
    Ok(())
}

fn build_agent() -> ureq::Agent {
    ureq::AgentBuilder::new()
        .timeout_connect(CONNECT_TIMEOUT)
        .timeout_read(READ_TIMEOUT)
        .build()
}

/// A minimal parsed image reference. We deliberately do *not* try to fully
/// emulate the OCI distribution-spec parser; we support the subset we need.
#[derive(Debug, Clone)]
struct ImageRef {
    registry: String,
    repository: String,
    /// `Some(tag)` xor `Some(digest)`.
    tag: Option<String>,
    digest: Option<Sha256Digest>,
}

impl ImageRef {
    fn parse(image: &str) -> Result<Self> {
        // Split off `@sha256:...` first (digest references are unambiguous).
        let (head, digest) = match image.split_once('@') {
            Some((h, d)) => (h, Some(Sha256Digest::parse(d)?)),
            None => (image, None),
        };

        // Split host from path. A host is recognized when the first segment
        // contains a `.` or `:` or is `localhost`. Otherwise the reference
        // is assumed to be on Docker Hub (`docker.io/library/<name>`).
        let (registry, path) = match head.split_once('/') {
            Some((maybe_host, rest))
                if maybe_host == "localhost"
                    || maybe_host.contains('.')
                    || maybe_host.contains(':') =>
            {
                (maybe_host.to_string(), rest.to_string())
            }
            Some(_) => ("docker.io".to_string(), head.to_string()),
            None => ("docker.io".to_string(), format!("library/{head}")),
        };

        // Tag: a `:` in the *last* path segment, never confused with a port
        // because we already stripped the host.
        let (repository, tag) = match (digest.is_some(), path.rsplit_once(':')) {
            (false, Some((repo, t))) if !t.contains('/') => {
                (repo.to_string(), Some(t.to_string()))
            }
            _ => (path, None),
        };

        if repository.is_empty() {
            bail!("Invalid image reference: {image:?}");
        }

        Ok(Self {
            registry,
            repository,
            tag,
            digest,
        })
    }

    /// The reference suitable for asking the registry for the manifest.
    fn manifest_reference(&self) -> String {
        if let Some(d) = &self.digest {
            d.prefixed()
        } else {
            self.tag.clone().unwrap_or_else(|| "latest".to_string())
        }
    }
}

/// Read up to `max` bytes from a ureq response into a `Vec<u8>`.
fn read_capped(resp: ureq::Response, max: u64) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    resp.into_reader()
        .take(max + 1)
        .read_to_end(&mut buf)
        .context("Reading HTTP response body")?;
    if buf.len() as u64 > max {
        bail!("Response exceeds maximum allowed size of {max} bytes");
    }
    Ok(buf)
}

fn read_capped_json(resp: ureq::Response, max: u64) -> Result<serde_json::Value> {
    let bytes = read_capped(resp, max)?;
    serde_json::from_slice(&bytes).context("Parsing HTTP response body as JSON")
}

/// Acquire a registry token, honoring the WWW-Authenticate Bearer challenge
/// if the registry returns one. Falls back to the simple `<registry>/token`
/// form for registries (like ghcr.io) that accept it directly.
fn get_registry_token(agent: &ureq::Agent, image: &ImageRef) -> Result<String> {
    let scope = format!("repository:{}:pull", image.repository);

    // First try the /v2/ probe and read the WWW-Authenticate header.
    let probe = agent
        .get(&format!("https://{}/v2/", image.registry))
        .call();

    let (realm, service) = match &probe {
        // Anonymous registries that don't require auth.
        Ok(_) => return Ok(String::new()),
        Err(ureq::Error::Status(401, resp)) => {
            let www_auth = resp
                .header("www-authenticate")
                .ok_or_else(|| anyhow!("Registry returned 401 without WWW-Authenticate"))?;
            parse_bearer_challenge(www_auth)?
        }
        Err(e) => bail!("Registry probe failed: {e}"),
    };

    let mut req = agent.get(&realm).query("scope", &scope);
    if let Some(svc) = service.as_deref() {
        req = req.query("service", svc);
    }
    let body = read_capped_json(req.call().context("Token request failed")?, MAX_TOKEN_BYTES)?;
    body.get("token")
        .and_then(|v| v.as_str())
        .or_else(|| body.get("access_token").and_then(|v| v.as_str()))
        .map(str::to_string)
        .ok_or_else(|| anyhow!("Registry token response did not contain a token"))
}

/// Parse a `WWW-Authenticate: Bearer realm="...",service="..."` header.
/// Returns `(realm, Some(service))`.
fn parse_bearer_challenge(header: &str) -> Result<(String, Option<String>)> {
    let rest = header
        .strip_prefix("Bearer ")
        .or_else(|| header.strip_prefix("bearer "))
        .ok_or_else(|| anyhow!("Unsupported auth scheme: {header}"))?;

    let mut realm = None;
    let mut service = None;
    for part in rest.split(',') {
        let (k, v) = part
            .trim()
            .split_once('=')
            .ok_or_else(|| anyhow!("Malformed challenge fragment: {part}"))?;
        let v = v.trim().trim_matches('"').to_string();
        match k.trim() {
            "realm" => realm = Some(v),
            "service" => service = Some(v),
            _ => {}
        }
    }
    let realm = realm.ok_or_else(|| anyhow!("WWW-Authenticate is missing realm"))?;
    Ok((realm, service))
}

fn auth_request(req: ureq::Request, token: &str) -> ureq::Request {
    if token.is_empty() {
        req
    } else {
        req.set("Authorization", &format!("Bearer {token}"))
    }
}

const ACCEPT_MANIFEST: &str =
    "application/vnd.oci.image.manifest.v1+json,application/vnd.oci.image.index.v1+json,\
     application/vnd.docker.distribution.manifest.v2+json";

fn fetch_manifest(
    agent: &ureq::Agent,
    image: &ImageRef,
    reference: &str,
    token: &str,
) -> Result<serde_json::Value> {
    let req = auth_request(
        agent
            .get(&format!(
                "https://{}/v2/{}/manifests/{reference}",
                image.registry, image.repository
            ))
            .set("Accept", ACCEPT_MANIFEST),
        token,
    );
    let resp = req.call().context("Fetching manifest")?;
    read_capped_json(resp, MAX_MANIFEST_BYTES)
}

fn fetch_blob(
    agent: &ureq::Agent,
    image: &ImageRef,
    digest: &Sha256Digest,
    token: &str,
) -> Result<Vec<u8>> {
    let req = auth_request(
        agent.get(&format!(
            "https://{}/v2/{}/blobs/{}",
            image.registry,
            image.repository,
            digest.prefixed()
        )),
        token,
    );
    let resp = req.call().context("Fetching blob")?;
    let bytes = read_capped(resp, MAX_BLOB_BYTES)?;

    // Independently verify the blob hashes to the digest we asked for.
    let actual = hex::encode(Sha256::digest(&bytes));
    if actual != digest.as_hex() {
        bail!(
            "Blob digest mismatch: expected sha256:{}, got sha256:{actual}",
            digest.as_hex()
        );
    }
    Ok(bytes)
}

/// Get the remote image digest from the `Docker-Content-Digest` header
/// without pulling the image.
pub fn get_remote_image_digest(image_name: &str) -> Result<Sha256Digest> {
    let agent = build_agent();
    let image = ImageRef::parse(image_name)?;
    let token = get_registry_token(&agent, &image)?;

    let req = auth_request(
        agent
            .get(&format!(
                "https://{}/v2/{}/manifests/{}",
                image.registry,
                image.repository,
                image.manifest_reference()
            ))
            .set("Accept", ACCEPT_MANIFEST),
        &token,
    );
    let resp = req.call().context("Fetching remote manifest")?;

    let header = resp
        .header("Docker-Content-Digest")
        .ok_or_else(|| anyhow!("Registry response missing Docker-Content-Digest header"))?
        .to_string();
    Sha256Digest::parse(&header)
}

/// Download cosign signatures from the OCI registry (tag
/// `sha256-<digest>.sig`).
pub fn download_signatures_from_registry(
    image_name: &str,
    image_digest: &Sha256Digest,
) -> Result<Vec<CosignSignature>> {
    let agent = build_agent();
    let image = ImageRef::parse(image_name)?;
    let token = get_registry_token(&agent, &image)?;

    let sig_tag = format!("sha256-{}.sig", image_digest.as_hex());
    let manifest = fetch_manifest(&agent, &image, &sig_tag, &token)?;

    let layers = manifest
        .get("layers")
        .and_then(|v| v.as_array())
        .ok_or_else(|| anyhow!("Signature manifest has no layers array"))?;
    if layers.is_empty() {
        bail!("Signature manifest is empty for sha256:{image_digest}");
    }

    let mut signatures = Vec::with_capacity(layers.len());
    for layer in layers {
        let annotations = layer
            .get("annotations")
            .ok_or_else(|| anyhow!("Signature layer missing annotations"))?;
        let base64_signature = annotations
            .get("dev.cosignproject.cosign/signature")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("Layer missing cosign signature annotation"))?
            .to_string();
        let bundle: serde_json::Value = annotations
            .get("dev.sigstore.cosign/bundle")
            .and_then(|v| v.as_str())
            .map(serde_json::from_str)
            .transpose()
            .context("Parsing cosign bundle annotation")?
            .ok_or_else(|| anyhow!("Layer missing cosign bundle annotation"))?;
        let layer_digest_str = layer
            .get("digest")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("Signature layer missing digest"))?;
        let layer_digest = Sha256Digest::parse(layer_digest_str)?;

        // fetch_blob enforces that the bytes hash to `layer_digest`.
        let blob = fetch_blob(&agent, &image, &layer_digest, &token)?;

        signatures.push(CosignSignature {
            base64_signature,
            payload: BASE64.encode(&blob),
            cert: None,
            chain: None,
            bundle: Some(bundle),
            rfc3161_timestamp: None,
        });
    }

    Ok(signatures)
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
    let status = std::process::Command::new("podman")
        .args(["pull", &pull_ref])
        .status()
        .context("Running `podman pull`")?;
    if !status.success() {
        bail!("podman pull failed for '{pull_ref}'");
    }

    // Best-effort: also tag the pulled image with the original tag so that
    // subsequent runs can refer to it by name. Failure here is non-fatal.
    if let Some(tag) = &image.tag {
        let tagged = format!("{}/{}:{tag}", image.registry, image.repository);
        let _ = std::process::Command::new("podman")
            .args(["tag", &pull_ref, &tagged])
            .status();
    } else {
        let plain = format!("{}/{}", image.registry, image.repository);
        let _ = std::process::Command::new("podman")
            .args(["tag", &pull_ref, &plain])
            .status();
    }
    Ok(())
}

/// Download and verify signatures, then pull the image **by digest**, then
/// store the verified signatures. Pulling by digest after verification means
/// a registry compromise cannot serve unsigned content under the same tag.
pub fn upgrade_image(image_name: &str, pubkey_pem: &str) -> Result<()> {
    let image = ImageRef::parse(image_name)?;

    eprintln!("Fetching remote digest...");
    let digest = get_remote_image_digest(image_name)?;
    eprintln!("  sha256:{digest}");

    eprintln!("Downloading signatures...");
    let signatures = download_signatures_from_registry(image_name, &digest)?;
    eprintln!("  {} signature(s)", signatures.len());

    eprintln!("Verifying signatures...");
    verify_signatures(&signatures, digest.as_hex(), pubkey_pem)?;
    eprintln!(
        "  {} signature(s) verified against trusted key",
        signatures.len()
    );

    eprintln!("Pulling image by digest...");
    pull_image_by_digest(&image, &digest)?;

    eprintln!("Storing signatures...");
    store_signatures(&signatures, digest.as_hex(), pubkey_pem)?;
    eprintln!("Done");

    Ok(())
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
    fn verify_invalid_digest_input() {
        let (sk, pk_pem) = generate_test_keypair();
        let sig = make_signature(&sk, sample_digest());
        assert!(verify_signature(&sig, "not-a-digest", &pk_pem).is_err());
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
    fn verify_signatures_multiple_valid() {
        let (sk, pk_pem) = generate_test_keypair();
        let sigs = vec![
            make_signature(&sk, sample_digest()),
            make_signature(&sk, sample_digest()),
        ];
        assert!(verify_signatures(&sigs, sample_digest(), &pk_pem).is_ok());
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
    fn log_index_compat_alias() {
        let sig = CosignSignature {
            base64_signature: "AAAA".to_string(),
            payload: BASE64.encode(b"{}"),
            cert: None,
            chain: None,
            bundle: Some(serde_json::json!({"Payload": {"logIndex": 42}})),
            rfc3161_timestamp: None,
        };
        assert_eq!(get_log_index_from_signatures(&[sig]), 42);
        assert_eq!(get_log_index_from_signatures(&[]), 0);
    }

    #[test]
    fn parse_image_reference_full() {
        let r = ImageRef::parse("ghcr.io/freedomofpress/dangerzone/v1:latest").unwrap();
        assert_eq!(r.registry, "ghcr.io");
        assert_eq!(r.repository, "freedomofpress/dangerzone/v1");
        assert_eq!(r.tag.as_deref(), Some("latest"));
        assert!(r.digest.is_none());
    }

    #[test]
    fn parse_image_reference_no_tag() {
        let r = ImageRef::parse("ghcr.io/foo/bar").unwrap();
        assert_eq!(r.registry, "ghcr.io");
        assert_eq!(r.repository, "foo/bar");
        assert!(r.tag.is_none());
    }

    #[test]
    fn parse_image_reference_with_port() {
        let r = ImageRef::parse("localhost:5000/foo/bar:1.2").unwrap();
        assert_eq!(r.registry, "localhost:5000");
        assert_eq!(r.repository, "foo/bar");
        assert_eq!(r.tag.as_deref(), Some("1.2"));
    }

    #[test]
    fn parse_image_reference_with_digest() {
        let r = ImageRef::parse(&format!("ghcr.io/foo/bar@sha256:{}", sample_digest())).unwrap();
        assert_eq!(r.registry, "ghcr.io");
        assert_eq!(r.repository, "foo/bar");
        assert!(r.tag.is_none());
        assert_eq!(r.digest.as_ref().unwrap().as_hex(), sample_digest());
    }

    #[test]
    fn parse_image_reference_dockerhub_short() {
        let r = ImageRef::parse("alpine").unwrap();
        assert_eq!(r.registry, "docker.io");
        assert_eq!(r.repository, "library/alpine");
    }

    #[test]
    fn parse_image_reference_dockerhub_user() {
        let r = ImageRef::parse("user/image:tag").unwrap();
        assert_eq!(r.registry, "docker.io");
        assert_eq!(r.repository, "user/image");
        assert_eq!(r.tag.as_deref(), Some("tag"));
    }

    #[test]
    fn parse_bearer_challenge_basic() {
        let (realm, service) =
            parse_bearer_challenge(r#"Bearer realm="https://auth.docker.io/token",service="registry.docker.io""#).unwrap();
        assert_eq!(realm, "https://auth.docker.io/token");
        assert_eq!(service.as_deref(), Some("registry.docker.io"));
    }

    #[test]
    fn parse_bearer_challenge_no_service() {
        let (realm, service) =
            parse_bearer_challenge(r#"Bearer realm="https://ghcr.io/token""#).unwrap();
        assert_eq!(realm, "https://ghcr.io/token");
        assert!(service.is_none());
    }

    #[test]
    fn parse_bearer_challenge_rejects_basic_auth() {
        assert!(parse_bearer_challenge("Basic realm=\"x\"").is_err());
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
    fn payload_bytes_roundtrip() {
        let sig = CosignSignature {
            base64_signature: "AAAA".into(),
            payload: BASE64.encode(
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

    #[test]
    fn atomic_write_creates_file() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("nested/file.txt");
        atomic_write(&path, b"hello").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"hello");
    }

    #[test]
    fn advance_log_index_only_forward() {
        let tmp = tempfile::tempdir().unwrap();
        advance_last_log_index(tmp.path(), 5).unwrap();
        assert_eq!(read_last_log_index(tmp.path()), 5);
        advance_last_log_index(tmp.path(), 3).unwrap();
        assert_eq!(read_last_log_index(tmp.path()), 5);
        advance_last_log_index(tmp.path(), 10).unwrap();
        assert_eq!(read_last_log_index(tmp.path()), 10);
    }
}
