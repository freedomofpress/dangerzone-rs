//! OCI registry client used by the cosign verifier.
//!
//! Responsibilities of this module:
//!
//! * Parse and strictly validate image references.
//! * Acquire registry Bearer tokens by following the
//!   `WWW-Authenticate: Bearer ...` challenge. **Only Bearer tokens are
//!   supported**; HTTP Basic auth is intentionally not implemented (the
//!   public Dangerzone images are anonymously pullable, and we do not
//!   want to encourage shipping credentials with this tool).
//! * Fetch manifests and blobs with strict response-size caps and
//!   independent SHA-256 verification of blob bytes.
//!
//! Everything in this module treats the registry as untrusted: digests
//! returned by the registry are recomputed locally, response bodies are
//! capped, and all interpolated request components go through validators.
//!
//! All registry interactions go over HTTPS; non-https token realms are
//! refused.

use anyhow::{anyhow, bail, Context, Result};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use sha2::{Digest as _, Sha256};
use std::io::Read;
use std::time::Duration;

use crate::cosign::{CosignSignature, Sha256Digest};

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

const ACCEPT_MANIFEST: &str =
    "application/vnd.oci.image.manifest.v1+json,application/vnd.oci.image.index.v1+json,\
     application/vnd.docker.distribution.manifest.v2+json";

/// Strictly validate a registry host (with optional port). Allows IPv4
/// dotted-quad, DNS hostnames, and `localhost`. Rejects userinfo, paths,
/// query strings, and anything that would alter URL structure when
/// interpolated into `https://{registry}/v2/...`.
fn validate_registry(registry: &str) -> Result<()> {
    if registry.is_empty() || registry.len() > 253 {
        bail!("registry has invalid length");
    }
    let (host, port) = match registry.rsplit_once(':') {
        Some((h, p)) => (h, Some(p)),
        None => (registry, None),
    };
    if host.is_empty() {
        bail!("registry host is empty");
    }
    // DNS labels: alnum + '-' + '.', no leading/trailing dot or hyphen, no
    // consecutive dots.
    if host.starts_with('.')
        || host.ends_with('.')
        || host.starts_with('-')
        || host.ends_with('-')
        || host.contains("..")
    {
        bail!("registry host has invalid label boundaries");
    }
    if !host
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
    {
        bail!("registry host contains invalid character");
    }
    if let Some(p) = port {
        if p.is_empty() || p.len() > 5 || !p.bytes().all(|b| b.is_ascii_digit()) {
            bail!("registry port is not a valid number");
        }
        let n: u32 = p
            .parse()
            .map_err(|_| anyhow!("registry port unparseable"))?;
        if n == 0 || n > 65_535 {
            bail!("registry port out of range");
        }
    }
    Ok(())
}

/// Validate an OCI repository path (the bit after the registry, e.g.
/// `freedomofpress/dangerzone/v1`). Permits the docker-distribution name
/// component grammar joined by single slashes.
fn validate_repository(repository: &str) -> Result<()> {
    if repository.is_empty() || repository.len() > 255 {
        bail!("repository has invalid length");
    }
    if repository.starts_with('/') || repository.ends_with('/') || repository.contains("//") {
        bail!("repository has empty component");
    }
    if repository.contains("..") {
        bail!("repository contains '..'");
    }
    for component in repository.split('/') {
        if component.is_empty() {
            bail!("repository component is empty");
        }
        if !component.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'_' | b'-')
        }) {
            bail!("repository component contains invalid character: {component:?}");
        }
        // Components must start and end with alnum.
        let first = component.bytes().next().unwrap();
        let last = component.bytes().next_back().unwrap();
        if !first.is_ascii_lowercase() && !first.is_ascii_digit() {
            bail!("repository component must start with alnum: {component:?}");
        }
        if !last.is_ascii_lowercase() && !last.is_ascii_digit() {
            bail!("repository component must end with alnum: {component:?}");
        }
    }
    Ok(())
}

/// Validate a tag. Tags follow `[A-Za-z0-9_][A-Za-z0-9._-]{0,127}`.
fn validate_tag(tag: &str) -> Result<()> {
    if tag.is_empty() || tag.len() > 128 {
        bail!("tag has invalid length");
    }
    let mut bytes = tag.bytes();
    let first = bytes.next().unwrap();
    if !(first.is_ascii_alphanumeric() || first == b'_') {
        bail!("tag must start with [A-Za-z0-9_]: {tag:?}");
    }
    if !bytes.all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-')) {
        bail!("tag contains invalid character: {tag:?}");
    }
    Ok(())
}

/// A minimal parsed image reference. We deliberately do *not* try to fully
/// emulate the OCI distribution-spec parser; we support the subset we need.
#[derive(Debug, Clone)]
pub(crate) struct ImageRef {
    pub(crate) registry: String,
    pub(crate) repository: String,
    /// `Some(tag)` xor `Some(digest)`.
    pub(crate) tag: Option<String>,
    pub(crate) digest: Option<Sha256Digest>,
}

impl ImageRef {
    pub(crate) fn parse(image: &str) -> Result<Self> {
        if image.is_empty() || image.len() > 4096 {
            bail!("Invalid image reference: {image:?}");
        }
        // Reject embedded credentials, whitespace, and other URL-injection
        // hazards. We're going to interpolate parts of this string directly
        // into URL paths and HTTP headers, so be strict.
        if image.bytes().any(|b| {
            b.is_ascii_whitespace() || b.is_ascii_control() || b == b'?' || b == b'#' || b == b'\\'
        }) {
            bail!("Invalid image reference (illegal character): {image:?}");
        }

        // Split off `@sha256:...` first (digest references are unambiguous).
        let (head, digest) = match image.split_once('@') {
            Some((h, d)) => (h, Some(Sha256Digest::parse(d)?)),
            None => (image, None),
        };
        // Reject `userinfo@host` forms entirely: there must not be a second
        // `@`, and `head` must not itself contain a userinfo separator.
        if head.contains('@') {
            bail!("Invalid image reference (multiple '@'): {image:?}");
        }

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
            (false, Some((repo, t))) if !t.contains('/') => (repo.to_string(), Some(t.to_string())),
            _ => (path, None),
        };

        validate_registry(&registry)
            .with_context(|| format!("Invalid registry in image reference {image:?}"))?;
        validate_repository(&repository)
            .with_context(|| format!("Invalid repository in image reference {image:?}"))?;
        if let Some(t) = &tag {
            validate_tag(t).with_context(|| format!("Invalid tag in image reference {image:?}"))?;
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

fn build_agent() -> ureq::Agent {
    ureq::AgentBuilder::new()
        .timeout_connect(CONNECT_TIMEOUT)
        .timeout_read(READ_TIMEOUT)
        .build()
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
    let probe = agent.get(&format!("https://{}/v2/", image.registry)).call();

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
///
/// We only need `realm` and `service`, and real registries (ghcr.io, Docker
/// Hub, quay, GAR, ECR) send those as plain quoted strings with no embedded
/// commas or escapes. A simple split-on-`,` parse is sufficient; values that
/// don't fit that shape will fail closed at the subsequent token request,
/// which is the correct response to a malformed/hostile registry.
fn parse_bearer_challenge(header: &str) -> Result<(String, Option<String>)> {
    let rest = header
        .strip_prefix("Bearer ")
        .or_else(|| header.strip_prefix("bearer "))
        .ok_or_else(|| anyhow!("Unsupported auth scheme: {header}"))?;

    let mut realm: Option<String> = None;
    let mut service: Option<String> = None;

    for part in rest.split(',') {
        let (key, value) = part
            .split_once('=')
            .ok_or_else(|| anyhow!("Malformed challenge part: {part:?}"))?;
        let value = value.trim().trim_matches('"').to_string();
        match key.trim().to_ascii_lowercase().as_str() {
            "realm" => realm = Some(value),
            "service" => service = Some(value),
            _ => {}
        }
    }

    let realm = realm.ok_or_else(|| anyhow!("WWW-Authenticate is missing realm"))?;

    // Refuse plaintext auth endpoints. A registry served over HTTPS that
    // tries to redirect token issuance to http:// (or any non-https scheme)
    // is either misconfigured or hostile.
    if !realm.starts_with("https://") {
        bail!("Refusing non-https token realm: {realm}");
    }
    Ok((realm, service))
}

fn auth_request(req: ureq::Request, token: &str) -> ureq::Request {
    if token.is_empty() {
        req
    } else {
        req.set("Authorization", &format!("Bearer {token}"))
    }
}

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

/// Get the remote image digest by fetching the manifest body and hashing it
/// ourselves. We deliberately do **not** trust the `Docker-Content-Digest`
/// response header: the manifest bytes we fetch are the canonical source of
/// truth for the digest, so we hash what we actually see.
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
    let bytes = read_capped(resp, MAX_MANIFEST_BYTES)?;
    let computed = hex::encode(Sha256::digest(&bytes));
    Sha256Digest::parse(&computed)
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

    // Reject manifest indexes and unknown media types early. Cosign signature
    // manifests are always image manifests; an index here would mean the
    // registry is returning something we don't know how to parse.
    const ALLOWED_SIG_MANIFEST_TYPES: &[&str] = &[
        "application/vnd.oci.image.manifest.v1+json",
        "application/vnd.docker.distribution.manifest.v2+json",
    ];
    if let Some(mt) = manifest.get("mediaType").and_then(|v| v.as_str()) {
        if !ALLOWED_SIG_MANIFEST_TYPES.contains(&mt) {
            bail!("Unexpected signature manifest mediaType: {mt}");
        }
    }

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

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_digest() -> &'static str {
        "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
    }

    #[test]
    fn parse_image_reference_positive_paths() {
        // Full host/repo/tag.
        let r = ImageRef::parse("ghcr.io/freedomofpress/dangerzone/v1:latest").unwrap();
        assert_eq!(r.registry, "ghcr.io");
        assert_eq!(r.repository, "freedomofpress/dangerzone/v1");
        assert_eq!(r.tag.as_deref(), Some("latest"));
        assert!(r.digest.is_none());

        // Host with port and tag.
        let r = ImageRef::parse("localhost:5000/foo/bar:1.2").unwrap();
        assert_eq!(r.registry, "localhost:5000");
        assert_eq!(r.repository, "foo/bar");
        assert_eq!(r.tag.as_deref(), Some("1.2"));

        // By-digest reference.
        let r = ImageRef::parse(&format!("ghcr.io/foo/bar@sha256:{}", sample_digest())).unwrap();
        assert!(r.tag.is_none());
        assert_eq!(r.digest.as_ref().unwrap().as_hex(), sample_digest());

        // Docker Hub shorthand: bare name and user/image both expand.
        let r = ImageRef::parse("alpine").unwrap();
        assert_eq!(r.registry, "docker.io");
        assert_eq!(r.repository, "library/alpine");
        let r = ImageRef::parse("user/image:tag").unwrap();
        assert_eq!(r.registry, "docker.io");
        assert_eq!(r.repository, "user/image");
        assert_eq!(r.tag.as_deref(), Some("tag"));
    }

    #[test]
    fn parse_image_reference_rejects_malicious() {
        // Newlines / control chars
        assert!(ImageRef::parse("foo\n/bar").is_err());
        assert!(ImageRef::parse("foo bar/x").is_err());
        // Path traversal
        assert!(ImageRef::parse("ghcr.io/../etc").is_err());
        assert!(ImageRef::parse("ghcr.io/foo/..").is_err());
        // Userinfo
        assert!(ImageRef::parse("user:pass@ghcr.io/foo/bar").is_err());
        assert!(ImageRef::parse("ghcr.io/foo@bar@sha256:abc").is_err());
        // Query/fragment
        assert!(ImageRef::parse("ghcr.io/foo?evil=1").is_err());
        assert!(ImageRef::parse("ghcr.io/foo#frag").is_err());
        // Empty / bad components
        assert!(ImageRef::parse("").is_err());
        assert!(ImageRef::parse("ghcr.io//foo").is_err());
        assert!(ImageRef::parse("ghcr.io/foo/").is_err());
        // Bad port
        assert!(ImageRef::parse("ghcr.io:abc/foo/bar").is_err());
        assert!(ImageRef::parse("ghcr.io:99999/foo/bar").is_err());
        // Uppercase repo (OCI grammar requires lowercase)
        assert!(ImageRef::parse("ghcr.io/Foo/Bar").is_err());
        // Bad tag chars
        assert!(ImageRef::parse("ghcr.io/foo/bar:has space").is_err());
        assert!(ImageRef::parse("ghcr.io/foo/bar:.leadingdot").is_err());
    }

    #[test]
    fn parse_bearer_challenge_positive_paths() {
        // With service.
        let (realm, service) = parse_bearer_challenge(
            r#"Bearer realm="https://auth.docker.io/token",service="registry.docker.io""#,
        )
        .unwrap();
        assert_eq!(realm, "https://auth.docker.io/token");
        assert_eq!(service.as_deref(), Some("registry.docker.io"));

        // Without service (ghcr.io style).
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
    fn parse_bearer_challenge_rejects_http_realm() {
        assert!(parse_bearer_challenge(r#"Bearer realm="http://evil/token""#).is_err());
        assert!(parse_bearer_challenge(r#"Bearer realm="ftp://evil/token""#).is_err());
    }
}
