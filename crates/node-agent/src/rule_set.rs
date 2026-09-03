//! Asynchronous preparation of panel-managed route rule-set resources.
//!
//! The topology compiler remains a pure, synchronous translation step.  It
//! turns remote rule sets into stable local references and records the fetches
//! required to make those references valid.  [`RuleSetLoader`] performs that
//! I/O at the runtime transaction boundary, before shoes validates or mutates
//! a live inbound.

use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, SystemTime};

use serde::Serialize;
use sha2::{Digest as _, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_util::sync::CancellationToken;

const DEFAULT_UPDATE_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);
const MAX_RULE_SET_BYTES: usize = 64 * 1024 * 1024;
const SNAPSHOT_VERIFY_BUFFER_BYTES: usize = 64 * 1024;
static SNAPSHOT_SEQUENCE: AtomicU64 = AtomicU64::new(0);
static RULE_SET_STATE_ROOT: OnceLock<PathBuf> = OnceLock::new();

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RuleSetReference {
    pub format: String,
    pub path: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleSetResource {
    pub tag: String,
    pub format: String,
    pub path: PathBuf,
    pub source: RuleSetSource,
    pub update_interval: Duration,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuleSetSource {
    Local,
    Remote {
        url: String,
    },
    /// Panel inline rules encoded as a sing-box source rule-set. The loader
    /// snapshots these bytes exactly like local/remote resources so route and
    /// DNS consumers share the same parser and match semantics.
    Inline {
        bytes: Arc<[u8]>,
    },
}

/// Exact, immutable files prepared for one runtime transaction.
///
/// Panel resources keep stable cache paths so refresh scheduling remains
/// predictable. Running selectors use content-addressed snapshots instead: a
/// failed multi-inbound transaction can then restore the previous selectors
/// without accidentally reparsing bytes published by the failed candidate.
#[derive(Debug, Clone)]
pub struct PreparedRuleSets {
    pub digest: [u8; 32],
    path_replacements: BTreeMap<String, String>,
    pending_publications: Vec<PendingPublication>,
}

impl PreparedRuleSets {
    /// Rewrite only rule-set reference objects (`{ format, path }`). Other
    /// configuration paths, such as TLS certificates, are never touched even
    /// if they happen to equal a rule-set source path.
    pub fn rewrite_config(&self, value: &mut serde_json::Value) {
        rewrite_rule_set_paths(value, &self.path_replacements);
    }

    /// Publish remote candidates as the durable last-good cache only after the
    /// caller has successfully committed the corresponding runtime topology.
    pub async fn commit(&self) -> Result<(), RuleSetError> {
        for publication in &self.pending_publications {
            commit_candidate(publication).await?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
struct PendingPublication {
    tag: String,
    snapshot: PathBuf,
    target: PathBuf,
}

impl RuleSetResource {
    pub fn reference(&self) -> RuleSetReference {
        RuleSetReference {
            format: self.format.clone(),
            path: self.path.to_string_lossy().into_owned(),
        }
    }
}

#[derive(Debug)]
pub struct RuleSetError(String);

impl RuleSetError {
    fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl fmt::Display for RuleSetError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for RuleSetError {}

/// Build a local resource reference without performing any I/O.
pub fn plan_resource(
    tag: &str,
    kind: &str,
    format: &str,
    path: &str,
    url: &str,
    download_detour: &str,
    update_interval: &str,
) -> Result<RuleSetResource, RuleSetError> {
    let tag = tag.trim();
    if tag.is_empty() {
        return Err(RuleSetError::new("route rule-set tag is required"));
    }
    let format = match format.trim() {
        "source" => "source",
        "binary" | "" => "binary",
        other => {
            return Err(RuleSetError::new(format!(
                "route rule-set {tag:?} has unsupported format {other:?}"
            )));
        }
    };
    if !download_detour.trim().is_empty() {
        return Err(RuleSetError::new(format!(
            "route rule-set {tag:?} download_detour is not supported until its outbound is executable"
        )));
    }
    let update_interval = parse_duration(update_interval).map_err(|error| {
        RuleSetError::new(format!(
            "route rule-set {tag:?} update_interval {update_interval:?}: {error}"
        ))
    })?;
    let current_dir = fixed_state_root()?;

    match kind.trim() {
        "local" => {
            if path.trim().is_empty() {
                return Err(RuleSetError::new(format!(
                    "local route rule-set {tag:?} path is required"
                )));
            }
            let path = PathBuf::from(path.trim());
            Ok(RuleSetResource {
                tag: tag.to_owned(),
                format: format.to_owned(),
                path: if path.is_absolute() {
                    path
                } else {
                    current_dir.join(path)
                },
                source: RuleSetSource::Local,
                update_interval,
            })
        }
        "remote" => {
            let parsed = reqwest::Url::parse(url.trim()).map_err(|error| {
                RuleSetError::new(format!("remote route rule-set {tag:?} URL: {error}"))
            })?;
            if !matches!(parsed.scheme(), "http" | "https") {
                return Err(RuleSetError::new(format!(
                    "remote route rule-set {tag:?} URL must use http or https"
                )));
            }
            let path = cache_path(&current_dir, tag, format, parsed.as_str());
            Ok(RuleSetResource {
                tag: tag.to_owned(),
                format: format.to_owned(),
                path,
                source: RuleSetSource::Remote { url: parsed.into() },
                update_interval,
            })
        }
        "inline" => Err(RuleSetError::new(format!(
            "inline route rule-set {tag:?} does not require a resource plan"
        ))),
        other => Err(RuleSetError::new(format!(
            "route rule-set {tag:?} has unsupported type {other:?}"
        ))),
    }
}

/// Build an immutable source rule-set resource from panel inline rules.
///
/// The returned path is only a stable rewrite key. [`RuleSetLoader::prepare`]
/// writes the validated bytes to a content-addressed snapshot and rewrites all
/// route/DNS references before shoes sees the configuration.
pub fn plan_inline_resource(tag: &str, bytes: Vec<u8>) -> Result<RuleSetResource, RuleSetError> {
    let tag = tag.trim();
    if tag.is_empty() {
        return Err(RuleSetError::new("route rule-set tag is required"));
    }
    if bytes.len() > MAX_RULE_SET_BYTES {
        return Err(RuleSetError::new(format!(
            "inline route rule-set {tag:?} exceeds {MAX_RULE_SET_BYTES} bytes"
        )));
    }
    validate_envelope("source", &bytes)
        .map_err(|error| RuleSetError::new(format!("inline route rule-set {tag:?}: {error}")))?;
    validate_for_runtime("source", &bytes)
        .map_err(|error| RuleSetError::new(format!("inline route rule-set {tag:?}: {error}")))?;

    let digest = Sha256::digest(&bytes);
    let short_digest: String = digest[..8]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let path = fixed_state_root()?
        .join("runtime")
        .join("rule-sets")
        .join("inline")
        .join(format!("{}-{short_digest}.json", safe_rule_set_tag(tag)));
    Ok(RuleSetResource {
        tag: tag.to_owned(),
        format: "source".to_owned(),
        path,
        source: RuleSetSource::Inline {
            bytes: Arc::from(bytes),
        },
        update_interval: DEFAULT_UPDATE_INTERVAL,
    })
}

fn cache_path(base: &Path, tag: &str, format: &str, url: &str) -> PathBuf {
    let safe_tag = safe_rule_set_tag(tag);
    let digest = Sha256::digest(format!("{format}\0{url}").as_bytes());
    let short_digest: String = digest[..8]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let extension = if format == "binary" { "srs" } else { "json" };
    base.join("runtime")
        .join("rule-sets")
        .join(format!("{}-{}.{}", safe_tag, short_digest, extension))
}

fn safe_rule_set_tag(tag: &str) -> String {
    let mut safe_tag: String = tag
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.') {
                character
            } else {
                '_'
            }
        })
        .take(48)
        .collect();
    if safe_tag.is_empty() {
        safe_tag.push_str("rules");
    }
    safe_tag
}

async fn read_response_limited(
    response: &mut reqwest::Response,
    limit: usize,
    tag: &str,
) -> Result<Vec<u8>, RuleSetError> {
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|error| RuleSetError::new(format!("read route rule-set {tag}: {error}")))?
    {
        let next_len = bytes
            .len()
            .checked_add(chunk.len())
            .ok_or_else(|| RuleSetError::new(format!("route rule-set {tag} size overflow")))?;
        if next_len > limit {
            return Err(RuleSetError::new(format!(
                "route rule-set {tag} exceeds {limit} bytes"
            )));
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

async fn read_resource(resource: &RuleSetResource) -> Result<Vec<u8>, RuleSetError> {
    let file = tokio::fs::File::open(&resource.path)
        .await
        .map_err(|error| {
            RuleSetError::new(format!(
                "read route rule-set {} at {}: {error}",
                resource.tag,
                resource.path.display()
            ))
        })?;
    let mut bytes = Vec::new();
    file.take(MAX_RULE_SET_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .await
        .map_err(|error| {
            RuleSetError::new(format!(
                "read route rule-set {} at {}: {error}",
                resource.tag,
                resource.path.display()
            ))
        })?;
    if bytes.len() > MAX_RULE_SET_BYTES {
        return Err(RuleSetError::new(format!(
            "route rule-set {} exceeds {} bytes",
            resource.tag, MAX_RULE_SET_BYTES
        )));
    }
    Ok(bytes)
}

fn parse_duration(raw: &str) -> Result<Duration, &'static str> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Ok(DEFAULT_UPDATE_INTERVAL);
    }
    let split = raw
        .find(|character: char| !character.is_ascii_digit())
        .ok_or("duration unit is required")?;
    let value = raw[..split]
        .parse::<u64>()
        .map_err(|_| "duration value is invalid")?;
    if value == 0 {
        return Err("duration must be greater than zero");
    }
    let multiplier = match &raw[split..] {
        "s" => 1,
        "m" => 60,
        "h" => 60 * 60,
        "d" => 24 * 60 * 60,
        _ => return Err("supported units are s, m, h, and d"),
    };
    value
        .checked_mul(multiplier)
        .map(Duration::from_secs)
        .ok_or("duration is too large")
}

#[derive(Clone)]
pub struct RuleSetLoader {
    client: reqwest::Client,
    snapshot_root: PathBuf,
}

impl RuleSetLoader {
    pub fn new() -> Result<Self, RuleSetError> {
        let state_root = fixed_state_root()?;
        let client = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(30))
            .redirect(reqwest::redirect::Policy::limited(5))
            .user_agent(concat!("node-agent/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|error| RuleSetError::new(format!("build rule-set HTTP client: {error}")))?;
        Ok(Self {
            client,
            snapshot_root: state_root
                .join("runtime")
                .join("rule-sets")
                .join("snapshots"),
        })
    }

    /// Ensure every resource exists and return a content fingerprint for the
    /// exact bytes that shoes will parse. The runtime includes this fingerprint
    /// in its diff, so refreshing a file at the same stable path still hot-swaps
    /// the affected selectors.
    pub async fn prepare(
        &self,
        resources: &[RuleSetResource],
    ) -> Result<PreparedRuleSets, RuleSetError> {
        self.prepare_with_cancel(resources, &CancellationToken::new())
            .await
    }

    /// Cancellation interrupts network waits, but filesystem publication steps
    /// finish before it is observed so they cannot strand a partial snapshot.
    pub(crate) async fn prepare_with_cancel(
        &self,
        resources: &[RuleSetResource],
        cancel: &CancellationToken,
    ) -> Result<PreparedRuleSets, RuleSetError> {
        let mut prepared = PreparedRuleSetBuilder::default();
        for resource in resources {
            if cancel.is_cancelled() {
                return Err(RuleSetError::new("route rule-set preparation cancelled"));
            }
            match &resource.source {
                RuleSetSource::Local => {
                    let bytes = read_resource(resource).await?;
                    prepared
                        .push(&self.snapshot_root, resource, &bytes, false)
                        .await?;
                }
                RuleSetSource::Remote { url } => {
                    let (bytes, publish) = self.prepare_remote(resource, url, cancel).await?;
                    prepared
                        .push(&self.snapshot_root, resource, &bytes, publish)
                        .await?;
                }
                RuleSetSource::Inline { bytes } => {
                    prepared
                        .push(&self.snapshot_root, resource, bytes, false)
                        .await?;
                }
            }
        }
        if cancel.is_cancelled() {
            return Err(RuleSetError::new("route rule-set preparation cancelled"));
        }
        Ok(prepared.finish())
    }

    async fn prepare_remote(
        &self,
        resource: &RuleSetResource,
        url: &str,
        cancel: &CancellationToken,
    ) -> Result<(Vec<u8>, bool), RuleSetError> {
        recover_interrupted_publication(&resource.path, &resource.tag).await?;
        if cache_is_fresh(&resource.path, resource.update_interval).await {
            return read_resource(resource).await.map(|bytes| (bytes, false));
        }
        let cached = tokio::fs::metadata(&resource.path).await.is_ok();
        let fetch = async {
            let mut response = self.client.get(url).send().await.map_err(|error| {
                RuleSetError::new(format!("download route rule-set {}: {error}", resource.tag))
            })?;
            response = response.error_for_status().map_err(|error| {
                RuleSetError::new(format!("download route rule-set {}: {error}", resource.tag))
            })?;
            if let Some(length) = response.content_length()
                && length > MAX_RULE_SET_BYTES as u64
            {
                return Err(RuleSetError::new(format!(
                    "route rule-set {} exceeds {} bytes",
                    resource.tag, MAX_RULE_SET_BYTES
                )));
            }
            let bytes =
                read_response_limited(&mut response, MAX_RULE_SET_BYTES, &resource.tag).await?;
            validate_envelope(&resource.format, &bytes).map_err(|error| {
                RuleSetError::new(format!("route rule-set {}: {error}", resource.tag))
            })?;
            validate_for_runtime(&resource.format, &bytes).map_err(|error| {
                RuleSetError::new(format!("route rule-set {}: {error}", resource.tag))
            })?;
            Ok::<_, RuleSetError>(bytes)
        };
        let fetch = tokio::select! {
            biased;
            () = cancel.cancelled() => {
                return Err(RuleSetError::new("route rule-set preparation cancelled"));
            }
            result = fetch => result,
        };

        match fetch {
            Ok(bytes) => Ok((bytes, true)),
            Err(error) if cached => {
                log::warn!(
                    "{}; using cached rule-set at {}",
                    error,
                    resource.path.display()
                );
                read_resource(resource).await.map(|bytes| (bytes, false))
            }
            Err(error) => Err(error),
        }
    }
}

fn fixed_state_root() -> Result<PathBuf, RuleSetError> {
    if let Some(root) = RULE_SET_STATE_ROOT.get() {
        return Ok(root.clone());
    }
    let current_dir = std::env::current_dir()
        .map_err(|error| RuleSetError::new(format!("resolve rule-set state directory: {error}")))?;
    let resolved = std::fs::canonicalize(&current_dir).unwrap_or(current_dir);
    Ok(RULE_SET_STATE_ROOT.get_or_init(|| resolved).clone())
}

#[derive(Default)]
struct PreparedRuleSetBuilder {
    digest: Sha256,
    path_replacements: BTreeMap<String, String>,
    pending_publications: Vec<PendingPublication>,
}

impl PreparedRuleSetBuilder {
    async fn push(
        &mut self,
        snapshot_root: &Path,
        resource: &RuleSetResource,
        bytes: &[u8],
        publish: bool,
    ) -> Result<(), RuleSetError> {
        validate_envelope(&resource.format, bytes).map_err(|error| {
            RuleSetError::new(format!("route rule-set {}: {error}", resource.tag))
        })?;
        validate_for_runtime(&resource.format, bytes).map_err(|error| {
            RuleSetError::new(format!("route rule-set {}: {error}", resource.tag))
        })?;
        self.digest
            .update((resource.tag.len() as u64).to_be_bytes());
        self.digest.update(resource.tag.as_bytes());
        self.digest
            .update((resource.format.len() as u64).to_be_bytes());
        self.digest.update(resource.format.as_bytes());
        self.digest.update((bytes.len() as u64).to_be_bytes());
        self.digest.update(bytes);

        let snapshot = snapshot_path(snapshot_root, resource, bytes);
        publish_snapshot(&snapshot, bytes, &resource.tag).await?;
        let source = resource.path.to_string_lossy().into_owned();
        let target = snapshot.to_string_lossy().into_owned();
        if let Some(previous) = self
            .path_replacements
            .insert(source.clone(), target.clone())
            && previous != target
        {
            return Err(RuleSetError::new(format!(
                "route rule-set source path {source:?} resolves to conflicting snapshots"
            )));
        }
        if publish {
            self.pending_publications.push(PendingPublication {
                tag: resource.tag.clone(),
                snapshot,
                target: resource.path.clone(),
            });
        }
        Ok(())
    }

    fn finish(self) -> PreparedRuleSets {
        PreparedRuleSets {
            digest: self.digest.finalize().into(),
            path_replacements: self.path_replacements,
            pending_publications: self.pending_publications,
        }
    }
}

fn snapshot_path(root: &Path, resource: &RuleSetResource, bytes: &[u8]) -> PathBuf {
    let content_digest = Sha256::digest(bytes);
    let short_digest: String = content_digest[..16]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let extension = if resource.format == "binary" {
        "srs"
    } else {
        "json"
    };
    root.join(format!("{}-{short_digest}.{extension}", resource.format))
}

async fn publish_snapshot(target: &Path, bytes: &[u8], tag: &str) -> Result<(), RuleSetError> {
    if tokio::fs::metadata(target).await.is_ok() {
        return verify_snapshot(target, bytes, tag).await;
    }
    let parent = target
        .parent()
        .ok_or_else(|| RuleSetError::new(format!("route rule-set {tag} snapshot has no parent")))?;
    tokio::fs::create_dir_all(parent).await.map_err(|error| {
        RuleSetError::new(format!("create route rule-set snapshot directory: {error}"))
    })?;
    let sequence = SNAPSHOT_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let temporary = target.with_extension(format!(
        "{}.{}.{}.pending",
        target
            .extension()
            .and_then(|value| value.to_str())
            .unwrap_or("data"),
        std::process::id(),
        sequence
    ));
    tokio::fs::write(&temporary, bytes).await.map_err(|error| {
        RuleSetError::new(format!("write route rule-set {tag} snapshot: {error}"))
    })?;
    if let Err(error) = tokio::fs::rename(&temporary, target).await {
        if tokio::fs::metadata(target).await.is_ok() {
            let _ = tokio::fs::remove_file(&temporary).await;
            return verify_snapshot(target, bytes, tag).await;
        }
        let _ = tokio::fs::remove_file(&temporary).await;
        return Err(RuleSetError::new(format!(
            "publish route rule-set {tag} snapshot: {error}"
        )));
    }
    Ok(())
}

async fn verify_snapshot(target: &Path, expected: &[u8], tag: &str) -> Result<(), RuleSetError> {
    let mut actual = tokio::fs::File::open(target).await.map_err(|error| {
        RuleSetError::new(format!("read route rule-set {tag} snapshot: {error}"))
    })?;
    let mut buffer = vec![0u8; SNAPSHOT_VERIFY_BUFFER_BYTES];
    let mut offset = 0usize;
    loop {
        let read = actual.read(&mut buffer).await.map_err(|error| {
            RuleSetError::new(format!("read route rule-set {tag} snapshot: {error}"))
        })?;
        if read == 0 {
            if offset == expected.len() {
                return Ok(());
            }
            break;
        }
        let Some(expected_chunk) = expected.get(offset..offset.saturating_add(read)) else {
            break;
        };
        if buffer[..read] != *expected_chunk {
            break;
        }
        offset += read;
    }
    Err(RuleSetError::new(format!(
        "route rule-set {tag} snapshot digest collision at {}",
        target.display()
    )))
}

fn rewrite_rule_set_paths(value: &mut serde_json::Value, replacements: &BTreeMap<String, String>) {
    match value {
        serde_json::Value::Array(values) => {
            for value in values {
                rewrite_rule_set_paths(value, replacements);
            }
        }
        serde_json::Value::Object(fields) => {
            let is_rule_set_reference = fields
                .get("format")
                .and_then(serde_json::Value::as_str)
                .is_some_and(|format| matches!(format, "source" | "binary"));
            if is_rule_set_reference
                && let Some(path) = fields.get_mut("path")
                && let Some(replacement) = path
                    .as_str()
                    .and_then(|path| replacements.get(path))
                    .cloned()
            {
                *path = serde_json::Value::String(replacement);
            }
            for value in fields.values_mut() {
                rewrite_rule_set_paths(value, replacements);
            }
        }
        _ => {}
    }
}

async fn commit_candidate(publication: &PendingPublication) -> Result<(), RuleSetError> {
    recover_interrupted_publication(&publication.target, &publication.tag).await?;
    let parent = publication.target.parent().ok_or_else(|| {
        RuleSetError::new(format!(
            "route rule-set {} cache has no parent",
            publication.tag
        ))
    })?;
    tokio::fs::create_dir_all(parent)
        .await
        .map_err(|error| RuleSetError::new(format!("create rule-set cache directory: {error}")))?;
    let sequence = SNAPSHOT_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let temporary =
        publication
            .target
            .with_extension(format!("{}.{}.commit", std::process::id(), sequence));
    let mut source = tokio::fs::File::open(&publication.snapshot)
        .await
        .map_err(|error| {
            RuleSetError::new(format!(
                "open route rule-set {} candidate: {error}",
                publication.tag
            ))
        })?;
    let mut target = tokio::fs::File::create(&temporary).await.map_err(|error| {
        RuleSetError::new(format!(
            "create route rule-set {} cache candidate: {error}",
            publication.tag
        ))
    })?;
    if let Err(error) = tokio::io::copy(&mut source, &mut target).await {
        let _ = tokio::fs::remove_file(&temporary).await;
        return Err(RuleSetError::new(format!(
            "write route rule-set {} cache candidate: {error}",
            publication.tag
        )));
    }
    if let Err(error) = target.flush().await {
        let _ = tokio::fs::remove_file(&temporary).await;
        return Err(RuleSetError::new(format!(
            "flush route rule-set {} cache candidate: {error}",
            publication.tag
        )));
    }
    if let Err(error) = target.sync_all().await {
        drop(target);
        let _ = tokio::fs::remove_file(&temporary).await;
        return Err(RuleSetError::new(format!(
            "sync route rule-set {} cache candidate: {error}",
            publication.tag
        )));
    }
    drop(target);
    if let Err(error) = publish_cache(&temporary, &publication.target, &publication.tag).await {
        let _ = tokio::fs::remove_file(&temporary).await;
        return Err(error);
    }
    sync_parent(parent, &publication.tag).await
}

/// Recover the only crash window of the Windows replacement sequence. If both
/// names exist, the new file had already acquired its durable name; if only the
/// backup exists, restore it before freshness checks or downloads.
async fn recover_interrupted_publication(target: &Path, tag: &str) -> Result<(), RuleSetError> {
    let backup = target.with_extension("previous");
    if tokio::fs::metadata(&backup).await.is_err() {
        return Ok(());
    }
    if tokio::fs::metadata(target).await.is_ok() {
        tokio::fs::remove_file(&backup).await.map_err(|error| {
            RuleSetError::new(format!(
                "remove completed route rule-set {tag} cache backup: {error}"
            ))
        })?;
    } else {
        tokio::fs::rename(&backup, target).await.map_err(|error| {
            RuleSetError::new(format!(
                "restore interrupted route rule-set {tag} cache: {error}"
            ))
        })?;
    }
    Ok(())
}

#[cfg(unix)]
async fn sync_parent(parent: &Path, tag: &str) -> Result<(), RuleSetError> {
    let parent = parent.to_owned();
    let tag = tag.to_owned();
    tokio::task::spawn_blocking(move || {
        std::fs::File::open(&parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| {
                RuleSetError::new(format!(
                    "sync route rule-set {tag} cache directory: {error}"
                ))
            })
    })
    .await
    .map_err(|error| RuleSetError::new(format!("join route rule-set cache sync: {error}")))?
}

#[cfg(not(unix))]
async fn sync_parent(_parent: &Path, _tag: &str) -> Result<(), RuleSetError> {
    Ok(())
}

/// Publish only fully downloaded and envelope-validated bytes.
///
/// Unix rename replaces an existing file atomically. Windows does not allow
/// that form of rename, so retain a recoverable backup until the new cache is
/// in place. In particular, never delete the last usable cache before the
/// replacement has a durable name.
#[cfg(not(windows))]
async fn publish_cache(temporary: &Path, target: &Path, tag: &str) -> Result<(), RuleSetError> {
    tokio::fs::rename(temporary, target)
        .await
        .map_err(|error| RuleSetError::new(format!("publish route rule-set {tag} cache: {error}")))
}

#[cfg(windows)]
async fn publish_cache(temporary: &Path, target: &Path, tag: &str) -> Result<(), RuleSetError> {
    let backup = target.with_extension("previous");
    recover_interrupted_publication(target, tag).await?;
    let had_target = tokio::fs::metadata(target).await.is_ok();
    if had_target {
        tokio::fs::rename(target, &backup).await.map_err(|error| {
            RuleSetError::new(format!(
                "stage existing route rule-set {tag} cache: {error}"
            ))
        })?;
    }

    if let Err(publish_error) = tokio::fs::rename(temporary, target).await {
        if had_target && let Err(restore_error) = tokio::fs::rename(&backup, target).await {
            return Err(RuleSetError::new(format!(
                "publish route rule-set {tag} cache: {publish_error}; restore previous cache: {restore_error}"
            )));
        }
        return Err(RuleSetError::new(format!(
            "publish route rule-set {tag} cache: {publish_error}"
        )));
    }

    if had_target {
        tokio::fs::remove_file(&backup).await.map_err(|error| {
            RuleSetError::new(format!(
                "remove previous route rule-set {tag} cache: {error}"
            ))
        })?;
    }
    Ok(())
}

async fn cache_is_fresh(path: &Path, interval: Duration) -> bool {
    let Ok(metadata) = tokio::fs::metadata(path).await else {
        return false;
    };
    let Ok(modified) = metadata.modified() else {
        return false;
    };
    SystemTime::now()
        .duration_since(modified)
        .is_ok_and(|age| age < interval)
}

fn validate_envelope(format: &str, bytes: &[u8]) -> Result<(), &'static str> {
    match format {
        "binary" if bytes.starts_with(b"SRS") && bytes.len() >= 5 => Ok(()),
        "binary" => Err("invalid binary SRS header"),
        "source" => {
            let value: serde_json::Value =
                serde_json::from_slice(bytes).map_err(|_| "invalid source JSON")?;
            if value.is_object() {
                Ok(())
            } else {
                Err("source rule-set must be a JSON object")
            }
        }
        _ => Err("unsupported rule-set format"),
    }
}

fn validate_for_runtime(format: &str, bytes: &[u8]) -> Result<(), String> {
    shoes::validate_route_rule_set(format, bytes)
        .map_err(|error| format!("cannot be used by shoes: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn duration_parser_accepts_panel_intervals() {
        assert_eq!(
            parse_duration("720h").unwrap(),
            Duration::from_secs(720 * 3600)
        );
        assert_eq!(parse_duration("5m").unwrap(), Duration::from_secs(300));
        assert!(parse_duration("0h").is_err());
        assert!(parse_duration("1ms").is_err());
    }

    #[test]
    fn remote_paths_are_stable_and_do_not_trust_tags() {
        let base = Path::new("C:/agent");
        let first = cache_path(base, "../private", "binary", "https://example.com/a.srs");
        let second = cache_path(base, "../private", "binary", "https://example.com/a.srs");
        assert_eq!(first, second);
        assert!(first.starts_with(base.join("runtime").join("rule-sets")));
        assert_eq!(
            first.extension().and_then(|value| value.to_str()),
            Some("srs")
        );
    }

    #[test]
    fn envelopes_are_checked_before_publication() {
        assert!(validate_envelope("binary", b"SRS\x04x").is_ok());
        assert!(validate_envelope("binary", b"not-srs").is_err());
        assert!(validate_envelope("source", br#"{"version":4,"rules":[]}"#).is_ok());
        assert!(validate_envelope("source", b"[]").is_err());
    }

    #[test]
    fn immutable_snapshot_names_follow_content_and_format() {
        let resource = RuleSetResource {
            tag: "private".into(),
            format: "source".into(),
            path: PathBuf::from("rules.json"),
            source: RuleSetSource::Local,
            update_interval: DEFAULT_UPDATE_INTERVAL,
        };
        let root = Path::new("snapshots");
        let first = snapshot_path(root, &resource, br#"{"version":4,"rules":[]}"#);
        let same = snapshot_path(root, &resource, br#"{"version":4,"rules":[]}"#);
        let changed = snapshot_path(root, &resource, br#"{"version":4,"rules":[{}]}"#);
        assert_eq!(first, same);
        assert_ne!(first, changed);
        assert_eq!(
            first.extension().and_then(|value| value.to_str()),
            Some("json")
        );
    }

    #[test]
    fn cloning_inline_resource_shares_the_large_payload() {
        let resource = plan_inline_resource("inline", br#"{"version":4,"rules":[]}"#.to_vec())
            .expect("valid inline rule set");
        let cloned = resource.clone();
        let (RuleSetSource::Inline { bytes: original }, RuleSetSource::Inline { bytes: copy }) =
            (&resource.source, &cloned.source)
        else {
            panic!("inline planner must retain inline bytes");
        };
        assert!(Arc::ptr_eq(original, copy));
    }

    #[test]
    fn rewrite_only_changes_rule_set_reference_paths() {
        let prepared = PreparedRuleSets {
            digest: [1; 32],
            path_replacements: BTreeMap::from([("rules.srs".into(), "snapshot.srs".into())]),
            pending_publications: Vec::new(),
        };
        let mut config = serde_json::json!({
            "certificate": "rules.srs",
            "rules": [{
                "match": {"rule_set": [{"format": "binary", "path": "rules.srs"}]}
            }],
            "dns": {"rules": [{
                "rule_set": [{"format": "binary", "path": "rules.srs"}]
            }]}
        });
        prepared.rewrite_config(&mut config);
        assert_eq!(config["certificate"], "rules.srs");
        assert_eq!(
            config["rules"][0]["match"]["rule_set"][0]["path"],
            "snapshot.srs"
        );
        assert_eq!(
            config["dns"]["rules"][0]["rule_set"][0]["path"],
            "snapshot.srs"
        );
    }

    #[tokio::test]
    async fn interrupted_backup_is_restored_before_cache_use() {
        let temporary = tempfile::tempdir().expect("create cache directory");
        let target = temporary.path().join("rules.json");
        let backup = target.with_extension("previous");
        tokio::fs::write(&backup, br#"{"version":4,"rules":[]}"#)
            .await
            .expect("write interrupted backup");

        recover_interrupted_publication(&target, "test")
            .await
            .expect("restore backup");

        assert_eq!(
            tokio::fs::read(&target).await.expect("read restored cache"),
            br#"{"version":4,"rules":[]}"#
        );
        assert!(tokio::fs::metadata(&backup).await.is_err());
    }

    #[tokio::test]
    async fn existing_snapshot_is_verified_without_a_second_full_size_buffer() {
        let temporary = tempfile::tempdir().expect("create snapshot directory");
        let target = temporary.path().join("rules.json");
        let expected = vec![b'x'; SNAPSHOT_VERIFY_BUFFER_BYTES * 2 + 17];
        tokio::fs::write(&target, &expected)
            .await
            .expect("write matching snapshot");
        verify_snapshot(&target, &expected, "matching")
            .await
            .expect("matching snapshot");

        tokio::fs::write(&target, &expected[..expected.len() - 1])
            .await
            .expect("write truncated snapshot");
        assert!(
            verify_snapshot(&target, &expected, "truncated")
                .await
                .expect_err("truncated snapshot must fail")
                .to_string()
                .contains("digest collision")
        );
    }

    #[tokio::test]
    async fn response_reader_enforces_limit_while_streaming() {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test server");
        let address = listener.local_addr().expect("test server address");
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept request");
            let mut request = [0u8; 1024];
            let _ = socket.read(&mut request).await.expect("read request");
            socket
                .write_all(
                    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n4\r\n1234\r\n5\r\n56789\r\n0\r\n\r\n",
                )
                .await
                .expect("write chunked response");
        });
        let client = reqwest::Client::new();
        let mut response = client
            .get(format!("http://{address}/rules"))
            .send()
            .await
            .expect("download response");
        let error = read_response_limited(&mut response, 8, "oversized")
            .await
            .expect_err("ninth streamed byte must exceed the limit");
        assert!(error.to_string().contains("exceeds 8 bytes"));
        server.await.expect("join test server");
    }
}
