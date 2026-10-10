//! Read-only local evidence accounting; old schema does not imply verified contents.
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::Read,
    path::Path,
};

/// One retained mapping. 128 MiB holds the 92,319,172-byte image in `base.vdex`
/// and the 128 MiB anonymous container copied on device.
const RUNTIME_RANGE_FILE_CAP: u64 = 128 * 1024 * 1024;
/// One imported tree. A code-only dump on device is about 201MB. Spending the
/// first 128MB must not drop the later container that holds the plaintext DEX.
const RUNTIME_RANGE_TREE_CAP: u64 = 512 * 1024 * 1024;
/// The `kernsight.bound-code-copy/v1` finite metadata agreement matches
/// KernSight `qualified_code.rs` NOTE_LIMIT / NOTES_TOTAL_LIMIT /
/// NOTE_COUNT_LIMIT and compact_bound_notes' record limit (producer 6a1b833).
/// ME's pinned core predates these producer-local constants, so keep this
/// explicit agreement and its boundary tests until they move to shared protocol.
/// Per-document admission is separate from bounded local analysis below.
pub(super) const BOUND_SOURCE_BYTE_LIMIT: u64 = 2 * 1024 * 1024;
pub(super) const BOUND_SOURCE_TOTAL_BYTE_LIMIT: u64 = 8 * 1024 * 1024;
pub(super) const BOUND_SOURCE_COUNT_LIMIT: usize = 16;
pub(super) const BOUND_SOURCE_RECORD_LIMIT: usize = 65536;
const BOUND_SOURCE_DIAGNOSTIC_LIMIT: usize = 256;
const RUNTIME_OBSERVATION_LIMIT: usize = 256;
/// A scheduling hint only. The actual read is charged to the unchanged tree
/// inspection budget and never establishes range or DEX verification.
const RUNTIME_PROBE_PREFIX_CAP: u64 = 64 * 1024;

fn scope_failure() -> Option<&'static str> {
    match super::session_deadline::check() {
        Err(error) if error.contains("parent_cancelled") => Some("parent_cancelled"),
        Err(_) => Some("parent_deadline_exhausted"),
        Ok(()) => None,
    }
}

fn read_failure(error: &std::io::Error, fallback: &'static str) -> &'static str {
    let text = error.to_string();
    if text.contains("parent_cancelled") {
        "parent_cancelled"
    } else if text.contains("parent_deadline_exhausted") {
        "parent_deadline_exhausted"
    } else if text.contains("time_budget_exhausted") {
        "time_budget_exhausted"
    } else {
        scope_failure().unwrap_or(fallback)
    }
}

fn scope_failure_at(path: &Path) -> Option<&'static str> {
    super::session_budget::charge(path, 0)
        .err()
        .map(|error| read_failure(&error, "unknown_scope_failure"))
}

fn runtime_omission_reason(scope_stop: Option<&str>) -> &str {
    scope_stop.unwrap_or("runtime_observation_limit")
}

fn load_bound_source(
    root: &Path,
    path: &str,
    catalog_bytes: u64,
    remaining: &mut u64,
) -> Result<Value, &'static str> {
    if let Some(reason) = scope_failure_at(root) {
        return Err(reason);
    }
    if catalog_bytes > BOUND_SOURCE_BYTE_LIMIT {
        return Err("source_byte_limit");
    }
    if !safe_local_file(root, path) {
        return Err("unsafe_or_missing_source");
    }
    let (_source_file, before) = open_anchored_regular(root, path)?;
    let actual_bytes = before.len;
    if actual_bytes > BOUND_SOURCE_BYTE_LIMIT {
        return Err("source_byte_limit");
    }
    if actual_bytes > *remaining {
        return Err("source_total_byte_limit");
    }
    // One anchored, stable stream computes the report SHA over exactly the
    // retained parse bytes. The metadata budget counts actual successful inner
    // reads, including reads rejected by a subsequent scope checkpoint.
    let read = stable_hash_read_anchored(root, path, actual_bytes, true, remaining)?;
    if read.snapshot != before {
        return Err("range_file_changed");
    }
    let bytes = read.retained.ok_or("source_read_failed")?;
    if let Some(reason) = scope_failure_at(root) {
        return Err(reason);
    }
    let parsed = serde_json::from_slice::<Value>(&bytes);
    if let Some(reason) = scope_failure_at(root) {
        return Err(reason);
    }
    let mut note = parsed.map_err(|_| "invalid_or_truncated_json")?;
    if note["schema"] != "kernsight.bound-code-copy/v1" {
        return Err("unknown_source_schema");
    }
    let records = note["records"]
        .as_array()
        .ok_or("missing_or_invalid_records")?;
    if records.len() > BOUND_SOURCE_RECORD_LIMIT {
        return Err("source_record_limit");
    }
    note["mobilee_source_report_sha256"] = json!(read.sha256);
    Ok(note)
}

/// This reports bounded candidate/class-index work, never full DEX validation
/// or a consistent mapping snapshot. Failed checksums keep their own validation
/// status; finishing a candidate walk must not upgrade them.
fn runtime_analysis_gaps(runtime: &[Value]) -> BTreeMap<&'static str, usize> {
    let mut gaps = BTreeMap::new();
    if runtime.is_empty() {
        gaps.insert("no_runtime_observations", 1);
    }
    for row in runtime {
        let inspection = &row["object_inspection"];
        let mut add = |reason| *gaps.entry(reason).or_default() += 1;
        if row["local_content_status"] != "complete_range_hash_verified" {
            add("unverified_runtime_range");
        }
        if !matches!(
            inspection["status"].as_str(),
            Some("bounded_candidate_inspection" | "no_dex_or_elf_header_in_retained_range")
        ) {
            add("unknown_or_unavailable_inspection");
        }
        if inspection
            .get("candidate_stop_reason")
            .is_some_and(|v| !v.is_null())
        {
            add("candidate_stop");
        }
        if inspection
            .get("scope_stop_reason")
            .is_some_and(|v| !v.is_null())
        {
            add("inspection_scope_stopped");
        }
        if inspection["rejected_candidates"]
            .as_array()
            .is_some_and(|v| !v.is_empty())
        {
            add("rejected_or_unparsed_dex_candidates");
        }
        if inspection["elf_magic_count"]
            .as_u64()
            .is_some_and(|n| n > 0)
            && inspection["elf_status"]
                .as_str()
                .is_some_and(|s| s.starts_with("unknown"))
        {
            add("unknown_or_unsupported_elf_analysis");
        }
        if inspection["omitted_after_stop"] == true {
            add("candidate_omission");
        }
        // A 0..3 byte suffix cannot contain a four-byte candidate marker.
        if inspection["unscanned_tail_bytes"]
            .as_u64()
            .is_some_and(|n| n >= 4)
        {
            add("unscanned_range_tail");
        }
        for object in inspection["derived_objects"]
            .as_array()
            .into_iter()
            .flatten()
        {
            let index = &object["class_index"];
            if index["status"] != "complete_class_def_index" {
                add("partial_or_unknown_class_index");
            }
            if index["omitted_classes"].as_u64().is_some_and(|n| n > 0) {
                add("class_index_omission");
            }
            if index["invalid_classes"].as_u64().is_some_and(|n| n > 0) {
                add("invalid_class_definitions");
            }
            if index["duplicate_class_definitions"]
                .as_u64()
                .is_some_and(|n| n > 0)
            {
                add("duplicate_class_definitions");
            }
        }
    }
    gaps
}

fn range_budget_admits(len: u64, remaining: u64) -> bool {
    len > 0 && len <= RUNTIME_RANGE_FILE_CAP && len <= remaining
}

// Candidate private helpers for monitoring/storage_evidence.rs.
// Uses that module's existing fs, Path, Read, Sha256, Digest, read_failure,
// scope_failure_at and RUNTIME_RANGE_FILE_CAP definitions. No cache insertion:
// the caller must first compare the actual full digest with the source claim.

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct FileSnapshot {
    len: u64,
    #[cfg(unix)]
    dev: u64,
    #[cfg(unix)]
    ino: u64,
    #[cfg(unix)]
    mtime_sec: i64,
    #[cfg(unix)]
    mtime_nsec: i64,
    #[cfg(unix)]
    ctime_sec: i64,
    #[cfg(unix)]
    ctime_nsec: i64,
    // Without a reliable platform file identity, keep the exact safe path in
    // the comparison and disable cache reuse, including reuse on that path.
    #[cfg(not(unix))]
    path: std::path::PathBuf,
    #[cfg(not(unix))]
    modified: Option<std::time::SystemTime>,
    #[cfg(not(unix))]
    created: Option<std::time::SystemTime>,
}

impl FileSnapshot {
    fn from_metadata(metadata: &fs::Metadata, path: &Path) -> Result<Self, &'static str> {
        if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
            return Err("range_not_regular");
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let _ = path;
            Ok(Self {
                len: metadata.len(),
                dev: metadata.dev(),
                ino: metadata.ino(),
                mtime_sec: metadata.mtime(),
                mtime_nsec: metadata.mtime_nsec(),
                ctime_sec: metadata.ctime(),
                ctime_nsec: metadata.ctime_nsec(),
            })
        }
        #[cfg(not(unix))]
        {
            Ok(Self {
                len: metadata.len(),
                path: path.to_owned(),
                modified: metadata.modified().ok(),
                created: metadata.created().ok(),
            })
        }
    }

    fn cacheable(&self) -> bool {
        cfg!(unix)
    }
}

/// Leaf must be a regular file, never a symlink. The caller still performs
/// safe_local_file(root, relative) immediately before calling this helper;
/// that check also excludes symlinked ancestors and path traversal.
fn snapshot(path: &Path) -> Result<FileSnapshot, &'static str> {
    if let Some(reason) = scope_failure_at(path) {
        return Err(reason);
    }
    let result = fs::symlink_metadata(path);
    if let Some(reason) = scope_failure_at(path) {
        return Err(reason);
    }
    let metadata = result.map_err(|error| read_failure(&error, "range_read_failed"))?;
    FileSnapshot::from_metadata(&metadata, path)
}

fn descriptor_snapshot(file: &fs::File, path: &Path) -> Result<FileSnapshot, &'static str> {
    if let Some(reason) = scope_failure_at(path) {
        return Err(reason);
    }
    let result = file.metadata();
    if let Some(reason) = scope_failure_at(path) {
        return Err(reason);
    }
    let metadata = result.map_err(|error| read_failure(&error, "range_read_failed"))?;
    FileSnapshot::from_metadata(&metadata, path)
}

/// Open the checked regular leaf without following a raced symlink or waiting
/// for a raced FIFO. The external safe_local_file check remains required for
/// root confinement and symlinked ancestors. On Unix, fstat must still prove
/// the opened descriptor is the same regular inode observed at this path.
fn open_regular_checked(path: &Path) -> Result<fs::File, &'static str> {
    let before = snapshot(path)?;
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC);
    }
    let opened = options.open(path);
    if let Some(reason) = scope_failure_at(path) {
        return Err(reason);
    }
    let file = opened.map_err(|error| read_failure(&error, "range_read_failed"))?;
    let descriptor = descriptor_snapshot(&file, path)?;
    let current = snapshot(path)?;
    if descriptor != before || current != descriptor {
        return Err("range_file_changed");
    }
    Ok(file)
}

struct StableRead {
    sha256: String,
    snapshot: FileSnapshot,
    retained: Option<Vec<u8>>,
}

/// Hash the complete expected file once; if requested, retain those exact
/// hashed bytes for inspection. No second open/read or second digest occurs.
/// A raced replacement/write rejects the result and must never be cached.
fn stable_hash_read(path: &Path, expected: u64, retain: bool) -> Result<StableRead, &'static str> {
    if let Some(reason) = scope_failure_at(path) {
        return Err(reason);
    }
    if retain && expected > RUNTIME_RANGE_FILE_CAP {
        return Err("range_retention_limit");
    }
    let read_limit = expected.checked_add(1).ok_or("range_length_overflow")?;
    let path_before = snapshot(path)?;
    if path_before.len != expected {
        return Err("range_length_changed");
    }
    let mut file = open_regular_checked(path)?;
    let fd_before = descriptor_snapshot(&file, path)?;
    if path_before != fd_before {
        return Err("range_file_changed");
    }
    let mut retained = if retain {
        let capacity = usize::try_from(expected).map_err(|_| "range_retention_limit")?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(capacity)
            .map_err(|_| "range_allocation_failed")?;
        Some(bytes)
    } else {
        None
    };
    let mut hash = Sha256::new();
    let mut count = 0_u64;
    let mut buffer = [0_u8; 65536];
    {
        let reader = super::session_budget::CheckedReader::new(&mut file, path);
        // A growing file consumes at most expected + 1 bytes, even when its
        // original fstat length matched. Every read stays <= 64 KiB.
        let mut reader = reader.take(read_limit);
        loop {
            if let Some(reason) = scope_failure_at(path) {
                return Err(reason);
            }
            let result = reader.read(&mut buffer);
            if let Some(reason) = scope_failure_at(path) {
                return Err(reason);
            }
            let n = result.map_err(|error| read_failure(&error, "range_read_failed"))?;
            if n == 0 {
                break;
            }
            count = count.checked_add(n as u64).ok_or("range_length_overflow")?;
            if count > expected {
                return Err("range_length_changed");
            }
            hash.update(&buffer[..n]);
            if let Some(bytes) = retained.as_mut() {
                bytes.extend_from_slice(&buffer[..n]);
            }
            if let Some(reason) = scope_failure_at(path) {
                return Err(reason);
            }
        }
    }
    if count != expected {
        return Err("range_length_changed");
    }
    let fd_after = descriptor_snapshot(&file, path)?;
    let path_after = snapshot(path)?;
    if fd_after != fd_before || path_after != fd_before {
        return Err("range_file_changed");
    }
    let sha256 = format!("{:x}", hash.finalize());
    if let Some(reason) = scope_failure_at(path) {
        return Err(reason);
    }
    Ok(StableRead {
        sha256,
        snapshot: fd_after,
        retained,
    })
}

// Additional private helpers for storage_evidence.rs. Requires FileSnapshot,
// StableRead and descriptor_snapshot from stable_read_helpers.rs and the
// parent's shared bound_source_page::open_anchored implementation. No caller
// cache insertion occurs here. Unix directory-FD anchoring belongs to that
// shared opener, not to a second implementation in this module.

fn anchored_checkpoint(root: &Path, relative: &str) -> Result<std::path::PathBuf, &'static str> {
    if relative.is_empty()
        || !Path::new(relative)
            .components()
            .all(|part| matches!(part, std::path::Component::Normal(_)))
    {
        return Err("unsafe_or_missing_range");
    }
    Ok(root.join(relative))
}

fn open_anchored_regular(
    root: &Path,
    relative: &str,
) -> Result<(fs::File, FileSnapshot), &'static str> {
    let checkpoint = anchored_checkpoint(root, relative)?;
    if let Some(reason) = scope_failure_at(&checkpoint) {
        return Err(reason);
    }
    let opened = super::bound_source_page::open_anchored(root, relative);
    if let Some(reason) = scope_failure_at(&checkpoint) {
        return Err(reason);
    }
    let file =
        opened.map_err(|error| read_failure(&std::io::Error::other(error), "range_read_failed"))?;
    let stamp = descriptor_snapshot(&file, &checkpoint)?;
    Ok((file, stamp))
}

/// Every cache lookup opens from the root again and obtains an actual regular
/// descriptor snapshot. It never proves reuse from full-path metadata alone.
fn stable_cache_snapshot_anchored(
    root: &Path,
    relative: &str,
) -> Result<FileSnapshot, &'static str> {
    let checkpoint = anchored_checkpoint(root, relative)?;
    let (file, before) = open_anchored_regular(root, relative)?;
    let after = descriptor_snapshot(&file, &checkpoint)?;
    let (_current_file, current) = open_anchored_regular(root, relative)?;
    if after != before || current != before {
        return Err("range_file_changed");
    }
    Ok(before)
}

/// Account actual successful inner reads immediately, including a successful
/// payload read whose outer CheckedReader subsequently rejects an expired
/// scope. The optional budget is only used for inspection/probe payload reads.
struct InspectionReadMeter<'a, R> {
    inner: R,
    budget: Option<&'a mut u64>,
    actual: u64,
}

impl<'a, R> InspectionReadMeter<'a, R> {
    fn new(inner: R, budget: Option<&'a mut u64>) -> Self {
        Self {
            inner,
            budget,
            actual: 0,
        }
    }
    fn allowance(&self, requested: u64) -> u64 {
        self.budget
            .as_deref()
            .map_or(requested, |remaining| requested.min(*remaining))
    }
}

impl<R: Read> Read for InspectionReadMeter<'_, R> {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        let limit = self.allowance(buffer.len() as u64) as usize;
        if limit == 0 {
            return Err(std::io::Error::other("range_inspection_budget_exhausted"));
        }
        let count = self.inner.read(&mut buffer[..limit])?;
        self.actual = self.actual.saturating_add(count as u64);
        if let Some(remaining) = self.budget.as_deref_mut() {
            *remaining = remaining.saturating_sub(count as u64);
        }
        Ok(count)
    }
}

struct AnchoredStreamRead {
    sha256: Option<String>,
    snapshot: FileSnapshot,
    retained: Option<Vec<u8>>,
}

fn anchored_stream_read(
    root: &Path,
    relative: &str,
    expected: u64,
    retain: bool,
    compute_hash: bool,
    verified: Option<&FileSnapshot>,
    inspection_budget: &mut u64,
) -> Result<AnchoredStreamRead, &'static str> {
    let checkpoint = anchored_checkpoint(root, relative)?;
    if let Some(reason) = scope_failure_at(&checkpoint) {
        return Err(reason);
    }
    if retain && expected > RUNTIME_RANGE_FILE_CAP {
        return Err("range_retention_limit");
    }
    if retain && expected > *inspection_budget {
        return Err("range_inspection_budget_exhausted");
    }
    let read_limit = expected.checked_add(1).ok_or("range_length_overflow")?;
    let (mut file, before) = open_anchored_regular(root, relative)?;
    if before.len != expected {
        return Err("range_length_changed");
    }
    if verified.is_some_and(|stamp| !stamp.cacheable() || *stamp != before) {
        return Err("range_file_changed");
    }
    let mut retained = if retain {
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(usize::try_from(expected).map_err(|_| "range_retention_limit")?)
            .map_err(|_| "range_allocation_failed")?;
        Some(bytes)
    } else {
        None
    };
    let mut hash = compute_hash.then(Sha256::new);
    let mut count = 0_u64;
    let mut buffer = [0_u8; 65536];
    {
        let budget = if retain {
            Some(inspection_budget)
        } else {
            None
        };
        let mut meter = InspectionReadMeter::new(&mut file, budget);
        loop {
            let requested = (read_limit - count).min(buffer.len() as u64);
            let allowance = meter.allowance(requested);
            if allowance == 0 {
                // With a budget exactly equal to expected, do not spend an
                // extra sentinel byte. All expected bytes are hashed and the
                // unchanged pre/post fstat lengths plus rooted re-open below
                // provide the exact-length check without exceeding the cap.
                if count == expected {
                    break;
                }
                return Err("range_inspection_budget_exhausted");
            }
            if let Some(reason) = scope_failure_at(&checkpoint) {
                return Err(reason);
            }
            let result = super::session_budget::CheckedReader::new(&mut meter, &checkpoint)
                .read(&mut buffer[..allowance as usize]);
            if let Some(reason) = scope_failure_at(&checkpoint) {
                return Err(reason);
            }
            let n = result.map_err(|error| read_failure(&error, "range_read_failed"))?;
            if n == 0 {
                break;
            }
            count = count.checked_add(n as u64).ok_or("range_length_overflow")?;
            if count > expected {
                return Err("range_length_changed");
            }
            if let Some(hash) = hash.as_mut() {
                hash.update(&buffer[..n]);
            }
            if let Some(bytes) = retained.as_mut() {
                bytes.extend_from_slice(&buffer[..n]);
            }
            if let Some(reason) = scope_failure_at(&checkpoint) {
                return Err(reason);
            }
        }
    }
    if count != expected {
        return Err("range_length_changed");
    }
    let after = descriptor_snapshot(&file, &checkpoint)?;
    let (_current_file, current) = open_anchored_regular(root, relative)?;
    if after != before || current != before {
        return Err("range_file_changed");
    }
    let sha256 = hash.map(|hash| format!("{:x}", hash.finalize()));
    if let Some(reason) = scope_failure_at(&checkpoint) {
        return Err(reason);
    }
    Ok(AnchoredStreamRead {
        sha256,
        snapshot: after,
        retained,
    })
}

fn stable_hash_read_anchored(
    root: &Path,
    relative: &str,
    expected: u64,
    retain: bool,
    inspection_budget: &mut u64,
) -> Result<StableRead, &'static str> {
    let read = anchored_stream_read(
        root,
        relative,
        expected,
        retain,
        true,
        None,
        inspection_budget,
    )?;
    Ok(StableRead {
        sha256: read.sha256.ok_or("range_hash_missing")?,
        snapshot: read.snapshot,
        retained: read.retained,
    })
}

/// A previously verified same-inode/stamp digest can supply provenance for a
/// fresh retained read only while all opened descriptor stamps still match.
/// This path does not compute a second digest and never accepts non-Unix reuse.
fn stable_retained_read_anchored(
    root: &Path,
    relative: &str,
    expected: u64,
    verified: &FileSnapshot,
    inspection_budget: &mut u64,
) -> Result<Vec<u8>, &'static str> {
    let read = anchored_stream_read(
        root,
        relative,
        expected,
        true,
        false,
        Some(verified),
        inspection_budget,
    )?;
    read.retained.ok_or("range_retention_missing")
}

/// Bounded header probe, not range verification. Its bytes use the same actual
/// inspection meter, including failed post-read scope checks.
fn probe_prefix_anchored(
    root: &Path,
    relative: &str,
    limit: u64,
    inspection_budget: &mut u64,
) -> Result<(Vec<u8>, FileSnapshot, u64), &'static str> {
    let checkpoint = anchored_checkpoint(root, relative)?;
    let limit = limit.min(RUNTIME_PROBE_PREFIX_CAP).min(*inspection_budget);
    if limit == 0 {
        return Err("range_probe_budget_exhausted");
    }
    let (mut file, before) = open_anchored_regular(root, relative)?;
    let mut bytes = Vec::with_capacity(limit as usize);
    let actual;
    {
        let mut meter = InspectionReadMeter::new(&mut file, Some(inspection_budget));
        let result = super::session_budget::CheckedReader::new(&mut meter, &checkpoint)
            .take(limit)
            .read_to_end(&mut bytes);
        actual = meter.actual;
        if let Some(reason) = scope_failure_at(&checkpoint) {
            return Err(reason);
        }
        result.map_err(|error| read_failure(&error, "range_probe_read_failed"))?;
    }
    let after = descriptor_snapshot(&file, &checkpoint)?;
    let (_current_file, current) = open_anchored_regular(root, relative)?;
    if after != before || current != before {
        return Err("range_file_changed");
    }
    Ok((bytes, before, actual))
}

fn header_priority(bytes: &[u8]) -> Option<u8> {
    if bytes.starts_with(b"vdex")
        || memchr::memmem::find(bytes, b"dex\n").is_some()
        || memchr::memmem::find(bytes, b"cdex").is_some()
    {
        Some(0)
    } else if bytes.starts_with(b"\x7fELF") {
        Some(2)
    } else {
        None
    }
}

fn mapping_priority(path: &str) -> u8 {
    if [".vdex", ".dex", ".cdex", ".apk", ".oat"]
        .iter()
        .any(|suffix| path.ends_with(suffix))
    {
        1
    } else {
        3
    }
}

/// A bounded actual prefix probe also catches inner DEX headers in non-header
/// library segments. It only orders work; it never verifies a range or image.
fn probe_priority_anchored(
    root: &Path,
    relative: &str,
    budget: &mut u64,
) -> Result<(Option<u8>, FileSnapshot, u64), &'static str> {
    let (bytes, stamp, actual) =
        probe_prefix_anchored(root, relative, RUNTIME_PROBE_PREFIX_CAP, budget)?;
    Ok((header_priority(&bytes), stamp, actual))
}

/// The full class array lives once in runtime_observations. Inventory rows and
/// caches contain bounded summaries, including the exact class-index gaps.
fn inspection_summary(analysis: &Value) -> Value {
    let mut summary = Value::Object(
        analysis
            .as_object()
            .into_iter()
            .flatten()
            .filter(|(key, _)| key.as_str() != "derived_objects")
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect(),
    );
    let objects = analysis["derived_objects"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|object| {
            let index_summary = Value::Object(
                object["class_index"]
                    .as_object()
                    .into_iter()
                    .flatten()
                    .filter(|(key, _)| key.as_str() != "classes")
                    .map(|(key, value)| (key.clone(), value.clone()))
                    .collect(),
            );
            json!({
                "kind":object["kind"], "sha256":object["sha256"], "length":object["length"],
                "source_offset":object["source_offset"], "class_index":index_summary,
                "sha1_signature_verified":object["sha1_signature_verified"],
                "adler32_checksum_verified":object["adler32_checksum_verified"]
            })
        })
        .collect::<Vec<_>>();
    summary["derived_objects"] = json!(objects);
    summary["inventory_summary_only"] = json!(true);
    summary
}

struct RangeWork {
    inventory_index: usize,
    relative: String,
    expected: String,
    bytes: u64,
    priority: u8,
}

struct InspectionReference {
    summary: Value,
    heavy_row_index: Option<usize>,
}

fn add_inspection_source(analysis: &mut Value, observation: &Value) {
    if let Some(objects) = analysis["derived_objects"].as_array_mut() {
        for object in objects {
            object["source_artifact"] = observation["relative_path"].clone();
            object["source_artifact_sha256"] = observation["read"]["sha256"].clone();
            object["source_instance"] = observation["source"].clone();
            object["source_absolute_start"] = json!(observation["read"]["actual_start"]
                .as_u64()
                .zip(object["source_offset"].as_u64())
                .and_then(|(a, b)| a.checked_add(b)));
            object["source_torn"] = observation["read"]["torn"].clone();
        }
    }
}

pub(super) fn account(root: &Path, files: &[(String, u64)]) -> Value {
    let mut logical = 0_u64;
    let mut inode_bytes = 0_u64;
    let mut allocated = 0_u64;
    let mut unknown_metadata = 0_u64;
    #[cfg(unix)]
    let mut inodes = BTreeSet::<(u64, u64)>::new();
    let mut categories = BTreeMap::<String, u64>::new();
    for (path, _) in files {
        match fs::symlink_metadata(root.join(path)) {
            Ok(m) if m.is_file() => {
                logical += m.len();
                *categories
                    .entry(path.split('/').next().unwrap_or("report").to_owned())
                    .or_default() += m.len();
                #[cfg(unix)]
                {
                    use std::os::unix::fs::MetadataExt;
                    if inodes.insert((m.dev(), m.ino())) {
                        inode_bytes += m.len();
                        allocated += m.blocks() * 512;
                    }
                }
                #[cfg(not(unix))]
                {
                    inode_bytes += m.len();
                    allocated += m.len();
                }
            }
            _ => unknown_metadata += 1,
        }
    }
    let known = files
        .iter()
        .map(|(p, n)| (p.as_str(), *n))
        .collect::<BTreeMap<_, _>>();
    let mut observations = Vec::new();
    let mut omitted = 0_usize;
    let mut failures = 0_usize;
    let mut hash_budget = RUNTIME_RANGE_TREE_CAP;
    let mut inspection_budget = RUNTIME_RANGE_TREE_CAP;
    let mut probe_bytes = 0_u64;
    let mut hash_bytes = 0_u64;
    let mut static_hash_cache_hits = 0_usize;
    let mut runtime_hash_cache_hits = 0_usize;
    let mut verified_paths = BTreeMap::<String, (String, u64)>::new();
    let mut verified_inodes = BTreeMap::<FileSnapshot, String>::new();

    for (path, len) in files
        .iter()
        .filter(|(p, _)| p.starts_with("code-evidence/") && p.ends_with(".json"))
    {
        if scope_failure_at(root).is_some() {
            failures += 1;
            continue;
        }
        if observations.len() >= 256 || *len > 32768 {
            omitted += 1;
            continue;
        }
        let value = if safe_local_file(root, path) {
            open_anchored_regular(root, path)
                .ok()
                .and_then(|(mut file, before)| {
                    if before.len > 32768 {
                        return None;
                    }
                    let mut bytes = Vec::new();
                    super::session_budget::CheckedReader::new(&mut file, &root.join(path))
                        .take(32769)
                        .read_to_end(&mut bytes)
                        .ok()
                        .filter(|_| bytes.len() <= 32768)
                        .and_then(|_| {
                            let after = descriptor_snapshot(&file, &root.join(path)).ok()?;
                            let current = stable_cache_snapshot_anchored(root, path).ok()?;
                            if after != before || current != before {
                                return None;
                            }
                            serde_json::from_slice::<Value>(&bytes).ok()
                        })
                })
        } else {
            None
        };
        let Some(mut note) = value else {
            failures += 1;
            continue;
        };
        if note["schema"] != "kernsight.apk-member-evidence/v1" {
            failures += 1;
            continue;
        }
        let relative = note["relative_path"].as_str().unwrap_or("").to_owned();
        let expected = note["sha256"].as_str().unwrap_or("").to_owned();
        let bytes = note["bytes"].as_u64().unwrap_or(u64::MAX);
        let code_path = ["apk-dex/", "readable-dex/", "lib/", "apk-assets/"]
            .iter()
            .any(|prefix| relative.starts_with(prefix))
            || (!relative.contains('/')
                && ["dex", "so"]
                    .iter()
                    .any(|ext| Path::new(&relative).extension().is_some_and(|e| e == *ext)));
        let valid = code_path
            && known.get(relative.as_str()) == Some(&bytes)
            && expected.len() == 64
            && expected.bytes().all(|b| b.is_ascii_hexdigit())
            && note["source_complete"] == true
            && matches!(
                note["write_status"].as_str(),
                Some("hard_link" | "existing_verified")
            )
            && safe_local_file(root, &relative);
        let mut failure = None;
        let verified = if valid {
            match stable_cache_snapshot_anchored(root, &relative) {
                Ok(stamp) if stamp.len == bytes => {
                    if let Some(actual) = stamp
                        .cacheable()
                        .then(|| verified_inodes.get(&stamp))
                        .flatten()
                    {
                        static_hash_cache_hits += 1;
                        if actual == &expected {
                            true
                        } else {
                            failure = Some("range_hash_mismatch");
                            false
                        }
                    } else if range_budget_admits(bytes, hash_budget) {
                        hash_budget -= bytes;
                        hash_bytes += bytes;
                        match stable_hash_read_anchored(
                            root,
                            &relative,
                            bytes,
                            false,
                            &mut inspection_budget,
                        ) {
                            Ok(read) if read.sha256 == expected => {
                                if read.snapshot.cacheable() {
                                    verified_inodes.insert(read.snapshot, read.sha256);
                                }
                                true
                            }
                            Ok(_) => {
                                failure = Some("range_hash_mismatch");
                                false
                            }
                            Err(reason) => {
                                failure = Some(reason);
                                false
                            }
                        }
                    } else {
                        failure = Some(if bytes > RUNTIME_RANGE_FILE_CAP {
                            "range_hash_file_limit"
                        } else {
                            "range_hash_budget_exhausted"
                        });
                        false
                    }
                }
                Ok(_) => {
                    failure = Some("range_length_changed");
                    false
                }
                Err(reason) => {
                    failure = Some(reason);
                    false
                }
            }
        } else {
            failure = Some("range_metadata_not_admitted_or_complete");
            false
        };
        if verified {
            verified_paths.insert(relative, (expected, bytes));
        } else {
            failures += 1;
        }
        note["local_content_status"] = json!(if verified {
            "complete_file_hash_verified"
        } else {
            "unknown_or_failed"
        });
        note["content_verification_failure_reason"] = json!(failure);
        note["apk_member_rechecked_locally"] = json!(false);
        observations.push(note);
    }

    let mut inventory = Vec::<Value>::new();
    let mut queue = Vec::<RangeWork>::new();
    let mut runtime = Vec::<Value>::new();
    let mut source_diagnostics = Vec::<Value>::new();
    let mut source_count = 0_usize;
    let mut source_omitted = 0_usize;
    let mut source_byte_budget = BOUND_SOURCE_TOTAL_BYTE_LIMIT;
    let mut class_index_budget = 4 * 1024 * 1024_usize;
    let mut probe_cache = BTreeMap::<FileSnapshot, Option<u8>>::new();
    let mut inspections = BTreeMap::<String, InspectionReference>::new();
    for (path, len) in files.iter().filter(|(p, _)| {
        Path::new(p)
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.starts_with("bound-source-") && n.ends_with(".json"))
    }) {
        let mut diagnostic = json!({"source_report":path,"status":"accepted","records_seen":null,
            "records_walked":false,"invalid_records":0,"metadata_invalid_records":0,
            "integrity_invalid_records":0,"omitted_records":0,"byte_limit":BOUND_SOURCE_BYTE_LIMIT,
            "record_limit":BOUND_SOURCE_RECORD_LIMIT});
        if source_count >= BOUND_SOURCE_COUNT_LIMIT {
            source_omitted += 1;
            omitted += 1;
            failures += 1;
            if source_diagnostics.len() < BOUND_SOURCE_DIAGNOSTIC_LIMIT {
                diagnostic["status"] = json!("source_count_limit");
                source_diagnostics.push(diagnostic);
            }
            continue;
        }
        source_count += 1;
        let before = source_byte_budget;
        let loaded = load_bound_source(root, path, *len, &mut source_byte_budget);
        diagnostic["metadata_bytes_read"] = json!(before - source_byte_budget);
        diagnostic["metadata_budget_remaining"] = json!(source_byte_budget);
        let note = match loaded {
            Ok(note) => note,
            Err(reason) => {
                diagnostic["status"] = json!(reason);
                failures += 1;
                source_diagnostics.push(diagnostic);
                continue;
            }
        };
        let records = note["records"].as_array().unwrap();
        diagnostic["records_seen"] = json!(records.len());
        diagnostic["records_walked"] = json!(true);
        diagnostic["source_report_sha256"] = note["mobilee_source_report_sha256"].clone();
        let diagnostic_index = source_diagnostics.len();
        let mut rejected_invalid = 0_usize;
        let mut rejected_unwalked = 0_usize;
        let mut rejected_prefix = Vec::<Value>::new();
        let mut rejected_reasons = BTreeMap::<String, usize>::new();
        for (record_index, record) in records.iter().enumerate() {
            if !record.is_object()
                || ["source", "mapping", "read"]
                    .iter()
                    .any(|field| !record[*field].is_object())
            {
                let scope_stop = scope_failure_at(root);
                let reason = scope_stop.unwrap_or(if record.is_object() {
                    "record_fields_not_objects"
                } else {
                    "record_not_object"
                });
                if scope_stop.is_some() {
                    rejected_unwalked += 1;
                    if diagnostic["scope_stop_reason"].is_null() {
                        diagnostic["scope_stop_reason"] = json!(reason);
                    }
                } else {
                    rejected_invalid += 1;
                }
                *rejected_reasons.entry(reason.to_owned()).or_default() += 1;
                if rejected_prefix.len() < BOUND_SOURCE_DIAGNOSTIC_LIMIT {
                    rejected_prefix
                        .push(json!({"source_record_index":record_index,"reason":reason}));
                }
                continue;
            }
            let mut observation = json!({"schema":"mobilee.bound-runtime-range/v1",
                "inventory_role":"lightweight_range_ledger", "source_report":path,
                "source_report_sha256":note["mobilee_source_report_sha256"],
                "source_record_index":record_index,"source_diagnostic_index":diagnostic_index,
                "source":record["source"],"mapping":record["mapping"],"read":record["read"],
                "raw_evidence":record["raw_evidence"],"admitted":record["admitted"],
                "selection_limit_reason":record["selection_limit_reason"],
                "ownership":"unknown", "parse_status":"unknown_not_attested_by_range_copy",
                "local_content_status":"unknown_or_failed", "mapping_complete":null,
                "object_inspection":{"status":"unknown_unverified_or_oversized_range"},
                "runtime_observation_row_index":null,"inspection_ref":null,"inspection_content_key":null,
                "inspection_status":null,"metadata_eligible":false});
            if let Some(reason) = scope_failure_at(root) {
                observation["metadata_eligible"] = Value::Null;
                observation["metadata_walk_status"] = json!("unknown_scope_not_walked");
                observation["content_verification_failure_reason"] = json!(reason);
                observation["object_inspection"] =
                    json!({"status":"unknown_scope_not_walked","reason":reason});
                inventory.push(observation);
                continue;
            }
            observation["metadata_walk_status"] = json!("eligibility_walked");
            let raw = record["raw_evidence"].as_str().unwrap_or("");
            let parent = Path::new(path).parent().unwrap_or(Path::new(""));
            let relative = parent.join(raw).to_string_lossy().into_owned();
            let read = &record["read"];
            let bytes = read["actual_length"].as_u64();
            let expected = read["sha256"].as_str().unwrap_or("");
            let source = &record["source"];
            let identity_known = source == &note["source"]
                && source["package"].as_str().is_some_and(|v| !v.is_empty())
                && source["pid"].as_u64().is_some_and(|v| v > 0)
                && source["birth_ns"].as_u64().is_some_and(|v| v > 0)
                && source["uid"].as_u64().is_some()
                && source["exec_id"].as_u64().is_some()
                && source["boot_id"].as_str().is_some_and(|v| !v.is_empty());
            let range_known = (|| {
                let start = record["mapping"]["start"].as_u64()?;
                let end = record["mapping"]["end"].as_u64()?;
                let request = read["requested_length"].as_u64()?;
                let actual = bytes?;
                let requested_start = read["requested_start"].as_u64()?;
                let actual_start = read["actual_start"].as_u64()?;
                Some(
                    end > start
                        && request > 0
                        && actual == request
                        && requested_start >= start
                        && actual_start == requested_start
                        && requested_start.checked_add(request)? <= end,
                )
            })()
            .unwrap_or(false);
            let code_scope = parent.as_os_str().is_empty() || parent == Path::new("runtime");
            let safe_raw = code_scope
                && !raw.is_empty()
                && !raw.contains('/')
                && !raw.contains('\\')
                && raw.starts_with("bound-")
                && raw.ends_with(".code")
                && safe_local_file(root, &relative);
            let valid = record.is_object()
                && identity_known
                && range_known
                && safe_raw
                && record["admitted"] == true
                && read["admission"] == "qualified_live_copy"
                && read["read_status"] == "complete"
                && read["write_status"] == "complete"
                && read.get("read_error").is_some_and(Value::is_null)
                && read.get("write_error").is_some_and(Value::is_null)
                && read["torn"].as_bool().is_some()
                && read["paused"].as_bool().is_some()
                && expected.len() == 64
                && expected.bytes().all(|b| b.is_ascii_hexdigit())
                && bytes.is_some_and(|n| known.get(relative.as_str()) == Some(&n));
            observation["relative_path"] = json!(relative);
            observation["source_identity_status"] = json!(if identity_known {
                "producer_identity_recorded"
            } else {
                "unknown_or_conflicting"
            });
            observation["retained_file_bytes"] = json!(known.get(relative.as_str()));
            observation["metadata_eligible"] = json!(valid);
            let reason = if !record.is_object() {
                Some("record_not_object")
            } else if !identity_known {
                Some("source_identity_missing_or_conflicting")
            } else if !range_known {
                Some("missing_or_inconsistent_range")
            } else if !safe_raw {
                Some("unsafe_or_missing_range")
            } else if !valid {
                Some("range_metadata_not_admitted_or_complete")
            } else {
                None
            };
            observation["content_verification_failure_reason"] = json!(reason);
            let inventory_index = inventory.len();
            inventory.push(observation);
            if valid {
                queue.push(RangeWork {
                    inventory_index,
                    relative,
                    expected: expected.to_owned(),
                    bytes: bytes.unwrap(),
                    priority: mapping_priority(record["mapping"]["path"].as_str().unwrap_or("")),
                });
            }
        }
        let rejected_prefix_len = rejected_prefix.len();
        diagnostic["rejected_record_prefix"] = json!(rejected_prefix);
        diagnostic["rejected_records_not_materialized"] =
            json!((rejected_invalid + rejected_unwalked).saturating_sub(rejected_prefix_len));
        diagnostic["rejected_records_invalid"] = json!(rejected_invalid);
        diagnostic["rejected_records_unwalked"] = json!(rejected_unwalked);
        diagnostic["rejected_record_reasons"] = json!(rejected_reasons);
        source_diagnostics.push(diagnostic);
    }

    // Every eligible row is inventoried before the heavy-result limit is used.
    // Header probes cannot spend hash bytes or promote producer metadata.
    for work in &mut queue {
        let checkpoint = root.join(&work.relative);
        if let Some(reason) = scope_failure_at(&checkpoint) {
            inventory[work.inventory_index]["probe_failure_reason"] = json!(reason);
            continue;
        }
        if !safe_local_file(root, &work.relative) {
            inventory[work.inventory_index]["probe_failure_reason"] =
                json!("unsafe_or_missing_range");
            continue;
        }
        let cached = stable_cache_snapshot_anchored(root, &work.relative)
            .ok()
            .and_then(|stamp| {
                stamp
                    .cacheable()
                    .then(|| probe_cache.get(&stamp).copied())
                    .flatten()
            });
        let probe_before = inspection_budget;
        let header = if let Some(priority) = cached {
            priority
        } else {
            match probe_priority_anchored(root, &work.relative, &mut inspection_budget) {
                Ok((priority, stamp, _actual)) => {
                    if stamp.cacheable() {
                        probe_cache.insert(stamp, priority);
                    }
                    priority
                }
                Err(reason) => {
                    inventory[work.inventory_index]["probe_failure_reason"] = json!(reason);
                    None
                }
            }
        };
        probe_bytes += probe_before - inspection_budget;
        if let Some(priority) = header {
            work.priority = work.priority.min(priority);
        }
        inventory[work.inventory_index]["analysis_priority"] = json!(work.priority);
    }
    queue.sort_by_key(|work| (work.priority, work.bytes, work.inventory_index));

    for work in &queue {
        let checkpoint = root.join(&work.relative);
        let key = format!("{}:{}", work.expected, work.bytes);
        let mut failure = scope_failure_at(&checkpoint);
        let mut retained = None;
        let mut verified = false;
        let mut cached_stamp = None;
        let analysis_known = inspections.contains_key(&key);
        let retain = !analysis_known
            && work.bytes <= RUNTIME_RANGE_FILE_CAP
            && work.bytes <= inspection_budget;
        if failure.is_none() && !safe_local_file(root, &work.relative) {
            failure = Some("unsafe_or_missing_range");
        }
        if failure.is_none() {
            match stable_cache_snapshot_anchored(root, &work.relative) {
                Ok(stamp) if stamp.len == work.bytes => {
                    if let Some(actual) = stamp
                        .cacheable()
                        .then(|| verified_inodes.get(&stamp))
                        .flatten()
                    {
                        runtime_hash_cache_hits += 1;
                        verified = actual == &work.expected;
                        if verified {
                            cached_stamp = Some(stamp);
                        } else {
                            failure = Some("range_hash_mismatch");
                        }
                    } else if range_budget_admits(work.bytes, hash_budget) {
                        hash_budget -= work.bytes;
                        hash_bytes += work.bytes;
                        match stable_hash_read_anchored(
                            root,
                            &work.relative,
                            work.bytes,
                            retain,
                            &mut inspection_budget,
                        ) {
                            Ok(read) if read.sha256 == work.expected => {
                                verified = true;
                                retained = read.retained;
                                if read.snapshot.cacheable() {
                                    verified_inodes.insert(read.snapshot, read.sha256);
                                }
                            }
                            Ok(_) => failure = Some("range_hash_mismatch"),
                            Err(reason) => failure = Some(reason),
                        }
                    } else {
                        failure = Some(if work.bytes > RUNTIME_RANGE_FILE_CAP {
                            "range_hash_file_limit"
                        } else {
                            "range_hash_budget_exhausted"
                        });
                    }
                }
                Ok(_) => failure = Some("range_length_changed"),
                Err(reason) => failure = Some(reason),
            }
        }
        let row = &mut inventory[work.inventory_index];
        row["content_verification_failure_reason"] = json!(failure);
        row["local_content_status"] = json!(if verified {
            "complete_range_hash_verified"
        } else {
            "unknown_or_failed"
        });
        if !verified {
            continue;
        }
        verified_paths.insert(work.relative.clone(), (work.expected.clone(), work.bytes));
        row["mapping_complete"] = json!(
            row["read"]["requested_start"] == row["mapping"]["start"]
                && row["read"]["actual_length"].as_u64()
                    == row["mapping"]["end"]
                        .as_u64()
                        .zip(row["mapping"]["start"].as_u64())
                        .map(|(e, s)| e - s)
        );
        if !analysis_known && retain && retained.is_none() {
            if let Some(stamp) = cached_stamp {
                match stable_retained_read_anchored(
                    root,
                    &work.relative,
                    work.bytes,
                    &stamp,
                    &mut inspection_budget,
                ) {
                    Ok(bytes) => retained = Some(bytes),
                    Err(reason) => {
                        row["object_inspection"] =
                            json!({"status":"unknown_scope_or_read_failed","reason":reason})
                    }
                }
            }
        }
        if let Some(bytes) = retained {
            let mut analysis = match scope_failure_at(&checkpoint) {
                Some(reason) => json!({"status":"unknown_scope_stopped","reason":reason}),
                None => inspect_runtime_bytes_with_class_budget(
                    &bytes,
                    &mut class_index_budget,
                    Some(&checkpoint),
                ),
            };
            if let Some(reason) = scope_failure_at(&checkpoint) {
                analysis["scope_stop_reason"] = json!(reason);
                analysis["omitted_after_stop"] = json!(true);
            }
            let summary = inspection_summary(&analysis);
            let derived = analysis["derived_objects"]
                .as_array()
                .is_some_and(|objects| !objects.is_empty());
            let heavy_row_index = if derived && runtime.len() < RUNTIME_OBSERVATION_LIMIT {
                let mut heavy = row.clone();
                heavy["inventory_role"] = json!("canonical_heavy_analysis");
                heavy["runtime_range_inventory_index"] = json!(work.inventory_index);
                heavy["parse_status"] = json!("derived_slice_inside_retained_range; container_file_not_a_reconstructed_dex_or_so");
                add_inspection_source(&mut analysis, &heavy);
                heavy["object_inspection"] = analysis;
                let index = runtime.len();
                runtime.push(heavy);
                Some(index)
            } else {
                None
            };
            inspections.insert(
                key.clone(),
                InspectionReference {
                    summary,
                    heavy_row_index,
                },
            );
        }
        if let Some(reference) = inspections.get(&key) {
            row["object_inspection"] = reference.summary.clone();
            row["runtime_observation_row_index"] = json!(reference.heavy_row_index);
            if reference.summary["derived_objects"]
                .as_array()
                .is_some_and(|objects| !objects.is_empty())
            {
                row["parse_status"] =
                    json!("derived_slice_summary; canonical_heavy_analysis_reference");
                if reference.heavy_row_index.is_none() {
                    row["analysis_omission_reason"] = json!("runtime_observation_limit");
                }
            }
        } else if row["object_inspection"]["status"] == "unknown_unverified_or_oversized_range" {
            row["object_inspection"] = json!({"status":"unknown_inspection_budget_exhausted"});
        }
    }

    // Light samples fill only remaining slots after every derived DEX result
    // had priority. Equal-content rows point to one canonical sample; full
    // source associations remain in inventory, including ELF segment windows.
    for (inventory_index, row) in inventory.iter_mut().enumerate() {
        if row["metadata_eligible"] != true
            || row["local_content_status"] != "complete_range_hash_verified"
        {
            continue;
        }
        let key = format!(
            "{}:{}",
            row["read"]["sha256"].as_str().unwrap_or(""),
            row["read"]["actual_length"].as_u64().unwrap_or(0)
        );
        let Some(reference) = inspections.get_mut(&key) else {
            continue;
        };
        if reference.heavy_row_index.is_none()
            && !reference.summary["derived_objects"]
                .as_array()
                .is_some_and(|objects| !objects.is_empty())
            && runtime.len() < RUNTIME_OBSERVATION_LIMIT
        {
            let mut sample = row.clone();
            sample["inventory_role"] = json!("canonical_light_sample");
            sample["runtime_range_inventory_index"] = json!(inventory_index);
            let index = runtime.len();
            runtime.push(sample);
            reference.heavy_row_index = Some(index);
        }
        row["runtime_observation_row_index"] = json!(reference.heavy_row_index);
    }

    for row in &mut inventory {
        if row["local_content_status"] != "complete_range_hash_verified" {
            continue;
        }
        let key = format!(
            "{}:{}",
            row["read"]["sha256"].as_str().unwrap_or(""),
            row["read"]["actual_length"].as_u64().unwrap_or(0)
        );
        if let Some(reference) = inspections.get(&key) {
            row["inspection_ref"] = json!(reference.heavy_row_index);
            row["inspection_content_key"] = json!(key);
            row["inspection_status"] = reference.summary["status"].clone();
            row["runtime_observation_row_index"] = json!(reference.heavy_row_index);
            if let Some(index) = reference.heavy_row_index {
                runtime[index]["inspection_ref"] = json!(index);
                runtime[index]["inspection_content_key"] = row["inspection_content_key"].clone();
                runtime[index]["inspection_status"] = row["inspection_status"].clone();
                runtime[index]["runtime_observation_row_index"] = json!(index);
            }
        }
    }

    // Derive source terminal counts from all original note records. A capacity
    // unknown is distinct from malformed producer metadata or a hash mismatch.
    let mut runtime_unverified = 0_usize;
    let mut heavy_omitted = 0_usize;
    for (diagnostic_index, diagnostic) in source_diagnostics.iter_mut().enumerate() {
        if diagnostic["records_seen"].is_null() {
            continue;
        }
        let rows = inventory
            .iter()
            .filter(|row| row["source_diagnostic_index"].as_u64() == Some(diagnostic_index as u64));
        let rejected_invalid =
            diagnostic["rejected_records_invalid"].as_u64().unwrap_or(0) as usize;
        let rejected_unwalked = diagnostic["rejected_records_unwalked"]
            .as_u64()
            .unwrap_or(0) as usize;
        let rejected = rejected_invalid + rejected_unwalked;
        runtime_unverified += rejected;
        let mut processed = rejected_invalid;
        let mut verified = 0_usize;
        let mut metadata_invalid = rejected_invalid;
        let mut integrity_invalid = 0_usize;
        let mut unknown = rejected;
        let mut source_heavy_omitted = 0_usize;
        let mut source_unwalked = rejected_unwalked;
        let mut analysis_complete = 0_usize;
        let mut analysis_partial = rejected;
        let mut analysis_reasons = BTreeMap::<String, usize>::new();
        let mut reasons = diagnostic["rejected_record_reasons"]
            .as_object()
            .into_iter()
            .flatten()
            .filter_map(|(reason, count)| {
                count.as_u64().map(|count| (reason.clone(), count as usize))
            })
            .collect::<BTreeMap<_, _>>();
        if rejected_invalid > 0 {
            analysis_reasons.insert("rejected_malformed_record".into(), rejected_invalid);
        }
        if rejected_unwalked > 0 {
            analysis_reasons.insert("scope_metadata_not_walked".into(), rejected_unwalked);
        }
        for row in rows {
            if row["metadata_walk_status"] == "eligibility_walked" {
                processed += 1;
            } else {
                source_unwalked += 1;
            }
            if row["local_content_status"] == "complete_range_hash_verified" {
                verified += 1;
            } else {
                runtime_unverified += 1;
                unknown += 1;
                if row["metadata_eligible"] == false {
                    metadata_invalid += 1;
                }
                if row["content_verification_failure_reason"] == "range_hash_mismatch" {
                    integrity_invalid += 1;
                }
                if let Some(reason) = row["content_verification_failure_reason"].as_str() {
                    *reasons.entry(reason.to_owned()).or_default() += 1;
                }
            }
            if let Some(reason) = row["analysis_omission_reason"].as_str() {
                source_heavy_omitted += 1;
                *reasons.entry(reason.to_owned()).or_default() += 1;
            }
            let row_gaps = runtime_analysis_gaps(std::slice::from_ref(row));
            if row_gaps.is_empty() && row["analysis_omission_reason"].is_null() {
                analysis_complete += 1;
            } else {
                analysis_partial += 1;
            }
            for (reason, count) in row_gaps {
                *analysis_reasons.entry(reason.to_owned()).or_default() += count;
            }
            if let Some(reason) = row["object_inspection"]["reason"].as_str() {
                *analysis_reasons.entry(reason.to_owned()).or_default() += 1;
            }
        }
        omitted += source_unwalked;
        heavy_omitted += source_heavy_omitted;
        diagnostic["processed_records"] = json!(processed);
        diagnostic["processed_records_scope"] =
            json!("metadata eligibility walk, not complete analysis");
        diagnostic["verified_records"] = json!(verified);
        diagnostic["metadata_invalid_records"] = json!(metadata_invalid);
        diagnostic["integrity_invalid_records"] = json!(integrity_invalid);
        diagnostic["invalid_records"] = json!(metadata_invalid + integrity_invalid);
        diagnostic["unknown_records"] =
            json!(unknown.saturating_sub(metadata_invalid + integrity_invalid));
        diagnostic["unverified_records"] = json!(unknown);
        diagnostic["omitted_records"] = json!(source_unwalked);
        diagnostic["metadata_walk_omitted_records"] = json!(source_unwalked);
        diagnostic["analysis_complete_records"] = json!(analysis_complete);
        diagnostic["analysis_unknown_or_partial_records"] = json!(analysis_partial);
        diagnostic["analysis_partial_reasons"] = json!(analysis_reasons);
        if source_unwalked > 0 {
            diagnostic["records_walked"] = json!(false);
            let scope_reason = inventory
                .iter()
                .find(|row| {
                    row["source_diagnostic_index"].as_u64() == Some(diagnostic_index as u64)
                        && row["metadata_walk_status"] == "unknown_scope_not_walked"
                })
                .and_then(|row| row["content_verification_failure_reason"].as_str())
                .or_else(|| diagnostic["scope_stop_reason"].as_str())
                .unwrap_or("unknown_scope_failure")
                .to_owned();
            diagnostic["scope_stop_reason"] = json!(scope_reason);
            diagnostic["omission_reason"] = json!(scope_reason);
        }
        diagnostic["heavy_results_omitted_records"] = json!(source_heavy_omitted);
        diagnostic["verification_failure_reasons"] = json!(reasons);
        if unknown > 0 || source_heavy_omitted > 0 || analysis_partial > 0 {
            diagnostic["status"] = json!("partial_records");
        }
    }
    failures += runtime_unverified;
    let code_logical = verified_paths.values().map(|(_, n)| *n).sum::<u64>();
    let unique = verified_paths
        .values()
        .cloned()
        .collect::<BTreeSet<_>>()
        .iter()
        .map(|(_, n)| *n)
        .sum::<u64>();
    let (elf_modules, elf_scope_failure) = match super::elf_runtime::module_views_scoped(
        root, &inventory,
    ) {
        Ok(modules) => (modules, None),
        Err(reason) => {
            failures += 1;
            (
                json!([{"schema":"mobilee.verified-elf-load-view/v1","status":"unknown_scope_stopped",
                "reason":reason,"complete_file_reconstructed":false,"ownership":"unknown"}]),
                Some(reason),
            )
        }
    };
    let ledger_complete = source_omitted == 0 && omitted == 0 && failures == 0;
    let mut analysis_gaps = runtime_analysis_gaps(&inventory);
    if elf_scope_failure.is_some() {
        analysis_gaps.insert("elf_module_scope_stopped", 1);
    }
    if omitted > 0 {
        analysis_gaps.insert("source_or_observation_omission", omitted);
    }
    if failures > 0 {
        analysis_gaps.insert("unverified_ledger_observations", failures);
    }
    if heavy_omitted > 0 {
        analysis_gaps.insert("canonical_heavy_analysis_omission", heavy_omitted);
    }
    let mut ledger = json!({"schema":"mobilee.local-storage-evidence/v1","logical_file_bytes":logical,
        "unique_inode_bytes":if cfg!(unix){Some(inode_bytes)}else{None},"allocated_bytes":if cfg!(unix){Some(allocated)}else{None},
        "shared_inode_logical_bytes":if cfg!(unix){Some(logical.saturating_sub(inode_bytes))}else{None},
        "allocation_basis":if cfg!(unix){"unique_inode_st_blocks_512"}else{"unavailable"},"unknown_metadata_files":unknown_metadata,"category_logical_bytes":categories,
        "verified_code_logical_bytes":code_logical,"verified_code_unique_bytes":unique,"verified_code_duplicate_bytes":code_logical.saturating_sub(unique),
        "unverified_observations":failures,"omitted_observations":omitted,"hash_budget_bytes":RUNTIME_RANGE_TREE_CAP,
        "hash_budget_file_cap_bytes":RUNTIME_RANGE_FILE_CAP,"hash_budget_remaining":hash_budget,"full_hash_bytes_charged":hash_bytes,
        "static_stable_inode_hash_cache_hits":static_hash_cache_hits,"runtime_stable_inode_hash_cache_hits":runtime_hash_cache_hits,
        "inspection_budget_bytes":RUNTIME_RANGE_TREE_CAP,"inspection_budget_remaining":inspection_budget,"runtime_header_probe_bytes":probe_bytes,
        "runtime_header_probe_prefix_cap_bytes":RUNTIME_PROBE_PREFIX_CAP,
        "observations":observations,"runtime_observations":runtime,"runtime_range_inventory":inventory,
        "runtime_inventory_role":"all admitted-document record metadata; class arrays retained only in canonical runtime_observations",
        "elf_module_observations":elf_modules});
    let Value::Object(extra) = json!({"runtime_source_diagnostics":source_diagnostics,
        "runtime_source_limit":BOUND_SOURCE_COUNT_LIMIT,"runtime_sources_omitted":source_omitted,
        "runtime_observation_limit":RUNTIME_OBSERVATION_LIMIT,"runtime_heavy_results_omitted_records":heavy_omitted,
        "runtime_source_ledger_complete":ledger_complete,"runtime_analysis_complete":ledger_complete && analysis_gaps.is_empty(),
        "runtime_analysis_partial_reasons":analysis_gaps,
        "runtime_analysis_scope":"bounded candidate walk and class index only; not collection coverage, consistent mapping snapshot, full DEX verification or code reconstruction",
        "bound_source_byte_limit":BOUND_SOURCE_BYTE_LIMIT,
        "bound_source_metadata_contract":{"schema":"kernsight.bound-code-copy/v1","producer_definition":"qualified_code.rs@6a1b833",
            "document_bytes":BOUND_SOURCE_BYTE_LIMIT,"inventory_bytes":BOUND_SOURCE_TOTAL_BYTE_LIMIT,"inventory_documents":BOUND_SOURCE_COUNT_LIMIT,
            "document_records":BOUND_SOURCE_RECORD_LIMIT,"inventory_metadata_budget_remaining":source_byte_budget},
        "class_index_descriptor_budget_bytes":4194304,"class_index_descriptor_budget_scope":"per dex image; not a shared pool across images",
        "class_index_descriptor_budget_remaining":class_index_budget,
        "warnings":["Content redundancy is an accounting opportunity, not physical disk savings",
            "APK members and producer transformations are provenance assertions; local verification hashes retained files only",
            "This bounded code ledger does not hash private data or old memory windows"]})
    else {
        unreachable!()
    };
    ledger.as_object_mut().unwrap().extend(extra);
    ledger
}

/// Reuse the existing bounded DEX splitter/semantic parser. Slice references
/// identify original bytes; no repaired or standalone file is fabricated.
#[cfg(test)]
fn inspect_runtime_bytes(bytes: &[u8]) -> Value {
    inspect_runtime_bytes_with_class_budget(bytes, &mut 1048576, None)
}
fn dex_layout_diagnostics(bytes: &[u8]) -> Value {
    let word = |at: usize| {
        bytes
            .get(at..at + 4)
            .and_then(|b| b.try_into().ok())
            .map(u32::from_le_bytes)
            .map(u64::from)
    };
    if bytes.len() < 112 || !matches!(&bytes[4..7], b"035" | b"037" | b"038" | b"039" | b"040") {
        return json!({"status":"unknown_unsupported_header_version","full_dex_verifier":false});
    }
    let declared = word(32).unwrap();
    let data_off = word(108).unwrap();
    let data_size = word(104).unwrap();
    let link_off = word(48).unwrap();
    let link_size = word(44).unwrap();
    let data_end = data_off + data_size;
    let link_end = link_off + link_size;
    let end = 112_u64.max(data_end).max(link_end);
    let bounds = data_end <= declared && link_end <= declared && declared == bytes.len() as u64;
    json!({"status":if !bounds {"declared_spans_out_of_bounds"} else if end<declared {"declared_spans_leave_unaccounted_tail"}else{"declared_spans_cover_file"},"actual_bytes":bytes.len(),"declared_file_bytes":declared,"declared_data_start":data_off,"declared_data_bytes":data_size,"declared_data_end":data_end,"declared_link_start":link_off,"declared_link_bytes":link_size,"trailing_unaccounted_bytes":declared.saturating_sub(end),"full_dex_verifier":false,"scope":"header-declared data/link spans only; map entries and instruction code items not fully validated; trailing bytes remain uninterpreted"})
}
struct DexCandidateScan {
    images: Vec<(usize, usize)>,
    rejected: Vec<Value>,
    stop_reason: Option<&'static str>,
    scanned_through: usize,
}

fn fitting_dex_images(bytes: &[u8]) -> DexCandidateScan {
    let mut images = Vec::new();
    let mut rejected = Vec::new();
    let mut search = 0_usize;
    let mut stop_reason = None;
    let mut scanned_through = 0_usize;
    // Step through every `dex\n`, including ones inside a shell whose declared
    // length covers a later image. Do not jump to `at + declared`.
    // Stop at 64 candidates and say so; do not treat the unread tail as scanned.
    while search.saturating_add(4) <= bytes.len() {
        if images.len() >= 64 {
            stop_reason = Some("accepted_image_limit");
            break;
        }
        if rejected.len() >= 64 {
            stop_reason = Some("rejected_candidate_limit");
            break;
        }
        let Some(rel) = memchr::memmem::find(&bytes[search..], b"dex\n") else {
            scanned_through = bytes.len();
            break;
        };
        let at = search.saturating_add(rel);
        let inside_accepted = images
            .iter()
            .any(|(off, len)| at > *off && at < off.saturating_add(*len));
        let word = |offset: usize| {
            bytes
                .get(at.saturating_add(offset)..at.saturating_add(offset).saturating_add(4))
                .and_then(|raw| raw.try_into().ok())
                .map(u32::from_le_bytes)
        };
        let declared = word(32);
        let endian = word(40);
        let header_ok = bytes.get(at..at.saturating_add(8)).is_some_and(|header| {
            header.starts_with(b"dex\n")
                && header[4..7].iter().all(u8::is_ascii_digit)
                && header[7] == 0
        }) && word(36) == Some(112)
            && endian == Some(0x1234_5678)
            && declared.is_some_and(|n| n >= 112);
        if header_ok {
            let declared = declared.unwrap_or(0) as usize;
            if at.saturating_add(declared) <= bytes.len() {
                images.push((at, declared));
            } else if rejected.len() < 64 {
                rejected.push(json!({
                    "source_offset": at,
                    "reason": "declared_dex_extends_beyond_retained_range",
                    "header_claim_only": true,
                    "declared_length": declared,
                    "available_range_bytes": bytes.len().saturating_sub(at),
                    "missing_declared_bytes": (declared as u64).saturating_sub(bytes.len().saturating_sub(at) as u64),
                    "complete_dex_validated": false
                }));
            }
        } else if !inside_accepted && rejected.len() < 64 {
            rejected.push(json!({
                "source_offset": at,
                "reason": "truncated_or_invalid_dex_header_and_declared_bounds",
                "header_claim_only": true,
                "declared_length": null,
                "available_range_bytes": bytes.len().saturating_sub(at),
                "complete_dex_validated": false
            }));
        }
        search = at.saturating_add(4);
        scanned_through = search;
    }
    DexCandidateScan {
        images,
        rejected,
        stop_reason,
        scanned_through,
    }
}

fn inspect_runtime_bytes_with_class_budget(
    bytes: &[u8],
    _class_budget: &mut usize,
    checkpoint: Option<&Path>,
) -> Value {
    let DexCandidateScan {
        images,
        mut rejected,
        stop_reason,
        scanned_through,
    } = fitting_dex_images(bytes);
    let file_bytes = bytes.len();
    let unscanned_tail = file_bytes.saturating_sub(scanned_through);
    let elf_magic =
        memchr::memmem::find_iter(bytes.get(..scanned_through).unwrap_or(&[]), b"\x7fELF").count();
    let mut objects = Vec::new();
    let mut scope_stop = None;
    for (offset, len) in images {
        if let Some(reason) = checkpoint.and_then(scope_failure_at).or_else(scope_failure) {
            scope_stop = Some(reason);
            break;
        }
        let slice = &bytes[offset..offset.saturating_add(len)];
        // Each image gets its own descriptor budget. A shared 1MiB pool was cutting later DEX.
        let mut dex_budget = 4 * 1024 * 1024_usize;
        match ksight_core::parse_dex_semantics(slice) {
            Some(semantic) => objects.push(json!({"kind":"dex","source_offset":offset,"length":slice.len(),"declared_file_bytes":semantic.declared_file_size,"length_matches_declared":semantic.declared_file_size==slice.len() as u64,"sha256":format!("{:x}",Sha256::digest(slice)),"semantic":semantic,"layout_diagnostics":dex_layout_diagnostics(slice),"class_index":super::dex_class_index::classes(slice, &mut dex_budget),"sha1_signature_verified":sha1::Sha1::digest(&slice[32..]).as_slice()==&slice[12..32],"adler32_checksum_verified":dex_adler32(&slice[12..])==u32::from_le_bytes(slice[8..12].try_into().unwrap()),"validation_level":"bounded_semantic_tables_and_checksum_results; instruction_code_items_not_fully_validated","retained_as_separate_file":false,"ownership":"unknown","relationship":"exact_declared_length_slice_of_original_runtime_range"})),
            None => rejected.push(json!({"source_offset":offset,"reason":"semantic_tables_invalid_or_unsupported","declared_length":len,"complete_dex_validated":false})),
        }
    }
    json!({"status":if objects.is_empty() && rejected.is_empty() && elf_magic==0 {"no_dex_or_elf_header_in_retained_range"} else {"bounded_candidate_inspection"},"file_bytes":file_bytes,"scanned_bytes":scanned_through,"scanned_through_offset":scanned_through,"unscanned_tail_bytes":unscanned_tail,"candidate_stop_reason":stop_reason,"scope_stop_reason":scope_stop,"omitted_after_stop":(stop_reason.is_some() && unscanned_tail > 0) || scope_stop.is_some(),"dex_magic_count":objects.len()+rejected.len(),"elf_magic_count":elf_magic,"elf_header":super::elf_runtime::header(bytes.get(..scanned_through).unwrap_or(&[])),"derived_objects":objects,"rejected_candidates":rejected,"elf_status":if elf_magic==0 {"no_elf_header"} else {"unknown_no_linked_elf_reconstruction_parser"},"boundary":"file_bytes is the retained file; scanned_bytes is only the DEX candidate walk. A stop leaves unscanned_tail_bytes unread"})
}

fn dex_adler32(bytes: &[u8]) -> u32 {
    let (mut a, mut b) = (1_u32, 0_u32);
    for chunk in bytes.chunks(5552) {
        for byte in chunk {
            a += u32::from(*byte);
            b += a;
        }
        a %= 65521;
        b %= 65521;
    }
    (b << 16) | a
}

fn safe_local_file(root: &Path, relative: &str) -> bool {
    let mut path = root.to_path_buf();
    for part in Path::new(relative).components() {
        let std::path::Component::Normal(name) = part else {
            return false;
        };
        path.push(name);
        if fs::symlink_metadata(&path).map_or(true, |m| m.file_type().is_symlink()) {
            return false;
        }
    }
    fs::metadata(path).is_ok_and(|m| m.is_file())
}

fn read_inspection_bytes_result(path: &Path, expected: u64) -> Result<Vec<u8>, &'static str> {
    if let Some(reason) = scope_failure_at(path) {
        return Err(reason);
    }
    let file = fs::File::open(path).map_err(|_| "range_read_failed")?;
    let mut bytes = Vec::new();
    super::session_budget::CheckedReader::new(file, path)
        .take(expected.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| read_failure(&error, "range_read_failed"))?;
    if let Some(reason) = scope_failure_at(path) {
        return Err(reason);
    }
    if bytes.len() as u64 != expected {
        return Err("range_length_changed");
    }
    Ok(bytes)
}

#[cfg(test)]
fn read_inspection_bytes(path: &Path, expected: u64) -> Option<Vec<u8>> {
    read_inspection_bytes_result(path, expected).ok()
}

fn hash_file_result(path: &Path, expected: u64) -> Result<String, &'static str> {
    let file = fs::File::open(path).map_err(|_| "range_read_failed")?;
    let mut file = super::session_budget::CheckedReader::new(file, path);
    let mut hash = Sha256::new();
    let mut n = 0_u64;
    let mut buffer = [0; 65536];
    loop {
        let count = file
            .read(&mut buffer)
            .map_err(|error| read_failure(&error, "range_read_failed"))?;
        if count == 0 {
            break;
        }
        n = n.checked_add(count as u64).ok_or("range_length_overflow")?;
        if n > expected {
            return Err("range_length_changed");
        }
        hash.update(&buffer[..count]);
    }
    if let Some(reason) = scope_failure_at(path) {
        return Err(reason);
    }
    if n != expected {
        return Err("range_length_changed");
    }
    Ok(format!("{:x}", hash.finalize()))
}

pub(super) fn hash_file(path: &Path, expected: u64) -> Option<String> {
    hash_file_result(path, expected).ok()
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn runtime_inspection_reuses_dex_parser_and_rejects_fake_truncated_headers() {
        let mut dex = vec![0_u8; 112];
        dex[..8].copy_from_slice(b"dex\n035\0");
        dex[32..36].copy_from_slice(&112_u32.to_le_bytes());
        dex[36..40].copy_from_slice(&112_u32.to_le_bytes());
        dex[40..44].copy_from_slice(&0x12345678_u32.to_le_bytes());
        let mut bytes = vec![9_u8; 17];
        bytes.extend(&dex);
        let valid = inspect_runtime_bytes(&bytes);
        assert_eq!(valid["derived_objects"][0]["source_offset"], 17);
        assert_eq!(valid["derived_objects"][0]["length"], 112);
        assert_eq!(valid["derived_objects"][0]["semantic"]["class_defs"], 0);
        assert_eq!(
            valid["derived_objects"][0]["retained_as_separate_file"],
            false
        );
        assert_eq!(valid["derived_objects"][0]["ownership"], "unknown");
        for bad in [&bytes[..bytes.len() - 1], b"dex\nnot-a-dex".as_slice()] {
            let result = inspect_runtime_bytes(bad);
            assert!(result["derived_objects"].as_array().unwrap().is_empty());
            assert_eq!(result["rejected_candidates"].as_array().unwrap().len(), 1);
        }
        assert_eq!(
            inspect_runtime_bytes(b"\x7fELFfake")["elf_status"],
            "unknown_no_linked_elf_reconstruction_parser"
        );
    }
    #[test]
    fn shell_declared_length_keeps_the_inner_dex_at_its_own_length() {
        let mut image = vec![0_u8; 0xE0];
        image[..8].copy_from_slice(b"dex\n035\0");
        image[32..36].copy_from_slice(&0xE0_u32.to_le_bytes());
        image[36..40].copy_from_slice(&112_u32.to_le_bytes());
        image[40..44].copy_from_slice(&0x1234_5678_u32.to_le_bytes());
        image[0x70..0x78].copy_from_slice(b"dex\n035\0");
        image[0x70 + 32..0x70 + 36].copy_from_slice(&0x70_u32.to_le_bytes());
        image[0x70 + 36..0x70 + 40].copy_from_slice(&112_u32.to_le_bytes());
        image[0x70 + 40..0x70 + 44].copy_from_slice(&0x1234_5678_u32.to_le_bytes());
        let view = inspect_runtime_bytes(&image);
        let objects = view["derived_objects"].as_array().unwrap();
        assert_eq!(objects.len(), 2);
        assert_eq!(objects[0]["length"], 0xE0);
        assert_eq!(objects[0]["length_matches_declared"], true);
        assert_eq!(objects[1]["source_offset"], 0x70);
        assert_eq!(objects[1]["length"], 0x70);
        assert_eq!(objects[1]["length_matches_declared"], true);
    }
    #[test]
    fn declared_oversize_shell_does_not_hide_a_fitting_inner_dex() {
        let mut image = vec![0_u8; 0x70 + 0x70];
        image[..8].copy_from_slice(b"dex\n035\0");
        image[32..36].copy_from_slice(&50_000_u32.to_le_bytes());
        image[36..40].copy_from_slice(&112_u32.to_le_bytes());
        image[40..44].copy_from_slice(&0x1234_5678_u32.to_le_bytes());
        image[0x70..0x78].copy_from_slice(b"dex\n035\0");
        image[0x70 + 32..0x70 + 36].copy_from_slice(&0x70_u32.to_le_bytes());
        image[0x70 + 36..0x70 + 40].copy_from_slice(&112_u32.to_le_bytes());
        image[0x70 + 40..0x70 + 44].copy_from_slice(&0x1234_5678_u32.to_le_bytes());
        let view = inspect_runtime_bytes(&image);
        assert_eq!(
            view["rejected_candidates"][0]["reason"],
            "declared_dex_extends_beyond_retained_range"
        );
        let objects = view["derived_objects"].as_array().unwrap();
        assert_eq!(objects.len(), 1);
        assert_eq!(objects[0]["source_offset"], 0x70);
        assert_eq!(objects[0]["length"], 0x70);
        assert_eq!(objects[0]["length_matches_declared"], true);
    }
    #[test]
    fn sixty_four_bad_candidates_stop_before_a_later_real_dex() {
        let mut bytes = Vec::new();
        for _ in 0..64 {
            bytes.extend_from_slice(b"dex\nXXXX");
        }
        let real_at = bytes.len();
        bytes.extend_from_slice(b"dex\n035\0");
        bytes.resize(real_at + 112, 0);
        bytes[real_at + 32..real_at + 36].copy_from_slice(&112_u32.to_le_bytes());
        bytes[real_at + 36..real_at + 40].copy_from_slice(&112_u32.to_le_bytes());
        bytes[real_at + 40..real_at + 44].copy_from_slice(&0x1234_5678_u32.to_le_bytes());
        let view = inspect_runtime_bytes(&bytes);
        assert!(view["derived_objects"].as_array().unwrap().is_empty());
        assert_eq!(view["rejected_candidates"].as_array().unwrap().len(), 64);
        assert_eq!(view["candidate_stop_reason"], "rejected_candidate_limit");
        assert!(view["scanned_through_offset"].as_u64().unwrap() <= real_at as u64);
        assert_eq!(view["omitted_after_stop"], true);
        assert_eq!(view["file_bytes"], bytes.len() as u64);
        assert_eq!(view["scanned_bytes"], view["scanned_through_offset"]);
        assert!(view["unscanned_tail_bytes"].as_u64().unwrap() > 0);
        assert!(view["scanned_bytes"].as_u64().unwrap() < view["file_bytes"].as_u64().unwrap());
    }
    #[test]
    fn tree_budget_keeps_a_later_range_after_the_old_128mib_pool_would_be_spent() {
        let mut remaining = RUNTIME_RANGE_TREE_CAP;
        let first = 90 * 1024 * 1024;
        assert!(range_budget_admits(first, remaining));
        remaining -= first;
        let second = 76 * 1024 * 1024;
        assert!(first + second > RUNTIME_RANGE_FILE_CAP);
        assert!(range_budget_admits(second, remaining));
        assert!(!range_budget_admits(RUNTIME_RANGE_FILE_CAP + 1, remaining));
        assert!(range_budget_admits(
            RUNTIME_RANGE_FILE_CAP,
            RUNTIME_RANGE_TREE_CAP
        ));
    }
    fn runtime_fixture() -> (std::path::PathBuf, Vec<(String, u64)>, Value) {
        let root = std::env::temp_dir().join(format!("me-runtime-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(root.join("runtime")).unwrap();
        let bytes = [7; 256];
        fs::write(root.join("runtime/bound-fixture.code"), bytes).unwrap();
        let source = json!({"package":"org.example.fixture","pid":42,"uid":10001,"birth_ns":77,"exec_id":4,"boot_id":"fixture-boot"});
        let note = json!({"schema":"kernsight.bound-code-copy/v1","source":source,"partial":true,"torn":true,"records":[{
            "source":source,"mapping":{"start":4096,"end":8192,"path":"/memfd:fixture","perms":"r-x"},"raw_evidence":"bound-fixture.code","admitted":true,"derived":[],
            "read":{"requested_start":4096,"requested_length":256,"actual_start":4096,"actual_length":256,"read_status":"complete","write_status":"complete","read_error":null,"write_error":null,"admission":"qualified_live_copy","sha256":format!("{:x}",Sha256::digest(bytes)),"torn":true,"paused":false}}]});
        (
            root,
            vec![
                ("runtime/bound-fixture.code".into(), 256),
                ("runtime/bound-source-fixture.json".into(), 0),
            ],
            note,
        )
    }
    #[test]
    fn runtime_complete_range_is_not_complete_mapping_or_parsed_dex() {
        let (root, files, note) = runtime_fixture();
        fs::write(
            root.join("runtime/bound-source-fixture.json"),
            serde_json::to_vec(&note).unwrap(),
        )
        .unwrap();
        let result = account(&root, &files);
        assert_eq!(result["verified_code_unique_bytes"], 256);
        let row = &result["runtime_observations"][0];
        assert_eq!(row["local_content_status"], "complete_range_hash_verified");
        assert_eq!(row["mapping_complete"], false);
        assert_eq!(row["read"]["torn"], true);
        assert_eq!(row["parse_status"], "unknown_not_attested_by_range_copy");
        assert_eq!(row["source"], note["source"]);
        assert_eq!(
            row["object_inspection"]["status"],
            "no_dex_or_elf_header_in_retained_range"
        );
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn runtime_partial_missing_identity_forged_hash_and_private_paths_are_not_verified() {
        for (field, value) in [
            ("read_status", json!("short_read")),
            ("write_status", json!("write_failed")),
            ("actual_length", json!(128)),
            ("sha256", json!("0".repeat(64))),
            ("torn", Value::Null),
            ("requested_start", json!(0)),
        ] {
            let (root, files, mut note) = runtime_fixture();
            note["records"][0]["read"][field] = value;
            fs::write(
                root.join("runtime/bound-source-fixture.json"),
                serde_json::to_vec(&note).unwrap(),
            )
            .unwrap();
            assert_eq!(
                account(&root, &files)["verified_code_unique_bytes"],
                0,
                "{field}"
            );
            fs::remove_dir_all(root).unwrap();
        }
        for (field, value) in [
            ("source", Value::Null),
            ("raw_evidence", json!("../data-private/log.txt")),
            ("admitted", Value::Null),
        ] {
            let (root, files, mut note) = runtime_fixture();
            note["records"][0][field] = value;
            fs::write(
                root.join("runtime/bound-source-fixture.json"),
                serde_json::to_vec(&note).unwrap(),
            )
            .unwrap();
            let result = account(&root, &files);
            assert_eq!(result["verified_code_unique_bytes"], 0, "{field}");
            assert_eq!(
                result["hash_budget_remaining"],
                result["hash_budget_bytes"].as_u64().unwrap(),
                "{field}"
            );
            fs::remove_dir_all(root).unwrap();
        }
    }
    #[test]
    fn actual_checksum_results_do_not_upgrade_corrupted_retained_dex() {
        let mut dex = vec![0_u8; 112];
        dex[..8].copy_from_slice(b"dex\n035\0");
        dex[32..36].copy_from_slice(&112_u32.to_le_bytes());
        dex[36..40].copy_from_slice(&112_u32.to_le_bytes());
        dex[40..44].copy_from_slice(&0x12345678_u32.to_le_bytes());
        let signature = sha1::Sha1::digest(&dex[32..]);
        dex[12..32].copy_from_slice(&signature);
        let checksum = dex_adler32(&dex[12..]);
        dex[8..12].copy_from_slice(&checksum.to_le_bytes());
        let result = inspect_runtime_bytes(&dex);
        assert_eq!(
            result["derived_objects"][0]["sha1_signature_verified"],
            true
        );
        assert_eq!(
            result["derived_objects"][0]["adler32_checksum_verified"],
            true
        );
        dex[8] ^= 1;
        let corrupt = inspect_runtime_bytes(&dex);
        assert_eq!(
            corrupt["derived_objects"][0]["adler32_checksum_verified"],
            false
        );
        assert_eq!(corrupt["derived_objects"][0]["ownership"], "unknown");
    }
    #[test]
    fn declared_full_bytes_and_valid_checksums_do_not_hide_unaccounted_tail() {
        let mut dex = vec![0_u8; 128];
        dex[..8].copy_from_slice(b"dex\n035\0");
        dex[32..36].copy_from_slice(&128_u32.to_le_bytes());
        dex[36..40].copy_from_slice(&112_u32.to_le_bytes());
        dex[40..44].copy_from_slice(&0x12345678_u32.to_le_bytes());
        let signature = sha1::Sha1::digest(&dex[32..]);
        dex[12..32].copy_from_slice(&signature);
        let checksum = dex_adler32(&dex[12..]);
        dex[8..12].copy_from_slice(&checksum.to_le_bytes());
        let result = inspect_runtime_bytes(&dex);
        let object = &result["derived_objects"][0];
        assert_eq!(object["sha1_signature_verified"], true);
        assert_eq!(object["adler32_checksum_verified"], true);
        assert_eq!(
            object["layout_diagnostics"]["trailing_unaccounted_bytes"],
            16
        );
        assert_eq!(
            object["layout_diagnostics"]["status"],
            "declared_spans_leave_unaccounted_tail"
        );
        assert_eq!(object["layout_diagnostics"]["full_dex_verifier"], false);
    }
    #[test]
    fn partial_dex_header_reports_exact_gap_without_fabricating_object() {
        let mut bytes = vec![0_u8; 176];
        bytes[64..72].copy_from_slice(b"dex\n035\0");
        bytes[96..100].copy_from_slice(&1000_u32.to_le_bytes());
        bytes[100..104].copy_from_slice(&112_u32.to_le_bytes());
        bytes[104..108].copy_from_slice(&0x12345678_u32.to_le_bytes());
        let result = inspect_runtime_bytes(&bytes);
        assert_eq!(result["derived_objects"].as_array().unwrap().len(), 0);
        assert_eq!(
            result["rejected_candidates"][0]["reason"],
            "declared_dex_extends_beyond_retained_range"
        );
        assert_eq!(
            result["rejected_candidates"][0]["missing_declared_bytes"],
            888
        );
        assert_eq!(
            result["rejected_candidates"][0]["complete_dex_validated"],
            false
        );
        bytes[104] = 0;
        assert!(
            inspect_runtime_bytes(&bytes)["rejected_candidates"][0]["declared_length"].is_null()
        );
    }
    #[test]
    fn source_errors_and_invalid_item_preserve_valid_sibling_with_bounded_diagnostics() {
        let (root, mut files, mut note) = runtime_fixture();
        note["records"]
            .as_array_mut()
            .unwrap()
            .insert(0, Value::Null);
        fs::write(
            root.join("runtime/bound-source-fixture.json"),
            serde_json::to_vec(&note).unwrap(),
        )
        .unwrap();
        fs::write(
            root.join("runtime/bound-source-truncated.json"),
            b"{\"schema\":",
        )
        .unwrap();
        files.push(("runtime/bound-source-truncated.json".into(), 10));
        let result = account(&root, &files);
        assert_eq!(result["verified_code_unique_bytes"], 256);
        assert_eq!(result["runtime_observations"].as_array().unwrap().len(), 1);
        let diagnostics = result["runtime_source_diagnostics"].as_array().unwrap();
        assert_eq!(diagnostics[0]["invalid_records"], 1);
        assert_eq!(diagnostics[1]["status"], "invalid_or_truncated_json");
        note.as_object_mut().unwrap().remove("records");
        fs::write(
            root.join("runtime/bound-source-fixture.json"),
            serde_json::to_vec(&note).unwrap(),
        )
        .unwrap();
        assert_eq!(
            account(&root, &files)["runtime_source_diagnostics"][0]["status"],
            "missing_or_invalid_records"
        );
        for _ in 0..300 {
            files.push(("runtime/bound-source-truncated.json".into(), 10));
        }
        let bounded = account(&root, &files);
        assert_eq!(
            bounded["runtime_source_diagnostics"]
                .as_array()
                .unwrap()
                .len(),
            256
        );
        assert!(bounded["runtime_sources_omitted"].as_u64().unwrap() > 0);
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn bound_source_between_64kib_and_1mib_is_analyzed() {
        let (root, mut files, mut note) = runtime_fixture();
        note["bounded_extra_metadata"] = json!("x".repeat(33000));
        let bytes = serde_json::to_vec(&note).unwrap();
        assert!(bytes.len() > 32768 && bytes.len() < 65536);
        fs::write(root.join("runtime/bound-source-fixture.json"), &bytes).unwrap();
        files
            .iter_mut()
            .find(|(p, _)| p == "runtime/bound-source-fixture.json")
            .unwrap()
            .1 = bytes.len() as u64;
        let result = account(&root, &files);
        assert_eq!(result["verified_code_unique_bytes"], 256);
        assert_eq!(result["runtime_observations"].as_array().unwrap().len(), 1);
        note["bounded_extra_metadata"] = json!("x".repeat(200_000));
        let bytes = serde_json::to_vec(&note).unwrap();
        assert!(bytes.len() > 174_685 && (bytes.len() as u64) < BOUND_SOURCE_BYTE_LIMIT);
        fs::write(root.join("runtime/bound-source-fixture.json"), &bytes).unwrap();
        files
            .iter_mut()
            .find(|(p, _)| p == "runtime/bound-source-fixture.json")
            .unwrap()
            .1 = bytes.len() as u64;
        assert_eq!(account(&root, &files)["verified_code_unique_bytes"], 256);
        note["bounded_extra_metadata"] = json!("x".repeat(BOUND_SOURCE_BYTE_LIMIT as usize + 64));
        let bytes = serde_json::to_vec(&note).unwrap();
        fs::write(root.join("runtime/bound-source-fixture.json"), &bytes).unwrap();
        files
            .iter_mut()
            .find(|(p, _)| p == "runtime/bound-source-fixture.json")
            .unwrap()
            .1 = bytes.len() as u64;
        assert_eq!(account(&root, &files)["verified_code_unique_bytes"], 0);
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn runtime_duplicate_sources_preserve_rows_without_double_counting_and_symlinks_fail() {
        let (root, mut files, note) = runtime_fixture();
        for name in [
            "runtime/bound-source-fixture.json",
            "runtime/bound-source-second.json",
        ] {
            fs::write(root.join(name), serde_json::to_vec(&note).unwrap()).unwrap();
        }
        files.push(("runtime/bound-source-second.json".into(), 0));
        let result = account(&root, &files);
        assert_eq!(
            result["runtime_range_inventory"].as_array().unwrap().len(),
            2
        );
        assert_eq!(result["runtime_observations"].as_array().unwrap().len(), 1);
        assert_eq!(result["verified_code_logical_bytes"], 256);
        assert_eq!(
            result["hash_budget_remaining"],
            result["hash_budget_bytes"].as_u64().unwrap() - 256
        );
        #[cfg(unix)]
        {
            fs::rename(
                root.join("runtime/bound-fixture.code"),
                root.join("original.code"),
            )
            .unwrap();
            std::os::unix::fs::symlink(
                root.join("original.code"),
                root.join("runtime/bound-fixture.code"),
            )
            .unwrap();
            assert_eq!(account(&root, &files)["verified_code_unique_bytes"], 0);
        }
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn all_range_metadata_reaches_a_later_dex_after_256_noncode_rows() {
        let (root, mut files, mut note) = runtime_fixture();
        let original = note["records"][0].clone();
        let mut records = vec![original.clone(); 256];
        for (index, row) in records.iter_mut().enumerate() {
            row["mapping"]["start"] = json!(4096 + index * 4096);
            row["mapping"]["end"] = json!(8192 + index * 4096);
            row["read"]["requested_start"] = row["mapping"]["start"].clone();
            row["read"]["actual_start"] = row["mapping"]["start"].clone();
        }
        let mut dex = vec![0_u8; 112];
        dex[..8].copy_from_slice(b"dex\n035\0");
        dex[32..36].copy_from_slice(&112_u32.to_le_bytes());
        dex[36..40].copy_from_slice(&112_u32.to_le_bytes());
        dex[40..44].copy_from_slice(&0x12345678_u32.to_le_bytes());
        fs::write(root.join("runtime/bound-tail.code"), &dex).unwrap();
        files.push(("runtime/bound-tail.code".into(), dex.len() as u64));
        let mut tail = original;
        tail["raw_evidence"] = json!("bound-tail.code");
        tail["mapping"]["start"] = json!(2_000_000);
        tail["mapping"]["end"] = json!(2_000_000 + dex.len());
        tail["read"]["requested_start"] = json!(2_000_000);
        tail["read"]["actual_start"] = json!(2_000_000);
        tail["read"]["requested_length"] = json!(dex.len());
        tail["read"]["actual_length"] = json!(dex.len());
        tail["read"]["sha256"] = json!(format!("{:x}", Sha256::digest(&dex)));
        records.push(tail);
        note["records"] = json!(records);
        let encoded = serde_json::to_vec(&note).unwrap();
        fs::write(root.join(&files[1].0), &encoded).unwrap();
        files[1].1 = encoded.len() as u64;
        let result = account(&root, &files);
        let inventory = result["runtime_range_inventory"].as_array().unwrap();
        assert_eq!(inventory.len(), 257);
        assert_eq!(inventory[256]["source_record_index"], 256);
        assert_eq!(
            inventory[256]["local_content_status"],
            "complete_range_hash_verified"
        );
        assert_eq!(
            inventory[256]["source_report_sha256"],
            format!("{:x}", Sha256::digest(&encoded))
        );
        assert_eq!(result["omitted_observations"], 0);
        let heavy = result["runtime_observations"].as_array().unwrap();
        assert!(heavy.len() <= RUNTIME_OBSERVATION_LIMIT);
        let ref_index = inventory[256]["inspection_ref"].as_u64().unwrap() as usize;
        assert_eq!(heavy[ref_index]["source_record_index"], 256);
        assert_eq!(
            heavy[ref_index]["object_inspection"]["derived_objects"][0]["kind"],
            "dex"
        );
        // Payload inspection does not retain a duplicate class JSON in each range.
        for row in inventory {
            for object in row["object_inspection"]["derived_objects"]
                .as_array()
                .into_iter()
                .flatten()
            {
                assert!(object["class_index"]["classes"].is_null());
            }
        }
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    #[cfg(unix)]
    fn verified_static_hardlinks_share_one_digest_but_separate_inodes_do_not() {
        for hard_link in [false, true] {
            let root =
                std::env::temp_dir().join(format!("me-static-cache-{}", uuid::Uuid::new_v4()));
            fs::create_dir_all(root.join("code-evidence")).unwrap();
            let payload = [3_u8; 512];
            fs::write(root.join("a.dex"), payload).unwrap();
            if hard_link {
                fs::hard_link(root.join("a.dex"), root.join("b.dex")).unwrap();
            } else {
                fs::write(root.join("b.dex"), payload).unwrap();
            }
            let hash = format!("{:x}", Sha256::digest(payload));
            let mut files = vec![("a.dex".into(), 512), ("b.dex".into(), 512)];
            for name in ["a", "b"] {
                let note = json!({"schema":"kernsight.apk-member-evidence/v1","relative_path":format!("{name}.dex"),"bytes":512,"sha256":hash,"source_complete":true,"write_status":"hard_link"});
                let encoded = serde_json::to_vec(&note).unwrap();
                let path = format!("code-evidence/{name}.json");
                fs::write(root.join(&path), &encoded).unwrap();
                files.push((path, encoded.len() as u64));
            }
            let result = account(&root, &files);
            assert_eq!(result["observations"].as_array().unwrap().len(), 2);
            assert!(result["observations"]
                .as_array()
                .unwrap()
                .iter()
                .all(|row| row["local_content_status"] == "complete_file_hash_verified"));
            assert_eq!(
                result["hash_budget_remaining"],
                RUNTIME_RANGE_TREE_CAP - if hard_link { 512 } else { 1024 }
            );
            assert_eq!(result["verified_code_unique_bytes"], 512);
            assert_eq!(result["verified_code_logical_bytes"], 1024);
            fs::remove_dir_all(root).unwrap();
        }
    }

    #[test]
    #[cfg(unix)]
    fn a_cached_physical_hash_never_upgrades_a_wrong_alias_claim() {
        let root =
            std::env::temp_dir().join(format!("me-static-cache-forged-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(root.join("code-evidence")).unwrap();
        let payload = [9_u8; 512];
        fs::write(root.join("a.dex"), payload).unwrap();
        fs::hard_link(root.join("a.dex"), root.join("b.dex")).unwrap();
        let mut files = vec![("a.dex".into(), 512), ("b.dex".into(), 512)];
        for (name, hash) in [
            ("a", format!("{:x}", Sha256::digest(payload))),
            ("b", "0".repeat(64)),
        ] {
            let note = json!({"schema":"kernsight.apk-member-evidence/v1","relative_path":format!("{name}.dex"),"bytes":512,"sha256":hash,"source_complete":true,"write_status":"hard_link"});
            let encoded = serde_json::to_vec(&note).unwrap();
            let path = format!("code-evidence/{name}.json");
            fs::write(root.join(&path), &encoded).unwrap();
            files.push((path, encoded.len() as u64));
        }
        let result = account(&root, &files);
        assert_eq!(
            result["observations"][0]["local_content_status"],
            "complete_file_hash_verified"
        );
        assert_eq!(
            result["observations"][1]["local_content_status"],
            "unknown_or_failed"
        );
        assert_eq!(result["unverified_observations"], 1);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn malformed_record_inventory_keeps_exact_counts_and_a_bounded_rejection_prefix() {
        for invalid in [Value::Null, json!({})] {
            let (root, mut files, mut note) = runtime_fixture();
            note["records"] = json!(vec![invalid; BOUND_SOURCE_RECORD_LIMIT]);
            let encoded = serde_json::to_vec(&note).unwrap();
            fs::write(root.join(&files[1].0), &encoded).unwrap();
            files[1].1 = encoded.len() as u64;
            let result = account(&root, &files);
            assert_eq!(
                result["runtime_range_inventory"].as_array().unwrap().len(),
                0
            );
            let source = &result["runtime_source_diagnostics"][0];
            assert_eq!(source["records_seen"], BOUND_SOURCE_RECORD_LIMIT);
            assert_eq!(source["invalid_records"], BOUND_SOURCE_RECORD_LIMIT);
            assert_eq!(source["unverified_records"], BOUND_SOURCE_RECORD_LIMIT);
            assert!(source["rejected_record_prefix"].as_array().unwrap().len() <= 256);
            assert_eq!(
                source["rejected_records_not_materialized"],
                BOUND_SOURCE_RECORD_LIMIT - 256
            );
            assert!(serde_json::to_vec(&result).unwrap().len() < 100_000);
            assert_eq!(result["runtime_analysis_complete"], false);
            fs::remove_dir_all(root).unwrap();
        }
    }

    fn note_at_exact_bytes(mut note: Value, target: usize) -> Vec<u8> {
        note["redacted_fixture_padding"] = json!("");
        let initial = serde_json::to_vec(&note).unwrap().len();
        assert!(initial <= target);
        note["redacted_fixture_padding"] = json!("x".repeat(target - initial));
        let bytes = serde_json::to_vec(&note).unwrap();
        assert_eq!(bytes.len(), target);
        bytes
    }
    #[test]
    fn producer_v1_1495234_byte_1390_record_shape_keeps_all_metadata_and_one_canonical_analysis() {
        // Matches the field topology and size of the retained 2b1dafca source
        // note. Identities, mapping paths and payload are synthetic; the actual
        // retained note is separately exercised by controlled-clone acceptance.
        let (root, mut files, mut note) = runtime_fixture();
        let mut row = note["records"][0].clone();
        row["mapping"]["inode"] = json!(1);
        row["excluded_local_window"] = json!(false);
        row["mapping_revalidated"] = json!(true);
        row["post_copy_source_verified"] = json!(true);
        row["requested_mapping_bytes"] = json!(4096);
        row["scope"] = json!("qualified_source_mapping");
        row["selection_limit_bytes"] = json!(256);
        row["selection_limit_reason"] = json!("parent_budget");
        row["selection_policy"] = json!("eligible_install_priority_until_parent_budget");
        note["records"] = json!(vec![row; 1390]);
        note["shard_count"] = json!(1);
        note["shard_index"] = json!(0);
        note["btf_sha256"] = json!("1".repeat(64));
        note["object_sha256"] = json!("2".repeat(64));
        note["candidate_manifest"] = json!("bound-candidates-redacted.json");
        note["candidate_result"] = json!({"actual_ranges":"records.read","attempted":1390,"total_attempted":1390,"budget_stop":false,"stop_scope":"none_or_parent_budget","truncation":"none","unattempted_state":"none"});
        let bytes = note_at_exact_bytes(note, 1_495_234);
        assert!(bytes.len() > 1024 * 1024);
        fs::write(root.join("runtime/bound-source-fixture.json"), &bytes).unwrap();
        files[1].1 = bytes.len() as u64;
        let result = account(&root, &files);
        assert_eq!(result["runtime_observations"].as_array().unwrap().len(), 1);
        assert_eq!(
            result["runtime_range_inventory"].as_array().unwrap().len(),
            1390
        );
        assert_eq!(result["verified_code_unique_bytes"], 256);
        assert_eq!(result["unverified_observations"], 0);
        assert_eq!(result["omitted_observations"], 0);
        assert_eq!(result["runtime_analysis_complete"], true);
        let diagnostic = &result["runtime_source_diagnostics"][0];
        assert_eq!(diagnostic["records_seen"], 1390);
        assert_eq!(diagnostic["invalid_records"], 0);
        assert_eq!(diagnostic["omitted_records"], 0);
        assert_eq!(diagnostic["verified_records"], 1390);
        assert!(diagnostic["omission_reason"].is_null());
        assert_eq!(
            diagnostic["source_report_sha256"],
            format!("{:x}", Sha256::digest(&bytes))
        );
        for row in result["runtime_observations"].as_array().unwrap() {
            assert_eq!(row["source_report"], "runtime/bound-source-fixture.json");
            assert_eq!(row["local_content_status"], "complete_range_hash_verified");
            assert_eq!(row["read"]["torn"], true);
            assert_eq!(row["ownership"], "unknown");
        }
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn producer_v1_document_and_inventory_boundaries_preserve_prior_sources() {
        assert_eq!(BOUND_SOURCE_BYTE_LIMIT, 2 * 1024 * 1024);
        assert_eq!(BOUND_SOURCE_TOTAL_BYTE_LIMIT, 8 * 1024 * 1024);
        assert_eq!(BOUND_SOURCE_COUNT_LIMIT, 16);
        assert_eq!(BOUND_SOURCE_RECORD_LIMIT, 65536);
        let (root, mut files, note) = runtime_fixture();
        let bytes = note_at_exact_bytes(note.clone(), BOUND_SOURCE_BYTE_LIMIT as usize);
        fs::write(root.join(&files[1].0), &bytes).unwrap();
        files[1].1 = bytes.len() as u64;
        for i in 1..5 {
            let path = format!("runtime/bound-source-{i}.json");
            fs::write(root.join(&path), &bytes).unwrap();
            files.push((path, bytes.len() as u64));
        }
        let result = account(&root, &files);
        assert_eq!(
            result["runtime_range_inventory"].as_array().unwrap().len(),
            4
        );
        assert_eq!(result["runtime_observations"].as_array().unwrap().len(), 1);
        assert_eq!(result["verified_code_unique_bytes"], 256);
        assert_eq!(
            result["runtime_source_diagnostics"][4]["status"],
            "source_total_byte_limit"
        );
        assert_eq!(
            result["bound_source_metadata_contract"]["inventory_metadata_budget_remaining"],
            0
        );
        assert_eq!(result["runtime_analysis_complete"], false);
        let oversize = note_at_exact_bytes(note, BOUND_SOURCE_BYTE_LIMIT as usize + 1);
        fs::write(root.join(&files[1].0), &oversize).unwrap();
        let mut remaining = BOUND_SOURCE_TOTAL_BYTE_LIMIT;
        // Verify actual length too, even when a stale catalog says zero.
        assert_eq!(
            load_bound_source(&root, &files[1].0, 0, &mut remaining).unwrap_err(),
            "source_byte_limit"
        );
        assert_eq!(remaining, BOUND_SOURCE_TOTAL_BYTE_LIMIT);
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn producer_v1_record_count_source_count_and_malformed_reads_are_bounded() {
        let (root, mut files, mut note) = runtime_fixture();
        note["records"] = json!(vec![Value::Null; BOUND_SOURCE_RECORD_LIMIT + 1]);
        fs::write(root.join(&files[1].0), serde_json::to_vec(&note).unwrap()).unwrap();
        let mut remaining = BOUND_SOURCE_TOTAL_BYTE_LIMIT;
        assert_eq!(
            load_bound_source(&root, &files[1].0, 0, &mut remaining).unwrap_err(),
            "source_record_limit"
        );
        assert!(remaining < BOUND_SOURCE_TOTAL_BYTE_LIMIT);
        note["records"] = json!([]);
        let bytes = serde_json::to_vec(&note).unwrap();
        fs::write(root.join(&files[1].0), &bytes).unwrap();
        for i in 1..BOUND_SOURCE_COUNT_LIMIT + 1 {
            let path = format!("runtime/bound-source-{i}.json");
            fs::write(root.join(&path), &bytes).unwrap();
            files.push((path, bytes.len() as u64));
        }
        let result = account(&root, &files);
        assert_eq!(
            result["runtime_source_diagnostics"][16]["status"],
            "source_count_limit"
        );
        assert_eq!(result["runtime_sources_omitted"], 1);
        assert_eq!(result["runtime_analysis_complete"], false);
        fs::write(root.join(&files[1].0), b"{\"schema\":").unwrap();
        remaining = BOUND_SOURCE_TOTAL_BYTE_LIMIT;
        assert_eq!(
            load_bound_source(&root, &files[1].0, 0, &mut remaining).unwrap_err(),
            "invalid_or_truncated_json"
        );
        assert_eq!(remaining, BOUND_SOURCE_TOTAL_BYTE_LIMIT - 10);
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn unverified_bound_records_do_not_upgrade_or_discard_a_verified_sibling() {
        for (field, value) in [
            ("source", json!({"package":"forged.example"})),
            ("raw_evidence", json!("bound-missing.code")),
            ("raw_evidence", json!("../bound-fixture.code")),
            ("sha256", json!("0".repeat(64))),
        ] {
            let (root, files, mut note) = runtime_fixture();
            let mut bad = note["records"][0].clone();
            if field == "sha256" {
                bad["read"][field] = value;
            } else {
                bad[field] = value;
            }
            note["records"].as_array_mut().unwrap().insert(0, bad);
            fs::write(root.join(&files[1].0), serde_json::to_vec(&note).unwrap()).unwrap();
            let result = account(&root, &files);
            assert_eq!(result["verified_code_unique_bytes"], 256, "{field}");
            assert_eq!(
                result["runtime_range_inventory"][0]["local_content_status"], "unknown_or_failed",
                "{field}"
            );
            assert_eq!(
                result["runtime_range_inventory"][1]["local_content_status"],
                "complete_range_hash_verified",
                "{field}"
            );
            assert_eq!(
                result["runtime_source_diagnostics"][0]["invalid_records"], 1,
                "{field}"
            );
            assert!(
                result["runtime_range_inventory"][0]["inspection_ref"].is_null(),
                "{field}"
            );
            assert_eq!(result["runtime_analysis_complete"], false, "{field}");
            fs::remove_dir_all(root).unwrap();
        }
    }

    fn account_fixture_bytes(bytes: &[u8]) -> Value {
        let (root, mut files, mut note) = runtime_fixture();
        fs::write(root.join(&files[0].0), bytes).unwrap();
        files[0].1 = bytes.len() as u64;
        note["records"][0]["mapping"]["end"] = json!(4096 + bytes.len());
        note["records"][0]["read"]["requested_length"] = json!(bytes.len());
        note["records"][0]["read"]["actual_length"] = json!(bytes.len());
        note["records"][0]["read"]["sha256"] = json!(format!("{:x}", Sha256::digest(bytes)));
        fs::write(root.join(&files[1].0), serde_json::to_vec(&note).unwrap()).unwrap();
        let result = account(&root, &files);
        fs::remove_dir_all(root).unwrap();
        result
    }

    #[test]
    fn embedded_dex_offsets_are_prioritized_within_the_existing_inspection_pool() {
        for offset in [19_664_usize, 25_386] {
            let mut dex = vec![0_u8; 112];
            dex[..8].copy_from_slice(b"dex\n035\0");
            dex[32..36].copy_from_slice(&112_u32.to_le_bytes());
            dex[36..40].copy_from_slice(&112_u32.to_le_bytes());
            dex[40..44].copy_from_slice(&0x12345678_u32.to_le_bytes());
            let signature = sha1::Sha1::digest(&dex[32..]);
            dex[12..32].copy_from_slice(&signature);
            let checksum = dex_adler32(&dex[12..]);
            dex[8..12].copy_from_slice(&checksum.to_le_bytes());
            let mut bytes = vec![0_u8; offset];
            bytes.extend_from_slice(&dex);
            assert_eq!(header_priority(&bytes), Some(0));
            let result = account_fixture_bytes(&bytes);
            let row = &result["runtime_range_inventory"][0];
            assert_eq!(row["analysis_priority"], 0);
            assert_eq!(row["local_content_status"], "complete_range_hash_verified");
            assert_eq!(result["runtime_header_probe_bytes"], bytes.len());
            assert_eq!(
                result["inspection_budget_remaining"],
                RUNTIME_RANGE_TREE_CAP - 2 * bytes.len() as u64
            );
            let reference = row["inspection_ref"].as_u64().unwrap() as usize;
            let object = &result["runtime_observations"][reference]["object_inspection"]
                ["derived_objects"][0];
            assert_eq!(object["source_offset"], offset);
            assert_eq!(object["sha1_signature_verified"], true);
            assert_eq!(object["adler32_checksum_verified"], true);
            assert_eq!(object["ownership"], "unknown");
            assert_eq!(row["read"]["torn"], true);
        }
    }

    #[test]
    fn a_prefix_dex_marker_is_a_hint_and_never_complete_dex_validation() {
        let mut bytes = vec![0_u8; 19_664];
        bytes.extend_from_slice(b"dex\nXXXX");
        assert_eq!(header_priority(&bytes), Some(0));
        let result = account_fixture_bytes(&bytes);
        let row = &result["runtime_range_inventory"][0];
        assert_eq!(row["analysis_priority"], 0);
        assert_eq!(row["local_content_status"], "complete_range_hash_verified");
        assert!(row["object_inspection"]["derived_objects"]
            .as_array()
            .unwrap()
            .is_empty());
        assert_eq!(
            row["object_inspection"]["rejected_candidates"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        assert_eq!(result["runtime_analysis_complete"], false);
        assert_eq!(row["ownership"], "unknown");
        assert_eq!(RUNTIME_PROBE_PREFIX_CAP, 65_536);
    }
    #[test]
    fn hash_verified_source_ledger_does_not_hide_a_candidate_stop() {
        let mut bytes = b"dex\nXXXX".repeat(64);
        let at = bytes.len();
        bytes.resize(at + 112, 0);
        bytes[at..at + 8].copy_from_slice(b"dex\n035\0");
        bytes[at + 32..at + 36].copy_from_slice(&112_u32.to_le_bytes());
        bytes[at + 36..at + 40].copy_from_slice(&112_u32.to_le_bytes());
        bytes[at + 40..at + 44].copy_from_slice(&0x12345678_u32.to_le_bytes());
        let result = account_fixture_bytes(&bytes);
        assert_eq!(
            result["runtime_observations"][0]["local_content_status"],
            "complete_range_hash_verified"
        );
        assert_eq!(result["runtime_source_ledger_complete"], true);
        assert_eq!(result["runtime_analysis_complete"], false);
        assert_eq!(
            result["runtime_analysis_partial_reasons"]["candidate_stop"],
            1
        );
        assert_eq!(
            result["runtime_analysis_partial_reasons"]["unscanned_range_tail"],
            1
        );
    }
    #[test]
    fn hash_verified_source_ledger_does_not_hide_a_partial_class_index() {
        let count = 16385_u32;
        let data_at = 120 + count as usize * 32;
        let mut bytes = vec![0; data_at + 9];
        bytes[..8].copy_from_slice(b"dex\n035\0");
        let size = bytes.len() as u32;
        for (at, value) in [
            (32, size),
            (36, 112),
            (40, 0x12345678),
            (56, 1),
            (60, 116),
            (64, 1),
            (68, 112),
            (96, count),
            (100, 120),
        ] {
            bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
        }
        bytes[116..120].copy_from_slice(&(data_at as u32).to_le_bytes());
        bytes[data_at..].copy_from_slice(b"\x07LFoo/x;\0");
        let result = account_fixture_bytes(&bytes);
        assert_eq!(
            result["runtime_observations"][0]["local_content_status"],
            "complete_range_hash_verified"
        );
        assert_eq!(result["runtime_source_ledger_complete"], true);
        assert_eq!(result["runtime_analysis_complete"], false);
        assert_eq!(
            result["runtime_analysis_partial_reasons"]["class_index_omission"],
            1
        );
        assert_eq!(
            result["runtime_analysis_partial_reasons"]["partial_or_unknown_class_index"],
            1
        );
        let index = &result["runtime_observations"][0]["object_inspection"]["derived_objects"][0]
            ["class_index"];
        assert_eq!(index["omitted_classes"], 1);
        assert!(index["duplicate_class_definitions"].as_u64().unwrap() > 0);
    }
    #[test]
    fn no_runtime_and_unknown_inspection_never_claim_complete_analysis() {
        assert_eq!(runtime_analysis_gaps(&[])["no_runtime_observations"], 1);
        let rows = [
            json!({"local_content_status":"complete_range_hash_verified","object_inspection":{"status":"unknown_inspection_budget_exhausted"}}),
        ];
        assert_eq!(
            runtime_analysis_gaps(&rows)["unknown_or_unavailable_inspection"],
            1
        );
        // A normal 0..3-byte suffix cannot hold another DEX marker.
        let rows = [
            json!({"local_content_status":"complete_range_hash_verified","object_inspection":{"status":"no_dex_or_elf_header_in_retained_range","candidate_stop_reason":null,"unscanned_tail_bytes":3,"derived_objects":[]}}),
        ];
        assert!(runtime_analysis_gaps(&rows).is_empty());
    }

    #[tokio::test]
    async fn cancelled_metadata_scope_is_explicit_and_does_not_become_a_hash_mismatch() {
        let (root, files, note) = runtime_fixture();
        fs::write(root.join(&files[1].0), serde_json::to_vec(&note).unwrap()).unwrap();
        let deadline =
            super::super::session_deadline::Deadline::new(std::time::Duration::from_secs(1));
        let result = deadline
            .run(async {
                deadline.cancel();
                let mut remaining = BOUND_SOURCE_TOTAL_BYTE_LIMIT;
                assert_eq!(
                    load_bound_source(&root, &files[1].0, 0, &mut remaining).unwrap_err(),
                    "parent_cancelled"
                );
                assert_eq!(remaining, BOUND_SOURCE_TOTAL_BYTE_LIMIT);
                assert_eq!(scope_failure(), Some("parent_cancelled"));
                assert!(hash_file(&root.join(&files[0].0), files[0].1).is_none());
                assert!(read_inspection_bytes(&root.join(&files[0].0), files[0].1).is_none());
                let ledger = account(&root, &files);
                assert_eq!(
                    ledger["runtime_source_diagnostics"][0]["status"],
                    "parent_cancelled"
                );
                assert!(ledger["runtime_source_diagnostics"][0]["records_seen"].is_null());
                assert_eq!(ledger["runtime_analysis_complete"], false);
                Err::<(), String>("parent_cancelled".into())
            })
            .await;
        assert!(result.unwrap_err().contains("parent_cancelled"));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn scope_stop_reason_takes_priority_over_runtime_row_limit() {
        for reason in [
            "parent_cancelled",
            "parent_deadline_exhausted",
            "time_budget_exhausted",
        ] {
            assert_eq!(runtime_omission_reason(Some(reason)), reason);
        }
        assert_eq!(runtime_omission_reason(None), "runtime_observation_limit");
    }
    #[test]
    fn independently_expired_guard_keeps_time_reason_for_all_metadata_reads() {
        let (root, files, note) = runtime_fixture();
        fs::write(root.join(&files[1].0), serde_json::to_vec(&note).unwrap()).unwrap();
        let guard =
            super::super::session_budget::Guard::install(vec![root.clone()], 1024 * 1024, 1)
                .unwrap();
        std::thread::sleep(std::time::Duration::from_millis(5));
        assert_eq!(scope_failure(), None); // No Deadline task-local scope.
        let mut remaining = BOUND_SOURCE_TOTAL_BYTE_LIMIT;
        assert_eq!(
            load_bound_source(&root, &files[1].0, 0, &mut remaining).unwrap_err(),
            "time_budget_exhausted"
        );
        assert_eq!(remaining, BOUND_SOURCE_TOTAL_BYTE_LIMIT);
        assert_eq!(
            hash_file_result(&root.join(&files[0].0), files[0].1).unwrap_err(),
            "time_budget_exhausted"
        );
        assert_eq!(
            read_inspection_bytes_result(&root.join(&files[0].0), files[0].1).unwrap_err(),
            "time_budget_exhausted"
        );
        assert_eq!(
            guard.receipt().reason.as_deref(),
            Some("time_budget_exhausted")
        );
        let ledger = account(&root, &files);
        assert_eq!(
            ledger["runtime_source_diagnostics"][0]["status"],
            "time_budget_exhausted"
        );
        assert!(ledger["runtime_source_diagnostics"][0]["records_seen"].is_null());
        assert_eq!(ledger["runtime_analysis_complete"], false);
        drop(guard);
        fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    #[ignore = "explicit retained 2b1dafca archive; new isolated cache; no device"]
    async fn retained_2b1_archive_reimports_with_full_metadata_and_prioritized_analysis() {
        let archive = std::path::PathBuf::from(
            std::env::var_os("ME_BOUND_SOURCE_RETAINED_ARCHIVE")
                .expect("explicit retained archive"),
        );
        let report = std::path::PathBuf::from(
            std::env::var_os("ME_BOUND_SOURCE_ACCEPTANCE_REPORT").expect("explicit report output"),
        );
        let archive_bytes = fs::metadata(&archive).unwrap().len();
        let archive_sha = hash_file(&archive, archive_bytes).unwrap();
        assert_eq!(archive_bytes, 1_174_263_584);
        assert_eq!(
            archive_sha,
            "14ba3b67be0c4f73451478727909ce28578d5ed35dcbf31c11f095e0442c2dec"
        );
        let started = std::time::Instant::now();
        let phase =
            super::super::session_deadline::Deadline::new(std::time::Duration::from_secs(120));
        let imported = phase
            .run(async {
                // The production v2 restore installs its own manifest-based
                // 2 GiB / 120s Guard; its deadline is shortened to this phase.
                // An additional temp-root Guard would overlap that owned scope.
                super::super::import_kernsight_evidence_archive(
                    archive.to_string_lossy().into_owned(),
                )
                .await
            })
            .await
            .unwrap();
        phase.check().unwrap();
        let elapsed_ms = started.elapsed().as_millis();
        assert!(elapsed_ms < 120_000);
        let imported_root = std::path::PathBuf::from(&imported.root);
        assert!(imported_root
            .canonicalize()
            .unwrap()
            .starts_with(std::env::temp_dir().canonicalize().unwrap()));
        let ledger = &imported.dump_report["local_storage_accounting"];
        let runtime = ledger["runtime_observations"].as_array().unwrap();
        assert!(runtime.len() <= RUNTIME_OBSERVATION_LIMIT);
        let inventory = ledger["runtime_range_inventory"].as_array().unwrap();
        assert_eq!(inventory.len(), 1390);
        assert_eq!(ledger["omitted_observations"], 0);
        assert_eq!(ledger["runtime_analysis_complete"], false);
        let sources = ledger["runtime_source_diagnostics"].as_array().unwrap();
        assert_eq!(sources.len(), 1);
        assert_eq!(sources[0]["records_seen"], 1390);
        assert_eq!(sources[0]["omitted_records"], 0);
        assert_eq!(sources[0]["processed_records"], 1390);
        assert_eq!(
            sources[0]["source_report_sha256"],
            "017ae3be325d5c017a385299ab57215ba07e066e6e370b0cb3737a1fab0a37ab"
        );
        assert_eq!(sources[0]["metadata_bytes_read"], 1_495_234);
        assert_eq!(sources[0]["status"], "partial_records");
        let verified = inventory
            .iter()
            .filter(|row| row["local_content_status"] == "complete_range_hash_verified")
            .count();
        assert!(
            verified > 256,
            "new scheduler must materially exceed the old 73 verified / 256 prefix"
        );
        for row in inventory {
            assert_eq!(
                row["source_report"],
                "runtime/bound-source-16329-d92c6ca6-44aa-44d7-ba65-c0c0fd718af7-00.json"
            );
            assert!(row["source_record_index"].as_u64().unwrap() < 1390);
            assert_eq!(row["source_identity_status"], "producer_identity_recorded");
        }
        let parent = &imported.session_report.as_ref().unwrap()["mobilee_capture_group"];
        assert_eq!(parent["id"], "2b1dafca-cbd8-4fc1-b541-0bb495aa9e0d");
        assert_eq!(parent["state"], "partial");
        let session_index: Value =
            serde_json::from_slice(&fs::read(imported_root.join("session-index.json")).unwrap())
                .unwrap();
        let children = session_index["includedSessions"].as_array().unwrap();
        assert_eq!(children.len(), 3);
        for id in [
            "2f537c3b-f5c0-49c8-ae5c-befb5fac4289",
            "355e3390-5b31-490e-b903-3721449be02a",
            "7e1f4e1d-7912-4f15-addd-28cb3da70454",
        ] {
            assert!(children.iter().any(|item| item == id));
        }
        let index = &imported.dump_report["content_dex_class_index"];
        let objects = index["objects"].as_array().unwrap();
        assert!(!objects.is_empty());
        assert_eq!(
            inventory[28]["local_content_status"],
            "complete_range_hash_verified"
        );
        assert_eq!(inventory[28]["analysis_priority"], 0);
        assert!(
            objects.iter().any(|object| object["sha256"]
                == "9f8898ce35a47aeafced99ea0d17c33e73037bb2307c7688e50819966f4ae939"
                && object["bytes"] == 284),
            "the verified embedded DEX at source record 28 must survive scheduling"
        );
        assert_eq!(hash_file(&archive, archive_bytes).unwrap(), archive_sha);
        let safe_runtime = inventory.iter().map(|row| json!({
            "source_report":row["source_report"],"source_report_sha256":row["source_report_sha256"],"source_record_index":row["source_record_index"],
            "relative_path":row["relative_path"],"local_content_status":row["local_content_status"],
            "verification_failure_reason":row["content_verification_failure_reason"],
            "source_identity_status":row["source_identity_status"],"torn":row["read"]["torn"],
            "mapping_complete":row["mapping_complete"],"inspection_ref":row["inspection_ref"],"inspection_content_key":row["inspection_content_key"],"inspection_status":row["inspection_status"],"analysis_priority":row["analysis_priority"],"derived_objects":row["object_inspection"]["derived_objects"].as_array().map(Vec::len),
        })).collect::<Vec<_>>();
        let safe_objects = objects.iter().map(|object| json!({
            "sha256":object["sha256"],"bytes":object["bytes"],"ownership":object["ownership"],
            "validation_status":object["validation_status"],"class_index_status":object["class_index_status"],
            "indexed_classes":object["indexed_classes"],"omitted_classes":object["omitted_classes"],
            "source_kinds":object["sources"].as_array().map(|rows| rows.iter().map(|row| row["kind"].clone()).collect::<Vec<_>>()),
        })).collect::<Vec<_>>();
        let summary = json!({"schema":"mobilee.bound-source-production-archive-acceptance/v1",
            "archive":archive,"archive_bytes":archive_bytes,"archive_sha256":archive_sha,"original_archive_unchanged":true,
            "root":imported.root,"package":imported.dump_report["package"],"parent_id":parent["id"],"parent_state":parent["state"],
            "included_sessions":children,"import_elapsed_ms":elapsed_ms,"import_phase_limit_ms":120000,"import_bytes_limit":2147483648_u64,"import_phase_remaining_ms":phase.remaining_ms().unwrap(),"file_count":imported.file_count,"total_bytes":imported.total_bytes,
            "unique_indexed_objects":objects.len(),"raw_readable_dex":imported.dump_report["readable_dex"],"runtime_observations":runtime.len(),
            "runtime_range_inventory_records":inventory.len(),"verified_runtime_ranges":verified,"verified_runtime_observations":verified,"omitted_observations":ledger["omitted_observations"],"runtime_analysis_complete":ledger["runtime_analysis_complete"],
            "runtime_source_ledger_complete":ledger["runtime_source_ledger_complete"],"runtime_analysis_partial_reasons":ledger["runtime_analysis_partial_reasons"],"runtime_analysis_scope":ledger["runtime_analysis_scope"],"unverified_observations":ledger["unverified_observations"],"hash_budget_remaining":ledger["hash_budget_remaining"],
            "inspection_budget_remaining":ledger["inspection_budget_remaining"],"runtime_header_probe_bytes":ledger["runtime_header_probe_bytes"],"static_stable_inode_hash_cache_hits":ledger["static_stable_inode_hash_cache_hits"],"runtime_stable_inode_hash_cache_hits":ledger["runtime_stable_inode_hash_cache_hits"],"full_hash_bytes_charged":ledger["full_hash_bytes_charged"],"runtime_heavy_results_omitted_records":ledger["runtime_heavy_results_omitted_records"],"runtime_source_diagnostics":sources,"metadata_contract":ledger["bound_source_metadata_contract"],"runtime_inventory":safe_runtime,"indexed_objects":safe_objects,
            "scope":"actual production archive importer and index rebuild; explicit isolated cache; class names and source instance identities omitted in report; not native UI adoption"});
        if let Some(fixture_path) = std::env::var_os("ME_BOUND_SOURCE_UI_FIXTURE") {
            // Private local fixture only. Preserve the actual serialized API
            // structure; the acceptance runner redacts identifiers consistently
            // before supplying it to browser tests. File bodies are not in it.
            let mut fixture = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(fixture_path)
                .unwrap();
            serde_json::to_writer(&mut fixture, &imported).unwrap();
        }
        let mut output = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(report)
            .unwrap();
        use std::io::Write;
        output
            .write_all(&serde_json::to_vec_pretty(&summary).unwrap())
            .unwrap();
    }

    #[tokio::test]
    #[ignore = "requires explicit retained local dump directory; no device access"]
    async fn retained_runtime_directory_import_keeps_file_sources_and_partial_parent() {
        let root = std::env::var("KSIGHT_RETAINED_DUMP_DIRECTORY")
            .expect("explicit retained dump directory");
        let imported = super::super::import_kernsight_evidence_directory(root)
            .await
            .unwrap();
        let ledger = &imported.dump_report["local_storage_accounting"];
        assert_eq!(ledger["verified_code_unique_bytes"], 19983868);
        assert_eq!(ledger["verified_code_logical_bytes"], 29603824);
        let file = imported
            .files
            .iter()
            .find(|f| {
                f.relative_path
                    .ends_with("0477ba96-b4db-4845-bcf4-19b62f67150a.code")
            })
            .unwrap();
        assert_eq!(file.code_evidence.len(), 1);
        assert_eq!(
            file.code_evidence[0]["local_content_status"],
            "complete_range_hash_verified"
        );
        assert_eq!(
            file.code_evidence[0]["source"]["birth_ns"],
            354039788906422_u64
        );
        let parent = &imported.session_report.as_ref().unwrap()["mobilee_capture_group"];
        assert_eq!(parent["state"], "partial");
        assert_eq!(parent["id"], "015a1673-f7f7-416c-96c2-30b17c469e26");
        if let Ok(output) = std::env::var("KSIGHT_RETAINED_LEDGER_REPORT") {
            fs::write(output,serde_json::to_vec_pretty(&json!({"verified_code_unique_bytes":ledger["verified_code_unique_bytes"],"verified_code_logical_bytes":ledger["verified_code_logical_bytes"],"runtime_observations":ledger["runtime_observations"],"parent_state":parent["state"],"parent_id":parent["id"]})).unwrap()).unwrap();
        }
    }
    #[test]
    #[ignore = "requires explicit retained local runtime sample; no device access"]
    fn retained_runtime_sample_uses_production_ledger() {
        let root = std::path::PathBuf::from(
            std::env::var_os("KSIGHT_RETAINED_RUNTIME_SAMPLE")
                .expect("explicit retained sample path"),
        );
        let files = fs::read_dir(&root)
            .unwrap()
            .map(|e| {
                let e = e.unwrap();
                (
                    e.file_name().to_string_lossy().into_owned(),
                    e.metadata().unwrap().len(),
                )
            })
            .collect::<Vec<_>>();
        let result = account(&root, &files);
        assert_eq!(result["verified_code_unique_bytes"], 16777216);
        assert_eq!(result["runtime_observations"].as_array().unwrap().len(), 2);
        assert_eq!(result["runtime_observations"][0]["mapping_complete"], false);
        assert_eq!(
            result["runtime_observations"][0]["object_inspection"]["status"],
            "no_dex_or_elf_header_in_retained_range"
        );
        assert_eq!(
            result["runtime_observations"][0]["object_inspection"]["scanned_bytes"],
            16777216
        );
        assert_eq!(
            result["runtime_observations"][1]["read"]["actual_length"],
            6946816
        );
        assert_eq!(
            result["runtime_observations"][1]["local_content_status"],
            "unknown_or_failed"
        );
    }
    #[test]
    #[cfg(unix)]
    fn legacy_zero_is_not_content_verification() {
        let root = std::env::temp_dir().join(format!("me-volume-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&root).unwrap();
        fs::write(root.join("a.dex"), [9; 17]).unwrap();
        fs::hard_link(root.join("a.dex"), root.join("b.dex")).unwrap();
        fs::write(root.join("c.dex"), [9; 17]).unwrap();
        let result = account(
            &root,
            &[
                ("a.dex".into(), 17),
                ("b.dex".into(), 17),
                ("c.dex".into(), 17),
            ],
        );
        assert_eq!(result["logical_file_bytes"], 51);
        assert_eq!(result["unique_inode_bytes"], 34);
        assert_eq!(result["shared_inode_logical_bytes"], 17);
        assert_eq!(result["verified_code_logical_bytes"], 0);
        assert_eq!(result["observations"], json!([]));
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn forged_member_hash_not_promoted_and_equal_files_are_only_accounted_redundancy() {
        let root = std::env::temp_dir().join(format!("me-members-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(root.join("code-evidence")).unwrap();
        let bytes = [7; 256];
        let hash = format!("{:x}", Sha256::digest(bytes));
        let mut files = Vec::new();
        for name in ["a.dex", "b.dex", "bad.dex"] {
            fs::write(root.join(name), bytes).unwrap();
            files.push((name.into(), 256));
            let note = json!({"schema":"kernsight.apk-member-evidence/v1","relative_path":name,"bytes":256,"sha256":if name=="bad.dex"{"0".repeat(64)}else{hash.clone()},"source_complete":true,"write_status":"hard_link"});
            let path = format!("code-evidence/{name}.json");
            fs::write(root.join(&path), serde_json::to_vec(&note).unwrap()).unwrap();
            files.push((path, 0));
        }
        let result = account(&root, &files);
        assert_eq!(result["verified_code_unique_bytes"], 256);
        assert_eq!(result["verified_code_logical_bytes"], 512);
        assert_eq!(result["verified_code_duplicate_bytes"], 256);
        #[cfg(unix)]
        assert_eq!(result["shared_inode_logical_bytes"], 0);
        assert_eq!(result["unverified_observations"], 1);
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn forged_member_note_cannot_hash_private_evidence() {
        let root = std::env::temp_dir().join(format!("me-private-scope-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(root.join("data-private")).unwrap();
        fs::create_dir(root.join("code-evidence")).unwrap();
        let bytes = b"synthetic placeholder";
        fs::write(root.join("data-private/log.txt"), bytes).unwrap();
        let note = json!({"schema":"kernsight.apk-member-evidence/v1","relative_path":"data-private/log.txt","bytes":bytes.len(),"sha256":format!("{:x}",Sha256::digest(bytes)),"source_complete":true,"write_status":"hard_link"});
        fs::write(
            root.join("code-evidence/forged.json"),
            serde_json::to_vec(&note).unwrap(),
        )
        .unwrap();
        let result = account(
            &root,
            &[
                ("data-private/log.txt".into(), bytes.len() as u64),
                ("code-evidence/forged.json".into(), 0),
            ],
        );
        assert_eq!(result["verified_code_logical_bytes"], 0);
        assert_eq!(result["unverified_observations"], 1);
        assert_eq!(
            result["hash_budget_remaining"],
            result["hash_budget_bytes"].as_u64().unwrap()
        );
        fs::remove_dir_all(root).unwrap();
    }
}

#[cfg(test)]
mod memmem_candidate_equivalence {
    #[test]
    fn byte_search_matches_windows_at_every_boundary() {
        for needle in [b"dex\n".as_slice(), b"\x7fELF".as_slice()] {
            for len in 0..128 {
                for offset in 0..=len {
                    let mut bytes = vec![0_u8; len];
                    if offset + needle.len() <= len {
                        bytes[offset..offset + needle.len()].copy_from_slice(needle);
                    }
                    assert_eq!(
                        memchr::memmem::find(&bytes, needle),
                        bytes.windows(4).position(|w| w == needle)
                    );
                    let old: Vec<_> = bytes
                        .windows(4)
                        .enumerate()
                        .filter_map(|(i, w)| (w == needle).then_some(i))
                        .collect();
                    let new: Vec<_> = memchr::memmem::find_iter(&bytes, needle).collect();
                    assert_eq!(new, old);
                }
            }
        }
    }
    #[test]
    fn adjacent_and_false_prefixes_preserve_all_matches() {
        for needle in [b"dex\n".as_slice(), b"\x7fELF".as_slice()] {
            let mut bytes = Vec::new();
            for _ in 0..80 {
                bytes.extend_from_slice(&needle[..3]);
                bytes.extend_from_slice(needle);
                bytes.extend_from_slice(needle);
            }
            let old: Vec<_> = bytes
                .windows(4)
                .enumerate()
                .filter_map(|(i, w)| (w == needle).then_some(i))
                .collect();
            assert_eq!(
                memchr::memmem::find_iter(&bytes, needle).collect::<Vec<_>>(),
                old
            );
        }
    }
}
