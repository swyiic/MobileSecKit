mod archive_objects;
mod build_identity;
pub mod capture_groups;
#[cfg(test)]
mod delivery_linker_intake;
mod dex_class_index;
mod dump_policy;
mod elf_runtime;
mod perf_loss;
mod runtime_paths;
mod session_budget;
pub(crate) mod session_deadline;
mod stage_policy;
mod storage_evidence;
use crate::{run_device_adb, run_device_root_script};
use ksight_core::{
    DexArtifactSet, DumpArtifact, MergedDumpRef, SessionGraph, SessionReport, SessionReportBuilder,
};
use ksight_model::Event;
use ksight_protocol::{
    AgentStatus, DurableSessionSummary, GetStatus, Hello, ListSessions, Message, ReplayBatches,
    CURRENT_PROTOCOL,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tauri::State;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStdin, ChildStdout, Command};
use tokio::time::{timeout, Duration, Instant};
use uuid::Uuid;
use zip::{write::SimpleFileOptions, ZipArchive, ZipWriter};

const KSIGHT_AGENT: &str = "/data/local/tmp/ksight/ksightd";
const KSIGHT_SPOOL: &str = "/data/local/tmp/ksight/spool";
const KSIGHT_PACKAGES: &str = "/data/local/tmp/ksight/packages";
const KSIGHT_PUBLIC_PACKAGES: &str = "/storage/emulated/0/Download/dexDump";
const MAX_PROTOCOL_FRAME: usize = 8 * 1024 * 1024;
const KSIGHT_LAST_SESSION: &str = "/data/local/tmp/ksight/spool/last_session";
const KSIGHT_CAPTURE_LOG: &str = "/data/local/tmp/ksight/capture.log";
const KSIGHT_HIDE_DEBUG: &str = "/data/local/tmp/ksight/ksight-hide-debug.sh";
const KSIGHT_RELEASES_API: &str =
    "https://api.github.com/repos/swyiic/KernSight/releases?per_page=20";
const KSIGHT_RELEASE_ASSET: &str = "ksightd-android-arm64";
const MAX_AGENT_DOWNLOAD_BYTES: u64 = 64 * 1024 * 1024;
const MAX_INSPECT_PLAINTEXT_BYTES: u32 = 64 * 1024;
const MIRROR_STATUS_TIMEOUT: Duration = Duration::from_secs(4);
const MIRROR_CONTROL_TIMEOUT: Duration = Duration::from_secs(8);
const MIRROR_STOP_TIMEOUT: Duration = Duration::from_secs(18);
const MOBILEE_EVIDENCE_SCHEMA: &str = "mobilee.kernsight-evidence/v1";
const MAX_EVIDENCE_ARCHIVE_FILES: usize = 100_000;
const MAX_EVIDENCE_ARCHIVE_BYTES: u64 = 8 * 1024 * 1024 * 1024;

const DEVICE_MIRROR_PROCESS_STATUS: &str = r#"
capture_count=0
pcap_count=0
for pid in $(pidof ksightd 2>/dev/null); do
  cmd=$(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null) || continue
  case "$cmd" in
    '/data/local/tmp/ksight/ksightd capture '*|*'/ksightd capture '*) capture_count=$((capture_count + 1)) ;;
  esac
done
for pid in $(pidof tcpdump 2>/dev/null); do
  cmd=$(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null) || continue
  case "$cmd" in
    'tcpdump '*'/data/local/tmp/ksight/spool/forensics/'*'/traffic.pcap '*|*'/tcpdump '*'/data/local/tmp/ksight/spool/forensics/'*'/traffic.pcap '*) pcap_count=$((pcap_count + 1)) ;;
  esac
done
echo "capture_count=$capture_count"
echo "pcap_count=$pcap_count"
"#;

const STOP_KSIGHTD_CAPTURE: &str = r#"
capture_pids=''
for pid in $(pidof ksightd 2>/dev/null); do
  cmd=$(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null) || continue
  case "$cmd" in
    '/data/local/tmp/ksight/ksightd capture '*|*'/ksightd capture '*) capture_pids="$capture_pids $pid" ;;
  esac
done
[ -z "$capture_pids" ] || kill $capture_pids 2>/dev/null || true

# Give ksightd enough time to stop its helpers and seal the durable session.
attempt=0
while [ "$attempt" -lt 24 ]; do
  alive=''
  for pid in $capture_pids; do
    [ -d "/proc/$pid" ] && alive="$alive $pid"
  done
  [ -z "$alive" ] && break
  sleep 0.5
  attempt=$((attempt + 1))
done
for pid in $capture_pids; do
  [ ! -d "/proc/$pid" ] || kill -9 "$pid" 2>/dev/null || true
done

# A killed collector cannot reap std::process::Child. Only touch tcpdump
# processes whose output is inside KernSight's own forensics spool.
pcap_pids=''
for pid in $(pidof tcpdump 2>/dev/null); do
  cmd=$(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null) || continue
  case "$cmd" in
    'tcpdump '*'/data/local/tmp/ksight/spool/forensics/'*'/traffic.pcap '*|*'/tcpdump '*'/data/local/tmp/ksight/spool/forensics/'*'/traffic.pcap '*)
      pcap_pids="$pcap_pids $pid"
      ;;
  esac
done
[ -z "$pcap_pids" ] || kill $pcap_pids 2>/dev/null || true
sleep 0.5
for pid in $pcap_pids; do
  [ ! -d "/proc/$pid" ] || kill -9 "$pid" 2>/dev/null || true
done

capture_count=0
pcap_count=0
for pid in $(pidof ksightd 2>/dev/null); do
  cmd=$(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null) || continue
  case "$cmd" in
    '/data/local/tmp/ksight/ksightd capture '*|*'/ksightd capture '*) capture_count=$((capture_count + 1)) ;;
  esac
done
for pid in $(pidof tcpdump 2>/dev/null); do
  cmd=$(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null) || continue
  case "$cmd" in
    'tcpdump '*'/data/local/tmp/ksight/spool/forensics/'*'/traffic.pcap '*|*'/tcpdump '*'/data/local/tmp/ksight/spool/forensics/'*'/traffic.pcap '*) pcap_count=$((pcap_count + 1)) ;;
  esac
done
echo "capture_count=$capture_count"
echo "pcap_count=$pcap_count"
"#;

const FORCE_STOP_KSIGHTD_CAPTURE: &str = r#"
for pid in $(pidof ksightd 2>/dev/null); do
  cmd=$(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null) || continue
  case "$cmd" in
    '/data/local/tmp/ksight/ksightd capture '*|*'/ksightd capture '*) kill -9 "$pid" 2>/dev/null || true ;;
  esac
done
for pid in $(pidof tcpdump 2>/dev/null); do
  cmd=$(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null) || continue
  case "$cmd" in
    'tcpdump '*'/data/local/tmp/ksight/spool/forensics/'*'/traffic.pcap '*|*'/tcpdump '*'/data/local/tmp/ksight/spool/forensics/'*'/traffic.pcap '*) kill -9 "$pid" 2>/dev/null || true ;;
  esac
done
echo 'capture_count=0'
echo 'pcap_count=0'
"#;

/// Host-side handle for one long-running Burp mirror capture.
#[derive(Default)]
pub struct MirrorSessionState {
    operation: tokio::sync::Mutex<()>,
    child: tokio::sync::Mutex<Option<Child>>,
    serial: tokio::sync::Mutex<Option<String>>,
    package: tokio::sync::Mutex<Option<String>>,
    reverse_port: tokio::sync::Mutex<Option<u16>>,
    logs: Arc<tokio::sync::Mutex<VecDeque<String>>>,
}

/// Live mirror status for Device Tools.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KernSightMirrorStatus {
    running: bool,
    cleanup_pending: bool,
    package: Option<String>,
    serial: Option<String>,
    detail: Option<String>,
    logs: Vec<String>,
    coverage: MirrorCoverageStatus,
}

/// Payload-free live coverage counters parsed from ksightd diagnostics.
#[derive(Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MirrorCoverageStatus {
    network_connects: u64,
    network_handshakes: u64,
    observed_fragments: u64,
    observed_bytes: u64,
    reconstructed_messages: u64,
    reconstructed_requests: u64,
    reconstructed_responses: u64,
    delivered: u64,
    delivery_failed: u64,
    retry_pending: u64,
    unknown_directions: u64,
    buffered_bytes: u64,
    attached_probes: u64,
    active_probes: u64,
    standard_tls_fragments: u64,
    vendor_fragments: u64,
    jni_fragments: u64,
    stack_candidates: u64,
    stack_export_candidates: u64,
    stack_pinned_boundaries: u64,
    stack_empirical_boundaries: u64,
    stack_keylog_candidates: u64,
    stack_uncovered: u64,
    state: &'static str,
}

fn mirror_counter(line: &str, key: &str) -> Option<u64> {
    line.split_whitespace().find_map(|part| {
        let (name, value) = part.split_once('=')?;
        if name != key {
            return None;
        }
        value
            .trim_matches(|ch: char| !ch.is_ascii_digit())
            .parse()
            .ok()
    })
}

fn mirror_coverage_from_logs(logs: &VecDeque<String>, running: bool) -> MirrorCoverageStatus {
    let diagnostic = logs
        .iter()
        .rev()
        .find(|line| line.contains("observed_fragments=") && line.contains("delivered="));
    let count = |key| {
        diagnostic
            .and_then(|line| mirror_counter(line, key))
            .unwrap_or(0)
    };
    let attached_probes = logs
        .iter()
        .filter(|line| line.contains("attached") && !line.contains("attached=0"))
        .count() as u64;
    let active_probes = logs
        .iter()
        .filter(|line| line.contains("hits=") && mirror_counter(line, "hits").unwrap_or(0) > 0)
        .count() as u64;
    let observed_fragments = count("observed_fragments");
    let network_connects = count("network_connects");
    let reconstructed_messages = count("reconstructed_messages");
    let delivered = count("delivered");
    let delivery_failed = count("delivery_failed");
    let state = if !running {
        "idle"
    } else if network_connects == 0 {
        "waiting_for_network"
    } else if observed_fragments == 0 {
        "waiting_for_boundary"
    } else if reconstructed_messages == 0 {
        "unrecognized_stream"
    } else if delivered == 0 && delivery_failed > 0 {
        "delivery_failed"
    } else if delivered == 0 {
        "waiting_for_pair"
    } else {
        "delivering"
    };
    MirrorCoverageStatus {
        network_connects,
        network_handshakes: count("network_handshakes"),
        observed_fragments,
        observed_bytes: count("observed_bytes"),
        reconstructed_messages,
        reconstructed_requests: count("reconstructed_requests"),
        reconstructed_responses: count("reconstructed_responses"),
        delivered,
        delivery_failed,
        retry_pending: count("retry_pending"),
        unknown_directions: count("unknown_directions"),
        buffered_bytes: count("buffered_bytes"),
        attached_probes,
        active_probes,
        standard_tls_fragments: count("standard_tls_fragments"),
        vendor_fragments: count("vendor_fragments"),
        jni_fragments: count("jni_fragments"),
        stack_candidates: count("stack_candidates"),
        stack_export_candidates: count("stack_export_candidates"),
        stack_pinned_boundaries: count("stack_pinned_boundaries"),
        stack_empirical_boundaries: count("stack_empirical_boundaries"),
        stack_keylog_candidates: count("stack_keylog_candidates"),
        stack_uncovered: count("stack_uncovered"),
        state,
    }
}

#[derive(Debug, Default)]
struct DeviceMirrorProcessStatus {
    capture_count: u32,
    pcap_count: u32,
}

fn sanitize_mirror_log(line: &str) -> Option<String> {
    let line = line.trim();
    if line.is_empty() {
        return None;
    }
    let sensitive_markers = [
        " preview=",
        " payload=",
        " plaintext=",
        " body=",
        " needle=",
        "\"preview\":",
        "\"payload\":",
        "\"plaintext\":",
        "\"body\":",
    ];
    let cutoff = sensitive_markers
        .iter()
        .filter_map(|marker| line.find(marker))
        .min();
    let mut sanitized = match cutoff {
        Some(index) => format!("{} [载荷已从运行日志中省略]", line[..index].trim_end()),
        None => line.to_owned(),
    };
    if sanitized.len() > 2_048 {
        sanitized.truncate(2_048);
        sanitized.push_str("…");
    }
    Some(sanitized)
}

fn collect_mirror_logs<R>(stream: R, logs: Arc<tokio::sync::Mutex<VecDeque<String>>>)
where
    R: AsyncRead + Unpin + Send + 'static,
{
    tokio::spawn(async move {
        let mut reader = BufReader::new(stream);
        let mut line = String::new();
        loop {
            line.clear();
            match reader.read_line(&mut line).await {
                Ok(0) | Err(_) => break,
                Ok(_) => {
                    let Some(entry) = sanitize_mirror_log(&line) else {
                        continue;
                    };
                    let mut logs = logs.lock().await;
                    while logs.len() >= 200 {
                        logs.pop_front();
                    }
                    logs.push_back(entry);
                }
            }
        }
    });
}

const PROBE_SCRIPT: &str = r#"
printf 'kernel_version='; uname -r 2>/dev/null
printf 'architecture='; uname -m 2>/dev/null
printf 'android_version='; getprop ro.build.version.release
printf 'sdk_version='; getprop ro.build.version.sdk
printf 'verified_boot_state='; getprop ro.boot.verifiedbootstate
printf 'flash_locked='; getprop ro.boot.flash.locked
printf 'selinux_status='; getenforce 2>/dev/null
if [ -r /sys/kernel/btf/vmlinux ]; then echo 'btf=available'; else echo 'btf=missing'; fi
if grep -q ' /sys/fs/bpf ' /proc/mounts 2>/dev/null; then echo 'bpffs=mounted'; elif [ -d /sys/fs/bpf ]; then echo 'bpffs=directory-only'; else echo 'bpffs=missing'; fi
if command -v su >/dev/null 2>&1; then echo 'su_binary=available'; else echo 'su_binary=missing'; fi
if [ -x /system/bin/ksightd ]; then echo 'agent=system'; elif [ -x /data/local/tmp/ksight/ksightd ]; then echo 'agent=development'; else echo 'agent=missing'; fi
printf 'unprivileged_bpf_disabled='; cat /proc/sys/kernel/unprivileged_bpf_disabled 2>/dev/null || echo unknown
"#;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CapabilityCheck {
    key: String,
    label: String,
    status: String,
    detail: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AndroidMonitorCapabilityProbe {
    serial: String,
    probed_at: u64,
    kernel_version: String,
    architecture: String,
    android_version: String,
    sdk_version: String,
    verified_boot_state: String,
    bootloader_status: String,
    selinux_status: String,
    root_status: String,
    btf_status: String,
    bpffs_status: String,
    bpf_status: String,
    agent_status: String,
    recommended_mode: String,
    trust_level: String,
    summary: String,
    checks: Vec<CapabilityCheck>,
    warnings: Vec<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KernSightOverview {
    agent_version: String,
    agent_build_identity: Option<build_identity::AgentBuildIdentity>,
    protocol_major: u16,
    protocol_minor: u16,
    status: AgentStatus,
    sessions: Vec<DurableSessionSummary>,
    private_package_bytes: u64,
    public_package_bytes: u64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KernSightProvisionStep {
    key: String,
    label: String,
    status: String,
    detail: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KernSightProvisionResult {
    installed_version: String,
    release_tag: String,
    release_url: String,
    asset_sha256: String,
    asset_bytes: u64,
    steps: Vec<KernSightProvisionStep>,
}

#[derive(Debug, Deserialize)]
struct GithubRelease {
    tag_name: String,
    html_url: String,
    draft: bool,
    assets: Vec<GithubReleaseAsset>,
}

#[derive(Debug, Deserialize)]
struct GithubReleaseAsset {
    name: String,
    browser_download_url: String,
    size: u64,
    digest: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KernSightSessionReport {
    session_id: Uuid,
    report_schema: String,
    report: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KernSightCaptureRequest {
    #[serde(default)]
    session_budget: Option<session_budget::Limits>,
    #[serde(default)]
    runtime_paths: Option<runtime_paths::RuntimePaths>,
    #[serde(default)]
    code_only: bool,
    #[serde(default)]
    expected_code_sources: Option<Value>,
    #[serde(default)]
    collect_keys: bool,
    #[serde(default)]
    collect_private: bool,
    #[serde(default)]
    collect_memory_windows: bool,
    #[serde(default)]
    output_budget_bytes: Option<u64>,
    #[serde(default)]
    output_budget_ms: Option<u64>,
    #[serde(default)]
    capture_relation: Option<capture_groups::Relation>,
    #[serde(default)]
    capture_relations: Option<Vec<capture_groups::Relation>>,
    serial: String,
    #[serde(default)]
    package: Option<String>,
    duration_seconds: u64,
    #[serde(default)]
    files: bool,
    #[serde(default)]
    files_fd: bool,
    #[serde(default)]
    network: bool,
    #[serde(default)]
    network_io: bool,
    #[serde(default)]
    memory: bool,
    #[serde(default)]
    memory_all: bool,
    #[serde(default)]
    binder: bool,
    #[serde(default)]
    sched: bool,
    #[serde(default)]
    include_threads: bool,
    #[serde(default)]
    inspect_tls: bool,
    #[serde(default)]
    inspect_jni: bool,
    #[serde(default)]
    inspect_linker: bool,
    #[serde(default)]
    inspect_stages: Option<String>,
    #[serde(default)]
    inspect_adapter: Option<String>,
    #[serde(default)]
    hide_debug: bool,
    #[serde(default = "default_sample_one_in")]
    sample_one_in: u32,
    #[serde(default = "default_inspect_max_bytes")]
    inspect_max_bytes: u32,
    #[serde(default)]
    inspect_max_hits: u32,
    /// Force-stop the package, start capture, then cold-start the launcher after 2s.
    #[serde(default)]
    launch_after_attach: bool,
    /// Burp HTTP proxy `host:port`. Reconstructs TLS HTTP/WS; does not set a device proxy.
    #[serde(default)]
    mirror_burp: Option<String>,
    /// `adb reverse` the Burp port and `adb forward` playback port 18081.
    #[serde(default)]
    mirror_via_adb: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KernSightCaptureResult {
    session_id: Option<Uuid>,
    started_unix_ms: u64,
    finished_unix_ms: u64,
    command_preview: String,
    stdout: String,
    stderr: String,
    exit_code: Option<i32>,
    hide_debug: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KernSightEventPage {
    session_id: Uuid,
    offset: usize,
    limit: usize,
    total_matches: usize,
    next_offset: Option<usize>,
    type_counts: BTreeMap<String, u64>,
    events: Vec<Value>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KernSightEvidenceFileContent {
    package: String,
    relative_path: String,
    bytes: u64,
    truncated: bool,
    encoding: String,
    content: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KernSightLocalEvidenceBundle {
    root: String,
    package: String,
    file_count: u64,
    total_bytes: u64,
    dump_report: Value,
    session_report: Option<Value>,
    capture_text: String,
    files: Vec<KernSightLocalEvidenceFile>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KernSightLocalEvidenceFile {
    relative_path: String,
    bytes: u64,
    category: String,
    memory_evidence: Vec<Value>,
    code_evidence: Vec<Value>,
}

#[derive(Debug, Deserialize)]
struct PackageDumpForMerge {
    #[serde(default)]
    package: String,
    #[serde(default)]
    dump_id: String,
    #[serde(default)]
    artifacts: Vec<DumpArtifact>,
    #[serde(default)]
    graph: SessionGraph,
}

fn default_sample_one_in() -> u32 {
    1
}

fn default_inspect_max_bytes() -> u32 {
    MAX_INSPECT_PLAINTEXT_BYTES
}

fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn parse_probe_output(output: &str) -> HashMap<String, String> {
    output
        .lines()
        .filter_map(|line| line.trim().split_once('='))
        .map(|(key, value)| (key.trim().to_string(), value.trim().to_string()))
        .collect()
}

fn value(values: &HashMap<String, String>, key: &str, fallback: &str) -> String {
    values
        .get(key)
        .filter(|value| !value.is_empty())
        .cloned()
        .unwrap_or_else(|| fallback.into())
}

fn check(key: &str, label: &str, status: &str, detail: impl Into<String>) -> CapabilityCheck {
    CapabilityCheck {
        key: key.into(),
        label: label.into(),
        status: status.into(),
        detail: detail.into(),
    }
}

fn bootloader_status(verified_boot: &str, flash_locked: &str) -> String {
    match (verified_boot.to_ascii_lowercase().as_str(), flash_locked) {
        ("green", _) => "Locked / OEM Verified".into(),
        ("yellow", _) => "Locked / Custom Key".into(),
        ("orange", _) | (_, "0") => "Unlocked".into(),
        (_, "1") => "Locked / State Unknown".into(),
        _ => "Unknown".into(),
    }
}

fn build_probe(
    serial: String,
    values: HashMap<String, String>,
    root_granted: bool,
) -> AndroidMonitorCapabilityProbe {
    let kernel_version = value(&values, "kernel_version", "Unknown");
    let architecture = value(&values, "architecture", "Unknown");
    let android_version = value(&values, "android_version", "Unknown");
    let sdk_version = value(&values, "sdk_version", "Unknown");
    let verified_boot_state = value(&values, "verified_boot_state", "unknown");
    let flash_locked = value(&values, "flash_locked", "unknown");
    let selinux_status = value(&values, "selinux_status", "Unknown");
    let btf_available = values.get("btf").is_some_and(|value| value == "available");
    let bpffs_value = value(&values, "bpffs", "missing");
    let bpffs_mounted = bpffs_value == "mounted";
    let su_available = values
        .get("su_binary")
        .is_some_and(|value| value == "available");
    let agent_value = value(&values, "agent", "missing");
    let unprivileged_bpf = value(&values, "unprivileged_bpf_disabled", "unknown");

    let root_status = if root_granted {
        "Granted"
    } else if su_available {
        "Installed / Not Granted"
    } else {
        "Unavailable"
    }
    .to_string();
    let btf_status = if btf_available {
        "Available"
    } else {
        "Missing"
    }
    .to_string();
    let bpffs_status = match bpffs_value.as_str() {
        "mounted" => "Mounted",
        "directory-only" => "Directory Only",
        _ => "Missing",
    }
    .to_string();
    let agent_status = match agent_value.as_str() {
        "system" => "KernSight System Agent",
        "development" => "KernSight Dev Agent",
        _ => "Not Installed",
    }
    .to_string();

    let recommended_mode = if agent_value == "system" && bpffs_mounted {
        "system"
    } else if root_granted && btf_available && bpffs_mounted {
        "development"
    } else {
        "standard"
    }
    .to_string();
    let trust_level = if agent_value == "system"
        && matches!(verified_boot_state.as_str(), "green" | "yellow")
        && flash_locked == "1"
    {
        "System Candidate"
    } else if root_granted {
        "Dev Root"
    } else {
        "Integrity Unknown"
    }
    .to_string();
    let bpf_status = if btf_available && bpffs_mounted && root_granted {
        "Ready for Dev Probe"
    } else if btf_available && bpffs_mounted {
        "Kernel Ready / Privilege Required"
    } else {
        "Prerequisites Missing"
    }
    .to_string();

    let bootloader = bootloader_status(&verified_boot_state, &flash_locked);
    let mut warnings = Vec::new();
    if !root_granted && agent_value != "system" {
        warnings.push("当前没有 Root 授权或 KernSight 系统 Agent，不能加载全设备采集程序。".into());
    }
    if !btf_available {
        warnings
            .push("未发现可读的 /sys/kernel/btf/vmlinux，CO-RE 采集需要设备专用兼容方案。".into());
    }
    if !bpffs_mounted {
        warnings.push("bpffs 尚未挂载，BPF program/map 无法按规划固定和共享。".into());
    }
    if bootloader.contains("Unlocked") {
        warnings.push("Bootloader 处于 Unlocked；该设备适合研发，但不能标记为系统可信。".into());
    }
    if agent_value == "system" {
        warnings.push("检测到系统 Agent 路径；仍需后续握手校验版本、签名和 BPF links。".into());
    }

    let checks = vec![
        check(
            "root",
            "Root authorization",
            if root_granted {
                "available"
            } else if su_available {
                "restricted"
            } else {
                "missing"
            },
            &root_status,
        ),
        check(
            "btf",
            "Kernel BTF",
            if btf_available {
                "available"
            } else {
                "missing"
            },
            &btf_status,
        ),
        check(
            "bpffs",
            "BPF filesystem",
            if bpffs_mounted {
                "available"
            } else {
                "missing"
            },
            &bpffs_status,
        ),
        check(
            "bpf",
            "eBPF readiness",
            if btf_available && bpffs_mounted {
                if root_granted {
                    "available"
                } else {
                    "restricted"
                }
            } else {
                "missing"
            },
            format!("{bpf_status} · unprivileged_bpf_disabled={unprivileged_bpf}"),
        ),
        check(
            "selinux",
            "SELinux",
            if selinux_status.eq_ignore_ascii_case("enforcing") {
                "available"
            } else {
                "warning"
            },
            &selinux_status,
        ),
        check(
            "boot",
            "Verified Boot",
            if matches!(verified_boot_state.as_str(), "green" | "yellow") {
                "available"
            } else if verified_boot_state == "orange" {
                "warning"
            } else {
                "unknown"
            },
            &bootloader,
        ),
        check(
            "agent",
            "KernSight Agent",
            if agent_value == "missing" {
                "missing"
            } else {
                "available"
            },
            &agent_status,
        ),
    ];

    let summary = match recommended_mode.as_str() {
        "system" => "检测到系统 Agent 候选，可以进入系统握手与完整性校验阶段。",
        "development" => "设备满足 Dev Root 基础条件，下一步可以经确认部署开发 Agent。",
        _ => "当前只能使用 Standard 模式；完整监控需要 Root 授权或预装系统 Agent。",
    }
    .to_string();

    AndroidMonitorCapabilityProbe {
        serial,
        probed_at: now_millis(),
        kernel_version,
        architecture,
        android_version,
        sdk_version,
        verified_boot_state,
        bootloader_status: bootloader,
        selinux_status,
        root_status,
        btf_status,
        bpffs_status,
        bpf_status,
        agent_status,
        recommended_mode,
        trust_level,
        summary,
        checks,
        warnings,
    }
}

#[tauri::command]
pub async fn probe_android_monitor_capabilities(
    serial: String,
) -> Result<AndroidMonitorCapabilityProbe, String> {
    if serial.trim().is_empty() {
        return Err("请先选择 Android 设备".into());
    }

    let (probe, root) = tokio::join!(
        run_device_adb(&serial, &["shell", PROBE_SCRIPT]),
        run_device_root_script(&serial, "id")
    );
    let probe = probe?;
    if probe.code != Some(0) && probe.stdout.trim().is_empty() {
        return Err(if probe.stderr.trim().is_empty() {
            "设备能力探测没有返回结果".into()
        } else {
            probe.stderr
        });
    }
    let root_granted = root
        .ok()
        .is_some_and(|output| output.code == Some(0) && output.stdout.contains("uid=0"));
    Ok(build_probe(
        serial,
        parse_probe_output(&probe.stdout),
        root_granted,
    ))
}

async fn download_release_asset(
    client: &reqwest::Client,
    url: &str,
    label: &str,
    expected_size: Option<u64>,
) -> Result<Vec<u8>, String> {
    let response = client
        .get(url)
        .send()
        .await
        .map_err(|error| format!("[{label}] 网络请求失败：{error}"))?;
    if !response.status().is_success() {
        return Err(format!("[{label}] GitHub 返回 HTTP {}", response.status()));
    }
    if response
        .content_length()
        .or(expected_size)
        .is_some_and(|size| size > MAX_AGENT_DOWNLOAD_BYTES)
    {
        return Err(format!("[{label}] 文件超过 64 MiB 安全上限"));
    }
    let bytes = response
        .bytes()
        .await
        .map_err(|error| format!("[{label}] 读取响应失败：{error}"))?
        .to_vec();
    if bytes.len() as u64 > MAX_AGENT_DOWNLOAD_BYTES {
        return Err(format!("[{label}] 文件超过 64 MiB 安全上限"));
    }
    if let Some(expected) = expected_size {
        if expected != bytes.len() as u64 {
            return Err(format!(
                "[{label}] 文件大小不一致：Release={expected}，下载={} ",
                bytes.len()
            ));
        }
    }
    Ok(bytes)
}

fn checksum_for_asset(manifest: &str, asset_name: &str) -> Option<String> {
    manifest.lines().find_map(|line| {
        let mut fields = line.split_whitespace();
        let checksum = fields.next()?;
        let name = fields.next()?.trim_start_matches('*');
        (name == asset_name
            && checksum.len() == 64
            && checksum.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .then(|| checksum.to_ascii_lowercase())
    })
}

fn provision_step(key: &str, label: &str, detail: impl Into<String>) -> KernSightProvisionStep {
    KernSightProvisionStep {
        key: key.into(),
        label: label.into(),
        status: "complete".into(),
        detail: detail.into(),
    }
}

#[tauri::command]
pub async fn provision_latest_kernsight_agent(
    serial: String,
) -> Result<KernSightProvisionResult, String> {
    validate_serial(&serial).map_err(|error| format!("[检查设备标识] {error}"))?;
    let mut steps = Vec::new();

    let state = run_device_adb(&serial, &["get-state"])
        .await
        .map_err(|error| format!("[连接设备] {error}"))?;
    if state.code != Some(0) || state.stdout.trim() != "device" {
        return Err(format!(
            "[连接设备] ADB 设备不可用：{}",
            if state.stderr.is_empty() {
                state.stdout
            } else {
                state.stderr
            }
        ));
    }
    steps.push(provision_step("device", "连接设备", serial.clone()));

    let architecture = run_device_adb(&serial, &["shell", "getprop", "ro.product.cpu.abi"])
        .await
        .map_err(|error| format!("[检查架构] {error}"))?;
    let architecture = architecture.stdout.trim();
    if architecture != "arm64-v8a" {
        return Err(format!(
            "[检查架构] 当前自动安装包仅支持 arm64-v8a，设备返回 {architecture:?}"
        ));
    }
    steps.push(provision_step("architecture", "检查架构", architecture));

    let root = run_device_root_script(&serial, "id")
        .await
        .map_err(|error| format!("[检查 Root] {error}"))?;
    if root.code != Some(0) || !root.stdout.contains("uid=0") {
        return Err(format!(
            "[检查 Root] 未获得 uid=0；请在手机上允许 Root 授权。{}",
            if root.stderr.is_empty() {
                root.stdout
            } else {
                root.stderr
            }
        ));
    }
    steps.push(provision_step("root", "检查 Root", "uid=0 已授权"));

    let client = reqwest::Client::builder()
        .user_agent(format!(
            "MobileE/{} KernSight-Provisioner",
            env!("CARGO_PKG_VERSION")
        ))
        .connect_timeout(Duration::from_secs(15))
        .timeout(Duration::from_secs(120))
        .build()
        .map_err(|error| format!("[初始化下载器] {error}"))?;
    let releases = client
        .get(KSIGHT_RELEASES_API)
        .send()
        .await
        .map_err(|error| format!("[查询 GitHub Release] 网络请求失败：{error}"))?;
    if !releases.status().is_success() {
        return Err(format!(
            "[查询 GitHub Release] GitHub 返回 HTTP {}",
            releases.status()
        ));
    }
    let releases: Vec<GithubRelease> = releases
        .json()
        .await
        .map_err(|error| format!("[解析 GitHub Release] JSON 格式错误：{error}"))?;
    let release = releases
        .into_iter()
        .find(|release| {
            !release.draft
                && release
                    .assets
                    .iter()
                    .any(|asset| asset.name == KSIGHT_RELEASE_ASSET)
        })
        .ok_or_else(|| {
            format!("[选择 GitHub Release] 没有找到包含 {KSIGHT_RELEASE_ASSET} 的可用 Release")
        })?;
    let agent_asset = release
        .assets
        .iter()
        .find(|asset| asset.name == KSIGHT_RELEASE_ASSET)
        .ok_or_else(|| format!("[选择发布包] 缺少 {KSIGHT_RELEASE_ASSET}"))?;
    let checksum_asset = release
        .assets
        .iter()
        .find(|asset| asset.name == "SHA256SUMS")
        .ok_or_else(|| "[选择发布包] Release 缺少 SHA256SUMS，拒绝安装".to_string())?;
    steps.push(provision_step(
        "release",
        "选择 GitHub Release",
        format!("{} · {} bytes", release.tag_name, agent_asset.size),
    ));

    let checksum_bytes = download_release_asset(
        &client,
        &checksum_asset.browser_download_url,
        "下载 SHA256SUMS",
        Some(checksum_asset.size),
    )
    .await?;
    let checksum_manifest = std::str::from_utf8(&checksum_bytes)
        .map_err(|error| format!("[解析 SHA256SUMS] 不是 UTF-8 文本：{error}"))?;
    let expected_sha256 = checksum_for_asset(checksum_manifest, KSIGHT_RELEASE_ASSET)
        .ok_or_else(|| format!("[解析 SHA256SUMS] 没有 {KSIGHT_RELEASE_ASSET} 的校验值"))?;
    let agent_bytes = download_release_asset(
        &client,
        &agent_asset.browser_download_url,
        "下载 KernSight Agent",
        Some(agent_asset.size),
    )
    .await?;
    let actual_sha256 = format!("{:x}", Sha256::digest(&agent_bytes));
    if actual_sha256 != expected_sha256 {
        return Err(format!(
            "[校验发布包] SHA-256 不一致：expected={expected_sha256} actual={actual_sha256}"
        ));
    }
    if let Some(github_digest) = agent_asset.digest.as_deref() {
        let github_sha256 = github_digest
            .strip_prefix("sha256:")
            .unwrap_or(github_digest);
        if !github_sha256.eq_ignore_ascii_case(&actual_sha256) {
            return Err(format!(
                "[校验发布包] GitHub digest 不一致：expected={github_sha256} actual={actual_sha256}"
            ));
        }
    }
    steps.push(provision_step(
        "download",
        "下载并校验",
        format!("{} · {} bytes", actual_sha256, agent_bytes.len()),
    ));

    let temporary_path =
        std::env::temp_dir().join(format!("mobilee-{}-{KSIGHT_RELEASE_ASSET}", Uuid::new_v4()));
    std::fs::write(&temporary_path, &agent_bytes)
        .map_err(|error| format!("[保存临时发布包] {}：{error}", temporary_path.display()))?;
    let remote_stage = format!("/data/local/tmp/ksight-install-{}", Uuid::new_v4());
    let local_path = temporary_path.to_string_lossy().into_owned();
    let push_result = timeout(
        Duration::from_secs(120),
        Command::new("adb")
            .args(["-s", &serial, "push", &local_path, &remote_stage])
            .kill_on_drop(true)
            .output(),
    )
    .await;
    let _ = std::fs::remove_file(&temporary_path);
    let push = push_result
        .map_err(|_| "[推送到手机] ADB push 超过 120 秒".to_string())?
        .map_err(|error| format!("[推送到手机] 无法启动 adb：{error}"))?;
    if !push.status.success() {
        return Err(format!(
            "[推送到手机] {}",
            String::from_utf8_lossy(&push.stderr).trim()
        ));
    }
    steps.push(provision_step("push", "推送到手机", remote_stage.clone()));

    let install_script = format!(
        "set -e; mkdir -p /data/local/tmp/ksight; chown root:root {stage}; chmod 0755 {stage}; mv -f {stage} {agent}; chown root:root {agent}; chmod 0755 {agent}",
        stage = remote_stage,
        agent = KSIGHT_AGENT,
    );
    let install = run_device_root_script(&serial, &install_script)
        .await
        .map_err(|error| format!("[安装 Agent] {error}"))?;
    if install.code != Some(0) {
        return Err(format!(
            "[安装 Agent] {}",
            if install.stderr.is_empty() {
                install.stdout
            } else {
                install.stderr
            }
        ));
    }
    steps.push(provision_step("install", "Root 原子安装", KSIGHT_AGENT));

    let version = run_device_root_script(&serial, &format!("{KSIGHT_AGENT} --version"))
        .await
        .map_err(|error| format!("[验证版本] {error}"))?;
    if version.code != Some(0) || !version.stdout.starts_with("ksightd ") {
        return Err(format!(
            "[验证版本] Agent 没有返回有效版本：{} {}",
            version.stdout, version.stderr
        ));
    }
    let installed_version = version.stdout.trim().to_string();
    steps.push(provision_step(
        "version",
        "验证版本",
        installed_version.clone(),
    ));

    let connection = KernSightConnection::connect(&serial)
        .await
        .map_err(|error| format!("[协议握手] Agent 已安装但握手失败：{error}"))?;
    let handshake_version = connection.agent_version.clone();
    connection
        .close()
        .await
        .map_err(|error| format!("[协议握手] 关闭测试连接失败：{error}"))?;
    steps.push(provision_step(
        "handshake",
        "协议握手",
        format!("KernSight {handshake_version} · protocol ready"),
    ));

    Ok(KernSightProvisionResult {
        installed_version,
        release_tag: release.tag_name,
        release_url: release.html_url,
        asset_sha256: actual_sha256,
        asset_bytes: agent_bytes.len() as u64,
        steps,
    })
}

struct KernSightConnection {
    child: Child,
    input: Option<ChildStdin>,
    output: BufReader<ChildStdout>,
    agent_version: String,
}

impl KernSightConnection {
    async fn connect(serial: &str) -> Result<Self, String> {
        Self::connect_scoped(serial, None).await
    }
    async fn connect_scoped(
        serial: &str,
        paths: Option<&runtime_paths::RuntimePaths>,
    ) -> Result<Self, String> {
        validate_serial(serial)?;
        let script = runtime_paths::route(
            paths,
            &format!("{KSIGHT_AGENT} serve --spool-root {KSIGHT_SPOOL}"),
        )?;
        let remote = crate::root_shell_command(&script);
        let mut child = Command::new("adb")
            .args(["-s", serial, "shell", &remote])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .map_err(|error| format!("无法启动 KernSight ADB 协议：{error}"))?;
        let input = child.stdin.take().ok_or("KernSight 协议输入管道不可用")?;
        let output = child.stdout.take().ok_or("KernSight 协议输出管道不可用")?;
        let mut connection = Self {
            child,
            input: Some(input),
            output: BufReader::new(output),
            agent_version: String::new(),
        };
        connection
            .send(&Message::Hello(Hello {
                protocol: CURRENT_PROTOCOL,
                client_name: format!("MobileE/{}", env!("CARGO_PKG_VERSION")),
                capabilities: Vec::new(),
            }))
            .await?;
        match connection.receive().await? {
            Message::HelloAck(ack)
                if ack.protocol.major == CURRENT_PROTOCOL.major
                    && ack.protocol.minor <= CURRENT_PROTOCOL.minor =>
            {
                connection.agent_version = ack.agent_version;
            }
            Message::HelloAck(ack) => {
                return Err(format!(
                    "KernSight 协议不兼容：agent={}.{} MobileE={}.{}",
                    ack.protocol.major,
                    ack.protocol.minor,
                    CURRENT_PROTOCOL.major,
                    CURRENT_PROTOCOL.minor
                ));
            }
            message => return Err(format!("KernSight 握手响应不正确：{message:?}")),
        }
        Ok(connection)
    }

    async fn send(&mut self, message: &Message) -> Result<(), String> {
        let bytes = serde_json::to_vec(message).map_err(|error| error.to_string())?;
        if bytes.len() > MAX_PROTOCOL_FRAME {
            return Err("KernSight 请求超过 8 MiB 协议限制".into());
        }
        let length = u32::try_from(bytes.len())
            .map_err(|_| "KernSight 请求长度无法表示".to_string())?
            .to_be_bytes();
        let input = self.input.as_mut().ok_or("KernSight 输入已经关闭")?;
        input
            .write_all(&length)
            .await
            .map_err(|error| error.to_string())?;
        input
            .write_all(&bytes)
            .await
            .map_err(|error| error.to_string())?;
        input.flush().await.map_err(|error| error.to_string())
    }

    async fn receive(&mut self) -> Result<Message, String> {
        let mut header = [0_u8; 4];
        timeout(Duration::from_secs(60), self.output.read_exact(&mut header))
            .await
            .map_err(|_| "等待 KernSight 响应超时".to_string())?
            .map_err(|error| format!("读取 KernSight 帧头失败：{error}"))?;
        let length = usize::try_from(u32::from_be_bytes(header))
            .map_err(|_| "KernSight 响应长度无法表示".to_string())?;
        if length > MAX_PROTOCOL_FRAME {
            return Err(format!("KernSight 响应超过协议限制：{length} bytes"));
        }
        let mut body = vec![0_u8; length];
        timeout(Duration::from_secs(60), self.output.read_exact(&mut body))
            .await
            .map_err(|_| "读取 KernSight 响应正文超时".to_string())?
            .map_err(|error| format!("读取 KernSight 响应正文失败：{error}"))?;
        serde_json::from_slice(&body).map_err(|error| format!("KernSight 响应 JSON 无效：{error}"))
    }

    async fn close(mut self) -> Result<(), String> {
        self.input.take();
        let status = timeout(Duration::from_secs(10), self.child.wait())
            .await
            .map_err(|_| "关闭 KernSight 协议超时".to_string())?
            .map_err(|error| error.to_string())?;
        if status.success() {
            Ok(())
        } else {
            Err(format!("KernSight ADB 协议进程异常退出：{status}"))
        }
    }
}

#[tauri::command]
pub async fn get_kernsight_overview(serial: String) -> Result<KernSightOverview, String> {
    let mut connection = KernSightConnection::connect(&serial).await?;
    let status_request = Uuid::new_v4();
    connection
        .send(&Message::GetStatus(GetStatus {
            request_id: status_request,
        }))
        .await?;
    let status = match connection.receive().await? {
        Message::AgentStatus(status) if status.request_id == status_request => status,
        Message::Ack(ack) if !ack.accepted => {
            return Err(ack
                .detail
                .unwrap_or_else(|| "KernSight 拒绝状态请求".into()));
        }
        message => return Err(format!("KernSight 状态响应不正确：{message:?}")),
    };
    let sessions_request = Uuid::new_v4();
    connection
        .send(&Message::ListSessions(ListSessions {
            request_id: sessions_request,
        }))
        .await?;
    let mut sessions = match connection.receive().await? {
        Message::SessionInventory(inventory) if inventory.request_id == sessions_request => {
            inventory.sessions
        }
        Message::Ack(ack) if !ack.accepted => {
            return Err(ack
                .detail
                .unwrap_or_else(|| "KernSight 拒绝会话清单请求".into()));
        }
        message => return Err(format!("KernSight 会话响应不正确：{message:?}")),
    };
    sessions.sort_by_key(|session| std::cmp::Reverse(session.started_unix_ms.unwrap_or(0)));
    let agent_version = connection.agent_version.clone();
    connection.close().await?;
    let build_command = format!("{KSIGHT_AGENT} code-capabilities");
    let (private_package_bytes, public_package_bytes, build_output) = tokio::join!(
        directory_bytes(&serial, KSIGHT_PACKAGES),
        directory_bytes(&serial, KSIGHT_PUBLIC_PACKAGES),
        timeout(
            Duration::from_secs(4),
            run_device_root_script(&serial, &build_command)
        )
    );
    let agent_build_identity = build_output
        .ok()
        .and_then(Result::ok)
        .and_then(|output| build_identity::parse(output.code, &output.stdout, &agent_version));
    Ok(KernSightOverview {
        agent_version,
        agent_build_identity,
        protocol_major: CURRENT_PROTOCOL.major,
        protocol_minor: CURRENT_PROTOCOL.minor,
        status,
        sessions,
        private_package_bytes: private_package_bytes.unwrap_or(0),
        public_package_bytes: public_package_bytes.unwrap_or(0),
    })
}

#[tauri::command]
pub async fn get_kernsight_session_report(
    serial: String,
    session_id: String,
) -> Result<KernSightSessionReport, String> {
    get_kernsight_session_report_scoped(serial, session_id, None).await
}
/// Parent-owned live report uses the same runtime selection; an old Me rejects this IPC.
#[tauri::command]
pub async fn get_kernsight_group_session_report(
    app: tauri::AppHandle,
    parent_id: Uuid,
    serial: String,
    package: String,
    session_id: String,
) -> Result<KernSightSessionReport, String> {
    let group = capture_groups::selected(&app, parent_id, &serial, &package)?;
    let id = Uuid::parse_str(&session_id).map_err(|e| e.to_string())?;
    if !group.session_ids().contains(&id) {
        return Err("子会话不属于所选parent".into());
    }
    let paths = runtime_paths_from_group(Some(&group))?;
    require_runtime_paths(&serial, paths.as_ref()).await?;
    get_kernsight_session_report_scoped(serial, session_id, paths.as_ref()).await
}
const LINKER_OBSERVATION_LIMIT: usize = 256;

#[derive(Default)]
struct LinkerObservations {
    rows: Vec<Value>,
    observed: u64,
}

fn bounded_linker_text(value: &str) -> String {
    value.chars().take(2048).collect()
}

impl LinkerObservations {
    fn record(&mut self, event: &Event) {
        let ksight_model::EventPayload::InspectObservation(observation) = &event.payload else {
            return;
        };
        if observation.adapter != "linker_so_load" || !observation.hit {
            return;
        }
        self.observed = self.observed.saturating_add(1);
        if self.rows.len() >= LINKER_OBSERVATION_LIMIT {
            return;
        }
        let process = &event.header.process;
        let text_truncated = [&observation.library, &observation.detail]
            .iter()
            .any(|value| value.chars().count() > 2048)
            || observation
                .path_hint
                .as_ref()
                .is_some_and(|value| value.chars().count() > 2048)
            || observation
                .build_id
                .as_ref()
                .is_some_and(|value| value.chars().count() > 2048);
        self.rows.push(serde_json::json!({
            "session_id": event.header.session_id,
            "source_sequence": event.header.source_sequence.to_string(),
            "monotonic_ns": event.header.monotonic_ns.to_string(),
            "pid": process.key.pid,
            "tid": process.tid,
            "boot_id": process.key.boot_id,
            "header_birth_ns": (process.key.start_time_ns != 0).then(|| process.key.start_time_ns.to_string()),
            "birth_status": if process.key.start_time_ns == 0 { "unknown" } else { "header-observed" },
            "library": bounded_linker_text(&observation.library),
            "build_id": observation.build_id.as_deref().map(bounded_linker_text),
            "offset": observation.offset.map(|value| value.to_string()),
            "path_hint": observation.path_hint.as_deref().map(bounded_linker_text),
            "detail": bounded_linker_text(&observation.detail),
            "text_truncated": text_truncated,
        }));
    }

    fn augment(self, report: &mut Value) {
        if let Some(object) = report.as_object_mut() {
            object.insert("linker_observations".into(), Value::Array(self.rows));
            object.insert("linker_observations_observed".into(), self.observed.into());
            object.insert(
                "linker_observations_limit".into(),
                LINKER_OBSERVATION_LIMIT.into(),
            );
            object.insert(
                "linker_observations_omitted".into(),
                self.observed
                    .saturating_sub(LINKER_OBSERVATION_LIMIT as u64)
                    .into(),
            );
        }
    }
}

async fn get_kernsight_session_report_scoped(
    serial: String,
    session_id: String,
    paths: Option<&runtime_paths::RuntimePaths>,
) -> Result<KernSightSessionReport, String> {
    let session_id = Uuid::parse_str(&session_id)
        .map_err(|error| format!("KernSight session UUID 无效：{error}"))?;
    let mut connection = KernSightConnection::connect_scoped(&serial, paths).await?;
    let request_id = Uuid::new_v4();
    connection
        .send(&Message::ReplayBatches(ReplayBatches {
            request_id,
            session_id,
            after_batch_sequence: None,
        }))
        .await?;
    let mut builder = SessionReportBuilder::default();
    let mut linker = LinkerObservations::default();
    let mut perf_loss = perf_loss::PerfLoss::default();
    loop {
        match connection.receive().await? {
            Message::EventBatch(batch) if batch.session_id == session_id => {
                for event in &batch.events {
                    builder.record(event);
                    linker.record(event);
                    perf_loss.record(event);
                }
            }
            Message::ReplayComplete(complete)
                if complete.request_id == request_id && complete.session_id == session_id =>
            {
                break;
            }
            Message::Ack(ack) if !ack.accepted => {
                return Err(ack
                    .detail
                    .unwrap_or_else(|| "KernSight 拒绝报告请求".into()));
            }
            message => return Err(format!("KernSight 报告流响应不正确：{message:?}")),
        }
    }
    connection.close().await?;
    let mut report = builder.finish();
    compact_session_report_for_ui(&mut report);
    let mut report = serde_json::to_value(report).map_err(|error| error.to_string())?;
    linker.augment(&mut report);
    perf_loss.augment(&mut report);
    Ok(KernSightSessionReport {
        session_id,
        report_schema: "mobilee.kernsight-session-report/v1".into(),
        report,
    })
}

#[tauri::command]
pub async fn cleanup_kernsight_session(serial: String, session_id: String) -> Result<(), String> {
    validate_serial(&serial)?;
    let session_id = Uuid::parse_str(&session_id)
        .map_err(|error| format!("KernSight session UUID 无效：{error}"))?;
    let _ = session_id;
    Err(
        "旧版直接删除已停用：请使用父会话的永久清理预览并明确确认；无归属证明的旧 session 保留"
            .into(),
    )
}

/// A new IPC command keeps an old backend from silently ignoring the new field.
#[tauri::command]
pub async fn start_kernsight_staged_capture(
    request: KernSightCaptureRequest,
) -> Result<KernSightCaptureResult, String> {
    if request.inspect_stages.is_none() {
        return Err("统一会话缺少阶段计划".into());
    }
    start_kernsight_capture(request).await
}

fn capture_launch_command(
    mut command: String,
    code_only: bool,
    launch: bool,
    has_relation: bool,
    hide_debug: bool,
    package: Option<&str>,
) -> Result<String, String> {
    if !launch {
        return Ok(command);
    }
    let package = package.ok_or("启动采集必须选择一个包")?;
    if has_relation {
        if hide_debug {
            return Err("parent 启动要求关闭 hide-debug".into());
        }
        command.push_str(" --launch-after-attach");
    } else if code_only {
        return Err("code-only 启动要求 parent attempt lease".into());
    } else {
        command = format!("am force-stop {package}; (sleep 2; monkey -p {package} -c android.intent.category.LAUNCHER 1 >/dev/null 2>&1) & {command}");
    }
    Ok(command)
}

#[tauri::command]
pub async fn start_kernsight_capture(
    request: KernSightCaptureRequest,
) -> Result<KernSightCaptureResult, String> {
    validate_serial(&request.serial)?;
    require_runtime_paths(&request.serial, request.runtime_paths.as_ref()).await?;
    if request.runtime_paths.is_some()
        && (request.capture_relation.is_none()
            || request.hide_debug
            || request.mirror_burp.is_some())
    {
        return Err("隔离模式仅支持父会话，关闭hide-debug/mirror".into());
    }
    capture_launch_command(
        String::new(),
        request.code_only,
        request.launch_after_attach,
        request.capture_relation.is_some(),
        request.hide_debug,
        request.package.as_deref(),
    )?;
    let stages = request.inspect_stages.as_deref();
    stage_policy::validate_mode(
        stages,
        request.duration_seconds,
        request
            .package
            .as_deref()
            .is_some_and(|p| !p.trim().is_empty()),
        request.inspect_tls
            || request.inspect_jni
            || request.inspect_linker
            || request.inspect_adapter.is_some()
            || request.mirror_burp.is_some(),
    )?;
    if request.code_only {
        require_code_scope_capability(&request.serial, request.runtime_paths.as_ref()).await?;
        let help = run_device_root_script(
            &request.serial,
            &runtime_paths::route(
                request.runtime_paths.as_ref(),
                &format!("{KSIGHT_AGENT} capture --help"),
            )?,
        )
        .await?;
        if help.code != Some(0)
            || !help.stdout.contains("--code-only")
            || !help.stdout.contains("--output-budget-bytes")
            || (request.launch_after_attach && !help.stdout.contains("--launch-after-attach"))
        {
            return Err("设备 agent 缺明确范围/输出预算能力，未启动；不降级为旧宽采集".into());
        }
    }
    if let Some(r) = request.capture_relation.as_ref() {
        require_parent_lifecycle_capability(&request.serial, request.runtime_paths.as_ref())
            .await?;
        if request.hide_debug
            || request.collect_keys
            || request.collect_memory_windows
            || request.collect_private
        {
            return Err(
                "此 parent 生命周期暂不支持 hide-debug/独立额外采集；普通阶段可单独运行".into(),
            );
        }
        if r.parent_id.is_nil()
            || r.stage_id.is_nil()
            || r.attempt_id.is_nil()
            || r.attempt == 0
            || !["l0", "l1", "linker"].contains(&r.stage_key.as_str())
        {
            return Err("无效阶段关联参数".into());
        }
        let help = run_device_root_script(
            &request.serial,
            &runtime_paths::route(
                request.runtime_paths.as_ref(),
                &format!("{KSIGHT_AGENT} capture --help"),
            )?,
        )
        .await?;
        if help.code != Some(0)
            || !help.stdout.contains("--parent-session")
            || (request.launch_after_attach && !help.stdout.contains("--launch-after-attach"))
        {
            return Err("设备 agent 不支持父子会话；未启动，不降级混入旧会话".into());
        }
    }
    if request.sample_one_in == 0 || request.sample_one_in > 10_000 {
        return Err("采样倍率必须在 1 到 10000 之间".into());
    }
    if request.inspect_max_bytes == 0 || request.inspect_max_bytes > MAX_INSPECT_PLAINTEXT_BYTES {
        return Err(format!(
            "Inspect 单次明文上限必须在 1 到 {MAX_INSPECT_PLAINTEXT_BYTES} 字节之间"
        ));
    }
    let inspect_adapter = request
        .inspect_adapter
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());
    if inspect_adapter.is_some_and(|value| value != "binder_userspace") {
        return Err(
            "MobileE 当前只开放 binder_userspace 命名 Inspect adapter；JNI 请用 inspectJni".into(),
        );
    }
    if request.inspect_linker
        && (request.inspect_tls || request.inspect_jni || inspect_adapter.is_some())
    {
        return Err("Linker SO Inspect 需要独立会话；TLS、JNI 与 Binder userspace 可以组合".into());
    }
    let package = request
        .package
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());
    if let Some(package) = package {
        validate_package(package)?;
    }
    let mirror_burp = request
        .mirror_burp
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let mirror = match mirror_burp {
        Some(value) => Some(parse_mirror_burp(value)?),
        None => None,
    };
    let inspect_tls = request.inspect_tls || mirror.is_some();
    if (inspect_tls
        || request.inspect_jni
        || request.inspect_linker
        || inspect_adapter.is_some()
        || request.sched)
        && package.is_none()
    {
        return Err("TLS、JNI、Binder userspace、Linker、Burp mirror 或调度语义采集必须选择一个包，避免无边界的全设备 Inspect".into());
    }
    if stages.is_some() {
        // Capability check is read-only and precedes any force-stop or capture.
        let help = run_device_root_script(
            &request.serial,
            &runtime_paths::route(
                request.runtime_paths.as_ref(),
                &format!("{KSIGHT_AGENT} capture --help"),
            )?,
        )
        .await?;
        if help.code != Some(0) || !help.stdout.contains("--inspect-stages") {
            return Err("设备 ksightd 未证明支持 --inspect-stages；统一会话未启动。可显式选择旧版启动重采模式，不能静默降级".into());
        }
    }
    if mirror.is_some() {
        let forward =
            crate::run_device_adb(&request.serial, &["forward", "tcp:18081", "tcp:18081"]).await?;
        if forward.code.is_some_and(|code| code != 0) {
            return Err(format!(
                "adb forward tcp:18081 失败：{}",
                if forward.stderr.is_empty() {
                    forward.stdout
                } else {
                    forward.stderr
                }
            ));
        }
    }
    if let Some((_, port)) = &mirror {
        if request.mirror_via_adb {
            let reverse = crate::run_device_adb(
                &request.serial,
                &["reverse", &format!("tcp:{port}"), &format!("tcp:{port}")],
            )
            .await?;
            if reverse.code.is_some_and(|code| code != 0) {
                return Err(format!(
                    "adb reverse tcp:{port} 失败：{}",
                    if reverse.stderr.is_empty() {
                        reverse.stdout
                    } else {
                        reverse.stderr
                    }
                ));
            }
            let forward =
                crate::run_device_adb(&request.serial, &["forward", "tcp:18081", "tcp:18081"])
                    .await?;
            if forward.code.is_some_and(|code| code != 0) {
                return Err(format!(
                    "adb forward tcp:18081 失败：{}",
                    if forward.stderr.is_empty() {
                        forward.stdout
                    } else {
                        forward.stderr
                    }
                ));
            }
        }
    }

    let mut args = vec![
        format!("{KSIGHT_AGENT} capture"),
        "--object /data/local/tmp/ksight/process_lifecycle.bpf.o".into(),
        "--file-object /data/local/tmp/ksight/file_open.bpf.o".into(),
        "--network-object /data/local/tmp/ksight/network_connect.bpf.o".into(),
        "--memory-object /data/local/tmp/ksight/memory_regions.bpf.o".into(),
        "--binder-object /data/local/tmp/ksight/binder_transaction.bpf.o".into(),
        "--sched-object /data/local/tmp/ksight/sched_wakeup.bpf.o".into(),
        "--uprobe-object /data/local/tmp/ksight/uprobe_regs.bpf.o".into(),
        format!("--duration-seconds {}", request.duration_seconds),
        format!("--sample-one-in {}", request.sample_one_in),
        "--spool-dir /data/local/tmp/ksight/spool".into(),
        "--spool-max-mib 64".into(),
        "--batch-events 64".into(),
        "--quiet".into(),
    ];
    if request.code_only {
        args.push("--code-only".into());
    }
    if request.collect_keys {
        args.push("--collect-keys".into());
    }
    if request.collect_memory_windows {
        args.push("--collect-memory-windows".into());
    }
    match (request.output_budget_bytes, request.output_budget_ms) {
        (Some(n), Some(t)) => args.push(format!(
            "--output-budget-bytes {n} --output-budget-ms {}",
            session_deadline::remaining_ms(t)?
        )),
        (None, None) => {}
        _ => return Err("写盘预算缺字节/期限".into()),
    }
    if let Some(r) = request.capture_relation.as_ref() {
        args.push(format!(
            "--parent-session {} --stage-id {} --stage-attempt {} --attempt-id {} --stage-key {}",
            r.parent_id, r.stage_id, r.attempt, r.attempt_id, r.stage_key
        ));
    }
    if let Some(links) = request.capture_relations.as_ref() {
        let Some(primary) = request.capture_relation.as_ref() else {
            return Err("stage links 缺主关联".into());
        };
        if links.len() != 3
            || request.inspect_stages.is_none()
            || links.iter().any(|r| {
                r.parent_id != primary.parent_id
                    || r.attempt == 0
                    || !["l0", "l1", "linker"].contains(&r.stage_key.as_str())
            })
            || links
                .iter()
                .map(|r| &r.stage_key)
                .collect::<BTreeSet<_>>()
                .len()
                != 3
        {
            return Err("无效 stage links".into());
        }
        let help = run_device_root_script(
            &request.serial,
            &runtime_paths::route(
                request.runtime_paths.as_ref(),
                &format!("{KSIGHT_AGENT} capture --help"),
            )?,
        )
        .await?;
        if help.code != Some(0) || !help.stdout.contains("--stage-links") {
            return Err("设备不支持统一阶段父子合同；未启动，不降级".into());
        }
        args.push(format!(
            "--stage-links {}",
            crate::shell_quote(&serde_json::to_string(links).map_err(|e| e.to_string())?)
        ));
    }
    for (enabled, flag) in [
        (request.files, "--files"),
        (request.files_fd, "--files-fd"),
        (request.network, "--network"),
        (request.network_io, "--network-io"),
        (request.memory, "--memory"),
        (request.memory_all, "--memory-all"),
        (request.binder, "--binder"),
        (request.sched, "--sched"),
        (request.include_threads, "--include-threads"),
        (inspect_tls, "--inspect-tls"),
        (request.inspect_jni, "--inspect-jni"),
        (request.inspect_linker, "--inspect-linker"),
    ] {
        if enabled {
            args.push(flag.into());
        }
    }
    if let Some(package) = package {
        args.push(format!("--package {package}"));
    }
    if let Some(adapter) = inspect_adapter {
        args.push(format!("--inspect-adapter {adapter}"));
    }
    if let Some(text) = stages {
        args.push(format!("--inspect-stages {text}"));
        args.push(format!("--inspect-max-bytes {}", request.inspect_max_bytes));
        args.push(format!("--inspect-max-hits {}", request.inspect_max_hits));
    }
    if inspect_tls || request.inspect_jni || request.inspect_linker || inspect_adapter.is_some() {
        args.push(format!("--inspect-max-secs {}", request.duration_seconds));
        args.push(format!("--inspect-max-bytes {}", request.inspect_max_bytes));
        args.push(format!("--inspect-max-hits {}", request.inspect_max_hits));
    }
    if let Some((host, port)) = &mirror {
        let target = if request.mirror_via_adb {
            format!("127.0.0.1:{port}")
        } else {
            format!("{host}:{port}")
        };
        args.push(format!("--mirror-burp {target}"));
    }
    let capture_command = capture_launch_command(
        args.join(" "),
        request.code_only,
        request.launch_after_attach,
        request.capture_relation.is_some(),
        request.hide_debug,
        package,
    )?;
    let capture_command = runtime_paths::route(request.runtime_paths.as_ref(), &capture_command)?;
    let command_preview = capture_command.replace(KSIGHT_AGENT, "ksightd");
    let started_unix_ms = now_millis();

    let (stdout, stderr, exit_code) = if request.hide_debug {
        let wrapped = format!(
            "{KSIGHT_HIDE_DEBUG} {} {capture_command}",
            request.duration_seconds
        );
        let remote = format!("su -c {}", crate::shell_quote(&wrapped));
        let mut command = Command::new("adb");
        command.args(["-s", &request.serial, "shell", &remote]);
        let output = session_deadline::output(
            &mut command,
            Duration::from_secs(request.duration_seconds.saturating_add(30)),
        )
        .await?;
        wait_for_adb_return(&request.serial, request.duration_seconds.saturating_add(25)).await?;
        let log = run_device_root_script(&request.serial, &format!("cat {KSIGHT_CAPTURE_LOG}"))
            .await
            .ok()
            .map_or_else(String::new, |value| value.stdout);
        (
            log,
            String::from_utf8_lossy(&output.stderr).trim().to_string(),
            output.status.code(),
        )
    } else {
        let remote = format!("su -c {}", crate::shell_quote(&capture_command));
        let capture_timeout = Duration::from_secs(request.duration_seconds.saturating_add(30));
        let mut command = Command::new("adb");
        command.args(["-s", &request.serial, "shell", &remote]);
        let output = session_deadline::output(&mut command, capture_timeout).await?;
        (
            String::from_utf8_lossy(&output.stdout).trim().to_string(),
            String::from_utf8_lossy(&output.stderr).trim().to_string(),
            output.status.code(),
        )
    };
    let mut session_id = extract_session_id(&format!("{stdout}\n{stderr}"));
    // Keep the legacy bridge fallback; parent captures must never guess identity.
    if request.capture_relation.is_none() && session_id.is_none() {
        session_id = read_last_session_id(&request.serial).await;
    }
    if session_id.is_none() {
        return Err(format!(
            "采集命令结束但没有生成 session id。stdout={stdout} stderr={stderr}"
        ));
    }
    Ok(KernSightCaptureResult {
        session_id,
        started_unix_ms,
        finished_unix_ms: now_millis(),
        command_preview,
        stdout,
        stderr,
        exit_code,
        hide_debug: request.hide_debug,
    })
}

fn parse_device_mirror_process_status(output: &str) -> DeviceMirrorProcessStatus {
    let values = parse_probe_output(output);
    DeviceMirrorProcessStatus {
        capture_count: values
            .get("capture_count")
            .and_then(|value| value.parse().ok())
            .unwrap_or(0),
        pcap_count: values
            .get("pcap_count")
            .and_then(|value| value.parse().ok())
            .unwrap_or(0),
    }
}

async fn mirror_root_command(
    serial: &str,
    script: &str,
    limit: Duration,
    operation: &str,
) -> Result<crate::RawOutput, String> {
    timeout(limit, run_device_root_script(serial, script))
        .await
        .map_err(|_| format!("{operation}超时（{} 秒）", limit.as_secs()))?
}

async fn mirror_adb_command(
    serial: &str,
    tail: &[&str],
    operation: &str,
) -> Result<crate::RawOutput, String> {
    timeout(MIRROR_CONTROL_TIMEOUT, run_device_adb(serial, tail))
        .await
        .map_err(|_| format!("{operation}超时（{} 秒）", MIRROR_CONTROL_TIMEOUT.as_secs()))?
}

async fn device_mirror_process_status(serial: &str) -> Result<DeviceMirrorProcessStatus, String> {
    let output = mirror_root_command(
        serial,
        DEVICE_MIRROR_PROCESS_STATUS,
        MIRROR_STATUS_TIMEOUT,
        "检查设备采集进程",
    )
    .await?;
    if output.code != Some(0) {
        return Err(format!(
            "无法检查设备端镜像进程：{}",
            if output.stderr.is_empty() {
                output.stdout
            } else {
                output.stderr
            }
        ));
    }
    Ok(parse_device_mirror_process_status(&output.stdout))
}

async fn stop_device_capture(serial: &str) -> Result<DeviceMirrorProcessStatus, String> {
    let graceful = mirror_root_command(
        serial,
        STOP_KSIGHTD_CAPTURE,
        MIRROR_STOP_TIMEOUT,
        "停止设备采集进程",
    )
    .await;
    let graceful_status = graceful.as_ref().ok().and_then(|output| {
        (output.code == Some(0)).then(|| parse_device_mirror_process_status(&output.stdout))
    });
    let requires_force = graceful_status
        .as_ref()
        .is_none_or(|status| status.capture_count != 0 || status.pcap_count != 0);
    let status = if requires_force {
        let forced = mirror_root_command(
            serial,
            FORCE_STOP_KSIGHTD_CAPTURE,
            MIRROR_CONTROL_TIMEOUT,
            "强制清理设备采集进程",
        )
        .await?;
        if forced.code != Some(0) {
            return Err(format!(
                "强制清理设备采集进程失败：{}",
                if forced.stderr.is_empty() {
                    forced.stdout
                } else {
                    forced.stderr
                }
            ));
        }
        parse_device_mirror_process_status(&forced.stdout)
    } else {
        graceful_status.unwrap_or_default()
    };

    // New agents expose an explicit repair operation. Older agents reject it;
    // process cleanup still succeeds and the next compatible agent startup repairs the manifest.
    let _ = mirror_root_command(
        serial,
        &format!("{KSIGHT_AGENT} spool --root {KSIGHT_SPOOL} repair"),
        MIRROR_CONTROL_TIMEOUT,
        "修复会话状态",
    )
    .await;
    Ok(status)
}

async fn stop_mirror_child(
    state: &MirrorSessionState,
    fallback_serial: Option<&str>,
    fallback_reverse_port: Option<u16>,
) -> Result<(), String> {
    let mut cleanup_error = None;
    let serial = state
        .serial
        .lock()
        .await
        .clone()
        .or_else(|| fallback_serial.map(str::to_owned));
    if let Some(serial) = serial.as_deref() {
        // Stop the device collector before its host-side adb transport. This
        // allows the signal handler to reap tcpdump and seal session.json.
        if let Err(error) = stop_device_capture(serial).await {
            cleanup_error = Some(error);
        }
        let _ = mirror_adb_command(
            serial,
            &["forward", "--remove", "tcp:18081"],
            "清理回放端口",
        )
        .await;
        let reverse_port = state
            .reverse_port
            .lock()
            .await
            .take()
            .or(fallback_reverse_port);
        if let Some(port) = reverse_port {
            let remote = format!("tcp:{port}");
            let _ =
                mirror_adb_command(serial, &["reverse", "--remove", &remote], "清理反向端口").await;
        }
    }
    if let Some(mut child) = state.child.lock().await.take() {
        match timeout(Duration::from_secs(2), child.wait()).await {
            Ok(_) => {}
            Err(_) => {
                let _ = child.start_kill();
                let _ = timeout(Duration::from_secs(2), child.wait()).await;
            }
        }
    }
    *state.serial.lock().await = None;
    *state.package.lock().await = None;
    *state.reverse_port.lock().await = None;
    cleanup_error.map_or(Ok(()), Err)
}

#[tauri::command]
pub async fn start_kernsight_mirror(
    state: State<'_, MirrorSessionState>,
    request: KernSightCaptureRequest,
) -> Result<KernSightCaptureResult, String> {
    let _operation = state.operation.lock().await;
    if let Some(child) = state.child.lock().await.as_mut() {
        if child
            .try_wait()
            .map_err(|error| format!("无法确认镜像状态：{error}"))?
            .is_none()
        {
            return Err("镜像任务正在运行，请先停止当前任务".into());
        }
    }
    validate_serial(&request.serial)?;
    let package = request
        .package
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or("镜像必须选择一个包")?;
    validate_package(package)?;
    let mirror = parse_mirror_burp(
        request
            .mirror_burp
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or("必须指定 Burp host:port")?,
    )?;
    stop_mirror_child(
        &state,
        Some(&request.serial),
        request.mirror_via_adb.then_some(mirror.1),
    )
    .await?;
    {
        let mut logs = state.logs.lock().await;
        logs.clear();
        logs.push_back("正在建立设备采集进程并校验运行状态…".to_owned());
    }

    let forward = mirror_adb_command(
        &request.serial,
        &["forward", "tcp:18081", "tcp:18081"],
        "建立回放端口",
    )
    .await?;
    if forward.code.is_some_and(|code| code != 0) {
        return Err(format!(
            "adb forward tcp:18081 失败：{}",
            if forward.stderr.is_empty() {
                forward.stdout
            } else {
                forward.stderr
            }
        ));
    }
    if request.mirror_via_adb {
        let port = mirror.1;
        let reverse = mirror_adb_command(
            &request.serial,
            &["reverse", &format!("tcp:{port}"), &format!("tcp:{port}")],
            "建立反向端口",
        )
        .await?;
        if reverse.code.is_some_and(|code| code != 0) {
            return Err(format!(
                "adb reverse tcp:{port} 失败：{}",
                if reverse.stderr.is_empty() {
                    reverse.stdout
                } else {
                    reverse.stderr
                }
            ));
        }
    }
    let burp = if request.mirror_via_adb {
        format!("127.0.0.1:{}", mirror.1)
    } else {
        format!("{}:{}", mirror.0, mirror.1)
    };
    let mut capture_command = format!(
        "{KSIGHT_AGENT} capture --object /data/local/tmp/ksight/process_lifecycle.bpf.o --file-object /data/local/tmp/ksight/file_open.bpf.o --network-object /data/local/tmp/ksight/network_connect.bpf.o --memory-object /data/local/tmp/ksight/memory_regions.bpf.o --binder-object /data/local/tmp/ksight/binder_transaction.bpf.o --sched-object /data/local/tmp/ksight/sched_wakeup.bpf.o --uprobe-object /data/local/tmp/ksight/uprobe_regs.bpf.o --duration-seconds 0 --sample-one-in 1 --spool-dir /data/local/tmp/ksight/spool --spool-max-mib 64 --batch-events 64 --quiet --package {package} --inspect-max-bytes {MAX_INSPECT_PLAINTEXT_BYTES} --mirror-burp {burp}"
    );
    if request.launch_after_attach {
        capture_command = format!(
            "am force-stop {package}; (sleep 2; monkey -p {package} -c android.intent.category.LAUNCHER 1 >/dev/null 2>&1) & {capture_command}"
        );
    }
    let command_preview = capture_command.replace(KSIGHT_AGENT, "ksightd");
    let remote = format!("su -c {}", crate::shell_quote(&capture_command));
    let mut child = Command::new("adb")
        .args(["-s", &request.serial, "shell", &remote])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(false)
        .spawn()
        .map_err(|error| format!("无法启动镜像采集：{error}"))?;
    if let Some(stdout) = child.stdout.take() {
        collect_mirror_logs(stdout, Arc::clone(&state.logs));
    }
    if let Some(stderr) = child.stderr.take() {
        collect_mirror_logs(stderr, Arc::clone(&state.logs));
    }

    // `spawn()` only proves that adb itself started. Do not announce RUNNING
    // until the device-side collector is visible; this also detects a blocked
    // root prompt or an adb shell that stays alive after the command failed.
    let startup_deadline = Instant::now() + Duration::from_secs(6);
    let startup_failure = loop {
        if let Some(status) = child
            .try_wait()
            .map_err(|error| format!("无法确认镜像启动状态：{error}"))?
        {
            break Some(format!("adb shell: {status}"));
        }
        match device_mirror_process_status(&request.serial).await {
            Ok(status) if status.capture_count > 0 => break None,
            Ok(_) => {}
            Err(error) => {
                if Instant::now() >= startup_deadline {
                    break Some(format!("无法确认设备进程：{error}"));
                }
            }
        }
        if Instant::now() >= startup_deadline {
            break Some("6 秒内未发现设备端采集进程".to_owned());
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    };
    if let Some(reason) = startup_failure {
        let _ = child.start_kill();
        let _ = timeout(Duration::from_secs(2), child.wait()).await;
        tokio::time::sleep(Duration::from_millis(50)).await;
        let lines = state
            .logs
            .lock()
            .await
            .iter()
            .rev()
            .take(12)
            .cloned()
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect::<Vec<_>>();
        let _ = mirror_adb_command(
            &request.serial,
            &["forward", "--remove", "tcp:18081"],
            "清理回放端口",
        )
        .await;
        if request.mirror_via_adb {
            let remote = format!("tcp:{}", mirror.1);
            let _ = mirror_adb_command(
                &request.serial,
                &["reverse", "--remove", &remote],
                "清理反向端口",
            )
            .await;
        }
        let detail = if lines.is_empty() {
            "设备进程未输出诊断信息".to_owned()
        } else {
            lines.join("\n")
        };
        return Err(format!("镜像采集启动失败（{reason}）\n{detail}"));
    }
    *state.child.lock().await = Some(child);
    *state.serial.lock().await = Some(request.serial.clone());
    *state.package.lock().await = Some(package.to_owned());
    *state.reverse_port.lock().await = request.mirror_via_adb.then_some(mirror.1);
    Ok(KernSightCaptureResult {
        session_id: None,
        started_unix_ms: now_millis(),
        finished_unix_ms: now_millis(),
        command_preview,
        stdout: format!("镜像已启动 {package} → {burp}，无时长上限。点停止后再关。"),
        stderr: String::new(),
        exit_code: None,
        hide_debug: false,
    })
}

#[tauri::command]
pub async fn stop_kernsight_mirror(
    state: State<'_, MirrorSessionState>,
    serial: Option<String>,
    reverse_port: Option<u16>,
) -> Result<KernSightMirrorStatus, String> {
    let _operation = state.operation.lock().await;
    if let Some(value) = serial.as_deref() {
        validate_serial(value)?;
    }
    stop_mirror_child(&state, serial.as_deref(), reverse_port).await?;
    let (logs, coverage) = {
        let stored = state.logs.lock().await;
        (
            stored.iter().cloned().collect(),
            mirror_coverage_from_logs(&stored, false),
        )
    };
    Ok(KernSightMirrorStatus {
        running: false,
        cleanup_pending: false,
        package: None,
        serial: None,
        detail: Some("设备端 ksightd、KernSight pcap 子进程与会话状态已完成清理".into()),
        logs,
        coverage,
    })
}

#[tauri::command]
pub async fn kernsight_mirror_status(
    state: State<'_, MirrorSessionState>,
    serial: Option<String>,
) -> Result<KernSightMirrorStatus, String> {
    if let Some(value) = serial.as_deref() {
        validate_serial(value)?;
    }
    let mut host_running = false;
    {
        let mut child = state.child.lock().await;
        if let Some(handle) = child.as_mut() {
            match handle.try_wait() {
                Ok(None) => host_running = true,
                Ok(Some(_)) | Err(_) => {
                    *child = None;
                }
            }
        }
    }
    let known_serial = state.serial.lock().await.clone().or_else(|| serial.clone());
    let device = if let Some(value) = known_serial.as_deref() {
        Some(device_mirror_process_status(value).await?)
    } else {
        None
    };
    let device_running = device
        .as_ref()
        .is_some_and(|status| status.capture_count > 0);
    let cleanup_pending = device
        .as_ref()
        .is_some_and(|status| status.pcap_count > 0 && status.capture_count == 0);
    let running = host_running || device_running;
    if !running && !cleanup_pending {
        *state.serial.lock().await = None;
        *state.package.lock().await = None;
    }
    let detail = device.as_ref().map(|status| {
        format!(
            "host_adb={} ksightd={} kernsight_tcpdump={}",
            u8::from(host_running),
            status.capture_count,
            status.pcap_count
        )
    });
    let package = state.package.lock().await.clone();
    let (logs, coverage) = {
        let stored = state.logs.lock().await;
        (
            stored.iter().cloned().collect(),
            mirror_coverage_from_logs(&stored, running),
        )
    };
    Ok(KernSightMirrorStatus {
        running,
        cleanup_pending,
        package,
        serial: known_serial,
        detail,
        logs,
        coverage,
    })
}

#[tauri::command]
pub async fn dump_kernsight_package(
    serial: String,
    package: String,
    hide_debug: bool,
    prefer_live: bool,
    require_live: Option<bool>,
) -> Result<KernSightCaptureResult, String> {
    dump_kernsight_package_scoped(
        serial,
        package,
        hide_debug,
        prefer_live,
        require_live,
        None,
        None,
    )
    .await
}
async fn dump_kernsight_package_scoped(
    serial: String,
    package: String,
    hide_debug: bool,
    prefer_live: bool,
    require_live: Option<bool>,
    relation: Option<capture_groups::Relation>,
    scope: Option<&KernSightCaptureRequest>,
) -> Result<KernSightCaptureResult, String> {
    let preflight_started = std::time::Instant::now();
    let paths = scope.and_then(|s| s.runtime_paths.as_ref());
    require_runtime_paths(&serial, paths).await?;
    validate_serial(&serial)?;
    validate_package(&package)?;
    if relation.is_some() {
        require_parent_lifecycle_capability(&serial, paths).await?;
    }
    if scope.is_some_and(|s| s.code_only) {
        require_code_scope_capability(&serial, paths).await?;
    }
    let remote = relation.as_ref().map_or_else(
        || format!("{KSIGHT_PACKAGES}/{package}"),
        |r| {
            format!(
                "/data/local/tmp/ksight/captures/{}/{}/{}/dump",
                r.parent_id, r.stage_id, r.attempt_id
            )
        },
    );
    let live = if prefer_live {
        run_device_root_script(&serial, &format!("pidof {package}"))
            .await
            .is_ok_and(|output| dump_policy::live_pid_confirmed(output.code, &output.stdout))
    } else {
        false
    };
    // Decide before removing the previous dump directory or launching anything.
    let launch_flag =
        dump_policy::dump_launch_flag(prefer_live, require_live.unwrap_or(false), live)?;
    if relation.is_some() {
        let help = run_device_root_script(
            &serial,
            &runtime_paths::route(paths, &format!("{KSIGHT_AGENT} dump-package --help"))?,
        )
        .await?;
        if help.code != Some(0)
            || !help.stdout.contains("--parent-session")
            || (scope.is_some_and(|r| r.code_only)
                && (!help.stdout.contains("--code-only")
                    || !help.stdout.contains("--output-budget-bytes")))
        {
            return Err("设备 dump 不支持父子会话；未启动".into());
        }
    }
    let prefix = if relation.is_some() {
        format!("test ! -e {remote} && mkdir -p {remote}")
    } else {
        format!("rm -rf {remote} && mkdir -p {remote}")
    };
    let mut dump = format!(
        "{prefix} && {KSIGHT_AGENT} dump-package --package {package} --dest {remote}{launch_flag}"
    );
    if let Some(r) = relation.as_ref() {
        dump.push_str(&format!(" --parent-session {} --stage-id {} --stage-attempt {} --attempt-id {} --stage-key dump",r.parent_id,r.stage_id,r.attempt,r.attempt_id));
    }
    if let Some(s) = scope {
        if relation.is_some() {
            let sources = s
                .expected_code_sources
                .as_ref()
                .ok_or("前一阶段具体实例资格缺失；不按 pidof 推测 dump 来源")?;
            dump.push_str(&format!(
                " --expected-code-sources {}",
                crate::shell_quote(&serde_json::to_string(sources).map_err(|e| e.to_string())?)
            ));
        }
        if s.code_only {
            dump.push_str(" --code-only");
        }
        if s.collect_keys {
            dump.push_str(" --collect-keys");
        }
        if s.collect_private {
            dump.push_str(" --collect-private");
        }
        if s.collect_memory_windows {
            dump.push_str(" --collect-memory-windows");
        }
        if let (Some(n), Some(t)) = (s.output_budget_bytes, s.output_budget_ms) {
            dump.push_str(&format!(
                " --output-budget-bytes {n} --output-budget-ms {}",
                dump_policy::producer_time_ms(
                    session_deadline::remaining_ms(t)?,
                    preflight_started
                        .elapsed()
                        .as_millis()
                        .min(u64::MAX as u128) as u64,
                )?
            ));
        }
    }
    if hide_debug {
        dump.push_str(" --hide-debug");
    }
    let command_preview = format!(
        "ksightctl device --serial {serial} pull-package --package {package}{launch_flag} --dest packages{}",
        if hide_debug { " --hide-debug" } else { "" }
    );
    let started_unix_ms = now_millis();
    let dump = runtime_paths::route(paths, &dump)?;
    let remote_shell = crate::root_shell_command(&dump);
    let mut command = Command::new("adb");
    command.args(["-s", &serial, "shell", &remote_shell]);
    let output = session_deadline::output(&mut command, Duration::from_secs(600)).await?;
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    if !output.status.success() && relation.is_none() {
        return Err(format!("dump-package 失败：{stderr}{stdout}"));
    }
    Ok(KernSightCaptureResult {
        session_id: None,
        started_unix_ms,
        finished_unix_ms: now_millis(),
        command_preview,
        stdout,
        stderr,
        exit_code: output.status.code(),
        hide_debug,
    })
}

#[tauri::command]
pub async fn get_kernsight_session_events(
    serial: String,
    session_id: String,
    offset: usize,
    limit: usize,
    sensor: Option<String>,
    query: Option<String>,
) -> Result<KernSightEventPage, String> {
    if limit == 0 || limit > 200 {
        return Err("事件分页大小必须在 1 到 200 之间".into());
    }
    let session_id = Uuid::parse_str(&session_id)
        .map_err(|error| format!("KernSight session UUID 无效：{error}"))?;
    let sensor = sensor
        .map(|value| value.trim().to_ascii_lowercase())
        .filter(|value| !value.is_empty() && value != "all");
    let query = query
        .map(|value| value.trim().to_ascii_lowercase())
        .filter(|value| !value.is_empty());
    let events = replay_session_events(&serial, session_id).await?;
    let mut type_counts = BTreeMap::new();
    let mut matches = Vec::new();
    for event in events {
        let value = serde_json::to_value(&event).map_err(|error| error.to_string())?;
        let event_sensor = value
            .pointer("/header/sensor")
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        if sensor
            .as_deref()
            .is_some_and(|wanted| wanted != event_sensor)
        {
            continue;
        }
        if query.as_deref().is_some_and(|needle| {
            !serde_json::to_string(&value)
                .unwrap_or_default()
                .to_ascii_lowercase()
                .contains(needle)
        }) {
            continue;
        }
        let event_type = value
            .pointer("/payload/type")
            .and_then(Value::as_str)
            .unwrap_or("unknown")
            .to_owned();
        *type_counts.entry(event_type).or_insert(0) += 1;
        matches.push(value);
    }
    let total_matches = matches.len();
    let events = matches.into_iter().skip(offset).take(limit).collect();
    let next = offset.saturating_add(limit);
    Ok(KernSightEventPage {
        session_id,
        offset,
        limit,
        total_matches,
        next_offset: (next < total_matches).then_some(next),
        type_counts,
        events,
    })
}

async fn replay_session_events(serial: &str, session_id: Uuid) -> Result<Vec<Event>, String> {
    replay_session_events_scoped(serial, session_id, None).await
}
async fn replay_session_events_scoped(
    serial: &str,
    session_id: Uuid,
    paths: Option<&runtime_paths::RuntimePaths>,
) -> Result<Vec<Event>, String> {
    replay_session_events_bounded(serial, session_id, paths, None).await
}
async fn replay_session_events_bounded(
    serial: &str,
    session_id: Uuid,
    paths: Option<&runtime_paths::RuntimePaths>,
    evidence_root: Option<&Path>,
) -> Result<Vec<Event>, String> {
    let replay = async {
        let mut connection = KernSightConnection::connect_scoped(serial, paths).await?;
        let request_id = Uuid::new_v4();
        connection
            .send(&Message::ReplayBatches(ReplayBatches {
                request_id,
                session_id,
                after_batch_sequence: None,
            }))
            .await?;
        let mut events = Vec::new();
        let mut envelope = session_budget::ReplayEnvelope::default();
        loop {
            match connection.receive().await? {
                Message::EventBatch(batch) if batch.session_id == session_id => {
                    if let Some(root) = evidence_root {
                        let batch_bytes = session_budget::measure_json(root, &batch.events)
                            .map_err(|e| format!("事件重放 JSON 超出有界输入：{e}"))?;
                        envelope
                            .admit(batch_bytes, batch.events.len())
                            .map_err(|e| e.to_string())?;
                    }
                    events.extend(batch.events);
                }
                Message::ReplayComplete(complete)
                    if complete.request_id == request_id && complete.session_id == session_id =>
                {
                    break;
                }
                Message::Ack(ack) if !ack.accepted => {
                    return Err(ack
                        .detail
                        .unwrap_or_else(|| "KernSight 拒绝事件重放".into()));
                }
                message => return Err(format!("KernSight 事件流响应不正确：{message:?}")),
            }
        }
        connection.close().await?;
        Ok(events)
    };
    if let Some(root) = evidence_root {
        let ms = session_budget::remaining_ms(root, 60000).map_err(|e| e.to_string())?;
        timeout(Duration::from_millis(ms), replay)
            .await
            .map_err(|_| {
                session_budget::record_failure(root, "time_budget_exhausted");
                "有界事件回放期限耗尽；未截断为成功".to_owned()
            })?
    } else {
        replay.await
    }
}

fn compact_session_report_for_ui(report: &mut SessionReport) {
    report.observed_mappings.clear();
    report.sched_wakeups.truncate(32);
    report.binder_reply_pairs.truncate(64);
    report.loopback_scans.truncate(32);
    report.artifacts.truncate(80);
    const KEEP: &[&str] = &[
        "connects",
        "answers",
        "sni",
        "http_host",
        "binder",
        "replies_to",
        "inspect_hit",
        "tls_send",
        "tls_recv",
        "joined_transact",
        "http_call",
        "http_reply",
    ];
    report
        .graph
        .edges
        .retain(|edge| KEEP.iter().any(|relation| edge.relation == *relation));
    report.graph.edges.truncate(400);
    report.graph.entities.truncate(400);
}

#[allow(dead_code)]
async fn merge_package_dumps(serial: &str, report: &mut SessionReport) {
    let session_id = report.session_id.unwrap_or(Uuid::nil());
    let packages = report
        .processes
        .iter()
        .filter_map(|process| process.package.clone())
        .collect::<BTreeSet<_>>();
    for package in packages {
        if validate_package(&package).is_err() {
            continue;
        }
        let path = format!("{KSIGHT_PACKAGES}/{package}/dump-report.json");
        let Ok(output) = run_device_root_script(serial, &format!("cat {path}")).await else {
            continue;
        };
        let Ok(dump) = serde_json::from_str::<PackageDumpForMerge>(&output.stdout) else {
            continue;
        };
        let dump_id = if dump.dump_id.is_empty() {
            dump.graph
                .dump_ids
                .first()
                .cloned()
                .unwrap_or_else(|| "unknown".into())
        } else {
            dump.dump_id
        };
        let package_name = if dump.package.is_empty() {
            package
        } else {
            dump.package
        };
        if !report
            .merged_dumps
            .iter()
            .any(|item| item.dump_id == dump_id)
        {
            report.merged_dumps.push(MergedDumpRef {
                package: package_name,
                dump_id: dump_id.clone(),
            });
        }
        if !report.graph.dump_ids.iter().any(|item| item == &dump_id) {
            report.graph.dump_ids.push(dump_id);
        }
        report.graph.merge_from(&dump.graph);
        report
            .graph
            .correlate_dump_vmas(session_id, &dump.artifacts, &report.observed_mappings);
    }
}

async fn read_last_session_id(serial: &str) -> Option<Uuid> {
    run_device_root_script(serial, &format!("cat {KSIGHT_LAST_SESSION}"))
        .await
        .ok()
        .and_then(|output| Uuid::parse_str(output.stdout.trim()).ok())
}

fn extract_session_id(text: &str) -> Option<Uuid> {
    text.split_whitespace().find_map(|token| {
        let candidate = token
            .strip_prefix("session=")
            .or_else(|| token.strip_prefix("session_id="))?
            .trim_matches(|character: char| !character.is_ascii_hexdigit() && character != '-');
        Uuid::parse_str(candidate).ok()
    })
}

async fn wait_for_adb_return(serial: &str, max_seconds: u64) -> Result<(), String> {
    let started = tokio::time::Instant::now();
    let max_wait = Duration::from_secs(max_seconds);
    loop {
        if let Ok(output) = run_device_adb(serial, &["get-state"]).await {
            if output.code == Some(0) && output.stdout.trim() == "device" {
                return Ok(());
            }
        }
        if started.elapsed() >= max_wait {
            return Err("ADB 未在 watchdog 时限内恢复，请在手机上重新开启 USB 调试".into());
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

#[tauri::command]
pub async fn list_kernsight_package_dumps(serial: String) -> Result<Vec<Value>, String> {
    validate_serial(&serial)?;
    let output = run_device_root_script(
        &serial,
        &format!("find {KSIGHT_PACKAGES} -mindepth 2 -maxdepth 2 -name dump-report.json -print 2>/dev/null"),
    )
    .await?;
    let mut reports = Vec::new();
    for path in output.stdout.lines() {
        let Some(package) = path
            .strip_prefix(&format!("{KSIGHT_PACKAGES}/"))
            .and_then(|rest| rest.strip_suffix("/dump-report.json"))
        else {
            continue;
        };
        validate_package(package)?;
        let document = run_device_root_script(&serial, &format!("cat {path}")).await?;
        if document.code == Some(0) {
            if let Ok(mut value) = serde_json::from_str::<Value>(&document.stdout) {
                // Re-catalog older agent reports in memory so opening phone evidence and
                // importing the same dump produce identical ownership results.
                enrich_local_dex_ownership(&mut value, package);
                reports.push(value);
            }
        }
    }
    reports.sort_by(|left, right| {
        left.get("package")
            .and_then(Value::as_str)
            .cmp(&right.get("package").and_then(Value::as_str))
    });
    Ok(reports)
}

#[tauri::command]
pub async fn read_kernsight_package_file(
    serial: String,
    package: String,
    relative_path: String,
    max_bytes: u64,
) -> Result<KernSightEvidenceFileContent, String> {
    validate_serial(&serial)?;
    validate_package(&package)?;
    validate_evidence_relative_path(&relative_path)?;
    if !(1..=1_048_576).contains(&max_bytes) {
        return Err("证据文件预览上限必须在 1 B 到 1 MiB 之间".into());
    }
    let path = format!("{KSIGHT_PACKAGES}/{package}/{relative_path}");
    let quoted_path = crate::shell_quote(&path);
    let size = run_device_root_script(&serial, &format!("stat -c %s {quoted_path} 2>/dev/null"))
        .await?
        .stdout
        .trim()
        .parse::<u64>()
        .map_err(|_| "证据文件不存在或无法读取大小".to_string())?;
    let output = run_device_root_script(
        &serial,
        &format!("head -c {max_bytes} {quoted_path} 2>/dev/null | base64"),
    )
    .await?;
    if output.code != Some(0) {
        return Err(if output.stderr.is_empty() {
            "读取证据文件失败".into()
        } else {
            output.stderr
        });
    }
    Ok(KernSightEvidenceFileContent {
        package,
        relative_path,
        bytes: size,
        truncated: size > max_bytes,
        encoding: "base64".into(),
        content: output.stdout.split_whitespace().collect(),
    })
}

/// Read-only presence refresh. Only NotFound proves absence; other IO errors stay unknown.
#[tauri::command]
pub fn local_kernsight_evidence_present(path: String) -> Result<bool, String> {
    let root = PathBuf::from(path.trim());
    if !root.is_absolute() {
        return Err("本地证据路径必须为绝对路径".into());
    }
    match std::fs::metadata(&root) {
        Ok(meta) if meta.is_dir() => {}
        Ok(_) => return Err("本地证据路径不再是目录；状态未确认".into()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(e.to_string()),
    }
    for name in [
        "dump-report.json",
        "bounded-code-report.json",
        "session-report.json",
    ] {
        match std::fs::metadata(root.join(name)) {
            Ok(meta) if meta.is_file() => return Ok(true),
            Ok(_) => return Err("证据清单类型已改变；状态未确认".into()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.to_string()),
        }
    }
    Ok(false)
}

#[test]
fn evidence_presence_refresh_distinguishes_missing_and_retained_reports() {
    let root = std::env::temp_dir().join(format!("me-presence-{}", uuid::Uuid::new_v4()));
    let path = root.to_string_lossy().into_owned();
    assert!(!local_kernsight_evidence_present(path.clone()).unwrap());
    std::fs::create_dir(&root).unwrap();
    assert!(!local_kernsight_evidence_present(path.clone()).unwrap());
    std::fs::write(root.join("bounded-code-report.json"), b"{}").unwrap();
    assert!(local_kernsight_evidence_present(path.clone()).unwrap());
    std::fs::remove_file(root.join("bounded-code-report.json")).unwrap();
    std::fs::write(root.join("dump-report.json"), b"{}").unwrap();
    assert!(local_kernsight_evidence_present(path).unwrap());
    std::fs::remove_file(root.join("dump-report.json")).unwrap();
    std::fs::remove_dir(root).unwrap();
    assert!(local_kernsight_evidence_present("relative".into()).is_err());
}

#[tauri::command]
pub async fn import_kernsight_evidence_directory(
    path: String,
) -> Result<KernSightLocalEvidenceBundle, String> {
    let root = PathBuf::from(path.trim());
    if !root.is_absolute() || !root.is_dir() {
        return Err("请选择含 dump-report.json 或 bounded-code-report.json 的本地绝对目录".into());
    }
    let dump_path = root.join("dump-report.json");
    let mut dump_report: Value = if dump_path.is_file() {
        let dump_text = read_bounded_text(&dump_path, 64 * 1024 * 1024)?;
        serde_json::from_str(&dump_text)
            .map_err(|error| format!("dump-report.json 无效：{error}"))?
    } else {
        let text = read_bounded_text(&root.join("bounded-code-report.json"), 32768)?;
        let bounded: Value = serde_json::from_str(&text)
            .map_err(|error| format!("bounded-code-report.json 无效：{error}"))?;
        if bounded["schema"] != "kernsight.bounded-code/v1" {
            return Err("不支持的有界代码证据 schema".into());
        }
        serde_json::json!({"schema_version":"mobilee.bounded-code-adapter/v1", "package":bounded["identity"]["package"],"bounded_code":bounded,
            "warnings":["有界安装代码容器采样，非完整进程或 package dump；旧成功/完整字段未填充"]})
    };
    let transport_notes = std::fs::read_dir(&root)
        .map_err(|e| e.to_string())?
        .filter_map(Result::ok)
        .filter(|entry| entry.file_type().is_ok_and(|kind| kind.is_file()))
        .filter(|entry| {
            entry.file_name().to_str().is_some_and(|name| {
                name.starts_with("transport-partial-") && name.ends_with(".json")
            })
        })
        .take(32)
        .map(|entry| {
            read_bounded_text(&entry.path(), 65536)
                .and_then(|text| serde_json::from_str::<Value>(&text).map_err(|e| e.to_string()))
        })
        .collect::<Result<Vec<_>, _>>()?;
    if !transport_notes.is_empty() {
        dump_report["mobilee_transport_status"] = serde_json::json!({"complete":false,"status":"partial","notes":transport_notes,"scope":"received local tree; original producer report preserved"});
    }
    let mut coverage_status = None;
    for entry in std::fs::read_dir(&root)
        .map_err(|e| e.to_string())?
        .filter_map(Result::ok)
        .filter(|e| e.file_type().is_ok_and(|t| t.is_file()))
        .filter(|e| {
            e.file_name().to_str().is_some_and(|n| {
                n.starts_with("archive-content-references-") && n.ends_with(".json")
            })
        })
        .take(32)
    {
        let note: Value =
            serde_json::from_str(&read_bounded_text(&entry.path(), 64 * 1024 * 1024)?)
                .map_err(|e| e.to_string())?;
        let partial = note["archiveCoverage"]["status"] == "partial";
        coverage_status = Some(if partial || coverage_status == Some("partial") {
            "partial"
        } else {
            "unknown"
        });
    }
    if let Some(status) = coverage_status {
        dump_report["mobilee_archive_coverage"] = serde_json::json!({"status":status,"complete_collection":false,"scope":"archived retained paths; semantic and full collection coverage not attested"});
    }
    let package = dump_report
        .get("package")
        .and_then(Value::as_str)
        .ok_or("dump-report.json 缺少 package")?
        .to_owned();
    validate_package(&package)?;
    enrich_local_dex_ownership(&mut dump_report, &package);
    let session_path = root.join("session-report.json");
    let mut session_report: Option<Value> = if session_path.is_file() {
        Some(
            serde_json::from_str(&read_bounded_text(&session_path, 64 * 1024 * 1024)?)
                .map_err(|error| format!("session-report.json 无效：{error}"))?,
        )
    } else {
        None
    };
    if let Some(group) = capture_groups::read_import(&root)? {
        if group.package != package {
            return Err("主会话清单和 dump 包归属冲突".into());
        }
        let value = session_report.get_or_insert_with(|| serde_json::json!({}));
        value["mobilee_capture_group"] = serde_json::to_value(&group).map_err(|e| e.to_string())?;
        value["mobilee_capture_edges"] = serde_json::json!(group.evidence_edges());
        value["mobilee_capture_source_status"] =
            serde_json::json!(if root.join("capture-relation.json").is_file() {
                "agent_relation_matched"
            } else {
                "unknown_missing_agent_relation"
            });
        value["mobilee_session_scope"] = serde_json::json!("explicit-parent-session-ids");
    }
    let capture_text = std::fs::read_to_string(root.join("CAPTURE.txt")).unwrap_or_default();
    let (file_count, total_bytes, mut files) = local_tree_stats(&root, 50_000)?;
    dump_report["local_storage_accounting"] = storage_evidence::account(
        &root,
        &files
            .iter()
            .map(|file| (file.relative_path.clone(), file.bytes))
            .collect::<Vec<_>>(),
    );
    let static_identity_records = read_bounded_text(&root.join("static-references.json"), 16384)
        .ok().and_then(|text|serde_json::from_str::<Value>(&text).ok())
        .and_then(|v|v["objects"].as_array().cloned()).unwrap_or_default()
        .into_iter().take(16).map(|v|serde_json::json!({"apk_sha256":v["sha256"],"source_path":v["source"],"producer_status":v["status"],"verification":"producer_reference; APK bytes not rechecked by this import"})).collect::<Vec<_>>();
    let mut indexed_static_sets = dump_report["dex_sets"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    if let Ok(text) = read_bounded_text(&root.join("runtime-dex-verification.json"), 16384) {
        if let Ok(note) = serde_json::from_str::<Value>(&text) {
            if note["schema"] == "kernsight.actual-runtime-dex-readback/v1"
                && note["static_full_bytes_equal"] == true
                && dump_report["local_storage_accounting"]["runtime_observations"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .any(|row| {
                        row["source"] == note["source"]
                            && row["read"]["sha256"] == note["read"]["sha256"]
                            && row["object_inspection"]["derived_objects"]
                                .as_array()
                                .into_iter()
                                .flatten()
                                .any(|dex| {
                                    dex["sha256"] == note["static_sha256"]
                                        && dex["length"] == note["dex_bytes"]
                                })
                    })
            {
                indexed_static_sets.push(serde_json::json!({"sha256":note["static_sha256"],"bytes":note["dex_bytes"],"source_kind":"static_comparison_reference","canonical_relative_path":null,"observations":[{"comparison_record":"runtime-dex-verification.json","apk_identity_records":static_identity_records,"scope":"earlier retained APK DEX; imported local comparison assertion, static bytes not rehashed here","package":package,"parent_instance":null}]}));
            }
        }
    }
    let mut content_dex_class_index = dex_class_index::objects(
        dump_report["local_storage_accounting"]["runtime_observations"]
            .as_array()
            .map(Vec::as_slice)
            .unwrap_or_default(),
        &serde_json::json!(indexed_static_sets),
        &package,
        &dump_report["registered_component_classes"],
        &session_report
            .as_ref()
            .map(|r| r["mobilee_capture_group"]["id"].clone())
            .unwrap_or(Value::Null),
    );
    if let Some(notes) = dump_report
        .get("warnings")
        .and_then(|value| value.as_array())
    {
        let payload: Vec<Value> = notes
            .iter()
            .filter(|note| note.as_str().is_some_and(|text| text.contains("dexdata0")))
            .cloned()
            .collect();
        if !payload.is_empty() {
            content_dex_class_index["dexdata0_notes"] = serde_json::json!(payload);
        }
    }
    if let Some(packed) = dump_report.get("packed_plaintext_names") {
        if !packed.as_array().is_some_and(Vec::is_empty) {
            content_dex_class_index["packed_plaintext_names"] = packed.clone();
            content_dex_class_index["packed_plaintext_status"] = serde_json::json!(
                "names are plaintext type descriptors inside dexdata0; they are not class_defs and the bytecode is not decrypted"
            );
        }
    }
    if let Some(symbols) = dump_report.get("dynamic_symbols") {
        if !symbols.as_array().is_some_and(Vec::is_empty) {
            dump_report["content_elf_symbols"] = symbols.clone();
        }
    }
    dump_report["content_dex_class_index"] = content_dex_class_index;
    if let Some(report) = session_report
        .as_mut()
        .filter(|r| r.get("mobilee_capture_group").is_some())
    {
        report["mobilee_capture_accounting"] = dump_report["local_storage_accounting"].clone();
        report["mobilee_capture_accounting_scope"]=serde_json::json!("this imported artifact tree only; no child-stage byte summation; unverified content remains unknown");
    }
    if let Some(observations) = dump_report["local_storage_accounting"]["observations"].as_array() {
        for file in &mut files {
            file.code_evidence = observations
                .iter()
                .filter(|note| note["relative_path"].as_str() == Some(&file.relative_path))
                .cloned()
                .collect();
            for note in &mut file.code_evidence {
                if let Some(entry) =
                    dump_report["dex_ownership"]["entries"]
                        .as_array()
                        .and_then(|entries| {
                            entries
                                .iter()
                                .find(|entry| entry["sha256"] == note["sha256"])
                        })
                {
                    note["ownership"] = serde_json::json!({"category":entry["category"],"confidence":entry["confidence"],"reasons":entry["reasons"],"basis":"DEX class namespace samples; inferred, not verified company ownership"});
                }
            }
        }
    }
    if let Some(ranges) = dump_report["local_storage_accounting"]["runtime_observations"].as_array()
    {
        for file in &mut files {
            file.code_evidence.extend(
                ranges
                    .iter()
                    .filter(|note| note["relative_path"].as_str() == Some(&file.relative_path))
                    .cloned(),
            );
        }
    }
    if let Some(ranges) = dump_report["bounded_code"]["ranges"].as_array() {
        for file in &mut files {
            if !(file.relative_path.len() == 12
                && file.relative_path.starts_with("range-")
                && file.relative_path.ends_with(".bin")
                && file.relative_path[6..8]
                    .parse::<u8>()
                    .is_ok_and(|index| index < 16))
            {
                continue;
            }
            for range in ranges
                .iter()
                .filter(|range| range["relative_path"].as_str() == Some(&file.relative_path))
            {
                let mut note = range.clone();
                note["schema"] = serde_json::json!("kernsight.bounded-code-range/v1");
                note["identity"] = dump_report["bounded_code"]["identity"].clone();
                let verified = range["retained_bytes"].as_u64() == Some(file.bytes)
                    && file.bytes <= 4 * 1024 * 1024
                    && storage_evidence::hash_file(&root.join(&file.relative_path), file.bytes)
                        .is_some_and(|hash| range["sha256"].as_str() == Some(&hash));
                note["local_content_status"] = serde_json::json!(if verified {
                    "complete_file_hash_verified"
                } else {
                    "unknown_or_failed"
                });
                file.code_evidence.push(note);
            }
        }
        let local_total = dump_report["local_storage_accounting"]["logical_file_bytes"].as_u64();
        dump_report["bounded_code_local_size_matches"] = serde_json::json!(
            local_total.is_some()
                && local_total
                    == dump_report["bounded_code"]["total_persisted_file_bytes"].as_u64()
        );
    }
    Ok(KernSightLocalEvidenceBundle {
        root: root.to_string_lossy().into_owned(),
        package,
        file_count,
        total_bytes,
        dump_report,
        session_report,
        capture_text,
        files,
    })
}

fn enrich_local_dex_ownership(dump_report: &mut Value, package: &str) {
    let ownership_is_current = dump_report.get("dex_ownership").is_some_and(|ownership| {
        ownership.get("schema_version").and_then(Value::as_str)
            == Some("mobilee.kernsight-dex-ownership/v4")
            && ownership
                .get("package")
                .and_then(Value::as_str)
                .is_some_and(|value| value.eq_ignore_ascii_case(package))
            && ownership
                .get("entries")
                .and_then(Value::as_array)
                .is_some_and(|entries| !entries.is_empty())
    });
    if ownership_is_current {
        return;
    }
    let Some(dex_sets_value) = dump_report.get("dex_sets").cloned() else {
        return;
    };
    let Ok(dex_sets) = serde_json::from_value::<Vec<DexArtifactSet>>(dex_sets_value) else {
        return;
    };
    if dex_sets.is_empty() {
        return;
    }
    let registered_component_classes = dump_report
        .get("registered_component_classes")
        .cloned()
        .and_then(|value| serde_json::from_value::<Vec<String>>(value).ok())
        .unwrap_or_default();
    let package_path = package.to_ascii_lowercase().replace('.', "/");
    let organization_path = package_path
        .split('/')
        .take(2)
        .collect::<Vec<_>>()
        .join("/");
    let internal_roots = registered_component_classes
        .iter()
        .map(|value| value.to_ascii_lowercase().replace('.', "/"))
        .map(|value| value.split('/').take(2).collect::<Vec<_>>().join("/"))
        .filter(|value| value.contains('/') && value != &organization_path)
        .collect::<BTreeSet<_>>();
    let mut counts = BTreeMap::<String, usize>::new();
    let mut business_class_samples = 0usize;
    let mut business_dex_sets = 0usize;
    let mut internal_class_samples = 0usize;
    let mut third_party_class_samples = 0usize;
    let mut unknown_class_samples = 0usize;
    let mut entries = Vec::new();
    for set in dex_sets {
        let descriptors = set
            .semantic
            .as_ref()
            .map(|semantic| semantic.class_descriptors.as_slice())
            .unwrap_or_default();
        let mut business = 0usize;
        let mut internal = 0usize;
        let mut sdk = 0usize;
        let mut namespaces = BTreeMap::<String, usize>::new();
        for descriptor in descriptors {
            let class = descriptor
                .trim_start_matches('[')
                .trim_start_matches('L')
                .trim_end_matches(';')
                .to_ascii_lowercase();
            let namespace = class.split('/').take(3).collect::<Vec<_>>().join(".");
            *namespaces.entry(namespace).or_default() += 1;
            if !package_path.is_empty() && mobilee_namespace_contains(&package_path, &class) {
                business += 1;
            } else if is_mobilee_sdk_namespace(&class) {
                sdk += 1;
            } else if internal_roots
                .iter()
                .any(|root| mobilee_namespace_contains(root, &class))
                || (organization_path.contains('/')
                    && mobilee_namespace_contains(&organization_path, &class))
            {
                internal += 1;
            }
        }
        let total = descriptors.len();
        let unknown = total.saturating_sub(business + internal + sdk);
        let percent = |value: usize| if total == 0 { 0 } else { value * 100 / total };
        let runtime_only = set
            .sources
            .iter()
            .any(|source| matches!(source.as_str(), "memory-dex" | "heap-blob"))
            && !set.sources.iter().any(|source| source == "apk-dex");
        let classified = business + internal + sdk;
        let has_first_party = business + internal > 0;
        let has_non_first_party = sdk + unknown > 0;
        let secneo_classes = descriptors
            .iter()
            .filter(|descriptor| {
                descriptor
                    .trim_start_matches('[')
                    .trim_start_matches('L')
                    .trim_end_matches(';')
                    .to_ascii_lowercase()
                    .starts_with("com/secneo/apkwrapper/")
            })
            .count();
        let packer_shell = total > 0 && total <= 512 && business == 0 && secneo_classes > 0;
        let category = if packer_shell {
            "dynamic_payload"
        } else if total == 0 {
            "unknown"
        } else if has_first_party && has_non_first_party {
            "mixed"
        } else if business > 0 {
            "business"
        } else if internal > 0 {
            "internal_component"
        } else if percent(sdk) >= 60 {
            "third_party_sdk"
        } else if classified * 100 >= total * 65 {
            if sdk >= internal {
                "third_party_sdk"
            } else {
                "internal_component"
            }
        } else {
            "unknown"
        };
        business_class_samples += business;
        internal_class_samples += internal;
        third_party_class_samples += sdk;
        unknown_class_samples += unknown;
        if business > 0 {
            business_dex_sets += 1;
        }
        *counts.entry(category.into()).or_default() += 1;
        let mut namespace_rows = namespaces.into_iter().collect::<Vec<_>>();
        namespace_rows.sort_by(|left, right| right.1.cmp(&left.1).then(left.0.cmp(&right.0)));
        entries.push(serde_json::json!({
            "sha256": set.sha256,
            "canonical_relative_path": set.canonical_relative_path,
            "category": category,
            "confidence": if category == "unknown" { 0 } else { percent(match category { "business" => business, "internal_component" => internal, "third_party_sdk" => sdk, "mixed" => classified, _ => unknown }) },
            "sampled_classes": total,
            "business_classes": business,
            "internal_classes": internal,
            "third_party_classes": sdk,
            "unknown_classes": unknown,
            "dominant_namespaces": namespace_rows.into_iter().take(6).map(|(name, count)| format!("{name} ({count})")).collect::<Vec<_>>(),
            "reasons": [format!("类样本 {total}：业务 {business}、内部组件 {internal}、第三方 SDK {sdk}、未知 {unknown}"), if packer_shell { String::from("SecNeo apkwrapper 壳；业务类不在这张 DEX 里") } else if runtime_only { String::from("仅在内存/堆载荷中观察到") } else { String::from("包含安装态或可读 DEX 来源") }],
        }));
    }
    if let Some(object) = dump_report.as_object_mut() {
        object.insert("dex_ownership".into(), serde_json::json!({
            "schema_version": "mobilee.kernsight-dex-ownership/v4",
            "package": package,
            "entries": entries,
            "business": counts.get("business").copied().unwrap_or_default(),
            "internal_components": counts.get("internal_component").copied().unwrap_or_default(),
            "third_party_sdks": counts.get("third_party_sdk").copied().unwrap_or_default(),
            "dynamic_payloads": counts.get("dynamic_payload").copied().unwrap_or_default(),
            "mixed": counts.get("mixed").copied().unwrap_or_default(),
            "unknown": counts.get("unknown").copied().unwrap_or_default(),
            "business_class_samples": business_class_samples,
            "business_dex_sets": business_dex_sets,
            "internal_class_samples": internal_class_samples,
            "third_party_class_samples": third_party_class_samples,
            "unknown_class_samples": unknown_class_samples,
        }));
        object.insert(
            "dex_ownership_generated_by".into(),
            Value::String("mobilee-import".into()),
        );
    }
}

fn mobilee_namespace_contains(root: &str, path: &str) -> bool {
    path == root
        || path
            .strip_prefix(root)
            .is_some_and(|suffix| suffix.starts_with('/'))
}

fn is_mobilee_sdk_namespace(path: &str) -> bool {
    const PREFIXES: &[&str] = &[
        "android/",
        "androidx/",
        "com/airbnb/",
        "com/alibaba/fastjson/",
        "com/alipay/",
        "com/bumptech/glide/",
        "com/fasterxml/",
        "com/meizu/",
        "com/facebook/",
        "com/google/",
        "com/huawei/hms/",
        "com/tenpay/",
        "com/tencent/bugly/",
        "com/tencent/mapsdk/",
        "com/tencent/mm/opensdk/",
        "com/tencent/qqmail/",
        "com/tencent/smtt/",
        "com/tencent/tencentmap/",
        "com/tencent/wework/",
        "com/tencent/weworklocal/",
        "com/weishu/reflection/",
        "io/flutter/",
        "kotlin/",
        "kotlinx/",
        "okhttp3/",
        "org/apache/",
        "org/chromium/",
        "org/json/",
        "retrofit2/",
    ];
    PREFIXES.iter().any(|prefix| path.starts_with(prefix))
}

fn collect_archive_files(root: &Path) -> Result<Vec<(PathBuf, String, u64)>, String> {
    let canonical_root = root
        .canonicalize()
        .map_err(|error| format!("证据目录不可访问：{error}"))?;
    let mut pending = vec![canonical_root.clone()];
    let mut files = Vec::new();
    let mut total_bytes = 0u64;
    while let Some(directory) = pending.pop() {
        for entry in
            std::fs::read_dir(&directory).map_err(|error| format!("无法遍历证据目录：{error}"))?
        {
            let entry = entry.map_err(|error| format!("无法读取证据目录项：{error}"))?;
            let path = entry.path();
            let file_type = entry
                .file_type()
                .map_err(|error| format!("无法读取证据目录项类型：{error}"))?;
            if file_type.is_symlink() {
                return Err("证据目录含符号链接；未跳过来源或读取目录外内容".into());
            }
            if entry
                .file_type()
                .map_err(|error| error.to_string())?
                .is_symlink()
            {
                return Err("证据目录含符号链接；请使用保留原始来源的普通文件目录".into());
            }
            if entry
                .file_type()
                .map_err(|error| error.to_string())?
                .is_symlink()
            {
                return Err("证据目录含符号链接；请使用保留原始来源的普通文件目录".into());
            }
            let metadata = entry
                .metadata()
                .map_err(|error| format!("无法读取证据元数据：{error}"))?;
            if metadata.is_dir() {
                pending.push(path);
                continue;
            }
            if !metadata.is_file() {
                continue;
            }
            let relative = path
                .strip_prefix(&canonical_root)
                .map_err(|_| "证据文件超出所选目录".to_string())?
                .to_string_lossy()
                .replace('\\', "/");
            validate_evidence_relative_path(&relative)?;
            total_bytes = total_bytes.saturating_add(metadata.len());
            if total_bytes > MAX_EVIDENCE_ARCHIVE_BYTES {
                return Err("证据包未压缩大小超过 8 GiB 上限".into());
            }
            files.push((path, relative, metadata.len()));
            if files.len() > MAX_EVIDENCE_ARCHIVE_FILES {
                return Err("证据包文件数超过 100000 个上限".into());
            }
        }
    }
    files.sort_by(|left, right| left.1.cmp(&right.1));
    Ok(files)
}

fn write_kernsight_evidence_archive(root: &Path, output: &Path) -> Result<(), String> {
    archive_objects::write(root, output)
}
#[cfg(test)]
fn write_kernsight_evidence_archive_v1(root: &Path, output: &Path) -> Result<(), String> {
    if !root.join("dump-report.json").is_file() {
        return Err("所选目录缺少 dump-report.json".into());
    }
    let files = collect_archive_files(root)?;
    let dump_report: Value = serde_json::from_str(&read_bounded_text(
        &root.join("dump-report.json"),
        64 * 1024 * 1024,
    )?)
    .map_err(|error| format!("dump-report.json 无效：{error}"))?;
    let package = dump_report
        .get("package")
        .and_then(Value::as_str)
        .ok_or("dump-report.json 缺少 package")?;
    validate_package(package)?;
    if let Some(parent) = output.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|error| format!("无法创建证据包输出目录：{error}"))?;
    }
    let mut temporary_name = output.as_os_str().to_os_string();
    temporary_name.push(".part");
    let temporary = PathBuf::from(temporary_name);
    let file = File::create(&temporary).map_err(|error| format!("无法创建证据包：{error}"))?;
    let mut writer = ZipWriter::new(file);
    let options = SimpleFileOptions::default()
        // APK/DEX/SO and most runtime artifacts are already dense or compressed.
        // Store them directly so a multi-gigabyte pull is packaged in one local
        // pass instead of spending minutes recompressing every artifact.
        .compression_method(zip::CompressionMethod::Stored)
        .unix_permissions(0o600);
    let manifest = serde_json::json!({
        "schemaVersion": MOBILEE_EVIDENCE_SCHEMA,
        "package": package,
        "dumpId": dump_report.get("dump_id").and_then(Value::as_str),
        "agentVersion": dump_report.get("agent_version").and_then(Value::as_str),
        "fileCount": files.len(),
        "storageRepresentation":"expanded-logical-files/v1",
        "hardLinksPreserved":false,
        "physicalBytes":"unknown-until-local-stat",
        "uncompressedBytes": files.iter().map(|item| item.2).sum::<u64>(),
    });
    writer
        .start_file("manifest.json", options)
        .map_err(|error| format!("无法写入证据包清单：{error}"))?;
    writer
        .write_all(
            serde_json::to_string_pretty(&manifest)
                .unwrap_or_default()
                .as_bytes(),
        )
        .map_err(|error| format!("无法写入证据包清单：{error}"))?;
    for (path, relative, _) in files {
        writer
            .start_file(format!("evidence/{relative}"), options)
            .map_err(|error| format!("无法写入证据包文件 {relative}：{error}"))?;
        let mut source =
            File::open(&path).map_err(|error| format!("无法读取证据文件 {relative}：{error}"))?;
        std::io::copy(&mut source, &mut writer)
            .map_err(|error| format!("无法写入证据文件 {relative}：{error}"))?;
    }
    writer
        .finish()
        .map_err(|error| format!("无法完成证据包：{error}"))?;
    std::fs::rename(&temporary, output).map_err(|error| {
        let _ = std::fs::remove_file(&temporary);
        format!("无法保存证据包：{error}")
    })?;
    Ok(())
}

fn resolve_local_path(value: &str, label: &str) -> Result<PathBuf, String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(format!("{label}为空"));
    }
    let path = PathBuf::from(trimmed);
    if path.is_absolute() {
        return Ok(path);
    }
    let current = std::env::current_dir().map_err(|error| format!("无法解析{label}：{error}"))?;
    Ok(current.join(path))
}

#[tauri::command]
pub fn export_kernsight_evidence_archive(
    root: String,
    output_path: String,
) -> Result<String, String> {
    let root = resolve_local_path(&root, "证据目录")?;
    let output = resolve_local_path(&output_path, "输出文件")?;
    if !root.is_dir() {
        return Err(format!(
            "证据目录不存在或已失效：{}。如果它来自临时解包，请重新打开 MobileE 案例文件后再导出。",
            root.display()
        ));
    }
    if output.file_name().is_none() {
        return Err(format!("输出文件名无效：{}", output.display()));
    }
    archive_objects::write_local_retained(&root, &output)?;
    archive_objects::restore_from_export_source(&output, &root)
        .map_err(|e| format!("归档已保存，但本地对象复用未确认（可保留归档单独导入）：{e}"))?;
    Ok(output.to_string_lossy().into_owned())
}

#[tauri::command]
pub async fn import_kernsight_evidence_archive(
    path: String,
) -> Result<KernSightLocalEvidenceBundle, String> {
    let archive_path = PathBuf::from(path.trim());
    if !archive_path.is_absolute() || !archive_path.is_file() {
        return Err("请选择有效的 MobileE 案例文件绝对路径".into());
    }
    if archive_objects::is_v2(&archive_path)? {
        let root = archive_objects::restore(&archive_path)?;
        // This content-addressed cache can predate this import and be shared by
        // other bundles. Semantic metadata failure does not grant ownership of
        // its verified content; retain it for recovery and report the failure.
        return import_kernsight_evidence_directory(root.to_string_lossy().into_owned())
            .await
            .map_err(|error| format!("{error}；已核验的内容缓存已保留，未作为成功案例导入"));
    }
    let file = File::open(&archive_path).map_err(|error| format!("无法打开证据包：{error}"))?;
    let mut archive =
        ZipArchive::new(file).map_err(|error| format!("证据包不是有效 ZIP：{error}"))?;
    if archive.len() > MAX_EVIDENCE_ARCHIVE_FILES + 1 {
        return Err("证据包文件数超过安全上限".into());
    }
    let extraction_root = std::env::temp_dir().join(format!("mobilee-evidence-{}", Uuid::new_v4()));
    let evidence_root = extraction_root.join("evidence");
    std::fs::create_dir_all(&evidence_root)
        .map_err(|error| format!("无法创建证据包缓存目录：{error}"))?;
    let mut total_bytes = 0u64;
    let mut manifest_valid = false;
    for index in 0..archive.len() {
        let mut entry = archive
            .by_index(index)
            .map_err(|error| format!("无法读取证据包条目：{error}"))?;
        let enclosed = entry
            .enclosed_name()
            .ok_or("证据包包含不安全路径")?
            .to_path_buf();
        total_bytes = total_bytes.saturating_add(entry.size());
        if total_bytes > MAX_EVIDENCE_ARCHIVE_BYTES {
            return Err("证据包解压大小超过 8 GiB 上限".into());
        }
        if enclosed == Path::new("manifest.json") {
            let mut text = String::new();
            entry
                .by_ref()
                .take(1024 * 1024)
                .read_to_string(&mut text)
                .map_err(|error| format!("无法读取证据包清单：{error}"))?;
            let manifest: Value =
                serde_json::from_str(&text).map_err(|error| format!("证据包清单无效：{error}"))?;
            manifest_valid = manifest.get("schemaVersion").and_then(Value::as_str)
                == Some(MOBILEE_EVIDENCE_SCHEMA);
            continue;
        }
        let Ok(relative) = enclosed.strip_prefix("evidence") else {
            continue;
        };
        if relative.as_os_str().is_empty() {
            continue;
        }
        let output = evidence_root.join(relative);
        if entry.is_dir() {
            std::fs::create_dir_all(&output)
                .map_err(|error| format!("无法创建证据目录：{error}"))?;
            continue;
        }
        if let Some(parent) = output.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|error| format!("无法创建证据目录：{error}"))?;
        }
        let mut target =
            File::create(&output).map_err(|error| format!("无法解压证据文件：{error}"))?;
        if entry.unix_mode().is_some_and(|m| m & 0o170000 == 0o120000) {
            return Err("旧归档含符号链接，拒绝".into());
        }
        let expected = entry.size();
        let copied = std::io::copy(&mut entry.take(expected.saturating_add(1)), &mut target)
            .map_err(|e| e.to_string())?;
        if copied != expected {
            return Err("旧归档短读/膨胀长度错误，原归档保留".into());
        }
    }
    if !manifest_valid {
        let _ = std::fs::remove_dir_all(&extraction_root);
        return Err("不是受支持的 MobileE KernSight 证据包".into());
    }
    import_kernsight_evidence_directory(evidence_root.to_string_lossy().into_owned()).await
}

#[tauri::command]
pub async fn pull_kernsight_package_evidence(
    serial: String,
    package: String,
    destination: String,
) -> Result<KernSightLocalEvidenceBundle, String> {
    pull_kernsight_package_evidence_scoped(serial, package, destination, None, None).await
}
fn runtime_paths_from_group(
    group: Option<&capture_groups::Group>,
) -> Result<Option<runtime_paths::RuntimePaths>, String> {
    group
        .and_then(|g| g.base.get("runtimePaths"))
        .filter(|v| !v.is_null())
        .map(|v| serde_json::from_value(v.clone()).map_err(|e| e.to_string()))
        .transpose()
}
fn reuse_verified_transfer(
    source: &Path,
    destination: &Path,
    bytes: u64,
    hash: &str,
) -> Result<bool, String> {
    if std::fs::symlink_metadata(source)
        .map_err(|e| e.to_string())?
        .file_type()
        .is_symlink()
        || storage_evidence::hash_file(source, bytes).as_deref() != Some(hash)
    {
        return Ok(false);
    }
    session_budget::charge(destination, 0).map_err(|e| e.to_string())?;
    if let Some(parent) = destination.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    if destination.exists() {
        return Err("内容引用目标已存在，不覆盖".into());
    }
    match std::fs::hard_link(source, destination) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Err(e.to_string()),
        Err(_) => Ok(false),
    }
}

async fn pull_kernsight_package_evidence_scoped(
    serial: String,
    package: String,
    destination: String,
    remote_override: Option<String>,
    paths: Option<&runtime_paths::RuntimePaths>,
) -> Result<KernSightLocalEvidenceBundle, String> {
    pull_kernsight_package_evidence_with_objects(
        serial,
        package,
        destination,
        remote_override,
        paths,
        BTreeMap::new(),
    )
    .await
}
struct RetainedTransferPlan {
    rows: Vec<Value>,
    omitted: Vec<Value>,
    unique_bytes: u64,
}
fn retained_path_priority(path: &str) -> u8 {
    if path == "dump-report.json" {
        0
    } else if path == "capture-relation.json" || path == "budget-receipt.json" {
        1
    } else if path.starts_with("runtime/") {
        2
    } else if path.starts_with("code-evidence/") {
        3
    } else if path.starts_with("code-objects/") {
        4
    } else if path.starts_with("apk-dex/") || path.starts_with("readable-dex/") {
        5
    } else if path.starts_with("lib/") || path.starts_with("oat/") || path.starts_with("apk/") {
        9
    } else {
        6
    }
}
fn retained_transfer_plan(
    rows: &[Value],
    maximum: Option<u64>,
) -> Result<RetainedTransferPlan, String> {
    let mut groups: BTreeMap<(String, u64), Vec<Value>> = BTreeMap::new();
    for row in rows {
        let path = row["path"].as_str().ok_or("missing transfer path")?;
        validate_evidence_relative_path(path)?;
        let key = (
            row["sha256"]
                .as_str()
                .ok_or("missing transfer hash")?
                .to_owned(),
            row["bytes"].as_u64().ok_or("missing transfer length")?,
        );
        groups.entry(key).or_default().push(row.clone());
    }
    let mut groups = groups.into_iter().collect::<Vec<_>>();
    groups.sort_by_key(|(key, rows)| {
        (
            rows.iter()
                .map(|r| retained_path_priority(r["path"].as_str().unwrap()))
                .min()
                .unwrap_or(9),
            key.clone(),
        )
    });
    let mut plan = RetainedTransferPlan {
        rows: vec![],
        omitted: vec![],
        unique_bytes: 0,
    };
    for ((hash, bytes), mut aliases) in groups {
        if maximum.is_some_and(|limit| bytes > limit.saturating_sub(plan.unique_bytes)) {
            plan.omitted.extend(aliases.into_iter().map(|r|serde_json::json!({"path":r["path"],"bytes":bytes,"sha256":hash,"status":"not_received_quota; retained_at_source"})));
        } else {
            plan.unique_bytes = plan
                .unique_bytes
                .checked_add(bytes)
                .ok_or("transfer plan overflow")?;
            aliases.sort_by_key(|r| {
                (
                    retained_path_priority(r["path"].as_str().unwrap()),
                    r["path"].as_str().unwrap().to_owned(),
                )
            });
            plan.rows.extend(aliases);
        }
    }
    if !plan.rows.iter().any(|r| r["path"] == "dump-report.json") {
        return Err("read-only quota cannot retain original report".into());
    }
    Ok(plan)
}

async fn pull_kernsight_package_evidence_with_objects(
    serial: String,
    package: String,
    destination: String,
    remote_override: Option<String>,
    paths: Option<&runtime_paths::RuntimePaths>,
    known_objects: BTreeMap<(String, u64), PathBuf>,
) -> Result<KernSightLocalEvidenceBundle, String> {
    pull_kernsight_package_evidence_with_plan(
        serial,
        package,
        destination,
        remote_override,
        paths,
        known_objects,
        None,
    )
    .await
}
async fn pull_kernsight_package_evidence_with_plan(
    serial: String,
    package: String,
    destination: String,
    remote_override: Option<String>,
    paths: Option<&runtime_paths::RuntimePaths>,
    known_objects: BTreeMap<(String, u64), PathBuf>,
    maximum_unique_bytes: Option<u64>,
) -> Result<KernSightLocalEvidenceBundle, String> {
    validate_serial(&serial)?;
    validate_package(&package)?;
    let destination = PathBuf::from(destination.trim());
    if !destination.is_absolute() {
        return Err("本地拉取目录必须是绝对路径".into());
    }
    std::fs::create_dir_all(&destination)
        .map_err(|error| format!("无法创建本地拉取目录：{error}"))?;
    let remote = remote_override.unwrap_or_else(|| format!("{KSIGHT_PACKAGES}/{package}"));
    let remote_report_path = format!("{remote}/dump-report.json");
    let report_output =
        run_device_root_script(&serial, &format!("cat {remote_report_path}")).await?;
    if report_output.code != Some(0) || report_output.stdout.trim().is_empty() {
        return Err("手机端没有完整的包证据索引；请先完成一次采集，再执行拉取".into());
    }
    let remote_report: Value = serde_json::from_str(&report_output.stdout)
        .map_err(|error| format!("手机端包证据报告不完整或已损坏：{error}"))?;
    let report_package = remote_report
        .get("package")
        .and_then(Value::as_str)
        .ok_or("手机端 dump-report.json 缺少 package，不能确认包证据归属")?;
    if report_package != package {
        return Err(format!(
            "手机端报告属于 {report_package}，与当前选择的 {package} 不一致"
        ));
    }
    let remote_dump_id = remote_report
        .get("dump_id")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or("手机端 dump-report.json 缺少 dump_id，不能确认已存信息完整收口")?
        .to_owned();

    let local_root = destination.join(&package);
    let local_report_path = local_root.join("dump-report.json");
    if local_root.is_dir()
        && !local_report_path.is_file()
        && std::fs::read_dir(&local_root)
            .map_err(|error| format!("无法检查本地目标目录：{error}"))?
            .next()
            .is_some()
    {
        return Err(
            "目标包目录非空但没有 dump-report.json；为避免混入旧文件，请选择一个新的空目录".into(),
        );
    }
    if local_report_path.is_file() {
        let local_report = serde_json::from_str::<Value>(&read_bounded_text(
            &local_report_path,
            64 * 1024 * 1024,
        )?)
        .map_err(|error| format!("目标目录中已有无效的 dump-report.json：{error}"))?;
        let local_dump_id = local_report
            .get("dump_id")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if local_dump_id != remote_dump_id {
            return Err(format!(
                "目标目录已保存另一轮包证据（{local_dump_id}），为避免新旧文件混合，请选择一个新的空目录"
            ));
        }
        // Existing evidence is read-only. Avoid adb nesting another source
        // directory into an already populated target on repeated pulls.
        return import_kernsight_evidence_directory(local_root.to_string_lossy().into_owned())
            .await;
    }

    if paths.is_some() || remote.starts_with("/data/local/tmp/ksight/captures/") {
        let inventory = run_device_root_script(
            &serial,
            &format!(
                "{} evidence-inventory --root {}",
                runtime_paths::route(paths, &format!("{KSIGHT_AGENT} "))?,
                crate::shell_quote(&remote)
            ),
        )
        .await?;
        if inventory.code != Some(0) {
            return Err("agent 缺安全逐文件清单能力，未执行旧 adb 整目录拉取".into());
        }
        let note: Value = serde_json::from_str(&inventory.stdout).map_err(|e| e.to_string())?;
        if note["schema"] != "kernsight.evidence-inventory/v1" {
            return Err("清单 schema 未确认".into());
        }
        let rows = note["files"].as_array().ok_or("清单缺原路径")?;
        if rows.len() > 100000 {
            return Err("清单文件数超限".into());
        }
        let mut seen = BTreeSet::new();
        let mut logical = 0u64;
        for row in rows {
            let rel = row["path"].as_str().ok_or("无来源路径")?;
            validate_evidence_relative_path(rel)?;
            if !seen.insert(rel) {
                return Err("清单重复路径".into());
            }
            let n = row["bytes"].as_u64().ok_or("无实际源长度")?;
            logical = logical.checked_add(n).ok_or("清单大小溢出")?;
            let hash = row["sha256"].as_str().ok_or("无完整内容 hash")?;
            if hash.len() != 64
                || !hash
                    .bytes()
                    .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
            {
                return Err("无效源 hash".into());
            }
        }
        if logical > MAX_EVIDENCE_ARCHIVE_BYTES || note["logical_bytes"].as_u64() != Some(logical) {
            return Err("清单总量不可信".into());
        }
        // Object member names are fixed SHA256 paths. Bound ZIP local/central headers
        // and descriptors before choosing payloads; aliases conservatively count too.
        let selected_payload_limit = maximum_unique_bytes
            .map(|limit| limit.saturating_sub((rows.len() as u64).saturating_mul(300)));
        let plan = retained_transfer_plan(rows, selected_payload_limit)?;
        std::fs::create_dir_all(&local_root).map_err(|e| e.to_string())?;
        if maximum_unique_bytes.is_some() {
            let manifest = format!("retained-transfer-plan-{}.json", Uuid::new_v4());
            let partial_path =
                local_root.join(format!("transport-partial-{}.json", Uuid::new_v4()));
            let manifest_value = serde_json::json!({
                "schema":"mobilee.retained-readonly-transfer-plan/v1","sourceRoot":remote,
                "maximumUniqueBytes":maximum_unique_bytes,"selectedUniqueBytes":plan.unique_bytes,
                "plannedPaths":plan.rows.iter().map(|r|r["path"].clone()).collect::<Vec<_>>(),
                "omitted":plan.omitted
            });
            let partial_value = serde_json::json!({
                "schema":"mobilee.retained-readonly-transfer/v1","complete":false,
                "scope":"existing retained files only; original capture state and deadline unchanged",
                "planManifest":manifest,"plannedPathCount":plan.rows.len(),"omittedPathCount":plan.omitted.len(),
                "reason":"explicit read-only intake quota; plan is not proof of receipt; omitted source bytes remain on device; no replacement content"
            });
            let manifest_bytes =
                session_budget::measure_json(&local_root.join(&manifest), &manifest_value)
                    .map_err(|e| e.to_string())?;
            let note_bytes = if plan.omitted.is_empty() {
                0
            } else {
                session_budget::measure_json(&partial_path, &partial_value)
                    .map_err(|e| e.to_string())?
            };
            if manifest_bytes > TRANSFER_MANIFEST_RESERVE.saturating_sub(note_bytes) {
                return Err("transfer plan metadata exceeds finite reserve; no payload transferred; original source retained".into());
            }
            session_budget::write_json(local_root.join(&manifest), &manifest_value)
                .map_err(|e| e.to_string())?;
            if !plan.omitted.is_empty() {
                session_budget::write_json(partial_path, &partial_value)
                    .map_err(|e| e.to_string())?;
            }
        }
        let mut verified_transfer_objects = known_objects;
        for row in &plan.rows {
            let rel = row["path"].as_str().unwrap();
            let content_key = (
                row["sha256"].as_str().unwrap().to_owned(),
                row["bytes"].as_u64().unwrap(),
            );
            let destination = local_root.join(rel);
            if let Some(prior) = verified_transfer_objects.get(&content_key) {
                if reuse_verified_transfer(prior, &destination, content_key.1, &content_key.0)? {
                    continue;
                }
            }
            let source = format!("{remote}/{rel}");
            let cmd = format!("cat {}", crate::shell_quote(&source));
            let remote_shell = crate::root_shell_command(&cmd);
            let mut child = Command::new("adb")
                .args(["-s", &serial, "exec-out", &remote_shell])
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::null())
                .kill_on_drop(true)
                .spawn()
                .map_err(|e| e.to_string())?;
            let reader = child.stdout.take().ok_or("无传输管道")?;
            timeout(
                Duration::from_secs(120),
                session_budget::stream_verified(
                    reader,
                    &local_root.join(rel),
                    row["bytes"].as_u64().unwrap(),
                    row["sha256"].as_str().unwrap(),
                ),
            )
            .await
            .map_err(|_| {
                format!(
                    "逐文件传输期限耗尽，partial 保留于 {}",
                    local_root.display()
                )
            })??;
            if !child.wait().await.map_err(|e| e.to_string())?.success() {
                return Err(format!(
                    "源读取失败，已保存证据保留于 {}",
                    local_root.display()
                ));
            }
            verified_transfer_objects.insert(content_key, destination);
        }
        return import_kernsight_evidence_directory(local_root.to_string_lossy().into_owned())
            .await;
    }

    // `ksightctl pull-package` always performs dump-package first. This action
    // is deliberately a transport-only path: preserve the completed device
    // snapshot and copy it without launching or touching the target process.
    let chmod = run_device_root_script(&serial, &format!("chmod -R a+rX {remote}")).await?;
    if chmod.code != Some(0) {
        return Err(if chmod.stderr.is_empty() {
            "无法开放手机端已存信息的只读拉取权限".into()
        } else {
            format!("无法读取手机端已存信息：{}", chmod.stderr)
        });
    }
    let destination_text = local_root.to_string_lossy().into_owned();
    let pull = crate::run_device_adb_with_timeout(
        &serial,
        &["pull", &remote, &destination_text],
        Duration::from_secs(600),
        "KernSight 全部已存信息拉取",
    )
    .await?;
    if pull.code != Some(0) {
        return Err(if pull.stderr.is_empty() {
            format!("KernSight 已存信息拉取失败：{}", pull.stdout)
        } else {
            format!("KernSight 已存信息拉取失败：{}", pull.stderr)
        });
    }

    let bundle =
        import_kernsight_evidence_directory(local_root.to_string_lossy().into_owned()).await?;
    let pulled_dump_id = bundle
        .dump_report
        .get("dump_id")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if pulled_dump_id != remote_dump_id {
        return Err("拉取后的 dump_id 与手机端不一致；本地结果未载入，请重新选择空目录拉取".into());
    }
    Ok(bundle)
}

#[tauri::command]
pub async fn pull_kernsight_package_archive(
    app: tauri::AppHandle,
    parent_id: Option<Uuid>,
    serial: String,
    package: String,
    output_path: String,
) -> Result<KernSightLocalEvidenceBundle, String> {
    let groups = parent_id.map(|_| capture_groups::root(&app)).transpose()?;
    pull_kernsight_package_archive_at(groups, parent_id, serial, package, output_path).await
}
async fn pull_kernsight_package_archive_at(
    group_root: Option<PathBuf>,
    parent_id: Option<Uuid>,
    serial: String,
    package: String,
    output_path: String,
) -> Result<KernSightLocalEvidenceBundle, String> {
    let mut group = parent_id
        .map(|id| {
            capture_groups::selected_at(
                group_root.as_deref().ok_or("parent 根缺失")?,
                id,
                &serial,
                &package,
            )
        })
        .transpose()?;
    let remote = group
        .as_ref()
        .map(capture_groups::export_root)
        .transpose()?;
    let output = PathBuf::from(output_path.trim());
    if !output.is_absolute() {
        return Err("MobileE 证据包输出文件必须是绝对路径".into());
    }
    if output.exists() || PathBuf::from(format!("{}.budget.json", output.display())).exists() {
        return Err("输出归档或预算回执已存在；请选择新路径，保留原文件".into());
    }
    if let Some(parent) = output.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|error| format!("无法创建证据输出目录：{error}"))?;
    }
    let mut partial_name = output.as_os_str().to_os_string();
    partial_name.push(format!(".progress-{}", Uuid::new_v4()));
    let partial = PathBuf::from(partial_name);
    std::fs::write(
        &partial,
        b"ME evidence transfer in progress. This file will be replaced atomically.\n",
    )
    .map_err(|error| format!("无法创建拉取进度文件：{error}"))?;
    let allocations = if let Some(g) = group.as_mut() {
        capture_groups::reserve_export_at(
            group_root.as_deref().ok_or("parent 根缺失")?,
            g,
            &output,
        )?
    } else {
        None
    };
    let staging = std::env::temp_dir().join(format!("mobilee-pull-{}", Uuid::new_v4()));
    if let Err(error) = std::fs::create_dir_all(&staging) {
        if let Some(g) = group.as_mut() {
            capture_groups::release_unstarted_export_after_lease_at(
                group_root.as_deref().ok_or("parent 根缺失")?,
                g,
                &output,
                &["transfer", "archive", "import"],
            )?;
        }
        let _ = std::fs::remove_file(&partial);
        return Err(format!("无法创建拉取缓存目录：{error}"));
    }
    let transfer_guard_result = (|| -> Result<Option<session_budget::Guard>, String> {
        let Some(a) = allocations.as_ref() else {
            return Ok(None);
        };
        let ms = capture_groups::begin_export_time_at(
            group_root.as_deref().ok_or("parent 根缺失")?,
            group.as_mut().ok_or("parent 缺失")?,
            "transfer",
        )?;
        session_budget::Guard::install(vec![staging.clone()], a.0.saturating_sub(65536), ms)
            .map(Some)
            .map_err(|e| e.to_string())
    })();
    let transfer_guard = match transfer_guard_result {
        Ok(guard) => guard,
        Err(error) => {
            if let Some(g) = group.as_mut() {
                capture_groups::release_unstarted_export_after_lease_at(
                    group_root.as_deref().ok_or("parent 根缺失")?,
                    g,
                    &output,
                    &["transfer", "archive", "import"],
                )?;
            }
            let _ = std::fs::remove_file(&partial);
            return Err(format!("传输未启动：{error}；未删除源或缓存"));
        }
    };
    // Leave a finite allowance for the parent-bound session replay and metadata.
    // Selection is planned before payload transfer; the guard still charges actual writes.
    let payload_limit = allocations
        .as_ref()
        .map(|a| planned_transfer_payload_limit(a.0, a.1, a.2));
    let bundle = pull_kernsight_package_evidence_with_plan(
        serial.clone(),
        package.clone(),
        staging.to_string_lossy().into_owned(),
        remote,
        runtime_paths_from_group(group.as_ref())?.as_ref(),
        BTreeMap::new(),
        payload_limit,
    )
    .await;
    let bundle = match bundle {
        Ok(bundle) => bundle,
        Err(error) => {
            if group.is_none() {
                let _ = std::fs::remove_dir_all(&staging);
            }
            let _ = std::fs::remove_file(&partial);
            if let Some(g) = group.as_mut() {
                if let Some(guard) = transfer_guard.as_ref() {
                    let mut note =
                        serde_json::to_value(guard.receipt()).map_err(|e| e.to_string())?;
                    note["partial"] = serde_json::json!(true);
                    capture_groups::settle_export_at(
                        group_root.as_deref().ok_or("parent 根缺失")?,
                        g,
                        &output,
                        "transfer",
                        &note,
                    )?;
                    capture_groups::release_unstarted_export_at(
                        group_root.as_deref().ok_or("parent 根缺失")?,
                        g,
                        &output,
                        &["archive", "import"],
                    )?;
                    retain_transport_partial(&staging.join(&package), &package, g, &note, &error)?;
                }
                return Err(format!(
                    "{error}；partial 已保留，可按本地目录导入：{}",
                    staging.join(&package).display()
                ));
            }
            return Err(error);
        }
    };
    let session_result = timeout(
        Duration::from_secs(120),
        append_device_sessions_to_package_evidence(
            &serial,
            &package,
            Path::new(&bundle.root),
            group.as_ref(),
        ),
    )
    .await;
    let mut session_error = match session_result {
        Err(_) => Some("关联会话处理超过120秒".to_owned()),
        Ok(Err(error)) => Some(error),
        Ok(Ok(())) => transfer_guard.as_ref().and_then(|_| {
            session_budget::remaining_ms(Path::new(&bundle.root), u64::MAX)
                .err()
                .map(|e| e.to_string())
        }),
    };
    if let Some(g) = group.as_ref() {
        if let Err(error) = g.budget.as_ref().ok_or("parent预算缺失")?.check_time_phase(
            "transfer",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|e| e.to_string())?
                .as_millis() as u64,
        ) {
            session_error = Some(error);
        }
    }
    if let Some(error) = session_error {
        if let (Some(g), Some(guard)) = (group.as_mut(), transfer_guard.as_ref()) {
            let mut note = serde_json::to_value(guard.receipt()).map_err(|e| e.to_string())?;
            note["partial"] = serde_json::json!(true);
            capture_groups::settle_export_at(
                group_root.as_deref().ok_or("parent 根缺失")?,
                g,
                &output,
                "transfer",
                &note,
            )?;
            capture_groups::release_unstarted_export_at(
                group_root.as_deref().ok_or("parent 根缺失")?,
                g,
                &output,
                &["archive", "import"],
            )?;
            retain_transport_partial(Path::new(&bundle.root), &package, g, &note, &error)?;
        }
        let _ = std::fs::remove_file(&partial);
        return Err(format!(
            "包文件已保留，关联会话未完成：{error}；可按本地目录导入：{}",
            bundle.root
        ));
    }
    if let Some(g) = transfer_guard.as_ref() {
        let note = serde_json::to_value(g.receipt()).map_err(|e| e.to_string())?;
        if let Some(group) = group.as_mut() {
            capture_groups::settle_export_at(
                group_root.as_deref().ok_or("parent 根缺失")?,
                group,
                &output,
                "transfer",
                &note,
            )?;
        }
    }
    drop(transfer_guard);
    let archive_setup = (|| -> Result<(), String> {
        if let Some((_, archive_cap, import_cap, _)) = allocations {
            let ms = capture_groups::begin_export_time_at(
                group_root.as_deref().ok_or("parent 根缺失")?,
                group.as_mut().ok_or("parent 缺失")?,
                "archive",
            )?;
            let mut note = serde_json::json!({"schema":"mobilee.archive-output-limits/v1","archive_bytes":archive_cap,"import_bytes":import_cap,"max_ms":ms,"deadline_unix_ms":group.as_ref().and_then(|g|g.budget.as_ref()).map(|b|b.deadline_unix_ms)});
            note["parent_id"] = serde_json::json!(parent_id);
            std::fs::write(
                Path::new(&bundle.root).join("archive-output-limits.json"),
                serde_json::to_vec(&note).map_err(|e| e.to_string())?,
            )
            .map_err(|e| e.to_string())?;
        }
        Ok(())
    })();
    if let Err(error) = archive_setup {
        if let Some(g) = group.as_mut() {
            capture_groups::release_unstarted_export_after_lease_at(
                group_root.as_deref().ok_or("parent 根缺失")?,
                g,
                &output,
                &["archive", "import"],
            )?;
        }
        let _ = std::fs::remove_file(&partial);
        return Err(format!("归档未启动：{error}；源目录保留：{}", bundle.root));
    }
    let mut archive_result = write_kernsight_evidence_archive(Path::new(&bundle.root), &output)
        .and_then(|_| archive_objects::share_fresh_pull(Path::new(&bundle.root), &output));
    if let Some(g) = group.as_mut() {
        if let Err(error) = g.budget.as_ref().ok_or("parent预算缺失")?.check_time_phase(
            "archive",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|e| e.to_string())?
                .as_millis() as u64,
        ) {
            archive_result = Err(error);
        }
        let path = PathBuf::from(format!("{}.budget.json", output.display()));
        let receipt_result = (|| -> Result<(), String> {
            if path.is_file() {
                let mut note: Value = serde_json::from_str(&read_bounded_text(&path, 65536)?)
                    .map_err(|e| e.to_string())?;
                if archive_result.is_err() {
                    note["partial"] = serde_json::json!(true);
                    note["host_time_fence_or_share_error"] =
                        serde_json::json!(archive_result.as_ref().err());
                }
                capture_groups::settle_export_at(
                    group_root.as_deref().ok_or("parent 根缺失")?,
                    g,
                    &output,
                    "archive",
                    &note,
                )?;
            } else {
                return Err("本次归档预算回执缺失，计量未知".into());
            }
            Ok(())
        })();
        if let Err(error) = receipt_result {
            archive_result = Err(format!("归档计量未确认：{error}"));
        }
    }
    if let Err(error) = archive_result {
        if let Some(g) = group.as_mut() {
            capture_groups::release_unstarted_export_at(
                group_root.as_deref().ok_or("parent 根缺失")?,
                g,
                &output,
                &["import"],
            )?;
        }
        let _ = std::fs::remove_file(&partial);
        return Err(format!("{error}；已保存源目录仍可导入：{}", bundle.root));
    }
    // The directory already contains the bytes represented by the newly written
    // archive. Re-index it in place instead of immediately extracting the archive
    // into a second multi-gigabyte cache.
    let import_guard = if let (Some(_), Some((_, _, import_cap, _))) = (group.as_ref(), allocations)
    {
        let remaining = capture_groups::begin_export_time_at(
            group_root.as_deref().ok_or("parent 根缺失")?,
            group.as_mut().ok_or("parent 缺失")?,
            "import",
        );
        match remaining {
            Ok(ms) => match session_budget::Guard::install(
                vec![PathBuf::from(&bundle.root)],
                import_cap.saturating_sub(65536),
                ms,
            ) {
                Ok(guard) => Some(guard),
                Err(error) => {
                    capture_groups::release_unstarted_export_after_lease_at(
                        group_root.as_deref().ok_or("parent 根缺失")?,
                        group.as_mut().ok_or("parent缺失")?,
                        &output,
                        &["import"],
                    )?;
                    return Err(format!("导入未启动，源目录和归档保留：{error}"));
                }
            },
            Err(error) => {
                capture_groups::release_unstarted_export_after_lease_at(
                    group_root.as_deref().ok_or("parent 根缺失")?,
                    group.as_mut().ok_or("parent缺失")?,
                    &output,
                    &["import"],
                )?;
                return Err(format!(
                    "{error}；归档和源目录保留，未启动导入：{}",
                    bundle.root
                ));
            }
        }
    } else {
        None
    };
    let imported_root = PathBuf::from(&bundle.root);
    let mut result = import_kernsight_evidence_directory(bundle.root).await;
    if import_guard.is_some() {
        if let Err(error) = session_budget::remaining_ms(&imported_root, u64::MAX) {
            result = Err(format!("{error}；导入超过阶段额度，保留结果并拒绝完整成功"));
        }
    }
    if let Some(g) = group.as_ref() {
        if let Err(error) = g.budget.as_ref().ok_or("parent预算缺失")?.check_time_phase(
            "import",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|e| e.to_string())?
                .as_millis() as u64,
        ) {
            result = Err(format!(
                "{error}；导入处理跨过原父或阶段期限，保留已写入结果，拒绝完整成功"
            ));
        }
    }
    if let (Some(g), Some(guard)) = (group.as_mut(), import_guard.as_ref()) {
        let mut note = serde_json::to_value(guard.receipt()).map_err(|e| e.to_string())?;
        if result.is_err() {
            note["partial"] = serde_json::json!(true);
        }
        capture_groups::settle_export_at(
            group_root.as_deref().ok_or("parent 根缺失")?,
            g,
            &output,
            "import",
            &note,
        )?;
    }
    result
}

const RETAINED_SESSION_JSON_LIMIT: u64 = 64 * 1024 * 1024;
const RETAINED_SESSION_METADATA_RESERVE: u64 = 16 * 1024 * 1024;
const TRANSFER_MANIFEST_RESERVE: u64 = 4 * 1024 * 1024;
fn planned_transfer_payload_limit(transfer: u64, archive: u64, import: u64) -> u64 {
    transfer
        .min(archive)
        .min(import)
        .saturating_sub(RETAINED_SESSION_JSON_LIMIT)
        .saturating_sub(TRANSFER_MANIFEST_RESERVE)
        .saturating_sub(archive_objects::REFERENCE_METADATA_LIMIT)
        .saturating_sub(1024 * 1024)
}
fn retain_session_document_bytes(used: &mut u64, bytes: u64, limit: u64) -> Result<(), String> {
    if bytes > limit.saturating_sub(*used) {
        return Err(
            "retained session JSON quota exhausted; complete source remains on device".into(),
        );
    }
    *used = used
        .checked_add(bytes)
        .ok_or("retained session JSON byte overflow")?;
    Ok(())
}

async fn append_device_sessions_to_package_evidence(
    serial: &str,
    package: &str,
    evidence_root: &Path,
    group: Option<&capture_groups::Group>,
) -> Result<(), String> {
    let Some(group) = group else {
        session_budget::write(evidence_root.join("session-index.json"),serde_json::to_vec_pretty(&serde_json::json!({"schemaVersion":"mobilee.kernsight-package-sessions/v2","scope":"legacy-parent-unknown","includedSessions":[],"warning":"无父会话依据，未按包名推测或回放设备历史会话"})).map_err(|e|e.to_string())?).map_err(|e|e.to_string())?;
        return Ok(());
    };
    group.validate()?;
    if evidence_root.join("capture-group.json").exists()
        || evidence_root.join("session-report.json").exists()
        || evidence_root.join("session-index.json").exists()
        || evidence_root.join("sessions").exists()
    {
        return Err("Session 证据目标已有保留记录；请选新的导入目录，拒绝覆盖".into());
    }
    let group_bytes =
        session_budget::measure_json(&evidence_root.join("capture-group.json"), group)
            .map_err(|e| e.to_string())?;
    let mut retained_session_bytes = 0;
    retain_session_document_bytes(
        &mut retained_session_bytes,
        group_bytes,
        RETAINED_SESSION_JSON_LIMIT - RETAINED_SESSION_METADATA_RESERVE,
    )?;
    session_budget::write_json(evidence_root.join("capture-group.json"), group)
        .map_err(|e| e.to_string())?;
    let paths = runtime_paths_from_group(Some(group))?;
    let selected_ids = group.session_ids();
    if selected_ids.len() > 16 {
        return Err("parent references more than16 source sessions; finite intake did not replay; original parent references preserved".into());
    }
    let sessions_root = evidence_root.join("sessions");
    std::fs::create_dir_all(&sessions_root)
        .map_err(|error| format!("无法创建 Session 证据目录：{error}"))?;

    let mut aggregate = SessionReportBuilder::default();
    let mut aggregate_linker = LinkerObservations::default();
    let mut aggregate_perf_loss = perf_loss::PerfLoss::default();
    let mut included_ids = Vec::new();
    let mut matched_ids = Vec::new();
    let mut failures = Vec::new();
    for session_id in selected_ids.iter().copied() {
        let remote = runtime_paths::route(
            paths.as_ref(),
            &format!("{KSIGHT_SPOOL}/{session_id}/capture-relation.json"),
        )?;
        let relation_result = async {
            let result = run_device_root_script(
                serial,
                &format!("head -c 32769 {}", crate::shell_quote(&remote)),
            )
            .await?;
            if result.code != Some(0) || result.stdout.len() > 32768 {
                return Err("session 原始关联缺失/读取超预算，未回放".to_owned());
            }
            let note: Value = serde_json::from_str(&result.stdout)
                .map_err(|e| format!("session 原始关联无效：{e}"))?;
            capture_groups::verify_session_relation(group, session_id, &note)?;
            Ok::<_, String>(result.stdout)
        }
        .await;
        let relation_text = match relation_result {
            Ok(text) => text,
            Err(error) => {
                failures.push(serde_json::json!({"sessionId":session_id,"error":error}));
                continue;
            }
        };
        let events = match replay_session_events_bounded(
            serial,
            session_id,
            paths.as_ref(),
            Some(evidence_root),
        )
        .await
        {
            Ok(events) => events,
            Err(error) => {
                failures.push(serde_json::json!({
                    "sessionId": session_id,
                    "error": error,
                }));
                continue;
            }
        };
        let mut builder = SessionReportBuilder::default();
        let mut perf_loss = perf_loss::PerfLoss::default();
        for event in &events {
            builder.record(event);
            perf_loss.record(event);
        }
        let report = builder.finish();
        let belongs_to_package = report
            .processes
            .iter()
            .any(|process| process.package.as_deref() == Some(package))
            || events.iter().any(|event| {
                event
                    .header
                    .process
                    .packages
                    .iter()
                    .any(|candidate| candidate.package_name == package)
                    || event
                        .header
                        .process
                        .command_line
                        .as_deref()
                        .is_some_and(|command| {
                            command == package || command.starts_with(&format!("{package}:"))
                        })
            });
        if !belongs_to_package {
            failures.push(serde_json::json!({"sessionId":session_id,"error":"父会话引用的子 session 尚无匹配包身份事件；保留父引用，未猜归属"}));
        }
        let mut report = serde_json::to_value(report).map_err(|error| error.to_string())?;
        let mut linker = LinkerObservations::default();
        for event in &events {
            linker.record(event);
        }
        linker.augment(&mut report);
        perf_loss.augment(&mut report);
        let session_dir = sessions_root.join(session_id.to_string());
        let report_bytes =
            session_budget::measure_json(&session_dir.join("session-report.json"), &report)
                .map_err(|e| e.to_string())?;
        let event_bytes = session_budget::measure_json(&session_dir.join("events.json"), &events)
            .map_err(|e| e.to_string())?;
        let document_bytes = report_bytes
            .checked_add(event_bytes)
            .and_then(|n| n.checked_add(relation_text.len() as u64))
            .ok_or("retained session JSON byte overflow")?;
        if let Err(error) = retain_session_document_bytes(
            &mut retained_session_bytes,
            document_bytes,
            RETAINED_SESSION_JSON_LIMIT - RETAINED_SESSION_METADATA_RESERVE,
        ) {
            failures.push(serde_json::json!({"sessionId":session_id,"error":error,"sourceStatus":"complete original spool remains at source; no partial JSON written"}));
            continue;
        }
        std::fs::create_dir_all(&session_dir)
            .map_err(|error| format!("无法创建 Session {session_id} 目录：{error}"))?;
        session_budget::write_new_bytes(
            session_dir.join("capture-relation.json"),
            relation_text.as_bytes(),
        )
        .map_err(|e| format!("子 session 原始关联落盘失败：{e}"))?;
        let report_path = session_dir.join("session-report.json");
        let events_path = session_dir.join("events.json");
        session_budget::write_json(&report_path, &report)
            .map_err(|error| format!("无法保存 Session {session_id} 报告：{error}"))?;
        session_budget::write_json(&events_path, &events)
            .map_err(|error| format!("无法保存 Session {session_id} 事件：{error}"))?;
        included_ids.push(session_id.to_string());
        for event in &events {
            aggregate.record(event);
            aggregate_linker.record(event);
            aggregate_perf_loss.record(event);
        }
        matched_ids.push(session_id.to_string());
    }

    let mut aggregate_report = aggregate.finish();
    compact_session_report_for_ui(&mut aggregate_report);
    let mut aggregate_value =
        serde_json::to_value(aggregate_report).map_err(|error| error.to_string())?;
    aggregate_linker.augment(&mut aggregate_value);
    aggregate_perf_loss.augment(&mut aggregate_value);
    if let Some(object) = aggregate_value.as_object_mut() {
        object.insert(
            "execution_complete".into(),
            serde_json::json!(
                group.state == "succeeded"
                    && failures.is_empty()
                    && included_ids.len() == selected_ids.len()
            ),
        );
        object.insert(
            "mobilee_capture_execution_state".into(),
            serde_json::json!(group.state),
        );
        object.insert(
            "mobilee_source_sessions".into(),
            serde_json::json!(matched_ids),
        );
        object.insert(
            "mobilee_session_scope".into(),
            Value::String("explicit-parent-session-ids".into()),
        );
        object.insert(
            "mobilee_included_sessions".into(),
            serde_json::json!(included_ids),
        );
        object.insert(
            "mobilee_session_failures".into(),
            serde_json::json!(failures),
        );
    }
    let index = serde_json::json!({
        "schemaVersion": "mobilee.kernsight-package-sessions/v1",
        "package": package,
        "scannedSessions": selected_ids.len(),
        "includedSessions": included_ids,
        "matchedSessions": matched_ids,
        "failures": failures,
        "scope": "仅本主会话明确引用的子 session/attempt；不按包名混入其他轮次",
    });
    aggregate_value["mobilee_retained_session_json_limit"] =
        serde_json::json!(RETAINED_SESSION_JSON_LIMIT);
    aggregate_value["mobilee_retained_session_group_and_child_bytes"] =
        serde_json::json!(retained_session_bytes);
    let capture_text = format!(
        "package={package}\nincluded_sessions={}\nmatched_sessions={}\nfailed_sessions={}\n",
        included_ids.len(),
        matched_ids.len(),
        failures.len(),
    );
    let aggregate_bytes =
        session_budget::measure_json(&evidence_root.join("session-report.json"), &aggregate_value)
            .map_err(|e| e.to_string())?;
    let index_bytes =
        session_budget::measure_json(&evidence_root.join("session-index.json"), &index)
            .map_err(|e| e.to_string())?;
    let metadata_bytes = aggregate_bytes
        .checked_add(index_bytes)
        .and_then(|n| n.checked_add(capture_text.len() as u64))
        .ok_or("retained session metadata byte overflow")?;
    retain_session_document_bytes(
        &mut retained_session_bytes,
        metadata_bytes,
        RETAINED_SESSION_JSON_LIMIT,
    )?;
    session_budget::write_json(evidence_root.join("session-report.json"), &aggregate_value)
        .map_err(|e| format!("无法保存汇总 Session 报告：{e}"))?;
    session_budget::write_json(evidence_root.join("session-index.json"), &index)
        .map_err(|e| format!("无法保存 Session 索引：{e}"))?;
    session_budget::write_new_bytes(evidence_root.join("capture.txt"), capture_text.as_bytes())
        .map_err(|e| format!("无法保存采集摘要：{e}"))?;
    Ok(())
}

#[tauri::command]
pub async fn read_local_kernsight_evidence_file(
    root: String,
    package: String,
    relative_path: String,
    max_bytes: u64,
) -> Result<KernSightEvidenceFileContent, String> {
    validate_package(&package)?;
    validate_evidence_relative_path(&relative_path)?;
    if !(1..=1_048_576).contains(&max_bytes) {
        return Err("证据文件预览上限必须在 1 B 到 1 MiB 之间".into());
    }
    let root = PathBuf::from(root);
    let root_canonical = root
        .canonicalize()
        .map_err(|error| format!("本地证据根目录不可访问：{error}"))?;
    let path = root.join(&relative_path);
    let canonical = path
        .canonicalize()
        .map_err(|error| format!("本地证据文件不可访问：{error}"))?;
    if !canonical.starts_with(&root_canonical) || !canonical.is_file() {
        return Err("本地证据文件不在已导入目录内".into());
    }
    let file = File::open(&canonical).map_err(|error| format!("读取本地证据文件失败：{error}"))?;
    let size = file
        .metadata()
        .map_err(|error| format!("读取本地证据文件失败：{error}"))?
        .len();
    let mut bytes = Vec::with_capacity(max_bytes.min(size) as usize);
    std::io::Read::read_to_end(&mut std::io::Read::take(file, max_bytes), &mut bytes)
        .map_err(|error| format!("读取本地证据文件失败：{error}"))?;
    use base64::Engine as _;
    Ok(KernSightEvidenceFileContent {
        package,
        relative_path,
        bytes: size,
        truncated: size > max_bytes,
        encoding: "base64".into(),
        content: base64::engine::general_purpose::STANDARD.encode(&bytes),
    })
}

#[tauri::command]
pub async fn cleanup_kernsight_package_dump(serial: String, package: String) -> Result<(), String> {
    validate_serial(&serial)?;
    validate_package(&package)?;
    Err(
        "旧版按包名批量清理已停用：请使用有归属证明的父会话永久清理预览；无归属证明的旧目录保留"
            .into(),
    )
}

async fn directory_bytes(serial: &str, path: &str) -> Result<u64, String> {
    let output = run_device_root_script(serial, &format!("du -sk {path} 2>/dev/null")).await?;
    let kib = output
        .stdout
        .split_whitespace()
        .next()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(0);
    Ok(kib.saturating_mul(1024))
}

fn parse_mirror_burp(value: &str) -> Result<(String, u16), String> {
    let (host, port) = value.rsplit_once(':').ok_or("Burp 地址必须是 host:port")?;
    if host.is_empty()
        || !host
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
    {
        return Err("Burp host 包含不支持的字符".into());
    }
    let port = port
        .parse::<u16>()
        .map_err(|_| "Burp 端口无效".to_string())?;
    if port == 0 {
        return Err("Burp 端口无效".into());
    }
    Ok((host.to_owned(), port))
}

fn validate_serial(serial: &str) -> Result<(), String> {
    if serial.is_empty()
        || !serial
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-_.:".contains(&byte))
    {
        return Err("ADB serial 包含不支持的字符".into());
    }
    Ok(())
}

fn validate_package(package: &str) -> Result<(), String> {
    if package.is_empty()
        || !package
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_'))
    {
        return Err("Android package 名称包含不支持的字符".into());
    }
    Ok(())
}

fn validate_evidence_relative_path(path: &str) -> Result<(), String> {
    if path.is_empty()
        || path.starts_with('/')
        || path.contains('\\')
        || path.contains(':')
        || path
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
        || path.chars().any(char::is_control)
    {
        return Err("证据文件路径不符合 MobileE 案例容器规则".into());
    }
    Ok(())
}

fn read_bounded_text(path: &Path, max_bytes: u64) -> Result<String, String> {
    let metadata = path
        .metadata()
        .map_err(|error| format!("无法读取 {}：{error}", path.display()))?;
    if metadata.len() > max_bytes {
        return Err(format!(
            "{} 超过 {} MiB 读取上限",
            path.display(),
            max_bytes / 1024 / 1024
        ));
    }
    std::fs::read_to_string(path).map_err(|error| format!("无法读取 {}：{error}", path.display()))
}

fn local_tree_stats(
    root: &Path,
    max_files: u64,
) -> Result<(u64, u64, Vec<KernSightLocalEvidenceFile>), String> {
    let mut stack = vec![root.to_path_buf()];
    let mut files = 0_u64;
    let mut bytes = 0_u64;
    let mut catalog = Vec::new();
    while let Some(directory) = stack.pop() {
        for entry in std::fs::read_dir(&directory)
            .map_err(|error| format!("无法扫描 {}：{error}", directory.display()))?
        {
            let entry = entry.map_err(|error| format!("本地证据目录项无效：{error}"))?;
            if entry
                .file_type()
                .map_err(|error| error.to_string())?
                .is_symlink()
            {
                return Err("证据目录含符号链接；不会读取目录外内容".into());
            }
            let metadata = entry
                .metadata()
                .map_err(|error| format!("无法读取本地证据元数据：{error}"))?;
            if metadata.is_dir() {
                stack.push(entry.path());
            } else if metadata.is_file() {
                files = files.saturating_add(1);
                bytes = bytes.saturating_add(metadata.len());
                if files > max_files {
                    return Err(format!("本地证据超过 {max_files} 个文件的索引上限"));
                }
                let relative_path = entry
                    .path()
                    .strip_prefix(root)
                    .map_err(|_| "本地证据路径无法相对化")?
                    .to_string_lossy()
                    .replace('\\', "/");
                if validate_evidence_relative_path(&relative_path).is_ok() {
                    let category = relative_path
                        .split('/')
                        .next()
                        .unwrap_or("report")
                        .to_owned();
                    catalog.push(KernSightLocalEvidenceFile {
                        relative_path,
                        bytes: metadata.len(),
                        category,
                        memory_evidence: Vec::new(),
                        code_evidence: Vec::new(),
                    });
                }
            }
        }
    }
    // Window notes retain source/derived relationships. Old files get an empty list,
    // which the UI treats as unknown, never as successful or complete.
    let mut notes = Vec::new();
    for file in &catalog {
        if (file.relative_path.starts_with("runtime/plaintext/")
            || file.relative_path.starts_with("runtime/crypto-windows/"))
            && file.relative_path.ends_with(".json")
            && file.bytes <= 256 * 1024
        {
            if let Ok(bytes) = std::fs::read(root.join(&file.relative_path)) {
                if let Ok(mut value) = serde_json::from_slice::<Value>(&bytes) {
                    if matches!(
                        value["schema"].as_str(),
                        Some("kernsight.memory-window/v1" | "kernsight.memory-read/v1")
                    ) {
                        value["note_relative_path"] = Value::String(file.relative_path.clone());
                        notes.push((file.relative_path.clone(), value));
                    }
                }
            }
        }
    }
    for file in &mut catalog {
        for (note_path, value) in &notes {
            let parent = note_path
                .rsplit_once('/')
                .map(|(parent, _)| parent)
                .unwrap_or("");
            let refers = ["relative_path", "source_relative_path"].iter().any(|key| {
                value[*key]
                    .as_str()
                    .map(|name| {
                        !name.contains('/')
                            && !name.contains('\\')
                            && format!("{parent}/{name}") == file.relative_path
                    })
                    .unwrap_or(false)
            });
            if file.relative_path == *note_path || refers {
                file.memory_evidence.push(value.clone());
            }
        }
    }
    catalog.sort_by(|left, right| left.relative_path.cmp(&right.relative_path));
    Ok((files, bytes, catalog))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn linker_fixture(hit: bool, adapter: &str) -> Event {
        serde_json::from_value(serde_json::json!({
            "header": {"schema":{"major":1,"minor":30},"session_id":Uuid::nil(),
                "source_sequence":9007199254740993u64,"monotonic_ns":9007199254740995u64,
                "cpu":null,"process":{"key":{"boot_id":Uuid::nil(),"pid":42,"start_time_ns":0},
                    "tid":43,"tgid":42,"uid":1,"gid":1,"comm":"fixture","command_line":null,
                    "selinux_context":null,"packages":[]},"sensor":"integrity","mode":"inspect",
                "quality":{"confidence":"confirmed","truncated":false,"lost_before":0,"sample_one_in":1,"source":"fixture"}},
            "payload":{"type":"inspect_observation","data":{"adapter":adapter,"attached":true,"hit":hit,
                "library":"/system/bin/linker64","build_id":"abc","offset":32,"path_hint":"/data/app/lib.so",
                "detail":"actual hit","detectability_notice":"fixture"}}
        })).unwrap()
    }

    #[test]
    fn linker_observations_keep_actual_source_and_unknown_birth() {
        let mut rows = LinkerObservations::default();
        rows.record(&linker_fixture(false, "linker_so_load"));
        rows.record(&linker_fixture(true, "tls_ssl_write"));
        rows.record(&linker_fixture(true, "linker_so_load"));
        rows.record(&linker_fixture(true, "linker_so_load"));
        let mut report = serde_json::json!({"execution_complete":false});
        rows.augment(&mut report);
        assert_eq!(report["linker_observations"].as_array().unwrap().len(), 2);
        assert_eq!(
            report["linker_observations"][0]["source_sequence"],
            "9007199254740993"
        );
        assert_eq!(
            report["linker_observations"][0]["monotonic_ns"],
            "9007199254740995"
        );
        assert_eq!(report["linker_observations"][0]["birth_status"], "unknown");
        assert!(report["linker_observations"][0]["header_birth_ns"].is_null());
        assert_eq!(report["execution_complete"], false);
    }

    #[test]
    fn linker_observations_bound_rows_and_strings_without_unique_load_claim() {
        let mut event = linker_fixture(true, "linker_so_load");
        if let ksight_model::EventPayload::InspectObservation(row) = &mut event.payload {
            row.path_hint = Some("界".repeat(3000));
        }
        let mut rows = LinkerObservations::default();
        for _ in 0..LINKER_OBSERVATION_LIMIT + 7 {
            rows.record(&event);
        }
        let mut report = serde_json::json!({});
        rows.augment(&mut report);
        assert_eq!(
            report["linker_observations"].as_array().unwrap().len(),
            LINKER_OBSERVATION_LIMIT
        );
        assert_eq!(report["linker_observations_omitted"], 7);
        assert_eq!(
            report["linker_observations"][0]["path_hint"]
                .as_str()
                .unwrap()
                .chars()
                .count(),
            2048
        );
        assert_eq!(report["linker_observations"][0]["text_truncated"], true);
    }

    #[test]
    fn code_only_launch_is_owned_and_legacy_startup_is_separate() {
        let command = capture_launch_command(
            "ksightd capture --code-only".into(),
            true,
            true,
            true,
            false,
            Some("org.example.fixture"),
        )
        .unwrap();
        assert_eq!(command, "ksightd capture --code-only --launch-after-attach");
        assert_eq!(
            capture_launch_command(
                "capture".into(),
                false,
                true,
                true,
                false,
                Some("org.example.fixture")
            )
            .unwrap(),
            "capture --launch-after-attach"
        );
        for forbidden in ["sleep", "monkey", "force-stop", "&"] {
            assert!(!command.contains(forbidden));
        }
        assert!(capture_launch_command(
            "capture".into(),
            true,
            true,
            false,
            false,
            Some("org.example.fixture")
        )
        .is_err());
        assert!(capture_launch_command(
            "capture".into(),
            true,
            true,
            true,
            true,
            Some("org.example.fixture")
        )
        .is_err());
        assert_eq!(
            capture_launch_command("capture".into(), true, false, false, false, None).unwrap(),
            "capture"
        );
        assert!(capture_launch_command(
            "capture".into(),
            false,
            true,
            false,
            false,
            Some("org.example.fixture")
        )
        .unwrap()
        .contains("sleep 2"));
    }

    fn values(text: &str) -> HashMap<String, String> {
        parse_probe_output(text)
    }

    #[tokio::test]
    #[ignore = "requires explicit synthetic device evidence path; never connects to a device"]
    async fn synthetic_device_memory_evidence_import() {
        let root = PathBuf::from(
            std::env::var("ME_MEMORY_EVIDENCE_FIXTURE")
                .expect("explicit synthetic device fixture path"),
        );
        let scope: Value =
            serde_json::from_slice(&std::fs::read(root.join("device-probe-report.json")).unwrap())
                .unwrap();
        assert_eq!(
            scope["schema"],
            "kernsight.synthetic-memory-device-probe/v1"
        );
        assert_eq!(scope["global_scan"], false);
        assert_eq!(scope["real_app_operations"], 0);
        let bundle = import_kernsight_evidence_directory(root.to_string_lossy().into_owned())
            .await
            .unwrap();
        assert_eq!(bundle.package, "fixture.memory.evidence");
        assert!(bundle.total_bytes <= 65536);
        let notes: Vec<&Value> = bundle
            .files
            .iter()
            .filter(|file| file.relative_path.ends_with(".json"))
            .flat_map(|file| &file.memory_evidence)
            .collect();
        assert!(notes
            .iter()
            .any(|note| note["write_status"] == "write_failed"));
        assert!(notes.iter().any(|note| note["duplicate"] == true));
        assert!(notes
            .iter()
            .any(|note| note["read_status"] == "read_failed"));
        assert!(notes
            .iter()
            .any(|note| note["read"]["read_status"] == "short_read"));
        for file in &bundle.files {
            if file.relative_path.ends_with(".txt")
                && file.relative_path.starts_with("runtime/plaintext/")
            {
                assert!(!file.memory_evidence.is_empty());
            }
        }
        println!(
            "SYNTHETIC_IMPORTED_BUNDLE:{}",
            serde_json::to_string(&bundle).unwrap()
        );
    }

    #[test]
    fn memory_window_catalog_preserves_notes_and_legacy_unknown() {
        let root = std::env::temp_dir().join(format!("memory-catalog-{}", Uuid::new_v4()));
        let dir = root.join("runtime/plaintext");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("old.txt"), b"old").unwrap();
        std::fs::write(dir.join("raw.bin"), b"raw").unwrap();
        std::fs::write(dir.join("window.txt"), b"raw").unwrap();
        let note = serde_json::json!({"schema":"kernsight.memory-window/v1", "source_relative_path":"raw.bin", "relative_path":"window.txt", "write_status":"write_failed", "read":{"schema":"kernsight.memory-read/v1", "read_status":"short_read", "requested_bytes":8,"actual_bytes":3}});
        std::fs::write(
            dir.join("window-note.json"),
            serde_json::to_vec(&note).unwrap(),
        )
        .unwrap();
        let (_, _, files) = local_tree_stats(&root, 16).unwrap();
        assert!(files
            .iter()
            .find(|f| f.relative_path.ends_with("old.txt"))
            .unwrap()
            .memory_evidence
            .is_empty());
        for name in ["raw.bin", "window.txt", "window-note.json"] {
            let file = files
                .iter()
                .find(|f| f.relative_path.ends_with(name))
                .unwrap();
            assert_eq!(file.memory_evidence.len(), 1);
            assert_eq!(file.memory_evidence[0]["write_status"], "write_failed");
            assert_eq!(file.memory_evidence[0]["read"]["actual_bytes"], 3);
        }
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn recommends_development_for_root_btf_and_bpffs() {
        let probe = build_probe(
            "pixel".into(),
            values(
                "kernel_version=6.1\narchitecture=aarch64\nandroid_version=15\nsdk_version=35\nverified_boot_state=orange\nflash_locked=0\nselinux_status=Enforcing\nbtf=available\nbpffs=mounted\nsu_binary=available\nagent=missing\nunprivileged_bpf_disabled=2",
            ),
            true,
        );
        assert_eq!(probe.recommended_mode, "development");
        assert_eq!(probe.trust_level, "Dev Root");
        assert_eq!(probe.bpf_status, "Ready for Dev Probe");
    }

    #[test]
    fn keeps_unprivileged_stock_device_in_standard_mode() {
        let probe = build_probe(
            "stock".into(),
            values(
                "verified_boot_state=green\nflash_locked=1\nselinux_status=Enforcing\nbtf=available\nbpffs=mounted\nsu_binary=missing\nagent=missing",
            ),
            false,
        );
        assert_eq!(probe.recommended_mode, "standard");
        assert_eq!(probe.trust_level, "Integrity Unknown");
        assert!(probe.bpf_status.contains("Privilege Required"));
    }

    #[test]
    fn system_agent_is_only_a_candidate_until_handshake() {
        let probe = build_probe(
            "system".into(),
            values(
                "verified_boot_state=yellow\nflash_locked=1\nselinux_status=Enforcing\nbtf=available\nbpffs=mounted\nsu_binary=missing\nagent=system",
            ),
            false,
        );
        assert_eq!(probe.recommended_mode, "system");
        assert_eq!(probe.trust_level, "System Candidate");
        assert!(probe
            .warnings
            .iter()
            .any(|item| item.contains("仍需后续握手")));
    }

    #[test]
    fn extracts_capture_session_from_agent_output() {
        let expected = Uuid::parse_str("cd880779-f261-4bbf-898d-8a85591703c0").unwrap();
        let output = "ksightd 0.2.0 session=cd880779-f261-4bbf-898d-8a85591703c0 files=true";
        assert_eq!(extract_session_id(output), Some(expected));
    }

    #[test]
    fn reads_exact_agent_checksum_from_release_manifest() {
        let checksum = "3d01e8e58279a6df85323154b9c6d3db66ca02b428d292c0533d60f004e919f1";
        let manifest = format!(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  other.tar.gz\n{checksum}  ksightd-android-arm64\n"
        );
        assert_eq!(
            checksum_for_asset(&manifest, KSIGHT_RELEASE_ASSET).as_deref(),
            Some(checksum)
        );
        assert_eq!(checksum_for_asset(&manifest, "ksightd"), None);
    }

    #[test]
    fn rejects_malformed_release_checksum() {
        assert_eq!(
            checksum_for_asset("not-a-sha  ksightd-android-arm64", KSIGHT_RELEASE_ASSET),
            None
        );
    }

    #[test]
    fn parses_device_mirror_process_counts() {
        let status = parse_device_mirror_process_status("capture_count=1\npcap_count=2\n");
        assert_eq!(status.capture_count, 1);
        assert_eq!(status.pcap_count, 2);
    }

    #[test]
    fn mirror_log_keeps_diagnostics_and_omits_payload_values() {
        assert_eq!(
            sanitize_mirror_log("attached adapter offset=0x10").as_deref(),
            Some("attached adapter offset=0x10")
        );
        let line = sanitize_mirror_log("event pid=42 preview=private-value").unwrap();
        assert!(line.starts_with("event pid=42"));
        assert!(line.contains("载荷已从运行日志中省略"));
        assert!(!line.contains("private-value"));
    }

    #[test]
    fn mirror_coverage_distinguishes_capture_reassembly_and_delivery() {
        let mut logs = VecDeque::new();
        logs.push_back("network_connects=3 network_handshakes=1 observed_fragments=18 observed_bytes=4096 reconstructed_messages=0 reconstructed_requests=0 reconstructed_responses=0 delivered=0 delivery_failed=0 retry_pending=0 unknown_directions=2 buffered_bytes=4096".into());
        let waiting = mirror_coverage_from_logs(&logs, true);
        assert_eq!(waiting.observed_fragments, 18);
        assert_eq!(waiting.state, "unrecognized_stream");

        logs.push_back("network_connects=5 network_handshakes=2 observed_fragments=30 observed_bytes=8192 reconstructed_messages=4 reconstructed_requests=2 reconstructed_responses=2 delivered=2 delivery_failed=0 retry_pending=0 unknown_directions=0 buffered_bytes=0".into());
        let delivering = mirror_coverage_from_logs(&logs, true);
        assert_eq!(delivering.reconstructed_responses, 2);
        assert_eq!(delivering.delivered, 2);
        assert_eq!(delivering.state, "delivering");
    }

    #[tokio::test]
    async fn mee_round_trip_preserves_all_supported_evidence_paths() {
        let root = std::env::temp_dir().join(format!("mobilee-archive-test-{}", Uuid::new_v4()));
        let source = root.join("source");
        std::fs::create_dir_all(source.join("runtime/plaintext")).unwrap();
        std::fs::write(
            source.join("dump-report.json"),
            r#"{"package":"com.example.archive","dump_id":"dump-1","agent_version":"0.2.10"}"#,
        )
        .unwrap();
        std::fs::write(source.join("runtime/plaintext/sample.txt"), b"sample").unwrap();
        std::fs::create_dir_all(source.join("sessions/session-1")).unwrap();
        std::fs::write(source.join("sessions/session-1/events.json"), b"[]").unwrap();
        std::fs::write(source.join("sessions/session-1/session-report.json"), b"{}").unwrap();
        std::fs::write(source.join("session-index.json"), b"{}").unwrap();
        std::fs::write(source.join("capture.txt"), b"included_sessions=1\n").unwrap();
        std::fs::create_dir_all(source.join("dex-classification/01-business")).unwrap();
        std::fs::write(
            source.join("dex-classification/01-business/index.json"),
            b"{}",
        )
        .unwrap();
        std::fs::create_dir_all(source.join("runtime/packer-mem")).unwrap();
        std::fs::write(
            source.join("runtime/packer-mem/42-1000-[anon_v8].bin"),
            b"memory",
        )
        .unwrap();
        let archive = root.join("com.example.archive.mee");
        write_kernsight_evidence_archive(&source, &archive).unwrap();
        let bundle = import_kernsight_evidence_archive(archive.to_string_lossy().into_owned())
            .await
            .unwrap();
        assert_eq!(bundle.package, "com.example.archive");
        assert!(bundle
            .files
            .iter()
            .any(|file| file.relative_path == "runtime/plaintext/sample.txt"));
        assert!(bundle
            .files
            .iter()
            .any(|file| file.relative_path == "sessions/session-1/events.json"));
        assert!(bundle
            .files
            .iter()
            .any(|file| { file.relative_path == "dex-classification/01-business/index.json" }));
        assert!(bundle
            .files
            .iter()
            .any(|file| { file.relative_path == "runtime/packer-mem/42-1000-[anon_v8].bin" }));
        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_dir_all(
            Path::new(&bundle.root)
                .parent()
                .unwrap_or_else(|| Path::new(&bundle.root)),
        );
    }

    #[test]
    fn legacy_dex_sets_are_recataloged_with_class_level_ownership() {
        let semantic = serde_json::json!({
            "version": "039", "declared_file_size": 1024, "string_ids": 1,
            "type_ids": 1, "field_ids": 0, "method_ids": 1, "class_defs": 1,
            "class_descriptors": ["Lcom/tencent/wework/api/WWAPI;"],
            "class_descriptors_truncated": false, "method_names": [],
            "method_names_truncated": false, "method_prototypes": [],
            "method_prototypes_truncated": false, "api_strings": []
        });
        let mut report = serde_json::json!({
            "package": "com.example.product",
            "dex_sets": [{
                "sha256": "abc", "bytes": 1024,
                "canonical_relative_path": "readable-dex/classes2.dex",
                "sources": ["apk-dex"], "observations": [], "semantic": semantic
            }]
        });
        enrich_local_dex_ownership(&mut report, "com.example.product");
        assert_eq!(
            report["dex_ownership"]["entries"][0]["category"],
            "third_party_sdk"
        );
        assert_eq!(report["dex_ownership"]["third_party_sdks"], 1);
    }

    #[test]
    fn legacy_ownership_does_not_hide_exact_package_classes_in_mixed_dex() {
        let semantic = serde_json::json!({
            "version": "039", "declared_file_size": 1024, "string_ids": 4,
            "type_ids": 4, "field_ids": 0, "method_ids": 4, "class_defs": 4,
            "class_descriptors": [
                "Lcom/dlxx/mam/Internal/MainActivity;",
                "Lcom/tencent/wework/Api;",
                "Lcom/tencent/wework/Auth;",
                "Lcom/tencent/wework/Storage;"
            ],
            "class_descriptors_truncated": false, "method_names": [],
            "method_names_truncated": false, "method_prototypes": [],
            "method_prototypes_truncated": false, "api_strings": []
        });
        let mut report = serde_json::json!({
            "package": "com.dlxx.mam.Internal",
            "dex_sets": [{
                "sha256": "mixed", "bytes": 1024,
                "canonical_relative_path": "apk-dex/split/classes13.dex",
                "sources": ["apk-dex"], "observations": [], "semantic": semantic
            }],
            "dex_ownership": {
                "schema_version": "mobilee.kernsight-dex-ownership/v1",
                "package": "com.dlxx.mam.Internal",
                "entries": [{"category": "third_party_sdk"}]
            }
        });

        enrich_local_dex_ownership(&mut report, "com.dlxx.mam.Internal");

        assert_eq!(
            report["dex_ownership"]["schema_version"],
            "mobilee.kernsight-dex-ownership/v4"
        );
        assert_eq!(report["dex_ownership"]["entries"][0]["category"], "mixed");
        assert_eq!(report["dex_ownership"]["business_class_samples"], 1);
        assert_eq!(report["dex_ownership"]["business_dex_sets"], 1);
        let mut descriptors = vec![serde_json::json!("Lcom/tencent/wework/Api;")];
        descriptors.extend(std::iter::repeat_n(
            serde_json::json!("Lcom/dlxx/mam/Internal/MainActivity;"),
            99,
        ));
        report["dex_sets"][0]["semantic"]["class_descriptors"] = serde_json::json!(descriptors);
        report["dex_ownership"]["schema_version"] =
            serde_json::json!("mobilee.kernsight-dex-ownership/v3");
        enrich_local_dex_ownership(&mut report, "com.dlxx.mam.Internal");
        assert_eq!(report["dex_ownership"]["entries"][0]["category"], "mixed");
        assert_eq!(
            report["dex_ownership"]["entries"][0]["third_party_classes"],
            1
        );
        report["dex_sets"][0]["semantic"]["class_descriptors"] = serde_json::json!(["La/b/c;"]);
        report["dex_sets"][0]["sources"] = serde_json::json!(["memory-dex"]);
        report["dex_ownership"]["schema_version"] =
            serde_json::json!("mobilee.kernsight-dex-ownership/v3");
        enrich_local_dex_ownership(&mut report, "com.dlxx.mam.Internal");
        assert_eq!(report["dex_ownership"]["entries"][0]["category"], "unknown");
        assert_eq!(report["dex_ownership"]["entries"][0]["confidence"], 0);
    }
    #[cfg(unix)]
    #[tokio::test]
    async fn evidence_import_rejects_symlink_before_outside_content_read() {
        let root = std::env::temp_dir().join(format!("me-no-symlink-{}", Uuid::new_v4()));
        std::fs::create_dir(&root).unwrap();
        std::fs::write(
            root.join("dump-report.json"),
            r#"{"package":"com.example.app"}"#,
        )
        .unwrap();
        let outside = root.with_extension("outside-fixture");
        std::fs::write(&outside, b"synthetic only").unwrap();
        std::os::unix::fs::symlink(&outside, root.join("linked.dex")).unwrap();
        let error = import_kernsight_evidence_directory(root.to_string_lossy().into_owned())
            .await
            .err()
            .expect("symlink must be rejected");
        assert!(error.contains("符号链接"));
        std::fs::remove_dir_all(root).unwrap();
        std::fs::remove_file(outside).unwrap();
    }

    #[tokio::test]
    async fn bounded_directory_import_preserves_partial_scope_without_package_dump_success() {
        let root = std::env::temp_dir().join(format!("me-bounded-import-{}", Uuid::new_v4()));
        std::fs::create_dir(&root).unwrap();
        let bytes = vec![7_u8; 512];
        std::fs::write(root.join("range-00.bin"), &bytes).unwrap();
        let mut report = serde_json::json!({"schema":"kernsight.bounded-code/v1","identity":{"package":"com.example.app","pid":123},"status":"bounded_partial","total_budget_bytes":131072,"payload_bytes":512,"ranges":[{"relative_path":"range-00.bin","path":"/data/app/fixture/base.apk","start":4096,"end":8192,"admitted_bytes":1024,"unadmitted_bytes":3072,"retained_bytes":512,"sha256":format!("{:x}",Sha256::digest(&bytes)),"write_status":"retained","read":{"schema":"kernsight.memory-read/v1","requested_start":4096,"actual_start":4096,"requested_bytes":1024,"actual_bytes":512,"read_status":"short_read","read_error":null}}]});
        for _ in 0..8 {
            let n = serde_json::to_vec_pretty(&report).unwrap().len();
            report["total_persisted_file_bytes"] = serde_json::json!(n + 512);
        }
        std::fs::write(
            root.join("bounded-code-report.json"),
            serde_json::to_vec_pretty(&report).unwrap(),
        )
        .unwrap();
        let bundle = import_kernsight_evidence_directory(root.to_string_lossy().into_owned())
            .await
            .unwrap();
        assert_eq!(
            bundle.dump_report["schema_version"],
            "mobilee.bounded-code-adapter/v1"
        );
        assert_eq!(bundle.dump_report["bounded_code_local_size_matches"], true);
        assert!(
            bundle.dump_report.get("schema_version").unwrap()
                != "mobilee.kernsight-package-dump/v2"
        );
        assert!(bundle.dump_report.get("heap_read_failures").is_none());
        let note = &bundle
            .files
            .iter()
            .find(|file| file.relative_path == "range-00.bin")
            .unwrap()
            .code_evidence[0];
        assert_eq!(note["read"]["read_status"], "short_read");
        assert_eq!(note["local_content_status"], "complete_file_hash_verified");
        assert_eq!(note["unadmitted_bytes"], 3072);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    #[ignore = "requires explicit synthetic production APK fixture, never connects a device"]
    async fn synthetic_apk_member_production_import() {
        let path =
            std::env::var("ME_APK_MEMBER_FIXTURE").expect("explicit synthetic fixture required");
        let bundle = import_kernsight_evidence_directory(path).await.unwrap();
        assert_eq!(bundle.package, "com.ksight.synthetic");
        let ledger = &bundle.dump_report["local_storage_accounting"];
        assert_eq!(ledger["unverified_observations"], 0);
        assert!(ledger["verified_code_duplicate_bytes"].as_u64().unwrap() > 0);
        assert!(ledger["shared_inode_logical_bytes"].as_u64().unwrap() > 0);
        let notes = bundle
            .files
            .iter()
            .flat_map(|file| &file.code_evidence)
            .collect::<Vec<_>>();
        assert!(notes
            .iter()
            .any(|note| note["transformation"] == "repair_dex/v1"));
        assert!(notes
            .iter()
            .all(|note| note["local_content_status"] == "complete_file_hash_verified"));
        println!(
            "MEMBER_IMPORTED_BUNDLE:{}",
            serde_json::to_string(&bundle).unwrap()
        );
    }

    #[tokio::test]
    #[ignore = "requires explicit bounded Launcher code fixture, never connects a device"]
    async fn bounded_launcher_device_evidence_import() {
        let path = std::env::var("ME_BOUNDED_CODE_FIXTURE").expect("explicit fixture required");
        let bundle = import_kernsight_evidence_directory(path).await.unwrap();
        assert_eq!(bundle.package, "com.google.android.apps.nexuslauncher");
        assert!(bundle.total_bytes <= 131072);
        assert_eq!(bundle.dump_report["bounded_code_local_size_matches"], true);
        let evidence = bundle
            .files
            .iter()
            .flat_map(|file| &file.code_evidence)
            .collect::<Vec<_>>();
        assert!(!evidence.is_empty());
        assert!(evidence
            .iter()
            .all(|note| note["local_content_status"] == "complete_file_hash_verified"));
        println!(
            "BOUNDED_IMPORTED_BUNDLE:{}",
            serde_json::to_string(&bundle).unwrap()
        );
    }

    #[test]
    fn old_capture_ipc_defaults_stages_to_none_and_new_field_is_not_dropped() {
        let old: KernSightCaptureRequest = serde_json::from_value(
            serde_json::json!({"serial":"offline-fixture","durationSeconds":45}),
        )
        .unwrap();
        assert!(old.inspect_stages.is_none());
        assert!(!old.inspect_tls);
        assert!(!old.memory_all);
        let new: KernSightCaptureRequest = serde_json::from_value(serde_json::json!({"serial":"offline-fixture","durationSeconds":120,"inspectStages":"l0:15,l1:90,linker:15"})).unwrap();
        assert_eq!(new.inspect_stages.as_deref(), Some("l0:15,l1:90,linker:15"));
    }
}

pub(super) fn qualified_dump_sources(note: Option<&Value>, package: &str) -> Result<Value, String> {
    let q = note
        .and_then(|n| n.get("qualification"))
        .ok_or("前一阶段实例资格缺失，来源未知")?;
    if q["schema"] != "kernsight.qualified-source/v1" {
        return Err("旧资格 schema 不当作已验证".into());
    }
    let n = note.unwrap();
    if q["relation"] != n["relation"]
        || q["token"] != n["token"]
        || q["token"].as_str().is_none_or(str::is_empty)
        || q["source"] != "MetadataObserver physical pidfd lease"
    {
        return Err("资格回执不属于此前具体生产者".into());
    }
    let sources = q["sources"].as_array().ok_or("资格 sources 缺失")?;
    if sources.is_empty()
        || sources.len() > 32
        || sources.iter().any(|s| {
            s["package"] != package
                || s["pid"].as_u64().is_none_or(|v| v == 0)
                || s["birth_ns"].as_u64().is_none_or(|v| v == 0)
                || !s["uid"].is_u64()
                || !s["exec_id"].is_u64()
                || s["boot_id"].as_str().is_none_or(str::is_empty)
        })
    {
        return Err("具体实例来源不完整或跨包，未启动 dump".into());
    }
    Ok(q["sources"].clone())
}
fn validate_parent_lifecycle_capability(code: Option<i32>, text: &str) -> Result<(), String> {
    let note: Value =
        serde_json::from_str(text).map_err(|_| "parent 生命周期能力未知；未操作目标")?;
    if code != Some(0)
        || note["schema"] != "kernsight.code-capabilities/v1"
        || note["parent_lifecycle_supported"] != true
        || note["lifecycle_schema"] != "kernsight.capture-lifecycle/v1"
        || note["code_copy_pause"] != "forbidden"
    {
        return Err(
            "parent 生命周期能力未知或旧 agent 仅支持 code-only lease；未启动，不降级旧后台 shell"
                .into(),
        );
    }
    // Code qualification is a separate feature. Its current refusal cannot block ordinary parent stages.
    Ok(())
}
async fn require_runtime_paths(
    serial: &str,
    paths: Option<&runtime_paths::RuntimePaths>,
) -> Result<(), String> {
    if let Some(paths) = paths {
        paths.validate()?;
        let script = paths.route(&format!("{KSIGHT_AGENT} code-capabilities"))?;
        let out = run_device_root_script(serial, &script).await?;
        paths.check_capability(out.code, &out.stdout)?;
    }
    Ok(())
}
async fn require_parent_lifecycle_capability(
    serial: &str,
    paths: Option<&runtime_paths::RuntimePaths>,
) -> Result<(), String> {
    let out = run_device_root_script(
        serial,
        &runtime_paths::route(paths, &format!("{KSIGHT_AGENT} code-capabilities"))?,
    )
    .await?;
    validate_parent_lifecycle_capability(out.code, &out.stdout)
}
fn validate_code_scope_capability(code: Option<i32>, text: &str) -> Result<(), String> {
    let note: Value = serde_json::from_str(text).map_err(|_| "代码采集范围能力未知，未操作目标")?;
    if code != Some(0)
        || note["schema"] != "kernsight.code-capabilities/v1"
        || note["supported"] != true
    {
        return Err(format!(
            "代码一键范围门禁未通过；未 force-stop/启动/采样：{}",
            note["reason"].as_str().unwrap_or("旧 agent 或身份范围未知")
        ));
    }
    if note["lifecycle_schema"] != "kernsight.capture-lifecycle/v1"
        || note["code_copy_pause"] != "forbidden"
    {
        return Err("代码采集范围能力未知：父生命周期/无暂停合同未验证，未操作目标".into());
    }
    Ok(())
}
async fn require_code_scope_capability(
    serial: &str,
    paths: Option<&runtime_paths::RuntimePaths>,
) -> Result<(), String> {
    let out = run_device_root_script(
        serial,
        &runtime_paths::route(paths, &format!("{KSIGHT_AGENT} code-capabilities"))?,
    )
    .await?;
    validate_code_scope_capability(out.code, &out.stdout)
}
#[cfg(test)]
mod code_scope_gate_tests {
    use super::*;
    #[test]
    fn corrected_ordinary_parent_accepts_lifecycle_independent_of_code_gate_and_rejects_old_agent()
    {
        let current = serde_json::json!({"schema":"kernsight.code-capabilities/v1","supported":false,"parent_lifecycle_supported":true,"lifecycle_schema":"kernsight.capture-lifecycle/v1","code_copy_pause":"forbidden"}).to_string();
        validate_parent_lifecycle_capability(Some(0), &current).unwrap();
        assert!(validate_code_scope_capability(Some(0), &current).is_err());
        assert!(validate_parent_lifecycle_capability(Some(0), "{}").is_err());
        let old = serde_json::json!({"schema":"kernsight.code-capabilities/v1","supported":false,"lifecycle_schema":"kernsight.capture-lifecycle/v1","code_copy_pause":"forbidden"}).to_string();
        assert!(validate_parent_lifecycle_capability(Some(0), &old).is_err());
    }
    #[test]
    fn old_unknown_and_current_unverified_cannot_launch() {
        assert!(validate_code_scope_capability(Some(0), "{}").is_err());
        assert!(validate_code_scope_capability(Some(0),r#"{"schema":"kernsight.code-capabilities/v1","supported":false,"reason":"numeric TGID instance binding unverified"}"#).unwrap_err().contains("未 force-stop"));
        assert!(validate_code_scope_capability(
            Some(1),
            r#"{"schema":"kernsight.code-capabilities/v1","supported":true}"#
        )
        .is_err());
    }
}

fn retain_transport_partial(
    root: &Path,
    package: &str,
    group: &capture_groups::Group,
    note: &Value,
    error: &str,
) -> Result<(), String> {
    std::fs::create_dir_all(root).map_err(|e| e.to_string())?;
    let index=serde_json::to_vec(&serde_json::json!({"schema_version":"mobilee.kernsight-package-dump/v2","package":package,"dump_id":null,"collection_status":"partial","transport_partial":true,"source_parent_id":group.id,"artifacts":[],"warnings":["transport did not retain every declared path; raw partial files remain; source coverage unknown"]})).map_err(|e|e.to_string())?;
    let terminal=serde_json::to_vec(&serde_json::json!({"schema":"mobilee.transport-partial/v1","source_parent_id":group.id,"budget":note,"reason":error.chars().take(4096).collect::<String>(),"coverage":"partial","original_paths":"complete received paths preserved; incomplete stream filenames marked partial"})).map_err(|e|e.to_string())?;
    let full = serde_json::to_vec(group).map_err(|e| e.to_string())?;
    if index.len() + terminal.len() + full.len() > 65536 {
        return Err(format!(
            "终态 metadata 超64KiB；原始 partial 保留于 {}，未宣称可完整索引",
            root.display()
        ));
    }
    if !root.join("dump-report.json").exists() {
        std::fs::write(root.join("dump-report.json"), index).map_err(|e| e.to_string())?;
    }
    if !root.join("capture-group.json").exists() {
        std::fs::write(root.join("capture-group.json"), full).map_err(|e| e.to_string())?;
    }
    std::fs::write(
        root.join(format!("transport-partial-{}.json", Uuid::new_v4())),
        terminal,
    )
    .map_err(|e| e.to_string())
}
#[cfg(test)]
mod transfer_reference_tests {
    use super::*;
    #[test]
    fn production_transfer_reference_reuses_only_complete_actual_hash_and_keeps_sources() {
        let root = std::env::temp_dir().join(format!("transfer-ref-{}", Uuid::new_v4()));
        std::fs::create_dir(&root).unwrap();
        let mut a = vec![7_u8; 256];
        let mut b = a.clone();
        a[255] = 1;
        b[255] = 2;
        let source = root.join("source-a.bin");
        std::fs::write(&source, &a).unwrap();
        let hash = format!("{:x}", Sha256::digest(&a));
        assert!(
            reuse_verified_transfer(&source, &root.join("other-source.bin"), 256, &hash).unwrap()
        );
        assert!(!reuse_verified_transfer(
            &source,
            &root.join("different-tail.bin"),
            256,
            &format!("{:x}", Sha256::digest(&b))
        )
        .unwrap());
        assert!(
            !reuse_verified_transfer(&source, &root.join("truncated.bin"), 257, &hash).unwrap()
        );
        assert_eq!(std::fs::read(root.join("other-source.bin")).unwrap(), a);
        assert!(
            reuse_verified_transfer(&source, &root.join("other-source.bin"), 256, &hash).is_err()
        );
        std::fs::remove_dir_all(root).unwrap();
    }
}

#[cfg(test)]
mod partial_terminal_tests {
    use super::*;
    #[tokio::test]
    async fn exhausted_transfer_terminal_import_preserves_raw_and_unknown() {
        let root = std::env::temp_dir().join(format!("partial-import-{}", Uuid::new_v4()));
        std::fs::create_dir(&root).unwrap();
        std::fs::write(root.join("base.apk.partial"), b"raw prefix").unwrap();
        let g:capture_groups::Group=serde_json::from_value(serde_json::json!({"schema":"mobilee.capture-group/v1","id":Uuid::new_v4(),"serial":"fixture","package":"org.example.fixture","createdUnixMs":1,"cancelRequested":false,"unified":false,"state":"partial","base":{},"stages":(["l0","l1","dump","linker"].iter().map(|k|serde_json::json!({"id":Uuid::new_v4(),"key":k,"mode":"observe","durationSeconds":1,"launchAfterAttach":false,"required":true,"attempts":[]})).collect::<Vec<_>>())})).unwrap();
        retain_transport_partial(
            &root,
            &g.package,
            &g,
            &serde_json::json!({"partial":true,"admitted_write_bytes":0}),
            "output budget exhausted",
        )
        .unwrap();
        let result = import_kernsight_evidence_directory(root.to_string_lossy().into_owned())
            .await
            .unwrap();
        assert_eq!(result.dump_report["collection_status"], "partial");
        assert!(result.dump_report["dump_id"].is_null());
        assert_eq!(
            std::fs::read(root.join("base.apk.partial")).unwrap(),
            b"raw prefix"
        );
        assert!(
            result.session_report.unwrap()["mobilee_capture_source_status"]
                .as_str()
                .unwrap()
                .starts_with("unknown")
        );
        std::fs::remove_dir_all(root).unwrap();
    }
}

#[cfg(test)]
mod qualified_source_tests {
    use super::*;
    #[test]
    fn production_source_handoff_rejects_legacy_foreign_and_incomplete_receipts() {
        assert!(qualified_dump_sources(None, "p").is_err());
        assert!(qualified_dump_sources(Some(&serde_json::json!({"complete":true})), "p").is_err());
        let mut n = serde_json::json!({"relation":{"attempt_id":"a"},"token":"t","qualification":{"schema":"kernsight.qualified-source/v1","relation":{"attempt_id":"a"},"token":"t","source":"MetadataObserver physical pidfd lease","sources":[{"package":"p","pid":123,"uid":10001,"birth_ns":9,"exec_id":0,"boot_id":"b"}]}});
        assert!(qualified_dump_sources(Some(&n), "p").is_ok());
        assert!(qualified_dump_sources(Some(&n), "foreign").is_err());
        n["qualification"]["token"] = serde_json::json!("foreign");
        assert!(qualified_dump_sources(Some(&n), "p").is_err());
        n["qualification"]["token"] = serde_json::json!("t");
        n["qualification"]["sources"][0]
            .as_object_mut()
            .unwrap()
            .remove("birth_ns");
        assert!(qualified_dump_sources(Some(&n), "p").is_err());
    }
}

#[cfg(test)]
mod recovery_reliability_tests;

#[cfg(test)]
mod bounded_local_preview_tests {
    use super::*;
    #[tokio::test]
    async fn large_sparse_file_preview_preserves_total_size_prefix_and_truncation() {
        let root = std::env::temp_dir().join(format!("me-preview-{}", Uuid::new_v4()));
        std::fs::create_dir(&root).unwrap();
        let path = root.join("large.bin");
        std::fs::write(&path, b"abc").unwrap();
        File::options()
            .write(true)
            .open(&path)
            .unwrap()
            .set_len(3 * 1024 * 1024 * 1024)
            .unwrap();
        let result = read_local_kernsight_evidence_file(
            root.to_string_lossy().into_owned(),
            "com.example.app".into(),
            "large.bin".into(),
            3,
        )
        .await
        .unwrap();
        assert_eq!(result.bytes, 3 * 1024 * 1024 * 1024);
        assert!(result.truncated);
        assert_eq!(result.content, "YWJj");
        assert_eq!(result.encoding, "base64");
        std::fs::write(root.join("small.bin"), b"abc").unwrap();
        let result = read_local_kernsight_evidence_file(
            root.to_string_lossy().into_owned(),
            "com.example.app".into(),
            "small.bin".into(),
            10,
        )
        .await
        .unwrap();
        assert_eq!(result.bytes, 3);
        assert!(!result.truncated);
        assert_eq!(result.content, "YWJj");
        std::fs::remove_dir_all(root).unwrap();
    }
}

#[cfg(test)]
mod retained_transfer_plan_tests {
    use super::*;
    fn row(path: &str, hash: u8, bytes: u64) -> Value {
        serde_json::json!({"path":path,"sha256":format!("{hash:064x}"),"bytes":bytes})
    }
    #[test]
    fn transfer_plan_reserves_sessions_and_respects_smallest_later_phase() {
        let limit =
            planned_transfer_payload_limit(512 * 1024 * 1024, 256 * 1024 * 1024, 384 * 1024 * 1024);
        assert_eq!(limit, 163 * 1024 * 1024);
        assert_eq!(planned_transfer_payload_limit(1, 2, 3), 0);
        let mut used = 1;
        retain_session_document_bytes(&mut used, 9, 10).unwrap();
        assert_eq!(used, 10);
        assert!(retain_session_document_bytes(&mut used, 1, 10).is_err());
        assert_eq!(used, 10);
    }
    #[test]
    fn whole_content_aliases_share_quota_and_original_report_is_required() {
        let rows = vec![
            row("lib/big.so", 3, 100),
            row("dump-report.json", 1, 10),
            row("code-objects/a", 2, 50),
            row("apk-dex/a.dex", 2, 50),
            row("readable-dex/a.dex", 2, 50),
        ];
        let plan = retained_transfer_plan(&rows, Some(60)).unwrap();
        assert_eq!(plan.unique_bytes, 60);
        assert_eq!(plan.rows.len(), 4);
        assert_eq!(plan.omitted.len(), 1);
        assert_eq!(plan.omitted[0]["path"], "lib/big.so");
        assert!(retained_transfer_plan(&rows, Some(9)).is_err());
        let full = retained_transfer_plan(&rows, None).unwrap();
        assert_eq!(full.unique_bytes, 160);
        assert!(full.omitted.is_empty());
    }
    #[test]
    fn priorities_preserve_runtime_before_static_and_never_truncate_a_group() {
        let rows = vec![
            row("dump-report.json", 1, 1),
            row("runtime/current", 2, 20),
            row("code-objects/large", 3, 50),
            row("lib/small.so", 4, 5),
        ];
        let plan = retained_transfer_plan(&rows, Some(26)).unwrap();
        assert_eq!(plan.unique_bytes, 26);
        assert!(plan.rows.iter().any(|r| r["path"] == "runtime/current"));
        assert!(plan
            .omitted
            .iter()
            .any(|r| r["path"] == "code-objects/large"));
    }
    #[tokio::test]
    async fn large_plan_manifest_with_small_partial_note_imports_without_rewriting_source_report() {
        let root = std::env::temp_dir().join(format!("retained-plan-import-{}", Uuid::new_v4()));
        std::fs::create_dir(&root).unwrap();
        let original=br#"{"schema_version":"mobilee.kernsight-package-dump/v2","package":"org.example.fixture","collection_status":"partial","artifacts":[]}"#;
        session_budget::write_new_bytes(root.join("dump-report.json"), original).unwrap();
        let omitted = (0..2000)
            .map(|n| row(&format!("lib/omitted-{n:06}.so"), 2, 999))
            .collect::<Vec<_>>();
        session_budget::write_json(
            root.join("retained-transfer-plan-test.json"),
            &serde_json::json!({"omitted":omitted}),
        )
        .unwrap();
        assert!(
            std::fs::metadata(root.join("retained-transfer-plan-test.json"))
                .unwrap()
                .len()
                > 65536
        );
        session_budget::write_json(root.join("transport-partial-test.json"),&serde_json::json!({"complete":false,"planManifest":"retained-transfer-plan-test.json","omittedPathCount":2000,"reason":"quota; original source preserved"})).unwrap();
        let bundle = import_kernsight_evidence_directory(root.to_string_lossy().into_owned())
            .await
            .unwrap();
        assert_eq!(
            bundle.dump_report["mobilee_transport_status"]["complete"],
            false
        );
        assert_eq!(
            std::fs::read(root.join("dump-report.json")).unwrap(),
            original
        );
        std::fs::remove_dir_all(root).unwrap();
    }
}
