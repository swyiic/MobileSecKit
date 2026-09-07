use crate::{run_device_adb, run_device_root_script};
use ksight_core::{DumpArtifact, MergedDumpRef, SessionGraph, SessionReport, SessionReportBuilder};
use ksight_model::Event;
use ksight_protocol::{
    AgentStatus, DurableSessionSummary, GetStatus, Hello, ListSessions, Message, ReplayBatches,
    CURRENT_PROTOCOL,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tauri::State;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStdin, ChildStdout, Command};
use tokio::time::{timeout, Duration, Instant};
use uuid::Uuid;

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

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KernSightCaptureRequest {
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
        validate_serial(serial)?;
        let remote = format!("su -c \"{KSIGHT_AGENT} serve --spool-root {KSIGHT_SPOOL}\"");
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
    let (private_package_bytes, public_package_bytes) = tokio::join!(
        directory_bytes(&serial, KSIGHT_PACKAGES),
        directory_bytes(&serial, KSIGHT_PUBLIC_PACKAGES)
    );
    Ok(KernSightOverview {
        agent_version,
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
    let session_id = Uuid::parse_str(&session_id)
        .map_err(|error| format!("KernSight session UUID 无效：{error}"))?;
    let mut connection = KernSightConnection::connect(&serial).await?;
    let request_id = Uuid::new_v4();
    connection
        .send(&Message::ReplayBatches(ReplayBatches {
            request_id,
            session_id,
            after_batch_sequence: None,
        }))
        .await?;
    let mut builder = SessionReportBuilder::default();
    loop {
        match connection.receive().await? {
            Message::EventBatch(batch) if batch.session_id == session_id => {
                for event in &batch.events {
                    builder.record(event);
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
    Ok(KernSightSessionReport {
        session_id,
        report_schema: "mobilee.kernsight-session-report/v1".into(),
        report: serde_json::to_value(report).map_err(|error| error.to_string())?,
    })
}

#[tauri::command]
pub async fn cleanup_kernsight_session(serial: String, session_id: String) -> Result<(), String> {
    validate_serial(&serial)?;
    let session_id = Uuid::parse_str(&session_id)
        .map_err(|error| format!("KernSight session UUID 无效：{error}"))?;
    let session_path = format!("{KSIGHT_SPOOL}/{session_id}");
    let output = run_device_root_script(&serial, &format!("rm -rf {session_path}")).await?;
    if output.code == Some(0) {
        Ok(())
    } else {
        Err(if output.stderr.is_empty() {
            "清理 KernSight session 失败".into()
        } else {
            output.stderr
        })
    }
}

#[tauri::command]
pub async fn start_kernsight_capture(
    request: KernSightCaptureRequest,
) -> Result<KernSightCaptureResult, String> {
    validate_serial(&request.serial)?;
    if !(1..=300).contains(&request.duration_seconds) {
        return Err("采集时长必须在 1 到 300 秒之间".into());
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
    let mut capture_command = args.join(" ");
    if request.launch_after_attach {
        let Some(package) = package else {
            return Err("冷启动采集必须选择一个包".into());
        };
        capture_command = format!(
            "am force-stop {package}; (sleep 2; monkey -p {package} -c android.intent.category.LAUNCHER 1 >/dev/null 2>&1) & {capture_command}"
        );
    }
    let command_preview = capture_command.replace(KSIGHT_AGENT, "ksightd");
    let started_unix_ms = now_millis();

    let (stdout, stderr, exit_code) = if request.hide_debug {
        let wrapped = format!(
            "{KSIGHT_HIDE_DEBUG} {} {capture_command}",
            request.duration_seconds
        );
        let remote = format!("su -c \"{wrapped}\"");
        let output = Command::new("adb")
            .args(["-s", &request.serial, "shell", &remote])
            .kill_on_drop(true)
            .output()
            .await
            .map_err(|error| format!("无法启动 hide-debug 采集：{error}"))?;
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
        let remote = format!("su -c \"{capture_command}\"");
        let capture_timeout = Duration::from_secs(request.duration_seconds.saturating_add(30));
        let output = timeout(
            capture_timeout,
            Command::new("adb")
                .args(["-s", &request.serial, "shell", &remote])
                .kill_on_drop(true)
                .output(),
        )
        .await
        .map_err(|_| {
            "KernSight 采集超过预期时长；设备端 watchdog/lease 会保留完整性状态".to_string()
        })?
        .map_err(|error| format!("无法启动 KernSight 采集：{error}"))?;
        (
            String::from_utf8_lossy(&output.stdout).trim().to_string(),
            String::from_utf8_lossy(&output.stderr).trim().to_string(),
            output.status.code(),
        )
    };
    let session_id = extract_session_id(&format!("{stdout}\n{stderr}"))
        .or(read_last_session_id(&request.serial).await);
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
    let remote = format!("su -c \"{capture_command}\"");
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
    Ok(KernSightMirrorStatus {
        running: false,
        cleanup_pending: false,
        package: None,
        serial: None,
        detail: Some("设备端 ksightd、KernSight pcap 子进程与会话状态已完成清理".into()),
        logs: state.logs.lock().await.iter().cloned().collect(),
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
    Ok(KernSightMirrorStatus {
        running,
        cleanup_pending,
        package: state.package.lock().await.clone(),
        serial: known_serial,
        detail,
        logs: state.logs.lock().await.iter().cloned().collect(),
    })
}

#[tauri::command]
pub async fn dump_kernsight_package(
    serial: String,
    package: String,
    hide_debug: bool,
    prefer_live: bool,
) -> Result<KernSightCaptureResult, String> {
    validate_serial(&serial)?;
    validate_package(&package)?;
    let remote = format!("{KSIGHT_PACKAGES}/{package}");
    let live = if prefer_live {
        let pids = run_device_root_script(&serial, &format!("pidof {package}"))
            .await
            .ok()
            .map(|output| output.stdout)
            .unwrap_or_default();
        pids.split_whitespace()
            .any(|token| !token.is_empty() && token.bytes().all(|byte| byte.is_ascii_digit()))
    } else {
        false
    };
    let launch_flag = if live { "" } else { " --launch" };
    let mut dump = format!(
        "rm -rf {remote} && mkdir -p {remote} && {KSIGHT_AGENT} dump-package --package {package} --dest {remote}{launch_flag}"
    );
    if hide_debug {
        dump.push_str(" --hide-debug");
    }
    let command_preview = format!(
        "ksightctl device --serial {serial} pull-package --package {package}{launch_flag} --dest packages{}",
        if hide_debug { " --hide-debug" } else { "" }
    );
    let started_unix_ms = now_millis();
    let remote_shell = format!("su -c \"{dump}\"");
    let output = timeout(
        Duration::from_secs(600),
        Command::new("adb")
            .args(["-s", &serial, "shell", &remote_shell])
            .kill_on_drop(true)
            .output(),
    )
    .await
    .map_err(|_| "L2 dump 超过 10 分钟".to_string())?
    .map_err(|error| format!("无法启动 dump-package：{error}"))?;
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    if !output.status.success() {
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
    let mut connection = KernSightConnection::connect(serial).await?;
    let request_id = Uuid::new_v4();
    connection
        .send(&Message::ReplayBatches(ReplayBatches {
            request_id,
            session_id,
            after_batch_sequence: None,
        }))
        .await?;
    let mut events = Vec::new();
    loop {
        match connection.receive().await? {
            Message::EventBatch(batch) if batch.session_id == session_id => {
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
            if let Ok(value) = serde_json::from_str::<Value>(&document.stdout) {
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
    let size = run_device_root_script(&serial, &format!("stat -c %s {path} 2>/dev/null"))
        .await?
        .stdout
        .trim()
        .parse::<u64>()
        .map_err(|_| "证据文件不存在或无法读取大小".to_string())?;
    let output = run_device_root_script(
        &serial,
        &format!("head -c {max_bytes} {path} 2>/dev/null | base64"),
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

#[tauri::command]
pub async fn import_kernsight_evidence_directory(
    path: String,
) -> Result<KernSightLocalEvidenceBundle, String> {
    let root = PathBuf::from(path.trim());
    if !root.is_absolute() || !root.is_dir() {
        return Err("请选择包含 dump-report.json 的本地绝对目录".into());
    }
    let dump_path = root.join("dump-report.json");
    let dump_text = read_bounded_text(&dump_path, 64 * 1024 * 1024)?;
    let dump_report: Value = serde_json::from_str(&dump_text)
        .map_err(|error| format!("dump-report.json 无效：{error}"))?;
    let package = dump_report
        .get("package")
        .and_then(Value::as_str)
        .ok_or("dump-report.json 缺少 package")?
        .to_owned();
    validate_package(&package)?;
    let session_path = root.join("session-report.json");
    let session_report = if session_path.is_file() {
        Some(
            serde_json::from_str(&read_bounded_text(&session_path, 64 * 1024 * 1024)?)
                .map_err(|error| format!("session-report.json 无效：{error}"))?,
        )
    } else {
        None
    };
    let capture_text = std::fs::read_to_string(root.join("CAPTURE.txt")).unwrap_or_default();
    let (file_count, total_bytes, files) = local_tree_stats(&root, 50_000)?;
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

#[tauri::command]
pub async fn pull_kernsight_package_evidence(
    serial: String,
    package: String,
    destination: String,
) -> Result<KernSightLocalEvidenceBundle, String> {
    validate_serial(&serial)?;
    validate_package(&package)?;
    let destination = PathBuf::from(destination.trim());
    if !destination.is_absolute() {
        return Err("本地拉取目录必须是绝对路径".into());
    }
    std::fs::create_dir_all(&destination)
        .map_err(|error| format!("无法创建本地拉取目录：{error}"))?;
    let executable = resolve_ksightctl()?;
    let output = Command::new(&executable)
        .args([
            "device",
            "--serial",
            &serial,
            "pull-package",
            "--package",
            &package,
            "--launch",
            "--dest",
        ])
        .arg(&destination)
        .output()
        .await
        .map_err(|error| format!("无法启动 {}：{error}", executable.display()))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        return Err(format!("KernSight L2 拉取失败：{}{}", stderr, stdout));
    }
    import_kernsight_evidence_directory(destination.join(package).to_string_lossy().into_owned())
        .await
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
    let bytes =
        std::fs::read(&canonical).map_err(|error| format!("读取本地证据文件失败：{error}"))?;
    let size = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    let take = usize::try_from(max_bytes.min(size)).unwrap_or(bytes.len());
    use base64::Engine as _;
    Ok(KernSightEvidenceFileContent {
        package,
        relative_path,
        bytes: size,
        truncated: size > max_bytes,
        encoding: "base64".into(),
        content: base64::engine::general_purpose::STANDARD.encode(&bytes[..take]),
    })
}

#[tauri::command]
pub async fn cleanup_kernsight_package_dump(serial: String, package: String) -> Result<(), String> {
    validate_serial(&serial)?;
    validate_package(&package)?;
    let output = run_device_root_script(
        &serial,
        &format!("rm -rf {KSIGHT_PACKAGES}/{package} {KSIGHT_PUBLIC_PACKAGES}/{package}"),
    )
    .await?;
    if output.code == Some(0) {
        Ok(())
    } else {
        Err(if output.stderr.is_empty() {
            "清理 KernSight package dump 失败".into()
        } else {
            output.stderr
        })
    }
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
    let allowed_root = [
        "runtime/",
        "data-private/",
        "readable-dex/",
        "forensics/",
        "apk/",
        "apk-dex/",
        "lib/",
        "oat/",
        "assets/",
        "apk-assets/",
        "mapped/",
        "open/",
        "code-loader/",
        "data-cache/",
        "repaired/",
    ]
    .iter()
    .any(|prefix| path.starts_with(prefix))
        || matches!(
            path,
            "dump-report.json"
                | "session-report.json"
                | "session-report.txt"
                | "session.uuid"
                | "CAPTURE.txt"
                | "EVIDENCE.txt"
                | "HOWTO.txt"
        );
    if path.is_empty()
        || path.starts_with('/')
        || path
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
        || !allowed_root
        || !path.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'.' | b'_' | b'-' | b'+' | b'@')
        })
    {
        return Err("证据相对路径不在允许的 package dump 目录内".into());
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

fn resolve_ksightctl() -> Result<PathBuf, String> {
    if let Some(path) = std::env::var_os("KSIGHTCTL_PATH").map(PathBuf::from) {
        if path.is_file() {
            return Ok(path);
        }
    }
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    for candidate in [
        manifest.join("../../KernSight/target/release/ksightctl"),
        manifest.join("../../KernSight/target/debug/ksightctl"),
    ] {
        if candidate.is_file() {
            return Ok(candidate);
        }
    }
    if let Some(paths) = std::env::var_os("PATH") {
        for directory in std::env::split_paths(&paths) {
            let candidate = directory.join("ksightctl");
            if candidate.is_file() {
                return Ok(candidate);
            }
        }
    }
    Err("找不到 ksightctl。请构建 KernSight release，或设置 KSIGHTCTL_PATH".into())
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
                    });
                }
            }
        }
    }
    catalog.sort_by(|left, right| left.relative_path.cmp(&right.relative_path));
    Ok((files, bytes, catalog))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn values(text: &str) -> HashMap<String, String> {
        parse_probe_output(text)
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
}
