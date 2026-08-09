//! Optional, local-only analysis tools.  This module deliberately exposes
//! diagnostics and user-provided Frida scripts; it does not ship bypass or
//! secret-extraction payloads.

use crate::{
    ensure_success, run_adb, run_device_adb, run_device_root, run_device_root_script, RawOutput,
    ADB_TIMEOUT,
};
use regex::Regex;
use serde::{Deserialize, Serialize};
use sha1::{Digest, Sha1};
use sha2::Sha256;
use std::collections::HashSet;
use std::process::Command as StdCommand;
use std::{
    fs::{self, File},
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::OnceLock,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    process::Command,
    time::{sleep, timeout},
};
use zip::{write::SimpleFileOptions, ZipArchive, ZipWriter};

fn push_path(paths: &mut Vec<PathBuf>, value: impl Into<PathBuf>) {
    let value = value.into();
    if value.is_dir() && !paths.iter().any(|existing| existing == &value) {
        paths.push(value);
    }
}

pub fn initialize_host_environment(directory: Option<&Path>) -> Result<String, String> {
    let mut paths = Vec::new();
    if let Some(directory) = directory {
        push_path(&mut paths, directory);
    }
    let home = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from);
    if let Some(home) = &home {
        for path in [
            home.join(".pyenv/shims"),
            home.join(".pyenv/bin"),
            home.join("Library/Android/sdk/platform-tools"),
            home.join("Android/Sdk/platform-tools"),
            home.join("Library/Python/3.13/bin"),
            home.join("Library/Python/3.12/bin"),
            home.join("Library/Python/3.11/bin"),
            home.join("Library/Python/3.10/bin"),
            home.join("AppData/Local/Android/Sdk/platform-tools"),
            home.join("AppData/Roaming/Python/Python313/Scripts"),
            home.join("AppData/Roaming/Python/Python312/Scripts"),
            home.join("AppData/Roaming/Python/Python311/Scripts"),
        ] {
            push_path(&mut paths, path);
        }
    }
    for path in [
        "/opt/homebrew/bin",
        "/opt/homebrew/sbin",
        "/usr/local/bin",
        "/usr/local/sbin",
        "/Library/Apple/usr/bin",
    ] {
        push_path(&mut paths, path);
    }
    #[cfg(unix)]
    {
        let shell = std::env::var("SHELL").unwrap_or_else(|_| "/bin/zsh".into());
        if let Ok(output) = StdCommand::new(shell)
            .args(["-lic", "printf '%s' \"$PATH\""])
            .output()
        {
            let login_path = String::from_utf8_lossy(&output.stdout);
            let login_path = std::ffi::OsString::from(login_path.as_ref());
            for path in std::env::split_paths(&login_path) {
                push_path(&mut paths, path);
            }
        }
    }
    if let Some(existing) = std::env::var_os("PATH") {
        for path in std::env::split_paths(&existing) {
            push_path(&mut paths, path);
        }
    }
    let joined =
        std::env::join_paths(&paths).map_err(|error| format!("合并 PATH 失败：{error}"))?;
    std::env::set_var("PATH", &joined);
    Ok(joined.to_string_lossy().into_owned())
}

#[tauri::command]
pub fn configure_host_environment(directory: Option<String>) -> Result<String, String> {
    initialize_host_environment(
        directory
            .as_deref()
            .filter(|value| !value.trim().is_empty())
            .map(Path::new),
    )
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ToolStatus {
    pub name: String,
    pub executable: String,
    pub available: bool,
    pub version: Option<String>,
    pub path: Option<String>,
    pub category: String,
    pub group: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EnvironmentReport {
    pub host_os: String,
    pub host_arch: String,
    pub tools: Vec<ToolStatus>,
    pub device_frida_version: Option<String>,
    pub device_frida_reachable: bool,
    pub device_frida_requires_developer_image: bool,
    pub device_architecture: Option<String>,
    pub recommended_frida_server: Option<String>,
    pub frida_version_match: Option<bool>,
    pub host_frida_tools_match: Option<bool>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EnvironmentRequest {
    pub serial: Option<String>,
    pub platform: Option<String>,
    pub tool_directory: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AdvancedCommandResult {
    pub success: bool,
    pub command: String,
    pub output: String,
    pub exit_code: Option<i32>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ShellRequest {
    pub serial: String,
    pub command: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProxyRequest {
    pub serial: String,
    pub action: String,
    pub host: Option<String>,
    pub port: Option<u16>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CertificateInfo {
    pub path: String,
    pub subject_hash: String,
    pub sha256: String,
    pub system_target: String,
    pub note: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CertificateRequest {
    pub serial: String,
    pub path: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FridaProcess {
    pub pid: Option<u32>,
    pub name: String,
    pub identifier: String,
    pub platform: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FridaScriptRequest {
    pub serial: Option<String>,
    pub process: String,
    pub pid: Option<u32>,
    pub script: String,
    pub mode: String,
    pub script_path: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DexDumpRequest {
    pub serial: String,
    pub package: String,
    pub script_path: String,
    pub destination_directory: Option<String>,
    pub duration_seconds: Option<u64>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SoDumpRequest {
    pub serial: String,
    pub package: String,
    pub script_path: String,
    pub destination_directory: Option<String>,
    pub duration_seconds: Option<u64>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IosDumpRequest {
    pub serial: String,
    pub bundle_id: String,
    pub destination_directory: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FridaScriptEntry {
    pub id: String,
    pub name: String,
    pub description: String,
    pub category: String,
    pub path: String,
    pub platform: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FridaServerRequest {
    pub serial: String,
    pub action: String,
    pub path: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FridaDownloadRequest {
    pub serial: String,
    pub destination_directory: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IosDeveloperImageRequest {
    pub serial: String,
    pub directory: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AppFinding {
    pub severity: String,
    pub title: String,
    pub detail: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProtectionAssessment {
    pub status: String,
    pub packers: Vec<String>,
    pub indicators: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AnalyzeAppRequest {
    pub path: String,
    pub apktool_path: Option<String>,
    pub jadx_path: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SensitiveItem {
    pub item: String,
    pub location: String,
    pub kind: String,
    pub severity: String,
    pub value: Option<String>,
    pub line_number: Option<usize>,
    pub context: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AppAnalysis {
    pub platform: String,
    pub path: String,
    pub file_name: String,
    pub file_size: u64,
    pub package_id: Option<String>,
    pub display_name: Option<String>,
    pub version_name: Option<String>,
    pub version_code: Option<String>,
    pub min_sdk: Option<String>,
    pub target_sdk: Option<String>,
    pub architectures: Vec<String>,
    pub frameworks: Vec<String>,
    pub third_party_libraries: Vec<String>,
    pub protection: ProtectionAssessment,
    pub permissions: Vec<String>,
    pub components: Vec<String>,
    pub exported_components: Vec<String>,
    pub intent_filters: Vec<String>,
    pub manifest_flags: Vec<String>,
    pub files: Vec<String>,
    pub manifest_xml: Option<String>,
    pub sensitive_items: Vec<SensitiveItem>,
    pub signature: Option<String>,
    pub findings: Vec<AppFinding>,
    pub tools_used: Vec<String>,
    pub missing_dependencies: Vec<String>,
}

fn executable_path(name: &str) -> Option<String> {
    std::env::var_os("PATH").and_then(|path| {
        std::env::split_paths(&path).find_map(|directory| {
            let candidate = directory.join(name);
            candidate
                .is_file()
                .then(|| candidate.to_string_lossy().into_owned())
        })
    })
}

fn cohesive_frida_executable_path(name: &str) -> Option<String> {
    if name != "frida" && name.starts_with("frida-") {
        if let Some(frida) = executable_path("frida") {
            let sibling = Path::new(&frida).parent()?.join(name);
            if sibling.is_file() {
                return Some(sibling.to_string_lossy().into_owned());
            }
        }
    }
    executable_path(name)
}

fn executable_path_in(name: &str, directory: Option<&Path>) -> Option<String> {
    directory
        .filter(|path| path.is_dir())
        .map(|path| path.join(name))
        .filter(|path| path.is_file())
        .map(|path| path.to_string_lossy().into_owned())
        .or_else(|| cohesive_frida_executable_path(name))
}

async fn run_host(program: &str, args: &[String]) -> Result<RawOutput, String> {
    let executable = cohesive_frida_executable_path(program)
        .ok_or_else(|| format!("未找到 {program}，请先安装对应工具"))?;
    let mut command = Command::new(executable);
    command.args(args).kill_on_drop(true);
    let output = timeout(ADB_TIMEOUT, command.output())
        .await
        .map_err(|_| format!("{program} 操作超时"))?
        .map_err(|error| format!("启动 {program} 失败：{error}"))?;
    Ok(RawOutput {
        stdout: String::from_utf8_lossy(&output.stdout).trim().to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
        code: output.status.code(),
    })
}

fn scan_decoded_directory(root: &Path, prefix: &str) -> Vec<SensitiveItem> {
    let mut items = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    let mut scanned = 0usize;
    while let Some(directory) = stack.pop() {
        let Ok(entries) = fs::read_dir(&directory) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                if stack.len() < 256 {
                    stack.push(path);
                }
                continue;
            }
            if scanned >= 2500 {
                break;
            }
            let extension = path
                .extension()
                .and_then(|value| value.to_str())
                .unwrap_or_default()
                .to_ascii_lowercase();
            if !matches!(
                extension.as_str(),
                "java"
                    | "kt"
                    | "smali"
                    | "xml"
                    | "json"
                    | "js"
                    | "txt"
                    | "properties"
                    | "yaml"
                    | "yml"
            ) {
                continue;
            }
            let Ok(metadata) = fs::metadata(&path) else {
                continue;
            };
            if metadata.len() > 3 * 1024 * 1024 {
                continue;
            }
            if let Ok(text) = fs::read_to_string(&path) {
                let relative = path.strip_prefix(root).unwrap_or(&path).to_string_lossy();
                scan_sensitive_text(&text, &format!("{prefix}:{relative}"), &mut items);
                scanned += 1;
            }
        }
    }
    items
}

async fn run_configured_static_tool(
    apk: &str,
    tool: &str,
    kind: &str,
) -> Result<Vec<SensitiveItem>, String> {
    let output_dir =
        std::env::temp_dir().join(format!("security-console-{}-{kind}-scan", now_millis()));
    let args = if kind == "apktool" {
        vec![
            "d".into(),
            "-f".into(),
            "--no-src".into(),
            "-o".into(),
            output_dir.to_string_lossy().into_owned(),
            apk.into(),
        ]
    } else {
        vec![
            "-q".into(),
            "-d".into(),
            output_dir.to_string_lossy().into_owned(),
            apk.into(),
        ]
    };
    let output = run_explicit_program(Path::new(tool), &args).await?;
    if output.code != Some(0) {
        let _ = fs::remove_dir_all(&output_dir);
        return Err(output_text(&output));
    }
    let items = scan_decoded_directory(&output_dir, kind);
    let _ = fs::remove_dir_all(&output_dir);
    Ok(items)
}

async fn run_explicit_program(program: &Path, args: &[String]) -> Result<RawOutput, String> {
    if !program.is_file() {
        return Err(format!("工具路径不存在：{}", program.display()));
    }
    let mut command = if program.extension().and_then(|value| value.to_str()) == Some("jar") {
        let mut command = Command::new("java");
        command.arg("-jar").arg(program);
        command
    } else {
        Command::new(program)
    };
    command.args(args).kill_on_drop(true);
    let output = timeout(Duration::from_secs(180), command.output())
        .await
        .map_err(|_| "分析工具操作超时".to_string())?
        .map_err(|error| format!("启动分析工具失败：{error}"))?;
    Ok(RawOutput {
        stdout: String::from_utf8_lossy(&output.stdout).trim().to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
        code: output.status.code(),
    })
}

async fn run_host_at(
    program: &str,
    args: &[String],
    directory: Option<&Path>,
) -> Result<RawOutput, String> {
    let executable = executable_path_in(program, directory)
        .ok_or_else(|| format!("未找到 {program}，请先安装对应工具"))?;
    let mut command = Command::new(executable);
    command.args(args).kill_on_drop(true);
    let output = timeout(ADB_TIMEOUT, command.output())
        .await
        .map_err(|_| format!("{program} 操作超时"))?
        .map_err(|error| format!("启动 {program} 失败：{error}"))?;
    Ok(RawOutput {
        stdout: String::from_utf8_lossy(&output.stdout).trim().to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
        code: output.status.code(),
    })
}

fn output_text(output: &RawOutput) -> String {
    match (output.stdout.is_empty(), output.stderr.is_empty()) {
        (false, false) => format!("{}\n{}", output.stdout, output.stderr),
        (false, true) => output.stdout.clone(),
        (true, false) => output.stderr.clone(),
        (true, true) => String::new(),
    }
}

async fn tool_status_at(
    label: &str,
    name: &str,
    category: &str,
    version_args: &[&str],
    directory: Option<&Path>,
) -> ToolStatus {
    let path = executable_path_in(name, directory);
    let version = if path.is_some() {
        let args: Vec<String> = version_args.iter().map(|value| (*value).into()).collect();
        run_host_at(name, &args, directory)
            .await
            .ok()
            .map(|output| {
                output_text(&output)
                    .lines()
                    .next()
                    .unwrap_or_default()
                    .to_string()
            })
            .filter(|value| !value.is_empty())
    } else {
        None
    };
    ToolStatus {
        name: label.into(),
        executable: name.into(),
        available: path.is_some(),
        version,
        path,
        category: category.into(),
        group: if matches!(
            name,
            "adb"
                | "frida"
                | "frida-ps"
                | "python3"
                | "curl"
                | "xz"
                | "idevice_id"
                | "ideviceinfo"
                | "iproxy"
                | "ideviceimagemounter"
        ) {
            "frida".into()
        } else {
            "analyzer".into()
        },
    }
}

#[tauri::command]
pub async fn inspect_environment(request: EnvironmentRequest) -> Result<EnvironmentReport, String> {
    let definitions: [(&str, &str, &[&str]); 24] = [
        ("ADB", "adb", &["version"]),
        ("Frida CLI", "frida", &["--version"]),
        ("Frida process scanner", "frida-ps", &["--version"]),
        ("Python runtime", "python3", &["--version"]),
        ("Download client", "curl", &["--version"]),
        ("XZ decompressor", "xz", &["--version"]),
        ("Java runtime", "java", &["-version"]),
        ("AAPT", "aapt", &["version"]),
        ("Apk Analyzer", "apkanalyzer", &["version"]),
        ("APK signer", "apksigner", &["--version"]),
        ("JADX", "jadx", &["--version"]),
        ("Apktool", "apktool", &["--version"]),
        ("Drozer", "drozer", &["--version"]),
        ("MobSF scanner", "mobsfscan", &["--version"]),
        ("APKLeaks", "apkleaks", &["--version"]),
        ("iOS device tools", "idevice_id", &["--version"]),
        ("iOS device info", "ideviceinfo", &["--version"]),
        ("iOS port forward", "iproxy", &["--version"]),
        ("iOS installer", "ideviceinstaller", &["--version"]),
        ("iOS filesystem", "ifuse", &["--version"]),
        ("iOS Developer Image", "ideviceimagemounter", &["--version"]),
        ("AXMLPrinter", "axmlprinter", &["--help"]),
        ("AXML decoder", "axml", &["--help"]),
        ("OpenSSL", "openssl", &["version"]),
    ];
    let mut tools = Vec::with_capacity(definitions.len());
    for (name, executable, args) in definitions {
        let category = matches!(
            executable,
            "adb"
                | "openssl"
                | "idevice_id"
                | "ideviceinfo"
                | "iproxy"
                | "ideviceinstaller"
                | "ideviceimagemounter"
        )
        .then_some("system")
        .unwrap_or("optional");
        tools.push(
            tool_status_at(
                name,
                executable,
                category,
                args,
                request.tool_directory.as_deref().map(Path::new),
            )
            .await,
        );
    }
    let (
        device_frida_version,
        device_architecture,
        device_frida_reachable,
        requires_developer_image,
    ) = if let Some(serial) = request.serial {
        let is_ios = request.platform.as_deref() == Some("ios");
        let architecture = if is_ios {
            Some("arm64 / Apple mobile".into())
        } else {
            run_device_adb(&serial, &["shell", "getprop", "ro.product.cpu.abi"])
                .await
                .ok()
                .map(|output| output_text(&output))
                .filter(|value| !value.is_empty())
        };
        let frida_version = if is_ios {
            None
        } else {
            run_device_root(&serial, &["/data/local/tmp/frida-server", "--version"])
                .await
                .ok()
                .map(|output| output_text(&output))
                .filter(|value| !value.is_empty())
        };
        let probe_args = vec!["-D".into(), serial, "-ai".into()];
        let (reachable, requires_image) = match run_host("frida-ps", &probe_args).await {
            Ok(output) => {
                let message = output_text(&output).to_ascii_lowercase();
                (
                    output.code == Some(0) || message.contains("developer disk image"),
                    message.contains("developer disk image"),
                )
            }
            Err(_) => (false, false),
        };
        (frida_version, architecture, reachable, requires_image)
    } else {
        (None, None, false, false)
    };
    let host_frida_version = tools
        .iter()
        .find(|tool| tool.executable == "frida")
        .and_then(|tool| tool.version.clone());
    let host_frida_ps_version = tools
        .iter()
        .find(|tool| tool.executable == "frida-ps")
        .and_then(|tool| tool.version.clone());
    let host_frida_tools_match = host_frida_version
        .as_ref()
        .zip(host_frida_ps_version.as_ref())
        .map(|(cli, scanner)| cli.trim() == scanner.trim());
    let recommended_frida_server = device_architecture.as_deref().map(|abi| {
        if abi.contains("x86_64") {
            "frida-server-android-x86_64"
        } else if abi.contains("x86") {
            "frida-server-android-x86"
        } else if abi.contains("arm64") {
            "frida-server-android-arm64"
        } else {
            "frida-server-android-arm"
        }
        .into()
    });
    let frida_version_match = device_frida_version
        .as_ref()
        .zip(host_frida_version.as_ref())
        .map(|(device, host)| device.trim() == host.trim());
    Ok(EnvironmentReport {
        host_os: std::env::consts::OS.into(),
        host_arch: std::env::consts::ARCH.into(),
        tools,
        device_frida_version,
        device_frida_reachable,
        device_frida_requires_developer_image: requires_developer_image,
        device_architecture,
        recommended_frida_server,
        frida_version_match,
        host_frida_tools_match,
    })
}

#[tauri::command]
pub async fn run_shell(request: ShellRequest) -> Result<AdvancedCommandResult, String> {
    let command = request.command.trim();
    if command.is_empty() || command.len() > 8_192 {
        return Err("Shell 命令不能为空，且不能超过 8192 个字符".into());
    }
    let output = run_device_root_script(&request.serial, command).await?;
    Ok(AdvancedCommandResult {
        success: output.code == Some(0),
        command: format!("adb -s {} shell su -c <command>", request.serial),
        output: output_text(&output),
        exit_code: output.code,
    })
}

fn validate_proxy_host(host: &str) -> Result<(), String> {
    if host.is_empty()
        || host.len() > 253
        || !host
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || ".:-_".contains(character))
    {
        Err("代理地址只能包含 IP、域名和端口字符".into())
    } else {
        Ok(())
    }
}

#[tauri::command]
pub async fn run_proxy(request: ProxyRequest) -> Result<AdvancedCommandResult, String> {
    let action = request.action.as_str();
    let host = request.host.unwrap_or_default();
    let port = request.port.unwrap_or_default();
    let output = match action {
        "set" => {
            validate_proxy_host(&host)?;
            if port == 0 {
                return Err("代理端口必须在 1-65535 之间".into());
            }
            let value = format!("{host}:{port}");
            run_device_root(
                &request.serial,
                &["settings", "put", "global", "http_proxy", &value],
            )
            .await?
        }
        "clear" => {
            run_device_root(
                &request.serial,
                &["settings", "delete", "global", "http_proxy"],
            )
            .await?
        }
        "transparent_set" | "transparent_clear" => {
            validate_proxy_host(&host)?;
            if port == 0 {
                return Err("透明代理端口必须在 1-65535 之间".into());
            }
            let rule_80 =
                format!("OUTPUT -p tcp --dport 80 -j DNAT --to-destination {host}:{port}");
            let rule_443 =
                format!("OUTPUT -p tcp --dport 443 -j DNAT --to-destination {host}:{port}");
            let script = if action == "transparent_set" {
                format!(
                    r#"if [ "$(id -u)" != "0" ]; then echo "Root 未生效，请在 Magisk/KernelSU 中授权本工具" >&2; exit 126; fi
command -v iptables >/dev/null 2>&1 || {{ echo "设备缺少 iptables" >&2; exit 127; }}
echo "Root UID=$(id -u), SELinux=$(getenforce 2>/dev/null || echo unknown)"
for rule in '{rule_80}' '{rule_443}'; do
  if iptables -t nat -C $rule >/dev/null 2>&1; then
    echo "规则已存在: $rule"
  else
    iptables -t nat -A $rule || exit $?
    echo "规则已添加: $rule"
  fi
done
echo "当前 OUTPUT 透明代理规则:"
iptables -t nat -S OUTPUT"#
                )
            } else {
                format!(
                    r#"if [ "$(id -u)" != "0" ]; then echo "Root 未生效，请在 Magisk/KernelSU 中授权本工具" >&2; exit 126; fi
command -v iptables >/dev/null 2>&1 || {{ echo "设备缺少 iptables" >&2; exit 127; }}
removed=0
for rule in '{rule_80}' '{rule_443}'; do
  while iptables -t nat -C $rule >/dev/null 2>&1; do
    iptables -t nat -D $rule || exit $?
    removed=$((removed + 1))
  done
done
echo "已清理 $removed 条匹配规则"
echo "当前 OUTPUT 透明代理规则:"
iptables -t nat -S OUTPUT"#
                )
            };
            run_device_root_script(&request.serial, &script).await?
        }
        "status" => {
            run_device_root(
                &request.serial,
                &["settings", "get", "global", "http_proxy"],
            )
            .await?
        }
        _ => return Err("不支持该代理操作".into()),
    };
    Ok(AdvancedCommandResult {
        success: output.code == Some(0),
        command: format!("adb -s {} proxy {}", request.serial, action),
        output: output_text(&output),
        exit_code: output.code,
    })
}

fn validate_certificate(path: &str) -> Result<PathBuf, String> {
    let path = PathBuf::from(path);
    if !path.is_file() {
        return Err("证书文件不存在".into());
    }
    let extension = path
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    if !matches!(extension.as_str(), "pem" | "crt" | "cer") {
        return Err("仅支持 PEM/CRT/CER 证书".into());
    }
    Ok(path)
}

#[tauri::command]
pub async fn certificate_info(path: String) -> Result<CertificateInfo, String> {
    let path = validate_certificate(&path)?;
    let path_string = path.to_string_lossy().to_string();
    let hash_output = ensure_success(
        run_host(
            "openssl",
            &["x509", "-subject_hash_old", "-in", &path_string, "-noout"]
                .iter()
                .map(|value| (*value).into())
                .collect::<Vec<_>>(),
        )
        .await?,
    )?;
    let fingerprint = ensure_success(
        run_host(
            "openssl",
            &[
                "x509",
                "-fingerprint",
                "-sha256",
                "-in",
                &path_string,
                "-noout",
            ]
            .iter()
            .map(|value| (*value).into())
            .collect::<Vec<_>>(),
        )
        .await?,
    )?;
    let subject_hash = hash_output
        .stdout
        .lines()
        .next()
        .unwrap_or_default()
        .trim()
        .to_string();
    if subject_hash.is_empty() {
        return Err("无法计算证书 subject_hash_old".into());
    }
    Ok(CertificateInfo {
        path: path_string,
        subject_hash: subject_hash.clone(),
        sha256: fingerprint.stdout,
        system_target: format!("/system/etc/security/cacerts/{subject_hash}.0"),
        note: "Android 10+ 通常需要 root/Magisk；请先确认目标设备属于测试环境。".into(),
    })
}

#[tauri::command]
pub async fn install_certificate(
    request: CertificateRequest,
) -> Result<AdvancedCommandResult, String> {
    let path = validate_certificate(&request.path)?;
    let info = certificate_info(request.path.clone()).await?;
    let tmp = format!("/data/local/tmp/{}.pem", info.subject_hash);
    let local = path.to_string_lossy().to_string();
    let push = run_adb(&[
        "-s".into(),
        request.serial.clone(),
        "push".into(),
        local,
        tmp.clone(),
    ])
    .await?;
    if push.code != Some(0) {
        return Err(output_text(&push));
    }
    let script = format!("mount -o rw,remount /system 2>/dev/null || true; cp {tmp} {}; chmod 644 {}; chown 0:0 {}; rm -f {tmp}", info.system_target, info.system_target, info.system_target);
    let output = run_device_root_script(&request.serial, &script).await?;
    Ok(AdvancedCommandResult {
        success: output.code == Some(0),
        command: format!(
            "adb -s {} install certificate {}",
            request.serial, info.system_target
        ),
        output: output_text(&output),
        exit_code: output.code,
    })
}

fn frida_target(serial: &Option<String>) -> Vec<String> {
    serial
        .as_deref()
        .filter(|value| !value.is_empty())
        .map(|value| vec!["-D".into(), value.into()])
        .unwrap_or_else(|| vec!["-U".into()])
}

#[tauri::command]
pub async fn list_frida_processes(serial: Option<String>) -> Result<Vec<FridaProcess>, String> {
    let mut args = frida_target(&serial);
    args.push("-ai".into());
    let output = ensure_success(run_host("frida-ps", &args).await?)?;
    let mut processes = Vec::new();
    let column_separator = Regex::new(r"\s{2,}").map_err(|error| error.to_string())?;
    for line in output.stdout.lines() {
        let fields = column_separator
            .split(line.trim())
            .filter(|value| !value.is_empty())
            .collect::<Vec<_>>();
        if fields.len() < 3
            || fields[0].eq_ignore_ascii_case("pid")
            || fields[0].chars().all(|character| character == '-')
        {
            continue;
        }
        let pid = fields[0].parse::<u32>().ok();
        let identifier = fields.last().copied().unwrap_or_default().to_string();
        let name = fields[1..fields.len() - 1].join("  ");
        if identifier.is_empty() {
            continue;
        }
        processes.push(FridaProcess {
            pid,
            name,
            identifier,
            platform: "mobile".into(),
        });
    }
    Ok(processes)
}

fn frida_script_args(
    serial: &Option<String>,
    mode: &str,
    process: &str,
    pid: Option<u32>,
    script_path: &Path,
) -> Result<Vec<String>, String> {
    let mut args = frida_target(serial);
    if mode == "spawn" {
        // Current Frida resumes spawned applications by default. `--no-pause`
        // belonged to older frida-tools releases and is rejected by Frida 17.
        args.extend(["-f".into(), process.into()]);
    } else if let Some(pid) = pid.filter(|value| *value > 0) {
        args.extend(["-p".into(), pid.to_string()]);
    } else {
        return Err(format!(
            "{process} 当前没有运行中的 PID，Attach 只能连接已运行进程；请改用 Spawn（冷启动）"
        ));
    }
    args.extend([
        "-l".into(),
        script_path.to_string_lossy().into_owned(),
        "-q".into(),
        "-t".into(),
        "12".into(),
    ]);
    Ok(args)
}

fn frida_script_roots() -> Vec<PathBuf> {
    vec![
        std::env::current_dir()
            .unwrap_or_default()
            .join("frida-scripts"),
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../frida-scripts"),
    ]
}

const BUILTIN_DUMP_DEX: &str = include_str!("../../frida-scripts/dump_dex.js");
const BUILTIN_DUMP_SO: &str = include_str!("../../frida-scripts/dump_so.js");
const BUILTIN_INSPECT_JAVA: &str = include_str!("../../frida-scripts/inspect_java_runtime.js");
const BUILTIN_INSPECT_NETWORK: &str =
    include_str!("../../frida-scripts/inspect_network_surface.js");
const BUILTIN_INSPECT_PROCESS: &str = include_str!("../../frida-scripts/inspect_process.js");
const BUILTIN_INSPECT_ROOT: &str = include_str!("../../frida-scripts/inspect_root_indicators.js");
const IOS_DUMP_AGENT: &str = include_str!("../scripts/ios_dump_agent.js");
const IOS_DUMP_RUNNER: &str = include_str!("../scripts/ios_dump_runner.py");

fn builtin_frida_script(path: &str) -> Option<&'static str> {
    match path {
        "builtin://dump_dex.js" => Some(BUILTIN_DUMP_DEX),
        "builtin://dump_so.js" => Some(BUILTIN_DUMP_SO),
        "builtin://inspect_java_runtime.js" => Some(BUILTIN_INSPECT_JAVA),
        "builtin://inspect_network_surface.js" => Some(BUILTIN_INSPECT_NETWORK),
        "builtin://inspect_process.js" => Some(BUILTIN_INSPECT_PROCESS),
        "builtin://inspect_root_indicators.js" => Some(BUILTIN_INSPECT_ROOT),
        _ => None,
    }
}

fn builtin_frida_script_entries() -> Vec<FridaScriptEntry> {
    [
        (
            "dump_dex",
            "dump dex（内置）",
            "内置 Frida 17 DEX 运行时提取与自动回收",
            "dex-dump",
            "builtin://dump_dex.js",
            "android",
        ),
        (
            "dump_so",
            "dump so（内置）",
            "内置 Frida 17 SO 可读内存分段提取与自动分析",
            "so-dump",
            "builtin://dump_so.js",
            "android",
        ),
        (
            "inspect_java_runtime",
            "inspect java runtime（内置）",
            "读取 Java 运行时基础信息",
            "diagnostic",
            "builtin://inspect_java_runtime.js",
            "android",
        ),
        (
            "inspect_network_surface",
            "inspect network surface（内置）",
            "读取进程网络相关模块线索",
            "diagnostic",
            "builtin://inspect_network_surface.js",
            "both",
        ),
        (
            "inspect_process",
            "inspect process（内置）",
            "读取进程与模块基础信息",
            "diagnostic",
            "builtin://inspect_process.js",
            "both",
        ),
        (
            "inspect_root_indicators",
            "inspect root indicators（内置）",
            "读取 Android Root 环境线索",
            "diagnostic",
            "builtin://inspect_root_indicators.js",
            "android",
        ),
    ]
    .into_iter()
    .map(
        |(id, name, description, category, path, platform)| FridaScriptEntry {
            id: format!("builtin:{id}"),
            name: name.into(),
            description: description.into(),
            category: category.into(),
            path: path.into(),
            platform: platform.into(),
        },
    )
    .collect()
}

#[tauri::command]
pub fn list_frida_scripts(directory: Option<String>) -> Result<Vec<FridaScriptEntry>, String> {
    let mut roots = directory
        .filter(|value| !value.trim().is_empty())
        .map(PathBuf::from)
        .into_iter()
        .collect::<Vec<_>>();
    roots.extend(frida_script_roots());
    let mut scripts = builtin_frida_script_entries();
    let mut seen = scripts
        .iter()
        .map(|script| {
            script
                .path
                .rsplit('/')
                .next()
                .unwrap_or_default()
                .to_string()
        })
        .collect::<HashSet<_>>();
    for root in roots.into_iter().filter(|path| path.is_dir()) {
        for entry in fs::read_dir(&root).map_err(|error| error.to_string())? {
            let path = entry.map_err(|error| error.to_string())?.path();
            if path.extension().and_then(|value| value.to_str()) != Some("js") {
                continue;
            }
            let name = path
                .file_stem()
                .and_then(|value| value.to_str())
                .unwrap_or_default();
            let file_name = path
                .file_name()
                .and_then(|value| value.to_str())
                .unwrap_or_default();
            if name.is_empty() || !seen.insert(file_name.to_string()) {
                continue;
            }
            let lower = name.to_ascii_lowercase();
            let description = fs::read_to_string(&path)
                .ok()
                .and_then(|text| {
                    text.lines()
                        .find(|line| line.starts_with("// @description "))
                        .map(|line| line.trim_start_matches("// @description ").to_string())
                })
                .unwrap_or_else(|| {
                    if lower.contains("dump") && lower.contains("dex") {
                        "DEX 运行时提取脚本；可使用一键 Dump 工作流自动回收产物".into()
                    } else if lower.contains("trust") || lower.contains("ssl") {
                        "SSL/证书诊断脚本；建议使用 Spawn 并配合 Burp 代理".into()
                    } else {
                        "外部 Frida 脚本".into()
                    }
                });
            let category = if lower.contains("dump") && lower.contains("dex") {
                "dex-dump"
            } else if lower.contains("trust") || lower.contains("ssl") {
                "ssl"
            } else if lower.contains("bypass") {
                "bypass"
            } else {
                "diagnostic"
            };
            scripts.push(FridaScriptEntry {
                id: format!("{}:{}", root.display(), name),
                name: name.replace('_', " "),
                description,
                category: category.into(),
                path: path.to_string_lossy().into_owned(),
                platform: if lower.contains("ios") {
                    "ios".into()
                } else if lower.contains("java") || lower.contains("root") || lower.contains("dex")
                {
                    "android".into()
                } else {
                    "both".into()
                },
            });
        }
    }
    if scripts.is_empty() {
        return Err("没有在内置或外部目录中找到 .js Frida 脚本".into());
    }
    scripts.sort_by(|left, right| left.name.cmp(&right.name));
    Ok(scripts)
}

fn read_script_path(path: &str) -> Result<String, String> {
    if let Some(script) = builtin_frida_script(path) {
        return Ok(script.to_string());
    }
    let path = PathBuf::from(path);
    if path.extension().and_then(|value| value.to_str()) != Some("js") || !path.is_file() {
        return Err("Frida 脚本路径必须是存在的 .js 文件".into());
    }
    let metadata = fs::metadata(&path).map_err(|error| error.to_string())?;
    if metadata.len() > 512 * 1024 {
        return Err("Frida 脚本不能超过 512KB".into());
    }
    fs::read_to_string(path).map_err(|error| format!("读取 Frida 脚本失败：{error}"))
}

fn adapt_frida_17_script(script: &str) -> (String, Vec<String>) {
    let mut adapted = script.to_string();
    let mut changes = Vec::new();
    for (old, new, label) in [
        (
            "Module.getExportByName(null,",
            "Module.getGlobalExportByName(",
            "getGlobalExportByName",
        ),
        (
            "Module.findExportByName(null,",
            "Module.findGlobalExportByName(",
            "findGlobalExportByName",
        ),
    ] {
        if adapted.contains(old) {
            adapted = adapted.replace(old, new);
            changes.push(label.to_string());
        }
    }
    for (pattern, method) in [
        (
            r#"Module\.getExportByName\(\s*(['\"][^'\"]+['\"])\s*,\s*"#,
            "getExportByName",
        ),
        (
            r#"Module\.findExportByName\(\s*(['\"][^'\"]+['\"])\s*,\s*"#,
            "findExportByName",
        ),
    ] {
        if let Ok(regex) = Regex::new(pattern) {
            if regex.is_match(&adapted) {
                adapted = regex
                    .replace_all(
                        &adapted,
                        format!("Process.getModuleByName($1).{method}(").as_str(),
                    )
                    .into_owned();
                changes.push(format!("Module instance {method}"));
            }
        }
    }
    if !changes.is_empty() {
        adapted = format!(
            "console.log('[Me] Frida 17 compatibility: {}');\n{}",
            changes.join(", "),
            adapted
        );
    }
    (adapted, changes)
}

#[tauri::command]
pub async fn run_frida_script(
    request: FridaScriptRequest,
) -> Result<AdvancedCommandResult, String> {
    let process = request.process.trim();
    if process.is_empty() || process.len() > 220 {
        return Err("请选择一个 Frida 进程".into());
    }
    let script = if let Some(path) = request.script_path.as_deref() {
        read_script_path(path)?
    } else {
        request.script.clone()
    };
    if script.trim().is_empty() || script.len() > 512 * 1024 {
        return Err("Frida 脚本不能为空且不能超过 256KB".into());
    }
    let mode = request.mode.to_ascii_lowercase();
    if !matches!(mode.as_str(), "attach" | "spawn") {
        return Err("Frida 模式只能是 attach 或 spawn".into());
    }
    let (script, _) = adapt_frida_17_script(&script);
    let file = std::env::temp_dir().join(format!("security-console-{}.js", now_millis()));
    fs::write(&file, script).map_err(|error| format!("无法写入临时 Frida 脚本：{error}"))?;
    let args = frida_script_args(&request.serial, &mode, process, request.pid, &file)?;
    let result = run_host("frida", &args).await;
    let _ = fs::remove_file(file);
    let output = result?;
    Ok(AdvancedCommandResult {
        success: output.code == Some(0),
        command: format!("frida {}", args.join(" ")),
        output: output_text(&output),
        exit_code: output.code,
    })
}

fn cohesive_frida_python_path() -> Option<String> {
    cohesive_frida_executable_path("frida")
        .and_then(|path| Path::new(&path).parent().map(Path::to_path_buf))
        .and_then(|parent| {
            ["python3", "python"]
                .iter()
                .map(|name| parent.join(name))
                .find(|path| path.is_file())
        })
        .map(|path| path.to_string_lossy().into_owned())
        .or_else(|| executable_path("python3"))
}

fn validate_decrypted_ipa(path: &Path) -> Result<Option<bool>, String> {
    let mut archive = ZipArchive::new(File::open(path).map_err(|error| error.to_string())?)
        .map_err(|error| format!("IPA ZIP 验证失败：{error}"))?;
    for index in 0..archive.len() {
        let mut entry = archive.by_index(index).map_err(|error| error.to_string())?;
        let name = entry.name().to_string();
        let leaf = name.rsplit('/').next().unwrap_or_default();
        if name.starts_with("Payload/")
            && name.contains(".app/")
            && name.split('/').count() == 3
            && !leaf.contains('.')
            && entry.size() <= 256 * 1024 * 1024
        {
            let mut bytes = Vec::new();
            entry
                .read_to_end(&mut bytes)
                .map_err(|error| error.to_string())?;
            return Ok(macho_encryption_state(&bytes));
        }
    }
    Ok(None)
}

#[tauri::command]
pub async fn run_ios_dump(request: IosDumpRequest) -> Result<AdvancedCommandResult, String> {
    if request.serial.trim().is_empty()
        || request.bundle_id.trim().is_empty()
        || !request
            .bundle_id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || ".-_".contains(c))
    {
        return Err("请选择有效的 iOS 设备与 Bundle ID".into());
    }
    let python = cohesive_frida_python_path()
        .ok_or_else(|| "未找到与 Frida CLI 同环境的 Python".to_string())?;
    let base = request
        .destination_directory
        .as_deref()
        .filter(|v| !v.trim().is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| default_dump_directory(&request.bundle_id).join("ios"));
    fs::create_dir_all(&base).map_err(|error| format!("创建输出目录失败：{error}"))?;
    let stem: String = request
        .bundle_id
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || ".-_".contains(c) {
                c
            } else {
                '_'
            }
        })
        .collect();
    let output = base.join(format!("{stem}-decrypted-{}.ipa", now_millis()));
    let temp = std::env::temp_dir().join(format!("me-ios-runner-{}", now_millis()));
    fs::create_dir_all(&temp).map_err(|error| error.to_string())?;
    let runner = temp.join("runner.py");
    let agent = temp.join("agent.js");
    fs::write(&runner, IOS_DUMP_RUNNER).map_err(|error| error.to_string())?;
    fs::write(&agent, IOS_DUMP_AGENT).map_err(|error| error.to_string())?;
    let args = vec![
        runner.to_string_lossy().into_owned(),
        "--serial".into(),
        request.serial.clone(),
        "--bundle".into(),
        request.bundle_id.clone(),
        "--output".into(),
        output.to_string_lossy().into_owned(),
        "--agent".into(),
        agent.to_string_lossy().into_owned(),
    ];
    let result = timeout(
        Duration::from_secs(1200),
        Command::new(&python)
            .args(&args)
            .kill_on_drop(true)
            .output(),
    )
    .await;
    let _ = fs::remove_dir_all(&temp);
    let raw = match result {
        Ok(Ok(value)) => RawOutput {
            stdout: String::from_utf8_lossy(&value.stdout).trim().into(),
            stderr: String::from_utf8_lossy(&value.stderr).trim().into(),
            code: value.status.code(),
        },
        Ok(Err(error)) => return Err(format!("启动 iOS Runner 失败：{error}")),
        Err(_) => return Err("iOS 砸壳超过 20 分钟，已停止".into()),
    };
    if raw.code != Some(0) || !output.is_file() {
        return Ok(AdvancedCommandResult {
            success: false,
            command: format!("iOS dump {}", request.bundle_id),
            output: output_text(&raw),
            exit_code: raw.code,
        });
    }
    let encryption = validate_decrypted_ipa(&output)?;
    let validation = match encryption {
        Some(false) => "验证成功：主程序 cryptid=0",
        Some(true) => "验证失败：主程序仍为 cryptid=1",
        None => "IPA 已生成，但未定位到主程序验证 cryptid",
    };
    Ok(AdvancedCommandResult {
        success: encryption != Some(true),
        command: format!("iOS dump {}", request.bundle_id),
        output: format!(
            "{}\n\n{}\n输出 IPA：{}\n可直接拖入 App Analyzer。",
            output_text(&raw),
            validation,
            output.display()
        ),
        exit_code: raw.code,
    })
}

fn validate_android_package(value: &str) -> Result<(), String> {
    if !value.is_empty()
        && value.len() <= 220
        && value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || ".:_$-".contains(character))
    {
        Ok(())
    } else {
        Err("请输入有效的 Android 包名".into())
    }
}

async fn run_frida_with_timeout(args: &[String], duration: Duration) -> Result<RawOutput, String> {
    let executable = cohesive_frida_executable_path("frida")
        .ok_or_else(|| "未找到 frida，请先安装 Frida Tools".to_string())?;
    let mut command = Command::new(executable);
    command.args(args).kill_on_drop(true);
    let output = match timeout(duration, command.output()).await {
        Ok(result) => result.map_err(|error| format!("启动 Frida DEX Dump 失败：{error}"))?,
        Err(_) => {
            return Ok(RawOutput {
                stdout: String::new(),
                stderr: "DEX Dump 会话达到等待上限，已停止 Frida 会话并继续回收手机端已有产物"
                    .into(),
                code: None,
            });
        }
    };
    Ok(RawOutput {
        stdout: String::from_utf8_lossy(&output.stdout).trim().to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
        code: output.status.code(),
    })
}

fn adler32(bytes: &[u8]) -> u32 {
    const MOD_ADLER: u32 = 65_521;
    let mut a = 1u32;
    let mut b = 0u32;
    for chunk in bytes.chunks(5_552) {
        for byte in chunk {
            a += u32::from(*byte);
            b += a;
        }
        a %= MOD_ADLER;
        b %= MOD_ADLER;
    }
    (b << 16) | a
}

fn repair_dex_header(mut bytes: Vec<u8>) -> Result<Vec<u8>, String> {
    if bytes.len() < 0x70 || !bytes.starts_with(b"dex\n") || bytes.get(7) != Some(&0) {
        return Err("不是标准 DEX 文件或文件过短".into());
    }
    let file_size = u32::try_from(bytes.len()).map_err(|_| "DEX 文件过大".to_string())?;
    bytes[32..36].copy_from_slice(&file_size.to_le_bytes());
    bytes[36..40].copy_from_slice(&0x70u32.to_le_bytes());
    bytes[40..44].copy_from_slice(&0x1234_5678u32.to_le_bytes());
    let signature = Sha1::digest(&bytes[32..]);
    bytes[12..32].copy_from_slice(&signature);
    let checksum = adler32(&bytes[12..]);
    bytes[8..12].copy_from_slice(&checksum.to_le_bytes());
    Ok(bytes)
}

fn collect_files(root: &Path, extension: &str) -> Vec<PathBuf> {
    let mut result = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(directory) = stack.pop() {
        let Ok(entries) = fs::read_dir(directory) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if path
                .extension()
                .and_then(|value| value.to_str())
                .is_some_and(|value| value.eq_ignore_ascii_case(extension))
            {
                result.push(path);
            }
        }
    }
    result.sort();
    result
}

fn repair_and_bundle_dex(raw: &Path, output: &Path) -> Result<(usize, usize, PathBuf), String> {
    fs::create_dir_all(output).map_err(|error| format!("创建 DEX 输出目录失败：{error}"))?;
    let mut seen = HashSet::new();
    let mut repaired_files = Vec::new();
    let mut rejected = 0usize;
    for path in collect_files(raw, "dex") {
        let Ok(bytes) = fs::read(&path) else {
            rejected += 1;
            continue;
        };
        let Ok(repaired) = repair_dex_header(bytes) else {
            rejected += 1;
            continue;
        };
        let digest = Sha256::digest(&repaired);
        let key = digest
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        if !seen.insert(key) {
            continue;
        }
        let index = repaired_files.len() + 1;
        let name = if index == 1 {
            "classes.dex".to_string()
        } else {
            format!("classes{index}.dex")
        };
        let destination = output.join(&name);
        fs::write(&destination, &repaired)
            .map_err(|error| format!("写入修复 DEX 失败：{error}"))?;
        repaired_files.push((name, repaired));
    }
    if repaired_files.is_empty() {
        return Err(format!(
            "没有找到可修复的标准 DEX；无效/不完整文件 {rejected} 个"
        ));
    }

    // Android multidex is a set of classes*.dex files. Concatenating DEX files
    // would corrupt their index tables, so package the repaired, de-duplicated
    // set without pretending it is one monolithic DEX.
    let bundle = output.join("recovered-multidex.zip");
    let file = File::create(&bundle).map_err(|error| format!("创建 DEX 合集失败：{error}"))?;
    let mut writer = ZipWriter::new(file);
    let options = SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);
    for (name, bytes) in &repaired_files {
        writer
            .start_file(name, options)
            .map_err(|error| format!("写入 DEX 合集失败：{error}"))?;
        writer
            .write_all(bytes)
            .map_err(|error| format!("写入 DEX 数据失败：{error}"))?;
    }
    writer
        .finish()
        .map_err(|error| format!("完成 DEX 合集失败：{error}"))?;
    Ok((repaired_files.len(), rejected, bundle))
}

fn default_dump_directory(package: &str) -> PathBuf {
    let home = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    home.join("Desktop")
        .join("Me-Dumps")
        .join(package)
        .join(now_millis().to_string())
}

async fn mirror_remote_dump(
    serial: &str,
    remote_files: &str,
    prefix: &str,
    remote_export: &str,
    seconds: u64,
) {
    let script = format!(
        "for dir in {remote_files}/{prefix}*; do if [ -d \"$dir\" ]; then cp -R \"$dir\"/. {remote_export}/ 2>/dev/null || true; chmod -R a+rX {remote_export} 2>/dev/null || true; fi; done"
    );
    for _ in 0..=seconds {
        let _ = run_device_root_script(serial, &script).await;
        sleep(Duration::from_secs(1)).await;
    }
}

#[tauri::command]
pub async fn run_dex_dump(request: DexDumpRequest) -> Result<AdvancedCommandResult, String> {
    let package = request.package.trim();
    validate_android_package(package)?;
    let script_path = PathBuf::from(request.script_path.trim());
    let script_text = read_script_path(script_path.to_string_lossy().as_ref())?;
    if !script_path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase()
        .contains("dex")
    {
        return Err("请选择经过审查的 DEX Dump Frida 脚本（文件名应包含 dex）".into());
    }
    if !script_text.contains("dex") {
        return Err("所选脚本未发现 DEX 相关逻辑，请确认脚本内容".into());
    }
    let duration = request.duration_seconds.unwrap_or(30).clamp(10, 120);
    let remote_files = format!("/data/data/{package}/files");
    let prepare = run_device_root_script(
        &request.serial,
        &format!("rm -rf {remote_files}/dump_dex_*; mkdir -p {remote_files}"),
    )
    .await?;
    ensure_success(prepare)?;

    let script_text = script_text.replace("__ME_PACKAGE__", package);
    let (adapted_script, compatibility_changes) = adapt_frida_17_script(&script_text);
    let runtime_script = std::env::temp_dir().join(format!("me-dex-dump-{}.js", now_millis()));
    fs::write(&runtime_script, adapted_script)
        .map_err(|error| format!("创建 Frida 17 兼容脚本失败：{error}"))?;
    let mut args = frida_target(&Some(request.serial.clone()));
    args.extend([
        "-f".into(),
        package.into(),
        "-l".into(),
        runtime_script.to_string_lossy().into_owned(),
        "-q".into(),
        "-t".into(),
        duration.to_string(),
    ]);
    let remote_export = format!("/data/local/tmp/me-dex-export-{}", now_millis());
    ensure_success(
        run_device_root_script(
            &request.serial,
            &format!("rm -rf {remote_export}; mkdir -p {remote_export}; chmod 755 {remote_export}"),
        )
        .await?,
    )?;
    let frida_future = run_frida_with_timeout(&args, Duration::from_secs(duration + 15));
    let mirror_future = mirror_remote_dump(
        &request.serial,
        &remote_files,
        "dump_dex_",
        &remote_export,
        duration + 3,
    );
    let (frida_result, _) = tokio::join!(frida_future, mirror_future);
    let _ = fs::remove_file(&runtime_script);
    let frida_output = frida_result?;
    // Community scripts may throw from a later hook after they have already
    // written usable DEX files. Artifact recovery is the source of truth.
    let frida_warning = (frida_output.code != Some(0))
        .then_some("（脚本返回非零状态，已继续抢救手机端已生成的 DEX）");

    let collect_script = format!(
        "for dir in {remote_files}/dump_dex_*; do if [ -d \"$dir\" ]; then cp -R \"$dir\"/. {remote_export}/ 2>/dev/null || true; fi; done; chmod -R a+rX {remote_export}; count=$(find {remote_export} -type f -name '*.dex' | wc -l); if [ \"$count\" -lt 1 ]; then echo '未发现 dump_dex 输出，请在等待时间内操作 App 触发加固代码加载' >&2; exit 2; fi; find {remote_export} -type f -name '*.dex' -print"
    );
    let collected = run_device_root_script(&request.serial, &collect_script).await?;
    if collected.code != Some(0) {
        return Ok(AdvancedCommandResult {
            success: false,
            command: format!("adb -s {} collect DEX", request.serial),
            output: format!(
                "Frida 会话已完成，但没有可回收的 DEX。\nFrida 日志：\n{}\n回收日志：\n{}",
                output_text(&frida_output),
                output_text(&collected)
            ),
            exit_code: collected.code,
        });
    }

    let destination = request
        .destination_directory
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| default_dump_directory(package));
    fs::create_dir_all(&destination).map_err(|error| format!("创建本机输出目录失败：{error}"))?;
    let raw = destination.join("raw");
    let pull = run_adb(&[
        "-s".into(),
        request.serial.clone(),
        "pull".into(),
        remote_export.clone(),
        raw.to_string_lossy().into_owned(),
    ])
    .await?;
    let _ = run_device_root_script(&request.serial, &format!("rm -rf {remote_export}")).await;
    if pull.code != Some(0) {
        return Err(format!(
            "DEX 已生成，但拉回 Mac 失败：{}",
            output_text(&pull)
        ));
    }
    let fixed = destination.join("repaired");
    let (count, rejected, bundle) = repair_and_bundle_dex(&raw, &fixed)?;
    Ok(AdvancedCommandResult {
        success: true,
        command: format!("frida DEX workflow {package}"),
        output: format!(
            "[1/4] Frida Spawn 完成{}{}\n{}\n[2/4] 手机端 DEX 已拉回：{}\n[3/4] 已修复 header/signature/checksum，去重后 {} 个，无效 {} 个\n[4/4] Multidex 合集：{}",
            if compatibility_changes.is_empty() { "".into() } else { format!("（已自动适配 Frida 17：{}）", compatibility_changes.join(", ")) },
            frida_warning.unwrap_or_default(),
            output_text(&frida_output),
            raw.display(),
            count,
            rejected,
            bundle.display()
        ),
        exit_code: Some(0),
    })
}

#[derive(Debug, Deserialize)]
struct SoRangeMap {
    path: String,
    offset: String,
    size: u64,
    protection: String,
}

#[derive(Debug, Deserialize)]
struct SoModuleMap {
    name: String,
    path: String,
    base: String,
    size: u64,
    ranges: Vec<SoRangeMap>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct SoReconstructionResult {
    module: String,
    source_path: String,
    load_address: String,
    mapped_size: u64,
    output: Option<String>,
    status: String,
    load_segments: usize,
    bytes_expected: u64,
    bytes_recovered: u64,
    completeness_percent: f64,
    notes: Vec<String>,
}

fn parse_hex_u64(value: &str) -> Option<u64> {
    u64::from_str_radix(value.trim_start_matches("0x"), 16).ok()
}

fn read_u16_le(bytes: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_le_bytes(
        bytes.get(offset..offset + 2)?.try_into().ok()?,
    ))
}

fn read_u32_le(bytes: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        bytes.get(offset..offset + 4)?.try_into().ok()?,
    ))
}

fn read_u64_le(bytes: &[u8], offset: usize) -> Option<u64> {
    Some(u64::from_le_bytes(
        bytes.get(offset..offset + 8)?.try_into().ok()?,
    ))
}

fn safe_module_file_name(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || "._-".contains(character) {
                character
            } else {
                '_'
            }
        })
        .collect()
}

fn reconstruct_so_module(raw: &Path, output_dir: &Path, map_path: &Path) -> SoReconstructionResult {
    let fallback_name = map_path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("unknown.so")
        .to_string();
    let fail = |module: String, reason: String| SoReconstructionResult {
        module,
        source_path: String::new(),
        load_address: String::new(),
        mapped_size: 0,
        output: None,
        status: "无法重建".into(),
        load_segments: 0,
        bytes_expected: 0,
        bytes_recovered: 0,
        completeness_percent: 0.0,
        notes: vec![reason],
    };
    let map_bytes = match fs::read(map_path) {
        Ok(value) => value,
        Err(error) => return fail(fallback_name, format!("读取 map.json 失败：{error}")),
    };
    let map: SoModuleMap = match serde_json::from_slice(&map_bytes) {
        Ok(value) => value,
        Err(error) => return fail(fallback_name, format!("解析 map.json 失败：{error}")),
    };
    let mut ranges = Vec::new();
    let mut notes = Vec::new();
    for range in &map.ranges {
        let Some(offset) = parse_hex_u64(&range.offset) else {
            notes.push(format!("忽略无效 range offset：{}", range.offset));
            continue;
        };
        let Some(name) = Path::new(&range.path).file_name() else {
            continue;
        };
        match fs::read(raw.join(name)) {
            Ok(bytes) => {
                if bytes.len() as u64 != range.size {
                    notes.push(format!(
                        "{} 声明 {} 字节，实际 {} 字节",
                        name.to_string_lossy(),
                        range.size,
                        bytes.len()
                    ));
                }
                ranges.push((offset, bytes, range.protection.clone()));
            }
            Err(error) => notes.push(format!("缺少 {}：{error}", name.to_string_lossy())),
        }
    }
    ranges.sort_by_key(|range| range.0);
    let Some((_, header_bytes, _)) = ranges.iter().find(|range| range.0 == 0) else {
        return SoReconstructionResult {
            module: map.name,
            source_path: map.path,
            load_address: map.base,
            mapped_size: map.size,
            output: None,
            status: "无法重建".into(),
            load_segments: 0,
            bytes_expected: 0,
            bytes_recovered: 0,
            completeness_percent: 0.0,
            notes: vec!["缺少包含 ELF Header 的 offset=0 range".into()],
        };
    };
    if header_bytes.get(0..4) != Some(b"\x7fELF") {
        return SoReconstructionResult {
            module: map.name,
            source_path: map.path,
            load_address: map.base,
            mapped_size: map.size,
            output: None,
            status: "无法重建".into(),
            load_segments: 0,
            bytes_expected: 0,
            bytes_recovered: 0,
            completeness_percent: 0.0,
            notes: vec!["offset=0 range 不包含 ELF Magic".into()],
        };
    }
    if header_bytes.get(5) != Some(&1) {
        notes.push("目前只自动重建 Little Endian ELF".into());
        return SoReconstructionResult {
            module: map.name,
            source_path: map.path,
            load_address: map.base,
            mapped_size: map.size,
            output: None,
            status: "不支持的字节序".into(),
            load_segments: 0,
            bytes_expected: 0,
            bytes_recovered: 0,
            completeness_percent: 0.0,
            notes,
        };
    }
    let is_64 = header_bytes.get(4) == Some(&2);
    let (phoff, phentsize, phnum) = if is_64 {
        (
            read_u64_le(header_bytes, 32),
            read_u16_le(header_bytes, 54).map(u64::from),
            read_u16_le(header_bytes, 56).map(u64::from),
        )
    } else {
        (
            read_u32_le(header_bytes, 28).map(u64::from),
            read_u16_le(header_bytes, 42).map(u64::from),
            read_u16_le(header_bytes, 44).map(u64::from),
        )
    };
    let (Some(phoff), Some(phentsize), Some(phnum)) = (phoff, phentsize, phnum) else {
        return fail(map.name, "ELF Program Header 字段不完整".into());
    };
    if phnum == 0 || phnum > 512 || phentsize < if is_64 { 56 } else { 32 } {
        return fail(map.name, "ELF Program Header 数量或大小异常".into());
    }
    let table_end = phoff.saturating_add(phentsize.saturating_mul(phnum));
    if table_end > header_bytes.len() as u64 {
        return fail(
            map.name,
            "ELF Program Header Table 不在已恢复的头部 range 中".into(),
        );
    }
    let mut loads = Vec::new();
    for index in 0..phnum {
        let offset = (phoff + index * phentsize) as usize;
        if read_u32_le(header_bytes, offset) != Some(1) {
            continue;
        }
        let (file_offset, virtual_address, file_size, memory_size) = if is_64 {
            (
                read_u64_le(header_bytes, offset + 8),
                read_u64_le(header_bytes, offset + 16),
                read_u64_le(header_bytes, offset + 32),
                read_u64_le(header_bytes, offset + 40),
            )
        } else {
            (
                read_u32_le(header_bytes, offset + 4).map(u64::from),
                read_u32_le(header_bytes, offset + 8).map(u64::from),
                read_u32_le(header_bytes, offset + 16).map(u64::from),
                read_u32_le(header_bytes, offset + 20).map(u64::from),
            )
        };
        if let (Some(file_offset), Some(virtual_address), Some(file_size), Some(memory_size)) =
            (file_offset, virtual_address, file_size, memory_size)
        {
            loads.push((file_offset, virtual_address, file_size, memory_size));
        }
    }
    let Some(min_vaddr) = loads.iter().map(|load| load.1).min() else {
        return fail(map.name, "没有找到 PT_LOAD Program Header".into());
    };
    let output_size = loads
        .iter()
        .map(|load| load.0.saturating_add(load.2))
        .max()
        .unwrap_or_default();
    if output_size == 0 || output_size > 1024 * 1024 * 1024 {
        return fail(map.name, format!("重建文件大小异常：{output_size}"));
    }
    let mut rebuilt = vec![0u8; output_size as usize];
    let mut expected = 0u64;
    let mut recovered = 0u64;
    for (file_offset, virtual_address, file_size, memory_size) in &loads {
        expected = expected.saturating_add(*file_size);
        let memory_start = virtual_address.saturating_sub(min_vaddr);
        let memory_end = memory_start.saturating_add(*file_size);
        for (range_offset, bytes, _) in &ranges {
            let range_end = range_offset.saturating_add(bytes.len() as u64);
            let start = memory_start.max(*range_offset);
            let end = memory_end.min(range_end);
            if start >= end {
                continue;
            }
            let source_start = (start - range_offset) as usize;
            let destination_start = (file_offset + start - memory_start) as usize;
            let length = (end - start) as usize;
            if destination_start + length <= rebuilt.len() && source_start + length <= bytes.len() {
                rebuilt[destination_start..destination_start + length]
                    .copy_from_slice(&bytes[source_start..source_start + length]);
                recovered = recovered.saturating_add(length as u64);
            }
        }
        if memory_size > file_size {
            notes.push(format!(
                "PT_LOAD vaddr=0x{virtual_address:x} 含 {} 字节 BSS/零填充区",
                memory_size - file_size
            ));
        }
    }
    let completeness = if expected == 0 {
        0.0
    } else {
        (recovered as f64 / expected as f64 * 100.0).min(100.0)
    };
    let output_name = format!("repaired-{}", safe_module_file_name(&map.name));
    let output_path = output_dir.join(output_name);
    if let Err(error) =
        fs::create_dir_all(output_dir).and_then(|_| fs::write(&output_path, rebuilt))
    {
        return fail(map.name, format!("写入重建 SO 失败：{error}"));
    }
    notes.push(
        "重建结果面向 IDA/Ghidra 静态分析；运行时重定位值未还原，不保证可重新打包加载".into(),
    );
    SoReconstructionResult {
        module: map.name,
        source_path: map.path,
        load_address: map.base,
        mapped_size: map.size,
        output: Some(output_path.to_string_lossy().into_owned()),
        status: if completeness >= 99.0 {
            "PT_LOAD 完整重建".into()
        } else if completeness >= 70.0 {
            "部分重建，可用于静态分析".into()
        } else {
            "低完整度重建".into()
        },
        load_segments: loads.len(),
        bytes_expected: expected,
        bytes_recovered: recovered,
        completeness_percent: (completeness * 100.0).round() / 100.0,
        notes,
    }
}

fn reconstruct_so_dump_directory(
    raw: &Path,
    output: &Path,
) -> Result<(Vec<SoReconstructionResult>, PathBuf), String> {
    let maps = collect_files(raw, "json")
        .into_iter()
        .filter(|path| {
            path.file_name()
                .and_then(|value| value.to_str())
                .is_some_and(|value| value.ends_with(".map.json"))
        })
        .collect::<Vec<_>>();
    let results = maps
        .iter()
        .map(|map| reconstruct_so_module(raw, output, map))
        .collect::<Vec<_>>();
    let report = output.join("reconstruction-report.json");
    fs::create_dir_all(output).map_err(|error| format!("创建 SO 重建目录失败：{error}"))?;
    fs::write(
        &report,
        serde_json::to_vec_pretty(&results).map_err(|error| error.to_string())?,
    )
    .map_err(|error| format!("写入 SO 重建报告失败：{error}"))?;
    Ok((results, report))
}

fn analyze_so_dump_directory(root: &Path) -> Result<(usize, usize, PathBuf), String> {
    let mut stack = vec![root.to_path_buf()];
    let mut files_scanned = 0usize;
    let mut items = Vec::new();
    while let Some(directory) = stack.pop() {
        let Ok(entries) = fs::read_dir(directory) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            let Ok(metadata) = fs::metadata(&path) else {
                continue;
            };
            if metadata.len() < 4 || metadata.len() > 256 * 1024 * 1024 {
                continue;
            }
            let Ok(bytes) = fs::read(&path) else {
                continue;
            };
            let strings = ascii_strings(&bytes, 5);
            scan_sensitive_text(&strings, &path.to_string_lossy(), &mut items);
            files_scanned += 1;
            if items.len() >= 1_000 {
                break;
            }
        }
    }
    items.sort_by(|a, b| {
        a.location
            .cmp(&b.location)
            .then(a.item.cmp(&b.item))
            .then(a.value.cmp(&b.value))
    });
    items.dedup_by(|a, b| a.location == b.location && a.item == b.item && a.value == b.value);
    items.truncate(1_000);
    let report = root.join("so-sensitive-report.json");
    fs::write(
        &report,
        serde_json::to_vec_pretty(&items).map_err(|error| error.to_string())?,
    )
    .map_err(|error| format!("写入 SO 分析报告失败：{error}"))?;
    Ok((files_scanned, items.len(), report))
}

#[tauri::command]
pub async fn run_so_dump(request: SoDumpRequest) -> Result<AdvancedCommandResult, String> {
    let package = request.package.trim();
    validate_android_package(package)?;
    let script_path = PathBuf::from(request.script_path.trim());
    let script_text = read_script_path(script_path.to_string_lossy().as_ref())?;
    let script_name = script_path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    if !script_name.contains("so") {
        return Err("请选择 SO Dump 脚本（文件名应包含 so）".into());
    }
    let duration = request.duration_seconds.unwrap_or(30).clamp(10, 120);
    let remote_files = format!("/data/data/{package}/files");
    ensure_success(
        run_device_root_script(
            &request.serial,
            &format!("rm -rf {remote_files}/dump_so_*; mkdir -p {remote_files}"),
        )
        .await?,
    )?;

    let script_text = script_text.replace("__ME_PACKAGE__", package);
    let (adapted_script, compatibility_changes) = adapt_frida_17_script(&script_text);
    let runtime_script = std::env::temp_dir().join(format!("me-so-dump-{}.js", now_millis()));
    fs::write(&runtime_script, adapted_script)
        .map_err(|error| format!("创建 SO Dump 临时脚本失败：{error}"))?;
    let mut args = frida_target(&Some(request.serial.clone()));
    args.extend([
        "-f".into(),
        package.into(),
        "-l".into(),
        runtime_script.to_string_lossy().into_owned(),
        "-q".into(),
        "-t".into(),
        duration.to_string(),
    ]);
    let remote_export = format!("/data/local/tmp/me-so-export-{}", now_millis());
    ensure_success(
        run_device_root_script(
            &request.serial,
            &format!("rm -rf {remote_export}; mkdir -p {remote_export}; chmod 755 {remote_export}"),
        )
        .await?,
    )?;
    let frida_future = run_frida_with_timeout(&args, Duration::from_secs(duration + 15));
    let mirror_future = mirror_remote_dump(
        &request.serial,
        &remote_files,
        "dump_so_",
        &remote_export,
        duration + 3,
    );
    let (frida_result, _) = tokio::join!(frida_future, mirror_future);
    let _ = fs::remove_file(&runtime_script);
    let frida_output = frida_result?;

    let collected = run_device_root_script(
        &request.serial,
        &format!("for dir in {remote_files}/dump_so_*; do if [ -d \"$dir\" ]; then cp -R \"$dir\"/. {remote_export}/ 2>/dev/null || true; fi; done; chmod -R a+rX {remote_export}; count=$(find {remote_export} -type f | wc -l); if [ \"$count\" -lt 1 ]; then echo '未发现 SO 内存产物，请操作 App 触发动态库加载' >&2; exit 2; fi; find {remote_export} -type f -print"),
    )
    .await?;
    if collected.code != Some(0) {
        return Ok(AdvancedCommandResult {
            success: false,
            command: format!("adb -s {} collect SO", request.serial),
            output: format!(
                "Frida 会话已完成，但没有可回收的 SO。\nFrida 日志：\n{}\n回收日志：\n{}",
                output_text(&frida_output),
                output_text(&collected)
            ),
            exit_code: collected.code,
        });
    }

    let destination = request
        .destination_directory
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| default_dump_directory(package).join("so"));
    fs::create_dir_all(&destination).map_err(|error| format!("创建 SO 输出目录失败：{error}"))?;
    let raw = destination.join("raw");
    let pull = run_adb(&[
        "-s".into(),
        request.serial.clone(),
        "pull".into(),
        remote_export.clone(),
        raw.to_string_lossy().into_owned(),
    ])
    .await?;
    let _ = run_device_root_script(&request.serial, &format!("rm -rf {remote_export}")).await;
    if pull.code != Some(0) {
        return Err(format!("SO 已生成，但拉回电脑失败：{}", output_text(&pull)));
    }
    let repaired = destination.join("repaired");
    let (reconstruction, reconstruction_report) = reconstruct_so_dump_directory(&raw, &repaired)?;
    let reconstructed_count = reconstruction
        .iter()
        .filter(|result| result.output.is_some())
        .count();
    let (files_scanned, finding_count, report) = analyze_so_dump_directory(&raw)?;
    Ok(AdvancedCommandResult {
        success: true,
        command: format!("frida SO workflow {package}"),
        output: format!(
            "[1/4] SO Dump 会话完成{}\n{}\n[2/4] 已拉回 {}\n[3/4] 已按 ELF PT_LOAD 重建 {}/{} 个模块\n重建目录：{}\n重建报告：{}\n[4/4] 扫描 {} 个内存分段，发现 {} 条敏感线索\n敏感信息报告：{}",
            if compatibility_changes.is_empty() { "".into() } else { format!("（已适配 Frida 17：{}）", compatibility_changes.join(", ")) },
            output_text(&frida_output),
            raw.display(),
            reconstructed_count,
            reconstruction.len(),
            repaired.display(),
            reconstruction_report.display(),
            files_scanned,
            finding_count,
            report.display()
        ),
        exit_code: Some(0),
    })
}

fn validate_frida_binary(path: &str) -> Result<PathBuf, String> {
    let path = PathBuf::from(path);
    if !path.is_file() {
        return Err("Frida-server 文件不存在".into());
    }
    if fs::metadata(&path)
        .map_err(|error| error.to_string())?
        .len()
        > 80 * 1024 * 1024
    {
        return Err("Frida-server 文件不能超过 80MB".into());
    }
    Ok(path)
}

#[tauri::command]
pub async fn manage_frida_server(
    request: FridaServerRequest,
) -> Result<AdvancedCommandResult, String> {
    let output = match request.action.as_str() {
        "start" => {
            let path = validate_frida_binary(
                request
                    .path
                    .as_deref()
                    .ok_or("请选择本机 Frida-server 文件")?,
            )?;
            // Stop the old process before replacing its executable. Pushing on
            // top of a running frida-server can stall `adb push` and leave the
            // destination truncated or missing.
            let stopped = run_device_root_script(
                &request.serial,
                "pids=$(pidof frida-server 2>/dev/null || true); if [ -n \"$pids\" ]; then kill $pids 2>/dev/null || true; sleep 1; fi",
            )
            .await?;
            if stopped.code != Some(0) {
                return Err(format!(
                    "停止旧 Frida-server 失败：{}",
                    output_text(&stopped)
                ));
            }
            let mut push = run_adb(&[
                "-s".into(),
                request.serial.clone(),
                "push".into(),
                path.to_string_lossy().into_owned(),
                "/data/local/tmp/frida-server".into(),
            ])
            .await?;
            if push.code != Some(0) {
                let fallback = "/sdcard/Download/frida-server";
                push = run_adb(&[
                    "-s".into(),
                    request.serial.clone(),
                    "push".into(),
                    path.to_string_lossy().into_owned(),
                    fallback.into(),
                ])
                .await?;
                if push.code != Some(0) {
                    return Err(output_text(&push));
                }
                let copy = run_device_root_script(
                    &request.serial,
                    &format!("cp {fallback} /data/local/tmp/frida-server && rm -f {fallback}"),
                )
                .await?;
                if copy.code != Some(0) {
                    return Err(format!(
                        "已推送到 Download，但 root 复制失败：{}",
                        output_text(&copy)
                    ));
                }
            }
            let start = run_device_root_script(
                &request.serial,
                r#"if [ "$(id -u)" != "0" ]; then echo "Root 未生效，无法启动 Frida-server" >&2; exit 126; fi
old_pids=$(pidof frida-server 2>/dev/null || true)
if [ -n "$old_pids" ]; then kill $old_pids 2>/dev/null || true; sleep 1; fi
chmod 755 /data/local/tmp/frida-server || exit $?
chown 0:0 /data/local/tmp/frida-server 2>/dev/null || true
rm -f /data/local/tmp/frida-server.log
nohup /data/local/tmp/frida-server </dev/null >/data/local/tmp/frida-server.log 2>&1 &
pid=$!
sleep 1
if ! kill -0 "$pid" 2>/dev/null; then echo "Frida-server 启动失败" >&2; tail -n 30 /data/local/tmp/frida-server.log >&2; exit 1; fi
uid=$(awk '/^Uid:/{print $2}' /proc/$pid/status 2>/dev/null)
echo "Frida-server PID=$pid UID=$uid SELinux=$(getenforce 2>/dev/null || echo unknown)"
if [ "$uid" != "0" ]; then echo "Frida-server 未以 Root 身份运行，请重新授权 su" >&2; exit 126; fi
tail -n 20 /data/local/tmp/frida-server.log 2>/dev/null || true"#,
            )
            .await?;
            RawOutput {
                stdout: format!(
                    "[push]\n{}\n[start]\n{}",
                    output_text(&push),
                    output_text(&start)
                ),
                stderr: start.stderr,
                code: start.code,
            }
        }
        "stop" => {
            run_device_root_script(
                &request.serial,
                "pids=$(pidof frida-server 2>/dev/null || true); if [ -n \"$pids\" ]; then kill $pids; echo \"已停止 $pids\"; else echo \"Frida-server 未运行\"; fi",
            )
            .await?
        }
        "log" => {
            run_device_root_script(
                &request.serial,
                "pid=$(pidof frida-server 2>/dev/null | awk '{print $1}'); if [ -n \"$pid\" ]; then uid=$(awk '/^Uid:/{print $2}' /proc/$pid/status); echo \"Frida-server PID=$pid UID=$uid SELinux=$(getenforce 2>/dev/null || echo unknown)\"; else echo \"Frida-server 未运行\"; fi; tail -n 100 /data/local/tmp/frida-server.log 2>/dev/null || true",
            )
            .await?
        }
        _ => return Err("Frida-server 操作只能是 start、stop 或 log".into()),
    };
    Ok(AdvancedCommandResult {
        success: output.code == Some(0),
        command: format!("adb -s {} frida-server {}", request.serial, request.action),
        output: output_text(&output),
        exit_code: output.code,
    })
}

#[tauri::command]
pub async fn install_frida_tools() -> Result<AdvancedCommandResult, String> {
    let output = run_host(
        "python3",
        &[
            "-m".into(),
            "pip".into(),
            "install".into(),
            "--user".into(),
            "--upgrade".into(),
            "frida-tools".into(),
        ],
    )
    .await?;
    Ok(AdvancedCommandResult {
        success: output.code == Some(0),
        command: "python3 -m pip install --user --upgrade frida-tools".into(),
        output: output_text(&output),
        exit_code: output.code,
    })
}

#[tauri::command]
pub async fn download_frida_server(
    request: FridaDownloadRequest,
) -> Result<AdvancedCommandResult, String> {
    let host_version = ensure_success(run_host("frida", &["--version".into()]).await?)?
        .stdout
        .lines()
        .next()
        .unwrap_or_default()
        .trim()
        .to_string();
    if host_version.is_empty()
        || !host_version
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || ".-_".contains(character))
    {
        return Err("无法从电脑端 Frida 读取安全的版本号".into());
    }
    let abi = run_device_adb(&request.serial, &["shell", "getprop", "ro.product.cpu.abi"])
        .await
        .map(|output| output_text(&output))?;
    let arch = if abi.contains("x86_64") {
        "x86_64"
    } else if abi.contains("x86") {
        "x86"
    } else if abi.contains("arm64") {
        "arm64"
    } else if abi.contains("arm") {
        "arm"
    } else {
        return Err(format!("无法识别设备 ABI：{abi}"));
    };
    let directory = request
        .destination_directory
        .map(PathBuf::from)
        .unwrap_or_else(|| std::env::temp_dir().join("security-console"));
    fs::create_dir_all(&directory).map_err(|error| format!("无法创建下载目录：{error}"))?;
    let base = format!("frida-server-{host_version}-android-{arch}");
    let archive = directory.join(format!("{base}.xz"));
    let binary = directory.join(&base);
    let url = format!("https://github.com/frida/frida/releases/download/{host_version}/{base}.xz");
    let download = run_host(
        "curl",
        &[
            "-fL".into(),
            "--retry".into(),
            "2".into(),
            "-o".into(),
            archive.to_string_lossy().into_owned(),
            url,
        ],
    )
    .await?;
    if download.code != Some(0) {
        return Err(output_text(&download));
    }
    let decompress = run_host(
        "xz",
        &[
            "-d".into(),
            "-f".into(),
            archive.to_string_lossy().into_owned(),
        ],
    )
    .await?;
    if decompress.code != Some(0) {
        return Err(format!(
            "下载成功，但解压失败：{}；可手动安装 xz 后重试",
            output_text(&decompress)
        ));
    }
    Ok(AdvancedCommandResult {
        success: true,
        command: format!("download frida-server {host_version} {arch}"),
        output: binary.to_string_lossy().into_owned(),
        exit_code: Some(0),
    })
}

#[tauri::command]
pub async fn mount_ios_developer_image(
    request: IosDeveloperImageRequest,
) -> Result<AdvancedCommandResult, String> {
    let directory = PathBuf::from(&request.directory);
    if !directory.is_dir() {
        return Err("Developer Disk Image 目录不存在".into());
    }
    let output = run_host(
        "ideviceimagemounter",
        &[
            "-u".into(),
            request.serial.clone(),
            directory.to_string_lossy().into_owned(),
        ],
    )
    .await?;
    Ok(AdvancedCommandResult {
        success: output.code == Some(0),
        command: format!("ideviceimagemounter -u {} <directory>", request.serial),
        output: output_text(&output),
        exit_code: output.code,
    })
}

#[tauri::command]
pub fn open_environment_terminal() -> Result<String, String> {
    let status = if cfg!(target_os = "macos") {
        StdCommand::new("osascript")
            .args(["-e", "tell application \"Terminal\" to do script \"adb version; frida --version; frida-ps --version; python3 --version\""])
            .spawn()
    } else if cfg!(target_os = "windows") {
        StdCommand::new("powershell")
            .args(["-NoExit", "-Command", "Get-Command adb,frida,frida-ps,python -ErrorAction SilentlyContinue | Format-Table Name,Source"])
            .spawn()
    } else {
        StdCommand::new("x-terminal-emulator")
            .args([
                "-e",
                "sh",
                "-lc",
                "adb version; frida --version; frida-ps --version; python3 --version; exec sh",
            ])
            .spawn()
    };
    status
        .map(|_| "已打开系统终端并运行环境检测命令".into())
        .map_err(|error| format!("无法打开系统终端：{error}"))
}

fn now_millis() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

fn parse_quoted_value(line: &str, key: &str) -> Option<String> {
    let start = line.find(key)? + key.len();
    let value = line[start..]
        .trim_start_matches(|character: char| matches!(character, '=' | ':' | ' ' | '\'' | '"'));
    let end = value
        .find(|character: char| matches!(character, '\'' | '"' | ' '))
        .unwrap_or(value.len());
    Some(value[..end].to_string()).filter(|value| !value.is_empty())
}

fn parse_aapt_badging(text: &str, analysis: &mut AppAnalysis) {
    for line in text.lines() {
        if line.starts_with("package:") {
            analysis.package_id = parse_quoted_value(line, "name='");
            analysis.version_code = parse_quoted_value(line, "versionCode='");
            analysis.version_name = parse_quoted_value(line, "versionName='");
        } else if line.starts_with("application-label:") {
            analysis.display_name = parse_quoted_value(line, "application-label:");
        } else if line.starts_with("sdkVersion:") {
            analysis.min_sdk = parse_quoted_value(line, "sdkVersion:");
        } else if line.starts_with("targetSdkVersion:") {
            analysis.target_sdk = parse_quoted_value(line, "targetSdkVersion:");
        } else if line.starts_with("uses-permission:") {
            if let Some(permission) = parse_quoted_value(line, "name='") {
                analysis.permissions.push(permission);
            }
        } else if line.starts_with("launchable-activity:") {
            if let Some(component) = parse_quoted_value(line, "name='") {
                analysis.components.push(format!("activity: {component}"));
            }
        }
    }
}

fn parse_decoded_manifest(text: &str, analysis: &mut AppAnalysis) {
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("<manifest") {
            analysis.package_id = parse_quoted_value(trimmed, "package=");
            analysis.version_name = parse_quoted_value(trimmed, "android:versionName=");
            analysis.version_code = parse_quoted_value(trimmed, "android:versionCode=");
        }
        if trimmed.starts_with("<uses-sdk") {
            analysis.min_sdk = parse_quoted_value(trimmed, "android:minSdkVersion=");
            analysis.target_sdk = parse_quoted_value(trimmed, "android:targetSdkVersion=");
        }
        if trimmed.starts_with("<uses-permission") {
            if let Some(value) = parse_quoted_value(trimmed, "android:name=") {
                analysis.permissions.push(value);
            }
        }
        if trimmed.starts_with("<application") {
            for (key, label) in [
                ("android:debuggable=", "debuggable"),
                ("android:allowBackup=", "allowBackup"),
                ("android:usesCleartextTraffic=", "usesCleartextTraffic"),
                ("android:networkSecurityConfig=", "networkSecurityConfig"),
                ("android:extractNativeLibs=", "extractNativeLibs"),
            ] {
                if let Some(value) = parse_quoted_value(trimmed, key) {
                    analysis.manifest_flags.push(format!("{label}={value}"));
                    if (label == "debuggable" && value == "true")
                        || (label == "allowBackup" && value == "true")
                        || (label == "usesCleartextTraffic" && value == "true")
                    {
                        analysis.findings.push(AppFinding {
                            severity: "high".into(),
                            title: format!("Manifest 安全配置：{label}"),
                            detail: format!("{label}={value}，建议人工确认发布配置。"),
                        });
                    }
                }
            }
        }
        for tag in [
            "activity",
            "activity-alias",
            "service",
            "receiver",
            "provider",
            "instrumentation",
        ] {
            if trimmed.starts_with(&format!("<{tag}")) {
                if let Some(value) = parse_quoted_value(trimmed, "android:name=") {
                    let exported = parse_quoted_value(trimmed, "android:exported=")
                        .unwrap_or_else(|| "implicit/unspecified".into());
                    let permission = parse_quoted_value(trimmed, "android:permission=");
                    let authorities = parse_quoted_value(trimmed, "android:authorities=");
                    let mut component = format!("{tag}: {value} · exported={exported}");
                    if let Some(permission) = permission {
                        component.push_str(&format!(" · permission={permission}"));
                    }
                    if let Some(authorities) = authorities {
                        component.push_str(&format!(" · authorities={authorities}"));
                    }
                    if exported == "true" {
                        analysis.exported_components.push(component.clone());
                    }
                    analysis.components.push(component);
                }
            }
        }
    }
    // Decode nested intent-filter blocks separately. A line-oriented parser loses these
    // relationships when Apktool/AXML pretty-print attributes across multiple lines.
    for tag in [
        "activity",
        "activity-alias",
        "service",
        "receiver",
        "provider",
    ] {
        let pattern = format!(r#"(?s)<{tag}\b([^>]*)>(.*?)</{tag}>"#);
        let Ok(component_regex) = Regex::new(&pattern) else {
            continue;
        };
        for component_match in component_regex.captures_iter(text) {
            let attributes = component_match
                .get(1)
                .map(|value| value.as_str())
                .unwrap_or_default();
            let body = component_match
                .get(2)
                .map(|value| value.as_str())
                .unwrap_or_default();
            let Some(name) = parse_quoted_value(attributes, "android:name=") else {
                continue;
            };
            let explicit_exported = parse_quoted_value(attributes, "android:exported=");
            let permission = parse_quoted_value(attributes, "android:permission=");
            let Ok(filter_regex) = Regex::new(r#"(?s)<intent-filter\b[^>]*>(.*?)</intent-filter>"#)
            else {
                continue;
            };
            let mut has_filter = false;
            for filter_match in filter_regex.captures_iter(body) {
                has_filter = true;
                let filter = filter_match
                    .get(1)
                    .map(|value| value.as_str())
                    .unwrap_or_default();
                let mut values = Vec::new();
                for (element, label) in [("action", "action"), ("category", "category")] {
                    let expression = format!(r#"(?s)<{element}\b([^>]*)/?>"#);
                    if let Ok(regex) = Regex::new(&expression) {
                        for capture in regex.captures_iter(filter) {
                            if let Some(value) = capture.get(1).and_then(|attrs| {
                                parse_quoted_value(attrs.as_str(), "android:name=")
                            }) {
                                values.push(format!("{label}={value}"));
                            }
                        }
                    }
                }
                if let Ok(data_regex) = Regex::new(r#"(?s)<data\b([^>]*)/?>"#) {
                    for capture in data_regex.captures_iter(filter) {
                        let attrs = capture
                            .get(1)
                            .map(|value| value.as_str())
                            .unwrap_or_default();
                        let data = [
                            "scheme",
                            "host",
                            "port",
                            "path",
                            "pathPrefix",
                            "pathPattern",
                            "mimeType",
                        ]
                        .iter()
                        .filter_map(|key| {
                            parse_quoted_value(attrs, &format!("android:{key}="))
                                .map(|value| format!("{key}={value}"))
                        })
                        .collect::<Vec<_>>();
                        if !data.is_empty() {
                            values.push(format!("data({})", data.join(", ")));
                        }
                    }
                }
                analysis
                    .intent_filters
                    .push(format!("{tag}: {name} · {}", values.join(" · ")));
            }
            if has_filter && explicit_exported.as_deref() != Some("false") {
                let mut entry = format!(
                    "{tag}: {name} · exported={}",
                    explicit_exported
                        .as_deref()
                        .unwrap_or("implicit-via-intent-filter")
                );
                if let Some(permission) = &permission {
                    entry.push_str(&format!(" · permission={permission}"));
                }
                analysis.exported_components.push(entry);
            }
        }
    }
    if !analysis.exported_components.is_empty() {
        analysis.findings.push(AppFinding {
            severity: "review".into(),
            title: "存在导出组件".into(),
            detail: format!(
                "发现 {} 个 exported=true 组件，请检查权限保护和 Intent 输入校验。",
                analysis.exported_components.len()
            ),
        });
    }
    let sensitive_permissions: Vec<_> = analysis
        .permissions
        .iter()
        .filter(|permission| {
            [
                "READ_CONTACTS",
                "READ_SMS",
                "SEND_SMS",
                "RECORD_AUDIO",
                "CAMERA",
                "ACCESS_FINE_LOCATION",
                "READ_PHONE_STATE",
                "MANAGE_EXTERNAL_STORAGE",
                "SYSTEM_ALERT_WINDOW",
                "QUERY_ALL_PACKAGES",
            ]
            .iter()
            .any(|name| permission.ends_with(name))
        })
        .cloned()
        .collect();
    if !sensitive_permissions.is_empty() {
        analysis.findings.push(AppFinding {
            severity: "review".into(),
            title: "申请敏感权限".into(),
            detail: sensitive_permissions.join(", "),
        });
    }
}

fn collect_findings(files: &[String], findings: &mut Vec<AppFinding>) {
    let sensitive = files
        .iter()
        .filter(|name| {
            let lower = name.to_ascii_lowercase();
            lower.contains("shared_prefs")
                || lower.contains("databases")
                || lower.contains("webview")
                || lower.ends_with(".pem")
                || lower.ends_with(".key")
                || lower.ends_with(".jks")
                || lower.ends_with(".map")
        })
        .take(20);
    for name in sensitive {
        findings.push(AppFinding {
            severity: "review".into(),
            title: "敏感存储或调试资源线索".into(),
            detail: name.clone(),
        });
    }
    if files.iter().any(|name| name == "classes.dex") {
        findings.push(AppFinding {
            severity: "info".into(),
            title: "包含 DEX".into(),
            detail: "建议结合运行时观察确认动态加载行为。".into(),
        });
    }
}

fn classify_sensitive_name(name: &str) -> Option<(&'static str, &'static str)> {
    let lower = name.to_ascii_lowercase();
    let rules: &[(&[&str], &str, &str)] = &[
        (
            &["shared_prefs", "sharedpreferences"],
            "SharedPreferences",
            "review",
        ),
        (
            &["databases", ".sqlite", ".db", "realm"],
            "数据库/Realm",
            "review",
        ),
        (
            &["webview", "indexeddb", "indexdb", "cookies"],
            "WebView/IndexedDB",
            "review",
        ),
        (
            &["keychain", "keystore", ".jks", ".keystore"],
            "Keychain/Keystore",
            "review",
        ),
        (
            &[".pem", ".key", ".p12", ".pfx", "certificate"],
            "证书或私钥文件名",
            "high",
        ),
        (
            &[
                "api_key",
                "apikey",
                "client_secret",
                "password",
                "passwd",
                "token",
                "secret",
            ],
            "疑似凭据命名",
            "high",
        ),
        (
            &["firebase", "google-services", ".env", "mobileprovision"],
            "配置/服务凭据线索",
            "review",
        ),
    ];
    rules.iter().find_map(|(needles, kind, severity)| {
        needles
            .iter()
            .any(|needle| lower.contains(needle))
            .then_some((*kind, *severity))
    })
}

fn push_sensitive(
    items: &mut Vec<SensitiveItem>,
    item: &str,
    location: &str,
    kind: &str,
    severity: &str,
    value: Option<String>,
    line_number: Option<usize>,
    context: Option<String>,
) {
    items.push(SensitiveItem {
        item: item.into(),
        location: location.into(),
        kind: kind.into(),
        severity: severity.into(),
        value,
        line_number,
        context,
    });
}

fn sensitive_patterns() -> &'static Vec<(&'static str, &'static str, &'static str, Regex)> {
    static PATTERNS: OnceLock<Vec<(&str, &str, &str, Regex)>> = OnceLock::new();
    PATTERNS.get_or_init(|| {
        [
            ("URL / API endpoint", "url", "review", r#"(?i)\b(?:https?|wss?)://[^\s\"'<>]{4,}"#),
            ("API 相对路径", "api-endpoint", "review", r#"(?i)[\"']/(?:api|rest|graphql|oauth|openapi|gateway)(?:/|\?)[A-Za-z0-9_./?&=%{}:-]{2,}"#),
            ("IPv4 地址", "ip", "review", r#"\b(?:25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})(?:\.(?:25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})){3}\b"#),
            ("邮箱地址", "email", "review", r#"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b"#),
            ("手机号格式", "phone", "review", r#"\b1[3-9][0-9]{9}\b"#),
            ("身份证号格式", "identity", "high", r#"\b[1-9][0-9]{5}(?:19|20)[0-9]{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12][0-9]|3[01])[0-9]{3}[0-9Xx]\b"#),
            ("AWS Access Key", "access-key", "high", r#"\bAKIA[0-9A-Z]{16}\b"#),
            ("AWS Secret Access Key", "secret", "high", r#"(?i)aws[_-]?secret(?:_access)?[_-]?key\s*[:=]\s*[\"']?[A-Za-z0-9/+=]{40}\b"#),
            ("Google API Key", "api-key", "high", r#"\bAIza[0-9A-Za-z_-]{35}\b"#),
            ("Google Service Account 私钥 ID", "secret", "high", r#"(?i)private_key_id[\"']?\s*:\s*[\"'][0-9a-f]{20,}"#),
            ("Firebase Database URL", "url", "high", r#"(?i)https://[a-z0-9-]+\.(?:firebaseio\.com|firebasedatabase\.app)[^\s\"'<>]*"#),
            ("OAuth Client Secret", "secret", "high", r#"(?i)client[_-]?secret\s*[:=]\s*[\"']?[A-Za-z0-9._~+/=-]{12,}"#),
            ("Bearer Token", "token", "high", r#"(?i)bearer\s+[A-Za-z0-9._~+/=-]{16,}"#),
            ("GitHub Token", "token", "high", r#"\bgh[opusr]_[A-Za-z0-9]{30,255}\b"#),
            ("Slack Token", "token", "high", r#"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"#),
            ("Stripe Secret Key", "secret", "high", r#"\bsk_(?:live|test)_[A-Za-z0-9]{16,}\b"#),
            ("数据库连接串", "credential", "high", r#"(?i)\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis)://[^\s\"'<>]{8,}"#),
            ("JWT Token", "token", "high", r#"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}\b"#),
            ("私钥内容", "private-key", "high", r#"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"#),
            ("硬编码凭据字段", "credential", "high", r#"(?i)(?:api[_-]?key|access[_-]?key|secret[_-]?key|client[_-]?secret|aes[_-]?key|password|passwd|token)\s*[:=]\s*[\"']?[A-Za-z0-9_./+=:-]{6,}"#),
            ("弱加密 AES/ECB", "crypto", "review", r#"(?i)AES/(?:ECB|DES)|DESede|MD5withRSA"#),
        ]
        .into_iter()
        .filter_map(|(label, kind, severity, pattern)| Regex::new(pattern).ok().map(|regex| (label, kind, severity, regex)))
        .collect()
    })
}

fn match_context(text: &str, start: usize) -> (usize, String) {
    let mut offset = 0usize;
    let lines: Vec<&str> = text.lines().collect();
    let mut matched = 0usize;
    for (index, line) in lines.iter().enumerate() {
        let end = offset + line.len() + 1;
        if start < end {
            matched = index;
            break;
        }
        offset = end;
    }
    let begin = matched.saturating_sub(2);
    let end = (matched + 3).min(lines.len());
    let context = lines[begin..end]
        .iter()
        .enumerate()
        .map(|(index, line)| {
            let clipped: String = line.chars().take(500).collect();
            format!("{} | {}", begin + index + 1, clipped)
        })
        .collect::<Vec<_>>()
        .join("\n");
    (matched + 1, context)
}

fn ascii_strings(bytes: &[u8], minimum: usize) -> String {
    let mut output = String::new();
    let mut current = Vec::new();
    for byte in bytes {
        if byte.is_ascii_graphic() || *byte == b' ' || *byte == b'\t' {
            current.push(*byte);
        } else {
            if current.len() >= minimum {
                output.push_str(&String::from_utf8_lossy(&current));
                output.push('\n');
            }
            current.clear();
        }
    }
    if current.len() >= minimum {
        output.push_str(&String::from_utf8_lossy(&current));
    }
    output
}

fn scan_sensitive_text(text: &str, location: &str, items: &mut Vec<SensitiveItem>) {
    for (label, kind, severity, regex) in sensitive_patterns() {
        for matched in regex.find_iter(text).take(30) {
            let value: String = matched.as_str().chars().take(240).collect();
            if should_ignore_sensitive_match(kind, &value) {
                continue;
            }
            let effective_severity = if *kind == "ip"
                && (value.starts_with("10.")
                    || value.starts_with("192.168.")
                    || (value.starts_with("172.")
                        && value
                            .split('.')
                            .nth(1)
                            .and_then(|part| part.parse::<u8>().ok())
                            .is_some_and(|part| (16..=31).contains(&part))))
            {
                "high"
            } else {
                *severity
            };
            let (line_number, context) = match_context(text, matched.start());
            push_sensitive(
                items,
                label,
                location,
                kind,
                effective_severity,
                Some(value),
                Some(line_number),
                Some(context),
            );
        }
    }
}

fn shannon_entropy(value: &str) -> f64 {
    let mut counts = [0usize; 256];
    let bytes = value.as_bytes();
    if bytes.is_empty() {
        return 0.0;
    }
    for byte in bytes {
        counts[*byte as usize] += 1;
    }
    counts
        .iter()
        .filter(|count| **count > 0)
        .map(|count| {
            let probability = *count as f64 / bytes.len() as f64;
            -probability * probability.log2()
        })
        .sum()
}

fn should_ignore_sensitive_match(kind: &str, value: &str) -> bool {
    let lower = value
        .trim_matches(|character: char| "\"'(),.;[]{}".contains(character))
        .to_ascii_lowercase();
    if kind == "url" {
        let host = lower
            .split_once("://")
            .map(|(_, rest)| rest)
            .unwrap_or(&lower)
            .split(['/', ':', '?', '#'])
            .next()
            .unwrap_or_default()
            .trim_start_matches("www.");
        const NOISE_HOSTS: &[&str] = &[
            "github.com",
            "githubusercontent.com",
            "apache.org",
            "w3.org",
            "android.com",
            "developer.android.com",
            "schemas.android.com",
            "kotlinlang.org",
            "gradle.org",
            "maven.org",
            "maven.apache.org",
            "squareup.com",
            "developer.apple.com",
            "opensource.org",
            "gnu.org",
            "ietf.org",
            "xmlpull.org",
            "example.com",
            "example.org",
            "localhost",
            "127.0.0.1",
        ];
        return NOISE_HOSTS
            .iter()
            .any(|noise| host == *noise || host.ends_with(&format!(".{noise}")));
    }
    if kind == "ip" {
        return matches!(lower.as_str(), "0.0.0.0" | "127.0.0.1" | "255.255.255.255");
    }
    if matches!(
        kind,
        "credential" | "secret" | "token" | "api-key" | "access-key"
    ) {
        let candidate = value
            .rsplit_once(['=', ':'])
            .map(|(_, candidate)| candidate)
            .unwrap_or(value)
            .trim_matches(|character: char| " \t\r\n\"'".contains(character));
        let candidate_lower = candidate.to_ascii_lowercase();
        const PLACEHOLDERS: &[&str] = &[
            "password",
            "passwd",
            "secret",
            "token",
            "apikey",
            "api_key",
            "changeme",
            "your_key",
            "your_secret",
            "insert_here",
            "replace_me",
            "undefined",
            "null",
            "example",
            "sample",
            "dummy",
            "test",
            "development",
        ];
        if candidate.len() < 8
            || PLACEHOLDERS
                .iter()
                .any(|placeholder| candidate_lower.contains(placeholder))
        {
            return true;
        }
        return candidate.len() < 20 && shannon_entropy(candidate) < 3.0;
    }
    false
}

fn detect_frameworks(files: &[String]) -> Vec<String> {
    let lower: Vec<String> = files.iter().map(|file| file.to_ascii_lowercase()).collect();
    let rules: &[(&str, &[&str])] = &[
        (
            "Flutter",
            &[
                "libflutter.so",
                "flutter_assets/",
                "flutter.framework",
                "main.dart.js",
            ],
        ),
        (
            "React Native",
            &["main.jsbundle", "reactnative", "libreactnative"],
        ),
        (
            "React Native · Hermes",
            &["libhermes.so", "hermes.framework", "hermesbytecode"],
        ),
        (
            "Unity",
            &["libunity.so", "unityframework.framework", "assets/bin/data"],
        ),
        ("Cordova / WebView", &["cordova.js", "www/", "webview"]),
        (
            "Xamarin / .NET",
            &["libmonosgen-2.0.so", "assemblies/", "xamarin"],
        ),
        (
            "Native Android/iOS",
            &["classes.dex", "info.plist", "frameworks/"],
        ),
    ];
    rules
        .iter()
        .filter(|(_, needles)| {
            needles
                .iter()
                .any(|needle| lower.iter().any(|file| file.contains(needle)))
        })
        .map(|(label, _)| (*label).into())
        .collect()
}

fn detect_third_party_libraries(archive: &mut ZipArchive<File>, files: &[String]) -> Vec<String> {
    let mut haystack = files.join("\n").to_ascii_lowercase();
    for name in files
        .iter()
        .filter(|name| {
            let lower = name.to_ascii_lowercase();
            (lower.ends_with(".dex")
                || lower.ends_with(".so")
                || lower.ends_with(".jsbundle")
                || lower.ends_with(".bundle")
                || lower.ends_with(".plist"))
                && !lower.contains("/assets.car")
        })
        .take(40)
    {
        if let Ok(mut entry) = archive.by_name(name) {
            if entry.size() <= 20 * 1024 * 1024 {
                let mut bytes = Vec::new();
                let _ = entry.read_to_end(&mut bytes);
                haystack.push('\n');
                haystack.push_str(&ascii_strings(&bytes, 5).to_ascii_lowercase());
            }
        }
    }
    let rules: &[(&str, &[&str])] = &[
        (
            "Fastjson",
            &["com/alibaba/fastjson", "com.alibaba.fastjson"],
        ),
        ("Log4j", &["org/apache/log4j", "org.apache.log4j"]),
        ("OkHttp", &["okhttp3/", "com/squareup/okhttp"]),
        ("Retrofit", &["retrofit2/", "com/squareup/retrofit"]),
        ("Gson", &["com/google/gson", "com.google.gson"]),
        (
            "Jackson",
            &["com/fasterxml/jackson", "org/codehaus/jackson"],
        ),
        ("Protobuf", &["com/google/protobuf", "libprotobuf"]),
        ("RxJava", &["io/reactivex", "rxjava"]),
        ("Glide", &["com/bumptech/glide", "bumptech.glide"]),
        ("Picasso", &["com/squareup/picasso"]),
        ("腾讯 X5/TBS", &["com/tencent/smtt", "libtbs"]),
        ("Bugly", &["com/tencent/bugly", "libbugly"]),
        (
            "Firebase",
            &[
                "com/google/firebase",
                "googleservice-info.plist",
                "google-services.json",
            ],
        ),
        ("支付宝 SDK", &["com/alipay", "alipay.framework"]),
        ("微信 SDK", &["com/tencent/mm/opensdk", "wechatopensdk"]),
        ("高德地图 SDK", &["com/amap/api", "libamap"]),
        ("百度地图 SDK", &["com/baidu/mapapi", "baidumapapi"]),
        ("Room", &["androidx/room", "androidx.room"]),
        ("Realm", &["io/realm", "realm.framework"]),
        ("Alamofire", &["alamofire.framework", "alamofire"]),
        ("AFNetworking", &["afnetworking.framework", "afnetworking"]),
        ("SDWebImage", &["sdwebimage.framework", "sdwebimage"]),
        ("Kingfisher", &["kingfisher.framework", "kingfisher"]),
        ("SnapKit", &["snapkit.framework", "snapkit"]),
        ("PromiseKit", &["promisekit.framework", "promisekit"]),
        ("CocoaLumberjack", &["cocoalumberjack", "ddlog"]),
        (
            "Google Analytics",
            &["googleanalytics", "firebase/analytics"],
        ),
        ("Sentry", &["io/sentry", "sentry.framework", "libsentry"]),
        ("友盟 Umeng", &["com/umeng", "umeng", "libumeng"]),
        ("极光推送 JPush", &["cn/jpush", "jpush", "jcore"]),
        ("Mob SDK", &["com/mob/", "mobfoundation.framework"]),
        ("Facebook SDK", &["com/facebook/", "fbsdkcorekit"]),
        (
            "Google Play Services",
            &["com/google/android/gms", "googlemobileads"],
        ),
        ("SQLCipher", &["net/sqlcipher", "libsqlcipher"]),
        ("MMKV", &["com/tencent/mmkv", "libmmkv"]),
        ("Dagger/Hilt", &["dagger/", "hilt_aggregated_deps"]),
        ("Koin", &["org/koin", "koin.core"]),
        ("EventBus", &["org/greenrobot/eventbus"]),
        ("WebSocket/Socket.IO", &["socket.io", "okhttp3/internal/ws"]),
        ("Flutter Engine", &["flutter.framework", "libflutter.so"]),
        (
            "Flutter Dart App",
            &["libapp.so", "app.framework/app", "flutter_assets"],
        ),
        ("React Native", &["main.jsbundle", "reactnative"]),
        (
            "Hermes JavaScript Engine",
            &["libhermes.so", "hermes.framework", "hbc\0"],
        ),
        (
            "Cordova/Ionic",
            &["cordova.js", "assets/www/", "www/index.html"],
        ),
        ("Xamarin/Mono", &["libmonosgen", "xamarin", "assemblies/"]),
        ("Unity", &["unityframework.framework", "libunity.so"]),
    ];
    rules
        .iter()
        .filter(|(_, needles)| needles.iter().any(|needle| haystack.contains(needle)))
        .map(|(label, _)| (*label).to_string())
        .collect()
}

fn assess_protection(files: &[String]) -> ProtectionAssessment {
    let lower: Vec<String> = files.iter().map(|file| file.to_ascii_lowercase()).collect();
    let mut packers = Vec::new();
    let mut indicators = Vec::new();
    let rules: &[(&str, &[&str])] = &[
        ("梆梆/娜迦类", &["libjiagu", "libsecexe", "libprotectclass"]),
        ("腾讯乐固类", &["libshell", "libtup", "libtosprotection"]),
        ("360 加固类", &["libjiagu_a", "lib360", "libprotect"]),
        ("爱加密类", &["ijiami", "libexecmain", "libexec"]),
        (
            "DexGuard/Guard 类",
            &["dexguard", "libdexhelper", "libdexguard"],
        ),
        (
            "通用自定义壳线索",
            &[
                "assets/shell",
                "assets/secneo",
                "classes2.dex",
                "classes3.dex",
            ],
        ),
    ];
    for (label, needles) in rules {
        if needles
            .iter()
            .any(|needle| lower.iter().any(|file| file.contains(needle)))
        {
            packers.push((*label).into());
        }
    }
    let dex_count = lower.iter().filter(|file| file.ends_with(".dex")).count();
    if dex_count > 1 {
        indicators.push(format!(
            "发现 {dex_count} 个 DEX 文件，存在拆分/动态加载线索"
        ));
    }
    if lower
        .iter()
        .any(|file| file.contains("assets") && file.ends_with(".dat"))
    {
        indicators.push("assets 中存在非标准数据文件".into());
    }
    if lower
        .iter()
        .any(|file| file.contains("classes.dex") && file.contains("unknown"))
    {
        indicators.push("DEX 路径异常或被重命名".into());
    }
    let status = if packers.is_empty() {
        "未命中已知加固壳特征"
    } else {
        "疑似存在加固壳"
    };
    ProtectionAssessment {
        status: status.into(),
        packers,
        indicators,
    }
}

fn enrich_protection_from_manifest(manifest: &str, protection: &mut ProtectionAssessment) {
    let lower = manifest.to_ascii_lowercase();
    let rules: &[(&str, &[&str])] = &[
        (
            "360 加固 / StubApp",
            &["com.stub.stubapp", "com.qihoo.util.stubapplication"],
        ),
        (
            "梆梆 / SecNeo",
            &["com.secneo.apkwrapper", "com.secneo.guard"],
        ),
        ("腾讯乐固", &["com.tencent.stub", "tencent.legu"]),
        ("爱加密", &["com.ijiami", "s.h.e.l.l.s"]),
        (
            "阿里聚安全",
            &["com.ali.mobisecenhance", "com.alibaba.wireless.security"],
        ),
        ("网易易盾", &["com.netease.nis.wrapper", "com.netease.nis"]),
        ("百度加固", &["com.baidu.protect", "com.baidu.mobstat.stub"]),
        (
            "通用 ProxyApplication 壳",
            &["proxyapplication", "shellapplication"],
        ),
    ];
    for (label, needles) in rules {
        if needles.iter().any(|needle| lower.contains(needle))
            && !protection.packers.iter().any(|value| value == label)
        {
            protection.packers.push((*label).into());
        }
    }
    if !protection.packers.is_empty() {
        protection.status = "疑似存在加固壳".into();
        protection
            .indicators
            .push("Manifest Application/ComponentFactory 命中已知壳特征".into());
    }
}

fn macho_architectures(bytes: &[u8]) -> Vec<String> {
    let mut result = Vec::new();
    let mut add = |cpu: u32| {
        let label = match cpu {
            0x0100000c => "arm64",
            0x01000007 => "x86_64",
            12 => "armv7",
            7 => "x86",
            _ => return,
        };
        if !result.iter().any(|value: &String| value == label) {
            result.push(label.into());
        }
    };
    if bytes.len() >= 8 {
        let magic_le = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let magic_be = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        if magic_le == 0xfeedfacf || magic_le == 0xfeedface {
            add(u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]));
        } else if magic_be == 0xcafebabe || magic_be == 0xcafebabf {
            let count = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]) as usize;
            let stride = if magic_be == 0xcafebabf { 32 } else { 20 };
            for index in 0..count.min(32) {
                let offset = 8 + index * stride;
                if offset + 4 <= bytes.len() {
                    add(u32::from_be_bytes([
                        bytes[offset],
                        bytes[offset + 1],
                        bytes[offset + 2],
                        bytes[offset + 3],
                    ]));
                }
            }
        }
    }
    result
}

fn macho_encryption_state(bytes: &[u8]) -> Option<bool> {
    if bytes.len() < 32 {
        return None;
    }
    let magic_be = u32::from_be_bytes(bytes[0..4].try_into().ok()?);
    let mut offset = 0usize;
    if magic_be == 0xcafebabe || magic_be == 0xcafebabf {
        let fat64 = magic_be == 0xcafebabf;
        offset = if fat64 {
            u64::from_be_bytes(bytes.get(16..24)?.try_into().ok()?) as usize
        } else {
            u32::from_be_bytes(bytes.get(16..20)?.try_into().ok()?) as usize
        };
    }
    let magic = u32::from_le_bytes(bytes.get(offset..offset + 4)?.try_into().ok()?);
    let header_size = match magic {
        0xfeedfacf => 32usize,
        0xfeedface => 28usize,
        _ => return None,
    };
    let commands =
        u32::from_le_bytes(bytes.get(offset + 16..offset + 20)?.try_into().ok()?) as usize;
    let mut cursor = offset + header_size;
    for _ in 0..commands.min(4096) {
        let command = u32::from_le_bytes(bytes.get(cursor..cursor + 4)?.try_into().ok()?);
        let size = u32::from_le_bytes(bytes.get(cursor + 4..cursor + 8)?.try_into().ok()?) as usize;
        if size < 8 || cursor + size > bytes.len() {
            return None;
        }
        if command == 0x21 || command == 0x2c {
            let cryptid = u32::from_le_bytes(bytes.get(cursor + 16..cursor + 20)?.try_into().ok()?);
            return Some(cryptid != 0);
        }
        cursor += size;
    }
    Some(false)
}

fn macho_security_flags(bytes: &[u8]) -> Vec<String> {
    if bytes.len() < 32 {
        return Vec::new();
    }
    let magic_be = u32::from_be_bytes(bytes[0..4].try_into().unwrap_or_default());
    let offset = if magic_be == 0xcafebabe {
        u32::from_be_bytes(
            bytes
                .get(16..20)
                .and_then(|slice| slice.try_into().ok())
                .unwrap_or([0; 4]),
        ) as usize
    } else if magic_be == 0xcafebabf {
        u64::from_be_bytes(
            bytes
                .get(16..24)
                .and_then(|slice| slice.try_into().ok())
                .unwrap_or([0; 8]),
        ) as usize
    } else {
        0
    };
    let Some(flags) = bytes
        .get(offset + 24..offset + 28)
        .and_then(|slice| slice.try_into().ok())
        .map(u32::from_le_bytes)
    else {
        return Vec::new();
    };
    let strings = ascii_strings(bytes, 6);
    vec![
        format!("Mach-O PIE={}", flags & 0x20_0000 != 0),
        format!(
            "Stack protector={}",
            strings.contains("___stack_chk_fail") || strings.contains("__stack_chk_guard")
        ),
        format!(
            "ARC runtime={}",
            strings.contains("_objc_retain") || strings.contains("_objc_release")
        ),
    ]
}

fn is_deep_binary_candidate(name: &str) -> bool {
    let leaf = name.rsplit('/').next().unwrap_or_default();
    let extensionless_app_binary = name.contains(".app/")
        && !leaf.is_empty()
        && !leaf.contains('.')
        && !matches!(leaf, "Payload" | "Frameworks" | "PlugIns");
    name.ends_with(".dex")
        || name.ends_with(".so")
        || name.ends_with(".jsbundle")
        || name.ends_with("index.android.bundle")
        || name.contains(".framework/")
        || extensionless_app_binary
        || leaf.eq_ignore_ascii_case("libapp.so")
}

fn collect_sensitive_items(archive: &mut ZipArchive<File>, files: &[String]) -> Vec<SensitiveItem> {
    let mut items = Vec::new();
    for name in files {
        if let Some((kind, severity)) = classify_sensitive_name(name) {
            items.push(SensitiveItem {
                item: kind.into(),
                location: name.clone(),
                kind: "archive-entry".into(),
                severity: severity.into(),
                value: None,
                line_number: None,
                context: None,
            });
        }
        let binary_like = is_deep_binary_candidate(name);
        // Flutter concentrates Dart snapshots and constant strings in
        // libapp.so (Android) or the extensionless App/Framework Mach-O (iOS),
        // which are commonly much larger than ordinary resources.
        let text_like = name.ends_with(".xml")
            || name.ends_with(".json")
            || name.ends_with(".plist")
            || name.ends_with(".properties")
            || name.ends_with(".txt")
            || name.ends_with(".js")
            || name.ends_with(".jsbundle")
            || name.ends_with(".bundle")
            || name.ends_with(".smali")
            || name.ends_with(".java")
            || name.ends_with(".kt")
            || name.ends_with(".dart")
            || name.ends_with(".swift")
            || name.ends_with(".m")
            || name.ends_with(".yaml")
            || name.ends_with(".yml")
            || name.ends_with(".gradle")
            || binary_like;
        if text_like && items.len() < 400 {
            if let Ok(mut entry) = archive.by_name(name) {
                let size_limit = if binary_like {
                    128 * 1024 * 1024
                } else {
                    32 * 1024 * 1024
                };
                if entry.size() <= size_limit {
                    let mut bytes = Vec::new();
                    let _ = entry.read_to_end(&mut bytes);
                    let text = if binary_like || bytes.starts_with(b"bplist") {
                        ascii_strings(&bytes, 5)
                    } else {
                        String::from_utf8_lossy(&bytes).into_owned()
                    };
                    scan_sensitive_text(&text, name, &mut items);
                }
            }
        }
    }
    items.sort_by(|a, b| {
        a.location
            .cmp(&b.location)
            .then(a.item.cmp(&b.item))
            .then(a.value.cmp(&b.value))
    });
    items.dedup_by(|a, b| a.location == b.location && a.item == b.item && a.value == b.value);
    items.truncate(300);
    items
}

fn read_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    bytes
        .get(offset..offset + 2)
        .map(|value| u16::from_le_bytes([value[0], value[1]]))
}

fn read_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    bytes
        .get(offset..offset + 4)
        .map(|value| u32::from_le_bytes([value[0], value[1], value[2], value[3]]))
}

fn axml_string_pool(bytes: &[u8]) -> Option<(Vec<String>, usize)> {
    if read_u16(bytes, 0)? != 0x0001 {
        return None;
    }
    let header_size = read_u16(bytes, 2)? as usize;
    let chunk_size = read_u32(bytes, 4)? as usize;
    let string_count = read_u32(bytes, 8)? as usize;
    let style_count = read_u32(bytes, 12)? as usize;
    let flags = read_u32(bytes, 16)?;
    let strings_start = read_u32(bytes, 20)? as usize;
    if chunk_size > bytes.len() || header_size < 28 {
        return None;
    }
    let offsets_start = header_size;
    let mut strings = Vec::with_capacity(string_count);
    for index in 0..string_count {
        let relative = read_u32(bytes, offsets_start + index * 4)? as usize;
        let start = strings_start.checked_add(relative)?;
        if start >= bytes.len() {
            strings.push(String::new());
            continue;
        }
        if flags & 0x100 != 0 {
            let first = *bytes.get(start)? as usize;
            let (length_bytes, mut cursor) = if first & 0x80 != 0 {
                (
                    ((first & 0x7f) << 8) | (*bytes.get(start + 1)? as usize),
                    start + 2,
                )
            } else {
                (first, start + 1)
            };
            let byte_length = *bytes.get(cursor)? as usize;
            cursor += if byte_length & 0x80 != 0 {
                let _second = *bytes.get(cursor + 1)? as usize;
                2
            } else {
                1
            };
            let actual_length = if byte_length & 0x80 != 0 {
                (byte_length & 0x7f) << 8 | (*bytes.get(cursor - 1)? as usize)
            } else {
                byte_length
            };
            let _ = length_bytes;
            let end = cursor.saturating_add(actual_length).min(bytes.len());
            strings.push(String::from_utf8_lossy(&bytes[cursor..end]).into_owned());
        } else {
            let first = read_u16(bytes, start)? as usize;
            let (length, cursor) = if first & 0x8000 != 0 {
                (
                    ((first & 0x7fff) << 16) | read_u16(bytes, start + 2)? as usize,
                    start + 4,
                )
            } else {
                (first, start + 2)
            };
            let end = cursor
                .saturating_add(length.saturating_mul(2))
                .min(bytes.len());
            let mut value = String::new();
            for pair in bytes[cursor..end].chunks_exact(2) {
                value.push(
                    char::from_u32(u16::from_le_bytes([pair[0], pair[1]]) as u32)
                        .unwrap_or('\u{fffd}'),
                );
            }
            strings.push(value);
        }
    }
    let after_pool = if style_count == 0 {
        chunk_size
    } else {
        strings_start.max(header_size + string_count * 4 + style_count * 4)
    };
    Some((strings, after_pool))
}

fn axml_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn decode_axml(bytes: &[u8]) -> Option<String> {
    let xml_header_size = if read_u16(bytes, 0)? == 0x0003 {
        read_u16(bytes, 2)? as usize
    } else {
        0
    };
    let (strings, pool_size) = axml_string_pool(bytes.get(xml_header_size..)?)?;
    let mut cursor = xml_header_size + pool_size;
    let mut xml = String::from("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n");
    let mut depth = 0usize;
    let mut open = Vec::<String>::new();
    let mut android_namespaces = Vec::<u32>::new();
    while cursor + 8 <= bytes.len() {
        let chunk_type = read_u16(bytes, cursor)?;
        let header_size = read_u16(bytes, cursor + 2)? as usize;
        let chunk_size = read_u32(bytes, cursor + 4)? as usize;
        if chunk_size < header_size || cursor + chunk_size > bytes.len() || chunk_size == 0 {
            break;
        }
        match chunk_type {
            0x0100 => {
                if let Some(uri) = read_u32(bytes, cursor + 20) {
                    if strings
                        .get(uri as usize)
                        .map(|value| value == "http://schemas.android.com/apk/res/android")
                        .unwrap_or(false)
                    {
                        android_namespaces.push(uri);
                    }
                }
            }
            0x0102 => {
                if chunk_size < 36 {
                    break;
                }
                let name_index = read_u32(bytes, cursor + 20)? as usize;
                let attribute_start = read_u16(bytes, cursor + 24)? as usize;
                let attribute_size = read_u16(bytes, cursor + 26)? as usize;
                let attribute_count = read_u16(bytes, cursor + 28)? as usize;
                let name = strings
                    .get(name_index)
                    .cloned()
                    .unwrap_or_else(|| "node".into());
                xml.push_str(&format!("{}<{}", "  ".repeat(depth), name));
                // attributeStart is relative to ResXMLTree_attrExt, which begins
                // after the 16-byte ResXMLTree_node header.
                let attrs_base = cursor + 16 + attribute_start;
                for index in 0..attribute_count {
                    let base = attrs_base + index * attribute_size.max(20);
                    let attr_name = strings
                        .get(read_u32(bytes, base + 4)? as usize)
                        .cloned()
                        .unwrap_or_else(|| "attr".into());
                    let attr_namespace = read_u32(bytes, base).unwrap_or(u32::MAX);
                    let is_android_namespace = android_namespaces.contains(&attr_namespace)
                        || strings
                            .get(attr_namespace as usize)
                            .map(|value| value.contains("schemas.android.com/apk/res/android"))
                            .unwrap_or(false)
                        || (attr_namespace != u32::MAX
                            && matches!(
                                attr_name.as_str(),
                                "name"
                                    | "versionCode"
                                    | "versionName"
                                    | "minSdkVersion"
                                    | "targetSdkVersion"
                                    | "exported"
                                    | "permission"
                                    | "authorities"
                                    | "debuggable"
                                    | "allowBackup"
                                    | "usesCleartextTraffic"
                                    | "networkSecurityConfig"
                                    | "extractNativeLibs"
                            ));
                    let attr_name = if is_android_namespace {
                        format!("android:{attr_name}")
                    } else {
                        attr_name
                    };
                    let raw = read_u32(bytes, base + 8)?;
                    let value_type = read_u32(bytes, base + 12)? >> 24;
                    let value_data = read_u32(bytes, base + 16)?;
                    let value = if raw != u32::MAX {
                        strings.get(raw as usize).cloned().unwrap_or_default()
                    } else if value_type == 0x03 {
                        strings
                            .get(value_data as usize)
                            .cloned()
                            .unwrap_or_default()
                    } else if value_type == 0x12 {
                        if value_data != 0 {
                            "true".into()
                        } else {
                            "false".into()
                        }
                    } else if value_type == 0x10 {
                        value_data.to_string()
                    } else {
                        format!("@0x{value_data:08x}")
                    };
                    xml.push_str(&format!(" {}=\"{}\"", attr_name, axml_escape(&value)));
                }
                xml.push_str(">\n");
                open.push(name);
                depth += 1;
            }
            0x0103 => {
                if depth == 0 {
                    cursor += chunk_size;
                    continue;
                }
                depth -= 1;
                let name_index = read_u32(bytes, cursor + 20).unwrap_or(u32::MAX) as usize;
                let name = strings
                    .get(name_index)
                    .cloned()
                    .or_else(|| open.pop())
                    .unwrap_or_else(|| "node".into());
                let _ = open.pop();
                xml.push_str(&format!("{}</{}>\n", "  ".repeat(depth), name));
            }
            _ => {}
        }
        cursor += chunk_size;
    }
    (xml.lines().count() > 1).then_some(xml)
}

async fn decode_android_manifest(
    path: &str,
    apktool_path: Option<&str>,
    jadx_path: Option<&str>,
) -> Option<String> {
    // Prefer an installed AXMLPrinter-compatible decoder for binary XML.
    let manifest_path = std::env::temp_dir().join(format!(
        "security-console-{}-AndroidManifest.xml",
        now_millis()
    ));
    if let Ok(file) = File::open(path) {
        if let Ok(mut archive) = ZipArchive::new(file) {
            let manifest_bytes =
                archive
                    .by_name("AndroidManifest.xml")
                    .ok()
                    .and_then(|mut entry| {
                        let mut bytes = Vec::new();
                        entry.read_to_end(&mut bytes).ok().map(|_| bytes)
                    });
            if let Some(bytes) = manifest_bytes {
                if let Some(decoded) = decode_axml(&bytes) {
                    return Some(decoded);
                }
                if fs::write(&manifest_path, bytes).is_ok() {
                    for decoder in ["axmlprinter", "axml"] {
                        if let Ok(output) =
                            run_host(decoder, &[manifest_path.to_string_lossy().into_owned()]).await
                        {
                            let text = output_text(&output);
                            if !text.is_empty() && output.code == Some(0) {
                                let _ = fs::remove_file(&manifest_path);
                                return Some(text);
                            }
                        }
                    }
                }
            }
        }
    }
    let _ = fs::remove_file(&manifest_path);
    let args = vec![
        "dump".into(),
        "xmltree".into(),
        path.into(),
        "AndroidManifest.xml".into(),
    ];
    if let Ok(output) = run_host("aapt", &args).await {
        let text = output_text(&output);
        if !text.is_empty() && (output.code == Some(0) || text.contains("E: manifest")) {
            return Some(text);
        }
    }
    let args = vec!["manifest".into(), "print".into(), path.into()];
    if let Ok(output) = run_host("apkanalyzer", &args).await {
        let text = output_text(&output);
        if !text.is_empty() {
            return Some(text);
        }
    }
    for (tool, kind) in [(apktool_path, "apktool"), (jadx_path, "jadx")] {
        let Some(tool) = tool.filter(|value| !value.trim().is_empty()) else {
            continue;
        };
        let output_dir =
            std::env::temp_dir().join(format!("security-console-{}-{kind}", now_millis()));
        let args = if kind == "apktool" {
            vec![
                "d".into(),
                "-f".into(),
                "--no-src".into(),
                "-o".into(),
                output_dir.to_string_lossy().into_owned(),
                path.into(),
            ]
        } else {
            vec![
                "-q".into(),
                "-d".into(),
                output_dir.to_string_lossy().into_owned(),
                path.into(),
            ]
        };
        if let Ok(output) = run_explicit_program(Path::new(tool), &args).await {
            let candidates = if kind == "apktool" {
                vec![output_dir.join("AndroidManifest.xml")]
            } else {
                vec![
                    output_dir.join("resources/AndroidManifest.xml"),
                    output_dir.join("AndroidManifest.xml"),
                ]
            };
            for candidate in candidates {
                if let Ok(text) = fs::read_to_string(&candidate) {
                    let _ = fs::remove_dir_all(&output_dir);
                    return Some(text);
                }
            }
            let _ = fs::remove_dir_all(&output_dir);
            if output.code != Some(0) && !output.stderr.is_empty() {
                continue;
            }
        }
    }
    None
}

#[tauri::command]
pub async fn analyze_app(request: AnalyzeAppRequest) -> Result<AppAnalysis, String> {
    let path = request.path;
    let apktool_path = request.apktool_path;
    let jadx_path = request.jadx_path;
    let file = Path::new(&path);
    if !file.is_file() {
        return Err("分析文件不存在".into());
    }
    let extension = file
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    if !matches!(extension.as_str(), "apk" | "ipa") {
        return Err("仅支持 APK 或 IPA".into());
    }
    let metadata = fs::metadata(file).map_err(|error| error.to_string())?;
    let mut archive = ZipArchive::new(File::open(file).map_err(|error| error.to_string())?)
        .map_err(|error| format!("文件不是有效的 APK/IPA：{error}"))?;
    let files: Vec<String> = (0..archive.len())
        .filter_map(|index| {
            archive
                .by_index(index)
                .ok()
                .map(|entry| entry.name().to_string())
        })
        .take(5000)
        .collect();
    let platform = if extension == "apk" { "android" } else { "ios" };
    let mut analysis = AppAnalysis {
        platform: platform.into(),
        path: path.clone(),
        file_name: file
            .file_name()
            .and_then(|value| value.to_str())
            .unwrap_or_default()
            .into(),
        file_size: metadata.len(),
        package_id: None,
        display_name: None,
        version_name: None,
        version_code: None,
        min_sdk: None,
        target_sdk: None,
        architectures: Vec::new(),
        frameworks: detect_frameworks(&files),
        third_party_libraries: Vec::new(),
        protection: assess_protection(&files),
        permissions: Vec::new(),
        components: Vec::new(),
        exported_components: Vec::new(),
        intent_filters: Vec::new(),
        manifest_flags: Vec::new(),
        files: files.clone(),
        manifest_xml: None,
        sensitive_items: Vec::new(),
        signature: None,
        findings: Vec::new(),
        tools_used: vec!["Rust ZIP/DEX/Mach-O scanner".into()],
        missing_dependencies: Vec::new(),
    };
    analysis.third_party_libraries = detect_third_party_libraries(&mut archive, &files);
    analysis.sensitive_items = collect_sensitive_items(&mut archive, &files);
    collect_findings(&files, &mut analysis.findings);
    for name in &files {
        if let Some(abi) = name
            .strip_prefix("lib/")
            .and_then(|value| value.split('/').next())
        {
            if ["arm64-v8a", "armeabi-v7a", "x86", "x86_64"].contains(&abi)
                && !analysis.architectures.contains(&abi.to_string())
            {
                analysis.architectures.push(abi.to_string());
            }
        }
    }
    if extension == "apk" {
        if cohesive_frida_executable_path("java").is_none() {
            analysis.missing_dependencies.push(
                "未检测到 Java：内置 Rust 分析仍可运行，但 JADX/Apktool JAR 无法启动；IPA 分析不依赖 Java"
                    .into(),
            );
        } else {
            analysis.tools_used.push("Java runtime detected".into());
        }
        analysis.manifest_xml =
            decode_android_manifest(&path, apktool_path.as_deref(), jadx_path.as_deref()).await;
        if let Some(manifest) = analysis.manifest_xml.clone() {
            parse_decoded_manifest(&manifest, &mut analysis);
            enrich_protection_from_manifest(&manifest, &mut analysis.protection);
            analysis.tools_used.push("内置 Rust AXML decoder".into());
        } else {
            analysis
                .missing_dependencies
                .push("Manifest 解析失败：可配置 Apktool 或 JADX 路径作为回退".into());
        }
        if let Ok(output) = run_host("aapt", &["dump".into(), "badging".into(), path.clone()]).await
        {
            if output.code == Some(0) {
                parse_aapt_badging(&output.stdout, &mut analysis);
                analysis.tools_used.push("aapt".into());
            }
        }
        if let Ok(output) = run_host(
            "apksigner",
            &[
                "verify".into(),
                "--verbose".into(),
                "--print-certs".into(),
                path.clone(),
            ],
        )
        .await
        {
            let signature_lines: Vec<_> = output
                .stdout
                .lines()
                .filter(|line| {
                    line.contains("Signer #")
                        || line.contains("Verified using v")
                        || line.contains("Number of signers")
                })
                .take(20)
                .map(str::to_string)
                .collect();
            analysis.signature = (!signature_lines.is_empty()).then(|| signature_lines.join("\n"));
            if output.stdout.to_ascii_lowercase().contains("android debug") {
                analysis.findings.push(AppFinding {
                    severity: "high".into(),
                    title: "APK 使用调试证书".into(),
                    detail: "签名主题包含 Android Debug，请勿用于正式发布。".into(),
                });
            }
            if output.stdout.contains("SHA1withRSA") || output.stdout.contains("MD5withRSA") {
                analysis.findings.push(AppFinding {
                    severity: "high".into(),
                    title: "APK 使用弱签名算法".into(),
                    detail: "检测到 SHA1withRSA/MD5withRSA，建议升级签名算法。".into(),
                });
            }
            analysis.tools_used.push("apksigner".into());
        } else {
            analysis
                .missing_dependencies
                .push("未找到 apksigner：暂不能验证 V1/V2/V3 签名与证书摘要".into());
        }
        for (configured, kind, label) in [
            (apktool_path.as_deref(), "apktool", "Apktool"),
            (jadx_path.as_deref(), "jadx", "JADX"),
        ] {
            let Some(tool) = configured.filter(|value| !value.trim().is_empty()) else {
                if kind == "jadx" {
                    analysis.missing_dependencies.push(
                        "未配置 JADX：敏感信息上下文来自 DEX 可见字符串，不是完整 Java 源码".into(),
                    );
                }
                continue;
            };
            if !Path::new(tool).is_file() {
                analysis
                    .missing_dependencies
                    .push(format!("{label} 路径不存在：{tool}"));
                continue;
            }
            match run_configured_static_tool(&path, tool, kind).await {
                Ok(items) => {
                    analysis.sensitive_items.extend(items);
                    analysis.tools_used.push(format!("{label} configured path"));
                }
                Err(error) => analysis
                    .missing_dependencies
                    .push(format!("{label} 执行失败：{error}")),
            }
        }
    } else if let Some(plist) = files
        .iter()
        .find(|name| name.starts_with("Payload/") && name.ends_with(".app/Info.plist"))
    {
        let mut bytes = Vec::new();
        if let Ok(mut entry) = archive.by_name(plist) {
            let _ = entry.read_to_end(&mut bytes);
        }
        let temp = std::env::temp_dir().join(format!("security-console-{}.plist", now_millis()));
        if fs::write(&temp, bytes).is_ok() {
            if let Ok(output) = run_host(
                "plutil",
                &["-p".into(), temp.to_string_lossy().into_owned()],
            )
            .await
            {
                analysis.tools_used.push("plutil".into());
                for line in output.stdout.lines() {
                    if line.contains("CFBundleIdentifier") {
                        analysis.package_id = parse_quoted_value(line, "=> ");
                    }
                    if line.contains("CFBundleDisplayName") || line.contains("CFBundleName") {
                        analysis.display_name = parse_quoted_value(line, "=> ");
                    }
                    if line.contains("CFBundleShortVersionString") {
                        analysis.version_name = parse_quoted_value(line, "=> ");
                    }
                    if line.contains("CFBundleVersion") {
                        analysis.version_code = parse_quoted_value(line, "=> ");
                    }
                    if line.contains("NSAppTransportSecurity")
                        || line.contains("NSAllowsArbitraryLoads")
                        || line.contains("NSAllowsLocalNetworking")
                        || line.contains("NSAllowsArbitraryLoadsInWebContent")
                        || line.contains("NSExceptionDomains")
                        || line.contains("CFBundleURLTypes")
                        || line.contains("CFBundleURLSchemes")
                        || line.contains("UsageDescription")
                        || line.contains("UIBackgroundModes")
                        || line.contains("UIFileSharingEnabled")
                        || line.contains("LSSupportsOpeningDocumentsInPlace")
                    {
                        analysis.manifest_flags.push(line.trim().to_string());
                    }
                    if line.contains("NSAllowsArbitraryLoads")
                        && line.to_ascii_lowercase().contains("true")
                    {
                        analysis.findings.push(AppFinding {
                            severity: "high".into(),
                            title: "iOS ATS 允许任意明文传输".into(),
                            detail: line.trim().to_string(),
                        });
                    }
                }
            } else {
                analysis
                    .missing_dependencies
                    .push("未找到 plutil：二进制 Info.plist 只能做文件/字符串扫描".into());
            }
            let _ = fs::remove_file(temp);
        }
        let mut encrypted = None;
        let mut main_binary: Option<(String, Vec<u8>)> = None;
        // Read Mach-O headers from app/framework binaries to report actual slices and cryptid.
        for name in files
            .iter()
            .filter(|name| {
                let file_name = name.rsplit('/').next().unwrap_or_default();
                name.starts_with("Payload/")
                    && !name.ends_with('/')
                    && (!file_name.contains('.')
                        || name.contains(".framework/")
                        || name.ends_with(".dylib"))
            })
            .take(40)
        {
            if let Ok(mut entry) = archive.by_name(name) {
                if entry.size() <= 64 * 1024 * 1024 {
                    let mut binary = Vec::new();
                    let is_main = name.split('/').count() == 3
                        && !name.rsplit('/').next().unwrap_or_default().contains('.');
                    if is_main {
                        let _ = entry.read_to_end(&mut binary);
                    } else {
                        let _ = entry
                            .by_ref()
                            .take(2 * 1024 * 1024)
                            .read_to_end(&mut binary);
                    }
                    if !binary.is_empty() {
                        for architecture in macho_architectures(&binary) {
                            if !analysis.architectures.contains(&architecture) {
                                analysis.architectures.push(architecture);
                            }
                        }
                        if is_main {
                            encrypted = macho_encryption_state(&binary);
                            let security_flags = macho_security_flags(&binary);
                            if security_flags.iter().any(|flag| flag == "Mach-O PIE=false") {
                                analysis.findings.push(AppFinding {
                                    severity: "high".into(),
                                    title: "Mach-O 未启用 PIE".into(),
                                    detail: "主程序未发现 MH_PIE，ASLR 保护可能受限。".into(),
                                });
                            }
                            if security_flags
                                .iter()
                                .any(|flag| flag == "Stack protector=false")
                            {
                                analysis.findings.push(AppFinding {
                                    severity: "review".into(),
                                    title: "未发现栈保护符号".into(),
                                    detail: "主程序可见符号中未找到 __stack_chk_fail/guard；需用 Mach-O 工具进一步确认。".into(),
                                });
                            }
                            analysis.manifest_flags.extend(security_flags);
                        } else if encrypted.is_none() {
                            encrypted = macho_encryption_state(&binary);
                        }
                        if is_main
                            && main_binary.is_none()
                            && macho_encryption_state(&binary).is_some()
                        {
                            main_binary = Some((name.clone(), binary));
                        }
                    }
                }
            }
        }
        if let Some((name, bytes)) = main_binary {
            let executable =
                std::env::temp_dir().join(format!("security-console-{}-ios-bin", now_millis()));
            if fs::write(&executable, bytes).is_ok() {
                if let Ok(output) = run_host(
                    "codesign",
                    &[
                        "-d".into(),
                        "--entitlements".into(),
                        ":-".into(),
                        executable.to_string_lossy().into_owned(),
                    ],
                )
                .await
                {
                    let entitlements = output_text(&output);
                    for line in entitlements.lines().filter(|line| {
                        line.contains("get-task-allow")
                            || line.contains("application-identifier")
                            || line.contains("keychain-access-groups")
                            || line.contains("aps-environment")
                    }) {
                        analysis
                            .manifest_flags
                            .push(format!("Entitlement: {}", line.trim()));
                    }
                    if entitlements.contains("get-task-allow") && entitlements.contains("true") {
                        analysis.findings.push(AppFinding {
                            severity: "high".into(),
                            title: "iOS get-task-allow 已开启".into(),
                            detail: format!("{name} 允许调试器附加，请确认是否为开发签名。"),
                        });
                    }
                    analysis.tools_used.push("codesign entitlements".into());
                } else {
                    analysis
                        .missing_dependencies
                        .push("未找到 codesign 或无法读取 Entitlements（非 macOS 可忽略）".into());
                }
                if let Ok(output) = run_host(
                    "codesign",
                    &["-dvvv".into(), executable.to_string_lossy().into_owned()],
                )
                .await
                {
                    let details = output_text(&output)
                        .lines()
                        .filter(|line| {
                            line.contains("Authority=")
                                || line.contains("TeamIdentifier=")
                                || line.contains("Identifier=")
                                || line.contains("Timestamp=")
                                || line.contains("Hash choices=")
                        })
                        .take(30)
                        .collect::<Vec<_>>()
                        .join("\n");
                    if !details.is_empty() {
                        analysis.signature = Some(details);
                    }
                }
                let _ = fs::remove_file(executable);
            }
        }
        if let Some(profile) = files
            .iter()
            .find(|name| name.ends_with("embedded.mobileprovision"))
        {
            if let Ok(mut entry) = archive.by_name(profile) {
                let mut profile_bytes = Vec::new();
                let _ = entry.read_to_end(&mut profile_bytes);
                let visible = ascii_strings(&profile_bytes, 5);
                let distribution = if visible.contains("ProvisionsAllDevices") {
                    "Enterprise 企业分发"
                } else if visible.contains("ProvisionedDevices")
                    && visible.contains("get-task-allow")
                {
                    "Development 开发签名"
                } else if visible.contains("ProvisionedDevices") {
                    "Ad-Hoc 分发"
                } else {
                    "App Store / Distribution"
                };
                analysis
                    .manifest_flags
                    .push(format!("Distribution={distribution}"));
                if distribution.contains("Enterprise") || distribution.contains("Development") {
                    analysis.findings.push(AppFinding {
                        severity: "review".into(),
                        title: "iOS 非 App Store 分发线索".into(),
                        detail: distribution.into(),
                    });
                }
            }
        }
        match encrypted {
            Some(true) => {
                analysis.protection.status =
                    "Mach-O 已加密（cryptid=1），需要先砸壳再做完整静态分析".into();
                analysis.protection.indicators.push(
                    "App Store 加密会隐藏主程序字符串和代码逻辑；当前结果主要来自资源与框架。"
                        .into(),
                );
            }
            Some(false) => {
                analysis.protection.status = "Mach-O 未加密或已经砸壳（cryptid=0）".into()
            }
            None => {
                analysis.protection.status = "未定位到可解析的 Mach-O 主程序".into();
                analysis.missing_dependencies.push(
                    "无法读取 Mach-O cryptid；可先确认 IPA 是否包含完整 Payload/*.app 主程序"
                        .into(),
                );
            }
        }
        analysis.tools_used.push("内置 Rust Mach-O scanner".into());
    }
    analysis.permissions.sort();
    analysis.permissions.dedup();
    analysis.components.sort();
    analysis.components.dedup();
    analysis.exported_components.sort();
    analysis.exported_components.dedup();
    analysis.intent_filters.sort();
    analysis.intent_filters.dedup();
    analysis.manifest_flags.sort();
    analysis.manifest_flags.dedup();
    analysis.third_party_libraries.sort();
    analysis.third_party_libraries.dedup();
    analysis.sensitive_items.sort_by(|a, b| {
        a.location
            .cmp(&b.location)
            .then(a.item.cmp(&b.item))
            .then(a.value.cmp(&b.value))
    });
    analysis
        .sensitive_items
        .dedup_by(|a, b| a.location == b.location && a.item == b.item && a.value == b.value);
    analysis.sensitive_items.truncate(500);
    analysis.tools_used.sort();
    analysis.tools_used.dedup();
    analysis.missing_dependencies.sort();
    analysis.missing_dependencies.dedup();
    Ok(analysis)
}

#[cfg(test)]
mod analyzer_tests {
    use super::*;

    #[test]
    fn packaged_app_restores_login_shell_tools_when_configured() {
        if std::env::var("ME_TEST_PACKAGED_PATH").is_err() {
            return;
        }
        std::env::set_var("PATH", "/usr/bin:/bin:/usr/sbin:/sbin");
        let restored = initialize_host_environment(None).expect("restore packaged app PATH");
        assert!(restored.contains(".pyenv/shims") || restored.contains("/usr/local/bin"));
        assert!(executable_path("frida").is_some(), "{restored}");
        assert!(executable_path("frida-ps").is_some(), "{restored}");
    }

    #[test]
    fn decodes_axml_sample_when_configured() {
        let Ok(path) = std::env::var("ME_AXML_SAMPLE") else {
            return;
        };
        let bytes = fs::read(path).expect("read AXML sample");
        let xml = decode_axml(&bytes).expect("decode binary AndroidManifest.xml");
        assert!(xml.contains("<manifest"));
        assert!(xml.contains("<uses-permission"));
        assert!(xml.contains("<activity"));
        assert!(xml.contains("android:name="));
        assert!(
            xml.lines()
                .filter(|line| line.trim().starts_with("<uses-permission"))
                .count()
                > 2
        );
        assert!(
            xml.lines()
                .filter(|line| line.trim().starts_with("<activity"))
                .count()
                > 2
        );
        assert!(
            xml.lines()
                .filter(|line| line.trim().starts_with("<uses-permission"))
                .filter_map(|line| parse_quoted_value(line, "android:name="))
                .count()
                > 2
        );
        assert!(
            xml.lines()
                .filter(|line| line.trim().starts_with("<activity"))
                .filter_map(|line| parse_quoted_value(line, "android:name="))
                .count()
                > 2
        );
        if xml.to_ascii_lowercase().contains("com.stub.stubapp") {
            let mut protection = assess_protection(&[]);
            enrich_protection_from_manifest(&xml, &mut protection);
            assert!(protection
                .packers
                .iter()
                .any(|value| value.contains("StubApp")));
        }
    }

    #[test]
    fn sensitive_patterns_compile_and_keep_context() {
        assert_eq!(sensitive_patterns().len(), 21);
        let mut items = Vec::new();
        scan_sensitive_text(
            "before\nconst api = \"https://api.corp.internal/v1\";\nconst docs = \"https://developer.android.com/reference\";\nafter",
            "Sample.java",
            &mut items,
        );
        assert!(items.iter().any(|item| item.kind == "url"
            && item.value.as_deref() == Some("https://api.corp.internal/v1")));
        assert!(!items.iter().any(|item| item
            .value
            .as_deref()
            .is_some_and(|value| value.contains("developer.android.com"))));
        assert!(items.iter().any(|item| item
            .context
            .as_deref()
            .unwrap_or_default()
            .contains("const api")));
    }

    #[test]
    fn includes_flutter_and_ios_macho_binaries_in_deep_scan() {
        assert!(is_deep_binary_candidate("lib/arm64-v8a/libapp.so"));
        assert!(is_deep_binary_candidate("Payload/Runner.app/App"));
        assert!(is_deep_binary_candidate(
            "Payload/Runner.app/Frameworks/App.framework/App"
        ));
        assert!(!is_deep_binary_candidate("Payload/Runner.app/Assets.car"));
    }

    #[test]
    fn frida_17_spawn_and_attach_arguments_are_unambiguous() {
        let serial = Some("device-1".to_string());
        let script = Path::new("/tmp/test.js");
        let spawn = frida_script_args(&serial, "spawn", "com.example.app", None, script)
            .expect("spawn arguments");
        assert!(spawn
            .windows(2)
            .any(|args| args == ["-f", "com.example.app"]));
        assert!(!spawn.iter().any(|arg| arg == "--no-pause"));

        let attach = frida_script_args(&serial, "attach", "com.example.app", Some(4321), script)
            .expect("attach arguments");
        assert!(attach.windows(2).any(|args| args == ["-p", "4321"]));
        assert!(frida_script_args(&serial, "attach", "com.example.app", None, script).is_err());
    }

    #[test]
    fn adapts_legacy_hooker_exports_without_editing_source_file() {
        let source =
            "Module.getExportByName('libc.so', 'open'); Module.findExportByName(null, 'dlopen');";
        let (adapted, changes) = adapt_frida_17_script(source);
        assert!(!adapted.contains("Module.getExportByName"));
        assert!(!adapted.contains("Module.findExportByName"));
        assert!(adapted.contains("Process.getModuleByName('libc.so').getExportByName('open')"));
        assert!(adapted.contains("Module.findGlobalExportByName("));
        assert!(adapted.contains("'dlopen')"));
        assert!(!changes.is_empty());
    }

    #[test]
    fn builtin_scripts_are_available_without_external_directory() {
        let scripts = list_frida_scripts(Some("/directory/that/does/not/exist".into()))
            .expect("list embedded scripts");
        assert!(scripts
            .iter()
            .any(|script| script.path == "builtin://dump_dex.js"));
        assert!(scripts
            .iter()
            .any(|script| script.path == "builtin://dump_so.js"));
        assert!(read_script_path("builtin://dump_so.js")
            .expect("read embedded SO script")
            .contains("[ME_SO_READY]"));
    }

    #[tokio::test]
    async fn frida_server_starts_as_root_when_device_is_configured() {
        let (Ok(serial), Ok(path)) = (
            std::env::var("ME_ADB_SERIAL"),
            std::env::var("ME_FRIDA_SERVER_PATH"),
        ) else {
            return;
        };
        let result = manage_frida_server(FridaServerRequest {
            serial,
            action: "start".into(),
            path: Some(path),
        })
        .await
        .expect("deploy and start frida-server");
        assert!(result.success, "{}", result.output);
        assert!(result.output.contains("UID=0"), "{}", result.output);
    }

    #[tokio::test]
    async fn matching_frida_ps_lists_apps_when_device_is_configured() {
        let Ok(serial) = std::env::var("ME_ADB_SERIAL") else {
            return;
        };
        let processes = list_frida_processes(Some(serial))
            .await
            .expect("list applications with matching frida-ps");
        assert!(!processes.is_empty());
        if let Ok(package) = std::env::var("ME_FRIDA_TEST_PACKAGE") {
            assert!(
                processes
                    .iter()
                    .any(|process| process.identifier == package),
                "missing {package}"
            );
        }
    }

    #[tokio::test]
    async fn hooker_dex_workflow_pulls_and_repairs_when_configured() {
        let (Ok(serial), Ok(package), Ok(script_path)) = (
            std::env::var("ME_ADB_SERIAL"),
            std::env::var("ME_FRIDA_TEST_PACKAGE"),
            std::env::var("ME_DEX_DUMP_SCRIPT"),
        ) else {
            return;
        };
        let destination = std::env::temp_dir().join(format!("me-dex-test-{}", now_millis()));
        let result = run_dex_dump(DexDumpRequest {
            serial,
            package,
            script_path,
            destination_directory: Some(destination.to_string_lossy().into_owned()),
            duration_seconds: Some(15),
        })
        .await
        .expect("run Hooker DEX workflow");
        assert!(result.success, "{}", result.output);
        assert!(
            destination
                .join("repaired")
                .join("recovered-multidex.zip")
                .is_file(),
            "{}",
            result.output
        );
    }

    #[tokio::test]
    async fn builtin_so_workflow_pulls_ranges_when_configured() {
        let (Ok(serial), Ok(package)) = (
            std::env::var("ME_ADB_SERIAL"),
            std::env::var("ME_FRIDA_TEST_PACKAGE"),
        ) else {
            return;
        };
        let destination = std::env::temp_dir().join(format!("me-so-test-{}", now_millis()));
        let result = run_so_dump(SoDumpRequest {
            serial,
            package,
            script_path: "builtin://dump_so.js".into(),
            destination_directory: Some(destination.to_string_lossy().into_owned()),
            duration_seconds: Some(10),
        })
        .await
        .expect("run built-in SO workflow");
        assert!(result.success, "{}", result.output);
        assert!(
            destination.join("raw/so-sensitive-report.json").is_file(),
            "{}",
            result.output
        );
        assert!(
            destination
                .join("repaired/reconstruction-report.json")
                .is_file(),
            "{}",
            result.output
        );
        assert!(
            fs::read_dir(destination.join("repaired"))
                .expect("read repaired directory")
                .flatten()
                .any(|entry| entry.file_name().to_string_lossy().starts_with("repaired-")),
            "{}",
            result.output
        );
    }

    #[tokio::test]
    async fn transparent_proxy_is_root_and_idempotent_when_device_is_configured() {
        let Ok(serial) = std::env::var("ME_ADB_SERIAL") else {
            return;
        };
        let host = std::env::var("ME_PROXY_HOST").unwrap_or_else(|_| "192.168.3.100".into());
        let port = std::env::var("ME_PROXY_PORT")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(8888);

        run_proxy(ProxyRequest {
            serial: serial.clone(),
            action: "transparent_clear".into(),
            host: Some(host.clone()),
            port: Some(port),
        })
        .await
        .expect("clear old transparent proxy rules");

        for _ in 0..2 {
            let result = run_proxy(ProxyRequest {
                serial: serial.clone(),
                action: "transparent_set".into(),
                host: Some(host.clone()),
                port: Some(port),
            })
            .await
            .expect("set transparent proxy rules");
            assert!(result.success, "{}", result.output);
            assert!(result.output.contains("Root UID=0"), "{}", result.output);
        }

        let rules = run_device_root_script(&serial, "iptables -t nat -S OUTPUT")
            .await
            .expect("list transparent proxy rules");
        let destination = format!("{host}:{port}");
        let matching = rules
            .stdout
            .lines()
            .filter(|line| line.contains(&destination))
            .collect::<Vec<_>>();
        assert_eq!(matching.len(), 2, "{}", rules.stdout);
        assert!(matching.iter().any(|line| line.contains("--dport 80")));
        assert!(matching.iter().any(|line| line.contains("--dport 443")));
    }
}
