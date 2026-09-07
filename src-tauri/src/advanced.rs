//! Optional, local-only analysis tools.  This module deliberately exposes
//! diagnostics and user-provided Frida scripts; it does not ship bypass or
//! secret-extraction payloads.

use crate::{
    ensure_success, run_adb, run_device_adb, run_device_root, run_device_root_script, RawOutput,
    ADB_TIMEOUT,
};
use regex::Regex;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::process::{Command as StdCommand, Stdio};
use std::{
    fs::{self, File},
    io::Read,
    path::{Path, PathBuf},
    sync::OnceLock,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{process::Command, time::timeout};
use zip::ZipArchive;

const MAX_DEEP_BINARY_BYTES: u64 = 256 * 1024 * 1024;

mod ai;
mod anti_instrumentation;
mod assessment;
mod boundaries;
mod cases;
mod frida;
mod knowledge;
mod model;
mod report;
mod rules;

pub use boundaries::DataBoundaryObservation;
pub use model::*;
#[cfg(test)]
use report::render_sensitive_report_rows;
pub use report::ExportSensitiveValueRequest;
use report::{code_insight_focus_score, low_signal_binary_evidence};

#[tauri::command]
pub fn save_analysis_case(request: cases::SaveAnalysisCaseRequest) -> Result<String, String> {
    cases::save(request)
}

#[tauri::command]
pub fn load_analysis_case(path: String) -> Result<cases::AnalysisCase, String> {
    cases::load(path)
}

#[tauri::command]
pub fn compare_analysis_case(
    request: cases::CompareAnalysisCaseRequest,
) -> Result<cases::AnalysisBaselineDiff, String> {
    cases::compare(request)
}

#[tauri::command]
pub fn list_ai_task_templates() -> Vec<ai::AiTaskTemplate> {
    ai::task_templates()
}

// Stable short alias kept for integrations that use the acceptance-spec name.
#[tauri::command]
pub fn list_task_templates() -> Vec<ai::AiTaskTemplate> {
    ai::task_templates()
}

#[tauri::command]
pub fn build_ai_context_pack(
    app: tauri::AppHandle,
    request: ai::BuildAiContextPackRequest,
) -> Result<ai::AiContextPack, String> {
    let knowledge = knowledge::load_for_app(&app)?;
    ai::build_context_pack_with_knowledge(request, knowledge)
}

#[tauri::command]
pub fn list_knowledge(app: tauri::AppHandle) -> Result<Vec<knowledge::KnowledgePattern>, String> {
    knowledge::list_knowledge(app)
}

#[tauri::command]
pub fn add_pattern(
    app: tauri::AppHandle,
    pattern: knowledge::KnowledgePattern,
) -> Result<knowledge::KnowledgeMutation, String> {
    knowledge::add_pattern(app, pattern)
}

#[tauri::command]
pub fn merge_pattern(
    app: tauri::AppHandle,
    pattern: knowledge::KnowledgePattern,
) -> Result<knowledge::KnowledgeMutation, String> {
    knowledge::merge_pattern(app, pattern)
}

#[tauri::command]
pub fn export_knowledge(app: tauri::AppHandle, output_path: String) -> Result<String, String> {
    knowledge::export_knowledge(app, output_path)
}

#[tauri::command]
pub fn import_knowledge(
    app: tauri::AppHandle,
    input_path: String,
) -> Result<knowledge::KnowledgeImportReport, String> {
    knowledge::import_knowledge(app, input_path)
}

#[tauri::command]
pub fn list_exclusions() -> Result<Vec<rules::ExclusionRule>, String> {
    rules::list_user_exclusions()
}

#[tauri::command]
pub fn list_rules(app: tauri::AppHandle) -> Result<rules::RuleInventory, String> {
    rules::list_inventory(Some(&app))
}

#[tauri::command]
pub fn merge_exclusion(rule: rules::ExclusionRule) -> Result<rules::ExclusionMutation, String> {
    rules::merge_user_exclusion(rule)
}

#[tauri::command]
pub fn export_ai_context_pack(request: ai::ExportAiContextPackRequest) -> Result<String, String> {
    ai::export_context_pack(request)
}

#[tauri::command]
pub fn validate_ai_analysis_result(
    request: ai::ValidateAiResultRequest,
) -> Result<ai::AiValidationReport, String> {
    ai::validate_result(request)
}

#[tauri::command]
pub async fn test_ai_provider(
    request: ai::AiProviderRequest,
) -> Result<ai::AiProviderStatus, String> {
    ai::test_provider(request).await
}

#[tauri::command]
pub async fn run_ai_security_review(
    request: ai::RunAiSecurityReviewRequest,
) -> Result<ai::AiProviderReview, String> {
    ai::run_security_review(request).await
}

#[cfg(test)]
use frida::{
    adapt_frida_17_script, apply_ios_compatibility_profile, frida_script_args,
    normalize_ios_compatibility_profile, read_script_path, IOS_DUMP_AGENT, IOS_DUMP_RUNNER,
};

#[tauri::command]
pub async fn list_frida_processes(serial: Option<String>) -> Result<Vec<FridaProcess>, String> {
    frida::list_processes(serial).await
}

#[tauri::command]
pub fn list_frida_scripts(directory: Option<String>) -> Result<Vec<FridaScriptEntry>, String> {
    frida::list_scripts(directory)
}

#[tauri::command]
pub async fn run_frida_script(
    request: FridaScriptRequest,
) -> Result<AdvancedCommandResult, String> {
    frida::run_script(request).await
}

#[tauri::command]
pub fn confirm_anti_instrumentation(
    app: tauri::AppHandle,
    request: anti_instrumentation::ConfirmAntiInstrumentationRequest,
) -> Result<AntiInstrumentationAssessment, String> {
    let app_id = request
        .app_id
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string);
    let assessment = anti_instrumentation::confirm(request);
    if matches!(assessment.status.as_str(), "blocked" | "passed") {
        if let Some(app_id) = app_id {
            let mut pattern = knowledge::anti_instrumentation_pattern();
            pattern.verified_in.push(app_id);
            knowledge::merge_pattern(app, pattern)?;
        }
    }
    Ok(assessment)
}

fn push_path(paths: &mut Vec<PathBuf>, value: impl Into<PathBuf>) {
    let value = value.into();
    if value.is_dir() && !paths.iter().any(|existing| existing == &value) {
        paths.push(value);
    }
}

pub fn initialize_host_environment(directory: Option<&Path>) -> Result<String, String> {
    // The native macOS USB backend can fail device enumeration with
    // `reported max packet size ... is 0` after some custom-kernel boots.
    // libusb handles the same descriptor correctly and is supported by adb.
    #[cfg(target_os = "macos")]
    if std::env::var_os("ADB_LIBUSB").is_none() {
        std::env::set_var("ADB_LIBUSB", "1");
    }

    let mut paths = Vec::new();
    if let Some(directory) = directory {
        push_path(&mut paths, directory);
    }
    // Prefer package-manager platform-tools over an often stale Android SDK
    // copy. An explicitly configured tool directory still has top priority.
    for path in [
        "/opt/homebrew/bin",
        "/opt/homebrew/sbin",
        "/usr/local/bin",
        "/usr/local/sbin",
        "/Library/Apple/usr/bin",
    ] {
        push_path(&mut paths, path);
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

fn sha256_file(path: &Path) -> Result<String, String> {
    let mut file = File::open(path).map_err(|error| format!("读取文件摘要失败：{error}"))?;
    let mut digest = Sha256::new();
    let mut buffer = vec![0_u8; 1024 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|error| format!("计算 SHA-256 失败：{error}"))?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    Ok(format!("{:x}", digest.finalize()))
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

async fn run_host_with_timeout(
    program: &str,
    args: &[String],
    duration: Duration,
) -> Result<RawOutput, String> {
    let executable = cohesive_frida_executable_path(program)
        .ok_or_else(|| format!("未找到 {program}，请先安装对应工具"))?;
    let mut command = Command::new(executable);
    command.args(args).kill_on_drop(true);
    let output = timeout(duration, command.output())
        .await
        .map_err(|_| format!("{program} 操作超时"))?
        .map_err(|error| format!("启动 {program} 失败：{error}"))?;
    Ok(RawOutput {
        stdout: String::from_utf8_lossy(&output.stdout).trim().to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
        code: output.status.code(),
    })
}

fn source_class_regex() -> &'static Regex {
    static REGEX: OnceLock<Regex> = OnceLock::new();
    REGEX.get_or_init(|| {
        Regex::new(r"\b(?:class|interface|object|enum\s+class|enum)\s+([A-Za-z_$][A-Za-z0-9_$]*)")
            .expect("valid source class regex")
    })
}

fn source_package_regex() -> &'static Regex {
    static REGEX: OnceLock<Regex> = OnceLock::new();
    REGEX.get_or_init(|| {
        Regex::new(r"(?m)^\s*package\s+([A-Za-z_$][A-Za-z0-9_$.]*)")
            .expect("valid source package regex")
    })
}

fn source_code_markers() -> &'static [(&'static str, &'static str)] {
    &[
        ("Retrofit endpoint", "@GET("),
        ("Retrofit endpoint", "@POST("),
        ("Retrofit endpoint", "@PUT("),
        ("Retrofit endpoint", "@DELETE("),
        ("Retrofit endpoint", "@PATCH("),
        ("Retrofit BaseURL", ".baseUrl("),
        ("OkHttp client", "OkHttpClient"),
        ("OkHttp interceptor", "Interceptor"),
        ("OkHttp CertificatePinner", "CertificatePinner"),
        ("custom HostnameVerifier", "HostnameVerifier"),
        ("custom TrustManager", "X509TrustManager"),
        ("TLS socket factory", "sslSocketFactory"),
        ("WebView JavaScript bridge", "addJavascriptInterface"),
        ("WebView JavaScript enabled", "setJavaScriptEnabled"),
        ("WebView URL load", "loadUrl("),
        ("WebView file access", "setAllowFileAccess"),
        (
            "WebView universal file access",
            "setAllowUniversalAccessFromFileURLs",
        ),
        ("Java crypto", "Cipher.getInstance"),
        ("Android Keystore", "AndroidKeyStore"),
        ("SharedPreferences", "SharedPreferences"),
        ("SQLite", "SQLiteDatabase"),
        ("Room database", "Room.databaseBuilder"),
        ("dynamic DEX", "DexClassLoader"),
        ("native library", "System.loadLibrary"),
        ("HTTP connection", "HttpURLConnection"),
        ("URL construction", "new URL("),
        ("network execute", ".execute("),
        ("network enqueue", ".enqueue("),
    ]
}

fn classify_android_code(references: &[String]) -> &'static str {
    let joined = references.join(" ").to_ascii_lowercase();
    if joined.contains("certificate")
        || joined.contains("hostname")
        || joined.contains("trustmanager")
        || joined.contains("tls")
    {
        "android-tls-entry"
    } else if joined.contains("webview") {
        "android-webview-entry"
    } else if joined.contains("retrofit")
        || joined.contains("okhttp")
        || joined.contains("http")
        || joined.contains("url")
        || joined.contains("network")
    {
        "android-network-entry"
    } else if joined.contains("crypto") || joined.contains("keystore") {
        "android-crypto-entry"
    } else if joined.contains("sharedpreferences")
        || joined.contains("sqlite")
        || joined.contains("room")
    {
        "android-storage-entry"
    } else if joined.contains("dex") || joined.contains("native library") {
        "android-loader-entry"
    } else {
        "android-method"
    }
}

fn source_method_name(line: &str, current_class: Option<&str>) -> Option<String> {
    let trimmed = line.trim();
    if !trimmed.contains('(')
        || trimmed.starts_with('@')
        || trimmed.ends_with(';')
        || trimmed.starts_with("//")
        || trimmed.starts_with("/*")
    {
        return None;
    }
    let before = trimmed.split_once('(')?.0.trim();
    if before.contains('=') || before.ends_with('.') || before.contains("->") {
        return None;
    }
    let name = before
        .split_whitespace()
        .last()?
        .trim_start_matches('*')
        .trim_start_matches('&');
    if name.contains('.')
        || name.contains(':')
        || !name
            .chars()
            .next()
            .is_some_and(|value| value.is_ascii_alphabetic() || value == '_' || value == '$')
        || !name
            .chars()
            .all(|value| value.is_ascii_alphanumeric() || value == '_' || value == '$')
    {
        return None;
    }
    if [
        "if",
        "for",
        "while",
        "switch",
        "catch",
        "return",
        "throw",
        "new",
        "when",
        "synchronized",
    ]
    .contains(&name)
    {
        return None;
    }
    let declaration_shape = trimmed.starts_with("fun ")
        || trimmed.contains(" fun ")
        || trimmed.contains(" public ")
        || trimmed.starts_with("public ")
        || trimmed.contains(" private ")
        || trimmed.starts_with("private ")
        || trimmed.contains(" protected ")
        || trimmed.starts_with("protected ")
        || trimmed.contains(" internal ")
        || trimmed.starts_with("internal ")
        || trimmed.contains(" static ")
        || trimmed.starts_with("static ")
        || trimmed.contains(" override ")
        || trimmed.starts_with("override ")
        || trimmed.ends_with('{')
        || current_class.is_some_and(|class_name| class_name == name);
    declaration_shape.then(|| name.to_string())
}

fn source_method_end(lines: &[&str], start: usize) -> usize {
    let mut depth = 0isize;
    let mut saw_open = false;
    for (index, line) in lines.iter().enumerate().skip(start).take(160) {
        let opens = line.chars().filter(|value| *value == '{').count() as isize;
        let closes = line.chars().filter(|value| *value == '}').count() as isize;
        if opens > 0 {
            saw_open = true;
        }
        depth += opens - closes;
        if saw_open && depth <= 0 {
            return index;
        }
        if !saw_open && index > start + 4 {
            return index;
        }
    }
    (start + 40).min(lines.len().saturating_sub(1))
}

fn clipped_source_snippet(lines: &[&str], start: usize, end: usize, limit: usize) -> Vec<String> {
    lines[start..=end.min(lines.len().saturating_sub(1))]
        .iter()
        .take(limit)
        .enumerate()
        .map(|(index, line)| {
            let clipped: String = line.chars().take(520).collect();
            format!("{} | {}", start + index + 1, clipped)
        })
        .collect()
}

fn scan_android_source(text: &str, relative: &str, insights: &mut Vec<CodeInsight>) {
    let lines: Vec<&str> = text.lines().collect();
    if lines.is_empty() {
        return;
    }
    let package = source_package_regex()
        .captures(text)
        .and_then(|captures| captures.get(1))
        .map(|value| value.as_str().to_string());
    let mut current_class: Option<String> = None;
    let mut seen_methods = HashSet::new();
    for (index, line) in lines.iter().enumerate() {
        if let Some(captures) = source_class_regex().captures(line) {
            if let Some(name) = captures.get(1) {
                current_class = Some(name.as_str().to_string());
                let qualified = package
                    .as_deref()
                    .map(|value| format!("{value}.{}", name.as_str()))
                    .unwrap_or_else(|| name.as_str().to_string());
                insights.push(CodeInsight {
                    platform: "android".into(),
                    kind: "android-class".into(),
                    binary: "classes*.dex via JADX".into(),
                    class_name: Some(qualified.clone()),
                    name: qualified,
                    signature: Some(line.trim().chars().take(520).collect()),
                    address: None,
                    module_offset: None,
                    source_file: Some(relative.into()),
                    line_number: Some(index + 1),
                    runtime_target: None,
                    references: Vec::new(),
                    snippet: clipped_source_snippet(&lines, index, index, 1),
                    confidence: "high".into(),
                });
            }
        }
        let Some(method_name) = source_method_name(line, current_class.as_deref()) else {
            continue;
        };
        let class_name = current_class.clone().or_else(|| {
            Path::new(relative)
                .file_stem()
                .and_then(|value| value.to_str())
                .map(str::to_string)
        });
        let qualified_class = match (package.as_deref(), class_name.as_deref()) {
            (Some(package), Some(class_name)) => Some(format!("{package}.{class_name}")),
            (_, class_name) => class_name.map(str::to_string),
        };
        let identity = format!("{}:{}:{method_name}", relative, index + 1);
        if !seen_methods.insert(identity) {
            continue;
        }
        let end = source_method_end(&lines, index);
        let body = lines[index..=end.min(lines.len() - 1)].join("\n");
        let mut references = Vec::new();
        for (label, marker) in source_code_markers() {
            if body.contains(marker) && !references.iter().any(|value| value == label) {
                references.push((*label).to_string());
            }
        }
        references.extend(binary_endpoint_samples(&body, 8));
        references.truncate(16);
        insights.push(CodeInsight {
            platform: "android".into(),
            kind: classify_android_code(&references).into(),
            binary: "classes*.dex via JADX".into(),
            class_name: qualified_class,
            name: method_name,
            signature: Some(line.trim().chars().take(520).collect()),
            address: None,
            module_offset: None,
            source_file: Some(relative.into()),
            line_number: Some(index + 1),
            runtime_target: None,
            references,
            snippet: clipped_source_snippet(&lines, index, end, 24),
            confidence: "high".into(),
        });
    }
}

fn scan_decoded_directory(
    root: &Path,
    prefix: &str,
    rule_set: &rules::RuleSet,
) -> StaticToolAnalysis {
    let mut result = StaticToolAnalysis::default();
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
            if scanned >= 4000 {
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
                    | "dart"
                    | "swift"
                    | "m"
                    | "mm"
                    | "c"
                    | "cc"
                    | "cpp"
                    | "h"
                    | "hpp"
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
                let location = format!("{prefix}:{relative}");
                scan_sensitive_text_with_rules(
                    &text,
                    &location,
                    &mut result.sensitive_items,
                    rule_set,
                    "text-resource",
                );
                if prefix == "jadx" && matches!(extension.as_str(), "java" | "kt") {
                    scan_android_source(&text, &location, &mut result.code_insights);
                }
                scanned += 1;
            }
        }
    }
    result.code_insights.sort_by(|left, right| {
        let left_generic = matches!(left.kind.as_str(), "android-class" | "android-method");
        let right_generic = matches!(right.kind.as_str(), "android-class" | "android-method");
        left_generic
            .cmp(&right_generic)
            .then(left.source_file.cmp(&right.source_file))
            .then(left.line_number.cmp(&right.line_number))
    });
    result.code_insights.dedup_by(|left, right| {
        left.source_file == right.source_file
            && left.line_number == right.line_number
            && left.kind == right.kind
            && left.name == right.name
    });
    result.code_insights.truncate(2000);
    result
}

async fn run_configured_static_tool(
    apk: &str,
    tool: &str,
    kind: &str,
) -> Result<StaticToolAnalysis, String> {
    let cli = resolve_static_cli_path(Path::new(tool), kind)?;
    let output_dir = std::env::temp_dir().join(format!("mobilee-{}-{kind}-scan", now_millis()));
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
    let output = run_explicit_program(&cli, &args).await?;
    if output.code != Some(0) {
        let _ = fs::remove_dir_all(&output_dir);
        return Err(output_text(&output));
    }
    let rule_set = rules::load_rules(None)?;
    let mut result = scan_decoded_directory(&output_dir, kind, &rule_set);
    let manifest_candidates = if kind == "apktool" {
        vec![output_dir.join("AndroidManifest.xml")]
    } else {
        vec![
            output_dir.join("resources/AndroidManifest.xml"),
            output_dir.join("AndroidManifest.xml"),
        ]
    };
    result.manifest_xml = manifest_candidates
        .into_iter()
        .find_map(|candidate| fs::read_to_string(candidate).ok());
    let _ = fs::remove_dir_all(&output_dir);
    Ok(result)
}

fn resolve_static_cli_path(configured: &Path, kind: &str) -> Result<PathBuf, String> {
    let mut candidates = Vec::new();
    if configured.is_dir() {
        if kind == "jadx" {
            candidates.extend([
                configured.join("bin/jadx"),
                configured.join("bin/jadx.bat"),
                configured.join("jadx"),
                configured.join("jadx.bat"),
            ]);
        } else {
            candidates.extend([
                configured.join("apktool"),
                configured.join("apktool.bat"),
                configured.join("apktool.jar"),
            ]);
        }
    } else {
        let file_name = configured
            .file_name()
            .and_then(|value| value.to_str())
            .unwrap_or_default()
            .to_ascii_lowercase();
        if kind == "jadx" && (file_name.contains("jadx-gui") || file_name.contains("jadx_gui")) {
            if let Some(parent) = configured.parent() {
                candidates.extend([
                    parent.join("jadx"),
                    parent.join("jadx.bat"),
                    parent.join("../bin/jadx"),
                    parent.join("../bin/jadx.bat"),
                ]);
            }
        } else {
            candidates.push(configured.to_path_buf());
        }
    }
    candidates
        .into_iter()
        .find(|candidate| candidate.is_file())
        .map(|candidate| fs::canonicalize(&candidate).unwrap_or(candidate))
        .ok_or_else(|| {
            if kind == "jadx" {
                format!(
                    "未找到 JADX CLI：请配置 jadx 安装目录、bin/jadx 或 jadx-cli.jar，不要选择 jadx-gui"
                )
            } else {
                format!("未找到 Apktool CLI：请配置 apktool、apktool.jar 或其所在目录")
            }
        })
}

fn configure_background_command(command: &mut Command) {
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    #[cfg(windows)]
    {
        // CREATE_NO_WINDOW: CLI analyzers must never open cmd.exe/PowerShell.
        command.creation_flags(0x0800_0000);
    }
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
    command.args(args);
    configure_background_command(&mut command);
    let output = timeout(Duration::from_secs(600), command.output())
        .await
        .map_err(|_| "后台分析工具运行超过 10 分钟，已停止并清理子进程".to_string())?
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
    let is_ios_platform = request.platform.as_deref() == Some("ios");
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
        let is_ios = is_ios_platform;
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
    let recommended_frida_server = (!is_ios_platform)
        .then(|| device_architecture.as_deref())
        .flatten()
        .map(|abi| {
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
    if !matches!(extension.as_str(), "pem" | "crt" | "cer" | "der") {
        return Err("仅支持 PEM/CRT/CER/DER 证书".into());
    }
    Ok(path)
}

#[tauri::command]
pub async fn certificate_info(path: String) -> Result<CertificateInfo, String> {
    let path = validate_certificate(&path)?;
    let bytes = std::fs::read(&path).map_err(|error| format!("读取证书失败：{error}"))?;
    let format = if bytes.starts_with(b"-----BEGIN") {
        "PEM"
    } else {
        "DER"
    };
    let path_string = path.to_string_lossy().to_string();
    let hash_output = ensure_success(
        run_host(
            "openssl",
            &[
                "x509",
                "-inform",
                format,
                "-subject_hash_old",
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
    let fingerprint = ensure_success(
        run_host(
            "openssl",
            &[
                "x509",
                "-inform",
                format,
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
        system_target: format!("系统 CA：{subject_hash}.0（自动选择 Conscrypt APEX / system / Magisk）"),
        note: "Android 14+ 优先创建本次开机有效的 Conscrypt APEX CA 覆盖；旧系统写 system CA，无法即时挂载时写入 Magisk 模块并提示重启。".into(),
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
    let bytes = std::fs::read(&path).map_err(|error| format!("读取证书失败：{error}"))?;
    let format = if bytes.starts_with(b"-----BEGIN") {
        "PEM"
    } else {
        "DER"
    };
    let pem = ensure_success(
        run_host(
            "openssl",
            &[
                "x509".into(),
                "-inform".into(),
                format.into(),
                "-in".into(),
                local,
                "-outform".into(),
                "PEM".into(),
            ],
        )
        .await?,
    )?
    .stdout;
    if !pem.starts_with("-----BEGIN CERTIFICATE-----") || pem.contains('\'') {
        return Err("证书转 PEM 失败".into());
    }
    let push =
        run_device_root_script(&request.serial, &format!("printf '%s' '{pem}' > '{tmp}'")).await?;
    if push.code != Some(0) {
        return Err(output_text(&push));
    }
    let cert_name = format!("{}.0", info.subject_hash);
    let script = format!(
        r#"set -e
cert='{tmp}'
name='{cert_name}'
legacy="/system/etc/security/cacerts/$name"
apex='/apex/com.android.conscrypt/cacerts'
installed=''
verified_path=''
if [ -d "$apex" ]; then
  stage=$(mktemp -d /data/local/tmp/mobilee-ca.XXXXXX)
  cp -a "$apex"/. "$stage"/
  cp "$cert" "$stage/$name"; chmod 644 "$stage/$name"; chown 0:0 "$stage/$name"
  if mount -t tmpfs tmpfs "$apex" 2>/dev/null; then
    cp -a "$stage"/. "$apex"/; chmod 644 "$apex/$name"; chown 0:0 "$apex/$name"
    installed="Conscrypt APEX（本次开机有效）:$apex/$name"
    verified_path="$apex/$name"
    chmod 755 "$apex"
    chcon -R u:object_r:system_security_cacerts_file:s0 "$apex"
    # Android APEX mounts are private to each mount namespace.
    # Publish the validated CA store for subsequently launched applications.
    chmod 755 "$stage"
    chcon -R u:object_r:system_security_cacerts_file:s0 "$stage"
    source="$stage"
    zygotes="$(pidof zygote64 zygote 2>/dev/null || true)"
    if [ -z "$zygotes" ]; then echo '证书仅在 shell 可见：未找到 Zygote，安装未完成' >&2; exit 1; fi
    command -v nsenter >/dev/null || {{ echo '缺少 nsenter，无法更新应用证书视图' >&2; exit 1; }}
    for pid in $zygotes; do
      nsenter -t "$pid" -m -- mount --bind "$source" "$apex"
      cmp "$cert" "/proc/$pid/root$apex/$name" || {{ echo "Zygote $pid 证书校验失败" >&2; exit 1; }}
      echo "Zygote $pid：证书可见且内容一致；请关闭并重新打开需要测试的应用"
    done
  fi
fi
if [ -z "$installed" ]; then
  mount -o rw,remount / 2>/dev/null || mount -o rw,remount /system 2>/dev/null || true
  if [ -d /system/etc/security/cacerts ] && cp "$cert" "$legacy" 2>/dev/null; then
    chmod 644 "$legacy"; chown 0:0 "$legacy"; installed="system CA:$legacy"
    verified_path="$legacy"
  fi
fi
if [ -z "$installed" ] && [ -d /data/adb/modules ]; then
  module='/data/adb/modules/mobilee-ca'
  mkdir -p "$module/system/etc/security/cacerts"
  printf 'id=mobilee-ca\nname=MobileE Test CA\nversion=1\nversionCode=1\nauthor=MobileE\ndescription=Authorized test CA module\n' >"$module/module.prop"
  touch "$module/auto_mount"
  cp "$cert" "$module/system/etc/security/cacerts/$name"
  chmod 644 "$module/system/etc/security/cacerts/$name"
  installed="Magisk 模块（重启后生效）:$module"
  verified_path="$module/system/etc/security/cacerts/$name"
fi
if [ -n "$verified_path" ]; then
  cmp "$cert" "$verified_path" || {{ echo '安装后校验失败：目标证书与输入不一致' >&2; exit 1; }}
  echo "写入校验通过：$verified_path"
  ls -l "$verified_path"
fi
rm -f "$cert"
if [ -z "$installed" ]; then echo '无法写入系统/Conscrypt CA，且未检测到 Magisk 模块目录' >&2; exit 1; fi
echo "证书安装完成：$installed"
echo '以上确认文件写入；App 是否信任仍取决于进程挂载视图、应用信任配置及证书固定。'
"#
    );
    let output = run_device_root_script(&request.serial, &script).await?;
    Ok(AdvancedCommandResult {
        success: output.code == Some(0),
        command: format!(
            "adb -s {} install certificate {}",
            request.serial, cert_name
        ),
        output: output_text(&output),
        exit_code: output.code,
    })
}

#[tauri::command]
pub async fn run_ios_dump(request: IosDumpRequest) -> Result<AdvancedCommandResult, String> {
    frida::run_ios_dump_internal(request).await
}

#[tauri::command]
pub async fn run_dex_dump(request: DexDumpRequest) -> Result<AdvancedCommandResult, String> {
    frida::run_dex_dump_internal(request).await
}

#[tauri::command]
pub async fn run_so_dump(request: SoDumpRequest) -> Result<AdvancedCommandResult, String> {
    frida::run_so_dump_internal(request).await
}

#[tauri::command]
pub async fn manage_frida_server(
    request: FridaServerRequest,
) -> Result<AdvancedCommandResult, String> {
    frida::manage_server(request).await
}

#[tauri::command]
pub async fn install_frida_tools() -> Result<AdvancedCommandResult, String> {
    frida::install_host_tools().await
}

#[tauri::command]
pub async fn download_frida_server(
    request: FridaDownloadRequest,
) -> Result<AdvancedCommandResult, String> {
    frida::download_server(request).await
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
    let mut value = line[start..].trim_start();
    value = value.trim_start_matches(|character: char| matches!(character, '=' | ':' | ' '));
    let parsed = match value.chars().next() {
        Some(quote @ ('\'' | '"')) => {
            let body = &value[quote.len_utf8()..];
            &body[..body.find(quote).unwrap_or(body.len())]
        }
        _ => {
            let end = value.find(char::is_whitespace).unwrap_or(value.len());
            &value[..end]
        }
    };
    Some(parsed.trim().to_string()).filter(|value| !value.is_empty())
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
        .take(20)
        .cloned()
        .collect::<Vec<_>>();
    if !sensitive.is_empty() {
        findings.push(AppFinding {
            severity: "review".into(),
            title: "敏感存储或调试资源线索".into(),
            detail: format!(
                "发现 {} 个候选；详细路径已归入 Sensitive information，示例：{}",
                sensitive.len(),
                sensitive
                    .iter()
                    .take(5)
                    .cloned()
                    .collect::<Vec<_>>()
                    .join("、")
            ),
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
    let leaf = lower.rsplit('/').next().unwrap_or_default();
    if [
        ".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".pdf", ".mp3", ".mp4", ".wav", ".ttf",
        ".otf", ".car",
    ]
    .iter()
    .any(|extension| leaf.ends_with(extension))
        || [
            "icon",
            "button",
            "background",
            "placeholder",
            "sprite",
            "asset",
        ]
        .iter()
        .any(|marker| leaf.contains(marker))
    {
        return None;
    }
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
    source: &str,
    filter_reason: Option<String>,
) {
    items.push(SensitiveItem {
        item: item.into(),
        location: location.into(),
        kind: kind.into(),
        severity: severity.into(),
        value,
        line_number,
        context,
        source: source.into(),
        filtered: filter_reason.is_some(),
        filter_reason,
    });
}

fn sensitive_filter_reason(
    rule: &rules::SensitiveRule,
    rule_set: &rules::RuleSet,
    value: &str,
    context: &str,
    text: &str,
    start: usize,
    end: usize,
    source: &str,
) -> Option<String> {
    let combined = format!("{value}\n{context}");
    if !rule.require_context.is_empty()
        && !rules::contains_any(&combined, &rule.require_context, false)
    {
        return Some(format!(
            "缺少使用上下文：需要命中 {}",
            rule.require_context.join(" / ")
        ));
    }
    if rules::contains_any(&combined, &rule.exclude_signals, false)
        || rule
            .exclude_patterns
            .iter()
            .any(|pattern| pattern.is_match(&combined))
    {
        return Some("命中该敏感规则的排除护栏".into());
    }
    if matches!(
        rule.kind.as_str(),
        "version" | "ip" | "token" | "weak-crypto" | "crypto"
    ) && contains_format_placeholder(&combined)
    {
        return Some("上下文包含格式化占位符，判定为模板/日志噪声".into());
    }
    if let Some(exclusion) = rule_set.exclusions.iter().find(|exclusion| {
        (exclusion.data.applies_to_kind == "*"
            || exclusion
                .data
                .applies_to_kind
                .eq_ignore_ascii_case(&rule.kind))
            && (rules::contains_any(&combined, &exclusion.data.exclude_signals, false)
                || exclusion
                    .exclude_patterns
                    .iter()
                    .any(|pattern| pattern.is_match(&combined)))
    }) {
        return Some(format!(
            "{}（{}）",
            exclusion.data.reason, exclusion.data.exclusion_id
        ));
    }
    if should_ignore_sensitive_match(&rule.kind, value)
        || should_ignore_contextual_match(&rule.kind, text, start, end)
    {
        return Some("命中 MobileE 内置低噪声护栏".into());
    }
    if source == "binary-strings"
        && matches!(rule.kind.as_str(), "ip" | "url" | "email")
        && !strong_binary_network_candidate(&rule.kind, value, &combined)
    {
        return Some("来自 SO/DEX/Mach-O 字符串且缺少可信网络上下文，按二进制噪声降级".into());
    }
    None
}

fn strong_binary_network_candidate(kind: &str, value: &str, context: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    let context = context.to_ascii_lowercase();
    let trusted_tld = |host: &str| {
        [
            ".com", ".cn", ".net", ".org", ".io", ".app", ".dev", ".cloud", ".tech", ".gov",
            ".edu", ".co", ".me",
        ]
        .iter()
        .any(|suffix| host.ends_with(suffix))
    };
    match kind {
        "url" => {
            let Some((scheme, rest)) = lower.split_once("://") else {
                return false;
            };
            if !matches!(scheme, "http" | "https" | "ws" | "wss") {
                return false;
            }
            let host = rest.split(['/', ':', '?', '#']).next().unwrap_or_default();
            trusted_tld(host)
                && host.split('.').all(|part| {
                    !part.is_empty()
                        && part
                            .chars()
                            .all(|character| character.is_ascii_alphanumeric() || character == '-')
                })
        }
        "email" => {
            let Some((local, host)) = lower.rsplit_once('@') else {
                return false;
            };
            local.len() >= 2
                && trusted_tld(host)
                && ["mail", "email", "contact", "support", "mailto:"]
                    .iter()
                    .any(|marker| context.contains(marker))
        }
        "ip" => {
            !["0.0.0.0", "127.0.0.1", "255.255.255.255"].contains(&lower.as_str())
                && !lower.starts_with("10.")
                && !lower.starts_with("192.168.")
                && !lower.starts_with("169.254.")
                && !lower.starts_with("224.")
                && !lower.starts_with("239.")
                && [
                    "http://", "https://", "server", "host", "endpoint", "connect", "socket",
                ]
                .iter()
                .any(|marker| context.contains(marker))
        }
        _ => true,
    }
}

fn sensitive_patterns(rules: &rules::RuleSet) -> &[rules::SensitiveRule] {
    &rules.sensitive
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

fn utf16_ascii_strings(bytes: &[u8], minimum: usize) -> String {
    let mut output = String::new();
    for little_endian in [true, false] {
        for alignment in 0..2 {
            let mut current = String::new();
            let mut cursor = alignment;
            while cursor + 1 < bytes.len() {
                let pair = [bytes[cursor], bytes[cursor + 1]];
                let code = if little_endian {
                    u16::from_le_bytes(pair)
                } else {
                    u16::from_be_bytes(pair)
                };
                if code <= 0x7f && (code as u8).is_ascii_graphic() || code == 0x20 || code == 0x09 {
                    current.push(char::from_u32(code as u32).unwrap_or_default());
                } else {
                    if current.len() >= minimum {
                        output.push_str(&current);
                        output.push('\n');
                    }
                    current.clear();
                }
                cursor += 2;
            }
            if current.len() >= minimum {
                output.push_str(&current);
                output.push('\n');
            }
        }
    }
    output
}

fn extracted_binary_strings(bytes: &[u8], minimum: usize) -> String {
    let mut output = ascii_strings(bytes, minimum);
    let wide = utf16_ascii_strings(bytes, minimum);
    if !wide.is_empty() {
        if !output.is_empty() {
            output.push('\n');
        }
        output.push_str(&wide);
    }
    output
}

const MAX_PEM_PRIVATE_KEY_BYTES: usize = 32 * 1024;

/// Returns the complete PEM block that starts at `start`, when a matching END
/// marker is found within a bounded window. The regex intentionally finds only
/// BEGIN markers; this helper keeps the match readable and avoids a large
/// backtracking expression over binary-derived strings.
fn complete_pem_private_key_block<'a>(
    text: &'a str,
    start: usize,
    begin_marker: &str,
) -> Option<&'a str> {
    let end_marker = begin_marker.replacen("BEGIN", "END", 1);
    let search_start = start.min(text.len());
    let search_end = search_start
        .saturating_add(MAX_PEM_PRIVATE_KEY_BYTES)
        .min(text.len());
    let window = text.get(search_start..search_end)?;
    let end_offset = window.find(&end_marker)?;
    let end = search_start
        .saturating_add(end_offset)
        .saturating_add(end_marker.len());
    text.get(search_start..end)
}

fn scan_sensitive_text_with_rules(
    text: &str,
    location: &str,
    items: &mut Vec<SensitiveItem>,
    rule_set: &rules::RuleSet,
    source: &str,
) {
    for rule in sensitive_patterns(rule_set) {
        for matched in rule.regex.find_iter(text).take(30) {
            let is_private_key = rule.kind == "private-key";
            let complete_value = is_private_key
                .then(|| complete_pem_private_key_block(text, matched.start(), matched.as_str()))
                .flatten();
            let value: String = complete_value
                .map(ToOwned::to_owned)
                .unwrap_or_else(|| matched.as_str().chars().take(240).collect());
            let (line_number, context) = match_context(text, matched.start());
            let filter_reason = sensitive_filter_reason(
                rule,
                rule_set,
                &value,
                &context,
                text,
                matched.start(),
                matched.end(),
                source,
            );
            let effective_severity = if source == "binary-strings"
                && matches!(rule.kind.as_str(), "ip" | "url" | "email")
                && filter_reason.is_some()
            {
                "low"
            } else if rule.kind == "ip"
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
                rule.severity.as_str()
            };
            push_sensitive(
                items,
                if complete_value.is_some() {
                    "私钥内容（完整 PEM）"
                } else {
                    &rule.label
                },
                location,
                &rule.kind,
                effective_severity,
                Some(value),
                Some(line_number),
                Some(context),
                source,
                filter_reason,
            );
        }
    }
}

#[cfg(test)]
fn scan_sensitive_text(text: &str, location: &str, items: &mut Vec<SensitiveItem>) {
    if let Ok(rule_set) = rules::load_rules(None) {
        scan_sensitive_text_with_rules(text, location, items, &rule_set, "text-resource");
    }
}

fn byte_window_before(text: &str, start: usize, maximum_chars: usize) -> &str {
    let mut begin = start.min(text.len());
    for _ in 0..maximum_chars {
        let Some((index, _)) = text[..begin].char_indices().next_back() else {
            begin = 0;
            break;
        };
        begin = index;
    }
    &text[begin..start.min(text.len())]
}

fn byte_window_after(text: &str, end: usize, maximum_chars: usize) -> &str {
    let end = end.min(text.len());
    let mut finish = end;
    for (index, character) in text[end..].char_indices().take(maximum_chars) {
        finish = end + index + character.len_utf8();
    }
    &text[end..finish]
}

fn should_ignore_contextual_match(kind: &str, text: &str, start: usize, end: usize) -> bool {
    let before = byte_window_before(text, start, 96);
    let after = byte_window_after(text, end, 96);
    if kind == "ip" {
        let previous = text
            .get(..start)
            .and_then(|value| value.chars().next_back());
        let next = text.get(end..).and_then(|value| value.chars().next());
        if previous.is_some_and(|value| value.is_ascii_digit() || value == '.')
            || next.is_some_and(|value| value.is_ascii_digit() || value == '.')
        {
            return true;
        }
        let context = format!("{before}{after}").to_ascii_lowercase();
        if [
            "version",
            "versionname",
            "versioncode",
            "bundle version",
            "sdk version",
            "release-",
            "dependency",
            "podspec",
            "gradle",
            "maven",
            "framework version",
            "opencv",
            "modules/",
            "/src/",
            ".cpp",
            ".cc",
            ".cxx",
            "runner/work/",
            "build/",
            "deriveddata/",
        ]
        .iter()
        .any(|marker| context.contains(marker))
        {
            return true;
        }
        let trimmed = before.trim_end();
        if trimmed.ends_with('v') || trimmed.ends_with("ver") {
            return true;
        }
    }
    false
}

fn contains_format_placeholder(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    [
        "%@",
        "%d",
        "%i",
        "%u",
        "%ld",
        "%lu",
        "%lld",
        "%llu",
        "%s",
        "%x",
        "%f",
        "%1$",
        "%2$",
        "${",
        "$(",
        "{{",
        "}}",
        "<host>",
        "<domain>",
        "{host}",
        "{domain}",
        "{baseurl}",
        "{base_url}",
    ]
    .iter()
    .any(|marker| lower.contains(marker))
}

fn is_valid_email_candidate(value: &str) -> bool {
    if contains_format_placeholder(value)
        || value.chars().any(char::is_whitespace)
        || value.contains('/')
        || value.contains('\\')
    {
        return false;
    }
    let Some((local, domain)) = value.rsplit_once('@') else {
        return false;
    };
    if local.is_empty()
        || local.len() > 64
        || domain.len() > 253
        || local.starts_with('.')
        || local.ends_with('.')
        || local.contains("..")
        || domain.starts_with('.')
        || domain.ends_with('.')
        || domain.contains("..")
    {
        return false;
    }
    let Some((_, suffix)) = domain.rsplit_once('.') else {
        return false;
    };
    suffix.len() >= 2
        && suffix.len() <= 24
        && suffix
            .chars()
            .all(|character| character.is_ascii_alphabetic())
        && domain.split('.').all(|label| {
            !label.is_empty()
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .chars()
                    .all(|character| character.is_ascii_alphanumeric() || character == '-')
        })
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
        if contains_format_placeholder(&lower) {
            return true;
        }
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
            "localhost",
            "127.0.0.1",
        ];
        if host.is_empty()
            || host
                .chars()
                .any(|character| "%{}[]<>\\".contains(character))
            || !host
                .chars()
                .any(|character| character.is_ascii_alphanumeric())
        {
            return true;
        }
        return NOISE_HOSTS
            .iter()
            .any(|noise| host == *noise || host.ends_with(&format!(".{noise}")));
    }
    if kind == "ip" {
        return matches!(lower.as_str(), "0.0.0.0" | "127.0.0.1" | "255.255.255.255");
    }
    if kind == "email" {
        // Asset scale suffixes and compiler/format templates can satisfy a generic
        // e-mail regex, but are not contact addresses.
        let compact = lower.replace(' ', "");
        return compact.contains("@1x.")
            || compact.contains("@2x.")
            || compact.contains("@3x.")
            || !is_valid_email_candidate(value);
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
        let looks_like_symbol = candidate
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "_$".contains(character))
            && [
                "method",
                "action",
                "title",
                "text",
                "view",
                "controller",
                "handler",
                "selector",
                "delegate",
                "callback",
                "swizzle",
                "show",
                "hide",
                "set",
                "get",
            ]
            .iter()
            .any(|marker| candidate_lower.contains(marker));
        if looks_like_symbol {
            return true;
        }
        return candidate.len() < 20 && shannon_entropy(candidate) < 3.0;
    }
    false
}

fn url_matches_exclusion(value: &str, patterns: &[String]) -> bool {
    let normalized = value
        .trim_matches(|character: char| "\"'(),.;[]{}".contains(character))
        .to_ascii_lowercase();
    let host = normalized
        .split_once("://")
        .map(|(_, rest)| rest)
        .unwrap_or(&normalized)
        .split(['/', ':', '?', '#'])
        .next()
        .unwrap_or_default()
        .trim_start_matches("www.");
    patterns.iter().any(|pattern| {
        let pattern = pattern.trim().to_ascii_lowercase();
        if pattern.is_empty() {
            return false;
        }
        if pattern.contains("://") {
            return normalized.starts_with(pattern.trim_end_matches('*'));
        }
        let domain = pattern
            .trim_start_matches("*.")
            .trim_start_matches("www.")
            .trim_matches('/');
        host == domain || host.ends_with(&format!(".{domain}"))
    })
}

fn collect_raw_inventory(
    analysis: &AppAnalysis,
    rule_set: &rules::RuleSet,
) -> Vec<RawInventoryItem> {
    static TOKEN: OnceLock<Regex> = OnceLock::new();
    let token = TOKEN.get_or_init(|| {
        Regex::new(r#"(?i)https?://[^\s\"'<>]{4,}|[A-Za-z_$][A-Za-z0-9_.$:/-]{4,160}"#)
            .expect("raw inventory token regex")
    });
    let covered_haystack = [
        analysis.frameworks.join("\n"),
        analysis.third_party_libraries.join("\n"),
        analysis.protection.packers.join("\n"),
        analysis.protection.indicators.join("\n"),
        analysis.permissions.join("\n"),
        analysis.components.join("\n"),
        analysis.exported_components.join("\n"),
        analysis.manifest_flags.join("\n"),
        analysis
            .findings
            .iter()
            .map(|item| format!("{} {}", item.title, item.detail))
            .collect::<Vec<_>>()
            .join("\n"),
        analysis
            .sensitive_items
            .iter()
            .filter(|item| !item.filtered)
            .flat_map(|item| item.value.iter())
            .cloned()
            .collect::<Vec<_>>()
            .join("\n"),
    ]
    .join("\n")
    .to_ascii_lowercase();
    let mut counts = HashMap::<(String, String), u32>::new();
    let mut feed = |source: &str, value: &str| {
        for matched in token.find_iter(value) {
            let candidate = matched
                .as_str()
                .trim_matches(|character: char| ".,;:()[]{}\"'".contains(character));
            let lower = candidate.to_ascii_lowercase();
            if candidate.len() < 5
                || lower
                    .chars()
                    .all(|character| character.is_ascii_digit() || character == '.')
                || [
                    "android",
                    "framework",
                    "foundation",
                    "application",
                    "payload",
                    "classes.dex",
                    "libsystem",
                    "swiftcore",
                ]
                .iter()
                .any(|noise| lower == *noise)
            {
                continue;
            }
            *counts.entry((source.into(), candidate.into())).or_default() += 1;
        }
    };
    for path in &analysis.files {
        feed("file", path);
    }
    for insight in &analysis.code_insights {
        feed("symbol", &insight.name);
        if let Some(class_name) = &insight.class_name {
            feed("class", class_name);
        }
        for value in insight.references.iter().chain(insight.snippet.iter()) {
            feed("code", value);
        }
    }
    for insight in &analysis.binary_insights {
        for value in &insight.evidence {
            feed("binary", value);
        }
    }
    let mut output = counts
        .into_iter()
        .map(|((source, value), frequency)| {
            let lower = value.to_ascii_lowercase();
            let covered = covered_haystack.contains(&lower)
                || rule_set
                    .sensitive
                    .iter()
                    .any(|rule| rule.regex.is_match(&value));
            RawInventoryItem {
                source,
                value,
                frequency,
                covered,
            }
        })
        .collect::<Vec<_>>();
    output.sort_by(|left, right| {
        left.covered
            .cmp(&right.covered)
            .then(right.frequency.cmp(&left.frequency))
            .then(left.source.cmp(&right.source))
            .then(left.value.cmp(&right.value))
    });
    output.truncate(400);
    output
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
        (
            "Cordova / Capacitor",
            &["cordova.js", "capacitor", "ionic", "cdv"],
        ),
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

fn detect_third_party_libraries(
    archive: &mut ZipArchive<File>,
    files: &[String],
    rule_set: &rules::RuleSet,
) -> Vec<String> {
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
    rule_set
        .frameworks
        .iter()
        .filter(|rule| rules::contains_any(&haystack, &rule.trigger_signals, false))
        .map(|rule| rule.label.clone())
        .collect()
}

fn push_binary_insight(
    insights: &mut Vec<BinaryInsight>,
    category: &str,
    target: &str,
    severity: &str,
    detail: &str,
    mut evidence: Vec<String>,
) {
    let mut seen = HashSet::new();
    evidence.retain(|value| seen.insert(value.trim().to_string()));
    if evidence.is_empty()
        || insights.iter().any(|item| {
            item.category == category && item.target == target && item.evidence == evidence
        })
    {
        return;
    }
    insights.push(BinaryInsight {
        category: category.into(),
        target: target.into(),
        severity: severity.into(),
        detail: detail.into(),
        evidence,
    });
}

fn matching_symbols(text: &str, needles: &[&str], limit: usize) -> Vec<String> {
    needles
        .iter()
        .filter(|needle| text.contains(**needle))
        .take(limit)
        .map(|needle| (*needle).to_string())
        .collect()
}

fn matching_symbols_case_insensitive(text: &str, needles: &[&str], limit: usize) -> Vec<String> {
    let lower = text.to_ascii_lowercase();
    needles
        .iter()
        .filter(|needle| lower.contains(&needle.to_ascii_lowercase()))
        .take(limit)
        .map(|needle| (*needle).to_string())
        .collect()
}

fn regex_samples(text: &str, pattern: &str, limit: usize) -> Vec<String> {
    let mut seen = HashSet::new();
    Regex::new(pattern)
        .ok()
        .map(|regex| {
            regex
                .find_iter(text)
                .map(|matched| {
                    matched
                        .as_str()
                        .trim_matches(|character: char| "\"' \t\r\n,;()[]{}".contains(character))
                        .trim_end_matches(['.', ':'])
                        .to_string()
                })
                .filter(|value| !value.is_empty())
                .filter(|value| {
                    !value.contains("://") || !should_ignore_sensitive_match("url", value)
                })
                .filter(|value| seen.insert(value.clone()))
                .take(limit)
                .collect()
        })
        .unwrap_or_default()
}

fn binary_endpoint_samples(text: &str, limit: usize) -> Vec<String> {
    let mut samples = regex_samples(text, r#"(?i)\bhttps?://[^\s\"'<>]{5,}"#, limit);
    if samples.len() < limit {
        let relative = regex_samples(
            text,
            r#"(?i)/(?:api|rest|graphql|oauth|openapi|gateway|v[0-9]+)(?:/|\?)[A-Za-z0-9_./?&=%{}:+-]{2,}"#,
            limit - samples.len(),
        );
        samples.extend(relative);
    }
    samples
}

fn exact_indent(line: &str, spaces: usize) -> bool {
    line.as_bytes()
        .iter()
        .take_while(|value| **value == b' ')
        .count()
        == spaces
}

fn parse_hex_address(value: &str) -> Option<u64> {
    u64::from_str_radix(value.trim_start_matches("0x"), 16).ok()
}

fn ios_module_offset(address: &str) -> Option<String> {
    let address = parse_hex_address(address)?;
    (address >= 0x1_0000_0000).then(|| format!("0x{:x}", address - 0x1_0000_0000))
}

fn objc_method_references(class_name: &str, selector: &str) -> Vec<String> {
    // Class names are useful for framework attribution, but must not turn every
    // NSObject method in a class such as AFHTTPRequestSerializer into a network
    // entry.  Generic selectors (for example automaticallyNotifiesObserversForKey:)
    // should therefore be classified from the selector/signature signal itself.
    let class_lower = class_name.to_ascii_lowercase();
    let selector_lower = selector.to_ascii_lowercase();
    let rules = [
        ("TLS challenge", &["challenge"] as &[&str]),
        ("certificate trust", &["trust"]),
        ("certificate pinning", &["pinning"]),
        ("invalid certificate configuration", &["allowinvalid"]),
        ("domain validation configuration", &["validatesdomain"]),
        ("BaseURL", &["baseurl"]),
        (
            "HTTP request",
            &["request", "httpbody", "httpmethod", "header"],
        ),
        (
            "URL session",
            &[
                "session",
                "urlsession",
                "datatask",
                "uploadtask",
                "downloadtask",
                "websockettask",
            ],
        ),
        ("WebView", &["webview"]),
        (
            "JavaScript bridge",
            &["javascript", "scriptmessage", "evaluatejavascript"],
        ),
        ("URL opener", &["openurl", "canopenurl"]),
        ("encryption", &["encrypt"]),
        ("decryption", &["decrypt"]),
        ("AES", &["aes"]),
        ("Keychain", &["keychain", "secitem"]),
        ("jailbreak detection", &["jailbreak", "ptrace", "sysctl"]),
        ("authentication", &["auth", "credential", "login", "fido"]),
    ];
    let mut references = rules
        .iter()
        .filter(|(_, needles)| needles.iter().any(|needle| selector_lower.contains(needle)))
        .map(|(label, _)| (*label).to_string())
        .collect::<Vec<_>>();

    // Keep framework attribution only for a method that already has a meaningful
    // selector signal.  This is deliberately not a blanket `af` class-name rule.
    if class_lower.contains("afnetworking") || class_lower.starts_with("af") {
        if !references.is_empty() {
            references.push("AFNetworking".into());
        }
    }
    references
}

fn classify_objc_method(references: &[String]) -> &'static str {
    let lower = references.join(" ").to_ascii_lowercase();
    if lower.contains("challenge")
        || lower.contains("certificate")
        || lower.contains("pinning")
        || lower.contains("domain validation")
    {
        "ios-tls-entry"
    } else if lower.contains("webview")
        || lower.contains("javascript")
        || lower.contains("url opener")
    {
        "ios-webview-entry"
    } else if lower.contains("baseurl")
        || lower.contains("http")
        || lower.contains("url session")
        || lower.contains("afnetworking")
    {
        "ios-network-entry"
    } else if lower.contains("encryption")
        || lower.contains("decryption")
        || lower.contains("aes")
        || lower.contains("keychain")
    {
        "ios-crypto-entry"
    } else if lower.contains("jailbreak") || lower.contains("authentication") {
        "ios-security-entry"
    } else {
        "ios-objc-method"
    }
}

fn flush_objc_method(
    insights: &mut Vec<CodeInsight>,
    binary: &str,
    class_name: Option<&str>,
    superclass: Option<&str>,
    is_meta: bool,
    method_name: &mut Option<String>,
    method_types: &mut Option<String>,
    method_imp: &mut Option<String>,
) {
    let Some(name) = method_name.take() else {
        method_types.take();
        method_imp.take();
        return;
    };
    let class_name = class_name.unwrap_or("<unknown>").to_string();
    let address = method_imp
        .take()
        .filter(|value| value != "0x0" && value != "0");
    let references = objc_method_references(&class_name, &name);
    let marker = if is_meta { '+' } else { '-' };
    let runtime_target = Some(format!(
        "ObjC.classes[{:?}][{:?}]",
        class_name,
        format!("{marker} {name}")
    ));
    let mut signature = method_types.take();
    if let Some(superclass) = superclass.filter(|value| !value.is_empty()) {
        if signature.is_none() {
            signature = Some(format!("superclass={superclass}"));
        }
    }
    insights.push(CodeInsight {
        platform: "ios".into(),
        kind: classify_objc_method(&references).into(),
        binary: binary.into(),
        class_name: Some(class_name),
        name: format!("{marker} {name}"),
        signature,
        module_offset: address.as_deref().and_then(ios_module_offset),
        address,
        source_file: None,
        line_number: None,
        runtime_target,
        references,
        snippet: Vec::new(),
        confidence: "high".into(),
    });
}

fn parse_otool_objc(output: &str, binary: &str) -> Vec<CodeInsight> {
    static OBJECT_REGEX: OnceLock<Regex> = OnceLock::new();
    static VALUE_REGEX: OnceLock<Regex> = OnceLock::new();
    let object_regex =
        OBJECT_REGEX.get_or_init(|| Regex::new(r"^[0-9a-fA-F]{16}\s+0x[0-9a-fA-F]+$").unwrap());
    let value_regex = VALUE_REGEX.get_or_init(|| {
        Regex::new(r"^\s+\w+\s+0x[0-9a-fA-F]+(?: \+ 0x[0-9a-fA-F]+)?\s+(.+)$").unwrap()
    });
    let mut insights = Vec::new();
    let mut current_class: Option<String> = None;
    let mut superclass: Option<String> = None;
    let mut class_emitted = false;
    let mut is_meta = false;
    let mut in_methods = false;
    let mut method_name: Option<String> = None;
    let mut method_types: Option<String> = None;
    let mut method_imp: Option<String> = None;

    for line in output.lines() {
        if object_regex.is_match(line) {
            flush_objc_method(
                &mut insights,
                binary,
                current_class.as_deref(),
                superclass.as_deref(),
                is_meta,
                &mut method_name,
                &mut method_types,
                &mut method_imp,
            );
            current_class = None;
            superclass = None;
            class_emitted = false;
            is_meta = false;
            in_methods = false;
            continue;
        }
        if line.trim() == "Meta Class" {
            flush_objc_method(
                &mut insights,
                binary,
                current_class.as_deref(),
                superclass.as_deref(),
                is_meta,
                &mut method_name,
                &mut method_types,
                &mut method_imp,
            );
            is_meta = true;
            in_methods = false;
            continue;
        }
        if exact_indent(line, 4) && line.trim_start().starts_with("superclass ") {
            superclass = line
                .split("_OBJC_CLASS_$_")
                .nth(1)
                .or_else(|| line.split("_OBJC_METACLASS_$_").nth(1))
                .map(str::trim)
                .map(str::to_string);
            continue;
        }
        if exact_indent(line, 8) && line.trim_start().starts_with("name ") {
            let value = value_regex
                .captures(line)
                .and_then(|captures| captures.get(1))
                .map(|value| value.as_str().trim().to_string());
            if let Some(value) = value {
                current_class = Some(value.clone());
                if !is_meta && !class_emitted {
                    let mut references = Vec::new();
                    if let Some(parent) = superclass.as_deref() {
                        references.push(format!("superclass: {parent}"));
                    }
                    insights.push(CodeInsight {
                        platform: "ios".into(),
                        kind: "ios-objc-class".into(),
                        binary: binary.into(),
                        class_name: Some(value.clone()),
                        name: value.clone(),
                        signature: superclass
                            .as_deref()
                            .map(|parent| format!("@interface {value} : {parent}")),
                        address: None,
                        module_offset: None,
                        source_file: None,
                        line_number: None,
                        runtime_target: Some(format!("ObjC.classes[{:?}]", value)),
                        references,
                        snippet: Vec::new(),
                        confidence: "high".into(),
                    });
                    class_emitted = true;
                }
            }
            continue;
        }
        if exact_indent(line, 8) && line.trim_start().starts_with("baseMethods ") {
            in_methods = !line.trim_end().ends_with("0x0");
            continue;
        }
        if exact_indent(line, 8) && !line.trim().is_empty() {
            flush_objc_method(
                &mut insights,
                binary,
                current_class.as_deref(),
                superclass.as_deref(),
                is_meta,
                &mut method_name,
                &mut method_types,
                &mut method_imp,
            );
            in_methods = false;
            continue;
        }
        if !in_methods || !exact_indent(line, 12) {
            continue;
        }
        let trimmed = line.trim_start();
        if trimmed.starts_with("name ") {
            flush_objc_method(
                &mut insights,
                binary,
                current_class.as_deref(),
                superclass.as_deref(),
                is_meta,
                &mut method_name,
                &mut method_types,
                &mut method_imp,
            );
            method_name = value_regex
                .captures(line)
                .and_then(|captures| captures.get(1))
                .map(|value| value.as_str().trim().to_string());
        } else if trimmed.starts_with("types ") {
            method_types = value_regex
                .captures(line)
                .and_then(|captures| captures.get(1))
                .map(|value| value.as_str().trim().to_string());
        } else if trimmed.starts_with("imp ") {
            method_imp = trimmed.split_whitespace().nth(1).map(str::to_string);
            flush_objc_method(
                &mut insights,
                binary,
                current_class.as_deref(),
                superclass.as_deref(),
                is_meta,
                &mut method_name,
                &mut method_types,
                &mut method_imp,
            );
        }
    }
    flush_objc_method(
        &mut insights,
        binary,
        current_class.as_deref(),
        superclass.as_deref(),
        is_meta,
        &mut method_name,
        &mut method_types,
        &mut method_imp,
    );
    insights.dedup_by(|left, right| {
        left.kind == right.kind
            && left.class_name == right.class_name
            && left.name == right.name
            && left.address == right.address
    });
    insights
}

fn attach_otool_disassembly(output: &str, insights: &mut [CodeInsight]) {
    let mut targets: HashMap<String, Vec<usize>> = HashMap::new();
    for (index, insight) in insights.iter().enumerate() {
        if let Some(address) = insight.address.as_deref().and_then(parse_hex_address) {
            targets
                .entry(format!("{address:016x}"))
                .or_default()
                .push(index);
        }
    }
    if targets.is_empty() {
        return;
    }
    static LINE_REGEX: OnceLock<Regex> = OnceLock::new();
    let line_regex = LINE_REGEX.get_or_init(|| Regex::new(r"^([0-9a-fA-F]{16})\t(.+)$").unwrap());
    let mut snippets: HashMap<String, Vec<String>> = HashMap::new();
    let mut current: Option<String> = None;
    for line in output.lines() {
        let Some(captures) = line_regex.captures(line) else {
            current = None;
            continue;
        };
        let address = captures.get(1).unwrap().as_str().to_ascii_lowercase();
        if targets.contains_key(&address) {
            current = Some(address.clone());
        }
        let Some(target) = current.as_ref() else {
            continue;
        };
        let snippet = snippets.entry(target.clone()).or_default();
        if snippet.len() < 18 {
            snippet.push(line.to_string());
        } else {
            current = None;
        }
    }
    for (address, indices) in targets {
        let Some(snippet) = snippets.get(&address) else {
            continue;
        };
        let comments = snippet
            .iter()
            .filter_map(|line| line.split_once(';').map(|(_, value)| value.trim()))
            .filter(|value| {
                value.contains("Objc ")
                    || value.contains("cfstring")
                    || value.contains("symbol stub")
            })
            .take(12)
            .map(str::to_string)
            .collect::<Vec<_>>();
        for index in indices {
            insights[index].snippet = snippet.clone();
            for comment in &comments {
                if !insights[index].references.contains(comment) {
                    insights[index].references.push(comment.clone());
                }
            }
            insights[index].references.truncate(18);
        }
    }
}

fn parse_nm_code_symbols(output: &str, binary: &str) -> Vec<CodeInsight> {
    static DEFINED_REGEX: OnceLock<Regex> = OnceLock::new();
    static UNDEFINED_REGEX: OnceLock<Regex> = OnceLock::new();
    let defined_regex = DEFINED_REGEX
        .get_or_init(|| Regex::new(r"^([0-9a-fA-F]{16}) \(([^)]+)\) .*? ([^\s].+)$").unwrap());
    let undefined_regex = UNDEFINED_REGEX.get_or_init(|| {
        Regex::new(r"^\s+\(undefined\) external ([^\s]+)(?: \(from ([^)]+)\))?").unwrap()
    });
    let interesting = [
        "SecTrust",
        "CCCrypt",
        "CC_MD5",
        "CC_SHA",
        "ptrace",
        "sysctl",
        "dlopen",
        "dlsym",
        "objc_msgSend",
        "NSURLSession",
        "CFNetwork",
        "Security",
        "Keychain",
    ];
    let mut insights = Vec::new();
    for line in output.lines() {
        if let Some(captures) = defined_regex.captures(line) {
            let section = captures.get(2).unwrap().as_str();
            let name = captures.get(3).unwrap().as_str().trim();
            if !section.contains("__text") || name == "__mh_execute_header" {
                continue;
            }
            let address = format!("0x{}", captures.get(1).unwrap().as_str());
            insights.push(CodeInsight {
                platform: "ios".into(),
                kind: "ios-native-symbol".into(),
                binary: binary.into(),
                class_name: None,
                name: name.into(),
                signature: Some(section.into()),
                module_offset: ios_module_offset(&address),
                address: Some(address),
                source_file: None,
                line_number: None,
                runtime_target: None,
                references: Vec::new(),
                snippet: Vec::new(),
                confidence: "high".into(),
            });
        } else if let Some(captures) = undefined_regex.captures(line) {
            let name = captures.get(1).unwrap().as_str();
            if !interesting.iter().any(|needle| name.contains(needle)) {
                continue;
            }
            let library = captures.get(2).map(|value| value.as_str().to_string());
            insights.push(CodeInsight {
                platform: "ios".into(),
                kind: "ios-native-import".into(),
                binary: binary.into(),
                class_name: None,
                name: name.trim_start_matches('_').into(),
                signature: library
                    .as_deref()
                    .map(|value| format!("import from {value}")),
                address: None,
                module_offset: None,
                source_file: None,
                line_number: None,
                runtime_target: None,
                references: library.into_iter().collect(),
                snippet: Vec::new(),
                confidence: "high".into(),
            });
        }
    }
    insights.truncate(300);
    insights
}

fn parse_ios_codeprotect_filter(
    bytes: &[u8],
    binary: &str,
    module_name: Option<&str>,
) -> Vec<CodeInsight> {
    let Ok(document) = serde_json::from_slice::<serde_json::Value>(bytes) else {
        return Vec::new();
    };
    let Some(groups) = document.as_object() else {
        return Vec::new();
    };
    let mut insights = Vec::new();
    for group in ["a", "b"] {
        let Some(mappings) = groups.get(group).and_then(|value| value.as_array()) else {
            continue;
        };
        for (index, mapping) in mappings.iter().enumerate() {
            let Some(source) = mapping.get("f").and_then(|value| value.as_u64()) else {
                continue;
            };
            let Some(target) = mapping.get("t").and_then(|value| value.as_u64()) else {
                continue;
            };
            let source_offset = format!("0x{source:x}");
            let target_offset = format!("0x{target:x}");
            let runtime_target = module_name.map(|module| {
                format!("Process.getModuleByName({module:?}).base.add({source_offset})")
            });
            let mut snippet = vec![format!(
                "group {group}[{index}]: module+{source_offset} -> module+{target_offset}"
            )];
            if let Some(module) = module_name {
                snippet.push(format!(
                    "source: Process.getModuleByName({module:?}).base.add({source_offset})"
                ));
                snippet.push(format!(
                    "target: Process.getModuleByName({module:?}).base.add({target_offset})"
                ));
            }
            insights.push(CodeInsight {
                platform: "ios".into(),
                kind: "ios-codeprotect-map".into(),
                binary: binary.into(),
                class_name: None,
                name: format!("{group}[{index}] {source_offset} -> {target_offset}"),
                signature: Some(format!(
                    "JMCodeProtect filter mapping group {group}; f={source}, t={target}"
                )),
                address: None,
                module_offset: Some(source_offset),
                source_file: Some(binary.into()),
                line_number: None,
                runtime_target,
                references: vec![format!("target module+{target_offset}")],
                snippet,
                confidence: "medium".into(),
            });
        }
    }
    insights
}

async fn analyze_ios_macho_code(
    executable: &Path,
    binary: &str,
) -> Result<Vec<CodeInsight>, String> {
    let path = executable.to_string_lossy().into_owned();
    let objc = run_host_with_timeout(
        "otool",
        &["-ov".into(), path.clone()],
        Duration::from_secs(180),
    )
    .await?;
    if objc.code != Some(0) || objc.stdout.is_empty() {
        return Err(output_text(&objc));
    }
    let mut insights = parse_otool_objc(&objc.stdout, binary);
    if let Ok(symbols) = run_host_with_timeout(
        "nm",
        &["-nm".into(), path.clone()],
        Duration::from_secs(120),
    )
    .await
    {
        insights.extend(parse_nm_code_symbols(&symbols.stdout, binary));
    }
    if let Ok(disassembly) =
        run_host_with_timeout("otool", &["-tvV".into(), path], Duration::from_secs(240)).await
    {
        attach_otool_disassembly(&disassembly.stdout, &mut insights);
    }
    insights.sort_by(|left, right| {
        let priority = |kind: &str| match kind {
            "ios-tls-entry" | "ios-network-entry" | "ios-webview-entry" | "ios-crypto-entry"
            | "ios-security-entry" => 0,
            "ios-objc-class" => 1,
            "ios-objc-method" => 2,
            _ => 3,
        };
        priority(&left.kind)
            .cmp(&priority(&right.kind))
            .then(left.class_name.cmp(&right.class_name))
            .then(left.name.cmp(&right.name))
    });
    insights.dedup_by(|left, right| {
        left.kind == right.kind
            && left.class_name == right.class_name
            && left.name == right.name
            && left.address == right.address
    });
    insights.truncate(4000);
    Ok(insights)
}

struct FrameworkBinaryRule {
    category: &'static str,
    markers: &'static [&'static str],
    evidence: &'static [&'static str],
    severity: &'static str,
    detail: &'static str,
}

fn framework_binary_rules() -> &'static [FrameworkBinaryRule] {
    static RULES: &[FrameworkBinaryRule] = &[
        FrameworkBinaryRule {
            category: "Alamofire 网络入口",
            markers: &["alamofire", "session.swift"],
            evidence: &["Session", "URLRequestConvertible", "Request", "DataRequest", "UploadRequest", "DownloadRequest"],
            severity: "review",
            detail: "Alamofire 请求构造与会话入口；结合 Endpoint、URLRequestConvertible、SessionConfiguration 和运行时请求确认实际 BaseURL、重定向与请求头。",
        },
        FrameworkBinaryRule {
            category: "Alamofire TLS / Pinning",
            markers: &["alamofire", "servertrustmanager", "pinnedcertificatestrustevaluator"],
            evidence: &["ServerTrustManager", "PinnedCertificatesTrustEvaluator", "PublicKeysTrustEvaluator", "DisabledTrustEvaluator", "RevocationTrustEvaluator"],
            severity: "review",
            detail: "Alamofire ServerTrustManager/TrustEvaluator 入口；静态命中只说明存在配置能力，需确认 evaluator 是否绑定到生产域名。",
        },
        FrameworkBinaryRule {
            category: "Moya 网络 / Endpoint 入口",
            markers: &["moya", "moyaprovider", "targettype"],
            evidence: &["MoyaProvider", "TargetType", "Endpoint", "EndpointClosure", "RequestClosure", "PluginType", "Task"],
            severity: "review",
            detail: "Moya 的 TargetType、Endpoint 和 Provider 抽象层；可用于定位 API 枚举、通用请求闭包、插件和认证注入点。",
        },
        FrameworkBinaryRule {
            category: "URLSession / CFNetwork 网络入口",
            markers: &["nsurlsession", "urlsession", "cfnetwork", "cfstream"],
            evidence: &["NSURLSession", "URLSessionConfiguration", "URLSessionTask", "dataTaskWithRequest:", "uploadTaskWithRequest:", "CFHTTPMessage", "CFReadStreamCreateForHTTPRequest"],
            severity: "info",
            detail: "Apple 原生网络栈入口；应继续关联 delegate、代理配置、重定向和 didReceiveChallenge 处理，而不是仅凭 API 名称判断安全性。",
        },
        FrameworkBinaryRule {
            category: "libcurl 网络入口",
            markers: &["libcurl", "curl_easy_", "curl_multi_"],
            evidence: &["curl_easy_init", "curl_easy_setopt", "CURLOPT_URL", "CURLOPT_SSL_VERIFYPEER", "CURLOPT_SSL_VERIFYHOST", "curl_multi_perform"],
            severity: "review",
            detail: "libcurl URL、TLS 验证和多路复用入口；重点复核 CURLOPT_SSL_VERIFYPEER/VERIFYHOST 与自定义 CA 设置。",
        },
        FrameworkBinaryRule {
            category: "TrustKit TLS / Pinning",
            markers: &["trustkit", "tskpinning", "tskpinningvalidator"],
            evidence: &["TrustKit", "TSKPinningValidator", "TSKPinningPolicy", "TSKPinningDecision", "kTSKEnforcePinning"],
            severity: "review",
            detail: "TrustKit 的 Pinning 策略和验证回调入口；建议提取配置域名并做运行时成功/失败路径验证。",
        },
        FrameworkBinaryRule {
            category: "WebKit / JavaScriptCore 桥接",
            markers: &["webkit", "wkwebview", "javascriptcore", "jscontext"],
            evidence: &["WKWebView", "WKUserContentController", "addScriptMessageHandler:", "evaluateJavaScript:", "JSContext", "JSExport"],
            severity: "review",
            detail: "WebKit/JavaScriptCore 的页面加载、脚本执行和原生桥接面；需要检查 message handler、scheme 白名单、导航策略及敏感 API 暴露。",
        },
        FrameworkBinaryRule {
            category: "FMDB / SQLite 存储入口",
            markers: &["fmdb", "sqlite3", "sqlite.framework"],
            evidence: &["FMDatabase", "FMDatabaseQueue", "FMResultSet", "sqlite3_open", "sqlite3_exec", "sqlite3_prepare_v2", "SQLITE_HAS_CODEC"],
            severity: "info",
            detail: "SQLite/FMDB 数据库打开、执行和结果读取入口；后续应检查数据库路径、加密配置、敏感字段和导出备份行为。",
        },
        FrameworkBinaryRule {
            category: "Realm 数据库入口",
            markers: &["realm", "rlmrealm", "realmcore"],
            evidence: &["RLMRealm", "RLMObject", "Realm.Configuration", "RealmSwift", "RealmCore"],
            severity: "info",
            detail: "Realm 对象模型和数据库配置入口；重点关注 Realm 文件位置、key 管理、同步配置和未加密本地数据。",
        },
        FrameworkBinaryRule {
            category: "Core Data 存储入口",
            markers: &["coredata", "nsmanagedobject", "persistentcontainer"],
            evidence: &["NSManagedObject", "NSPersistentContainer", "NSPersistentStoreCoordinator", "NSFetchRequest", "NSSQLiteStoreType"],
            severity: "info",
            detail: "Core Data 持久化容器、SQLite store 和查询入口；结合模型与沙盒路径复核敏感数据保护。",
        },
        FrameworkBinaryRule {
            category: "Keychain / Secure Enclave 入口",
            markers: &["security.framework", "keychain", "secitem", "secureenclave", "scescrow"],
            evidence: &["SecItemAdd", "SecItemCopyMatching", "SecItemUpdate", "SecItemDelete", "kSecAttrAccessible", "SecKeyCreateRandomKey", "SecureEnclave"],
            severity: "review",
            detail: "Keychain/Secure Enclave 存取和密钥生成入口；需要结合 kSecAttrAccessible、访问组、biometry 和实际存储对象判断保护强度。",
        },
        FrameworkBinaryRule {
            category: "SDWebImage / Kingfisher 图片网络入口",
            markers: &["sdwebimage", "sdwebimage", "kingfisher", "yywebimage"],
            evidence: &["SDWebImageManager", "SDWebImageDownloader", "SDImageCache", "KingfisherManager", "ImageDownloader", "Source.network"],
            severity: "info",
            detail: "图片下载、缓存和 URL 解析入口；可用于区分业务 API 与 CDN/图片噪音，并检查缓存目录和自定义 downloader 配置。",
        },
        FrameworkBinaryRule {
            category: "Firebase / Sentry / Bugly 诊断 SDK",
            markers: &["firebase", "sentry", "bugly", "crashlytics"],
            evidence: &["FIRApp", "FirebaseApp", "Crashlytics", "SentrySDK", "Bugly", "BLYLog", "recordError:"],
            severity: "info",
            detail: "崩溃、日志、性能和遥测 SDK 入口；应确认上传域名、用户标识、日志脱敏和测试环境开关。",
        },
        FrameworkBinaryRule {
            category: "React Native 原生桥接",
            markers: &["reactnative", "rctbridge", "rcteventemitter", "main.jsbundle"],
            evidence: &["RCTBridge", "RCTModuleData", "RCTEventEmitter", "RCT_EXPORT_METHOD", "RCTViewManager", "__fbBatchedBridge"],
            severity: "review",
            detail: "React Native JS-to-native bridge 和导出模块入口；重点检查导出方法参数校验、事件通道和调试 bridge 是否残留。",
        },
        FrameworkBinaryRule {
            category: "Cordova / Capacitor WebView 桥接",
            markers: &["cordova", "capacitor", "ionic", "cdvcommanddelegate"],
            evidence: &["CDVViewController", "CDVCommandDelegate", "cordova.exec", "CAPBridge", "CAPPlugin", "WKScriptMessageHandler"],
            severity: "review",
            detail: "Cordova/Capacitor 插件桥接和 WebView 命令入口；应核对插件白名单、scheme、文件访问和原生能力暴露。",
        },
        FrameworkBinaryRule {
            category: "Flutter MethodChannel / 插件桥接",
            markers: &["flutter", "methodchannel", "generatedpluginregistrant", "libapp.so"],
            evidence: &["FlutterMethodChannel", "MethodChannel", "GeneratedPluginRegistrant", "Dart_CObject", "BinaryMessenger", "vm_snapshot_data"],
            severity: "review",
            detail: "Flutter 引擎、Dart AOT 和 MethodChannel 入口；Release AOT 不等于源码可恢复，重点检查插件注册和敏感原生通道。",
        },
        FrameworkBinaryRule {
            category: "SwiftNIO 网络 / EventLoop 入口",
            markers: &["nio.framework", "swift nio", "niocore", "eventloopgroup", "channelpipeline"],
            evidence: &["EventLoopGroup", "MultiThreadedEventLoopGroup", "ChannelPipeline", "ClientBootstrap", "NIOHTTP1", "NIOAsyncChannel"],
            severity: "info",
            detail: "SwiftNIO 的 EventLoop、ChannelPipeline 和 Bootstrap 入口；常见于自定义 HTTP/TCP 服务或客户端，需结合 NIOHTTP1、TLS handler 和目标地址确认实际网络用途。",
        },
        FrameworkBinaryRule {
            category: "NIOSSL / NIOTLS TLS 入口",
            markers: &["niossl", "niotls", "cnioboringssls", "boringssl"],
            evidence: &["NIOSSLContext", "TLSConfiguration", "NIOSSLClientHandler", "NIOSSLServerHandler", "NIOTLS", "CNIOBoringSSL"],
            severity: "review",
            detail: "SwiftNIO TLS 与 BoringSSL shim 入口；继续检查证书验证回调、hostname 校验、TLSConfiguration 和自定义 trust store。",
        },
        FrameworkBinaryRule {
            category: "FaceLive / 活体检测 SDK",
            markers: &["facelivekit", "yylfacedetect", "facedetect", "liveness"],
            evidence: &["FaceLive", "FaceLiveKit", "YYLFaceDetect", "Liveness", "FaceDetect", "CameraSession"],
            severity: "review",
            detail: "人脸/活体检测 SDK 的采集、检测和结果回调入口；重点检查相机权限、图像缓存、调试日志及结果签名/传输保护。",
        },
        FrameworkBinaryRule {
            category: "第三方代码保护 / 运行时恢复",
            markers: &["jmprotection", "jmcodeprotectkit", "cryptosdkterminate", "ipacodeprotect"],
            evidence: &["JMProtection", "JMCodeProtectKit", "IPACodeProtect", "CodeProtect", "antiDebug", "antiJailbreak"],
            severity: "review",
            detail: "第三方代码保护、反调试或运行时恢复相关入口；不会改变 cryptid=0 的结论，但会降低静态类/IMP 归属的确定性，需结合运行时枚举确认。",
        },
        FrameworkBinaryRule {
            category: "Unity Native bridge",
            markers: &["unityframework", "libunity.so", "il2cpp", "unitysendmessage"],
            evidence: &["UnityFramework", "UnitySendMessage", "il2cpp_init", "il2cpp_runtime_invoke", "UnityAppController"],
            severity: "review",
            detail: "Unity/IL2CPP 原生桥接入口；可继续结合 global-metadata、导出符号和运行时消息定位游戏逻辑与网络插件。",
        },
    ];
    RULES
}

fn analyze_framework_binary_rules(
    insights: &mut Vec<BinaryInsight>,
    name: &str,
    file_lower: &str,
    lower: &str,
    text: &str,
) {
    for rule in framework_binary_rules() {
        let marker_hit = rule.markers.iter().any(|marker| {
            file_lower.contains(&marker.to_ascii_lowercase())
                || lower.contains(&marker.to_ascii_lowercase())
        });
        if !marker_hit {
            continue;
        }
        let mut evidence = rule
            .evidence
            .iter()
            .filter(|needle| lower.contains(&needle.to_ascii_lowercase()))
            .map(|needle| (*needle).to_string())
            .collect::<Vec<_>>();
        if evidence.is_empty() {
            evidence = rule
                .markers
                .iter()
                .filter(|marker| {
                    file_lower.contains(&marker.to_ascii_lowercase())
                        || lower.contains(&marker.to_ascii_lowercase())
                })
                .map(|marker| (*marker).to_string())
                .collect();
        }
        push_binary_insight(
            insights,
            rule.category,
            name,
            rule.severity,
            rule.detail,
            evidence,
        );
    }
    let _ = text;
}

struct FrameworkRiskSignalRule {
    category: &'static str,
    markers: &'static [&'static str],
    indicators: &'static [&'static str],
    severity: &'static str,
    detail: &'static str,
}

fn framework_risk_signal_rules() -> &'static [FrameworkRiskSignalRule] {
    static RULES: &[FrameworkRiskSignalRule] = &[
        FrameworkRiskSignalRule {
            category: "AFNetworking 弱 TLS 配置候选",
            markers: &["afnetworking", "afsecuritypolicy"],
            indicators: &[
                "allowInvalidCertificates",
                "setAllowInvalidCertificates:",
                "AFSSLPinningModeNone",
                "validatesDomainName",
                "setValidatesDomainName:",
            ],
            severity: "high",
            detail: "AFNetworking 命中允许无效证书、关闭域名校验或 None Pinning 的配置符号。需要确认生产调用点的实际布尔值、Pinning mode、challenge 分支和目标域名；静态字符串本身不等于配置已启用。",
        },
        FrameworkRiskSignalRule {
            category: "AFNetworking 缓存/敏感头候选",
            markers: &["afnetworking", "afurlsessionmanager", "afhttpsessionmanager"],
            indicators: &[
                "NSURLCache",
                "URLCache",
                "cachedResponse",
                "AFImageRequestCache",
                "Authorization",
                "Cookie",
                "accessToken",
                "refreshToken",
            ],
            severity: "review",
            detail: "发现 AFNetworking/URLSession 缓存或敏感认证头线索。需要核对缓存策略、响应缓存目录、Cache-Control、退出登录清理和是否把 Token/Cookie 写入可恢复缓存；这里不直接读取或导出凭据。",
        },
        FrameworkRiskSignalRule {
            category: "Alamofire 任意证书信任候选",
            markers: &["alamofire", "servertrustmanager", "servertrustpolicy"],
            indicators: &[
                "DisabledTrustEvaluator",
                "disableEvaluation",
                "ServerTrustPolicy.disableEvaluation",
                "allHostsMustBeEvaluated: false",
            ],
            severity: "high",
            detail: "发现 Alamofire DisabledTrustEvaluator、disableEvaluation 或旧版 ServerTrustPolicy 放行线索。需要确认是否绑定生产 Host、是否仅限测试环境，以及失败分支是否真正拒绝连接。",
        },
        FrameworkRiskSignalRule {
            category: "WebSocket 明文/鉴权候选",
            markers: &["socketrocket", "srwebsocket", "socket.io", "socketioclient", "websocket"],
            indicators: &[
                "ws://",
                "SocketRocket",
                "SRWebSocket",
                "SocketIOClient",
                "connectParams",
                "extraHeaders",
                "engine.io",
            ],
            severity: "review",
            detail: "发现 Socket.IO/SocketRocket/WebSocket 连接或连接参数。重点验证是否使用 wss、握手是否带短期鉴权、服务端是否校验 Origin/Session、消息是否含敏感字段；命中 ws:// 时应提升为高优先级人工复核。",
        },
        FrameworkRiskSignalRule {
            category: "MQTT 明文凭据/TLS 候选",
            markers: &["cocoamqtt", "mqttsession", "mqttclient", "mqtt.framework"],
            indicators: &[
                "mqtt://",
                "MQTTUsername",
                "MQTTPassword",
                "username",
                "password",
                "enableSSL",
                "tlsConfiguration",
            ],
            severity: "review",
            detail: "发现 CocoaMQTT/MQTT 凭据、连接地址或 TLS 配置线索。需要确认实际 URI 是否为 mqtt/mqtts、用户名密码是否短期化、连接失败是否拒绝降级以及 ACL 是否绑定设备/用户。",
        },
        FrameworkRiskSignalRule {
            category: "NIO/BoringSSL 弱 TLS 候选",
            markers: &["nio", "niossl", "niotls", "boringssl", "cnioboringssls"],
            indicators: &[
                "skipServerCertificateValidation",
                "SSL_VERIFY_NONE",
                "certificateVerification: .none",
                "acceptAnyCertificate",
                "verifyPeerCertificate",
            ],
            severity: "review",
            detail: "发现 SwiftNIO/NIOSSL/BoringSSL 的证书验证或客户端 TLS 配置入口。需要确认 verifyPeerCertificate、hostname 校验、TrustRoots 和失败路径；正常 TLS API 命中不能单独判定为弱校验。",
        },
        FrameworkRiskSignalRule {
            category: "旧版 OpenSSL/TLS 兼容候选",
            markers: &["openssl", "libcrypto", "boringssl"],
            indicators: &[
                "OpenSSL 1.0",
                "OpenSSL_1_0",
                "SSLv3_method",
                "TLSv1_method",
                "SSL_VERIFY_NONE",
            ],
            severity: "review",
            detail: "发现旧版 OpenSSL/兼容协议或关闭验证符号。静态字符串不能可靠替代 SBOM/CVE 版本判断；应记录精确库版本、架构、是否实际加载及服务端协议协商结果。",
        },
        FrameworkRiskSignalRule {
            category: "WebViewJavascriptBridge 来源校验候选",
            markers: &["webviewjavascriptbridge", "wvjb", "javascriptbridge"],
            indicators: &[
                "registerHandler",
                "callHandler",
                "messageHandlers",
                "sendData",
                "javascriptCommand",
            ],
            severity: "review",
            detail: "发现 WebViewJavascriptBridge/WVJB Handler 注册或调用入口。重点核对 scheme/host 白名单、frame/main-frame、Origin、消息 schema、认证状态和敏感 Handler allowlist；没有观察到来源校验不能直接等同于不存在校验。",
        },
        FrameworkRiskSignalRule {
            category: "Cordova/PhoneGap 本地文件访问候选",
            markers: &["cordova", "phonegap", "cdvfile", "cdvcommanddelegate"],
            indicators: &[
                "allowUniversalAccessFromFileURLs",
                "setAllowUniversalAccessFromFileURLs",
                "allowFileAccessFromFileURLs",
                "setAllowFileAccessFromFileURLs",
                "CDVFile",
                "file://",
                "cordova.exec",
            ],
            severity: "high",
            detail: "发现 Cordova/PhoneGap file://、Universal/File URL 访问或插件命令入口。需要检查 file scheme 的可访问根目录、远程页面导航、插件白名单和本地文件读取边界；静态命中不代表已成功读取文件。",
        },
        FrameworkRiskSignalRule {
            category: "React Native Bundle/调试桥候选",
            markers: &["reactnative", "rctbridge", "main.jsbundle", "hermes"],
            indicators: &[
                "RCTDevSettings",
                "RCTPackagerConnection",
                "remoteDebugging",
                "__fbBatchedBridge",
                "RCT_EXPORT_METHOD",
                "CodePush",
                "main.jsbundle",
            ],
            severity: "review",
            detail: "发现 React Native JS Bundle、导出模块、调试连接或热更新线索。需要检查 Release 包是否残留 DevMenu/Packager、Bundle 完整性保护、CodePush 签名/回滚和原生模块参数校验。",
        },
        FrameworkRiskSignalRule {
            category: "JSPatch/热更新任意脚本候选",
            markers: &["jspatch", "jpbox", "jpevaluate", "hotupdate", "codepush"],
            indicators: &[
                "JSPatch",
                "JPEngine",
                "JPBox",
                "evaluateScriptWithSourceURL",
                "JSContext",
                "hotUpdate",
                "downloadScript",
            ],
            severity: "high",
            detail: "发现 JSPatch 或脚本热更新执行入口。需要确认生产包是否可下载/执行未经强签名和完整性校验的脚本、更新源是否固定、回滚是否安全；静态存在不等于已经形成任意代码执行。",
        },
        FrameworkRiskSignalRule {
            category: "Flutter/uni-app 混合桥候选",
            markers: &["flutter", "methodchannel", "uniapp", "uni-jsbridge", "weex", "wxbridge"],
            indicators: &[
                "MethodChannel",
                "BinaryMessenger",
                "GeneratedPluginRegistrant",
                "uni-jsbridge",
                "uniapp",
                "Weex",
                "WXBridge",
                "postMessage",
            ],
            severity: "review",
            detail: "发现 Flutter MethodChannel、uni-app/Weex 或混合页面桥接入口。需要逐一建立 channel/handler 到原生插件能力的映射，并检查参数 schema、调用方身份、来源和敏感操作授权。",
        },
        FrameworkRiskSignalRule {
            category: "SQLCipher 密钥管理候选",
            markers: &["sqlcipher", "sqlite3_key", "encrypted database"],
            indicators: &[
                "sqlite3_key",
                "PRAGMA key",
                "setKey:",
                "encryptionKey",
                "passphrase",
                "databaseKey",
            ],
            severity: "high",
            detail: "发现 SQLCipher 数据库密钥设置入口。需要确认密钥是否硬编码、是否从 Keychain/Secure Enclave 派生、是否绑定设备/用户、轮换与迁移是否安全；工具不会在报告中导出完整密钥材料。",
        },
        FrameworkRiskSignalRule {
            category: "加密 API/弱模式候选",
            markers: &["cryptoswift", "commoncrypto", "openssl"],
            indicators: &[
                "AES/ECB",
                "kCCOptionECBMode",
                "DESede",
                "MD5",
                "fixedIV",
                "initializationVector",
            ],
            severity: "high",
            detail: "发现 CryptoSwift/CommonCrypto/OpenSSL 的弱模式、弱摘要或固定参数线索。需要结合调用点确认是否真的使用 ECB、DES/MD5、固定 IV 或硬编码 key；正常加密 API 命中不会进入此分类。",
        },
        FrameworkRiskSignalRule {
            category: "国密 API/密钥管理候选",
            markers: &["gmobjc", "sm2", "sm3", "sm4"],
            indicators: &["SM2", "SM3", "SM4", "GMObjC", "random"],
            severity: "review",
            detail: "发现 GMObjC/SM2/SM3/SM4 国密 API。需要确认密钥是否硬编码、随机数是否复用、签名验签是否在服务端完成以及密钥生命周期、轮换和设备绑定是否正确。",
        },
        FrameworkRiskSignalRule {
            category: "SQLite/FMDB/Core Data 明文存储候选",
            markers: &["fmdb", "sqlite", "coredata", "nsmanagedobject", "nspersistentcontainer"],
            indicators: &[
                "FMDatabase",
                "sqlite3_open",
                ".sqlite",
                "NSSQLiteStoreType",
                "NSPersistentContainer",
                "executeUpdate:",
                "SELECT ",
            ],
            severity: "review",
            detail: "发现 SQLite/FMDB/Core Data 数据库和查询入口。需要检查数据库文件保护级别、敏感字段是否加密、SQL 是否拼接外部输入、备份/共享设置及退出登录清理。",
        },
        FrameworkRiskSignalRule {
            category: "Realm 密钥/文件保护候选",
            markers: &["realm", "rlmrealm"],
            indicators: &[
                "Realm.Configuration",
                "RLMRealmConfiguration",
                "encryptionKey",
                "realmKey",
                ".realm",
                "syncConfiguration",
            ],
            severity: "review",
            detail: "发现 Realm 文件、同步或 encryptionKey 配置。需要确认本地 Realm 是否启用加密、密钥是否来自 Keychain、同步用户授权是否隔离、备份和导出路径是否受保护。",
        },
        FrameworkRiskSignalRule {
            category: "NSUserDefaults 敏感数据存储候选",
            markers: &["nsuserdefaults", "userdefaults"],
            indicators: &[
                "accessToken",
                "refreshToken",
                "authorization",
                "password",
                "cookie",
                "setObject:forKey:",
                "UserDefaults.standard",
            ],
            severity: "high",
            detail: "发现 UserDefaults/NSUserDefaults 与 Token、Cookie、密码或 Authorization 字段同时出现。需要确认是否真的写入敏感值，优先迁移到 Keychain，并检查日志、备份与注销清理。",
        },
        FrameworkRiskSignalRule {
            category: "地图/推送 SDK Key 候选",
            markers: &[
                "amap",
                "gaode",
                "baidu map",
                "bmap",
                "umeng",
                "jpush",
                "getui",
                "mobfoundation",
                "mobpush",
                "moblink",
            ],
            indicators: &[
                "apiKey",
                "APIKey",
                "appkey",
                "appKey",
                "appSecret",
                "AMapServices",
                "BMKMapManager",
                "deviceToken",
            ],
            severity: "high",
            detail: "发现地图、推送或第三方服务的 AppKey/AppSecret/设备标识配置线索。需要确认 Key 是否仅为可公开客户端 Key、服务端是否绑定包名/签名/域名/配额，禁止把 AppSecret 当作客户端安全边界。",
        },
        FrameworkRiskSignalRule {
            category: "支付 SDK 签名/回调候选",
            markers: &["alipay", "wechatpay", "wechatopensdk", "weixinpay", "alipay sdk", "payment sdk"],
            indicators: &[
                "rsa_private_key",
                "privateKey",
                "appsecret",
                "mch_id",
                "prepay_id",
                "notify_url",
                "signature",
                "verifySignature",
                "paymentResult",
            ],
            severity: "high",
            detail: "发现支付宝/微信支付签名参数、私钥或回调处理线索。需要确认私钥只在服务端、支付结果是否服务端验签和幂等校验、客户端回调是否仅作展示而非授权依据。",
        },
        FrameworkRiskSignalRule {
            category: "崩溃/遥测敏感数据上报候选",
            markers: &["bugly", "sentry", "crashlytics", "firebase"],
            indicators: &[
                "recordError:",
                "Crashlytics",
                "SentrySDK",
                "Bugly",
                "userInfo",
                "customData",
                "breadcrumb",
                "upload",
            ],
            severity: "review",
            detail: "发现 Bugly/Sentry/Crashlytics/Firebase 遥测入口和自定义字段。需要验证 Token、Cookie、身份证件、图像、认证响应和调试日志是否脱敏，以及生产环境采集开关和数据保留策略。",
        },
        FrameworkRiskSignalRule {
            category: "生产调试工具残留候选",
            markers: &["flex", "doraemonkit", "doraemon", "leakcanary", "reveal", "chisel", "reactotron"],
            indicators: &[
                "FLEXManager",
                "Doraemon",
                "LeakCanary",
                "Reactotron",
                "Shake",
                "debugMenu",
                "networkInspector",
            ],
            severity: "high",
            detail: "发现 FLEX/DoraemonKit/LeakCanary/Reactotron 等调试工具或面板入口。需要确认 Release 包是否可触发、是否可查看网络/存储/路由、是否受签名/环境/权限限制。",
        },
        FrameworkRiskSignalRule {
            category: "生物/AI SDK 结果与缓存候选",
            markers: &[
                "facelive",
                "facedetect",
                "liveness",
                "sensetime",
                "megvii",
                "face++",
                "aliyunface",
                "ocrkit",
                "tesseract",
                "visionocr",
                "speechrecognizer",
                "sfspeechrecognizer",
                "audiokit",
            ],
            indicators: &[
                "liveness",
                "image",
                "audio",
                "cache",
                "signature",
                "verify",
                "confidence",
                "faceImage",
                "sampleBuffer",
            ],
            severity: "review",
            detail: "发现人脸活体、OCR、语音或 AI SDK 的结果回调、媒体缓存或签名校验线索。需要确认结果是否由服务端签名验证、回调是否可篡改、图像/音频缓存是否加密及生命周期是否最小化。",
        },
    ];
    RULES
}

fn analyze_framework_risk_signals(
    insights: &mut Vec<BinaryInsight>,
    name: &str,
    file_lower: &str,
    lower: &str,
    text: &str,
) {
    for rule in framework_risk_signal_rules() {
        let framework_hit = rule
            .markers
            .iter()
            .any(|marker| file_lower.contains(marker) || lower.contains(marker));
        if !framework_hit {
            continue;
        }
        let evidence = matching_symbols_case_insensitive(text, rule.indicators, 16);
        if evidence.is_empty() {
            continue;
        }
        push_binary_insight(
            insights,
            rule.category,
            name,
            rule.severity,
            rule.detail,
            evidence,
        );
    }

    let version_candidates = regex_samples(
        text,
        r#"(?i)\b(?:afnetworking|alamofire|cocoamqtt|socketrocket|openssl|cordova|react(?:native)?|flutter|realm|sqlcipher|jspatch|bugly|umeng|jpush)[^0-9]{0,8}v?\d+\.\d+(?:\.\d+)?\b"#,
        12,
    );
    push_binary_insight(
        insights,
        "框架版本候选",
        name,
        "info",
        "从二进制/资源字符串提取到的版本候选，可用于依赖清单和 CVE 复核；版本字符串缺失或被裁剪时不能据此判断安全版本。",
        version_candidates,
    );
}

fn analyze_jsbridge_text(
    insights: &mut Vec<BinaryInsight>,
    name: &str,
    file_lower: &str,
    lower: &str,
    text: &str,
) {
    let bridge = matching_symbols(
        text,
        &[
            "WKWebView",
            "WKUserContentController",
            "WKScriptMessageHandler",
            "WKContentWorld",
            "addScriptMessageHandler:",
            "addScriptMessageHandler:contentWorld:name:",
            "addScriptMessageHandlerWithReply:contentWorld:name:",
            "removeScriptMessageHandlerForName:",
            "userContentController:didReceiveScriptMessage:",
            "userContentController:didReceiveScriptMessage:replyHandler:",
        ],
        24,
    );
    let jsbridge_file = file_lower.ends_with(".js")
        || file_lower.ends_with(".html")
        || file_lower.ends_with(".htm")
        || file_lower.ends_with(".jsbundle")
        || lower.contains("messagehandlers")
        || lower.contains("postmessage");
    if bridge.is_empty() && !jsbridge_file {
        return;
    }
    push_binary_insight(
        insights,
        "iOS JSBridge 注册/消息入口",
        name,
        "review",
        "发现 WKWebView/JavaScriptCore 的 Bridge 注册、消息接收或 Content World 入口。静态命中只是候选证据，不代表任意页面可以调用；应结合 Handler、来源、frame、参数 schema 和原生权限校验确认。",
        if bridge.is_empty() {
            vec!["JavaScript/HTML WebView 资源".into()]
        } else {
            bridge
        },
    );

    let handler_names = regex_samples(
        text,
        r#"(?i)(?:messageHandlers|cordova\.plugins|webkit\.messageHandlers)[._/]([A-Za-z][A-Za-z0-9_.-]{1,63})"#,
        40,
    );
    push_binary_insight(
        insights,
        "JSBridge Handler 名称候选",
        name,
        "review",
        "从 Mach-O、JS Bundle、HTML 或资源字符串提取 Bridge 名称候选；名称本身不能证明权限，但可用于运行时逐个验证来源和能力边界。",
        handler_names,
    );

    let bridge_calls = matching_symbols(
        text,
        &[
            "window.webkit.messageHandlers",
            "webkit.messageHandlers",
            ".postMessage(",
            "cordova.exec",
            "CapacitorNative",
            "window.webkit",
            "callNative",
            "invokeNative",
            "nativeCommand",
        ],
        24,
    );
    push_binary_insight(
        insights,
        "JSBridge 页面调用候选",
        name,
        "review",
        "发现页面侧向原生发送消息或动态调用的字符串。重点检查调用是否来自远程页面、消息参数是否可控，以及 native handler 是否做 allowlist 和业务授权。",
        bridge_calls,
    );

    let mut navigation = matching_symbols(
        text,
        &[
            "loadRequest:",
            "loadHTMLString:baseURL:",
            "loadFileURL:allowingReadAccessToURL:",
            "decidePolicyForNavigationAction:",
            "NSAppTransportSecurity",
            "NSAllowsArbitraryLoadsInWebContent",
            "NSExceptionDomains",
            "WKNavigationDelegate",
        ],
        24,
    );
    if navigation.is_empty() && (lower.contains("http://") || lower.contains("https://")) {
        navigation = vec!["远程 URL 字符串（需关联 WebView 加载点）".into()];
    }
    push_binary_insight(
        insights,
        "JSBridge 页面来源/导航候选",
        name,
        "review",
        "归纳 WebView 导航、文件读取和 ATS 相关线索。ATS 只约束传输，不等于 Bridge 来源校验；需建立远程/本地页面到 Handler 的可达性证据。",
        navigation,
    );

    let dynamic_eval = matching_symbols(
        text,
        &[
            "evaluateJavaScript:",
            "callAsyncJavaScript:",
            "JSContext",
            "JSExport",
            "stringByEvaluatingJavaScriptFromString:",
            "setObject:forKeyedSubscript:",
            "document.cookie",
            "innerHTML",
        ],
        24,
    );
    push_binary_insight(
        insights,
        "JavaScript 动态执行入口",
        name,
        "review",
        "发现原生执行 JavaScript 或向 JavaScriptCore 导出对象的入口；需要回溯脚本/参数是否由网络响应、深链或页面输入拼接。",
        dynamic_eval,
    );
}

fn analyze_binary_intelligence(
    archive: &mut ZipArchive<File>,
    files: &[String],
    coverage: &mut assessment::ScanCoverage,
) -> Vec<BinaryInsight> {
    let mut insights = Vec::new();
    let ios_protection_artifacts = files
        .iter()
        .filter(|name| {
            let lower = name.to_ascii_lowercase();
            lower.contains("jmcodeprotectkit.framework")
                || lower.contains("ipacodeprotecttwosdk_arm64_filter.json")
                || lower.contains("ipacodeprotecttwosdk_coderesources")
                || lower.contains("ipacodeprotecttwosdk_libs")
        })
        .take(24)
        .cloned()
        .collect();
    push_binary_insight(
        &mut insights,
        "iOS 第三方代码保护",
        "IPA archive",
        "review",
        "这些文件属于第三方代码保护/运行时恢复链路；cryptid=0 只能说明没有 Apple FairPlay 加密，不能据此排除函数重排、混淆、反调试或完整性校验。",
        ios_protection_artifacts,
    );
    let binary_candidates: Vec<&String> = files
        .iter()
        .filter(|name| {
            let lower = name.to_ascii_lowercase();
            is_deep_binary_candidate(name)
                || lower.ends_with(".dylib")
                || lower.ends_with(".jsbundle")
                || lower.ends_with(".js")
                || lower.ends_with(".html")
                || lower.ends_with(".htm")
                || lower.ends_with("index.android.bundle")
        })
        .collect();
    coverage.binary_candidates_total = binary_candidates.len();
    coverage.binary_candidates_selected = binary_candidates.len().min(96);
    for name in binary_candidates.into_iter().take(96) {
        let Ok(mut entry) = archive.by_name(name) else {
            coverage.unreadable_binary_candidates += 1;
            continue;
        };
        if entry.size() > MAX_DEEP_BINARY_BYTES {
            coverage.oversized_binary_candidates += 1;
            continue;
        }
        if entry.size() < 64 {
            continue;
        }
        let mut bytes = Vec::new();
        if entry.read_to_end(&mut bytes).is_err() {
            coverage.unreadable_binary_candidates += 1;
            continue;
        }
        coverage.binary_candidates_scanned += 1;
        let text = ascii_strings(&bytes, 4);
        let lower = text.to_ascii_lowercase();
        let file_lower = name.to_ascii_lowercase();

        analyze_framework_binary_rules(&mut insights, name, &file_lower, &lower, &text);
        analyze_framework_risk_signals(&mut insights, name, &file_lower, &lower, &text);
        analyze_jsbridge_text(&mut insights, name, &file_lower, &lower, &text);

        if name.contains(".app/") || name.contains(".framework/") || file_lower.ends_with(".dylib")
        {
            let classes = regex_samples(
                &text,
                r#"\b(?:AF|NS|UI|WK|CA|CL|MB|[A-Z][A-Za-z0-9_]{2,})(?:Manager|Controller|View|Delegate|Service|Client|Session|Request|Response|Policy|Handler)\b"#,
                24,
            );
            push_binary_insight(
                &mut insights,
                "Objective-C 类结构",
                name,
                "info",
                "从 Mach-O 的 Objective-C runtime 字符串恢复类名候选；效果类似轻量 class-dump 索引，可用于 Frida 按类名定位。",
                classes,
            );
            let selectors = regex_samples(
                &text,
                r#"\b(?:(?:set|is|has|should|can|did|will|load|open|send|request|validate|evaluate|authenticate|encrypt|decrypt)[A-Z][A-Za-z0-9_]{3,}|(?:[A-Za-z_][A-Za-z0-9_]*:){1,6})"#,
                40,
            );
            push_binary_insight(
                &mut insights,
                "Objective-C 方法/Selector",
                name,
                "info",
                "可见方法名与 Selector 候选，可直接作为 class-dump/Frida 动态确认的入口。",
                selectors,
            );
        }

        if file_lower.contains("afnetworking") || lower.contains("afsecuritypolicy") {
            let risky = matching_symbols(
                &text,
                &[
                    "allowInvalidCertificates",
                    "setAllowInvalidCertificates:",
                    "validatesDomainName",
                    "setValidatesDomainName:",
                    "AFSSLPinningModeNone",
                ],
                12,
            );
            push_binary_insight(
                &mut insights,
                "AFNetworking TLS 配置",
                name,
                "high",
                "发现允许无效证书、关闭域名校验或无 Pinning 的配置入口；静态出现不等于已启用，应在调用点/运行时确认属性值。",
                risky,
            );
            let normal = matching_symbols(
                &text,
                &[
                    "AFSecurityPolicy",
                    "AFHTTPSessionManager",
                    "AFURLSessionManager",
                    "pinnedCertificates",
                    "evaluateServerTrust:forDomain:",
                    "securityPolicy",
                    "baseURL",
                ],
                16,
            );
            push_binary_insight(
                &mut insights,
                "AFNetworking 网络入口",
                name,
                "review",
                "AFNetworking 的会话、BaseURL 与证书策略入口；建议关联下方 URL 和 Selector 检查实际配置。",
                normal,
            );
        }

        if file_lower.contains("libapp.so")
            || file_lower.contains("app.framework/app")
            || lower.contains("flutter")
        {
            let flutter = matching_symbols(
                &text,
                &[
                    "FlutterMethodChannel",
                    "MethodChannel",
                    "GeneratedPluginRegistrant",
                    "Dart_CObject",
                    "vm_snapshot_data",
                    "isolate_snapshot_data",
                    "kernel_blob.bin",
                    "flutter_assets",
                    "package:flutter",
                ],
                20,
            );
            push_binary_insight(
                &mut insights,
                "Flutter AOT/Channel",
                name,
                "review",
                "Flutter Release 的 Dart AOT 通常没有可直接恢复的函数名；这里提取 Snapshot、MethodChannel、插件注册与调试产物线索。",
                flutter,
            );
            let channels = regex_samples(
                &text,
                r#"\b(?:com\.[A-Za-z0-9_.-]+/[A-Za-z0-9_./-]+|plugins?\.[A-Za-z0-9_.-]{4,}|flutter/[A-Za-z0-9_./-]{3,})\b"#,
                24,
            );
            push_binary_insight(
                &mut insights,
                "Flutter MethodChannel 候选",
                name,
                "info",
                "可用于定位 Dart 与原生桥接面，重点检查敏感原生能力是否缺少参数和调用方校验。",
                channels,
            );
        }

        let webview = matching_symbols(
            &text,
            &[
                "addJavascriptInterface",
                "setJavaScriptEnabled",
                "setAllowFileAccess",
                "setAllowUniversalAccessFromFileURLs",
                "MIXED_CONTENT_ALWAYS_ALLOW",
                "WKWebView",
                "loadRequest:",
                "loadHTMLString:baseURL:",
                "decidePolicyForNavigationAction",
                "openURL:",
                "canOpenURL:",
            ],
            20,
        );
        push_binary_insight(
            &mut insights,
            "WebView / URL 跳转入口",
            name,
            "review",
            "发现 WebView、JavaScript Bridge 或外部 URL 打开入口；需确认 URL 白名单、Scheme/Host 校验和本地文件访问配置，防止任意跳转或 SSRF。",
            webview,
        );

        let tls = matching_symbols(
            &text,
            &[
                "CertificatePinner",
                "TrustManager",
                "HostnameVerifier",
                "proceed()",
                "ServerTrustManager",
                "DisabledTrustEvaluator",
                "URLSession:didReceiveChallenge:completionHandler:",
                "SecTrustEvaluate",
                "SecTrustEvaluateWithError",
                "kCFStreamSSLValidatesCertificateChain",
            ],
            20,
        );
        push_binary_insight(
            &mut insights,
            "TLS / Pinning 入口",
            name,
            "review",
            "发现证书信任或 Pinning 相关 API；检查是否存在无条件信任、空 HostnameVerifier、DisabledTrustEvaluator 或 challenge 直接放行。",
            tls,
        );

        let native_security = matching_symbols(
            &text,
            &[
                "DexClassLoader",
                "PathClassLoader",
                "System.loadLibrary",
                "dlopen",
                "SharedPreferences",
                "MODE_WORLD_READABLE",
                "MODE_WORLD_WRITEABLE",
                "android.security.KeyStore",
                "Cipher.getInstance",
                "AES/ECB",
                "DESede",
                "MessageDigest",
                "setWebContentsDebuggingEnabled",
                "android:debuggable",
                "ptrace",
                "sysctl",
                "jailbreak",
                "rooted",
            ],
            28,
        );
        push_binary_insight(
            &mut insights,
            "动态加载 / 存储 / 加密入口",
            name,
            "review",
            "归纳 DEX、SO 与 Mach-O 中的动态加载、弱加密、调试、敏感存储及 Root/越狱检测入口；需结合调用点确认是否构成实际风险。",
            native_security,
        );

        let urls = binary_endpoint_samples(&text, 32);
        push_binary_insight(
            &mut insights,
            "二进制 BaseURL / Endpoint",
            name,
            "review",
            "从 DEX/SO/Mach-O/JS Bundle 可打印字符串提取并过滤常见文档站后的 URL。",
            urls,
        );
    }
    insights.truncate(180);
    insights
}

#[tauri::command]
pub fn export_sensitive_value(request: ExportSensitiveValueRequest) -> Result<String, String> {
    report::export_sensitive_value(request)
}

#[tauri::command]
pub fn export_analysis_html(
    analysis: AppAnalysis,
    output_path: String,
    verdicts: Option<HashMap<String, String>>,
    notes: Option<String>,
) -> Result<String, String> {
    report::export_analysis_html(analysis, output_path, verdicts, notes)
}

#[tauri::command]
pub fn export_analysis_html_compact(
    analysis: AppAnalysis,
    output_path: String,
    verdicts: Option<HashMap<String, String>>,
    notes: Option<String>,
) -> Result<String, String> {
    report::export_analysis_html_compact(analysis, output_path, verdicts, notes)
}

fn severity_rank(value: &str) -> u8 {
    match value.to_ascii_lowercase().as_str() {
        "critical" => 0,
        "high" => 1,
        "review" | "medium" => 2,
        "info" | "low" => 3,
        _ => 4,
    }
}

fn sensitive_kind_rank(value: &str) -> u8 {
    match value {
        "private-key" | "secret" | "token" | "api-key" | "access-key" | "credential" => 0,
        "url" | "api-endpoint" => 1,
        "ip" | "email" | "phone" | "identity" => 2,
        "crypto" => 3,
        _ => 4,
    }
}

fn chrono_like_now() -> String {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or_default();
    format_epoch_utc(seconds)
}

fn epoch_utc_parts(seconds: u64) -> (i64, i64, i64, u64, u64, u64) {
    const SECONDS_PER_DAY: u64 = 86_400;
    let days = (seconds / SECONDS_PER_DAY) as i64;
    let day_seconds = seconds % SECONDS_PER_DAY;
    let hour = day_seconds / 3_600;
    let minute = (day_seconds % 3_600) / 60;
    let second = day_seconds % 60;

    // Civil date conversion from days since 1970-01-01 (Gregorian calendar).
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let mut year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let month_part = (5 * doy + 2) / 153;
    let day = doy - (153 * month_part + 2) / 5 + 1;
    let month = month_part + if month_part < 10 { 3 } else { -9 };
    year += if month <= 2 { 1 } else { 0 };

    (year, month, day, hour, minute, second)
}

/// Formats Unix seconds without adding a date/time dependency. Reports use
/// UTC explicitly so the same exported HTML remains unambiguous on every
/// machine; interactive UI timestamps are formatted in the user's locale.
fn format_epoch_utc(seconds: u64) -> String {
    let (year, month, day, hour, minute, second) = epoch_utc_parts(seconds);
    format!("{year:04}-{month:02}-{day:02} {hour:02}:{minute:02}:{second:02} UTC")
}

fn format_epoch_iso_utc(seconds: u64) -> String {
    let (year, month, day, hour, minute, second) = epoch_utc_parts(seconds);
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

fn format_epoch_millis_filename_utc(milliseconds: u128) -> String {
    let seconds = u64::try_from(milliseconds / 1_000).unwrap_or(u64::MAX);
    let millis = milliseconds % 1_000;
    let (year, month, day, hour, minute, second) = epoch_utc_parts(seconds);
    format!("{year:04}-{month:02}-{day:02}_{hour:02}-{minute:02}-{second:02}-{millis:03}_UTC")
}

fn format_bytes(bytes: u64) -> String {
    if bytes >= 1024 * 1024 {
        format!("{:.2} MB", bytes as f64 / (1024.0 * 1024.0))
    } else if bytes >= 1024 {
        format!("{:.2} KB", bytes as f64 / 1024.0)
    } else {
        format!("{bytes} B")
    }
}

fn assess_protection(files: &[String], rule_set: &rules::RuleSet) -> ProtectionAssessment {
    let lower: Vec<String> = files.iter().map(|file| file.to_ascii_lowercase()).collect();
    let haystack = lower.join("\n");
    let matched_rules: Vec<&rules::SignalRule> = rule_set
        .protection
        .iter()
        .filter(|rule| rule.scope.as_deref().unwrap_or("archive") == "archive")
        .filter(|rule| rules::contains_any(&haystack, &rule.trigger_signals, false))
        .collect();
    let packers: Vec<String> = matched_rules
        .iter()
        .map(|rule| rule.label.clone())
        .collect();
    let mut indicators: Vec<String> = matched_rules
        .iter()
        .filter_map(|rule| rule.indicator.clone())
        .collect();
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

fn enrich_protection_from_manifest(
    manifest: &str,
    protection: &mut ProtectionAssessment,
    rule_set: &rules::RuleSet,
) {
    for rule in rule_set
        .protection
        .iter()
        .filter(|rule| rule.scope.as_deref() == Some("manifest"))
    {
        if rules::contains_any(manifest, &rule.trigger_signals, false)
            && !protection.packers.iter().any(|value| value == &rule.label)
        {
            protection.packers.push(rule.label.clone());
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

fn collect_sensitive_items(
    archive: &mut ZipArchive<File>,
    files: &[String],
    rule_set: &rules::RuleSet,
) -> Vec<SensitiveItem> {
    let mut items = Vec::new();
    for name in files {
        if let Some((kind, severity)) = classify_sensitive_name(name) {
            items.push(SensitiveItem {
                item: kind.into(),
                location: name.clone(),
                kind: "archive-entry".into(),
                severity: severity.into(),
                value: Some(format!("文件路径规则命中：{kind}")),
                line_number: None,
                context: Some(
                    "这是文件路径线索，不代表文件内容已确认包含凭据；请结合文件内容人工复核。"
                        .into(),
                ),
                source: "archive-entry".into(),
                filtered: false,
                filter_reason: None,
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
                        extracted_binary_strings(&bytes, 5)
                    } else {
                        String::from_utf8_lossy(&bytes).into_owned()
                    };
                    let source = if name.ends_with(".so")
                        || name.ends_with(".dex")
                        || ios_macho_candidate(name)
                    {
                        "binary-strings"
                    } else {
                        "text-resource"
                    };
                    scan_sensitive_text_with_rules(&text, name, &mut items, rule_set, source);
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
    // The next XML chunk starts after the complete string-pool chunk. Style
    // offsets/data are part of that chunk and must never be treated as XML.
    let _ = style_count;
    Some((strings, chunk_size))
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
                let declared_name = strings
                    .get(name_index)
                    .filter(|value| !value.is_empty())
                    .cloned();
                // Pop exactly once. The old fallback popped here and again
                // below, corrupting the nesting stack after one bad name index.
                let opened_name = open.pop();
                let name = declared_name
                    .or(opened_name)
                    .unwrap_or_else(|| "node".into());
                xml.push_str(&format!("{}</{}>\n", "  ".repeat(depth), name));
            }
            _ => {}
        }
        cursor += chunk_size;
    }
    (xml.lines().count() > 1).then_some(xml)
}

fn inspect_network_security_config(xml: &str, location: &str, analysis: &mut AppAnalysis) {
    analysis
        .manifest_flags
        .push(format!("networkSecurityConfig parsed: {location}"));
    let lower = xml.to_ascii_lowercase();
    if lower.contains("cleartexttrafficpermitted=\"true\"")
        || lower.contains("cleartexttrafficpermitted='true'")
    {
        analysis.findings.push(AppFinding {
            severity: "high".into(),
            title: "Network Security Config 允许明文流量".into(),
            detail: format!("{location} 设置 cleartextTrafficPermitted=true"),
        });
    }
    if (lower.contains("src=\"user\"") || lower.contains("src='user'"))
        && !lower.contains("<debug-overrides")
    {
        analysis.findings.push(AppFinding {
            severity: "review".into(),
            title: "发布网络配置可能信任用户 CA".into(),
            detail: format!("{location} 的 trust-anchors 包含 src=user；确认是否仅用于调试构建。"),
        });
    }
    if lower.contains("overridepins=\"true\"") || lower.contains("overridepins='true'") {
        analysis.findings.push(AppFinding {
            severity: "review".into(),
            title: "Network Security Config 允许 CA 绕过 Pinning".into(),
            detail: format!("{location} 存在 overridePins=true，需要核对适用域名与构建变体。"),
        });
    }
    if lower.contains("<debug-overrides") {
        analysis
            .manifest_flags
            .push(format!("debug-overrides present: {location}"));
    }
}

async fn decode_android_manifest(
    path: &str,
    _apktool_path: Option<&str>,
    _jadx_path: Option<&str>,
) -> Option<String> {
    // Prefer an installed AXMLPrinter-compatible decoder for binary XML.
    let manifest_path =
        std::env::temp_dir().join(format!("mobilee-{}-AndroidManifest.xml", now_millis()));
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
    None
}

fn ios_framework_executable(name: &str) -> bool {
    let path = Path::new(name);
    let Some(file_name) = path.file_name().and_then(|value| value.to_str()) else {
        return false;
    };
    let Some(parent) = path.parent() else {
        return false;
    };
    let Some(parent_name) = parent.file_name().and_then(|value| value.to_str()) else {
        return false;
    };
    parent_name.ends_with(".framework")
        && Path::new(parent_name)
            .file_stem()
            .and_then(|value| value.to_str())
            == Some(file_name)
}

fn ios_main_executable(name: &str) -> bool {
    let path = Path::new(name);
    let Some(file_name) = path.file_name().and_then(|value| value.to_str()) else {
        return false;
    };
    let Some(parent) = path.parent() else {
        return false;
    };
    let Some(parent_name) = parent.file_name().and_then(|value| value.to_str()) else {
        return false;
    };
    parent_name.ends_with(".app")
        && Path::new(parent_name)
            .file_stem()
            .and_then(|value| value.to_str())
            == Some(file_name)
        && parent
            .parent()
            .and_then(|value| value.file_name())
            .is_some_and(|value| value == "Payload")
}

fn ios_macho_candidate(name: &str) -> bool {
    name.starts_with("Payload/")
        && !name.ends_with('/')
        && (ios_main_executable(name)
            || ios_framework_executable(name)
            || name.to_ascii_lowercase().ends_with(".dylib"))
}

#[tauri::command]
pub async fn analyze_app(request: AnalyzeAppRequest) -> Result<AppAnalysis, String> {
    // Reload on every analysis so edited JSON rules take effect without restarting
    // or recompiling the application.
    let rule_set = rules::load_rules(None)?;
    let path = request.path;
    let apktool_path = request
        .apktool_path
        .filter(|value| !value.trim().is_empty())
        .or_else(|| executable_path("apktool"));
    let jadx_path = request
        .jadx_path
        .filter(|value| !value.trim().is_empty())
        .or_else(|| executable_path("jadx"))
        .or_else(|| executable_path("jadx-cli"));
    let excluded_url_patterns = request.excluded_url_patterns;
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
    let artifact_sha256 = sha256_file(file)?;
    let mut archive = ZipArchive::new(File::open(file).map_err(|error| error.to_string())?)
        .map_err(|error| format!("文件不是有效的 APK/IPA：{error}"))?;
    let archive_entries_total = archive.len();
    const ARCHIVE_ENTRY_INDEX_LIMIT: usize = 50_000;
    let files: Vec<String> = (0..archive_entries_total)
        .filter_map(|index| {
            archive
                .by_index(index)
                .ok()
                .map(|entry| entry.name().to_string())
        })
        .take(ARCHIVE_ENTRY_INDEX_LIMIT)
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
        artifact_sha256,
        package_id: None,
        display_name: None,
        version_name: None,
        version_code: None,
        min_sdk: None,
        target_sdk: None,
        architectures: Vec::new(),
        frameworks: detect_frameworks(&files),
        third_party_libraries: Vec::new(),
        protection: assess_protection(&files, &rule_set),
        anti_instrumentation: AntiInstrumentationAssessment::default(),
        permissions: Vec::new(),
        components: Vec::new(),
        exported_components: Vec::new(),
        intent_filters: Vec::new(),
        manifest_flags: Vec::new(),
        files: files.clone(),
        manifest_xml: None,
        sensitive_items: Vec::new(),
        raw_inventory: Vec::new(),
        binary_insights: Vec::new(),
        code_insights: Vec::new(),
        data_boundaries: Vec::new(),
        scan_coverage: assessment::ScanCoverage {
            archive_entries_total,
            archive_entries_indexed: files.len(),
            ..Default::default()
        },
        masvs_observations: Vec::new(),
        verification_recipes: Vec::new(),
        signature: None,
        findings: Vec::new(),
        tools_used: vec!["Rust ZIP/DEX/Mach-O scanner".into()],
        missing_dependencies: Vec::new(),
    };
    analysis.third_party_libraries = detect_third_party_libraries(&mut archive, &files, &rule_set);
    analysis.anti_instrumentation = anti_instrumentation::assess(&mut archive, &files, &rule_set);
    analysis.sensitive_items = collect_sensitive_items(&mut archive, &files, &rule_set);
    analysis.binary_insights =
        analyze_binary_intelligence(&mut archive, &files, &mut analysis.scan_coverage);
    if !analysis.binary_insights.is_empty() {
        analysis
            .tools_used
            .push("内置 Rust binary strings / ObjC symbol scanner".into());
    }
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
            enrich_protection_from_manifest(&manifest, &mut analysis.protection, &rule_set);
            analysis.tools_used.push("内置 Rust AXML decoder".into());
        }
        let referenced_network_config = analysis.manifest_xml.as_deref().and_then(|manifest| {
            parse_quoted_value(manifest, "android:networkSecurityConfig=")
                .and_then(|value| value.strip_prefix("@xml/").map(str::to_string))
                .map(|name| format!("res/xml/{name}.xml"))
        });
        let network_configs = files
            .iter()
            .filter(|name| {
                referenced_network_config.as_deref() == Some(name.as_str())
                    || (name.starts_with("res/xml/")
                        && name.ends_with(".xml")
                        && name.to_ascii_lowercase().contains("network_security"))
            })
            .take(8)
            .cloned()
            .collect::<Vec<_>>();
        for name in network_configs {
            let Ok(mut entry) = archive.by_name(&name) else {
                continue;
            };
            if entry.size() > 2 * 1024 * 1024 {
                continue;
            }
            let mut config_bytes = Vec::new();
            if entry.read_to_end(&mut config_bytes).is_err() {
                continue;
            }
            let xml = if config_bytes.starts_with(b"<") {
                Some(String::from_utf8_lossy(&config_bytes).into_owned())
            } else {
                decode_axml(&config_bytes)
            };
            if let Some(xml) = xml {
                inspect_network_security_config(&xml, &name, &mut analysis);
                analysis
                    .tools_used
                    .push("内置 Network Security Config parser".into());
            }
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
                .push("未找到 apksigner（Android SDK build-tools）：可在全局设置的“主机工具目录”中配置 build-tools 目录，或安装 Android SDK build-tools 后重新分析；当前暂不能验证 V1/V2/V3 签名与证书摘要".into());
        }
        for (configured, kind, label) in [
            (apktool_path.as_deref(), "apktool", "Apktool"),
            (jadx_path.as_deref(), "jadx", "JADX"),
        ] {
            let Some(tool) = configured.filter(|value| !value.trim().is_empty()) else {
                if kind == "jadx" {
                    analysis.missing_dependencies.push(
                        "未配置且 PATH 中未找到 JADX：敏感信息上下文来自 DEX 可见字符串，不是完整 Java/Kotlin 源码".into(),
                    );
                }
                continue;
            };
            let cli = match resolve_static_cli_path(Path::new(tool), kind) {
                Ok(cli) => cli,
                Err(error) => {
                    analysis
                        .missing_dependencies
                        .push(format!("{label} 配置无效：{error}（当前值：{tool}）"));
                    continue;
                }
            };
            if !cli.is_file() {
                analysis
                    .missing_dependencies
                    .push(format!("{label} CLI 路径不存在：{}", cli.display()));
                continue;
            }
            match run_configured_static_tool(&path, cli.to_string_lossy().as_ref(), kind).await {
                Ok(result) => {
                    let StaticToolAnalysis {
                        sensitive_items,
                        code_insights,
                        manifest_xml,
                    } = result;
                    analysis.sensitive_items.extend(sensitive_items);
                    analysis.code_insights.extend(code_insights);
                    if analysis.manifest_xml.is_none() {
                        if let Some(manifest) = manifest_xml {
                            parse_decoded_manifest(&manifest, &mut analysis);
                            enrich_protection_from_manifest(
                                &manifest,
                                &mut analysis.protection,
                                &rule_set,
                            );
                            analysis.manifest_xml = Some(manifest);
                        }
                    }
                    analysis
                        .tools_used
                        .push(format!("{label} background CLI source extraction"));
                    if kind == "jadx" {
                        analysis
                            .tools_used
                            .push("JADX source/class/method scanner".into());
                    }
                }
                Err(error) => analysis
                    .missing_dependencies
                    .push(format!("{label} 执行失败：{error}")),
            }
        }
        if analysis.manifest_xml.is_none() {
            analysis.missing_dependencies.push(
                "Manifest 解析失败：内置 AXML、aapt、apkanalyzer 及已配置的后台 Apktool/JADX 均未得到可读 XML"
                    .into(),
            );
        }
    } else if let Some(plist) = files
        .iter()
        .find(|name| name.starts_with("Payload/") && name.ends_with(".app/Info.plist"))
    {
        let mut bytes = Vec::new();
        if let Ok(mut entry) = archive.by_name(plist) {
            let _ = entry.read_to_end(&mut bytes);
        }
        let temp = std::env::temp_dir().join(format!("mobilee-{}.plist", now_millis()));
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
                    let lower_line = line.to_ascii_lowercase();
                    let plist_bool_true = lower_line.contains("true")
                        || lower_line.contains("yes")
                        || lower_line.contains("=> 1")
                        || lower_line.ends_with(" 1");
                    if line.contains("NSAllowsArbitraryLoadsInWebContent") && plist_bool_true {
                        analysis.findings.push(AppFinding {
                            severity: "high".into(),
                            title: "iOS ATS 对 Web 内容允许任意明文传输".into(),
                            detail: line.trim().to_string(),
                        });
                    } else if line.contains("NSAllowsArbitraryLoads") && plist_bool_true {
                        analysis.findings.push(AppFinding {
                            severity: "high".into(),
                            title: "iOS ATS 允许任意明文传输".into(),
                            detail: line.trim().to_string(),
                        });
                    } else if line.contains("NSAllowsLocalNetworking") && plist_bool_true {
                        analysis.findings.push(AppFinding {
                            severity: "review".into(),
                            title: "iOS ATS 允许本地网络明文".into(),
                            detail: line.trim().to_string(),
                        });
                    }
                }
            } else {
                analysis
                    .missing_dependencies
                    .push("未找到 plutil：二进制 Info.plist 只能做文件/字符串扫描".into());
            }
            if let Ok(json_output) = run_host(
                "plutil",
                &[
                    "-convert".into(),
                    "json".into(),
                    "-o".into(),
                    "-".into(),
                    temp.to_string_lossy().into_owned(),
                ],
            )
            .await
            {
                if json_output.code == Some(0) {
                    if let Ok(plist_json) =
                        serde_json::from_str::<serde_json::Value>(&json_output.stdout)
                    {
                        if let Some(object) = plist_json.as_object() {
                            for (key, value) in object {
                                if key.ends_with("UsageDescription") {
                                    let description = value.as_str().unwrap_or("未提供说明");
                                    analysis.permissions.push(format!("{key}: {description}"));
                                }
                            }
                            if let Some(types) = object
                                .get("CFBundleURLTypes")
                                .and_then(serde_json::Value::as_array)
                            {
                                for item in types {
                                    if let Some(schemes) = item
                                        .get("CFBundleURLSchemes")
                                        .and_then(serde_json::Value::as_array)
                                    {
                                        for scheme in schemes.iter().filter_map(|v| v.as_str()) {
                                            analysis
                                                .intent_filters
                                                .push(format!("URL Scheme: {scheme}://"));
                                        }
                                    }
                                }
                            }
                            if let Some(modes) = object
                                .get("UIBackgroundModes")
                                .and_then(serde_json::Value::as_array)
                            {
                                let modes = modes
                                    .iter()
                                    .filter_map(|value| value.as_str())
                                    .collect::<Vec<_>>();
                                if !modes.is_empty() {
                                    analysis
                                        .manifest_flags
                                        .push(format!("UIBackgroundModes={}", modes.join(",")));
                                }
                            }
                            for key in ["UIFileSharingEnabled", "LSSupportsOpeningDocumentsInPlace"]
                            {
                                if object.get(key).and_then(serde_json::Value::as_bool)
                                    == Some(true)
                                {
                                    analysis.manifest_flags.push(format!("{key}=true"));
                                    analysis.findings.push(AppFinding {
                                        severity: "review".into(),
                                        title: format!("iOS {key} 已开启"),
                                        detail: "应用文档可能通过 Finder/iTunes 或系统文档入口暴露，请确认敏感文件不位于共享容器。".into(),
                                    });
                                }
                            }
                        }
                        analysis
                            .tools_used
                            .push("plutil JSON metadata parser".into());
                    }
                }
            }
            let _ = fs::remove_file(temp);
        }
        let mut encrypted = None;
        let mut main_binary: Option<(String, Vec<u8>)> = None;
        let mut framework_code_binaries: Vec<(String, Vec<u8>)> = Vec::new();
        // Read Mach-O headers from the app executable and embedded framework executables.
        // The old path only kept the first 2 MiB of frameworks, which is enough for a magic
        // number but not enough for Objective-C metadata, symbols, or disassembly.
        let mut macho_candidates: Vec<&String> = files
            .iter()
            .filter(|name| ios_macho_candidate(name))
            .collect();
        macho_candidates.sort_by_key(|name| {
            let lower = name.to_ascii_lowercase();
            if ios_main_executable(name) {
                0
            } else if lower.contains("afnetworking.framework/afnetworking") {
                1
            } else if lower.contains("jmcodeprotectkit.framework/jmcodeprotectkit") {
                2
            } else if lower.contains(".framework/") {
                3
            } else {
                4
            }
        });
        for name in macho_candidates.into_iter().take(64) {
            if let Ok(mut entry) = archive.by_name(name) {
                if entry.size() <= 64 * 1024 * 1024 {
                    let mut binary = Vec::new();
                    let is_main = ios_main_executable(name);
                    let is_framework = ios_framework_executable(name);
                    if is_main || is_framework {
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
                        } else if is_framework
                            && framework_code_binaries.len() < 12
                            && binary.len() <= 32 * 1024 * 1024
                        {
                            framework_code_binaries.push((name.clone(), binary));
                        }
                    }
                }
            }
        }
        if let Some(filter_name) = files.iter().find(|name| {
            name.to_ascii_lowercase()
                .ends_with("ipacodeprotecttwosdk_arm64_filter.json")
        }) {
            let module_name = main_binary
                .as_ref()
                .and_then(|(name, _)| Path::new(name).file_name().and_then(|value| value.to_str()));
            if let Ok(mut entry) = archive.by_name(filter_name) {
                let mut filter_bytes = Vec::new();
                if entry.read_to_end(&mut filter_bytes).is_ok() {
                    let mappings =
                        parse_ios_codeprotect_filter(&filter_bytes, filter_name, module_name);
                    if !mappings.is_empty() {
                        let group_a = mappings
                            .iter()
                            .filter(|item| item.name.starts_with("a["))
                            .count();
                        let group_b = mappings.len().saturating_sub(group_a);
                        analysis.protection.indicators.push(format!(
                            "已解析 JMCodeProtect filter 映射：a={group_a} 条，b={group_b} 条；已输出 module offset 与 Frida 地址表达式供静态/运行时对照。"
                        ));
                        analysis.code_insights.extend(mappings);
                        analysis
                            .tools_used
                            .push("JMCodeProtect filter mapping parser".into());
                    }
                }
            }
        }
        if let Some((name, bytes)) = main_binary {
            let executable = std::env::temp_dir().join(format!("mobilee-{}-ios-bin", now_millis()));
            if fs::write(&executable, bytes).is_ok() {
                match analyze_ios_macho_code(&executable, &name).await {
                    Ok(items) => {
                        analysis.code_insights.extend(items);
                        analysis.tools_used.push(
                            "otool Objective-C metadata + IMP disassembly + nm symbols".into(),
                        );
                    }
                    Err(error) => analysis.missing_dependencies.push(format!(
                        "Objective-C 类/方法/反汇编提取失败（需要 macOS otool/nm）：{error}"
                    )),
                }
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
        for (name, bytes) in framework_code_binaries {
            let safe_name = name.replace('/', "-").replace('\\', "-").replace('.', "-");
            let executable = std::env::temp_dir().join(format!(
                "mobilee-{}-ios-framework-{safe_name}",
                now_millis()
            ));
            if fs::write(&executable, bytes).is_ok() {
                match analyze_ios_macho_code(&executable, &name).await {
                    Ok(items) => {
                        if !items.is_empty() {
                            analysis.code_insights.extend(items);
                            analysis.tools_used.push(format!(
                                "otool Objective-C metadata + IMP disassembly + nm symbols ({name})"
                            ));
                        }
                    }
                    Err(error) => analysis.missing_dependencies.push(format!(
                        "Framework {name} 的 Objective-C 类/方法/反汇编提取失败：{error}"
                    )),
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
                analysis.protection.status = if analysis.protection.packers.is_empty() {
                    "Apple FairPlay 已加密（cryptid=1），需要先砸壳再做完整静态分析".into()
                } else {
                    "Apple FairPlay 已加密（cryptid=1），并命中第三方代码保护线索".into()
                };
                analysis.protection.indicators.push(
                    "cryptid=1 表示主程序仍受 Apple FairPlay 加密；当前静态结果主要来自资源与可读框架。"
                        .into(),
                );
            }
            Some(false) => {
                analysis.protection.status = if analysis.protection.packers.is_empty() {
                    "Apple FairPlay 未加密/已砸壳（cryptid=0）".into()
                } else {
                    "Apple FairPlay 未加密（cryptid=0）；但命中第三方代码保护线索".into()
                };
                if !analysis.protection.packers.is_empty() {
                    analysis.findings.push(AppFinding {
                        severity: "review".into(),
                        title: "cryptid=0 不代表未做第三方加固".into(),
                        detail: "无需再做 Apple FairPlay 砸壳，但 JMCodeProtect/CodeProtect 一类 SDK 仍可能做函数重排、混淆、完整性校验、反调试或运行时恢复；应继续做类/Selector、调用点和运行时网络验证。".into(),
                    });
                }
            }
            None => {
                analysis.protection.status = if analysis.protection.packers.is_empty() {
                    "未定位到可解析的 Mach-O 主程序".into()
                } else {
                    "未读到 Mach-O cryptid；但命中第三方代码保护线索".into()
                };
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
    for item in &mut analysis.sensitive_items {
        if item.kind == "url"
            && item
                .value
                .as_deref()
                .is_some_and(|value| url_matches_exclusion(value, &excluded_url_patterns))
        {
            item.filtered = true;
            item.filter_reason = Some("命中设置中的 URL 排除规则".into());
        }
    }
    for insight in &mut analysis.binary_insights {
        insight.evidence.retain(|value| {
            (!value.contains("://") || !url_matches_exclusion(value, &excluded_url_patterns))
                && !low_signal_binary_evidence(value)
        });
    }
    for insight in &mut analysis.code_insights {
        insight.references.retain(|value| {
            (!value.contains("://") || !url_matches_exclusion(value, &excluded_url_patterns))
                && !low_signal_binary_evidence(value)
        });
    }
    analysis
        .binary_insights
        .retain(|insight| !insight.evidence.is_empty());
    analysis.sensitive_items.sort_by(|left, right| {
        severity_rank(&left.severity)
            .cmp(&severity_rank(&right.severity))
            .then(sensitive_kind_rank(&left.kind).cmp(&sensitive_kind_rank(&right.kind)))
            .then(left.location.cmp(&right.location))
            .then(left.item.cmp(&right.item))
    });
    analysis.code_insights.sort_by(|left, right| {
        code_insight_focus_score(right)
            .cmp(&code_insight_focus_score(left))
            .then(left.kind.cmp(&right.kind))
            .then(left.class_name.cmp(&right.class_name))
            .then(left.name.cmp(&right.name))
    });
    analysis.code_insights.dedup_by(|left, right| {
        left.platform == right.platform
            && left.kind == right.kind
            && left.binary == right.binary
            && left.class_name == right.class_name
            && left.name == right.name
            && left.address == right.address
            && left.source_file == right.source_file
            && left.line_number == right.line_number
    });
    analysis.scan_coverage.code_insights_discovered = analysis.code_insights.len();
    analysis.scan_coverage.sensitive_items_discovered = analysis.sensitive_items.len();
    analysis.code_insights.truncate(12_000);
    analysis.sensitive_items.truncate(500);
    analysis.scan_coverage.code_insights_returned = analysis.code_insights.len();
    analysis.scan_coverage.sensitive_items_returned = analysis.sensitive_items.len();
    analysis.data_boundaries = boundaries::derive_data_boundaries(&analysis);
    analysis.raw_inventory = collect_raw_inventory(&analysis, &rule_set);
    analysis.masvs_observations = assessment::derive_masvs_observations(&analysis);
    analysis.verification_recipes =
        assessment::derive_verification_recipes(&analysis.platform, &analysis.masvs_observations);
    analysis.scan_coverage.finalize();
    analysis.tools_used.sort();
    analysis.tools_used.dedup();
    analysis.missing_dependencies.sort();
    analysis.missing_dependencies.dedup();
    Ok(analysis)
}

#[cfg(test)]
#[path = "advanced/tests.rs"]
mod analyzer_tests;
