use super::super::{
    cohesive_frida_executable_path, now_millis, output_text, run_adb, run_device_root_script,
    run_host_with_timeout, AdvancedCommandResult, FridaProcess, FridaScriptEntry,
    FridaScriptRequest, RawOutput,
};
use super::server::hardened_port;
use regex::Regex;
use sha2::{Digest, Sha256};
use std::{
    collections::HashSet,
    fs,
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};
use tokio::{io::AsyncReadExt, process::Command, time::timeout};

pub(in crate::advanced) fn frida_target(serial: &Option<String>) -> Vec<String> {
    serial
        .as_deref()
        .filter(|value| !value.is_empty())
        .map(|value| vec!["-D".into(), value.into()])
        .unwrap_or_else(|| vec!["-U".into()])
}

pub(in crate::advanced) async fn resolve_target(serial: &Option<String>) -> (Vec<String>, String) {
    let Some(serial) = serial.as_deref().filter(|value| !value.trim().is_empty()) else {
        return (frida_target(serial), "USB".into());
    };
    let Some(port) = hardened_port(serial).await else {
        return (frida_target(&Some(serial.into())), "USB/serial".into());
    };
    let forward = run_adb(&[
        "-s".into(),
        serial.into(),
        "forward".into(),
        "--list".into(),
    ])
    .await;
    let marker = format!("{serial} tcp:{port} tcp:{port}");
    let forwarded = forward
        .as_ref()
        .is_ok_and(|output| output.code == Some(0) && output_text(output).contains(&marker));
    if forwarded {
        let process = run_device_root_script(
            serial,
            "test -n \"$(pidof myfs 2>/dev/null)\" && echo active",
        )
        .await;
        if process
            .as_ref()
            .is_ok_and(|output| output.code == Some(0) && output.stdout.contains("active"))
        {
            return (
                vec!["-H".into(), format!("127.0.0.1:{port}")],
                format!("myfs:{port}"),
            );
        }
    }
    (frida_target(&Some(serial.into())), "USB/serial".into())
}

pub(in crate::advanced) async fn list_frida_processes(
    serial: Option<String>,
) -> Result<Vec<FridaProcess>, String> {
    // iOS 设备的 usbmuxd UDID 与 Frida 内部设备 id 偶尔不一致，
    // 导致 `frida-ps -D <serial>` 枚举不到进程（终端 `frida-ps -Uai` 却正常）。
    // 这里先按 serial 尝试，失败或超时自动回退 `-U`（USB 唯一设备）。
    let mut candidates = Vec::<Vec<String>>::new();
    if let Some(value) = serial.as_deref().filter(|value| !value.trim().is_empty()) {
        candidates.push(resolve_target(&Some(value.into())).await.0);
        candidates.push(frida_target(&Some(value.into())));
    }
    candidates.push(frida_target(&None));
    let mut seen = HashSet::new();
    candidates.retain(|args| seen.insert(args.join("\u{0}")));
    let mut last_error: Option<String> = None;
    for mut args in candidates {
        args.push("-ai".into());
        match run_host_with_timeout("frida-ps", &args, Duration::from_secs(30)).await {
            Ok(output) if output.code == Some(0) => {
                let parsed = parse_frida_ps(&output.stdout);
                if !parsed.is_empty() {
                    return Ok(parsed);
                }
                last_error = Some(
                    "frida-ps 返回空列表：请确认设备已解锁、frida-server 已运行且端口未被占用"
                        .into(),
                );
            }
            Ok(output) => last_error = Some(output_text(&output)),
            Err(error) => last_error = Some(error),
        }
    }
    Err(last_error.unwrap_or_else(|| "未找到可用的 Frida 设备".into()))
}

fn parse_frida_ps(stdout: &str) -> Vec<FridaProcess> {
    let Ok(column_separator) = Regex::new(r"\s{2,}") else {
        return Vec::new();
    };
    let mut processes = Vec::new();
    for line in stdout.lines() {
        let fields = column_separator
            .split(line.trim())
            .filter(|value| !value.is_empty())
            .collect::<Vec<_>>();
        let separator_row = fields
            .iter()
            .all(|field| !field.is_empty() && field.chars().all(|character| character == '-'));
        if fields.len() < 3 || fields[0].eq_ignore_ascii_case("pid") || separator_row {
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
    processes
}

fn looks_like_application_identifier(value: &str) -> bool {
    value.contains('.')
        && !value.chars().any(char::is_whitespace)
        && value.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '.' | '-' | '_')
        })
}

fn select_live_attach_pid(
    process: &str,
    requested_pid: Option<u32>,
    listing: Result<Vec<FridaProcess>, String>,
) -> Result<u32, String> {
    match listing {
        Ok(items) => items
            .into_iter()
            .find(|item| item.identifier.eq_ignore_ascii_case(process))
            .and_then(|item| item.pid)
            .ok_or_else(|| {
                format!(
                    "目标 {process} 当前没有运行中的实时 PID；已拒绝复用旧 PID {}。请先在手机上打开 App 并刷新进程，或切换 Spawn（冷启动）。",
                    requested_pid
                        .filter(|pid| *pid > 0)
                        .map_or_else(|| "—".into(), |pid| pid.to_string())
                )
            }),
        Err(error) => requested_pid.filter(|pid| *pid > 0).ok_or_else(|| {
            format!("无法刷新 {process} 的实时 PID：{error}；请重新扫描进程或改用 Spawn")
        }),
    }
}

fn is_ios_injection_probe(platform: Option<&str>, script_path: Option<&str>, script: &str) -> bool {
    platform.is_some_and(|value| value.eq_ignore_ascii_case("ios"))
        && (script_path.is_some_and(|path| {
            path.rsplit(['/', '\\'])
                .next()
                .is_some_and(|name| name.eq_ignore_ascii_case("ios_injection_probe.js"))
        }) || script.contains("ME_IOS_INJECTION_OK"))
}

fn should_retry_ios_probe_with_spawn(output: &str) -> bool {
    if output.contains("ME_IOS_INJECTION_OK") {
        return false;
    }
    let lower = output.to_ascii_lowercase();
    [
        "unable to find process with pid",
        "unable to find process with identifier",
        "refused to load frida-agent",
        "terminated during injection",
        "unexpected early end-of-stream",
        "unexpected error while probing dyld",
        "unexpected error while resuming process",
        "timeout was reached",
    ]
    .iter()
    .any(|marker| lower.contains(marker))
}

#[cfg_attr(not(test), allow(dead_code))]
pub(in crate::advanced) fn frida_script_args(
    serial: &Option<String>,
    mode: &str,
    process: &str,
    pid: Option<u32>,
    script_path: &Path,
    duration_seconds: u64,
) -> Result<Vec<String>, String> {
    frida_script_args_with_target(
        frida_target(serial),
        mode,
        process,
        pid,
        script_path,
        duration_seconds,
    )
}

fn frida_script_args_with_target(
    mut args: Vec<String>,
    mode: &str,
    process: &str,
    pid: Option<u32>,
    script_path: &Path,
    duration_seconds: u64,
) -> Result<Vec<String>, String> {
    if mode == "spawn" {
        // Current Frida resumes spawned applications by default. `--no-pause`
        // belonged to older frida-tools releases and is rejected by Frida 17.
        args.extend(["-f".into(), process.into()]);
    } else if let Some(pid) = pid.filter(|value| *value > 0) {
        // The caller refreshes this PID immediately before building the
        // command. On iOS this avoids a second identifier lookup inside Frida,
        // which can stall while FBS/dyld state is changing.
        args.extend(["-p".into(), pid.to_string()]);
    } else if looks_like_application_identifier(process) {
        args.extend(["-N".into(), process.into()]);
    } else {
        return Err(format!(
            "{process} 当前没有运行中的 PID，Attach 只能连接已运行进程；请先启动 App 并刷新进程"
        ));
    }
    args.extend([
        "-l".into(),
        script_path.to_string_lossy().into_owned(),
        "-q".into(),
        "-t".into(),
        duration_seconds.to_string(),
    ]);
    Ok(args)
}

fn frida_runtime_diagnostic(message: &str, mode: &str, process: &str) -> Option<String> {
    let lower = message.to_ascii_lowercase();
    let detail = if lower.contains("could not be, unlocked")
        || lower.contains("device was not") && lower.contains("unlocked")
    {
        "iPhone 当前处于锁屏或尚未完成首次解锁，iOS 拒绝 FBS 启动 App。请解锁手机、保持屏幕常亮并回到目标 App，再重新运行；这不是脚本或兼容策略问题。".into()
    } else if lower.contains("unable to find process with pid")
        || lower.contains("unable to find process with identifier")
    {
        format!(
            "目标 {process} 在 Attach 前已经退出或重启。请在手机上重新打开 App、保持前台，然后刷新进程再运行；新版本会使用 Bundle ID 实时解析 PID。"
        )
    } else if lower.contains("refused to load frida-agent")
        || lower.contains("terminated during injection")
    {
        "目标在 frida-agent 装载完成前拒绝注入或被终止；此时用户 JavaScript 尚未开始执行，所以脚本内 Hook 无法拦截这次检测。请先运行“iOS 注入通道探针（零 Hook）”：若 Reqable 等普通 App 能输出 ME_IOS_INJECTION_OK、只有目标失败，说明是目标保护的预脚本注入检测；可尝试 Spawn + compat，仍失败则使用经授权的 Frida Gadget/未加固开发构建。".into()
    } else if lower.contains("unexpected early end-of-stream") {
        "Frida 通道在用户脚本执行前被提前断开。先对 Reqable 等普通 App 运行“iOS 注入通道探针（零 Hook）”：若出现 ME_IOS_INJECTION_OK，说明设备与 Frida 基线正常，当前目标更可能在 agent 注入/恢复阶段被代码签名或保护机制终止；若普通 App 也失败，再检查 frida-server/客户端版本、root 启动状态和越狱激活状态。".into()
    } else if lower.contains("probing dyld") {
        "Frida 已找到进程，但无法读取目标 dyld。先确认 iPhone 已解锁并保持屏幕常亮；若解锁后普通 App 也出现同样错误，再检查设备端 frida-server 的 root/task_for_pid 权限或越狱激活状态。这发生在用户脚本执行前，切换 ObjC/Network 脚本无效。".into()
    } else if lower.contains("(os/kern) failure") {
        "iOS 内核在 frida-agent 注入/恢复阶段拒绝了目标进程，用户 JavaScript 尚未执行。请用 Reqable 等普通 App 运行“iOS 注入通道探针（零 Hook）”：若能输出 ME_IOS_INJECTION_OK，则设备与 Frida 基线正常，失败属于当前目标的注入限制/代码签名保护；若普通 App 也失败，再检查越狱激活和 root frida-server。此时切换 Hook 脚本或 PID 无法解决。".into()
    } else if lower.contains("timeout was reached") {
        "Attach 在设备端超时。通常是 frida-server helper、task_for_pid 或目标保护逻辑阻塞；先用无保护测试 App 验证 Attach，再判断是否为 JMCodeProtect。".into()
    } else if mode == "spawn" && lower.contains("process terminated") {
        "Spawn 后目标立即退出，可能是 App 自身启动崩溃或保护逻辑检测到冷启动注入。请先手动打开 App，再改用 Attach；但必须先保证设备对普通 App 的 Attach 自检可以通过。".into()
    } else {
        return None;
    };
    Some(format!("[运行时诊断] {detail}"))
}

fn frida_script_roots() -> Vec<PathBuf> {
    let mut roots = Vec::new();
    #[cfg(debug_assertions)]
    {
        roots.extend([
            std::env::current_dir()
                .unwrap_or_default()
                .join("frida-scripts"),
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../frida-scripts"),
        ]);
    }
    // Hooker remains an optional local extension. Its scripts are discovered
    // automatically on a tester workstation, while the MobileE workflows below
    // stay embedded in the executable and never depend on this directory.
    if let Some(home) = std::env::var_os("HOME").map(PathBuf::from) {
        roots.extend([
            home.join("Desktop/Tools/2-Mobile/hooker/js"),
            home.join("Documents/Tools/2-Mobile/hooker/js"),
        ]);
    }
    roots
}

const BUILTIN_DUMP_DEX: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../frida-scripts/dump_dex.js"
));
const BUILTIN_DUMP_SO: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../frida-scripts/dump_so.js"
));
const BUILTIN_INSPECT_JAVA: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../frida-scripts/inspect_java_runtime.js"
));
const BUILTIN_INSPECT_CLASSLOADER: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../frida-scripts/inspect_classloader.js"
));
const BUILTIN_INSPECT_NETWORK: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../frida-scripts/inspect_network_surface.js"
));
const BUILTIN_INSPECT_PROCESS: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../frida-scripts/inspect_process.js"
));
const BUILTIN_INSPECT_OBJC: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../frida-scripts/inspect_objc_runtime.js"
));
const BUILTIN_OBSERVE_IOS_NETWORK: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../frida-scripts/observe_ios_network_runtime.js"
));
const BUILTIN_OBSERVE_IOS_JSBRIDGE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../frida-scripts/observe_ios_jsbridge.js"
));
const BUILTIN_IOS_INJECTION_PROBE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../frida-scripts/ios_injection_probe.js"
));
const BUILTIN_IOS_TERMINATION_TRACE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../frida-scripts/ios_termination_trace.js"
));
const BUILTIN_OBSERVE_JMPROTECTION: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../frida-scripts/observe_jmprotection.js"
));
const IOS_COMPATIBILITY_BOOTSTRAP: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../frida-scripts/ios_compatibility_bootstrap.js"
));
const BUILTIN_INSPECT_ROOT: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../frida-scripts/inspect_root_indicators.js"
));
const BUILTIN_ANTI_INSTRUMENTATION_PROBE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../frida-scripts/anti_instrumentation_probe.js"
));
const BUILTIN_OBSERVE_ANDROID_NETWORK: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../frida-scripts/observe_android_network_runtime.js"
));
const BUILTIN_OBSERVE_ANDROID_WEBVIEW: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../frida-scripts/observe_android_webview_runtime.js"
));
const BUILTIN_OBSERVE_ANDROID_STORAGE_CRYPTO: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../frida-scripts/observe_android_storage_crypto_runtime.js"
));
pub(in crate::advanced) const IOS_DUMP_AGENT: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/scripts/ios_dump_agent.js"
));
pub(in crate::advanced) const IOS_DUMP_RUNNER: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/scripts/ios_dump_runner.py"
));

fn builtin_frida_script(path: &str) -> Option<&'static str> {
    match path {
        "builtin://dump_dex.js" => Some(BUILTIN_DUMP_DEX),
        "builtin://dump_so.js" => Some(BUILTIN_DUMP_SO),
        "builtin://inspect_java_runtime.js" => Some(BUILTIN_INSPECT_JAVA),
        "builtin://inspect_classloader.js" => Some(BUILTIN_INSPECT_CLASSLOADER),
        "builtin://inspect_network_surface.js" => Some(BUILTIN_INSPECT_NETWORK),
        "builtin://inspect_process.js" => Some(BUILTIN_INSPECT_PROCESS),
        "builtin://inspect_objc_runtime.js" => Some(BUILTIN_INSPECT_OBJC),
        "builtin://observe_ios_network_runtime.js" => Some(BUILTIN_OBSERVE_IOS_NETWORK),
        "builtin://observe_ios_jsbridge.js" => Some(BUILTIN_OBSERVE_IOS_JSBRIDGE),
        "builtin://ios_injection_probe.js" => Some(BUILTIN_IOS_INJECTION_PROBE),
        "builtin://ios_termination_trace.js" => Some(BUILTIN_IOS_TERMINATION_TRACE),
        "builtin://observe_jmprotection.js" => Some(BUILTIN_OBSERVE_JMPROTECTION),
        "builtin://inspect_root_indicators.js" => Some(BUILTIN_INSPECT_ROOT),
        "builtin://anti_instrumentation_probe.js" => Some(BUILTIN_ANTI_INSTRUMENTATION_PROBE),
        "builtin://observe_android_network_runtime.js" => Some(BUILTIN_OBSERVE_ANDROID_NETWORK),
        "builtin://observe_android_webview_runtime.js" => Some(BUILTIN_OBSERVE_ANDROID_WEBVIEW),
        "builtin://observe_android_storage_crypto_runtime.js" => {
            Some(BUILTIN_OBSERVE_ANDROID_STORAGE_CRYPTO)
        }
        _ => None,
    }
}

fn builtin_frida_script_entries() -> Vec<FridaScriptEntry> {
    [
        (
            "dump_dex",
            "dump dex（内置）",
            "内置 Frida 17 DEX 运行时提取：内存扫描、dexElements、InMemoryDexClassLoader 与 DefineClass 多路径自动回收",
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
            "inspect_classloader",
            "类加载器勘查（内置）",
            "只读枚举 ClassLoader 委派链、BaseDexClassLoader dexElements、DEX 路径与类名样本",
            "diagnostic",
            "builtin://inspect_classloader.js",
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
            "inspect_objc_runtime",
            "inspect Objective-C runtime（内置）",
            "读取 iOS App 自有类、方法、运行时 IMP 地址与模块偏移；适合静态元数据受保护时复核",
            "diagnostic",
            "builtin://inspect_objc_runtime.js",
            "ios",
        ),
        (
            "observe_ios_network_runtime",
            "observe iOS network runtime（内置）",
            "只读观察 NSURLSession 请求、TLS Challenge、SecTrust/Keychain 调用和已加载网络模块；不修改请求或信任结果",
            "diagnostic",
            "builtin://observe_ios_network_runtime.js",
            "ios",
        ),
        (
            "observe_ios_jsbridge",
            "observe iOS JSBridge（内置）",
            "只读观察 WKWebView/JavaScriptCore 的 Handler 注册、消息来源、导航和脚本执行，输出风险候选与证据分级",
            "diagnostic",
            "builtin://observe_ios_jsbridge.js",
            "ios",
        ),
        (
            "ios_injection_probe",
            "iOS 注入通道探针（零 Hook）",
            "只验证 frida-agent 与用户 JavaScript 是否成功装载；不访问 ObjC、不安装 Interceptor Hook",
            "diagnostic",
            "builtin://ios_injection_probe.js",
            "ios",
        ),
        (
            "ios_termination_trace",
            "iOS 异常 / 终止追踪（只读）",
            "记录 exit/abort/信号/Objective-C 异常和致命内存异常的调用栈与模块偏移；不阻断终止",
            "diagnostic",
            "builtin://ios_termination_trace.js",
            "ios",
        ),
        (
            "observe_jmprotection",
            "观察 JMProtection / FishHook 检测（只读）",
            "按已确认 UUID 和静态偏移观察 JMProtection 的符号扫描与 FishHook 检测调用；不替换函数、不修改返回值，避免把注入失败误判为脚本问题",
            "diagnostic",
            "builtin://observe_jmprotection.js",
            "ios",
        ),
        (
            "inspect_root_indicators",
            "inspect root indicators（内置）",
            "读取 Android Root 环境线索",
            "diagnostic",
            "builtin://inspect_root_indicators.js",
            "android",
        ),
        (
            "anti_instrumentation_probe",
            "Anti-Instrumentation 运行确认（零 Hook）",
            "只读采集 /proc/self、线程、模块和 Frida 默认端口，确认进程是否允许探针进入并保持存活",
            "diagnostic",
            "builtin://anti_instrumentation_probe.js",
            "android",
        ),
        (
            "observe_android_network_runtime",
            "observe Android network runtime（内置）",
            "只读观察 URL/OkHttp、SSLContext 与 HostnameVerifier 调用；不修改请求和信任结果",
            "diagnostic",
            "builtin://observe_android_network_runtime.js",
            "android",
        ),
        (
            "observe_android_webview_runtime",
            "observe Android WebView runtime（内置）",
            "只读观察 WebView URL、JavaScript 执行与 JavaScript Interface 注册",
            "diagnostic",
            "builtin://observe_android_webview_runtime.js",
            "android",
        ),
        (
            "observe_android_storage_crypto_runtime",
            "observe Android storage / crypto runtime（内置）",
            "只记录 SharedPreferences 键名和 Cipher/KeyStore 元数据，不采集值、密钥或明文",
            "diagnostic",
            "builtin://observe_android_storage_crypto_runtime.js",
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

pub(in crate::advanced) fn list_frida_scripts(
    directory: Option<String>,
) -> Result<Vec<FridaScriptEntry>, String> {
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
            let is_hooker = root
                .to_string_lossy()
                .to_ascii_lowercase()
                .contains("hooker");
            scripts.push(FridaScriptEntry {
                id: format!("{}:{}", root.display(), name),
                name: name.replace('_', " "),
                description,
                category: category.into(),
                path: path.to_string_lossy().into_owned(),
                platform: if lower.contains("ios") {
                    "ios".into()
                } else if is_hooker
                    || lower.contains("java")
                    || lower.contains("root")
                    || lower.contains("dex")
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

pub(in crate::advanced) fn read_script_path(path: &str) -> Result<String, String> {
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

pub(in crate::advanced) fn write_private_embedded_script(
    path: &Path,
    contents: &str,
) -> Result<(), String> {
    fs::write(path, contents).map_err(|error| format!("无法释放内置脚本：{error}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .map_err(|error| format!("无法限制内置脚本权限：{error}"))?;
    }
    let written = fs::read(path).map_err(|error| format!("无法校验内置脚本：{error}"))?;
    if Sha256::digest(contents.as_bytes()) != Sha256::digest(&written) {
        let _ = fs::remove_file(path);
        return Err("内置脚本完整性校验失败".into());
    }
    Ok(())
}

pub(in crate::advanced) fn normalize_ios_compatibility_profile(
    value: Option<&str>,
) -> Result<String, String> {
    let profile = value.unwrap_or("minimal").trim().to_ascii_lowercase();
    if matches!(profile.as_str(), "minimal" | "compat" | "aggressive") {
        Ok(profile)
    } else {
        Err("iOS Frida 兼容策略只能是 minimal、compat 或 aggressive".into())
    }
}

pub(in crate::advanced) fn apply_ios_compatibility_profile(
    script: String,
    profile: &str,
) -> String {
    if profile == "minimal" {
        return script;
    }
    format!(
        "globalThis.__ME_IOS_COMPATIBILITY_PROFILE = {profile:?};\n{IOS_COMPATIBILITY_BOOTSTRAP}\n{script}"
    )
}

pub(in crate::advanced) fn adapt_frida_17_script(script: &str) -> (String, Vec<String>) {
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
            "console.log('[MobileE] Frida 17 compatibility: {}');\n{}",
            changes.join(", "),
            adapted
        );
    }
    (adapted, changes)
}

/// Run a quiet Frida observation while retaining output if the CLI fails to
/// honour its own `--timeout`. `Command::output()` discards buffered logs when
/// wrapped in a Tokio timeout, which previously turned a useful session into
/// the misleading error "frida 操作超时".
async fn run_frida_observation(
    args: &[String],
    observation: Duration,
) -> Result<(RawOutput, bool), String> {
    let executable = cohesive_frida_executable_path("frida")
        .ok_or_else(|| "未找到 frida，请先安装对应工具".to_string())?;
    let mut command = Command::new(executable);
    command
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    let mut child = command
        .spawn()
        .map_err(|error| format!("启动 frida 失败：{error}"))?;
    let mut stdout = child
        .stdout
        .take()
        .ok_or_else(|| "无法读取 frida 标准输出".to_string())?;
    let mut stderr = child
        .stderr
        .take()
        .ok_or_else(|| "无法读取 frida 错误输出".to_string())?;
    let stdout_task = tokio::spawn(async move {
        let mut bytes = Vec::new();
        let _ = stdout.read_to_end(&mut bytes).await;
        bytes
    });
    let stderr_task = tokio::spawn(async move {
        let mut bytes = Vec::new();
        let _ = stderr.read_to_end(&mut bytes).await;
        bytes
    });

    // Frida itself receives `-t observation`; the grace window only covers
    // detach/transport cleanup. If it stays alive we end the host session,
    // retain all observed output, and leave the target App running.
    let grace = observation.saturating_add(Duration::from_secs(12));
    let (status, forced_stop) = match timeout(grace, child.wait()).await {
        Ok(result) => (
            result.map_err(|error| format!("等待 frida 失败：{error}"))?,
            false,
        ),
        Err(_) => {
            let _ = child.kill().await;
            let status = child
                .wait()
                .await
                .map_err(|error| format!("结束 frida 观察会话失败：{error}"))?;
            (status, true)
        }
    };
    let stdout = stdout_task
        .await
        .map_err(|error| format!("读取 frida 输出失败：{error}"))?;
    let stderr = stderr_task
        .await
        .map_err(|error| format!("读取 frida 错误输出失败：{error}"))?;
    Ok((
        RawOutput {
            stdout: String::from_utf8_lossy(&stdout).trim().into(),
            stderr: String::from_utf8_lossy(&stderr).trim().into(),
            code: status.code(),
        },
        forced_stop,
    ))
}

pub(in crate::advanced) async fn run_frida_script(
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
        return Err("Frida 脚本不能为空且不能超过 512KB".into());
    }
    let mode = request.mode.to_ascii_lowercase();
    if !matches!(mode.as_str(), "attach" | "spawn") {
        return Err("Frida 模式只能是 attach 或 spawn".into());
    }
    let ios_injection_probe = is_ios_injection_probe(
        request.platform.as_deref(),
        request.script_path.as_deref(),
        &script,
    );
    let compatibility_profile =
        normalize_ios_compatibility_profile(request.compatibility_profile.as_deref())?;
    let (script, _) = adapt_frida_17_script(&script);
    let script = if request.platform.as_deref() == Some("ios") {
        apply_ios_compatibility_profile(script, &compatibility_profile)
    } else {
        script
    };
    let file = std::env::temp_dir().join(format!("mobilee-{}.js", now_millis()));
    write_private_embedded_script(&file, &script)?;
    let duration_seconds = request.duration_seconds.unwrap_or(60).clamp(5, 300);
    let (target, _endpoint) = resolve_target(&request.serial).await;
    let mut fallback_note = None;
    let (initial_mode, live_pid) = if mode == "attach" {
        match select_live_attach_pid(
            process,
            request.pid,
            list_frida_processes(request.serial.clone()).await,
        ) {
            Ok(pid) => ("attach", Some(pid)),
            Err(error) if ios_injection_probe => {
                fallback_note = Some(format!(
                    "[MobileE] Attach 前实时 PID 已失效，零 Hook 注入基线自动改用 Spawn：{error}"
                ));
                ("spawn", None)
            }
            Err(error) => {
                let _ = fs::remove_file(&file);
                return Err(error);
            }
        }
    } else {
        ("spawn", request.pid)
    };
    let args = frida_script_args_with_target(
        target.clone(),
        initial_mode,
        process,
        live_pid,
        &file,
        duration_seconds,
    )?;
    let mut command = format!("frida {}", args.join(" "));
    let (mut output, mut forced_stop) =
        run_frida_observation(&args, Duration::from_secs(duration_seconds)).await?;
    let first_rendered = output_text(&output);
    let mut effective_mode = initial_mode;
    if ios_injection_probe
        && initial_mode == "attach"
        && should_retry_ios_probe_with_spawn(&first_rendered)
    {
        let spawn_args =
            frida_script_args_with_target(target, "spawn", process, None, &file, duration_seconds)?;
        fallback_note = Some(
            "[MobileE] Attach 在用户脚本执行前失败，零 Hook 注入基线已自动回退 Spawn 重试。".into(),
        );
        command = format!("{command}\n↳ fallback: frida {}", spawn_args.join(" "));
        let (spawn_output, spawn_forced_stop) =
            run_frida_observation(&spawn_args, Duration::from_secs(duration_seconds)).await?;
        output = spawn_output;
        forced_stop = spawn_forced_stop;
        effective_mode = "spawn";
    }
    let _ = fs::remove_file(file);
    let mut rendered = output_text(&output);
    if let Some(note) = fallback_note {
        let first_attempt = if initial_mode == "attach" && !first_rendered.trim().is_empty() {
            format!("\n[MobileE] 首次 Attach 输出：\n{first_rendered}")
        } else {
            String::new()
        };
        rendered = if rendered.is_empty() {
            format!("{note}{first_attempt}")
        } else {
            format!("{note}{first_attempt}\n[MobileE] Spawn 重试输出：\n{rendered}")
        };
    }
    if forced_stop {
        let note = if rendered.trim().is_empty() {
            "[MobileE] 已到观察时长并结束主机 Frida 会话，但没有收到任何脚本输出；连接或注入阶段可能被阻塞。"
        } else {
            "[MobileE] 已到观察时长并结束主机 Frida 会话；上方已采集输出仍然有效，目标 App 不会因此被判定失败。"
        };
        rendered = if rendered.is_empty() {
            note.into()
        } else {
            format!("{rendered}\n{note}")
        };
    }
    if compatibility_profile != "minimal" {
        let prefix =
            format!("[MobileE] requested iOS compatibility profile={compatibility_profile}");
        rendered = if rendered.is_empty() {
            prefix
        } else {
            format!("{prefix}\n{rendered}")
        };
    }
    if rendered.contains("ME_IOS_INJECTION_OK") && rendered.contains("Process terminated") {
        let note = if rendered.contains("ME_IOS_TERMINATION_CALL")
            || rendered.contains("ME_IOS_FATAL_EXCEPTION")
        {
            "[运行时诊断] iOS 注入基线已经通过，App 在恢复后终止；上方终止事件可用于定位调用栈。"
        } else {
            "[运行时诊断] iOS 注入基线已经通过，frida-agent 与零 Hook 脚本均已进入进程；App 在恢复后退出，但未观察到 exit/abort/信号/ObjC 异常调用。更可能是外部看护进程、直接系统调用、原生崩溃或保护框架结束目标，而不是注入前拒绝。"
        };
        rendered.push_str("\n\n");
        rendered.push_str(note);
    }
    let retained_observation = forced_stop
        && rendered.lines().any(|line| {
            let line = line.trim();
            !line.is_empty()
                && !line.starts_with("[MobileE]")
                && !line.starts_with("Failed to")
                && !line.starts_with("Spawned `")
                && !line.contains("Resuming main thread")
        });
    let success = output.code == Some(0) || retained_observation;
    if !success {
        if let Some(diagnostic) = frida_runtime_diagnostic(&rendered, effective_mode, process) {
            if !rendered.is_empty() {
                rendered.push_str("\n\n");
            }
            rendered.push_str(&diagnostic);
        }
    }
    Ok(AdvancedCommandResult {
        success,
        command,
        output: rendered,
        exit_code: output.code,
    })
}

#[cfg(test)]
mod embedded_script_tests {
    use super::*;

    #[test]
    fn embedded_scripts_are_written_privately_and_exactly() {
        let path = std::env::temp_dir().join(format!(
            "me-embedded-script-test-{}-{}.js",
            std::process::id(),
            now_millis()
        ));
        write_private_embedded_script(&path, "console.log('bound');\n").unwrap();
        assert_eq!(
            fs::read_to_string(&path).unwrap(),
            "console.log('bound');\n"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        let _ = fs::remove_file(path);
    }

    #[test]
    fn anti_instrumentation_probe_is_registered_and_emits_contract_prefix() {
        let entry = builtin_frida_script_entries()
            .into_iter()
            .find(|item| item.path == "builtin://anti_instrumentation_probe.js")
            .expect("built-in anti instrumentation probe");
        assert_eq!(entry.platform, "android");
        assert_eq!(entry.category, "diagnostic");
        assert!(BUILTIN_ANTI_INSTRUMENTATION_PROBE.contains("ME_ANTI_INSTRUMENTATION_RESULT:"));
        assert!(!BUILTIN_ANTI_INSTRUMENTATION_PROBE.contains("Interceptor.attach"));
    }

    #[test]
    fn android_runtime_observers_are_registered_with_stable_markers() {
        let scripts = builtin_frida_script_entries();
        for (path, marker) in [
            (
                "builtin://observe_android_network_runtime.js",
                "ME_ANDROID_NETWORK_RUNTIME:",
            ),
            (
                "builtin://observe_android_webview_runtime.js",
                "ME_ANDROID_WEBVIEW_RUNTIME:",
            ),
            (
                "builtin://observe_android_storage_crypto_runtime.js",
                "ME_ANDROID_STORAGE_CRYPTO_RUNTIME:",
            ),
        ] {
            let entry = scripts.iter().find(|entry| entry.path == path).expect(path);
            assert_eq!(entry.platform, "android");
            assert!(builtin_frida_script(path).expect(path).contains(marker));
        }
        assert!(BUILTIN_INSPECT_JAVA.contains("ME_ANDROID_JAVA_RUNTIME:"));
        assert!(BUILTIN_INSPECT_ROOT.contains("ME_ANDROID_ROOT_INDICATORS:"));
    }

    #[test]
    fn classloader_inspector_is_registered_and_read_only() {
        let entry = builtin_frida_script_entries()
            .into_iter()
            .find(|item| item.path == "builtin://inspect_classloader.js")
            .expect("built-in classloader inspector");
        assert_eq!(entry.platform, "android");
        assert_eq!(entry.category, "diagnostic");
        assert!(BUILTIN_INSPECT_CLASSLOADER.contains("ME_CLASSLOADER_RESULT:"));
        assert!(BUILTIN_INSPECT_CLASSLOADER.contains("dexElements"));
        assert!(!BUILTIN_INSPECT_CLASSLOADER.contains("Interceptor.attach"));
    }

    #[test]
    fn dex_dump_embeds_classloader_and_in_memory_paths() {
        for marker in [
            "dexElements",
            "InMemoryDexClassLoader",
            "openInMemoryDexFile",
            "DefineClass",
            "ME_DEX_DUMP",
        ] {
            assert!(BUILTIN_DUMP_DEX.contains(marker), "missing {marker}");
        }
    }

    #[test]
    fn hardened_target_is_preserved_when_building_script_arguments() {
        let args = frida_script_args_with_target(
            vec!["-H".into(), "127.0.0.1:28731".into()],
            "spawn",
            "com.example.app",
            None,
            Path::new("/tmp/probe.js"),
            30,
        )
        .unwrap();
        assert_eq!(&args[..2], ["-H", "127.0.0.1:28731"]);
        assert!(args
            .windows(2)
            .any(|pair| pair == ["-f", "com.example.app"]));
    }

    #[test]
    fn live_attach_pid_never_reuses_stale_pid_after_a_successful_refresh() {
        let error = select_live_attach_pid(
            "com.asiainfo.ima.base",
            Some(12311),
            Ok(vec![FridaProcess {
                pid: None,
                name: "中移FIDO".into(),
                identifier: "com.asiainfo.ima.base".into(),
                platform: "mobile".into(),
            }]),
        )
        .expect_err("installed but stopped app must not reuse stale PID");
        assert!(error.contains("拒绝复用旧 PID 12311"));
        assert!(error.contains("Spawn"));
    }

    #[test]
    fn live_attach_pid_uses_refreshed_identifier_match() {
        let pid = select_live_attach_pid(
            "com.asiainfo.ima.base",
            Some(12311),
            Ok(vec![FridaProcess {
                pid: Some(12428),
                name: "中移FIDO".into(),
                identifier: "com.asiainfo.ima.base".into(),
                platform: "mobile".into(),
            }]),
        )
        .expect("live PID");
        assert_eq!(pid, 12428);
    }

    #[test]
    fn ios_zero_hook_probe_retries_pre_script_attach_failures_only() {
        assert!(should_retry_ios_probe_with_spawn(
            "Failed to attach: unexpected early end-of-stream"
        ));
        assert!(should_retry_ios_probe_with_spawn(
            "Failed to attach: unable to find process with pid 12455"
        ));
        assert!(!should_retry_ios_probe_with_spawn(
            "{\"type\":\"ME_IOS_INJECTION_OK\",\"pid\":42}\nProcess terminated"
        ));
    }

    #[test]
    fn ios_zero_hook_probe_is_identified_by_builtin_path_or_contract_marker() {
        assert!(is_ios_injection_probe(
            Some("ios"),
            Some("builtin://ios_injection_probe.js"),
            ""
        ));
        assert!(is_ios_injection_probe(
            Some("ios"),
            None,
            "send({ type: 'ME_IOS_INJECTION_OK' });"
        ));
        assert!(!is_ios_injection_probe(
            Some("android"),
            Some("builtin://ios_injection_probe.js"),
            ""
        ));
    }

    #[test]
    fn frida_process_parser_keeps_installed_but_stopped_apps() {
        let processes = parse_frida_ps(
            "  PID  Name       Identifier\n-----  ---------  ---------------------\n12455  中移FIDO   com.asiainfo.ima.base\n    -  MBOMC      com.central.mbomc\n",
        );
        assert_eq!(processes.len(), 2);
        assert_eq!(processes[0].pid, Some(12455));
        assert_eq!(processes[1].pid, None);
        assert_eq!(processes[1].identifier, "com.central.mbomc");
    }
}
