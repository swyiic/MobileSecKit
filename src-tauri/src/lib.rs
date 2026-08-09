use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{SystemTime, UNIX_EPOCH},
};
use tauri::{AppHandle, Emitter, State};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::{TcpListener, TcpStream},
    process::Command,
    time::{timeout, Duration},
};

mod advanced;

pub(crate) const BRIDGE_PORT: u16 = 7878;
pub(crate) const ADB_TIMEOUT: Duration = Duration::from_secs(20);

#[derive(Default)]
struct BridgeState {
    running: Arc<AtomicBool>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct DeviceSummary {
    platform: String,
    serial: String,
    status: String,
    model: String,
    product: String,
    device: String,
    transport_id: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct DeviceDetails {
    serial: String,
    model: String,
    manufacturer: String,
    android_version: String,
    sdk_version: String,
    build_number: String,
    codename: String,
    architecture: String,
    root_status: String,
    selinux_status: String,
    bootloader_status: String,
    ip_address: String,
    kernel_version: String,
    battery_level: Option<u8>,
    architecture_family: String,
    abi_list: Vec<String>,
    security_patch: String,
    brand: String,
    frida_server_version: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct IosDeviceDetails {
    serial: String,
    device_name: String,
    product_type: String,
    product_version: String,
    build_version: String,
    activation_state: String,
    battery_level: Option<u8>,
    architecture: String,
    jailbreak_hint: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct ProcessInfo {
    pid: u32,
    user: String,
    memory_kb: u64,
    name: String,
    protected: bool,
    system: bool,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AdbActionRequest {
    serial: String,
    action: String,
    argument: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct CommandResult {
    success: bool,
    command: String,
    output: String,
    exit_code: Option<i32>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct PhoneSignal {
    #[serde(default)]
    id: String,
    #[serde(default)]
    device_id: String,
    kind: String,
    #[serde(default)]
    value: String,
    #[serde(default)]
    timestamp: Option<u64>,
    #[serde(default)]
    payload: Value,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct SignalDecision {
    signal_id: String,
    accepted: bool,
    decision: String,
    risk_level: String,
    message: String,
    received_at: u64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct SignalEvent {
    signal: PhoneSignal,
    decision: SignalDecision,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct BridgeStatus {
    running: bool,
    port: u16,
    endpoint: String,
}

pub(crate) struct RawOutput {
    pub(crate) stdout: String,
    pub(crate) stderr: String,
    pub(crate) code: Option<i32>,
}

pub(crate) async fn run_adb(args: &[String]) -> Result<RawOutput, String> {
    let mut command = Command::new("adb");
    command.args(args).kill_on_drop(true);
    let output = timeout(ADB_TIMEOUT, command.output())
        .await
        .map_err(|_| "ADB 操作超时，请检查手机连接状态".to_string())?
        .map_err(|error| format!("无法启动 adb：{error}。请先安装 Android platform-tools"))?;

    Ok(RawOutput {
        stdout: String::from_utf8_lossy(&output.stdout).trim().to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
        code: output.status.code(),
    })
}

pub(crate) async fn run_device_adb(serial: &str, tail: &[&str]) -> Result<RawOutput, String> {
    let mut args = vec!["-s".to_string(), serial.to_string()];
    args.extend(tail.iter().map(|item| item.to_string()));
    run_adb(&args).await
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

fn root_shell_command(script: &str) -> String {
    format!("su -c {}", shell_quote(script))
}

pub(crate) async fn run_device_root_script(
    serial: &str,
    script: &str,
) -> Result<RawOutput, String> {
    if script.trim().is_empty() {
        return Err("root 命令不能为空".into());
    }

    // `adb shell` reconstructs all arguments following `shell` into a remote
    // command line. Passing `su`, `-c` and a script as separate arguments loses
    // the script boundary (especially at spaces and semicolons), so only part of
    // the command may execute as root. Keep the complete remote command in one
    // argument and quote the script for the device shell.
    let remote_command = root_shell_command(script);
    run_device_adb(serial, &["shell", &remote_command]).await
}

pub(crate) async fn run_device_root(serial: &str, command: &[&str]) -> Result<RawOutput, String> {
    if command.is_empty() {
        return Err("root 命令不能为空".into());
    }
    let script = command
        .iter()
        .map(|value| shell_quote(value))
        .collect::<Vec<_>>()
        .join(" ");
    run_device_root_script(serial, &script).await
}

pub(crate) fn ensure_success(output: RawOutput) -> Result<RawOutput, String> {
    if output.code == Some(0) {
        Ok(output)
    } else {
        let message = if output.stderr.is_empty() {
            output.stdout
        } else {
            output.stderr
        };
        Err(if message.is_empty() {
            "ADB 操作失败".to_string()
        } else {
            message
        })
    }
}

fn parse_properties(text: &str) -> HashMap<String, String> {
    text.lines()
        .filter_map(|line| {
            let (key, value) = line.split_once("]: [")?;
            Some((
                key.trim_start_matches('[').to_string(),
                value.trim_end_matches(']').to_string(),
            ))
        })
        .collect()
}

fn property(properties: &HashMap<String, String>, key: &str) -> String {
    properties.get(key).cloned().unwrap_or_else(|| "—".into())
}

fn extract_ipv4(text: &str) -> String {
    text.lines()
        .find_map(|line| {
            let fields: Vec<_> = line.split_whitespace().collect();
            let index = fields.iter().position(|field| *field == "inet")?;
            let ip = fields.get(index + 1)?.split('/').next()?;
            (ip != "127.0.0.1").then(|| ip.to_string())
        })
        .or_else(|| {
            text.split_whitespace()
                .find(|token| token.contains('.') && token.contains('/'))
                .and_then(|token| token.split('/').next())
                .map(str::to_string)
        })
        .unwrap_or_else(|| "—".into())
}

async fn idevice_info(serial: &str) -> Result<HashMap<String, String>, String> {
    let output = timeout(
        ADB_TIMEOUT,
        Command::new("ideviceinfo").args(["-u", serial]).output(),
    )
    .await
    .map_err(|_| "读取 iOS 设备信息超时".to_string())?
    .map_err(|error| format!("无法启动 ideviceinfo：{error}"))?;
    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).trim().to_string());
    }
    Ok(String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| line.split_once(": "))
        .map(|(key, value)| (key.to_string(), value.to_string()))
        .collect())
}

#[tauri::command]
async fn get_ios_device_details(serial: String) -> Result<IosDeviceDetails, String> {
    let info = idevice_info(&serial).await.unwrap_or_default();
    let frida_label = Command::new("frida-ls-devices")
        .output()
        .await
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| {
            String::from_utf8_lossy(&output.stdout)
                .lines()
                .skip(1)
                .find_map(|line| {
                    let mut fields = line.split_whitespace();
                    (fields.next()? == serial).then(|| fields.skip(1).collect::<Vec<_>>().join(" "))
                })
        });
    let battery_level = info
        .get("BatteryCurrentCapacity")
        .and_then(|value| value.parse::<u8>().ok());
    Ok(IosDeviceDetails {
        serial,
        device_name: info
            .get("DeviceName")
            .cloned()
            .or(frida_label)
            .unwrap_or_else(|| "iOS / Frida device".into()),
        product_type: info
            .get("ProductType")
            .cloned()
            .unwrap_or_else(|| "—（需 Developer Disk Image）".into()),
        product_version: info
            .get("ProductVersion")
            .cloned()
            .unwrap_or_else(|| "—".into()),
        build_version: info
            .get("BuildVersion")
            .cloned()
            .unwrap_or_else(|| "—".into()),
        activation_state: info
            .get("ActivationState")
            .cloned()
            .unwrap_or_else(|| "Frida reachable".into()),
        battery_level,
        architecture: "ARM64 / Apple mobile".into(),
        jailbreak_hint: if info.contains_key("UniqueChipID") {
            "标准设备信息可用；越狱状态请通过 Frida 诊断确认".into()
        } else {
            "ideviceinfo 未打开该 UDID；Frida 设备通道可用".into()
        },
    })
}

async fn probe_frida_device(serial: &str) -> (bool, bool) {
    let output = match timeout(
        Duration::from_secs(8),
        Command::new("frida-ps")
            .args(["-D", serial, "-ai"])
            .output(),
    )
    .await
    {
        Ok(Ok(output)) => output,
        _ => return (false, false),
    };
    let message = format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
    .to_ascii_lowercase();
    if message.contains("device not found")
        || message.contains("developer disk image")
        || message.contains("unable to find")
    {
        return (false, false);
    }
    if output.status.success() {
        return (true, false);
    }
    // A jailbroken device with a running but version-mismatched frida-server
    // is still a real selectable endpoint; the environment panel will explain
    // how to align host/server versions.
    (
        message.contains("remote frida-server") || message.contains("frida-server"),
        true,
    )
}

#[tauri::command]
async fn list_devices() -> Result<Vec<DeviceSummary>, String> {
    let adb_stdout = run_adb(&["devices".into(), "-l".into()])
        .await
        .ok()
        .filter(|output| output.code == Some(0))
        .map(|output| output.stdout)
        .unwrap_or_default();
    let mut devices: Vec<DeviceSummary> = adb_stdout
        .lines()
        .skip(1)
        .filter(|line| !line.trim().is_empty())
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            let serial = fields.next()?.to_string();
            let status = fields.next()?.to_string();
            let attributes: HashMap<_, _> = fields
                .filter_map(|field| field.split_once(':'))
                .map(|(key, value)| (key.to_string(), value.replace('_', " ")))
                .collect();
            Some(DeviceSummary {
                platform: "android".into(),
                serial,
                status,
                model: attributes
                    .get("model")
                    .cloned()
                    .unwrap_or_else(|| "Android device".into()),
                product: attributes.get("product").cloned().unwrap_or_default(),
                device: attributes.get("device").cloned().unwrap_or_default(),
                transport_id: attributes.get("transport_id").cloned(),
            })
        })
        .collect();
    // Frida exposes local/socket pseudo-devices and every paired iOS endpoint.
    // Only retain a physical USB/remote endpoint that answers Frida probing;
    // this avoids showing Local System, Local Socket and non-jailbroken phones
    // that merely advertise a Developer Disk Image transport.
    let mut ios_candidates: HashMap<String, (String, String)> = HashMap::new();
    if let Ok(ios) = Command::new("idevice_id").args(["-l"]).output().await {
        if ios.status.success() {
            for serial in String::from_utf8_lossy(&ios.stdout)
                .lines()
                .map(str::trim)
                .filter(|line| !line.is_empty())
            {
                let info = idevice_info(serial).await.unwrap_or_default();
                ios_candidates.insert(
                    serial.to_string(),
                    (
                        info.get("DeviceName")
                            .cloned()
                            .unwrap_or_else(|| "iPhone / iOS".into()),
                        "usb".into(),
                    ),
                );
            }
        }
    }
    if let Ok(frida_devices) = Command::new("frida-ls-devices").output().await {
        if frida_devices.status.success() {
            for line in String::from_utf8_lossy(&frida_devices.stdout)
                .lines()
                .skip(2)
            {
                let fields: Vec<_> = line.split_whitespace().collect();
                if fields.len() < 3 || !matches!(fields[1], "usb" | "remote") {
                    continue;
                }
                let serial = fields[0].to_string();
                let name = fields[2..].join(" ");
                let normalized = name.to_ascii_lowercase();
                if normalized.contains("local system") || normalized.contains("local socket") {
                    continue;
                }
                ios_candidates
                    .entry(serial)
                    .or_insert((name, fields[1].to_string()));
            }
        }
    }
    for (serial, (model, transport)) in ios_candidates {
        let (reachable, mismatch) = probe_frida_device(&serial).await;
        if !reachable {
            continue;
        }
        let model = if mismatch {
            format!("{model} · Frida 版本需对齐")
        } else {
            model
        };
        devices.push(DeviceSummary {
            platform: "ios".into(),
            serial,
            status: "frida".into(),
            model,
            product: "iOS".into(),
            device: "iphone".into(),
            transport_id: Some(transport),
        });
    }
    // A wired Android connection has priority over wireless Frida/iOS
    // discovery. This prevents stale remote iOS entries from being selected
    // while the Android phone is still plugged in.
    if devices.iter().any(|device| device.platform == "android") {
        devices.retain(|device| device.platform == "android");
    } else {
        devices.retain(|device| device.platform == "ios");
    }
    Ok(devices)
}

#[tauri::command]
async fn get_device_details(serial: String) -> Result<DeviceDetails, String> {
    let (props, identity, selinux, kernel, network, battery, su, frida_server) = tokio::join!(
        run_device_adb(&serial, &["shell", "getprop"]),
        run_device_adb(&serial, &["shell", "id"]),
        run_device_adb(&serial, &["shell", "getenforce"]),
        run_device_adb(&serial, &["shell", "uname", "-r"]),
        run_device_adb(
            &serial,
            &["shell", "ip", "-f", "inet", "addr", "show", "wlan0"]
        ),
        run_device_adb(&serial, &["shell", "dumpsys", "battery"]),
        run_device_adb(&serial, &["shell", "which", "su"]),
        run_device_adb(
            &serial,
            &["shell", "/data/local/tmp/frida-server", "--version"]
        ),
    );

    let properties = parse_properties(&ensure_success(props?)?.stdout);
    let identity = ensure_success(identity?)?.stdout;
    let selinux = selinux
        .map(|value| value.stdout)
        .unwrap_or_else(|_| "Unknown".into());
    let kernel = kernel
        .map(|value| value.stdout)
        .unwrap_or_else(|_| "—".into());
    let network = network.map(|value| value.stdout).unwrap_or_default();
    let battery_level = battery.ok().and_then(|value| {
        value.stdout.lines().find_map(|line| {
            line.trim()
                .strip_prefix("level:")
                .and_then(|level| level.trim().parse::<u8>().ok())
        })
    });
    let rooted =
        identity.contains("uid=0") || su.map(|value| value.code == Some(0)).unwrap_or(false);
    let verified_boot = property(&properties, "ro.boot.verifiedbootstate");
    let abi_list: Vec<String> = property(&properties, "ro.product.cpu.abilist")
        .split(',')
        .filter(|abi| !abi.is_empty() && *abi != "—")
        .map(str::to_string)
        .collect();
    let primary_abi = property(&properties, "ro.product.cpu.abi");
    let architecture_family = if primary_abi.contains("x86") {
        "x86 / x86_64"
    } else if primary_abi.contains("arm") || primary_abi.contains("aarch") {
        "ARM / ARM64"
    } else {
        "Unknown"
    };
    let frida_server_version = frida_server.ok().and_then(|output| {
        let text = if output.stdout.is_empty() {
            output.stderr
        } else {
            output.stdout
        };
        (!text.is_empty()).then_some(text)
    });

    Ok(DeviceDetails {
        serial: serial.clone(),
        model: property(&properties, "ro.product.model"),
        manufacturer: property(&properties, "ro.product.manufacturer"),
        android_version: property(&properties, "ro.build.version.release"),
        sdk_version: property(&properties, "ro.build.version.sdk"),
        build_number: property(&properties, "ro.build.display.id"),
        codename: property(&properties, "ro.product.device"),
        architecture: property(&properties, "ro.product.cpu.abi"),
        root_status: if rooted {
            "Root detected"
        } else {
            "Not detected"
        }
        .into(),
        selinux_status: if selinux.is_empty() {
            "Unknown".into()
        } else {
            selinux
        },
        bootloader_status: if verified_boot.eq_ignore_ascii_case("green") {
            "Locked / Verified".into()
        } else if verified_boot == "—" {
            "Unknown".into()
        } else {
            format!("Unlocked / {verified_boot}")
        },
        ip_address: extract_ipv4(&network),
        kernel_version: kernel,
        battery_level,
        architecture_family: architecture_family.into(),
        abi_list,
        security_patch: property(&properties, "ro.build.version.security_patch"),
        brand: property(&properties, "ro.product.brand"),
        frida_server_version,
    })
}

#[tauri::command]
async fn list_processes(serial: String) -> Result<Vec<ProcessInfo>, String> {
    let output = ensure_success(
        run_device_adb(&serial, &["shell", "ps", "-A", "-o", "PID,USER,RSS,NAME"]).await?,
    )?;
    let mut lines = output.stdout.lines();
    let header: Vec<_> = lines
        .next()
        .unwrap_or_default()
        .split_whitespace()
        .collect();
    let pid_index = header.iter().position(|item| *item == "PID").unwrap_or(0);
    let user_index = header.iter().position(|item| *item == "USER").unwrap_or(1);
    let rss_index = header.iter().position(|item| *item == "RSS");
    let name_index = header
        .iter()
        .position(|item| *item == "NAME" || *item == "CMD")
        .unwrap_or_else(|| header.len().saturating_sub(1));

    let mut processes: Vec<_> = lines
        .filter_map(|line| {
            let fields: Vec<_> = line.split_whitespace().collect();
            let pid = fields.get(pid_index)?.parse().ok()?;
            let user = fields.get(user_index)?.to_string();
            let name = fields.get(name_index)?.to_string();
            let memory_kb = rss_index
                .and_then(|index| fields.get(index))
                .and_then(|value| value.parse().ok())
                .unwrap_or(0);
            let protected = user == "root" || name == "zygote" || name == "zygote64";
            let system = !user.starts_with("u0_") && user != "shell";
            Some(ProcessInfo {
                pid,
                user,
                memory_kb,
                name,
                protected,
                system,
            })
        })
        .collect();
    processes.sort_by(|left, right| right.memory_kb.cmp(&left.memory_kb));
    processes.truncate(100);
    Ok(processes)
}

fn validate_package_name(value: &str) -> Result<(), String> {
    if !value.is_empty()
        && value.len() <= 180
        && value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || ".:_-$".contains(character))
    {
        Ok(())
    } else {
        Err("请输入有效的 Android 包名".into())
    }
}

#[tauri::command]
async fn run_adb_action(request: AdbActionRequest) -> Result<CommandResult, String> {
    let argument = request.argument.unwrap_or_default();
    let tail: Vec<&str> = match request.action.as_str() {
        "reboot" => vec!["reboot"],
        "recovery" => vec!["reboot", "recovery"],
        "logcat" => vec!["logcat", "-d", "-t", "120"],
        "packages" => vec!["shell", "pm", "list", "packages", "-3"],
        "processes" => vec!["shell", "ps", "-A"],
        "permissions" => {
            validate_package_name(&argument)?;
            vec!["shell", "dumpsys", "package", argument.as_str()]
        }
        "process_info" => {
            validate_package_name(&argument)?;
            vec!["shell", "dumpsys", "meminfo", argument.as_str()]
        }
        "storage" => vec!["shell", "find", "/sdcard", "-maxdepth", "3", "-type", "f"],
        "system_properties" => vec!["shell", "getprop"],
        "mounts" => vec!["shell", "cat", "/proc/mounts"],
        "proxy_status" => vec!["shell", "settings", "get", "global", "http_proxy"],
        "selinux_status" => vec!["shell", "getenforce"],
        "selinux_permissive" => vec!["shell", "sh", "-c", "setenforce 0; getenforce"],
        "selinux_enforcing" => vec!["shell", "sh", "-c", "setenforce 1; getenforce"],
        "shared_preferences" => {
            validate_package_name(&argument)?;
            vec![
                "shell",
                "run-as",
                argument.as_str(),
                "find",
                "files",
                "-type",
                "f",
            ]
        }
        "databases" => {
            validate_package_name(&argument)?;
            vec![
                "shell",
                "run-as",
                argument.as_str(),
                "find",
                "databases",
                "-type",
                "f",
            ]
        }
        "webview_storage" => {
            validate_package_name(&argument)?;
            vec![
                "shell",
                "run-as",
                argument.as_str(),
                "find",
                "app_webview",
                "-type",
                "f",
            ]
        }
        _ => return Err("不支持该操作；后端只执行预定义的安全 ADB 指令".into()),
    };
    let root_script = match request.action.as_str() {
        "selinux_permissive" => Some("setenforce 0; getenforce"),
        "selinux_enforcing" => Some("setenforce 1; getenforce"),
        _ => None,
    };
    let output = if let Some(script) = root_script {
        run_device_root_script(&request.serial, script).await?
    } else if tail.first() == Some(&"shell")
        && request.action != "reboot"
        && request.action != "recovery"
    {
        run_device_root(&request.serial, &tail[1..]).await?
    } else {
        run_device_adb(&request.serial, &tail).await?
    };
    let success = output.code == Some(0);
    let text = match (output.stdout.is_empty(), output.stderr.is_empty()) {
        (false, false) => format!("{}\n{}", output.stdout, output.stderr),
        (false, true) => output.stdout.clone(),
        (true, false) => output.stderr.clone(),
        (true, true) => String::new(),
    };
    let command_display = if let Some(script) = root_script {
        format!("adb -s {} shell \"su -c '{}'\"", request.serial, script)
    } else if tail.first() == Some(&"shell")
        && request.action != "reboot"
        && request.action != "recovery"
    {
        format!(
            "adb -s {} shell \"su -c '{}'\"",
            request.serial,
            tail[1..].join(" ")
        )
    } else {
        format!("adb -s {} {}", request.serial, tail.join(" "))
    };
    Ok(CommandResult {
        success,
        command: command_display,
        output: if text.is_empty() {
            "命令已完成".into()
        } else {
            text
        },
        exit_code: output.code,
    })
}

fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn signal_value(signal: &PhoneSignal) -> String {
    signal
        .payload
        .get("status")
        .or_else(|| signal.payload.get("value"))
        .and_then(Value::as_str)
        .unwrap_or(&signal.value)
        .trim()
        .to_ascii_lowercase()
}

fn evaluate_signal(signal: &PhoneSignal) -> SignalDecision {
    let kind = signal.kind.trim().to_ascii_lowercase();
    let value = signal_value(signal);
    let signal_id = if signal.id.is_empty() {
        format!("sig-{}", now_millis())
    } else {
        signal.id.clone()
    };

    let (accepted, decision, risk_level, message) = match kind.as_str() {
        "heartbeat" => (true, "allow", "info", "设备心跳正常".to_string()),
        "integrity"
            if ["rooted", "tampered", "compromised", "failed"].contains(&value.as_str()) =>
        {
            (
                false,
                "block",
                "critical",
                format!("设备完整性异常：{value}"),
            )
        }
        "integrity" => (true, "allow", "low", "设备完整性检查通过".to_string()),
        "risk_score" => {
            let score = signal
                .payload
                .get("score")
                .and_then(Value::as_f64)
                .or_else(|| signal.value.parse::<f64>().ok())
                .unwrap_or(0.0);
            if score >= 80.0 {
                (
                    false,
                    "block",
                    "critical",
                    format!("风险分 {score:.0}，已阻断"),
                )
            } else if score >= 50.0 {
                (
                    true,
                    "review",
                    "medium",
                    format!("风险分 {score:.0}，需要复核"),
                )
            } else {
                (true, "allow", "low", format!("风险分 {score:.0}，允许继续"))
            }
        }
        "alert" => (
            true,
            "review",
            "medium",
            if signal.value.is_empty() {
                "收到安卓告警".into()
            } else {
                signal.value.clone()
            },
        ),
        "event" | "app_event" => (true, "allow", "info", "应用事件已接收".to_string()),
        _ => (
            true,
            "record",
            "info",
            format!("已记录信号类型：{}", signal.kind),
        ),
    };

    SignalDecision {
        signal_id,
        accepted,
        decision: decision.into(),
        risk_level: risk_level.into(),
        message,
        received_at: now_millis(),
    }
}

async fn handle_signal_client(stream: TcpStream, app: AppHandle) -> Result<(), String> {
    let peer = stream.peer_addr().ok();
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);
    let mut buffer = String::new();

    loop {
        buffer.clear();
        let bytes = (&mut reader)
            .take(65_537)
            .read_line(&mut buffer)
            .await
            .map_err(|error| error.to_string())?;
        if bytes == 0 {
            break;
        }
        let response = if bytes > 65_536 {
            SignalDecision {
                signal_id: String::new(),
                accepted: false,
                decision: "reject".into(),
                risk_level: "high".into(),
                message: "单条信号不能超过 64KB".into(),
                received_at: now_millis(),
            }
        } else {
            match serde_json::from_str::<PhoneSignal>(buffer.trim()) {
                Ok(mut signal) => {
                    if signal.device_id.is_empty() {
                        signal.device_id = peer.map(|value| value.to_string()).unwrap_or_default();
                    }
                    let decision = evaluate_signal(&signal);
                    let event = SignalEvent {
                        signal,
                        decision: decision.clone(),
                    };
                    let _ = app.emit("phone-signal", event);
                    decision
                }
                Err(error) => SignalDecision {
                    signal_id: String::new(),
                    accepted: false,
                    decision: "reject".into(),
                    risk_level: "high".into(),
                    message: format!("JSON 格式错误：{error}"),
                    received_at: now_millis(),
                },
            }
        };
        let mut encoded = serde_json::to_vec(&response).map_err(|error| error.to_string())?;
        encoded.push(b'\n');
        writer
            .write_all(&encoded)
            .await
            .map_err(|error| error.to_string())?;
        if bytes > 65_536 {
            break;
        }
    }
    Ok(())
}

async fn serve_signal_bridge(listener: TcpListener, app: AppHandle, running: Arc<AtomicBool>) {
    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                let app = app.clone();
                tauri::async_runtime::spawn(async move {
                    let _ = handle_signal_client(stream, app).await;
                });
            }
            Err(_) => {
                running.store(false, Ordering::SeqCst);
                break;
            }
        }
    }
}

#[tauri::command]
async fn start_signal_bridge(
    serial: String,
    app: AppHandle,
    state: State<'_, BridgeState>,
) -> Result<BridgeStatus, String> {
    ensure_success(
        run_device_adb(
            &serial,
            &[
                "reverse",
                &format!("tcp:{BRIDGE_PORT}"),
                &format!("tcp:{BRIDGE_PORT}"),
            ],
        )
        .await?,
    )?;

    if state
        .running
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_ok()
    {
        let listener = TcpListener::bind(("127.0.0.1", BRIDGE_PORT))
            .await
            .map_err(|error| {
                state.running.store(false, Ordering::SeqCst);
                format!("无法启动信号服务：{error}")
            })?;
        let app = app.clone();
        let running = Arc::clone(&state.running);
        tauri::async_runtime::spawn(serve_signal_bridge(listener, app, running));
    }

    Ok(BridgeStatus {
        running: true,
        port: BRIDGE_PORT,
        endpoint: format!("127.0.0.1:{BRIDGE_PORT}"),
    })
}

#[tauri::command]
fn get_bridge_status(state: State<'_, BridgeState>) -> BridgeStatus {
    BridgeStatus {
        running: state.running.load(Ordering::SeqCst),
        port: BRIDGE_PORT,
        endpoint: format!("127.0.0.1:{BRIDGE_PORT}"),
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let _ = advanced::initialize_host_environment(None);
    tauri::Builder::default()
        .manage(BridgeState::default())
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_dialog::init())
        .invoke_handler(tauri::generate_handler![
            list_devices,
            get_ios_device_details,
            get_device_details,
            list_processes,
            run_adb_action,
            advanced::inspect_environment,
            advanced::configure_host_environment,
            advanced::run_shell,
            advanced::run_proxy,
            advanced::certificate_info,
            advanced::install_certificate,
            advanced::list_frida_processes,
            advanced::list_frida_scripts,
            advanced::run_frida_script,
            advanced::run_dex_dump,
            advanced::run_so_dump,
            advanced::run_ios_dump,
            advanced::manage_frida_server,
            advanced::download_frida_server,
            advanced::install_frida_tools,
            advanced::open_environment_terminal,
            advanced::mount_ios_developer_image,
            advanced::analyze_app,
            start_signal_bridge,
            get_bridge_status,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn signal(kind: &str, value: &str, payload: Value) -> PhoneSignal {
        PhoneSignal {
            id: "test-1".into(),
            device_id: "pixel".into(),
            kind: kind.into(),
            value: value.into(),
            timestamp: None,
            payload,
        }
    }

    #[test]
    fn parses_android_properties() {
        let properties =
            parse_properties("[ro.product.model]: [Pixel 4]\n[ro.build.version.release]: [13]");
        assert_eq!(
            properties.get("ro.product.model"),
            Some(&"Pixel 4".to_string())
        );
        assert_eq!(
            properties.get("ro.build.version.release"),
            Some(&"13".to_string())
        );
    }

    #[test]
    fn keeps_the_complete_su_script_in_one_remote_command() {
        assert_eq!(
            root_shell_command("setenforce 0; getenforce"),
            "su -c 'setenforce 0; getenforce'"
        );
        assert_eq!(
            root_shell_command("echo 'quoted value'"),
            "su -c 'echo '\\''quoted value'\\'''"
        );
    }

    #[tokio::test]
    async fn root_script_runs_as_one_command_when_device_is_configured() {
        let Ok(serial) = std::env::var("ME_ADB_SERIAL") else {
            return;
        };
        let output = run_device_root_script(&serial, "id; getenforce")
            .await
            .expect("run root script");
        assert_eq!(output.code, Some(0), "{}", output.stderr);
        assert!(output.stdout.contains("uid=0(root)"), "{}", output.stdout);
        assert!(
            output.stdout.contains("Enforcing") || output.stdout.contains("Permissive"),
            "{}",
            output.stdout
        );
    }

    #[test]
    fn blocks_compromised_integrity() {
        let decision = evaluate_signal(&signal("integrity", "rooted", Value::Null));
        assert!(!decision.accepted);
        assert_eq!(decision.decision, "block");
        assert_eq!(decision.risk_level, "critical");
    }

    #[test]
    fn sends_medium_score_to_review() {
        let decision = evaluate_signal(&signal("risk_score", "", json!({ "score": 67 })));
        assert!(decision.accepted);
        assert_eq!(decision.decision, "review");
        assert_eq!(decision.risk_level, "medium");
    }
}
