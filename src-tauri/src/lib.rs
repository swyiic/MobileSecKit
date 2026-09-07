use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::OnceLock;
use tokio::{
    process::Command,
    sync::Mutex,
    time::{timeout, Duration},
};

mod advanced;
mod config;
mod monitoring;

pub(crate) const ADB_TIMEOUT: Duration = Duration::from_secs(20);
static ADB_COMMAND_GATE: OnceLock<Mutex<()>> = OnceLock::new();

fn adb_command_gate() -> &'static Mutex<()> {
    ADB_COMMAND_GATE.get_or_init(|| Mutex::new(()))
}

fn prewarm_adb_server() -> Result<(), String> {
    let output = std::process::Command::new("adb")
        .arg("start-server")
        .output()
        .map_err(|error| format!("无法启动 adb server：{error}"))?;
    if output.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    Err(if stderr.is_empty() { stdout } else { stderr })
}

async fn bounded_command_output(
    program: &str,
    args: &[&str],
) -> Result<std::process::Output, String> {
    let mut command = Command::new(program);
    command.args(args).kill_on_drop(true);
    timeout(ADB_TIMEOUT, command.output())
        .await
        .map_err(|_| format!("{program} 操作超时"))?
        .map_err(|error| format!("无法启动 {program}：{error}"))
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

pub(crate) struct RawOutput {
    pub(crate) stdout: String,
    pub(crate) stderr: String,
    pub(crate) code: Option<i32>,
}

async fn run_adb_once(args: &[String]) -> Result<std::process::Output, String> {
    let mut command = Command::new("adb");
    command.args(args).kill_on_drop(true);
    timeout(ADB_TIMEOUT, command.output())
        .await
        .map_err(|_| "ADB 操作超时，请检查手机连接状态".to_string())?
        .map_err(|error| format!("无法启动 adb：{error}。请先安装 Android platform-tools"))
}

fn is_adb_daemon_failure(output: &std::process::Output) -> bool {
    let message = format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
    .to_ascii_lowercase();
    message.contains("server didn't ack")
        || message.contains("cannot connect to daemon")
        || message.contains("failed to check server version")
        || message.contains("protocol fault")
}

pub(crate) async fn run_adb(args: &[String]) -> Result<RawOutput, String> {
    // If the daemon is absent, every concurrent adb client otherwise tries to
    // become the server. macOS then reports USB interface ownership failures
    // and none of the competing daemons survives. Keep the complete command
    // behind one process-wide gate; normal adb calls are short and the device
    // detail fan-out remains fast enough while startup/restart stays reliable.
    let _guard = adb_command_gate().lock().await;
    let mut output = run_adb_once(args).await?;
    if !output.status.success() && is_adb_daemon_failure(&output) {
        // Recovery is deliberately limited to daemon-transport failures. Do
        // not restart a healthy server for ordinary device/command errors.
        let _ = Command::new("adb")
            .arg("kill-server")
            .kill_on_drop(true)
            .output()
            .await;
        let start = Command::new("adb")
            .arg("start-server")
            .kill_on_drop(true)
            .output()
            .await
            .map_err(|error| format!("ADB daemon 自动恢复失败：{error}"))?;
        if start.status.success() {
            output = run_adb_once(args).await?;
        }
    }

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
    let frida_label = bounded_command_output("frida-ls-devices", &[])
        .await
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| {
            String::from_utf8_lossy(&output.stdout)
                .lines()
                .skip(2)
                .find_map(|line| {
                    let fields = line.split_whitespace().collect::<Vec<_>>();
                    (fields.first().copied()? == serial && fields.len() >= 3)
                        .then(|| fields[2..].join(" "))
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
        architecture: info
            .get("CPUArchitecture")
            .cloned()
            .unwrap_or_else(|| "arm64 / Apple mobile".into()),
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
    let adb = run_adb(&["devices".into(), "-l".into()]).await?;
    if adb.code != Some(0) {
        let detail = if adb.stderr.is_empty() {
            adb.stdout
        } else {
            adb.stderr
        };
        return Err(format!(
            "ADB 设备扫描失败：{}。MobileE 已限制并发启动；请确认 USB 连接后再次刷新。",
            if detail.is_empty() {
                "adb 未返回错误详情"
            } else {
                detail.as_str()
            }
        ));
    }
    let adb_stdout = adb.stdout;
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
    let mut wired_ios = Vec::new();
    if let Ok(ios) = bounded_command_output("idevice_id", &["-l"]).await {
        if ios.status.success() {
            for serial in String::from_utf8_lossy(&ios.stdout)
                .lines()
                .map(str::trim)
                .filter(|line| !line.is_empty())
            {
                let info = idevice_info(serial).await.unwrap_or_default();
                wired_ios.push(DeviceSummary {
                    platform: "ios".into(),
                    serial: serial.to_string(),
                    status: "device".into(),
                    model: info
                        .get("DeviceName")
                        .cloned()
                        .unwrap_or_else(|| "iPhone / iOS".into()),
                    product: info
                        .get("ProductType")
                        .cloned()
                        .unwrap_or_else(|| "iOS".into()),
                    device: "iphone".into(),
                    transport_id: Some("usb".into()),
                });
            }
        }
    }
    // A real usbmuxd device is authoritative even when frida-server is absent or
    // version-mismatched. Device inventory must not disappear merely because a
    // runtime instrumentation channel is temporarily unavailable.
    if !wired_ios.is_empty() {
        devices.extend(wired_ios);
    } else if let Ok(frida_devices) = bounded_command_output("frida-ls-devices", &[]).await {
        let mut ios_candidates: HashMap<String, (String, String)> = HashMap::new();
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
        "install_apk" => {
            if argument.is_empty() {
                return Err("请选择要安装的 APK 文件".into());
            }
            vec!["install", "-r", argument.as_str()]
        }
        "uninstall_apk" => {
            validate_package_name(&argument)?;
            vec!["uninstall", argument.as_str()]
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

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PullFilesRequest {
    serial: String,
    remote_path: String,
    local_dir: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PushFileRequest {
    serial: String,
    local_path: String,
}

#[tauri::command]
async fn pull_device_files(request: PullFilesRequest) -> Result<CommandResult, String> {
    if request.remote_path.trim().is_empty() {
        return Err("远程路径不能为空".into());
    }
    if request.local_dir.trim().is_empty() {
        return Err("本地目录不能为空".into());
    }
    std::fs::create_dir_all(&request.local_dir)
        .map_err(|error| format!("无法创建本地目录 {}：{error}", request.local_dir))?;
    let mut command = Command::new("adb");
    command
        .args([
            "-s",
            request.serial.as_str(),
            "pull",
            request.remote_path.as_str(),
            request.local_dir.as_str(),
        ])
        .kill_on_drop(true);
    let output = timeout(Duration::from_secs(300), command.output())
        .await
        .map_err(|_| "拉取超时（300 秒）".to_string())?
        .map_err(|error| format!("无法启动 adb：{error}"))?;
    let success = output.status.success();
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    let text = match (stdout.is_empty(), stderr.is_empty()) {
        (false, false) => format!("{stdout}\n{stderr}"),
        (false, true) => stdout,
        (true, false) => stderr,
        (true, true) => String::new(),
    };
    Ok(CommandResult {
        success,
        command: format!(
            "adb -s {} pull {} {}",
            request.serial, request.remote_path, request.local_dir
        ),
        output: if text.is_empty() {
            "拉取完成".into()
        } else {
            text
        },
        exit_code: output.status.code(),
    })
}

#[tauri::command]
async fn push_device_file(request: PushFileRequest) -> Result<CommandResult, String> {
    let local_path = std::path::Path::new(request.local_path.trim());
    if !local_path.is_file() {
        return Err("请选择一个存在的本地文件".into());
    }
    let file_name = local_path
        .file_name()
        .and_then(std::ffi::OsStr::to_str)
        .filter(|value| !value.is_empty())
        .ok_or("无法解析本地文件名")?;
    let remote_path = format!("/storage/emulated/0/Download/{file_name}");
    let mut command = Command::new("adb");
    command
        .args([
            "-s",
            request.serial.as_str(),
            "push",
            request.local_path.as_str(),
            remote_path.as_str(),
        ])
        .kill_on_drop(true);
    let output = timeout(Duration::from_secs(300), command.output())
        .await
        .map_err(|_| "推送超时（300 秒）".to_string())?
        .map_err(|error| format!("无法启动 adb：{error}"))?;
    let success = output.status.success();
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    let text = match (stdout.is_empty(), stderr.is_empty()) {
        (false, false) => format!("{stdout}\n{stderr}"),
        (false, true) => stdout,
        (true, false) => stderr,
        (true, true) => String::new(),
    };
    Ok(CommandResult {
        success,
        command: format!(
            "adb -s {} push {} {}",
            request.serial, request.local_path, remote_path
        ),
        output: if text.is_empty() {
            format!("已推送到 {remote_path}")
        } else {
            text
        },
        exit_code: output.status.code(),
    })
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let _ = advanced::initialize_host_environment(None);
    if let Err(error) = prewarm_adb_server() {
        eprintln!("MobileE ADB prewarm failed: {error}");
    }
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_dialog::init())
        .manage(monitoring::MirrorSessionState::default())
        .invoke_handler(tauri::generate_handler![
            list_devices,
            get_ios_device_details,
            get_device_details,
            list_processes,
            run_adb_action,
            pull_device_files,
            push_device_file,
            advanced::inspect_environment,
            advanced::configure_host_environment,
            advanced::run_shell,
            advanced::run_proxy,
            advanced::certificate_info,
            advanced::install_certificate,
            advanced::list_frida_processes,
            advanced::list_frida_scripts,
            advanced::run_frida_script,
            advanced::confirm_anti_instrumentation,
            advanced::run_dex_dump,
            advanced::run_so_dump,
            advanced::run_ios_dump,
            advanced::manage_frida_server,
            advanced::download_frida_server,
            advanced::install_frida_tools,
            advanced::open_environment_terminal,
            advanced::mount_ios_developer_image,
            advanced::analyze_app,
            advanced::export_analysis_html,
            advanced::export_analysis_html_compact,
            advanced::export_sensitive_value,
            advanced::save_analysis_case,
            advanced::load_analysis_case,
            advanced::compare_analysis_case,
            advanced::list_ai_task_templates,
            advanced::list_task_templates,
            advanced::list_knowledge,
            advanced::add_pattern,
            advanced::merge_pattern,
            advanced::export_knowledge,
            advanced::import_knowledge,
            advanced::list_rules,
            advanced::list_exclusions,
            advanced::merge_exclusion,
            advanced::build_ai_context_pack,
            advanced::export_ai_context_pack,
            advanced::validate_ai_analysis_result,
            advanced::test_ai_provider,
            advanced::run_ai_security_review,
            config::load_app_config,
            config::save_app_config,
            monitoring::probe_android_monitor_capabilities,
            monitoring::provision_latest_kernsight_agent,
            monitoring::get_kernsight_overview,
            monitoring::get_kernsight_session_report,
            monitoring::cleanup_kernsight_session,
            monitoring::get_kernsight_session_events,
            monitoring::start_kernsight_capture,
            monitoring::start_kernsight_mirror,
            monitoring::stop_kernsight_mirror,
            monitoring::kernsight_mirror_status,
            monitoring::dump_kernsight_package,
            monitoring::list_kernsight_package_dumps,
            monitoring::read_kernsight_package_file,
            monitoring::import_kernsight_evidence_directory,
            monitoring::pull_kernsight_package_evidence,
            monitoring::read_local_kernsight_evidence_file,
            monitoring::cleanup_kernsight_package_dump,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
