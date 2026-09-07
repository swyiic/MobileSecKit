use super::super::{
    ensure_success, output_text, run_adb, run_device_adb, run_device_root_script, run_host,
    AdvancedCommandResult, FridaDownloadRequest, FridaServerRequest, RawOutput,
};
use std::{
    fs,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

const HARDENED_SERVER_NAME: &str = "myfs";
const HARDENED_PORT_STATE: &str = "/data/local/tmp/myfs.port";

pub(super) async fn hardened_port(serial: &str) -> Option<u16> {
    let output = run_device_root_script(
        serial,
        &format!("cat {HARDENED_PORT_STATE} 2>/dev/null || true"),
    )
    .await
    .ok()?;
    output
        .stdout
        .lines()
        .map(str::trim)
        .find_map(|value| value.parse::<u16>().ok())
        .filter(|port| (20_000..45_000).contains(port))
}

async fn remove_forward(serial: &str, port: u16) {
    let _ = run_adb(&[
        "-s".into(),
        serial.into(),
        "forward".into(),
        "--remove".into(),
        format!("tcp:{port}"),
    ])
    .await;
}

fn random_hardened_port() -> u16 {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    20_000 + (millis % 25_000) as u16
}

fn parse_frida_version(output: &RawOutput, source: &str) -> Result<String, String> {
    if output.code != Some(0) {
        return Err(format!(
            "读取{source} Frida 版本失败：{}",
            output_text(output)
        ));
    }
    output
        .stdout
        .lines()
        .chain(output.stderr.lines())
        .map(str::trim)
        .find(|line| {
            !line.is_empty()
                && line
                    .chars()
                    .next()
                    .is_some_and(|character| character.is_ascii_digit())
                && line
                    .chars()
                    .all(|character| character.is_ascii_alphanumeric() || ".-_".contains(character))
        })
        .map(str::to_owned)
        .ok_or_else(|| format!("无法从{source}输出解析 Frida 版本：{}", output_text(output)))
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

pub(in crate::advanced) async fn manage_frida_server(
    request: FridaServerRequest,
) -> Result<AdvancedCommandResult, String> {
    let mut command_override = None;
    let output = match request.action.as_str() {
        "start" => {
            let path = validate_frida_binary(
                request
                    .path
                    .as_deref()
                    .ok_or("请选择本机 Frida-server 文件")?,
            )?;
            let old_hardened_port = hardened_port(&request.serial).await;
            // Stop the old process before replacing its executable. Pushing on
            // top of a running frida-server can stall `adb push` and leave the
            // destination truncated or missing.
            let stopped = run_device_root_script(
                &request.serial,
                &format!("pids=$(pidof frida-server 2>/dev/null || true); renamed=$(pidof {HARDENED_SERVER_NAME} 2>/dev/null || true); if [ -n \"$pids\" ] || [ -n \"$renamed\" ]; then kill $pids $renamed 2>/dev/null || true; sleep 1; fi; rm -f {HARDENED_PORT_STATE}"),
            )
            .await?;
            if stopped.code != Some(0) {
                return Err(format!(
                    "停止旧 Frida-server 失败：{}",
                    output_text(&stopped)
                ));
            }
            if let Some(port) = old_hardened_port {
                remove_forward(&request.serial, port).await;
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
uid=$(awk '/^Uid:/{{print $2}}' /proc/$pid/status 2>/dev/null)
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
            let port = hardened_port(&request.serial).await;
            let stopped = run_device_root_script(
                &request.serial,
                &format!("pids=$(pidof frida-server 2>/dev/null || true); renamed_pids=$(pidof {HARDENED_SERVER_NAME} 2>/dev/null || true); all_pids=\"$pids $renamed_pids\"; if [ -n \"$pids\" ] || [ -n \"$renamed_pids\" ]; then kill $all_pids 2>/dev/null || true; sleep 1; echo \"已停止 $all_pids\"; else echo \"Frida-server 未运行\"; fi; rm -f {HARDENED_PORT_STATE}"),
            )
            .await?;
            if let Some(port) = port {
                remove_forward(&request.serial, port).await;
            }
            RawOutput {
                stdout: format!(
                    "{}\n{}",
                    output_text(&stopped),
                    port.map(|value| format!(
                        "已移除 adb forward tcp:{value} 并清理 {HARDENED_PORT_STATE}"
                    ))
                    .unwrap_or_else(|| format!("未发现端口状态；已清理 {HARDENED_PORT_STATE}"))
                ),
                stderr: stopped.stderr,
                code: stopped.code,
            }
        }
        "harden" => {
            // Compare the exact client/server versions before changing any device
            // state. A transport that starts successfully can still fail during
            // injection when the Frida major/minor versions differ.
            let host_version_output = run_host("frida", &["--version".into()]).await?;
            let host_version = parse_frida_version(&host_version_output, "电脑端")?;
            let device_version_output = run_device_root_script(
                &request.serial,
                "/data/local/tmp/frida-server --version 2>&1",
            )
            .await?;
            let device_version =
                parse_frida_version(&device_version_output, "设备端 frida-server")?;
            if host_version != device_version {
                return Err(format!(
                    "[版本检查] client={host_version} / server={device_version} ❌ 不一致\n未执行一键对抗：请先推送与电脑端 Frida 完全一致的 frida-server。"
                ));
            }

            if let Some(old_port) = hardened_port(&request.serial).await {
                remove_forward(&request.serial, old_port).await;
            }
            let cleanup = run_device_root_script(
                &request.serial,
                &format!("pids=$(pidof frida-server 2>/dev/null || true); renamed=$(pidof {HARDENED_SERVER_NAME} 2>/dev/null || true); if [ -n \"$pids\" ] || [ -n \"$renamed\" ]; then kill $pids $renamed 2>/dev/null || true; fi; rm -f {HARDENED_PORT_STATE}; sleep 1"),
            )
            .await?;
            if cleanup.code != Some(0) {
                return Err(format!("清理旧 Frida 服务失败：{}", output_text(&cleanup)));
            }

            let first_port = random_hardened_port();
            let mut started = None;
            let mut attempts = Vec::new();
            for offset in 0..5u16 {
                let port = 20_000 + ((first_port - 20_000 + offset) % 25_000);
                let forward = run_adb(&[
                    "-s".into(),
                    request.serial.clone(),
                    "forward".into(),
                    format!("tcp:{port}"),
                    format!("tcp:{port}"),
                ])
                .await?;
                if forward.code != Some(0) {
                    attempts.push(format!(
                        "tcp:{port} host forward：{}",
                        output_text(&forward)
                    ));
                    continue;
                }
                let start = run_device_root_script(
                    &request.serial,
                    &format!(
                        r#"if [ "$(id -u)" != "0" ]; then echo "Root 未生效，无法启动 Frida-server" >&2; exit 126; fi
[ -f /data/local/tmp/frida-server ] || {{ echo "/data/local/tmp/frida-server 不存在，请先推送并启动" >&2; exit 1; }}
cp -f /data/local/tmp/frida-server /data/local/tmp/{name} || exit $?
chmod 755 /data/local/tmp/{name} || exit $?
chown 0:0 /data/local/tmp/{name} 2>/dev/null || true
rm -f /data/local/tmp/{name}.log
nohup /data/local/tmp/{name} -l 127.0.0.1:{port} </dev/null >/data/local/tmp/{name}.log 2>&1 &
pid=$!
sleep 1
if ! kill -0 "$pid" 2>/dev/null; then echo "{name} 启动失败，设备端端口 {port} 可能已占用" >&2; tail -n 30 /data/local/tmp/{name}.log >&2; exit 1; fi
uid=$(awk '/^Uid:/{{print $2}}' /proc/$pid/status 2>/dev/null)
if [ "$uid" != "0" ]; then kill "$pid" 2>/dev/null || true; echo "{name} 未以 Root 身份运行" >&2; exit 126; fi
echo {port} > {state} || exit $?
echo "{name} PID=$pid UID=$uid PORT={port} SELinux=$(getenforce 2>/dev/null || echo unknown)"
tail -n 20 /data/local/tmp/{name}.log 2>/dev/null || true"#,
                        name = HARDENED_SERVER_NAME,
                        state = HARDENED_PORT_STATE,
                    ),
                )
                .await?;
                if start.code == Some(0) {
                    started = Some((port, start));
                    break;
                }
                attempts.push(format!("tcp:{port} device server：{}", output_text(&start)));
                remove_forward(&request.serial, port).await;
            }
            let Some((port, start)) = started else {
                return Err(format!(
                    "随机端口连续 5 次启动失败：\n{}",
                    attempts.join("\n")
                ));
            };

            let renamed_version_output = run_device_root_script(
                &request.serial,
                &format!("/data/local/tmp/{HARDENED_SERVER_NAME} --version 2>&1"),
            )
            .await?;
            let renamed_version = parse_frida_version(&renamed_version_output, "设备端改名服务")?;
            if renamed_version != host_version {
                let _ = run_device_root_script(
                    &request.serial,
                    &format!(
                        "pids=$(pidof {HARDENED_SERVER_NAME} 2>/dev/null || true); [ -n \"$pids\" ] && kill $pids 2>/dev/null || true"
                    ),
                )
                .await;
                remove_forward(&request.serial, port).await;
                return Err(format!(
                    "[版本检查] client={host_version} / server={renamed_version} ❌ 改名后版本异常，已停止 {HARDENED_SERVER_NAME} 并移除端口转发"
                ));
            }

            let verify = run_adb(&[
                "-s".into(),
                request.serial.clone(),
                "forward".into(),
                "--list".into(),
            ])
            .await?;
            let forward_marker = format!("{} tcp:{port} tcp:{port}", request.serial);
            if verify.code != Some(0) || !output_text(&verify).contains(&forward_marker) {
                return Err(format!(
                    "{HARDENED_SERVER_NAME} 已启动，但未确认 adb forward：{}",
                    output_text(&verify)
                ));
            }

            command_override = Some(format!(
                "adb -s {} forward tcp:{port} tcp:{port} && frida -H 127.0.0.1:{port}",
                request.serial
            ));
            RawOutput {
                stdout: format!(
                    "[环境层] {HARDENED_SERVER_NAME}:{port} ✅ 已应用（改名 + 随机端口 + adb forward）\n[版本检查] client={host_version} / server={renamed_version} ✅ 一致\n[端口状态] {HARDENED_PORT_STATE} = {port}\n[连接方式] frida -H 127.0.0.1:{port}\n[验证命令] frida-ps -H 127.0.0.1:{port} -ai\n\n[设备详情]\n{}\n\n[端口转发]\n{}",
                    output_text(&start),
                    output_text(&verify),
                ),
                stderr: String::new(),
                code: Some(0),
            }
        }
        "log" => {
            let port = hardened_port(&request.serial).await;
            run_device_root_script(
                &request.serial,
                &format!("pid=$(pidof frida-server 2>/dev/null | awk '{{print $1}}'); renamed_pid=$(pidof myfs 2>/dev/null | awk '{{print $1}}'); active_pid=\"${{pid:-$renamed_pid}}\"; if [ -n \"$active_pid\" ]; then uid=$(awk '/^Uid:/{{print $2}}' /proc/$active_pid/status); echo \"Frida-server PID=$active_pid UID=$uid PORT={} SELinux=$(getenforce 2>/dev/null || echo unknown)\"; else echo \"Frida-server 未运行\"; fi; tail -n 100 /data/local/tmp/frida-server.log 2>/dev/null || true; tail -n 100 /data/local/tmp/myfs.log 2>/dev/null || true", port.map(|value| value.to_string()).unwrap_or_else(|| "standard/unknown".into())),
            )
            .await?
        }
        _ => return Err("Frida-server 操作只能是 start、stop、log 或 harden".into()),
    };
    Ok(AdvancedCommandResult {
        success: output.code == Some(0),
        command: command_override.unwrap_or_else(|| {
            format!("adb -s {} frida-server {}", request.serial, request.action)
        }),
        output: output_text(&output),
        exit_code: output.code,
    })
}

pub(in crate::advanced) async fn install_frida_tools() -> Result<AdvancedCommandResult, String> {
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

pub(in crate::advanced) async fn download_frida_server(
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
        .unwrap_or_else(|| std::env::temp_dir().join("mobilee"));
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
