use super::super::{
    cohesive_frida_executable_path, executable_path, format_epoch_millis_filename_utc,
    macho_encryption_state, now_millis, output_text, AdvancedCommandResult, IosDumpRequest,
    RawOutput,
};
use super::android_dump::default_dump_directory;
use super::runtime::{
    normalize_ios_compatibility_profile, write_private_embedded_script, IOS_DUMP_AGENT,
    IOS_DUMP_RUNNER,
};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File},
    io::Read,
    path::{Path, PathBuf},
    time::Duration,
};
use tokio::{process::Command, time::timeout};
use zip::ZipArchive;

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

pub(in crate::advanced) async fn run_ios_dump(
    request: IosDumpRequest,
) -> Result<AdvancedCommandResult, String> {
    if request.serial.trim().is_empty()
        || request.bundle_id.trim().is_empty()
        || !request
            .bundle_id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || ".-_".contains(c))
    {
        return Err("请选择有效的 iOS 设备与 Bundle ID".into());
    }
    let compatibility_profile =
        normalize_ios_compatibility_profile(request.compatibility_profile.as_deref())?;
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
    let started_at = now_millis();
    let output = base.join(format!(
        "{stem}-decrypted-{}.ipa",
        format_epoch_millis_filename_utc(started_at)
    ));
    let run_token = format!(
        "{:x}",
        Sha256::digest(format!(
            "{}:{}:{}:{}",
            started_at,
            std::process::id(),
            request.serial,
            request.bundle_id
        ))
    );
    let temp = std::env::temp_dir().join(format!("me-ios-runner-{started_at}"));
    fs::create_dir_all(&temp).map_err(|error| error.to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&temp, fs::Permissions::from_mode(0o700))
            .map_err(|error| format!("无法限制脚本临时目录权限：{error}"))?;
    }
    let runner = temp.join("runner.py");
    let agent = temp.join("agent.js");
    let bound_runner = IOS_DUMP_RUNNER.replace("__ME_RUN_TOKEN__", &run_token);
    if let Err(error) = write_private_embedded_script(&runner, &bound_runner)
        .and_then(|_| write_private_embedded_script(&agent, IOS_DUMP_AGENT))
    {
        let _ = fs::remove_dir_all(&temp);
        return Err(error);
    }
    let mut args = vec![
        runner.to_string_lossy().into_owned(),
        "--serial".into(),
        request.serial.clone(),
        "--bundle".into(),
        request.bundle_id.clone(),
        "--output".into(),
        output.to_string_lossy().into_owned(),
        "--agent".into(),
        agent.to_string_lossy().into_owned(),
        "--profile".into(),
        compatibility_profile,
    ];
    if let Some(mode) = request.mode.as_deref() {
        if matches!(mode, "spawn" | "attach") {
            args.push("--mode".into());
            args.push(mode.to_string());
        }
    }
    let result = timeout(
        Duration::from_secs(1200),
        Command::new(&python)
            .args(&args)
            .env("ME_EMBEDDED_RUN_TOKEN", &run_token)
            .current_dir(&temp)
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
            "{}\n\n{}\n输出 IPA：{}\n可直接拖入 App Analyzer。\nME_IOS_ARTIFACT_READY",
            output_text(&raw),
            validation,
            output.display()
        ),
        exit_code: raw.code,
    })
}
