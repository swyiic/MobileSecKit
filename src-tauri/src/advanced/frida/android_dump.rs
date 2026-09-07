use super::super::{
    cohesive_frida_executable_path, ensure_success, format_epoch_millis_filename_utc, now_millis,
    output_text, rules, run_adb, run_device_root_script, scan_sensitive_text_with_rules,
    AdvancedCommandResult, DexDumpRequest, RawOutput, SoDumpRequest,
};
use super::runtime::{adapt_frida_17_script, read_script_path, resolve_target};
use serde::{Deserialize, Serialize};
use sha1::{Digest, Sha1};
use sha2::Sha256;
use std::{
    collections::HashSet,
    fs::{self, File},
    io::Write,
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};
use tokio::{
    io::AsyncReadExt,
    process::Command,
    time::{sleep, timeout},
};
use zip::{write::SimpleFileOptions, ZipWriter};

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

fn append_dump_target(
    args: &mut Vec<String>,
    mode: Option<&str>,
    pid: Option<u32>,
    package: &str,
) -> Result<&'static str, String> {
    match mode.unwrap_or("spawn").to_ascii_lowercase().as_str() {
        "spawn" => {
            args.extend(["-f".into(), package.into()]);
            Ok("Spawn")
        }
        "attach" => {
            if let Some(pid) = pid.filter(|value| *value > 0) {
                args.extend(["-p".into(), pid.to_string()]);
            } else {
                args.extend(["-N".into(), package.into()]);
            }
            Ok("Attach")
        }
        _ => Err("DEX/SO Dump 模式只能是 attach 或 spawn".into()),
    }
}

async fn run_frida_with_timeout(
    args: &[String],
    duration: Duration,
    workflow: &str,
) -> Result<RawOutput, String> {
    let executable = cohesive_frida_executable_path("frida")
        .ok_or_else(|| "未找到 frida，请先安装 Frida Tools".to_string())?;
    let mut command = Command::new(executable);
    command
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    let mut child = command
        .spawn()
        .map_err(|error| format!("启动 Frida {workflow} 失败：{error}"))?;
    let mut stdout = child
        .stdout
        .take()
        .ok_or_else(|| format!("无法读取 Frida {workflow} 标准输出"))?;
    let mut stderr = child
        .stderr
        .take()
        .ok_or_else(|| format!("无法读取 Frida {workflow} 错误输出"))?;
    let stdout_task = tokio::spawn(async move {
        let mut bytes = Vec::new();
        stdout.read_to_end(&mut bytes).await.map(|_| bytes)
    });
    let stderr_task = tokio::spawn(async move {
        let mut bytes = Vec::new();
        stderr.read_to_end(&mut bytes).await.map(|_| bytes)
    });

    let (code, timed_out) = match timeout(duration, child.wait()).await {
        Ok(result) => (
            result
                .map_err(|error| format!("等待 Frida {workflow} 失败：{error}"))?
                .code(),
            false,
        ),
        Err(_) => {
            let _ = child.kill().await;
            let _ = child.wait().await;
            (None, true)
        }
    };
    let stdout = stdout_task
        .await
        .map_err(|error| format!("读取 Frida {workflow} 输出任务失败：{error}"))?
        .map_err(|error| format!("读取 Frida {workflow} 输出失败：{error}"))?;
    let stderr = stderr_task
        .await
        .map_err(|error| format!("读取 Frida {workflow} 错误任务失败：{error}"))?
        .map_err(|error| format!("读取 Frida {workflow} 错误失败：{error}"))?;
    let mut stderr = String::from_utf8_lossy(&stderr).trim().to_string();
    if timed_out {
        if !stderr.is_empty() {
            stderr.push('\n');
        }
        stderr.push_str(&format!(
            "{workflow} 会话达到等待上限，已停止 Frida 会话并继续回收设备端已有产物"
        ));
    }
    Ok(RawOutput {
        stdout: String::from_utf8_lossy(&stdout).trim().to_string(),
        stderr,
        code,
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

pub(super) fn default_dump_directory(package: &str) -> PathBuf {
    let home = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    home.join("Desktop")
        .join("MobileE-Dumps")
        .join(package)
        .join(format_epoch_millis_filename_utc(now_millis()))
}

async fn mirror_remote_dump(
    serial: &str,
    remote_files: &[&str],
    prefix: &str,
    remote_export: &str,
    seconds: u64,
) {
    let sources = remote_files
        .iter()
        .map(|root| format!("{root}/{prefix}*"))
        .collect::<Vec<_>>()
        .join(" ");
    let script = format!(
        "for dir in {sources}; do if [ -d \"$dir\" ]; then cp -R \"$dir\"/. {remote_export}/ 2>/dev/null || echo \"无法镜像 $dir\" >&2; chmod -R a+rX {remote_export} 2>/dev/null || true; fi; done"
    );
    for _ in 0..=seconds {
        let _ = run_device_root_script(serial, &script).await;
        sleep(Duration::from_secs(1)).await;
    }
}

pub(in crate::advanced) async fn run_dex_dump(
    request: DexDumpRequest,
) -> Result<AdvancedCommandResult, String> {
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
    let remote_files = format!("/sdcard/Android/data/{package}/files");
    let legacy_remote_files = format!("/data/data/{package}/files");
    let prepare = run_device_root_script(
        &request.serial,
        &format!(
            "mkdir -p {remote_files} || exit $?; rm -rf {remote_files}/dump_dex_*; if [ -d {legacy_remote_files} ]; then rm -rf {legacy_remote_files}/dump_dex_* 2>/dev/null || echo 'SELinux 阻止清理 App 私有 DEX 目录，继续使用外部专属目录' >&2; fi"
        ),
    )
    .await?;
    ensure_success(prepare)?;

    let script_text = script_text.replace("__ME_PACKAGE__", package);
    let (adapted_script, compatibility_changes) = adapt_frida_17_script(&script_text);
    let runtime_script = std::env::temp_dir().join(format!("me-dex-dump-{}.js", now_millis()));
    fs::write(&runtime_script, adapted_script)
        .map_err(|error| format!("创建 Frida 17 兼容脚本失败：{error}"))?;
    let (mut args, frida_endpoint) = resolve_target(&Some(request.serial.clone())).await;
    let launch_mode = append_dump_target(&mut args, request.mode.as_deref(), request.pid, package)?;
    args.extend([
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
    let frida_future =
        run_frida_with_timeout(&args, Duration::from_secs(duration + 15), "DEX Dump");
    let dump_roots = [&remote_files[..], &legacy_remote_files[..]];
    let mirror_future = mirror_remote_dump(
        &request.serial,
        &dump_roots,
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
        "for dir in {remote_files}/dump_dex_* {legacy_remote_files}/dump_dex_*; do if [ -d \"$dir\" ]; then cp -R \"$dir\"/. {remote_export}/ 2>/dev/null || echo \"无法读取 $dir（可能被 SELinux 拒绝）\" >&2; fi; done; chmod -R a+rX {remote_export}; count=$(find {remote_export} -type f -name '*.dex' | wc -l); if [ \"$count\" -lt 1 ]; then echo '未发现 DEX 产物：请先确认 Frida 日志出现 [ME_DEX_READY] 或 [ME_DEX_SCAN]；若脚本已就绪，请在等待时间内操作 App 触发加固代码加载' >&2; exit 2; fi; find {remote_export} -type f -name '*.dex' -print"
    );
    let collected = run_device_root_script(&request.serial, &collect_script).await?;
    if collected.code != Some(0) {
        return Ok(AdvancedCommandResult {
            success: false,
            command: format!("adb -s {} collect DEX", request.serial),
            output: format!(
                "DEX Dump 未生成可回收产物。\n连接通道：{frida_endpoint}\nFrida 日志：\n{}\n回收日志：\n{}",
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
            "[1/4] Frida {launch_mode} 完成{}{}\n{}\n[2/4] 手机端 DEX 已拉回：{}\n[3/4] 已修复 header/signature/checksum，去重后 {} 个，无效 {} 个\n[4/4] Multidex 合集：{}\nME_DEX_ARTIFACT_READY",
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
    let rule_set = rules::load_rules(None)?;
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
            let strings = super::super::extracted_binary_strings(&bytes, 5);
            scan_sensitive_text_with_rules(
                &strings,
                &path.to_string_lossy(),
                &mut items,
                &rule_set,
                "binary-strings",
            );
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

pub(in crate::advanced) async fn run_so_dump(
    request: SoDumpRequest,
) -> Result<AdvancedCommandResult, String> {
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
    let remote_files = format!("/sdcard/Android/data/{package}/files");
    let legacy_remote_files = format!("/data/data/{package}/files");
    ensure_success(
        run_device_root_script(
            &request.serial,
            &format!(
                "mkdir -p {remote_files} || exit $?; rm -rf {remote_files}/dump_so_*; if [ -d {legacy_remote_files} ]; then rm -rf {legacy_remote_files}/dump_so_* 2>/dev/null || echo 'SELinux 阻止清理 App 私有 SO 目录，继续使用外部专属目录' >&2; fi"
            ),
        )
        .await?,
    )?;

    let script_text = script_text.replace("__ME_PACKAGE__", package);
    let (adapted_script, compatibility_changes) = adapt_frida_17_script(&script_text);
    let runtime_script = std::env::temp_dir().join(format!("me-so-dump-{}.js", now_millis()));
    fs::write(&runtime_script, adapted_script)
        .map_err(|error| format!("创建 SO Dump 临时脚本失败：{error}"))?;
    let (mut args, frida_endpoint) = resolve_target(&Some(request.serial.clone())).await;
    let launch_mode = append_dump_target(&mut args, request.mode.as_deref(), request.pid, package)?;
    args.extend([
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
    let frida_future = run_frida_with_timeout(&args, Duration::from_secs(duration + 15), "SO Dump");
    let dump_roots = [&remote_files[..], &legacy_remote_files[..]];
    let mirror_future = mirror_remote_dump(
        &request.serial,
        &dump_roots,
        "dump_so_",
        &remote_export,
        duration + 3,
    );
    let (frida_result, _) = tokio::join!(frida_future, mirror_future);
    let _ = fs::remove_file(&runtime_script);
    let frida_output = frida_result?;

    let collected = run_device_root_script(
        &request.serial,
        &format!("for dir in {remote_files}/dump_so_* {legacy_remote_files}/dump_so_*; do if [ -d \"$dir\" ]; then cp -R \"$dir\"/. {remote_export}/ 2>/dev/null || echo \"无法读取 $dir（可能被 SELinux 拒绝）\" >&2; fi; done; chmod -R a+rX {remote_export}; count=$(find {remote_export} -type f | wc -l); if [ \"$count\" -lt 1 ]; then echo '未发现 SO 内存产物：请先确认 Frida 日志出现 [ME_SO_READY]，然后在等待时间内操作 App 触发动态库加载' >&2; exit 2; fi; find {remote_export} -type f -print"),
    )
    .await?;
    if collected.code != Some(0) {
        return Ok(AdvancedCommandResult {
            success: false,
            command: format!("adb -s {} collect SO", request.serial),
            output: format!(
                "SO Dump 未生成可回收产物。\n连接通道：{frida_endpoint}\nFrida 日志：\n{}\n回收日志：\n{}",
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
            "[1/4] SO Dump {launch_mode} 会话完成{}\n{}\n[2/4] 已拉回 {}\n[3/4] 已按 ELF PT_LOAD 重建 {}/{} 个模块\n重建目录：{}\n重建报告：{}\n[4/4] 扫描 {} 个内存分段，发现 {} 条敏感线索\n敏感信息报告：{}\nME_SO_ARTIFACT_READY",
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
