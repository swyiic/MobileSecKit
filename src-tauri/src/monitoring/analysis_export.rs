//! Independent, ordinary files for external tools; never hard-link writable exports to evidence.
use super::*;

fn metadata_path(root: &Path, name: &str) -> PathBuf {
    let path = root.join(name);
    if path.exists() {
        root.join(format!("derived-{}-{name}", Uuid::new_v4()))
    } else {
        path
    }
}

fn preview_bytes(encoding: &str, preview: &str) -> Option<Vec<u8>> {
    if encoding == "hex" {
        let hex: Vec<_> = preview
            .bytes()
            .filter(|b| !b.is_ascii_whitespace())
            .collect();
        if hex.len() % 2 != 0 || !hex.iter().all(u8::is_ascii_hexdigit) {
            return None;
        }
        hex.chunks_exact(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok())
            .collect()
    } else if matches!(encoding, "utf8" | "utf8_lossy" | "utf-8") {
        Some(preview.as_bytes().to_vec())
    } else {
        None
    }
}

fn readable_preview(bytes: &[u8]) -> (String, &'static str) {
    if bytes.starts_with(&[0xff, 0xfe])
        || (bytes.len() >= 8
            && bytes.chunks_exact(2).take(32).filter(|p| p[1] == 0).count() * 4
                >= bytes.len().min(64))
    {
        let raw = if bytes.starts_with(&[0xff, 0xfe]) {
            &bytes[2..]
        } else {
            bytes
        };
        let units: Vec<_> = raw
            .chunks_exact(2)
            .map(|b| u16::from_le_bytes([b[0], b[1]]))
            .collect();
        (String::from_utf16_lossy(&units), "utf16le_display")
    } else {
        (
            String::from_utf8_lossy(bytes).into_owned(),
            "utf8_lossy_display",
        )
    }
}

fn export_plaintext_previews(root: &Path, files: &[Value]) -> Result<(), String> {
    let derived_directory = format!("analysis-derived-{}", Uuid::new_v4());
    let mut index = Vec::new();
    let mut written = 0_usize;
    let mut omissions = Vec::new();
    for file in files {
        let Some(path) = file["path"].as_str() else {
            continue;
        };
        if !(path.starts_with("sessions/") && path.ends_with("/events.json")) {
            continue;
        }
        if file["bytes"].as_u64().unwrap_or(u64::MAX) > 64 * 1024 * 1024 {
            omissions.push(serde_json::json!({"source":path,"reason":"derived_preview_input_limit; original events retained"}));
            continue;
        }
        let raw = read_bounded_text_scoped(&root.join(path), 64 * 1024 * 1024, root)?;
        let events: Value = match serde_json::from_str(&raw) {
            Ok(value) => value,
            Err(_) => {
                omissions.push(serde_json::json!({"source":path,"reason":"events_json_not_decodable; original retained"}));
                continue;
            }
        };
        let Some(rows) = events.as_array() else {
            continue;
        };
        for (event_index, event) in rows.iter().enumerate() {
            if event["payload"]["type"] != "inspect_plaintext" {
                continue;
            }
            if index.len() >= 8192 || written >= 32 * 1024 * 1024 {
                omissions.push(serde_json::json!({"source":path,"reason":"derived_preview_output_limit; all original events retained"}));
                break;
            }
            let payload = &event["payload"]["data"];
            let (Some(preview), Some(encoding)) = (
                payload["preview"].as_str(),
                payload["preview_encoding"].as_str(),
            ) else {
                continue;
            };
            let Some(bytes) = preview_bytes(encoding, preview) else {
                omissions.push(serde_json::json!({"source":path,"eventIndex":event_index,"reason":"unsupported_preview_encoding; original retained"}));
                continue;
            };
            let (text, display_encoding) = readable_preview(&bytes);
            if written
                .saturating_add(bytes.len())
                .saturating_add(text.len())
                > 32 * 1024 * 1024
            {
                omissions.push(serde_json::json!({"source":path,"reason":"derived_preview_output_limit; original retained"}));
                break;
            }
            let directory = format!(
                "{derived_directory}/inspect-plaintext/{:x}",
                Sha256::digest(path.as_bytes())
            );
            std::fs::create_dir_all(root.join(&directory)).map_err(|e| e.to_string())?;
            let binary = format!("{directory}/{event_index}.bin");
            let readable = format!("{directory}/{event_index}.txt");
            session_budget::write(root.join(&binary), &bytes).map_err(|e| e.to_string())?;
            session_budget::write(root.join(&readable), text.as_bytes())
                .map_err(|e| e.to_string())?;
            written += bytes.len() + text.len();
            index.push(serde_json::json!({"source":path,"sourceSha256":file["sha256"],"eventIndex":event_index,"binary":binary,"text":readable,"adapter":payload["adapter"],"direction":payload["direction"],"capturedBytes":payload["captured_bytes"],"truncated":payload["truncated"],"previewEncoding":encoding,"displayEncoding":display_encoding,"scope":"retained Inspect preview only; not a complete HTTP message; utf8_lossy cannot recover original invalid bytes"}));
        }
    }
    session_budget::write_json(metadata_path(root, "inspect-plaintext-index.json"), &serde_json::json!({"schema":"mobilee.external-plaintext-previews/v1","fragments":index,"omissions":omissions,"originalEventsRetained":true})).map(|_| ()).map_err(|e| e.to_string())
}

pub(super) fn export(root: &Path, output: &Path) -> Result<String, String> {
    if !root.is_absolute() || !output.is_absolute() {
        return Err("证据目录和导出目录须为绝对路径".into());
    }
    if std::fs::symlink_metadata(root)
        .map_err(|e| e.to_string())?
        .file_type()
        .is_symlink()
    {
        return Err("证据根目录不能是符号链接".into());
    }
    let root = root.canonicalize().map_err(|e| e.to_string())?;
    let parent = output
        .parent()
        .ok_or("导出目录缺少父目录")?
        .canonicalize()
        .map_err(|e| e.to_string())?;
    let output = parent.join(output.file_name().ok_or("导出目录名称无效")?);
    if output.starts_with(&root) || root.starts_with(&output) || output.exists() {
        return Err("请选择新的独立导出目录；已有证据和文件不会被覆盖".into());
    }
    let staging = parent.join(format!(".me-export-{}", Uuid::new_v4()));
    std::fs::create_dir(&staging).map_err(|e| e.to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&staging, std::fs::Permissions::from_mode(0o700))
            .map_err(|e| e.to_string())?;
    }
    let result = (|| -> Result<(), String> {
        let _budget = session_budget::Guard::install(
            vec![staging.clone()],
            MAX_EVIDENCE_ARCHIVE_BYTES + 64 * 1024 * 1024,
            900_000,
        )
        .map_err(|e| e.to_string())?;
        let files = collect_archive_files_scoped(&root, &staging)?;
        let mut references = Vec::new();
        for (source, relative, expected) in files {
            validate_evidence_relative_path(&relative)?;
            let destination = staging.join(&relative);
            std::fs::create_dir_all(destination.parent().ok_or("导出路径无父目录")?)
                .map_err(|e| e.to_string())?;
            let mut input = session_budget::CheckedReader::new(
                File::open(&source).map_err(|e| e.to_string())?,
                &staging,
            );
            let mut target =
                session_budget::BudgetFile::create(&destination).map_err(|e| e.to_string())?;
            let mut hash = Sha256::new();
            let mut count = 0_u64;
            let mut buffer = [0; 65536];
            loop {
                let n = input.read(&mut buffer).map_err(|e| e.to_string())?;
                if n == 0 {
                    break;
                }
                count = count.checked_add(n as u64).ok_or("导出长度溢出")?;
                if count > expected {
                    return Err("导出期间源文件增长".into());
                }
                std::io::Write::write_all(&mut target, &buffer[..n]).map_err(|e| e.to_string())?;
                hash.update(&buffer[..n]);
            }
            std::io::Write::flush(&mut target).map_err(|e| e.to_string())?;
            if count != expected {
                return Err("导出期间源文件短读".into());
            }
            let digest = format!("{:x}", hash.finalize());
            if archive_objects::digest_scoped(&destination, expected, &staging)? != digest {
                return Err("导出文件 SHA-256 校验失败".into());
            }
            references.push(serde_json::json!({"path":relative,"bytes":count,"sha256":digest}));
        }
        export_plaintext_previews(&staging, &references)?;
        session_budget::write_json(metadata_path(&staging, "analysis-export.json"), &serde_json::json!({"schema":"mobilee.analysis-directory/v1","source":root,"files":references,"independentCopies":true,"coverage":"preserved from original reports; not upgraded by export"})).map_err(|e| e.to_string())?;
        session_budget::write(metadata_path(&staging, "ANALYSIS-HELP.txt"), b"Original paths and bytes are preserved. Open apk-dex/ or readable-dex/ with JADX; open lib/ or runtime/runtime-so/ with ELF tools. runtime/*.code and *.bin are original memory ranges, not automatically complete DEX/ELF files. Consult runtime/bound-source-*.json for source, address, read status and hashes. Partial reads remain partial. Text and plaintext files retain their original encodings. Exported files are independent copies and may be edited without modifying the evidence cache.\n").map_err(|e| e.to_string())?;
        Ok(())
    })();
    if let Err(error) = result {
        return Err(format!(
            "{error}；已导出的部分文件保留在 {}",
            staging.display()
        ));
    }
    std::fs::rename(&staging, &output)
        .map_err(|e| format!("导出文件保留在 {}：{e}", staging.display()))?;
    Ok(output.to_string_lossy().into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ordinary_paths_and_independent_bytes_are_preserved() {
        let base = std::env::temp_dir().join(format!("me-analysis-export-{}", Uuid::new_v4()));
        let root = base.join("source");
        std::fs::create_dir_all(root.join("lib")).unwrap();
        std::fs::write(root.join("lib/libfixture.so"), b"\x7fELFfixture").unwrap();
        std::fs::create_dir_all(root.join("sessions/fixture")).unwrap();
        std::fs::write(root.join("sessions/fixture/events.json"), br#"[{"payload":{"type":"inspect_plaintext","data":{"preview":"485454502f312e31","preview_encoding":"hex","adapter":"tls_ssl_read","direction":"recv","captured_bytes":8,"truncated":false}}}]"#).unwrap();
        let output = base.join("external-tools");
        export(&root, &output).unwrap();
        let index: Value = serde_json::from_slice(
            &std::fs::read(output.join("inspect-plaintext-index.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(index["fragments"].as_array().unwrap().len(), 1);
        assert_eq!(
            std::fs::read_to_string(output.join(index["fragments"][0]["text"].as_str().unwrap()))
                .unwrap(),
            "HTTP/1.1"
        );
        assert_eq!(
            std::fs::read(output.join("lib/libfixture.so")).unwrap(),
            b"\x7fELFfixture"
        );
        std::fs::write(output.join("lib/libfixture.so"), b"edited").unwrap();
        assert_eq!(
            std::fs::read(root.join("lib/libfixture.so")).unwrap(),
            b"\x7fELFfixture"
        );
        assert!(export(&root, &output).is_err());
        let original_index = std::fs::read(output.join("inspect-plaintext-index.json")).unwrap();
        let reexport = base.join("reexport");
        export(&output, &reexport).unwrap();
        assert_eq!(
            std::fs::read(reexport.join("inspect-plaintext-index.json")).unwrap(),
            original_index
        );
        std::fs::remove_dir_all(base).unwrap();
    }
}
