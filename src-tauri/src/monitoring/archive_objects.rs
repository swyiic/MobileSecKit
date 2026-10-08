//! v2 archives store full content once and keep every logical evidence path.
//! v1 import remains supported by the caller; no ZIP header alias tricks.
pub(super) const REFERENCE_METADATA_LIMIT: u64 = 24 * 1024 * 1024;

use super::*;
use serde_json::json;
const SCHEMA: &str = "mobilee.kernsight-evidence/v2";
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Reference {
    path: String,
    sha256: String,
    bytes: u64,
}
fn digest(path: &Path, expected: u64) -> Result<String, String> {
    let mut source = File::open(path).map_err(|e| format!("读取失败 {}: {e}", path.display()))?;
    let mut hash = Sha256::new();
    let mut count = 0u64;
    let mut buf = [0; 65536];
    loop {
        let n = source
            .read(&mut buf)
            .map_err(|e| format!("读取失败 {}: {e}", path.display()))?;
        if n == 0 {
            break;
        }
        count = count.checked_add(n as u64).ok_or("字节数溢出")?;
        if count > expected {
            return Err("源文件读取期间增长，未生成成功归档".into());
        }
        hash.update(&buf[..n]);
    }
    if count != expected {
        return Err("源文件短读/变更，未生成成功归档".into());
    }
    Ok(format!("{:x}", hash.finalize()))
}
fn equal(a: &Path, b: &Path) -> Result<bool, String> {
    let mut a = File::open(a).map_err(|e| e.to_string())?;
    let mut b = File::open(b).map_err(|e| e.to_string())?;
    let mut x = [0; 65536];
    let mut y = [0; 65536];
    loop {
        let n = a.read(&mut x).map_err(|e| e.to_string())?;
        let m = b.read(&mut y[..n]).map_err(|e| e.to_string())?;
        if n != m || x[..n] != y[..m] {
            return Ok(false);
        }
        if n == 0 {
            let mut last = [0];
            return b.read(&mut last).map(|n| n == 0).map_err(|e| e.to_string());
        }
    }
}
pub(super) fn write(root: &Path, output: &Path) -> Result<(), String> {
    write_scoped(root, output, false)
}
pub(super) fn write_local_retained(root: &Path, output: &Path) -> Result<(), String> {
    write_scoped(root, output, true)
}
fn write_scoped(root: &Path, output: &Path, offline_retained: bool) -> Result<(), String> {
    if output.exists() {
        return Err("输出归档已存在；保留原件，请使用新路径或只读导入复用".into());
    }
    if std::fs::symlink_metadata(root)
        .map_err(|e| e.to_string())?
        .file_type()
        .is_symlink()
    {
        return Err("引用归档根是符号链接，拒绝读取".into());
    }
    let limits_path = root.join("archive-output-limits.json");
    let mut limits: Option<Value> = if limits_path.is_file() {
        Some(
            serde_json::from_str(&read_bounded_text(&limits_path, 65536)?)
                .map_err(|e| e.to_string())?,
        )
    } else {
        None
    };
    if offline_retained {
        if let Some(note) = limits.as_mut() {
            note["capture_deadline_unix_ms"] = note["deadline_unix_ms"].clone();
            note.as_object_mut()
                .ok_or("归档限额必须为对象")?
                .remove("deadline_unix_ms");
            note["scope"] = json!("explicit_offline_retained_evidence_export_not_capture_resume");
            note["max_ms"] = json!(note["max_ms"].as_u64().ok_or("缺归档期限")?.min(30000));
        }
    }
    let _guard = limits
        .as_ref()
        .map(|v| {
            session_budget::Guard::install(
                vec![
                    output.to_owned(),
                    PathBuf::from(format!("{}.part", output.display())),
                ],
                v["archive_bytes"]
                    .as_u64()
                    .ok_or_else(|| std::io::Error::other("缺归档额度"))?
                    .saturating_sub(65536),
                v["max_ms"]
                    .as_u64()
                    .ok_or_else(|| std::io::Error::other("缺归档期限"))?
                    .min(
                        v["deadline_unix_ms"]
                            .as_u64()
                            .map(|d| d.saturating_sub(now_millis()))
                            .unwrap_or(u64::MAX),
                    ),
            )
        })
        .transpose()
        .map_err(|e| e.to_string())?;
    let files = collect_archive_files(root)?;
    let report: Value = serde_json::from_str(&read_bounded_text(
        &root.join("dump-report.json"),
        64 * 1024 * 1024,
    )?)
    .map_err(|e| e.to_string())?;
    let package = report["package"].as_str().ok_or("dump 缺包身份")?;
    validate_package(package)?;
    let mut objects = BTreeMap::<String, (PathBuf, u64)>::new();
    let mut refs = Vec::with_capacity(files.len());
    for (path, relative, n) in files {
        validate_evidence_relative_path(&relative)?;
        let hash = digest(&path, n)?;
        if let Some((prior, len)) = objects.get(&hash) {
            if *len != n || !equal(prior, &path)? {
                return Err("完整 hash/实际字节冲突，拒绝内容合并".into());
            }
        } else {
            objects.insert(hash.clone(), (path, n));
        }
        refs.push(Reference {
            path: relative,
            sha256: hash,
            bytes: n,
        });
    }
    let partial = report["collection_status"] == "partial"
        || report["transport_partial"] == true
        || refs.iter().any(|r| {
            r.path.starts_with("transport-partial-")
                || r.path.contains(".partial-")
                || r.path.ends_with(".pending")
        })
        || root.join("capture-group.json").is_file()
            && serde_json::from_str::<Value>(&read_bounded_text(
                &root.join("capture-group.json"),
                65536,
            )?)
            .map_err(|e| e.to_string())?["state"]
                == "partial";
    let coverage = json!({"status":if partial {"partial"} else {"unknown"},"scope":"all retained paths only; missing producer/transport bytes are not in this archive","complete_collection":false,"hash_verification_scope":"every archived object and path reference; not process or application coverage"});
    let manifest = serde_json::json!({"schemaVersion":SCHEMA,"package":package,"dumpId":report["dump_id"],"fileCount":refs.len(),"uncompressedBytes":refs.iter().map(|r|r.bytes).sum::<u64>(),"objectCount":objects.len(),"objectBytes":objects.values().map(|(_,n)|n).sum::<u64>(),"storageRepresentation":"full-sha256-objects-and-path-references/v1","references":refs,"outputLimits":limits,"coverage":coverage});
    let metadata_bytes =
        session_budget::measure_json(output, &manifest).map_err(|e| e.to_string())?;
    if metadata_bytes > REFERENCE_METADATA_LIMIT {
        return Err(
            "archive reference metadata exceeds finite reserve; original tree retained".into(),
        );
    }

    let bytes = serde_json::to_vec(&manifest).map_err(|e| e.to_string())?;
    if bytes.len() > 64 * 1024 * 1024 {
        return Err("引用清单超过64MiB，未丢弃来源路径".into());
    }
    if let Some(parent) = output.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let mut name = output.as_os_str().to_os_string();
    name.push(".part");
    let temporary = PathBuf::from(name);
    if temporary.exists() {
        return Err("归档临时输出已存在，保留旧证据，请用新输出路径".into());
    }
    // Select Stored for partial evidence only when the full unique content and
    // conservative ZIP write overhead fit a known remaining quota. Coverage and
    // per-write enforcement remain independent of this representation choice.
    let remaining = _guard.as_ref().map(|guard| {
        let receipt = guard.receipt();
        receipt
            .limit_bytes
            .saturating_sub(receipt.admitted_write_bytes)
    });
    let object_bytes = objects
        .values()
        .try_fold(0u64, |sum, (_, n)| sum.checked_add(*n));
    let names = std::iter::once("manifest.json".len() as u64).chain(
        objects
            .keys()
            .map(|hash| ("objects/".len() + hash.len() + ".bin".len()) as u64),
    );
    let stored_bound = object_bytes.and_then(|n| stored_write_bound(n, bytes.len() as u64, names));
    let stored_fits = remaining
        .zip(stored_bound)
        .is_some_and(|(quota, bound)| bound <= quota);
    let result = (|| {
        let mut writer = ZipWriter::new(
            session_budget::BudgetFile::create(&temporary).map_err(|e| e.to_string())?,
        );
        let options = SimpleFileOptions::default()
            .compression_method(if !partial || stored_fits {
                zip::CompressionMethod::Stored
            } else {
                zip::CompressionMethod::Deflated
            })
            .unix_permissions(0o600);
        writer
            .start_file("manifest.json", options)
            .map_err(|e| e.to_string())?;
        writer.write_all(&bytes).map_err(|e| e.to_string())?;
        for (hash, (path, expected)) in objects {
            writer
                .start_file(format!("objects/{hash}.bin"), options)
                .map_err(|e| e.to_string())?;
            let mut source = File::open(path).map_err(|e| format!("归档源读取失败：{e}"))?;
            let mut actual = Sha256::new();
            let mut count = 0u64;
            let mut buf = [0; 65536];
            loop {
                let n = source
                    .read(&mut buf)
                    .map_err(|e| format!("归档源读取失败：{e}"))?;
                if n == 0 {
                    break;
                }
                count = count.checked_add(n as u64).ok_or("长度溢出")?;
                if count > expected {
                    return Err("归档源已增长，拒绝提交".into());
                }
                actual.update(&buf[..n]);
                writer
                    .write_all(&buf[..n])
                    .map_err(|e| format!("归档落盘失败：{e}"))?;
            }
            if count != expected || format!("{:x}", actual.finalize()) != hash {
                return Err("归档源短读/内容变更，拒绝提交".into());
            }
        }
        let file = writer.finish().map_err(|e| format!("归档落盘失败：{e}"))?;
        file.sync_all().map_err(|e| e.to_string())?;
        std::fs::rename(&temporary, output).map_err(|e| format!("归档发布到本地路径失败：{e}"))?;
        Ok(())
    })();
    if let Some(g) = _guard.as_ref() {
        let note = serde_json::to_vec(&g.receipt()).map_err(|e| e.to_string())?;
        std::fs::write(
            PathBuf::from(format!("{}.budget.json", output.display())),
            note,
        )
        .map_err(|e| e.to_string())?;
    }
    if result.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    result
}
pub(super) fn is_v2(path: &Path) -> Result<bool, String> {
    let mut archive =
        ZipArchive::new(File::open(path).map_err(|e| e.to_string())?).map_err(|e| e.to_string())?;
    let mut manifest = archive
        .by_name("manifest.json")
        .map_err(|e| e.to_string())?;
    if manifest.size() > 64 * 1024 * 1024 {
        return Err("证据清单超过安全上限".into());
    }
    let mut text = String::new();
    manifest
        .by_ref()
        .take(64 * 1024 * 1024 + 1)
        .read_to_string(&mut text)
        .map_err(|e| e.to_string())?;
    if text.len() > 64 * 1024 * 1024 {
        return Err("清单实际读取超过预算".into());
    }
    let value: Value = serde_json::from_str(&text).map_err(|e| e.to_string())?;
    Ok(value["schemaVersion"] == SCHEMA)
}
pub(super) fn restore(path: &Path) -> Result<PathBuf, String> {
    restore_with_source(path, None)
}
pub(super) fn restore_from_export_source(path: &Path, source: &Path) -> Result<PathBuf, String> {
    restore_with_source(path, Some(source))
}
fn restore_with_source(path: &Path, reuse_source: Option<&Path>) -> Result<PathBuf, String> {
    let archive_len = std::fs::metadata(path).map_err(|e| e.to_string())?.len();
    if archive_len > MAX_EVIDENCE_ARCHIVE_BYTES + 128 * 1024 * 1024 {
        return Err("归档实际文件超安全上限".into());
    }
    let archive_hash = digest(path, archive_len)?;
    let staging = std::env::temp_dir().join(format!("mobilee-objects-{archive_hash}"));
    let mut owned = false;
    let root = staging.join("evidence");
    let pool = staging.join("objects");
    let result = (|| {
        let mut archive = ZipArchive::new(File::open(path).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
        if archive.len() > MAX_EVIDENCE_ARCHIVE_FILES + 1 {
            return Err("归档对象数超过上限".into());
        }
        let manifest: Value = {
            let mut source = archive
                .by_name("manifest.json")
                .map_err(|e| e.to_string())?;
            if source.size() > 64 * 1024 * 1024 {
                return Err("清单超过上限".into());
            }
            let mut text = String::new();
            source
                .by_ref()
                .take(64 * 1024 * 1024 + 1)
                .read_to_string(&mut text)
                .map_err(|e| e.to_string())?;
            if text.len() > 64 * 1024 * 1024 {
                return Err("清单实际读取超过预算".into());
            }
            serde_json::from_str(&text).map_err(|e| e.to_string())?
        };
        if manifest["schemaVersion"] != SCHEMA {
            return Err("不支持的引用归档版本".into());
        }
        let _guard = manifest["outputLimits"]
            .as_object()
            .map(|v| {
                session_budget::Guard::install(
                    vec![staging.clone()],
                    v.get("import_bytes")
                        .and_then(Value::as_u64)
                        .ok_or_else(|| std::io::Error::other("缺导入额度"))?
                        .saturating_sub(65536),
                    v.get("max_ms")
                        .and_then(Value::as_u64)
                        .ok_or_else(|| std::io::Error::other("缺导入期限"))?,
                )
            })
            .transpose()
            .map_err(|e| e.to_string())?;
        let refs: Vec<Reference> =
            serde_json::from_value(manifest["references"].clone()).map_err(|e| e.to_string())?;
        if refs.len() > MAX_EVIDENCE_ARCHIVE_FILES
            || manifest["fileCount"].as_u64() != Some(refs.len() as u64)
        {
            return Err("引用数量不完整".into());
        }
        let mut paths = BTreeSet::new();
        let mut objects = BTreeMap::new();
        let mut logical = 0u64;
        for r in &refs {
            validate_evidence_relative_path(&r.path)?;
            if !paths.insert(r.path.clone())
                || r.sha256.len() != 64
                || !r
                    .sha256
                    .bytes()
                    .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
            {
                return Err("引用路径/hash冲突或无效".into());
            }
            if objects
                .insert(r.sha256.clone(), r.bytes)
                .is_some_and(|old| old != r.bytes)
            {
                return Err("同一对象长度冲突".into());
            }
            logical = logical.checked_add(r.bytes).ok_or("引用总量溢出")?;
        }
        if !paths.contains("dump-report.json")
            || logical > MAX_EVIDENCE_ARCHIVE_BYTES
            || manifest["uncompressedBytes"].as_u64() != Some(logical)
            || manifest["objectCount"].as_u64() != Some(objects.len() as u64)
            || archive.len() != objects.len() + 1
        {
            return Err("引用范围/总预算/对象集合不完整".into());
        }
        let object_bytes = objects
            .values()
            .try_fold(0u64, |sum, n| sum.checked_add(*n))
            .ok_or("对象总量溢出")?;
        if manifest["objectBytes"].as_u64() != Some(object_bytes) {
            return Err("对象总量声明不匹配".into());
        }
        if staging.exists() {
            if std::fs::symlink_metadata(&staging)
                .map_err(|e| e.to_string())?
                .file_type()
                .is_symlink()
                || std::fs::symlink_metadata(&root)
                    .map_err(|e| e.to_string())?
                    .file_type()
                    .is_symlink()
            {
                return Err("已有缓存根为符号链接；保留并拒绝".into());
            }
            let marker: Value = serde_json::from_str(&read_bounded_text(
                &if staging.join("archive-cache-identity.json").is_file() {
                    staging.join("archive-cache-identity.json")
                } else {
                    root.join("archive-cache-identity.json")
                },
                65536,
            )?)
            .map_err(|e| e.to_string())?;
            if marker["sha256"] != archive_hash || marker["bytes"] != archive_len {
                return Err("已有缓存身份未知；不覆盖".into());
            }
            let canonical = root.canonicalize().map_err(|e| e.to_string())?;
            for r in &refs {
                let path = root.join(&r.path);
                if std::fs::symlink_metadata(&path)
                    .map_err(|e| e.to_string())?
                    .file_type()
                    .is_symlink()
                    || !path
                        .canonicalize()
                        .map_err(|e| e.to_string())?
                        .starts_with(&canonical)
                    || digest(&path, r.bytes)? != r.sha256
                {
                    return Err("已有缓存内容变化；保留旧缓存及原归档，不当作成功复用".into());
                }
            }
            return Ok(root.clone());
        }
        let mut reuse = BTreeMap::<String, PathBuf>::new();
        if let Some(source) = reuse_source {
            if std::fs::symlink_metadata(source)
                .map_err(|e| e.to_string())?
                .file_type()
                .is_symlink()
            {
                return Err("复用源根为符号链接".into());
            }
            let canonical = source.canonicalize().map_err(|e| e.to_string())?;
            for r in &refs {
                let p = source.join(&r.path);
                let canonical_file = p.canonicalize().map_err(|e| e.to_string())?;
                if std::fs::symlink_metadata(&p)
                    .map_err(|e| e.to_string())?
                    .file_type()
                    .is_symlink()
                    || !canonical_file.starts_with(&canonical)
                    || digest(&canonical_file, r.bytes)? != r.sha256
                {
                    return Err("已导出源内容改变或范围未知，保留原件，拒绝复用".into());
                }
                reuse.entry(r.sha256.clone()).or_insert(canonical_file);
            }
        }
        std::fs::create_dir(&staging).map_err(|e| e.to_string())?;
        owned = true;
        std::fs::create_dir_all(&root).map_err(|e| e.to_string())?;
        std::fs::create_dir_all(&pool).map_err(|e| e.to_string())?;
        let mut observed = BTreeSet::new();
        let mut reused_objects = 0_usize;
        for index in 0..archive.len() {
            let mut entry = archive.by_index(index).map_err(|e| e.to_string())?;
            if entry.name() == "manifest.json" {
                if !observed.insert("manifest".into()) {
                    return Err("重复清单".into());
                }
                continue;
            }
            let hash = entry
                .name()
                .strip_prefix("objects/")
                .and_then(|v| v.strip_suffix(".bin"))
                .ok_or("额外/危险的对象路径")?
                .to_owned();
            let expected = *objects.get(&hash).ok_or("对象未被引用")?;
            if !observed.insert(hash.clone())
                || entry.size() != expected
                || entry
                    .unix_mode()
                    .is_some_and(|mode| mode & 0o170000 == 0o120000)
            {
                return Err("重复对象/长度/符号链接无效".into());
            }
            let reused = reuse
                .get(&hash)
                .is_some_and(|source| std::fs::hard_link(source, pool.join(&hash)).is_ok());
            if reused {
                reused_objects += 1;
            }
            let mut file = if reused {
                None
            } else {
                Some(
                    std::fs::OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .open(pool.join(&hash))
                        .map_err(|e| e.to_string())?,
                )
            };
            let mut actual = Sha256::new();
            let mut count = 0u64;
            let mut buf = [0; 65536];
            loop {
                let n = entry
                    .read(&mut buf)
                    .map_err(|e| format!("对象读取/CRC失败：{e}"))?;
                if n == 0 {
                    break;
                }
                count = count.checked_add(n as u64).ok_or("对象长度溢出")?;
                if count > expected {
                    return Err("对象超出准入字节预算".into());
                }
                actual.update(&buf[..n]);
                if let Some(file) = file.as_mut() {
                    session_budget::charge(&pool.join(&hash), n as u64)
                        .map_err(|e| e.to_string())?;
                    file.write_all(&buf[..n])
                        .map_err(|e| format!("对象落盘失败：{e}"))?;
                }
            }
            if count != expected || format!("{:x}", actual.finalize()) != hash {
                return Err("对象短读/完整hash失败".into());
            }
            if let Some(file) = file.as_ref() {
                file.sync_all().map_err(|e| e.to_string())?;
            }
            if reused && digest(&pool.join(&hash), expected)? != hash {
                return Err("复用源在归档核验期间变化，拒绝成功".into());
            }
        }
        let mut linked = 0usize;
        let mut copied = 0usize;
        for r in &refs {
            let target = root.join(&r.path);
            if let Some(parent) = target.parent() {
                std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
            }
            if target.exists() {
                return Err("引用目标已存在，拒绝覆盖".into());
            }
            if std::fs::hard_link(pool.join(&r.sha256), &target).is_ok() {
                linked += 1;
            } else {
                let bytes = session_budget::copy(pool.join(&r.sha256), &target)
                    .map_err(|e| format!("引用恢复落盘失败：{e}"))?;
                if bytes != r.bytes {
                    return Err("引用恢复短写".into());
                }
                copied += 1;
            }
        }
        let note = serde_json::json!({"schema":"mobilee.archive-content-references/v1","archiveSchema":SCHEMA,"references":refs,"objectBytes":object_bytes,"logicalBytes":logical,"restoredLinks":linked,"copyFallbacks":copied,"reusedSourceObjects":reused_objects,"archiveCoverage":manifest.get("coverage").cloned().unwrap_or_else(||json!({"status":"unknown","scope":"legacy manifest lacks coverage"})),"physicalSavings":"recompute-from-local-stat"});
        session_budget::write(
            root.join(format!(
                "archive-content-references-{}.json",
                Uuid::new_v4()
            )),
            serde_json::to_vec(&note).map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?;
        session_budget::write(staging.join("archive-cache-identity.json"),serde_json::to_vec(&serde_json::json!({"schema":"mobilee.archive-cache/v1","sha256":archive_hash,"bytes":archive_len,"references":refs.len(),"reuse":"full-source-sha-and-every-original-path-verified"})).map_err(|e|e.to_string())?).map_err(|e|e.to_string())?;
        std::fs::remove_dir_all(&pool).map_err(|e| e.to_string())?;
        Ok(root.clone())
    })();
    if result.is_err() && owned {
        let _ = std::fs::remove_dir_all(&staging);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> PathBuf {
        let root = std::env::temp_dir().join(format!("mobilee-ref-fixture-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("dump-report.json"),serde_json::to_vec(&serde_json::json!({"package":"org.example.fixture","dump_id":Uuid::new_v4(),"artifacts":[]})).unwrap()).unwrap();
        root
    }
    #[test]
    fn explicit_local_partial_keeps_byte_caps_and_preserves_expired_capture_limits() {
        let source = fixture();
        std::fs::write(source.join("raw.pending"), vec![0_u8; 1024]).unwrap();
        let original=b"{\"archive_bytes\":73728,\"import_bytes\":73728,\"max_ms\":1000,\"deadline_unix_ms\":1}";
        std::fs::write(source.join("archive-output-limits.json"), original).unwrap();
        let output = source.with_extension("closed.mee");
        assert!(write(&source, &output).is_err());
        assert!(!output.exists());
        write_local_retained(&source, &output).unwrap();
        assert_eq!(
            std::fs::read(source.join("archive-output-limits.json")).unwrap(),
            original
        );
        let mut zip = ZipArchive::new(File::open(&output).unwrap()).unwrap();
        let mut text = String::new();
        zip.by_name("manifest.json")
            .unwrap()
            .read_to_string(&mut text)
            .unwrap();
        let note: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(note["outputLimits"]["archive_bytes"], 73728);
        assert_eq!(note["outputLimits"]["capture_deadline_unix_ms"], 1);
        assert_eq!(note["coverage"]["status"], "partial");
        drop(zip);
        std::fs::remove_file(output).unwrap();
        std::fs::remove_dir_all(source).unwrap();
    }
    #[tokio::test]
    async fn partial_archive_compresses_reuses_verified_source_and_keeps_all_hashes() {
        let source = fixture();
        let bytes = vec![7_u8; 256 * 1024];
        std::fs::write(source.join("raw.partial-fixture"), &bytes).unwrap();
        std::fs::write(source.join("second-source.pending"), &bytes).unwrap();
        std::fs::write(
            source.join("archive-cache-identity.json"),
            b"original marker evidence",
        )
        .unwrap();
        let before = collect_archive_files(&source).unwrap();
        let expected = before
            .iter()
            .map(|(p, r, n)| (r.clone(), (*n, digest(p, *n).unwrap())))
            .collect::<BTreeMap<_, _>>();
        let output = source.with_extension("partial.mee");
        let archive_guard = session_budget::Guard::install(
            vec![
                output.clone(),
                PathBuf::from(format!("{}.part", output.display())),
            ],
            8192,
            30000,
        )
        .unwrap();
        write(&source, &output).unwrap();
        assert!(std::fs::metadata(&output).unwrap().len() < 8192);
        drop(archive_guard);
        let restore_guard = session_budget::Guard::install(
            vec![std::env::temp_dir().join(format!(
                "mobilee-objects-{}",
                digest(&output, std::fs::metadata(&output).unwrap().len()).unwrap()
            ))],
            65536,
            30000,
        )
        .unwrap();
        let root = restore_from_export_source(&output, &source).unwrap();
        assert!(restore_guard.receipt().admitted_write_bytes < 65536);
        drop(restore_guard);
        for (relative, (n, hash)) in expected {
            assert_eq!(digest(&root.join(&relative), n).unwrap(), hash);
            assert_eq!(digest(&source.join(&relative), n).unwrap(), hash);
        }
        assert_eq!(
            std::fs::read(root.join("archive-cache-identity.json")).unwrap(),
            b"original marker evidence"
        );
        assert_eq!(restore(&output).unwrap(), root);
        let bundle = import_kernsight_evidence_directory(root.to_string_lossy().into_owned())
            .await
            .unwrap();
        assert_eq!(
            bundle.dump_report["mobilee_archive_coverage"]["status"],
            "partial"
        );
        assert_eq!(
            bundle.dump_report["mobilee_archive_coverage"]["complete_collection"],
            false
        );
        std::fs::remove_dir_all(root.parent().unwrap()).unwrap();
        std::fs::remove_dir_all(source).unwrap();
        std::fs::remove_file(output).unwrap();
    }
    #[tokio::test]
    async fn production_complete_bytes_multiple_sources_and_shared_restore() {
        let root = fixture();
        let mut a = vec![b'a'; 256 * 1024];
        let mut b = a.clone();
        *a.last_mut().unwrap() = b'x';
        *b.last_mut().unwrap() = b'y';
        std::fs::write(root.join("source-a.bin"), &a).unwrap();
        std::fs::write(root.join("source-b.bin"), &b).unwrap();
        std::fs::write(root.join("independent-same-a.bin"), &a).unwrap();
        std::fs::hard_link(root.join("source-a.bin"), root.join("linked-a.bin")).unwrap();
        std::fs::write(
            root.join("origin-a.json"),
            b"{\"pid\":42,\"read_status\":\"short_read\",\"source\":\"source-a.bin\"}",
        )
        .unwrap();
        std::fs::write(
            root.join("origin-b.json"),
            b"{\"pid\":43,\"read_status\":\"read_failed\",\"source\":\"linked-a.bin\"}",
        )
        .unwrap();
        let archive = root.with_extension("mee");
        write_kernsight_evidence_archive(&root, &archive).unwrap();
        assert!(is_v2(&archive).unwrap());
        assert!(std::fs::metadata(&archive).unwrap().len() < 800 * 1024);
        let bundle = import_kernsight_evidence_archive(archive.to_string_lossy().into_owned())
            .await
            .unwrap();
        let target = Path::new(&bundle.root);
        assert_eq!(std::fs::read(target.join("source-a.bin")).unwrap(), a);
        assert_eq!(std::fs::read(target.join("source-b.bin")).unwrap(), b);
        assert_eq!(
            std::fs::read(target.join("origin-a.json")).unwrap(),
            std::fs::read(root.join("origin-a.json")).unwrap()
        );
        assert_eq!(
            std::fs::read(target.join("origin-b.json")).unwrap(),
            std::fs::read(root.join("origin-b.json")).unwrap()
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let a = std::fs::metadata(target.join("source-a.bin")).unwrap();
            let same = std::fs::metadata(target.join("independent-same-a.bin")).unwrap();
            let b = std::fs::metadata(target.join("source-b.bin")).unwrap();
            assert_eq!(a.ino(), same.ino());
            assert_ne!(a.ino(), b.ino());
            assert_eq!(
                bundle.dump_report["local_storage_accounting"]["shared_inode_logical_bytes"],
                512 * 1024
            );
        }
        let again = root.with_extension("again.mee");
        write_kernsight_evidence_archive(target, &again).unwrap();
        let second = import_kernsight_evidence_archive(again.to_string_lossy().into_owned())
            .await
            .unwrap();
        assert_eq!(
            std::fs::read(Path::new(&second.root).join("source-b.bin")).unwrap(),
            b
        );
        for value in [&bundle, &second] {
            std::fs::remove_dir_all(Path::new(&value.root).parent().unwrap()).unwrap();
        }
        std::fs::remove_file(archive).unwrap();
        std::fs::remove_file(again).unwrap();
        std::fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn missing_and_short_source_are_failures_not_empty_success() {
        let root = fixture();
        std::fs::write(root.join("tiny.bin"), b"one").unwrap();
        assert!(digest(&root.join("tiny.bin"), 4).is_err());
        assert!(digest(&root.join("absent.bin"), 0).is_err());
        std::fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn corrupt_hash_and_budget_overflow_refused_before_restore() {
        let root = fixture();
        std::fs::write(root.join("tiny.bin"), b"one").unwrap();
        let archive = root.with_extension("mee");
        write(&root, &archive).unwrap();
        let mut zip = ZipArchive::new(File::open(&archive).unwrap()).unwrap();
        let mut manifest = String::new();
        zip.by_name("manifest.json")
            .unwrap()
            .read_to_string(&mut manifest)
            .unwrap();
        let mut value: Value = serde_json::from_str(&manifest).unwrap();
        value["uncompressedBytes"] = serde_json::json!(u64::MAX);
        let bad = archive.with_extension("bad.mee");
        let mut writer = ZipWriter::new(File::create(&bad).unwrap());
        let options = SimpleFileOptions::default();
        writer.start_file("manifest.json", options).unwrap();
        writer
            .write_all(&serde_json::to_vec(&value).unwrap())
            .unwrap();
        writer.finish().unwrap();
        assert!(restore(&bad).is_err());
        std::fs::remove_file(bad).unwrap();
        std::fs::remove_file(archive).unwrap();
        std::fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn wrong_full_hash_and_failed_output_never_succeed() {
        let root = fixture();
        let archive = root.with_extension("corrupt.mee");
        let hash = "f".repeat(64);
        let value = serde_json::json!({"schemaVersion":SCHEMA,"fileCount":1,"uncompressedBytes":3,"objectCount":1,"objectBytes":3,"references":[{"path":"dump-report.json","sha256":hash,"bytes":3}]});
        let mut writer = ZipWriter::new(File::create(&archive).unwrap());
        let options = SimpleFileOptions::default();
        writer.start_file("manifest.json", options).unwrap();
        writer
            .write_all(&serde_json::to_vec(&value).unwrap())
            .unwrap();
        writer
            .start_file(format!("objects/{hash}.bin"), options)
            .unwrap();
        writer.write_all(b"one").unwrap();
        writer.finish().unwrap();
        assert!(restore(&archive).unwrap_err().contains("完整hash失败"));
        std::fs::create_dir(root.join("block")).unwrap();
        assert!(write(&root, &root.join("block")).is_err());
        assert!(!root.join("block.part").exists());
        std::fs::remove_file(archive).unwrap();
        std::fs::remove_dir_all(root).unwrap();
    }
}

/// Only called on the fresh staging directory created by the current pull.
/// Link via a new name and atomically replace a verified identical alias;
/// never unlink a source first or mutate an imported/user evidence directory.
pub(super) fn share_fresh_pull(root: &Path, archive_path: &Path) -> Result<(), String> {
    let owner = root
        .parent()
        .and_then(|p| p.file_name())
        .and_then(|p| p.to_str())
        .and_then(|p| p.strip_prefix("mobilee-pull-"))
        .and_then(|p| Uuid::parse_str(p).ok())
        .ok_or("仅允许本次 fresh pull 缓存内容共享")?;
    let _ = owner;
    let mut archive = ZipArchive::new(File::open(archive_path).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;
    let mut manifest = archive
        .by_name("manifest.json")
        .map_err(|e| e.to_string())?;
    if manifest.size() > 64 * 1024 * 1024 {
        return Err("引用清单超过预算".into());
    }
    let mut text = String::new();
    manifest
        .by_ref()
        .take(64 * 1024 * 1024 + 1)
        .read_to_string(&mut text)
        .map_err(|e| e.to_string())?;
    if text.len() > 64 * 1024 * 1024 {
        return Err("引用清单读取超预算".into());
    }
    let value: Value = serde_json::from_str(&text).map_err(|e| e.to_string())?;
    if value["schemaVersion"] != SCHEMA {
        return Err("仅 v2 完整引用可共享".into());
    }
    let refs: Vec<Reference> =
        serde_json::from_value(value["references"].clone()).map_err(|e| e.to_string())?;
    for r in &refs {
        validate_evidence_relative_path(&r.path)?;
        if digest(&root.join(&r.path), r.bytes)? != r.sha256 {
            return Err("fresh pull 内容已变；未合并".into());
        }
    }
    let mut objects = BTreeMap::<String, PathBuf>::new();
    for r in refs {
        let target = root.join(r.path);
        if let Some(source) = objects.get(&r.sha256) {
            if !equal(source, &target)? {
                return Err("完整实际字节冲突；未覆盖来源".into());
            }
            let scratch = target.with_extension(format!("share-{}", Uuid::new_v4()));
            // Unsupported filesystems keep their original copies; actual stat
            // reports this, without advertising a hypothetical saving.
            if std::fs::hard_link(source, &scratch).is_ok() {
                let _ = std::fs::rename(&scratch, &target);
                // POSIX rename of two names for one inode can be a no-op.
                // Reclaim only the temporary alias created by this invocation.
                match std::fs::remove_file(&scratch) {
                    Ok(()) => {}
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                    Err(e) => return Err(format!("本次缓存临时别名未回收：{e}")),
                }
            }
        } else {
            objects.insert(r.sha256, target);
        }
    }
    Ok(())
}

#[cfg(test)]
mod fresh_tests {
    use super::*;
    #[test]
    fn only_fresh_pull_is_shared_all_paths_and_no_scratch_remain() {
        let staging = std::env::temp_dir().join(format!("mobilee-pull-{}", Uuid::new_v4()));
        let root = staging.join("org.example.fixture");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(
            root.join("dump-report.json"),
            b"{\"package\":\"org.example.fixture\",\"dump_id\":\"synthetic\"}",
        )
        .unwrap();
        std::fs::write(root.join("a.bin"), vec![b'x'; 128 * 1024]).unwrap();
        std::fs::write(root.join("same-a.bin"), vec![b'x'; 128 * 1024]).unwrap();
        let archive = staging.join("snapshot.mee");
        write(&root, &archive).unwrap();
        share_fresh_pull(&root, &archive).unwrap();
        share_fresh_pull(&root, &archive).unwrap();
        assert_eq!(collect_archive_files(&root).unwrap().len(), 3);
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            assert_eq!(
                std::fs::metadata(root.join("a.bin")).unwrap().ino(),
                std::fs::metadata(root.join("same-a.bin")).unwrap().ino()
            );
        }
        assert!(share_fresh_pull(&staging, &archive).is_err());
        std::fs::remove_dir_all(staging).unwrap();
    }
}

#[cfg(test)]
mod configured_fixture {
    use super::*;
    #[tokio::test]
    #[ignore = "requires explicit synthetic reference export fixture and output directory; never connects a device"]
    async fn synthetic_reference_archive_production_deliverable() {
        let source = PathBuf::from(
            std::env::var("ME_REFERENCE_EXPORT_FIXTURE")
                .expect("explicit synthetic fixture required"),
        );
        let output = PathBuf::from(
            std::env::var("ME_REFERENCE_EXPORT_OUTPUT").expect("explicit new output required"),
        );
        assert!(!output.exists(), "fresh deliverable directory required");
        std::fs::create_dir_all(&output).unwrap();
        let archive = output.join("synthetic-full-evidence-v2.mee");
        let legacy = output.join("synthetic-full-evidence-v1.mee");
        write_kernsight_evidence_archive_v1(&source, &legacy).unwrap();
        write_kernsight_evidence_archive(&source, &archive).unwrap();
        let bundle = import_kernsight_evidence_archive(archive.to_string_lossy().into_owned())
            .await
            .unwrap();
        let source_files = collect_archive_files(&source).unwrap();
        for (path, relative, n) in &source_files {
            assert_eq!(
                digest(path, *n).unwrap(),
                digest(&Path::new(&bundle.root).join(relative), *n).unwrap()
            );
        }
        assert!(
            std::fs::metadata(&archive).unwrap().len() < std::fs::metadata(&legacy).unwrap().len()
        );
        let result = serde_json::json!({"schema":"mobilee.reference-archive-fixture/v1","synthetic_only":true,"source_paths":source_files.len(),"source_logical_bytes":source_files.iter().map(|(_,_,n)|n).sum::<u64>(),"v1_archive_bytes":std::fs::metadata(&legacy).unwrap().len(),"v2_archive_bytes":std::fs::metadata(&archive).unwrap().len(),"all_source_full_hashes_match":true,"bundle":bundle});
        std::fs::write(
            output.join("production-import-result.json"),
            serde_json::to_vec_pretty(&result).unwrap(),
        )
        .unwrap();
    }
}

#[cfg(test)]
mod budget_tests {
    use super::*;
    #[test]
    fn real_archive_budget_exhaustion_keeps_source_and_no_success() {
        let root = std::env::temp_dir().join(format!("archive-budget-{}", Uuid::new_v4()));
        std::fs::create_dir(&root).unwrap();
        std::fs::write(
            root.join("dump-report.json"),
            b"{\"package\":\"org.example.budget\",\"dump_id\":\"fixture\"}",
        )
        .unwrap();
        std::fs::write(root.join("raw.bin"), [7; 100]).unwrap();
        std::fs::write(
            root.join("archive-output-limits.json"),
            b"{\"archive_bytes\":65536,\"import_bytes\":65536,\"max_ms\":1000}",
        )
        .unwrap();
        assert!(write(&root, &root.join("out.mee")).is_err());
        assert_eq!(std::fs::read(root.join("raw.bin")).unwrap(), [7; 100]);
        assert!(!root.join("out.mee").exists());
        std::fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn real_restore_budget_exhaustion_keeps_original_archive() {
        let root = std::env::temp_dir().join(format!("import-budget-{}", Uuid::new_v4()));
        std::fs::create_dir(&root).unwrap();
        std::fs::write(
            root.join("dump-report.json"),
            b"{\"package\":\"org.example.budget\",\"dump_id\":\"fixture\"}",
        )
        .unwrap();
        std::fs::write(
            root.join("archive-output-limits.json"),
            b"{\"archive_bytes\":1048576,\"import_bytes\":65536,\"max_ms\":1000}",
        )
        .unwrap();
        let out = root
            .parent()
            .unwrap()
            .join(format!("{}.mee", Uuid::new_v4()));
        write(&root, &out).unwrap();
        let before = std::fs::read(&out).unwrap();
        assert!(restore(&out).is_err());
        assert_eq!(std::fs::read(&out).unwrap(), before);
        std::fs::remove_file(out).unwrap();
        std::fs::remove_dir_all(root).unwrap();
    }
}

#[cfg(test)]
mod cache_budget_tests {
    use super::*;
    #[test]
    fn repeated_full_verified_import_reuses_paths_and_changed_cache_is_preserved() {
        let source = std::env::temp_dir().join(format!("repeat-source-{}", Uuid::new_v4()));
        std::fs::create_dir(&source).unwrap();
        std::fs::write(
            source.join("dump-report.json"),
            b"{\"package\":\"org.example.repeat\",\"dump_id\":\"repeat\"}",
        )
        .unwrap();
        std::fs::write(source.join("raw.bin"), b"same complete bytes").unwrap();
        let output = source
            .parent()
            .unwrap()
            .join(format!("repeat-{}.mee", Uuid::new_v4()));
        write(&source, &output).unwrap();
        let first = restore(&output).unwrap();
        let before = collect_archive_files(&first).unwrap();
        let second = restore(&output).unwrap();
        assert_eq!(first, second);
        assert_eq!(before.len(), collect_archive_files(&second).unwrap().len());
        std::fs::write(first.join("raw.bin"), b"changed").unwrap();
        assert!(restore(&output).is_err());
        assert_eq!(std::fs::read(first.join("raw.bin")).unwrap(), b"changed");
        assert!(output.exists());
        std::fs::remove_dir_all(first.parent().unwrap()).unwrap();
        std::fs::remove_dir_all(source).unwrap();
        std::fs::remove_file(output).unwrap();
    }
}

// SimpleFileOptions below has no comments/custom extras. Include local/central
// headers, both filename copies, ZIP64/trailer and seek-back header rewrites.
// This is a charged-write bound; the BudgetFile still enforces actual writes.
fn stored_write_bound(
    object_bytes: u64,
    manifest_bytes: u64,
    names: impl Iterator<Item = u64>,
) -> Option<u64> {
    let mut bound = object_bytes
        .checked_add(manifest_bytes)?
        .checked_add(128 * 1024)?;
    for name_bytes in names {
        bound = bound.checked_add(1024u64.checked_add(name_bytes.checked_mul(2)?)?)?;
    }
    Some(bound)
}

#[cfg(test)]
mod adaptive_stored_tests {
    use super::*;
    #[test]
    fn charged_bound_and_overflow_fail_closed() {
        assert_eq!(
            stored_write_bound(100, 20, [13, 76].into_iter()),
            Some(100 + 20 + 131072 + 2 * 1024 + 2 * (13 + 76))
        );
        assert!(stored_write_bound(u64::MAX, 1, [13].into_iter()).is_none());
        assert!(stored_write_bound(1, 1, [u64::MAX].into_iter()).is_none());
    }
    #[test]
    fn unique_objects_fit_and_small_or_unknown_quota_deflates_without_upgrading_coverage() {
        for (cap, method) in [
            (Some(2 * 1024 * 1024), zip::CompressionMethod::Stored),
            (Some(256 * 1024), zip::CompressionMethod::Deflated),
            (None, zip::CompressionMethod::Deflated),
        ] {
            let base = std::env::temp_dir().join(format!("me-adaptive-stored-{}", Uuid::new_v4()));
            let root = base.join("input");
            std::fs::create_dir_all(&root).unwrap();
            std::fs::write(root.join("dump-report.json"),br#"{"package":"org.example.fixture","collection_status":"partial","artifacts":[]}"#).unwrap();
            let payload = vec![0u8; 1024 * 1024];
            std::fs::write(root.join("payload.code"), &payload).unwrap();
            std::fs::write(root.join("alias.code"), &payload).unwrap();
            if let Some(cap) = cap {
                std::fs::write(
                    root.join("archive-output-limits.json"),
                    serde_json::to_vec(
                        &json!({"archive_bytes":cap,"import_bytes":1048576,"max_ms":10000}),
                    )
                    .unwrap(),
                )
                .unwrap();
            }
            let output = base.join("fixture.mee");
            write(&root, &output).unwrap();
            let mut zip = ZipArchive::new(File::open(&output).unwrap()).unwrap();
            for index in 0..zip.len() {
                assert_eq!(zip.by_index(index).unwrap().compression(), method);
            }
            let mut text = String::new();
            zip.by_name("manifest.json")
                .unwrap()
                .read_to_string(&mut text)
                .unwrap();
            let manifest: Value = serde_json::from_str(&text).unwrap();
            assert_eq!(manifest["coverage"]["status"], "partial");
            assert_eq!(manifest["coverage"]["complete_collection"], false);
            let refs = manifest["references"].as_array().unwrap();
            let payload_refs: Vec<_> = refs
                .iter()
                .filter(|r| r["path"] == "payload.code" || r["path"] == "alias.code")
                .collect();
            assert_eq!(payload_refs.len(), 2);
            assert_eq!(payload_refs[0]["sha256"], payload_refs[1]["sha256"]);
            for row in refs {
                let name = format!("objects/{}.bin", row["sha256"].as_str().unwrap());
                let mut content = Vec::new();
                zip.by_name(&name)
                    .unwrap()
                    .read_to_end(&mut content)
                    .unwrap();
                assert_eq!(content.len() as u64, row["bytes"].as_u64().unwrap());
                assert_eq!(
                    format!("{:x}", Sha256::digest(&content)),
                    row["sha256"].as_str().unwrap()
                );
            }
            if let Some(cap) = cap {
                let receipt: Value = serde_json::from_str(
                    &std::fs::read_to_string(format!("{}.budget.json", output.display())).unwrap(),
                )
                .unwrap();
                assert_eq!(receipt["partial"], false);
                let unique = refs
                    .iter()
                    .map(|row| {
                        (
                            row["sha256"].as_str().unwrap(),
                            row["bytes"].as_u64().unwrap(),
                        )
                    })
                    .collect::<BTreeMap<_, _>>();
                let bound = stored_write_bound(
                    unique.values().sum(),
                    text.len() as u64,
                    std::iter::once("manifest.json".len() as u64).chain(
                        unique
                            .keys()
                            .map(|hash| ("objects/".len() + hash.len() + ".bin".len()) as u64),
                    ),
                )
                .unwrap();
                assert_eq!(
                    bound <= cap - 65536,
                    method == zip::CompressionMethod::Stored
                );
                if method == zip::CompressionMethod::Stored {
                    assert!(receipt["admitted_write_bytes"].as_u64().unwrap() <= bound);
                }
                assert!(receipt["admitted_write_bytes"].as_u64().unwrap() <= cap - 65536);
            }
            assert_eq!(std::fs::read(root.join("payload.code")).unwrap(), payload);
            drop(zip);
            std::fs::remove_dir_all(base).unwrap();
        }
    }
}

#[cfg(test)]
mod retained_closeout_acceptance {
    use super::*;
    #[tokio::test]
    #[ignore = "requires explicit independent cloned retained inputs and fresh output; never accesses device or renews old parent"]
    async fn bounded_real_retained_archive_share_and_production_import() {
        let root = PathBuf::from(
            std::env::var("ME_RETAINED_CLOSEOUT_ROOT").expect("explicit isolated clone"),
        );
        let out =
            PathBuf::from(std::env::var("ME_RETAINED_CLOSEOUT_OUTPUT").expect("fresh output"));
        assert!(root.is_absolute() && out.is_absolute() && !out.exists());
        std::fs::create_dir_all(&out).unwrap();
        let source_group = std::fs::read(root.join("capture-group.json")).unwrap();
        let started = std::time::Instant::now();
        let archive = out.join("retained.mee");
        let share_guard =
            session_budget::Guard::install(vec![root.clone()], 65536, 120000).unwrap();
        write(&root, &archive).unwrap();
        share_fresh_pull(&root, &archive).unwrap();
        session_budget::charge(&root.join("capture-group.json"), 0).unwrap();
        let archive_elapsed_ms = started.elapsed().as_millis();
        let share_receipt = share_guard.receipt();
        drop(share_guard);
        let import_start = std::time::Instant::now();
        let import_guard =
            session_budget::Guard::install(vec![root.clone()], 768 * 1024 * 1024, 120000).unwrap();
        let bundle = import_kernsight_evidence_directory(root.to_string_lossy().into_owned())
            .await
            .unwrap();
        session_budget::charge(&root.join("capture-group.json"), 0).unwrap();
        assert_eq!(
            std::fs::read(root.join("capture-group.json")).unwrap(),
            source_group
        );
        let import_elapsed_ms = import_start.elapsed().as_millis();
        let receipt = import_guard.receipt();
        drop(import_guard);
        let archive_receipt: Value = serde_json::from_slice(
            &std::fs::read(format!("{}.budget.json", archive.display())).unwrap(),
        )
        .unwrap();
        let report = json!({"scope":"independent offline cloned retained inputs; not old-parent resume or physical capture", "archive_share_ms":archive_elapsed_ms,"archive_receipt":archive_receipt,"share_receipt":share_receipt,"import_ms":import_elapsed_ms,"import_receipt":receipt,"package":bundle.package,"original_parent_bytes_unchanged":true,"device_operations":false,"ack_sent":false});
        std::fs::write(
            out.join("verification.json"),
            serde_json::to_vec_pretty(&report).unwrap(),
        )
        .unwrap();
        assert!(archive_elapsed_ms < 120000 && import_elapsed_ms < 120000);
        assert_ne!(archive_receipt["partial"], true);
        assert!(!receipt.partial);
    }
}
