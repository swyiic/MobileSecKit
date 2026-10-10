//! Bounded, read-only pages of retained producer metadata. This never analyzes
//! payload bytes or resumes an expired capture/import contract.
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{fs, io::Read, path::Path};

const PAGE_LIMIT: usize = 100;
const PAGE_BYTES: usize = 256 * 1024;

#[cfg(unix)]
fn same_snapshot(a: &fs::Metadata, b: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    a.dev() == b.dev()
        && a.ino() == b.ino()
        && a.len() == b.len()
        && a.mtime() == b.mtime()
        && a.mtime_nsec() == b.mtime_nsec()
        && a.ctime() == b.ctime()
        && a.ctime_nsec() == b.ctime_nsec()
}
#[cfg(not(unix))]
fn same_snapshot(a: &fs::Metadata, b: &fs::Metadata) -> bool {
    a.len() == b.len() && matches!((a.modified(), b.modified()), (Ok(a), Ok(b)) if a == b)
}

fn checked_path(root: &Path, relative: &str) -> Result<std::path::PathBuf, String> {
    super::validate_evidence_relative_path(relative)?;
    let parent = Path::new(relative).parent().unwrap_or(Path::new(""));
    let name = Path::new(relative)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("");
    if !(parent.as_os_str().is_empty() || parent == Path::new("runtime"))
        || !name.starts_with("bound-source-")
        || !name.ends_with(".json")
    {
        return Err("请选择当前导入目录的原始范围来源报告".into());
    }
    let mut path = root.to_path_buf();
    for part in Path::new(relative).components() {
        let std::path::Component::Normal(name) = part else {
            return Err("来源路径无效".into());
        };
        path.push(name);
        let metadata = fs::symlink_metadata(&path).map_err(|e| format!("来源文件不可访问：{e}"))?;
        if metadata.file_type().is_symlink() {
            return Err("来源路径含符号链接".into());
        }
    }
    let canonical = path
        .canonicalize()
        .map_err(|e| format!("来源文件不可访问：{e}"))?;
    if !canonical.starts_with(root) || !canonical.is_file() {
        return Err("来源文件不在当前导入目录内".into());
    }
    Ok(path)
}

// Directory descriptors keep a swapped runtime directory from redirecting
// the read. NONBLOCK also prevents a raced FIFO from blocking open forever.
#[cfg(unix)]
pub(super) fn open_anchored(root: &Path, relative: &str) -> Result<fs::File, String> {
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::fs::OpenOptionsExt;
    fn child(parent: &fs::File, name: &str, directory: bool) -> Result<fs::File, String> {
        let name = std::ffi::CString::new(name).map_err(|_| "来源路径含 NUL")?;
        let flags = libc::O_RDONLY
            | libc::O_NOFOLLOW
            | libc::O_NONBLOCK
            | libc::O_CLOEXEC
            | if directory { libc::O_DIRECTORY } else { 0 };
        let fd = unsafe { libc::openat(parent.as_raw_fd(), name.as_ptr(), flags) };
        if fd < 0 {
            return Err(format!(
                "打开来源文件失败：{}",
                std::io::Error::last_os_error()
            ));
        }
        // Ownership is transferred exactly once; all descriptors close on drop.
        Ok(unsafe { fs::File::from_raw_fd(fd) })
    }
    super::validate_evidence_relative_path(relative)?;
    super::session_deadline::check()?;
    let mut directory = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(root)
        .map_err(|e| format!("打开证据根目录失败：{e}"))?;
    let mut parts = Path::new(relative).components().peekable();
    while let Some(part) = parts.next() {
        super::session_deadline::check()?;
        let std::path::Component::Normal(name) = part else {
            return Err("来源路径无效".into());
        };
        directory = child(
            &directory,
            name.to_str().ok_or("来源文件名无效")?,
            parts.peek().is_some(),
        )?;
        super::session_deadline::check()?;
    }
    if !directory.metadata().map_err(|e| e.to_string())?.is_file() {
        return Err("来源不是常规文件".into());
    }
    super::session_deadline::check()?;
    Ok(directory)
}
#[cfg(not(unix))]
pub(super) fn open_anchored(root: &Path, relative: &str) -> Result<fs::File, String> {
    super::validate_evidence_relative_path(relative)?;
    super::session_deadline::check()?;
    let file = fs::File::open(root.join(relative)).map_err(|e| format!("打开来源文件失败：{e}"))?;
    if !file.metadata().map_err(|e| e.to_string())?.is_file() {
        return Err("来源不是常规文件".into());
    }
    super::session_deadline::check()?;
    Ok(file)
}

pub(super) fn read_page(
    root: &Path,
    package: &str,
    source_report: &str,
    offset: usize,
    limit: usize,
    expected_sha256: Option<&str>,
) -> Result<Value, String> {
    super::session_deadline::check()?;
    if !(1..=PAGE_LIMIT).contains(&limit) {
        return Err("来源记录每页须为 1 到 100 条".into());
    }
    if offset > 0 && expected_sha256.is_none() {
        return Err("后续页缺少来源快照标识，请从首页重新加载".into());
    }
    if expected_sha256.is_some_and(|s| s.len() != 64 || !s.bytes().all(|b| b.is_ascii_hexdigit())) {
        return Err("来源快照标识无效".into());
    }
    let root = root
        .canonicalize()
        .map_err(|e| format!("本地证据根目录不可访问：{e}"))?;
    let path = checked_path(&root, source_report)?;
    let before = fs::symlink_metadata(&path).map_err(|e| format!("读取来源文件失败：{e}"))?;
    if !before.is_file() {
        return Err("来源不是常规文件".into());
    }
    let file = open_anchored(&root, source_report)?;
    let opened = file.metadata().map_err(|e| e.to_string())?;
    if !opened.is_file() {
        return Err("来源不是常规文件".into());
    }
    if !same_snapshot(&before, &opened) {
        return Err("来源文件在打开期间变化，请重新加载".into());
    }
    let byte_limit = super::storage_evidence::BOUND_SOURCE_BYTE_LIMIT;
    if opened.len() > byte_limit {
        return Err("来源报告超过既有 2 MiB 元数据协议上限".into());
    }
    let mut bytes = Vec::with_capacity(opened.len() as usize);
    super::session_budget::CheckedReader::new(file.try_clone().map_err(|e| e.to_string())?, &path)
        .take(byte_limit.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    super::session_deadline::check()?;
    if bytes.len() as u64 != opened.len() || bytes.len() as u64 > byte_limit {
        return Err("来源报告长度在读取期间变化".into());
    }
    let sha = format!("{:x}", Sha256::digest(&bytes));
    if expected_sha256.is_some_and(|s| s != sha) {
        return Err("来源报告已变化，旧页快照失效，请从首页重新加载".into());
    }
    let note: Value =
        serde_json::from_slice(&bytes).map_err(|e| format!("来源报告 JSON 无效：{e}"))?;
    super::session_deadline::check()?;
    if note["schema"] != "kernsight.bound-code-copy/v1" || note["source"]["package"] != package {
        return Err("来源报告协议或包归属与当前采集不一致".into());
    }
    let records = note["records"].as_array().ok_or("来源报告缺少记录数组")?;
    if records.len() > super::storage_evidence::BOUND_SOURCE_RECORD_LIMIT {
        return Err("来源报告超过既有记录协议上限".into());
    }
    if offset > records.len() {
        return Err("来源记录页起点超过当前快照范围".into());
    }
    let mut page = Vec::new();
    let mut encoded = 0;
    for (index, record) in records.iter().enumerate().skip(offset).take(limit) {
        super::session_deadline::check()?;
        let row = json!({"sourceRecordIndex":index,"producerRecord":record});
        let size = serde_json::to_vec(&row).map_err(|e| e.to_string())?.len();
        if encoded + size + 4096 > PAGE_BYTES {
            if page.is_empty() {
                return Err("单条来源记录超过 256 KiB 页面上限，原报告仍保留".into());
            }
            break;
        }
        encoded += size;
        page.push(row);
    }
    let end = offset + page.len();
    let path_after = checked_path(&root, source_report)?;
    if !same_snapshot(&opened, &file.metadata().map_err(|e| e.to_string())?)
        || !same_snapshot(
            &opened,
            &fs::metadata(path_after).map_err(|e| e.to_string())?,
        )
    {
        return Err("来源报告在读取期间变化，拒绝混合快照".into());
    }
    super::session_deadline::check()?;
    let result = json!({"schema":"mobilee.bound-source-page/v1","sourceReport":source_report,
        "sourceSha256":sha,"offset":offset,"limit":limit,"totalRecords":records.len(),
        "nextOffset":(end<records.len()).then_some(end),"records":page,
        "analysisScope":"producer metadata only; payload bytes not read or verified by this page"});
    if serde_json::to_vec(&result)
        .map_err(|e| e.to_string())?
        .len()
        > PAGE_BYTES
    {
        return Err("来源页面超过 256 KiB 响应上限，原报告仍保留".into());
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> (std::path::PathBuf, &'static str) {
        let root =
            std::env::temp_dir().join(format!("mobilee-bound-page-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(root.join("runtime")).unwrap();
        let path = "runtime/bound-source-page.json";
        let records: Vec<Value> = (0..1390)
            .map(|i| json!({"index":i,"padding":"x".repeat(900)}))
            .collect();
        fs::write(root.join(path),serde_json::to_vec(&json!({"schema":"kernsight.bound-code-copy/v1","source":{"package":"com.example.app"},"records":records})).unwrap()).unwrap();
        (root, path)
    }
    #[test]
    fn retained_tail_is_pageable_without_payload_or_analysis() {
        let (root, path) = fixture();
        assert!(fs::metadata(root.join(path)).unwrap().len() > 1_048_576);
        let first = read_page(&root, "com.example.app", path, 0, 100, None).unwrap();
        let tail = read_page(
            &root,
            "com.example.app",
            path,
            1300,
            100,
            first["sourceSha256"].as_str(),
        )
        .unwrap();
        assert_eq!(tail["totalRecords"], 1390);
        assert_eq!(tail["records"].as_array().unwrap().len(), 90);
        assert_eq!(tail["records"][89]["sourceRecordIndex"], 1389);
        assert!(tail["nextOffset"].is_null());
        assert!(tail["records"][0].get("localAnalysis").is_none());
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn changed_source_and_unbound_tail_fail_closed() {
        let (root, path) = fixture();
        let first = read_page(&root, "com.example.app", path, 0, 100, None).unwrap();
        assert!(read_page(&root, "com.example.app", path, 100, 100, None).is_err());
        fs::write(root.join(path),br#"{"schema":"kernsight.bound-code-copy/v1","source":{"package":"com.example.app"},"records":[]}"#).unwrap();
        assert!(read_page(
            &root,
            "com.example.app",
            path,
            0,
            100,
            first["sourceSha256"].as_str()
        )
        .unwrap_err()
        .contains("已变化"));
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn invalid_package_paths_and_limits_are_not_empty_success() {
        let (root, path) = fixture();
        for (p, l) in [
            ("../runtime/bound-source-page.json", 100),
            (path, 0),
            (path, 101),
        ] {
            assert!(read_page(&root, "com.example.app", p, 0, l, None).is_err());
        }
        assert!(read_page(&root, "wrong.package", path, 0, 100, None).is_err());
        assert!(read_page(&root, "com.example.app", path, 0, 100, Some("bad")).is_err());
        fs::remove_dir_all(root).unwrap();
    }
    #[tokio::test]
    async fn expired_original_scope_is_not_success() {
        let (root, path) = fixture();
        let deadline = super::super::session_deadline::Deadline::new(std::time::Duration::ZERO);
        assert!(deadline
            .run(async { read_page(&root, "com.example.app", path, 0, 100, None) })
            .await
            .is_err());
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn oversized_document_and_records_are_rejected() {
        let (root, path) = fixture();
        fs::write(
            root.join(path),
            vec![b' '; super::super::storage_evidence::BOUND_SOURCE_BYTE_LIMIT as usize + 1],
        )
        .unwrap();
        assert!(read_page(&root, "com.example.app", path, 0, 100, None)
            .unwrap_err()
            .contains("2 MiB"));
        let note = json!({"schema":"kernsight.bound-code-copy/v1","source":{"package":"com.example.app"},"records":vec![Value::Null;super::super::storage_evidence::BOUND_SOURCE_RECORD_LIMIT+1]});
        fs::write(root.join(path), serde_json::to_vec(&note).unwrap()).unwrap();
        assert!(read_page(&root, "com.example.app", path, 0, 100, None)
            .unwrap_err()
            .contains("记录协议"));
        fs::remove_dir_all(root).unwrap();
    }
    #[cfg(unix)]
    #[test]
    fn symbolic_links_are_rejected() {
        let (root, path) = fixture();
        let alias = root.join("runtime/bound-source-alias.json");
        std::os::unix::fs::symlink(root.join(path), alias).unwrap();
        assert!(read_page(
            &root,
            "com.example.app",
            "runtime/bound-source-alias.json",
            0,
            100,
            None
        )
        .unwrap_err()
        .contains("符号链接"));
        fs::remove_dir_all(root).unwrap();
    }
    #[cfg(unix)]
    #[test]
    fn generic_open_anchors_nested_directories_and_rejects_symlinked_ancestors() {
        let (root, _) = fixture();
        fs::create_dir_all(root.join("lib/arm64")).unwrap();
        fs::write(root.join("lib/arm64/file.code"), b"retained").unwrap();
        let mut opened = open_anchored(&root, "lib/arm64/file.code").unwrap();
        let mut bytes = Vec::new();
        opened.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, b"retained");
        fs::rename(root.join("lib/arm64"), root.join("lib/original")).unwrap();
        std::os::unix::fs::symlink(root.join("lib/original"), root.join("lib/arm64")).unwrap();
        assert!(open_anchored(&root, "lib/arm64/file.code").is_err());
        assert!(open_anchored(&root, "../outside.code").is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn fifo_cannot_block_the_metadata_reader() {
        let (root, _) = fixture();
        let path = root.join("runtime/bound-source-fifo.json");
        let name = std::ffi::CString::new(path.to_str().unwrap()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
        assert!(open_anchored(&root, "runtime/bound-source-fifo.json")
            .unwrap_err()
            .contains("常规文件"));
        assert!(read_page(
            &root,
            "com.example.app",
            "runtime/bound-source-fifo.json",
            0,
            100,
            None
        )
        .is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    #[ignore = "requires the original retained metadata path and a workspace receipt destination"]
    async fn actual_retained_source_tail_remains_accessible() {
        let root = std::path::PathBuf::from(
            std::env::var("ME_BOUND_SOURCE_PAGE_ROOT").expect("explicit existing evidence root"),
        );
        let source =
            std::env::var("ME_BOUND_SOURCE_PAGE_REPORT").expect("explicit retained source report");
        let deadline =
            super::super::session_deadline::Deadline::new(std::time::Duration::from_secs(10));
        let started = std::time::Instant::now();
        let result=deadline.run(async {
            let first=read_page(&root,"cmb.pb",&source,0,100,None)?;
            let sha=first["sourceSha256"].as_str().unwrap();
            let mut offset=0; let mut seen=0; let mut last=None; let mut pages=0;
            loop {
                let page=read_page(&root,"cmb.pb",&source,offset,100,Some(sha))?;
                let rows=page["records"].as_array().unwrap();
                assert!(serde_json::to_vec(&page).unwrap().len()<=PAGE_BYTES);
                for row in rows { assert_eq!(row["sourceRecordIndex"].as_u64(),Some(seen)); seen+=1;last=row["sourceRecordIndex"].as_u64(); }
                pages+=1;
                if let Some(next)=page["nextOffset"].as_u64() {offset=next as usize;} else {break;}
            }
            assert_eq!(seen,1390);assert_eq!(last,Some(1389));
            Ok(json!({"schema":"mobilee.actual-bound-source-page-acceptance/v1","sourceReport":source,"sourceSha256":sha,"totalRecords":seen,"lastRecordIndex":last,"pages":pages,"payloadBytesRead":0,"metadataOnly":true,"elapsedMs":started.elapsed().as_millis()}))
        }).await.unwrap();
        let output =
            std::env::var("ME_BOUND_SOURCE_PAGE_ACCEPTANCE").expect("explicit workspace receipt");
        fs::write(output, serde_json::to_vec_pretty(&result).unwrap()).unwrap();
    }
}
