//! Bounded, manifest-driven streams; one ADB process carries several objects.
//! Remote names never become local paths. A frame is published only after its
//! declared length, SHA256 and boundary all verify; failures retain prefixes.
use super::session_budget;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::Write,
    path::{Component, Path, PathBuf},
    process::Stdio,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt},
    process::Command,
    time::Duration,
};
use uuid::Uuid;

const MAX_BATCH_FILES: usize = 128;
const MAX_BATCH_SCRIPT: usize = 48 * 1024;
// Group split threshold; an individual object may exceed it but stays under MAX_OBJECT_BYTES.
const BATCH_GROUP_BYTES: u64 = 64 * 1024 * 1024;
const MAX_OBJECT_BYTES: u64 = 8 * 1024 * 1024 * 1024;

#[derive(Clone, Debug)]
struct Item {
    path: String,
    bytes: u64,
    hash: String,
}
#[derive(Clone)]
struct Batch {
    nonce: String,
    items: Vec<Item>,
    script: String,
}

fn item(row: &Value) -> Result<Item, String> {
    let path = row["path"].as_str().ok_or("missing transfer path")?;
    super::validate_evidence_relative_path(path)?;
    let bytes = row["bytes"]
        .as_u64()
        .filter(|n| *n <= MAX_OBJECT_BYTES)
        .ok_or("invalid transfer length")?;
    let hash = row["sha256"]
        .as_str()
        .filter(|h| {
            h.len() == 64
                && h.bytes()
                    .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        })
        .ok_or("invalid transfer hash")?;
    Ok(Item {
        path: path.into(),
        bytes,
        hash: hash.into(),
    })
}
fn begin(nonce: &str, index: usize, bytes: u64) -> String {
    format!("ME_BATCH_BEGIN {nonce} {index} {bytes}\n")
}
fn end(nonce: &str, index: usize) -> String {
    format!("\nME_BATCH_END {nonce} {index}\n")
}

fn script(remote: &str, nonce: &str, items: &[Item]) -> Result<String, String> {
    let root = Path::new(remote);
    if !root.is_absolute()
        || root
            .components()
            .any(|c| !matches!(c, Component::RootDir | Component::Normal(_)))
        || remote.contains(['\n', '\r', '\0'])
    {
        return Err("unsafe remote root".into());
    }
    let mut out = String::from("set -e\n");
    // Reject symlink roots and ancestors. No mutation, chmod or target action.
    for ancestor in root.ancestors().filter(|p| *p != Path::new("/")) {
        out.push_str(&format!(
            "test ! -L {}\n",
            crate::shell_quote(&ancestor.to_string_lossy())
        ));
    }
    out.push_str(&format!("cd {}\n", crate::shell_quote(remote)));
    for (index, file) in items.iter().enumerate() {
        for ancestor in Path::new(&file.path)
            .ancestors()
            .filter(|p| !p.as_os_str().is_empty())
        {
            out.push_str(&format!(
                "test ! -L {}\n",
                crate::shell_quote(&format!("./{}", ancestor.display()))
            ));
        }
        let source = crate::shell_quote(&format!("./{}", file.path));
        out.push_str(&format!("test -f {source}\ntest \"$(stat -c %s {source})\" = {}\nprintf %s {}\ncat {source}\nprintf %s {}\n", file.bytes, crate::shell_quote(&begin(nonce,index,file.bytes)), crate::shell_quote(&end(nonce,index))));
    }
    Ok(out)
}
fn batches(remote: &str, items: Vec<Item>) -> Result<Vec<Batch>, String> {
    let mut out = Vec::new();
    let mut pending = Vec::new();
    let mut bytes = 0_u64;
    let mut nonce = Uuid::new_v4().to_string();
    for item in items {
        let mut proposed = pending.clone();
        proposed.push(item.clone());
        let text = script(remote, &nonce, &proposed)?;
        if !pending.is_empty()
            && (proposed.len() > MAX_BATCH_FILES
                || crate::root_shell_command(&text).len() > MAX_BATCH_SCRIPT
                || bytes.saturating_add(item.bytes) > BATCH_GROUP_BYTES)
        {
            let text = script(remote, &nonce, &pending)?;
            out.push(Batch {
                nonce,
                items: std::mem::take(&mut pending),
                script: text,
            });
            nonce = Uuid::new_v4().to_string();
            bytes = 0;
        }
        bytes = bytes.checked_add(item.bytes).ok_or("batch size overflow")?;
        pending.push(item);
        if crate::root_shell_command(&script(remote, &nonce, &pending)?).len() > MAX_BATCH_SCRIPT {
            return Err("source path exceeds bounded command envelope".into());
        }
    }
    if !pending.is_empty() {
        out.push(Batch {
            script: script(remote, &nonce, &pending)?,
            nonce,
            items: pending,
        });
    }
    Ok(out)
}

fn check_destination(root: &Path, path: &Path) -> Result<(), String> {
    for ancestor in path.ancestors().take_while(|p| p.starts_with(root)) {
        if std::fs::symlink_metadata(ancestor).is_ok_and(|m| m.file_type().is_symlink()) {
            return Err("local output path escapes via symlink".into());
        }
    }
    session_budget::charge(path, 0).map_err(|e| e.to_string())
}
pub(super) fn verify_local_object(
    source: &Path,
    fence: &Path,
    expected: u64,
    hash: &str,
) -> Result<bool, String> {
    use std::io::Read;
    session_budget::charge(fence, 0).map_err(|e| e.to_string())?;
    let metadata = std::fs::symlink_metadata(source).map_err(|e| e.to_string())?;
    if !metadata.is_file() || metadata.len() != expected {
        return Ok(false);
    }
    let mut input = std::fs::File::open(source).map_err(|e| e.to_string())?;
    let mut digest = Sha256::new();
    let mut count = 0_u64;
    let mut buffer = [0_u8; 65536];
    loop {
        session_budget::charge(fence, 0).map_err(|e| e.to_string())?;
        let n = input.read(&mut buffer).map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        }
        count = count
            .checked_add(n as u64)
            .ok_or("local object size overflow")?;
        if count > expected {
            return Ok(false);
        }
        digest.update(&buffer[..n]);
    }
    session_budget::charge(fence, 0).map_err(|e| e.to_string())?;
    Ok(count == expected && format!("{:x}", digest.finalize()) == hash)
}

async fn boundary<R: AsyncRead + Unpin>(reader: &mut R, expected: &str) -> Result<(), String> {
    let mut bytes = vec![0; expected.len()];
    reader
        .read_exact(&mut bytes)
        .await
        .map_err(|e| format!("truncated batch boundary: {e}"))?;
    if bytes != expected.as_bytes() {
        return Err("batch boundary mismatch; source length changed or stream corrupt".into());
    }
    Ok(())
}
async fn receive<R: AsyncRead + Unpin>(
    reader: &mut R,
    root: &Path,
    batch: &Batch,
) -> Result<(), String> {
    for (index, file) in batch.items.iter().enumerate() {
        session_budget::charge(root, 0).map_err(|e| e.to_string())?;
        boundary(reader, &begin(&batch.nonce, index, file.bytes)).await?;
        let destination = root.join(&file.path);
        check_destination(root, &destination)?;
        if destination.exists() || std::fs::symlink_metadata(&destination).is_ok() {
            return Err("transfer destination exists; originals never overwritten".into());
        }
        for ancestor in destination.ancestors().take_while(|p| p.starts_with(root)) {
            if std::fs::symlink_metadata(ancestor).is_ok_and(|m| m.file_type().is_symlink()) {
                return Err("local output path escapes via symlink".into());
            }
        }
        if let Some(parent) = destination.parent() {
            std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        let partial = destination.with_extension(format!("partial-{}", Uuid::new_v4()));
        let mut output = session_budget::BudgetFile::create(&partial).map_err(|e| e.to_string())?;
        let mut remaining = file.bytes;
        let mut hash = Sha256::new();
        let mut buffer = [0_u8; 65536];
        while remaining > 0 {
            session_budget::charge(&partial, 0).map_err(|e| {
                format!(
                    "transfer budget exhausted; partial {}: {e}",
                    partial.display()
                )
            })?;
            let limit = remaining.min(buffer.len() as u64) as usize;
            let n = reader
                .read(&mut buffer[..limit])
                .await
                .map_err(|e| format!("source read failed; partial {}: {e}", partial.display()))?;
            if n == 0 {
                return Err(format!("source short read; partial {}", partial.display()));
            }
            output.write_all(&buffer[..n]).map_err(|e| {
                format!(
                    "transfer budget/write failed; partial {}: {e}",
                    partial.display()
                )
            })?;
            hash.update(&buffer[..n]);
            remaining -= n as u64;
        }
        if format!("{:x}", hash.finalize()) != file.hash {
            return Err(format!(
                "source SHA256 mismatch; partial {}",
                partial.display()
            ));
        }
        boundary(reader, &end(&batch.nonce, index))
            .await
            .map_err(|e| format!("{e}; partial {}", partial.display()))?;
        output
            .sync_all()
            .map_err(|e| format!("sync failed; partial {}: {e}", partial.display()))?;
        drop(output);
        // Atomic no-clobber publication. Only remove our successful staging link.
        std::fs::hard_link(&partial, &destination)
            .map_err(|e| format!("publish failed; partial {}: {e}", partial.display()))?;
        std::fs::remove_file(&partial).map_err(|e| e.to_string())?;
    }
    let mut extra = [0_u8; 1];
    if reader.read(&mut extra).await.map_err(|e| e.to_string())? != 0 {
        return Err("trailing batch data; source growth or unexpected output".into());
    }
    Ok(())
}

pub(super) async fn transfer(
    serial: &str,
    remote: &str,
    root: &Path,
    rows: &[Value],
    known: BTreeMap<(String, u64), PathBuf>,
) -> Result<(), String> {
    let started = std::time::Instant::now();
    let items = rows.iter().map(item).collect::<Result<Vec<_>, _>>()?;
    let mut seen = BTreeSet::new();
    let mut unique = BTreeSet::new();
    let mut pending = Vec::new();
    let mut verified = known;
    for file in &items {
        check_destination(root, &root.join(&file.path))?;
        if !seen.insert(file.path.clone()) {
            return Err("duplicate transfer destination".into());
        }
        let key = (file.hash.clone(), file.bytes);
        if let Some(prior) = verified.get(&key) {
            if super::reuse_verified_transfer(
                prior,
                &root.join(&file.path),
                file.bytes,
                &file.hash,
            )? {
                continue;
            }
        }
        if unique.insert(key) {
            pending.push(file.clone());
        }
    }
    let streamed_objects = pending.len();
    let streamed_bytes = pending.iter().map(|i| i.bytes).sum::<u64>();
    let planned_batches = batches(remote, pending)?;
    let adb_batches = planned_batches.len();
    for batch in planned_batches {
        let ms = session_budget::remaining_ms(root, 120000).map_err(|e| e.to_string())?;
        let remote_shell = crate::root_shell_command(&batch.script);
        let mut command = Command::new("adb");
        command
            .args(["-s", serial, "exec-out", &remote_shell])
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        let received_root = root.to_owned();
        let received_batch = batch.clone();
        if let Err(error) =
            super::session_deadline::stream_output(
                command,
                Duration::from_millis(ms),
                move |mut reader| async move {
                    receive(&mut reader, &received_root, &received_batch).await
                },
            )
            .await
        {
            let reason = if error.contains("deadline") || error.contains("timeout") {
                "time_budget_exhausted"
            } else {
                "source_transfer_failed"
            };
            session_budget::record_failure(root, reason);
            return Err(format!(
                "{error}; received objects/partial retained at {}",
                root.display()
            ));
        }
        for file in batch.items {
            verified.insert((file.hash, file.bytes), root.join(file.path));
        }
    }
    for file in items {
        let path = root.join(&file.path);
        if path.exists() {
            if !verify_local_object(&path, &path, file.bytes, &file.hash)? {
                return Err("existing received path no longer matches its declared object".into());
            }
            continue;
        }
        let prior = verified
            .get(&(file.hash.clone(), file.bytes))
            .ok_or("missing verified transfer object")?;
        if !super::reuse_verified_transfer(prior, &path, file.bytes, &file.hash)? {
            return Err("verified alias could not be retained".into());
        }
    }
    session_budget::write_json(root.join("batch-transfer-receipt.json"),&serde_json::json!({"schema":"mobilee.batch-transfer-receipt/v1","complete":true,"plannedPaths":rows.len(),"streamedUniqueObjects":streamed_objects,"streamedPayloadBytes":streamed_bytes,"adbStreamCommands":adb_batches,"elapsedMs":started.elapsed().as_millis(),"verification":"manifest paths; per-object exact length + SHA256 + framed boundary; finite output deadline; owned host child reaped"})).map_err(|e|e.to_string())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::timeout;
    fn fixture(path: &str, bytes: &[u8]) -> Item {
        Item {
            path: path.into(),
            bytes: bytes.len() as u64,
            hash: format!("{:x}", Sha256::digest(bytes)),
        }
    }
    fn wire(batch: &Batch, payloads: &[&[u8]]) -> Vec<u8> {
        let mut out = Vec::new();
        for (i, (file, data)) in batch.items.iter().zip(payloads).enumerate() {
            out.extend(begin(&batch.nonce, i, file.bytes).as_bytes());
            out.extend(*data);
            out.extend(end(&batch.nonce, i).as_bytes());
        }
        out
    }
    fn root() -> PathBuf {
        let p = std::env::temp_dir().join(format!("me-batch-{}", Uuid::new_v4()));
        std::fs::create_dir(&p).unwrap();
        p
    }
    #[test]
    fn large_plan_uses_bounded_batches_and_quotes_paths() {
        let files = (0..1850)
            .map(|i| fixture(&format!("runtime/object-{i}.bin"), b"x"))
            .collect();
        let planned = batches("/data/local/tmp/ksight/captures/fixture/dump", files).unwrap();
        assert!(planned.len() < 40);
        assert_eq!(planned.iter().map(|b| b.items.len()).sum::<usize>(), 1850);
        assert!(planned.iter().all(|b| b.items.len() <= MAX_BATCH_FILES
            && crate::root_shell_command(&b.script).len() <= MAX_BATCH_SCRIPT));
        assert!(
            item(&serde_json::json!({"path":"../outside","bytes":1,"sha256":"0".repeat(64)}))
                .is_err()
        );
        let dangerous = fixture("runtime/$(touch pwn)' x.bin", b"x");
        assert!(script(
            "/data/local/tmp/ksight/captures/fixture/dump",
            "nonce",
            &[dangerous]
        )
        .unwrap()
        .contains("'\\''"));
        assert!(batches("/data/../outside", vec![fixture("file", b"x")]).is_err());
    }
    #[tokio::test]
    async fn binary_frames_empty_objects_and_boundaries_are_verified() {
        let root = root();
        let data = &b"\0\xff\nME_BATCH_END arbitrary\0"[..];
        let batch = batches(
            "/data/local/tmp/ksight/captures/fixture/dump",
            vec![fixture("runtime/data", data), fixture("empty", b"")],
        )
        .unwrap()
        .remove(0);
        receive(&mut &wire(&batch, &[data, b""])[..], &root, &batch)
            .await
            .unwrap();
        assert_eq!(std::fs::read(root.join("runtime/data")).unwrap(), data);
        assert!(root.join("empty").is_file());
        assert!(receive(&mut &wire(&batch, &[data, b""])[..], &root, &batch)
            .await
            .is_err());
        std::fs::remove_dir_all(root).unwrap();
    }
    #[tokio::test]
    async fn changed_length_hash_and_late_failure_preserve_prior_objects() {
        for bad in [&b"wrong"[..], &b"short"[..], &b"abcdefgrown"[..]] {
            let root = root();
            let batch = batches(
                "/data/local/tmp/ksight/captures/fixture/dump",
                vec![fixture("good", b"good"), fixture("bad", b"abcdef")],
            )
            .unwrap()
            .remove(0);
            assert!(
                receive(&mut &wire(&batch, &[b"good", bad])[..], &root, &batch)
                    .await
                    .is_err()
            );
            assert_eq!(std::fs::read(root.join("good")).unwrap(), b"good");
            assert!(!root.join("bad").exists());
            assert!(std::fs::read_dir(&root)
                .unwrap()
                .filter_map(Result::ok)
                .any(|p| p.file_name().to_string_lossy().contains("partial-")));
            std::fs::remove_dir_all(root).unwrap();
        }
    }
    #[tokio::test]
    async fn quota_and_deadline_stop_without_publishing_incomplete_data() {
        use tokio::io::AsyncWriteExt;
        let root = root();
        let batch = batches(
            "/data/local/tmp/ksight/captures/fixture/dump",
            vec![fixture("bad", b"abcdef")],
        )
        .unwrap()
        .remove(0);
        let guard = session_budget::Guard::install(vec![root.clone()], 3, 1000).unwrap();
        assert!(receive(&mut &wire(&batch, &[b"abcdef"])[..], &root, &batch)
            .await
            .is_err());
        assert!(guard.receipt().partial);
        assert!(!root.join("bad").exists());
        drop(guard);
        let (mut reader, mut writer) = tokio::io::duplex(512);
        writer
            .write_all(begin(&batch.nonce, 0, 6).as_bytes())
            .await
            .unwrap();
        writer.write_all(b"abc").await.unwrap();
        let guard = session_budget::Guard::install(vec![root.clone()], 64, 30).unwrap();
        assert!(timeout(
            Duration::from_millis(session_budget::remaining_ms(&root, 120000).unwrap()),
            receive(&mut reader, &root, &batch)
        )
        .await
        .is_err());
        assert!(!root.join("bad").exists());
        drop(guard);
        drop(writer);
        std::fs::remove_dir_all(root).unwrap();
    }
    #[cfg(unix)]
    #[tokio::test]
    async fn local_symlink_cannot_escape_even_without_a_budget_guard() {
        let root = root();
        let outside = root
            .parent()
            .unwrap()
            .join(format!("me-batch-outside-{}", Uuid::new_v4()));
        std::fs::create_dir(&outside).unwrap();
        std::os::unix::fs::symlink(&outside, root.join("escape")).unwrap();
        let batch = batches(
            "/data/local/tmp/ksight/captures/fixture/dump",
            vec![fixture("escape/bad", b"abcdef")],
        )
        .unwrap()
        .remove(0);
        assert!(receive(&mut &wire(&batch, &[b"abcdef"])[..], &root, &batch)
            .await
            .is_err());
        assert!(!outside.join("bad").exists());
        std::fs::remove_dir_all(root).unwrap();
        std::fs::remove_dir(outside).unwrap();
    }
    #[tokio::test]
    async fn existing_aliases_preserve_source_and_output_conflicts() {
        let root = root();
        let source = root.join("source");
        std::fs::write(&source, b"abcdef").unwrap();
        let hash = format!("{:x}", Sha256::digest(b"abcdef"));
        let known = BTreeMap::from([((hash.clone(), 6), source.clone())]);
        let rows = vec![
            serde_json::json!({"path":"a","bytes":6,"sha256":hash}),
            serde_json::json!({"path":"b","bytes":6,"sha256":hash}),
        ];
        transfer(
            "no-adb-needed",
            "/data/local/tmp/ksight/captures/fixture/dump",
            &root,
            &rows,
            known.clone(),
        )
        .await
        .unwrap();
        assert_eq!(std::fs::read(root.join("a")).unwrap(), b"abcdef");
        assert_eq!(std::fs::read(root.join("b")).unwrap(), b"abcdef");
        assert!(transfer(
            "no-adb-needed",
            "/data/local/tmp/ksight/captures/fixture/dump",
            &root,
            &rows,
            known
        )
        .await
        .is_err());
        assert_eq!(std::fs::read(&source).unwrap(), b"abcdef");
        std::fs::remove_dir_all(root).unwrap();
    }
    #[tokio::test]
    async fn local_alias_hash_respects_expired_original_fence() {
        let root = root();
        let source = root.join("source");
        std::fs::write(&source, vec![9_u8; 1024 * 1024]).unwrap();
        let hash = format!("{:x}", Sha256::digest(vec![9_u8; 1024 * 1024]));
        let guard = session_budget::Guard::install(vec![root.clone()], 64, 1).unwrap();
        tokio::time::sleep(Duration::from_millis(10)).await;
        assert!(verify_local_object(&source, &root.join("alias"), 1024 * 1024, &hash).is_err());
        assert!(guard.receipt().partial);
        assert!(!root.join("alias").exists());
        drop(guard);
        std::fs::remove_dir_all(root).unwrap();
    }
}
