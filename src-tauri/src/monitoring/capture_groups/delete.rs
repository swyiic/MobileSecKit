//! One-click durable deletion. The small tombstone hides the complete family;
//! physical cleanup runs independently and retries after disconnect/restart.
use super::*;
use base64::{engine::general_purpose::STANDARD, Engine as _};

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Progress {
    pub local_done: bool,
    pub device_done: bool,
    pub error: Option<String>,
}
impl Progress {
    pub(super) fn complete(&self) -> bool {
        self.local_done && self.device_done
    }
}
static WORKERS: Mutex<BTreeSet<(PathBuf, Uuid)>> = Mutex::new(BTreeSet::new());
struct Worker(PathBuf, Uuid);
impl Drop for Worker {
    fn drop(&mut self) {
        if let Ok(mut workers) = WORKERS.lock() {
            workers.remove(&(self.0.clone(), self.1));
        }
    }
}

fn enqueue(root: &Path, id: Uuid, sources: Vec<String>) -> Result<trash::TrashEntry, String> {
    if let Ok(entry) = trash::read_entry(root, id) {
        if entry.deletion.is_some() {
            return Ok(entry);
        }
    }
    // No USB round trip or recursive file inventory on the click path.
    let mut entry = trash::trash_at(root, id, sources)?;
    if entry.deletion.is_none() {
        entry.deletion = Some(Progress::default());
        trash::write_entry(root, &entry)?;
    }
    Ok(entry)
}

#[tauri::command]
pub fn delete_kernsight_group(
    app: tauri::AppHandle,
    parent_id: Uuid,
    imported_roots: Vec<String>,
) -> Result<trash::TrashEntry, String> {
    let root = root(&app)?;
    let entry = {
        let _guard = IO_LOCK.lock().map_err(|e| e.to_string())?;
        enqueue(&root, parent_id, imported_roots)?
    };
    schedule(root, parent_id);
    Ok(entry)
}

pub fn resume_pending(app: tauri::AppHandle) {
    tauri::async_runtime::spawn(async move {
        let entries =
            root(&app).and_then(|root| trash::list_at(&root).map(|entries| (root, entries)));
        match entries {
            Ok((root, entries)) => {
                for entry in entries {
                    if entry.deletion.as_ref().is_some_and(|d| !d.complete()) {
                        schedule(root.clone(), entry.group.id);
                    }
                }
            }
            Err(error) => eprintln!("读取会话删除队列失败：{error}"),
        }
    });
}

pub(super) fn schedule(root: PathBuf, id: Uuid) {
    let Ok(mut workers) = WORKERS.lock() else {
        return;
    };
    if !workers.insert((root.clone(), id)) {
        return;
    }
    tauri::async_runtime::spawn(async move {
        let _worker = Worker(root.clone(), id);
        loop {
            if sweep(&root, id).await.unwrap_or(false) {
                break;
            }
            tokio::time::sleep(Duration::from_secs(30)).await;
        }
    });
}

async fn sweep(root: &Path, id: Uuid) -> Result<bool, String> {
    let mut entry = trash::read_entry(root, id)?;
    let mut progress = entry.deletion.clone().ok_or("会话未请求删除")?;
    if progress.complete() {
        return Ok(true);
    }
    // A shared child is not owned exclusively by this family.
    let root_copy = root.to_owned();
    let candidate = entry.clone();
    let local = tauri::async_runtime::spawn_blocking(move || {
        purge::check_shared_ownership(
            &root_copy,
            &candidate.group,
            &candidate.imported_roots,
            &|| Ok(()),
        )?;
        if !candidate.deletion.as_ref().is_some_and(|d| d.local_done) {
            remove_local(&root_copy, &candidate)?;
        }
        Ok::<_, String>(())
    })
    .await
    .map_err(|e| e.to_string())?;
    let mut errors = Vec::new();
    match local {
        Ok(()) => progress.local_done = true,
        Err(error) => errors.push(format!("本地：{error}")),
    }
    // Ownership conflicts must also block remote deletion.
    if errors.is_empty() && !progress.device_done {
        match remove_device(root, &mut entry).await {
            Ok(()) => progress.device_done = true,
            Err(error) => errors.push(format!("手机待清理：{error}")),
        }
    }
    progress.error = (!errors.is_empty()).then(|| errors.join("；"));
    let complete = progress.complete();
    entry.deletion = Some(progress);
    let _guard = IO_LOCK.lock().map_err(|e| e.to_string())?;
    trash::write_entry(root, &entry)?;
    Ok(complete)
}

fn same_family(a: &Group, b: &Group) -> bool {
    a.id == b.id
        && a.serial == b.serial
        && a.package == b.package
        && a.created_unix_ms == b.created_unix_ms
}

fn remove_local(root: &Path, entry: &trash::TrashEntry) -> Result<(), String> {
    let app_root = purge_local::safe_path(root)?;
    for source in &entry.imported_roots {
        let source = Path::new(source);
        if !source.try_exists().map_err(|e| e.to_string())? {
            continue;
        }
        let source = purge_local::safe_path(source)?;
        if source.starts_with(&app_root) || app_root.starts_with(&source) {
            return Err("导入目录与应用数据目录重叠".into());
        }
        let manifest = source.join("capture-group.json");
        if !manifest.exists()
            && std::fs::read_dir(&source)
                .map_err(|e| e.to_string())?
                .next()
                .is_none()
        {
            std::fs::remove_dir(&source).map_err(|e| e.to_string())?;
            continue;
        }
        purge_local::safe_path(&manifest)?;
        let imported: Group =
            serde_json::from_str(&read_bounded_text(&manifest, MAX_CAPTURE_GROUP_BYTES)?)
                .map_err(|e| e.to_string())?;
        imported.validate()?;
        if !same_family(&entry.group, &imported) {
            return Err("导入目录属于其他主会话".into());
        }
        purge_local::reject_nested_mounts(&source)?;
        // Keep ownership manifest until the last unlink, so interrupted cleanup
        // can retry without relying on the success receipt of a failed capture.
        for child in std::fs::read_dir(&source).map_err(|e| e.to_string())? {
            let child = child.map_err(|e| e.to_string())?;
            if child.path() == manifest {
                continue;
            }
            if child.file_type().map_err(|e| e.to_string())?.is_dir() {
                std::fs::remove_dir_all(child.path()).map_err(|e| e.to_string())?;
            } else {
                std::fs::remove_file(child.path()).map_err(|e| e.to_string())?;
            }
        }
        std::fs::remove_file(manifest).map_err(|e| e.to_string())?;
        std::fs::remove_dir(source).map_err(|e| e.to_string())?;
    }
    let manifest = path(root, entry.group.id);
    if manifest.exists() {
        purge_local::safe_path(&manifest)?;
        let current: Group =
            serde_json::from_str(&read_bounded_text(&manifest, MAX_CAPTURE_GROUP_BYTES)?)
                .map_err(|e| e.to_string())?;
        if !same_family(&current, &entry.group) {
            return Err("本地主会话身份变化".into());
        }
        std::fs::remove_file(manifest).map_err(|e| e.to_string())?;
    }
    Ok(())
}

fn device_base(group: &Group) -> Result<String, String> {
    group.validate()?;
    Ok(runtime_paths_from_group(Some(group))?
        .map(|p| p.root)
        .unwrap_or_else(|| "/data/local/tmp/ksight".into()))
}

async fn shell(serial: &str, script: &str) -> Result<String, String> {
    // Never stop unrelated collectors. A running collector postpones physical
    // removal; the durable deletion request remains hidden and retries later.
    let script = format!("set -e\nif pidof ksightd >/dev/null; then echo '采集进程仍在运行，稍后自动重试' >&2; exit 80; fi\n{script}");
    let command = format!(
        "su -c {}",
        crate::shell_quote(&format!(
            "timeout -s TERM -k 2 20 sh -c {}",
            crate::shell_quote(&script)
        ))
    );
    let output = crate::run_device_adb_with_timeout(
        serial,
        &["shell", &command],
        Duration::from_secs(25),
        "删除会话",
    )
    .await?;
    if output.code != Some(0) {
        return Err(format!(
            "{} {} (exit {:?})",
            output.stderr.trim(),
            output.stdout.trim(),
            output.code
        ));
    }
    Ok(output.stdout)
}

fn read_spool_owners(text: &str, group: &Group) -> Result<BTreeMap<Uuid, Uuid>, String> {
    if text.len() > 16 * 1024 * 1024 {
        return Err("设备归属索引过大".into());
    }
    let mut owners = BTreeMap::new();
    for line in text.lines().filter(|l| !l.is_empty()) {
        let (id, encoded) = line.split_once(' ').ok_or("设备归属索引格式错误")?;
        let id = Uuid::parse_str(id).map_err(|e| e.to_string())?;
        let bytes = STANDARD.decode(encoded).map_err(|e| e.to_string())?;
        let note: Value = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
        let parent = note["relation"]["parent_id"]
            .as_str()
            .and_then(|s| Uuid::parse_str(s).ok())
            .ok_or("spool 缺父会话身份")?;
        if note["session_id"].as_str() != Some(id.to_string().as_str())
            || (parent == group.id && note["package"].as_str() != Some(&group.package))
        {
            return Err("spool 归属冲突".into());
        }
        owners.insert(id, parent);
    }
    Ok(owners)
}

async fn remove_device(root: &Path, entry: &mut trash::TrashEntry) -> Result<(), String> {
    let group = &entry.group;
    let base = device_base(group)?;
    for stage in &group.stages {
        for a in &stage.attempts {
            if let Some(remote) = &a.remote_artifact_root {
                let expected = format!(
                    "{base}/captures/{}/{}/{}/dump",
                    group.id, stage.id, a.relation.attempt_id
                );
                if remote != &expected {
                    return Err("旧证据路径不属于此主会话目录，已保留，需单独清理".into());
                }
            }
        }
    }
    let spool = format!("{base}/spool");
    // Read tiny relation records only, never evidence payloads or content hashes.
    let inventory = format!("{}\nfor d in {spool}/*; do\n [ -d \"$d\" ] || continue\n [ ! -L \"$d\" ] || exit 71\n f=\"$d/capture-relation.json\"\n [ -f \"$f\" ] || continue\n [ ! -L \"$f\" ] || exit 71\n [ \"$(stat -c %s \"$f\")\" -le 32768 ] || exit 75\n printf '%s ' \"${{d##*/}}\"\n base64 \"$f\" | tr -d '\\n'\n printf '\\n'\ndone\n", purge_device::canonical_checks(&spool, true)?);
    let owners = read_spool_owners(&shell(&group.serial, &inventory).await?, group)?;
    let mut sessions: BTreeSet<Uuid> = entry.retained_session_ids.iter().copied().collect();
    sessions.extend(group.session_ids());
    sessions.extend(
        owners
            .iter()
            .filter_map(|(s, p)| (*p == group.id).then_some(*s)),
    );
    if sessions
        .iter()
        .any(|s| owners.get(s).is_some_and(|p| *p != group.id))
    {
        return Err("子会话属于其他主会话".into());
    }
    // Preserve crash-discovered child identities before the first unlink so
    // partial deletion cannot make children reappear as unrelated legacy rows.
    entry.retained_session_ids = sessions.iter().copied().collect();
    trash::write_entry(root, entry)?;
    let mut paths = vec![format!("{base}/captures/{}", group.id)];
    paths.extend(sessions.into_iter().map(|id| format!("{spool}/{id}")));
    // Bound the ADB command length even for a parent with many retries.
    for batch in paths.chunks(32) {
        let mut script = purge_device::canonical_checks(&base, true)?;
        script.push_str(&purge_device::canonical_checks(
            &format!("{base}/captures"),
            true,
        )?);
        script.push_str(&purge_device::canonical_checks(&spool, true)?);
        script.push_str(&purge_device::mount_checks(&base)?);
        for path in batch {
            let q = crate::shell_quote(path);
            script.push_str(&format!("[ ! -L {q} ] || exit 71\nif [ -e {q} ]; then [ \"$(readlink -f {q})\" = {q} ] || exit 72; fi\n"));
        }
        // One recursive unlink per owned directory; no per-file ADB/SHA calls.
        for path in batch {
            let q = crate::shell_quote(path);
            script.push_str(&format!(
                "rm -rf -- {q}\n[ ! -e {q} ] && [ ! -L {q} ] || exit 79\n"
            ));
        }
        shell(&group.serial, &script).await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Temp(PathBuf);
    impl Temp {
        fn new() -> Self {
            let p = std::env::temp_dir().join(format!("me-delete-test-{}", Uuid::new_v4()));
            std::fs::create_dir_all(&p).unwrap();
            Self(p)
        }
    }
    impl Drop for Temp {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    fn failed() -> Group {
        let mut g = super::super::tests::group();
        let r = g.start("l0", epoch()).unwrap();
        g.finish(
            &r,
            Some(Uuid::new_v4()),
            None,
            Some("ADB disconnected".into()),
        )
        .unwrap();
        g.stages[0].attempts[0].remote_lifecycle = None;
        g
    }
    #[test]
    fn failed_without_receipt_enqueues_and_removes_family_without_touching_neighbor() {
        let t = Temp::new();
        let root = t.0.join("groups");
        let g = failed();
        let neighbor = failed();
        save(&root, &g).unwrap();
        save(&root, &neighbor).unwrap();
        let import = t.0.join("import");
        std::fs::create_dir(&import).unwrap();
        std::fs::write(
            import.join("capture-group.json"),
            serde_json::to_vec(&g).unwrap(),
        )
        .unwrap();
        std::fs::write(import.join("child.dex"), b"fixture").unwrap();
        let before = std::time::Instant::now();
        let entry = enqueue(&root, g.id, vec![import.to_string_lossy().into_owned()]).unwrap();
        assert!(before.elapsed() < Duration::from_secs(1));
        assert!(trash::managed_is_trashed(&root, g.id).unwrap());
        assert_eq!(entry.retained_session_ids.len(), 1);
        purge::check_shared_ownership(&root, &g, &entry.imported_roots, &|| Ok(())).unwrap();
        remove_local(&root, &entry).unwrap();
        assert!(!path(&root, g.id).exists());
        assert!(!import.exists());
        assert!(path(&root, neighbor.id).exists());
        // Restart/repeat does not need the deleted original manifest.
        let retried = enqueue(&root, g.id, vec![]).unwrap();
        remove_local(&root, &retried).unwrap();
        assert!(retried.deletion.is_some());
        assert!(trash::managed_is_trashed(&root, g.id).unwrap());
    }
    #[test]
    fn running_rejected_and_shared_child_protected() {
        let t = Temp::new();
        let mut g = super::super::tests::group();
        g.start("l0", epoch()).unwrap();
        save(&t.0, &g).unwrap();
        assert!(enqueue(&t.0, g.id, vec![]).is_err());
        let g = failed();
        let mut other = failed();
        other.stages[0].attempts[0].session_id = g.stages[0].attempts[0].session_id;
        save(&t.0, &g).unwrap();
        save(&t.0, &other).unwrap();
        assert!(purge::check_shared_ownership(&t.0, &g, &[], &|| Ok(())).is_err());
    }
    #[test]
    fn import_symlink_and_foreign_manifest_are_not_removed() {
        let t = Temp::new();
        let g = failed();
        let root = t.0.join("groups");
        save(&root, &g).unwrap();
        let source = t.0.join("source");
        std::fs::create_dir(&source).unwrap();
        std::fs::write(
            source.join("capture-group.json"),
            serde_json::to_vec(&g).unwrap(),
        )
        .unwrap();
        let entry = enqueue(&root, g.id, vec![source.to_string_lossy().into_owned()]).unwrap();
        std::fs::write(
            source.join("capture-group.json"),
            serde_json::to_vec(&failed()).unwrap(),
        )
        .unwrap();
        assert!(remove_local(&root, &entry).is_err());
        assert!(source.exists());
        #[cfg(unix)]
        {
            std::fs::remove_file(source.join("capture-group.json")).unwrap();
            std::fs::remove_dir(&source).unwrap();
            std::os::unix::fs::symlink(&root, &source).unwrap();
            assert!(remove_local(&root, &entry).is_err());
            assert!(path(&root, g.id).exists());
        }
    }
    #[test]
    fn spool_owner_index_recovers_children_and_rejects_conflicts() {
        let g = failed();
        let id = Uuid::new_v4();
        let note =
            serde_json::json!({"session_id":id,"package":g.package,"relation":{"parent_id":g.id}});
        let wire = format!(
            "{id} {}",
            STANDARD.encode(serde_json::to_vec(&note).unwrap())
        );
        assert_eq!(read_spool_owners(&wire, &g).unwrap().get(&id), Some(&g.id));
        let bad = serde_json::json!({"session_id":id,"package":"different.app","relation":{"parent_id":g.id}});
        assert!(read_spool_owners(
            &format!(
                "{id} {}",
                STANDARD.encode(serde_json::to_vec(&bad).unwrap())
            ),
            &g
        )
        .is_err());
    }

    /// Explicit opt-in: creates only UUID-isolated fixture data on the connected
    /// phone, exercises production queue + physical delete, preserves a neighbor.
    #[tokio::test]
    #[ignore]
    async fn connected_delete_fixture() {
        assert_eq!(
            std::env::var("ME_DELETE_FIXTURE").as_deref(),
            Ok("35251JEGR12568")
        );
        crate::advanced::initialize_host_environment(None).unwrap();
        let t = Temp::new();
        let mut g = failed();
        g.serial = "35251JEGR12568".into();
        let neighbor = Uuid::new_v4();
        let session = *g.session_ids().iter().next().unwrap();
        let orphan = Uuid::new_v4();
        let base = device_base(&g).unwrap();
        let parent = format!("{base}/captures/{}", g.id);
        let sibling = format!("{base}/captures/{neighbor}");
        let mut script=format!("mkdir -p {parent}/child/dump {sibling}\nprintf fixture > {parent}/child/dump/data.bin\nprintf keep > {sibling}/keep\n");
        for id in [session, orphan] {
            let note = serde_json::json!({"session_id":id,"package":g.package,"relation":{"parent_id":g.id}});
            script.push_str(&format!("mkdir -p {base}/spool/{id}\nprintf %s {} > {base}/spool/{id}/capture-relation.json\nprintf fixture > {base}/spool/{id}/batch.bin\n",crate::shell_quote(&note.to_string())));
        }
        shell(&g.serial, &script).await.unwrap();
        save(&t.0, &g).unwrap();
        let now = std::time::Instant::now();
        let entry = enqueue(&t.0, g.id, vec![]).unwrap();
        let queue_ms = now.elapsed().as_millis();
        assert!(queue_ms < 1000);
        assert!(
            sweep(&t.0, g.id).await.unwrap(),
            "{:?}",
            trash::read_entry(&t.0, g.id).unwrap().deletion
        );
        shell(&g.serial,&format!("[ ! -e {parent} ]\n[ ! -e {base}/spool/{session} ]\n[ ! -e {base}/spool/{orphan} ]\n[ -f {sibling}/keep ]\nrm -rf -- {sibling}\n")).await.unwrap();
        let done = trash::read_entry(&t.0, g.id).unwrap();
        assert!(done.retained_session_ids.contains(&orphan));
        assert!(sweep(&t.0, g.id).await.unwrap());
        println!(
            "queue_ms={queue_ms} physical_total_ms={} parent={} deletion={:?}",
            now.elapsed().as_millis(),
            entry.group.id,
            done.deletion
        );
    }
}
