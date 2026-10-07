//! Recoverable, local-only removal. Never delete a device spool or evidence root.
use super::*;
use std::fs::OpenOptions;

const TRASH_SCHEMA: &str = "mobilee.capture-group-trash/v1";

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TrashEntry {
    pub schema: String,
    pub group: Group,
    pub trashed_unix_ms: u64,
    pub managed: bool,
    #[serde(default = "default_trashed")]
    pub trashed: bool,
    #[serde(default)]
    pub retained_session_ids: Vec<Uuid>,
    pub imported_roots: Vec<String>,
}

fn default_trashed() -> bool {
    true
}

fn trash_path(root: &Path, id: Uuid) -> PathBuf {
    root.join("trash").join(format!("{id}.json"))
}

pub(super) fn read_entry(root: &Path, id: Uuid) -> Result<TrashEntry, String> {
    let entry: TrashEntry =
        serde_json::from_str(&read_bounded_text(&trash_path(root, id), 2 * 1024 * 1024)?)
            .map_err(|e| e.to_string())?;
    entry.group.validate()?;
    if entry.schema != TRASH_SCHEMA
        || entry.group.id != id
        || entry.imported_roots.len() > 128
        || entry.retained_session_ids.len() > 16384
        || entry.retained_session_ids.iter().any(Uuid::is_nil)
    {
        return Err("回收站记录身份无效".into());
    }
    Ok(entry)
}

pub(super) fn managed_is_trashed(root: &Path, id: Uuid) -> Result<bool, String> {
    if !trash_path(root, id)
        .try_exists()
        .map_err(|e| e.to_string())?
    {
        return Ok(false);
    }
    let entry = read_entry(root, id)?;
    Ok(entry.managed && entry.trashed)
}

pub(super) fn ensure_not_trashed(root: &Path, id: Uuid) -> Result<(), String> {
    purge::ensure_not_purging(root, id)?;
    if managed_is_trashed(root, id)? {
        return Err("主会话已移入回收站，请先恢复；未启动采集".into());
    }
    Ok(())
}

fn ensure_inactive(group: &Group) -> Result<(), String> {
    if group.state == "running"
        || group
            .stages
            .iter()
            .any(|s| s.attempts.iter().any(|a| a.state == "running"))
    {
        return Err("主会话仍在采集，请先请求取消并等待当前阶段封存".into());
    }
    Ok(())
}

fn write_entry(root: &Path, entry: &TrashEntry) -> Result<(), String> {
    let bytes = serde_json::to_vec_pretty(entry).map_err(|e| e.to_string())?;
    if bytes.len() > 2 * 1024 * 1024 {
        return Err("回收站记录过大".into());
    }
    let directory = root.join("trash");
    // Persist new directory entries too, including first use for an imported-only
    // parent when the local capture directory has never existed.
    let mut missing = vec![];
    let mut ancestor = directory.as_path();
    while !ancestor.try_exists().map_err(|e| e.to_string())? {
        missing.push(ancestor.to_owned());
        ancestor = ancestor.parent().ok_or("回收站目录缺少父目录")?;
    }
    std::fs::create_dir_all(&directory).map_err(|e| e.to_string())?;
    for created in missing.iter().rev() {
        File::open(created.parent().ok_or("回收站目录缺少父目录")?)
            .and_then(|f| f.sync_all())
            .map_err(|e| e.to_string())?;
    }
    let temporary = directory.join(format!(".{}.tmp", Uuid::new_v4()));
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
            .map_err(|e| e.to_string())?;
        file.write_all(&bytes).map_err(|e| e.to_string())?;
        file.sync_all().map_err(|e| e.to_string())?;
        std::fs::rename(&temporary, trash_path(root, entry.group.id)).map_err(|e| e.to_string())?;
        File::open(&directory)
            .and_then(|f| f.sync_all())
            .map_err(|e| e.to_string())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(temporary);
    }
    result
}

fn trash_at(
    root: &Path,
    parent_id: Uuid,
    imported_roots: Vec<String>,
) -> Result<TrashEntry, String> {
    purge::ensure_not_purging(root, parent_id)?;
    if parent_id.is_nil() || imported_roots.len() > 128 {
        return Err("无效主会话或导入来源过多".into());
    }
    // The original manifest stays byte-for-byte available for evidence/export.
    // A tombstone only changes visibility and forbids starting new collection.
    let managed = path(root, parent_id)
        .try_exists()
        .map_err(|e| e.to_string())?;
    let mut group = if managed {
        Some(load(root, parent_id)?)
    } else {
        None
    };
    let mut sources = BTreeSet::new();
    let mut retained_sessions = group.as_ref().map(Group::session_ids).unwrap_or_default();
    for imported_root in imported_roots {
        let imported = read_import(Path::new(&imported_root))?.ok_or("导入目录缺少主会话清单")?;
        if imported.id != parent_id
            || group
                .as_ref()
                .is_some_and(|g| g.serial != imported.serial || g.package != imported.package)
        {
            return Err("导入来源不属于所选主会话".into());
        }
        retained_sessions.extend(imported.session_ids());
        if group.is_none() {
            group = Some(imported);
        }
        sources.insert(imported_root);
    }
    let group = group.ok_or("找不到所选主会话；未改动任何证据")?;
    if group.id != parent_id {
        return Err("本地主会话清单与所选身份冲突".into());
    }
    ensure_inactive(&group)?;
    let mut entry = TrashEntry {
        schema: TRASH_SCHEMA.into(),
        group,
        trashed_unix_ms: now_millis(),
        managed,
        trashed: true,
        retained_session_ids: vec![],
        imported_roots: vec![],
    };
    if trash_path(root, parent_id)
        .try_exists()
        .map_err(|e| e.to_string())?
    {
        let previous = read_entry(root, parent_id)?;
        if previous.group.serial != entry.group.serial
            || previous.group.package != entry.group.package
        {
            return Err("回收站主会话身份冲突".into());
        }
        retained_sessions.extend(previous.group.session_ids());
        retained_sessions.extend(previous.retained_session_ids);
        if previous.trashed {
            sources.extend(previous.imported_roots);
            entry.trashed_unix_ms = previous.trashed_unix_ms;
        }
        entry.managed |= previous.managed;
    }
    if sources.len() > 128 {
        return Err("回收站导入来源过多".into());
    }
    if retained_sessions.len() > 16384 {
        return Err("主会话留存的子会话归属过多".into());
    }
    entry.retained_session_ids = retained_sessions.into_iter().collect();
    entry.imported_roots = sources.into_iter().collect();
    write_entry(root, &entry)?;
    Ok(entry)
}

pub(super) fn list_at(root: &Path) -> Result<Vec<TrashEntry>, String> {
    let directory = root.join("trash");
    if !directory.try_exists().map_err(|e| e.to_string())? {
        return Ok(vec![]);
    }
    let mut entries = vec![];
    for file in std::fs::read_dir(directory).map_err(|e| e.to_string())? {
        let p = file.map_err(|e| e.to_string())?.path();
        if p.extension().and_then(|s| s.to_str()) != Some("json") {
            continue;
        }
        if let Some(id) = p
            .file_stem()
            .and_then(|s| s.to_str())
            .and_then(|s| Uuid::parse_str(s).ok())
        {
            entries.push(read_entry(root, id)?);
        }
    }
    entries.sort_by_key(|e| std::cmp::Reverse(e.trashed_unix_ms));
    Ok(entries)
}

fn restore_at(root: &Path, parent_id: Uuid) -> Result<TrashEntry, String> {
    purge::ensure_not_purging(root, parent_id)?;
    let mut entry = read_entry(root, parent_id)?;
    if entry.managed && !path(root, parent_id).is_file() {
        return Err("原主会话清单已在应用外移走，请先找回原清单；回收站记录已保留".into());
    }
    // Keep ownership refs after restore, even if an imported source is not open
    // after restart. No child may fall back to the destructive legacy path.
    entry.trashed = false;
    write_entry(root, &entry)?;
    Ok(entry)
}

#[tauri::command]
pub fn trash_kernsight_group(
    app: tauri::AppHandle,
    parent_id: Uuid,
    imported_roots: Vec<String>,
) -> Result<TrashEntry, String> {
    let _guard = IO_LOCK.lock().map_err(|e| e.to_string())?;
    trash_at(&root(&app)?, parent_id, imported_roots)
}

#[tauri::command]
pub fn list_kernsight_group_trash(app: tauri::AppHandle) -> Result<Vec<TrashEntry>, String> {
    let _guard = IO_LOCK.lock().map_err(|e| e.to_string())?;
    list_at(&root(&app)?)
}

#[tauri::command]
pub fn restore_kernsight_group(
    app: tauri::AppHandle,
    parent_id: Uuid,
) -> Result<TrashEntry, String> {
    let _guard = IO_LOCK.lock().map_err(|e| e.to_string())?;
    restore_at(&root(&app)?, parent_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fixture(PathBuf);
    impl Fixture {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!("me-group-trash-test-{}", Uuid::new_v4()));
            std::fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.0).unwrap();
        }
    }
    fn terminal(state: &str) -> Group {
        let mut g = super::super::tests::group();
        if state == "succeeded" {
            for key in ["l0", "l1", "dump", "linker"] {
                let r = g.start(key, epoch()).unwrap();
                g.finish(
                    &r,
                    (key != "dump").then(Uuid::new_v4),
                    (key == "dump").then(|| "/synthetic/retained-dump".into()),
                    None,
                )
                .unwrap();
            }
        } else if state != "planned" {
            let r = g.start("l0", epoch()).unwrap();
            g.cancel_requested = state == "cancelled";
            let error = match state {
                "partial" => "remote_collection_partial",
                "cancelled" => "parent_cancelled",
                _ => "synthetic failure",
            };
            g.finish(&r, Some(Uuid::new_v4()), None, Some(error.into()))
                .unwrap();
            if state == "interrupted" {
                g.stages[0].attempts[0].state = "interrupted".into();
                g.refresh();
            }
        }
        g
    }
    fn imported(root: &Path, group: &Group) {
        std::fs::create_dir_all(root).unwrap();
        std::fs::write(
            root.join("capture-group.json"),
            serde_json::to_vec_pretty(group).unwrap(),
        )
        .unwrap();
        std::fs::write(
            root.join("retained-evidence.bin"),
            b"synthetic immutable evidence",
        )
        .unwrap();
    }

    #[test]
    fn terminal_parents_trash_and_restore_without_changing_manifest_or_evidence() {
        for state in [
            "failed",
            "succeeded",
            "partial",
            "cancelled",
            "interrupted",
            "planned",
        ] {
            let fixture = Fixture::new();
            let g = terminal(state);
            save(&fixture.0, &g).unwrap();
            let source = fixture.0.join("fixture-import");
            imported(&source, &g);
            let manifest = std::fs::read(path(&fixture.0, g.id)).unwrap();
            let evidence = std::fs::read(source.join("retained-evidence.bin")).unwrap();
            let roots = vec![source.to_string_lossy().into_owned()];
            let entry = trash_at(&fixture.0, g.id, roots.clone()).unwrap();
            assert!(entry.managed);
            assert_eq!(entry.group.state, state);
            assert_eq!(entry.group.session_ids(), g.session_ids());
            assert_eq!(entry.group.evidence_edges(), g.evidence_edges());
            assert_eq!(entry.imported_roots, roots);
            assert!(managed_is_trashed(&fixture.0, g.id).unwrap());
            assert!(ensure_not_trashed(&fixture.0, g.id).is_err());
            assert_eq!(std::fs::read(path(&fixture.0, g.id)).unwrap(), manifest);
            assert_eq!(
                std::fs::read(source.join("retained-evidence.bin")).unwrap(),
                evidence
            );
            assert_eq!(list_at(&fixture.0).unwrap().len(), 1);
            restore_at(&fixture.0, g.id).unwrap();
            assert!(list_at(&fixture.0).unwrap().iter().all(|e| !e.trashed));
            assert!(ensure_not_trashed(&fixture.0, g.id).is_ok());
            assert_eq!(std::fs::read(path(&fixture.0, g.id)).unwrap(), manifest);
            assert_eq!(
                std::fs::read(source.join("retained-evidence.bin")).unwrap(),
                evidence
            );
        }
    }

    #[test]
    fn running_and_cancel_requested_running_parents_are_protected() {
        for cancel in [false, true] {
            let fixture = Fixture::new();
            let mut g = terminal("planned");
            g.start("l0", epoch()).unwrap();
            g.cancel_requested = cancel;
            g.refresh();
            save(&fixture.0, &g).unwrap();
            let before = std::fs::read(path(&fixture.0, g.id)).unwrap();
            assert!(trash_at(&fixture.0, g.id, vec![])
                .unwrap_err()
                .contains("仍在采集"));
            assert!(list_at(&fixture.0).unwrap().iter().all(|e| !e.trashed));
            assert_eq!(std::fs::read(path(&fixture.0, g.id)).unwrap(), before);
        }
    }

    #[test]
    fn imported_only_parent_is_root_scoped_and_does_not_become_managed() {
        let fixture = Fixture::new();
        let g = terminal("partial");
        let first = fixture.0.join("first-import");
        let second = fixture.0.join("second-import");
        imported(&first, &g);
        imported(&second, &g);
        let entry = trash_at(&fixture.0, g.id, vec![first.to_string_lossy().into_owned()]).unwrap();
        assert!(!entry.managed);
        assert_eq!(entry.imported_roots.len(), 1);
        assert!(!path(&fixture.0, g.id).exists());
        assert!(!managed_is_trashed(&fixture.0, g.id).unwrap());
        let again = trash_at(
            &fixture.0,
            g.id,
            vec![second.to_string_lossy().into_owned()],
        )
        .unwrap();
        assert_eq!(again.trashed_unix_ms, entry.trashed_unix_ms);
        assert_eq!(again.imported_roots.len(), 2);
        restore_at(&fixture.0, g.id).unwrap();
        assert!(first.join("capture-group.json").is_file());
        assert!(second.join("capture-group.json").is_file());
        assert!(!path(&fixture.0, g.id).exists());
    }

    #[test]
    fn exact_parent_identity_keeps_same_package_neighbor_and_rejects_foreign_imports() {
        let fixture = Fixture::new();
        let a = terminal("failed");
        let b = terminal("succeeded");
        save(&fixture.0, &a).unwrap();
        save(&fixture.0, &b).unwrap();
        let foreign = fixture.0.join("foreign");
        imported(&foreign, &b);
        assert!(trash_at(
            &fixture.0,
            a.id,
            vec![foreign.to_string_lossy().into_owned()]
        )
        .is_err());
        assert!(list_at(&fixture.0).unwrap().iter().all(|e| !e.trashed));
        trash_at(&fixture.0, a.id, vec![]).unwrap();
        assert!(!managed_is_trashed(&fixture.0, b.id).unwrap());
        assert!(ensure_not_trashed(&fixture.0, b.id).is_ok());
        assert_eq!(
            load(&fixture.0, b.id).unwrap().session_ids(),
            b.session_ids()
        );
    }

    #[test]
    fn repeat_trash_is_idempotent_and_persists_across_reload_without_a_device() {
        let fixture = Fixture::new();
        let g = terminal("failed");
        save(&fixture.0, &g).unwrap();
        let first = trash_at(&fixture.0, g.id, vec![]).unwrap();
        let second = trash_at(&fixture.0, g.id, vec![]).unwrap();
        assert_eq!(first.trashed_unix_ms, second.trashed_unix_ms);
        assert_eq!(list_at(&fixture.0).unwrap().len(), 1);
        assert_eq!(read_entry(&fixture.0, g.id).unwrap().group.id, g.id);
    }

    #[test]
    fn missing_mismatched_and_corrupt_manifests_fail_closed() {
        let fixture = Fixture::new();
        assert!(trash_at(&fixture.0, Uuid::new_v4(), vec![]).is_err());
        let g = terminal("failed");
        let wrong = Uuid::new_v4();
        std::fs::write(path(&fixture.0, wrong), serde_json::to_vec(&g).unwrap()).unwrap();
        assert!(trash_at(&fixture.0, wrong, vec![]).is_err());
        assert!(list_at(&fixture.0).unwrap().iter().all(|e| !e.trashed));
        save(&fixture.0, &g).unwrap();
        trash_at(&fixture.0, g.id, vec![]).unwrap();
        std::fs::write(trash_path(&fixture.0, g.id), b"corrupt fixture").unwrap();
        assert!(managed_is_trashed(&fixture.0, g.id).is_err());
        assert!(restore_at(&fixture.0, g.id).is_err());
    }

    #[test]
    fn imported_first_use_creates_only_local_markers_and_rejects_running_snapshot() {
        let fixture = Fixture::new();
        let root = fixture.0.join("new-app-data").join("captures");
        let source = fixture.0.join("imported-source");
        let mut group = terminal("planned");
        group.start("l0", epoch()).unwrap();
        imported(&source, &group);
        let roots = vec![source.to_string_lossy().into_owned()];
        assert!(trash_at(&root, group.id, roots.clone()).is_err());
        assert!(!root.exists());
        let relation = group.stages[0].attempts[0].relation.clone();
        group
            .finish(&relation, None, None, Some("synthetic failure".into()))
            .unwrap();
        imported(&source, &group);
        trash_at(&root, group.id, roots).unwrap();
        assert!(source.join("retained-evidence.bin").is_file());
        assert!(!path(&root, group.id).exists());
        assert_eq!(list_at(&root).unwrap().len(), 1);
        restore_at(&root, group.id).unwrap();
        assert!(list_at(&root).unwrap().iter().all(|e| !e.trashed));
    }

    #[test]
    fn imported_extra_child_ownership_survives_trash_restore_and_restart() {
        let fixture = Fixture::new();
        let group = terminal("failed");
        save(&fixture.0, &group).unwrap();
        let before = std::fs::read(path(&fixture.0, group.id)).unwrap();
        let mut copy = group.clone();
        let relation = copy.start("l0", epoch()).unwrap();
        let extra = Uuid::new_v4();
        copy.finish(
            &relation,
            Some(extra),
            None,
            Some("synthetic retry failed".into()),
        )
        .unwrap();
        let source = fixture.0.join("later-import");
        imported(&source, &copy);
        trash_at(
            &fixture.0,
            group.id,
            vec![source.to_string_lossy().into_owned()],
        )
        .unwrap();
        assert!(read_entry(&fixture.0, group.id)
            .unwrap()
            .retained_session_ids
            .contains(&extra));
        restore_at(&fixture.0, group.id).unwrap();
        let restored = read_entry(&fixture.0, group.id).unwrap();
        assert!(!restored.trashed);
        assert!(restored.retained_session_ids.contains(&extra));
        assert!(!managed_is_trashed(&fixture.0, group.id).unwrap());
        assert_eq!(std::fs::read(path(&fixture.0, group.id)).unwrap(), before);
        let retrash = trash_at(&fixture.0, group.id, vec![]).unwrap();
        assert!(retrash.trashed);
        assert!(retrash.retained_session_ids.contains(&extra));
        assert!(retrash.imported_roots.is_empty());
    }

    #[test]
    fn restore_preserves_tombstone_when_original_manifest_was_moved_externally() {
        let fixture = Fixture::new();
        let group = terminal("failed");
        save(&fixture.0, &group).unwrap();
        trash_at(&fixture.0, group.id, vec![]).unwrap();
        let moved = fixture.0.join("moved-manifest.json");
        std::fs::rename(path(&fixture.0, group.id), &moved).unwrap();
        assert!(restore_at(&fixture.0, group.id).is_err());
        assert_eq!(list_at(&fixture.0).unwrap().len(), 1);
        std::fs::rename(moved, path(&fixture.0, group.id)).unwrap();
        restore_at(&fixture.0, group.id).unwrap();
        assert!(list_at(&fixture.0).unwrap().iter().all(|e| !e.trashed));
    }

    #[tokio::test]
    async fn trashed_parent_cannot_start_a_new_stage_or_touch_a_device() {
        let fixture = Fixture::new();
        let g = terminal("planned");
        save(&fixture.0, &g).unwrap();
        trash_at(&fixture.0, g.id, vec![]).unwrap();
        let error = run_group_stage_at(fixture.0.clone(), g.id, "l0".into())
            .await
            .err()
            .unwrap();
        assert!(error.contains("回收站"));
        assert!(load(&fixture.0, g.id)
            .unwrap()
            .stages
            .iter()
            .all(|s| s.attempts.is_empty()));
    }
}
