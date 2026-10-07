//! Two-phase irreversible cleanup. Preview data is server-side, one-parent scoped,
//! durable across partial failures, and never treated as authorization by itself.
use super::purge_local::{self as local, Entry};
use super::*;
use std::fs::{self, OpenOptions};

const SCHEMA: &str = "mobilee.capture-group-purge/v1";
const TTL_MS: u64 = 5 * 60 * 1000;
const JOURNAL_LIMIT: u64 = 64 * 1024 * 1024;
static ACTIVE_PLAN: Mutex<Option<Uuid>> = Mutex::new(None);
struct ActivePlan;
impl Drop for ActivePlan {
    fn drop(&mut self) {
        if let Ok(mut active) = ACTIVE_PLAN.lock() {
            *active = None;
        }
    }
}
static EXECUTION_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DevicePreview {
    pub status: String,
    pub entries: Vec<Entry>,
    pub warnings: Vec<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Plan {
    pub schema: String,
    pub id: Uuid,
    pub parent_id: Uuid,
    pub serial: String,
    pub package: String,
    pub created_unix_ms: u64,
    pub expires_unix_ms: u64,
    pub confirmation_token: String,
    pub confirmation_text: String,
    pub local_entries: Vec<Entry>,
    pub device: DevicePreview,
    pub warnings: Vec<String>,
    pub local_only: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Report {
    pub id: Uuid,
    pub parent_id: Uuid,
    pub serial: String,
    pub package: String,
    pub imported_roots: Vec<String>,
    pub retained_session_ids: Vec<Uuid>,
    pub updated_unix_ms: u64,
    pub state: String,
    pub local_state: String,
    pub device_state: String,
    pub removed_local_files: u64,
    /// Sum of allocation on verified unlinked non-shared files; not a claim about
    /// filesystem free space (APFS snapshots/clones and caches may retain blocks).
    pub removed_local_allocated_bytes: Option<u64>,
    pub warnings: Vec<String>,
    pub error: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
struct Journal {
    plan: Plan,
    report: Report,
    group: Group,
    local: local::Snapshot,
    device: Option<purge_device::DeviceSnapshot>,
    started: bool,
    // A failed/disconnected command may have deleted a prefix. Retain the exact
    // previous device snapshot and never rediscover a broader deletion scope.
    device_attempted: bool,
}
fn journal_path(root: &Path, id: Uuid) -> PathBuf {
    root.join("purges").join(format!("{id}.json"))
}
fn create_durable_directory(directory: &Path) -> Result<(), String> {
    let mut missing = Vec::new();
    let mut ancestor = directory;
    while !ancestor.try_exists().map_err(|e| e.to_string())? {
        missing.push(ancestor.to_owned());
        ancestor = ancestor.parent().ok_or("清理目录缺少父路径")?;
    }
    fs::create_dir_all(directory).map_err(|e| e.to_string())?;
    for created in missing.iter().rev() {
        File::open(created.parent().ok_or("清理目录缺少父路径")?)
            .and_then(|f| f.sync_all())
            .map_err(|e| e.to_string())?;
    }
    Ok(())
}
fn write_journal(root: &Path, j: &Journal) -> Result<(), String> {
    let directory = root.join("purges");
    create_durable_directory(&directory)?;
    local::safe_path(&directory)?;
    if directory
        .canonicalize()
        .map_err(|e| e.to_string())?
        .parent()
        != Some(local::safe_path(root)?.as_path())
    {
        return Err("清理日志目录越出应用范围".into());
    }
    let bytes = serde_json::to_vec(j).map_err(|e| e.to_string())?;
    if bytes.len() as u64 > JOURNAL_LIMIT {
        return Err("清理日志超出安全上限；未执行".into());
    }
    let temporary = directory.join(format!(".{}.tmp", Uuid::new_v4()));
    let result = (|| {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&temporary).map_err(|e| e.to_string())?;
        file.write_all(&bytes).map_err(|e| e.to_string())?;
        file.sync_all().map_err(|e| e.to_string())?;
        fs::rename(&temporary, journal_path(root, j.plan.id)).map_err(|e| e.to_string())?;
        File::open(&directory)
            .and_then(|f| f.sync_all())
            .map_err(|e| e.to_string())?;
        File::open(root)
            .and_then(|f| f.sync_all())
            .map_err(|e| e.to_string())
    })();
    if result.is_err() {
        let _ = fs::remove_file(temporary);
    }
    result
}
fn read_journal(root: &Path, id: Uuid) -> Result<Journal, String> {
    let p = journal_path(root, id);
    local::safe_path(&p)?;
    let j: Journal =
        serde_json::from_str(&read_bounded_text(&p, JOURNAL_LIMIT)?).map_err(|e| e.to_string())?;
    if j.plan.schema != SCHEMA
        || j.plan.id != id
        || j.report.id != id
        || j.group.id != j.plan.parent_id
        || j.group.id != j.report.parent_id
        || j.group.serial != j.plan.serial
        || j.group.serial != j.report.serial
        || j.group.package != j.plan.package
        || j.group.package != j.report.package
    {
        return Err("清理日志身份冲突；保留并停止".into());
    }
    j.group.validate()?;
    local::validate_snapshot(root, &j.group, &j.local)?;
    if j.device
        .as_ref()
        .is_some_and(|device| !purge_device::matches_group(device, &j.group))
    {
        return Err("清理日志手机快照与父会话身份冲突".into());
    }
    if j.plan.device.status == "ready"
        && j.device
            .as_ref()
            .is_none_or(|device| j.plan.device != device_preview(device))
    {
        return Err("清理日志手机显示范围与快照不符".into());
    }
    if !j.plan.confirmation_token.is_empty()
        && j.plan.local_entries != remaining_local_entries(&j.local)
    {
        return Err("清理日志显示路径与实际剩余范围不符".into());
    }
    if j.report.imported_roots != local::selected_roots(&j.local)
        || j.report
            .retained_session_ids
            .iter()
            .copied()
            .collect::<BTreeSet<_>>()
            != j.group.session_ids()
        || j.plan
            .expires_unix_ms
            .saturating_sub(j.plan.created_unix_ms)
            > TTL_MS
        || (!j.plan.confirmation_token.is_empty()
            && Uuid::parse_str(&j.plan.confirmation_token).is_err())
        || j.plan.confirmation_text != token(j.group.id)
    {
        return Err("清理日志确认范围/归属冲突".into());
    }
    Ok(j)
}
fn list_journals(root: &Path) -> Result<Vec<Journal>, String> {
    let dir = root.join("purges");
    if !dir.try_exists().map_err(|e| e.to_string())? {
        return Ok(vec![]);
    }
    local::safe_path(&dir)?;
    let mut out = vec![];
    for entry in fs::read_dir(dir).map_err(|e| e.to_string())? {
        let p = entry.map_err(|e| e.to_string())?.path();
        if p.extension().and_then(|s| s.to_str()) != Some("json") {
            continue;
        }
        let id = p
            .file_stem()
            .and_then(|s| s.to_str())
            .and_then(|s| Uuid::parse_str(s).ok())
            .ok_or("未知清理日志名")?;
        out.push(read_journal(root, id)?);
        if out.len() > 4096 {
            return Err("清理日志超过安全读取上限".into());
        }
    }
    Ok(out)
}
pub(super) fn is_started(root: &Path, id: Uuid) -> Result<bool, String> {
    Ok(list_journals(root)?
        .iter()
        .any(|j| j.group.id == id && j.started))
}
pub(super) fn ensure_not_purging(root: &Path, id: Uuid) -> Result<(), String> {
    if is_started(root, id)? {
        return Err("该父会话已进入永久清理，不能恢复或重启采集".into());
    }
    Ok(())
}
fn ensure_no_other_started(root: &Path, id: Uuid, allowed: Option<Uuid>) -> Result<(), String> {
    if list_journals(root)?.iter().any(|j| {
        j.group.id == id && j.started && j.report.state != "completed" && Some(j.plan.id) != allowed
    }) {
        return Err("该父会话已进入永久清理流程；不能恢复/重启采集，请查看清理记录".into());
    }
    Ok(())
}
fn raw_group(p: &Path) -> Result<Group, String> {
    local::safe_path(p)?;
    let g: Group =
        serde_json::from_str(&read_bounded_text(p, 1024 * 1024)?).map_err(|e| e.to_string())?;
    g.validate()?;
    Ok(g)
}
fn chosen_group(root: &Path, id: Uuid, sources: &[String]) -> Result<Group, String> {
    if id.is_nil() {
        return Err("父会话身份无效".into());
    }
    let p = path(root, id);
    let g = if p.try_exists().map_err(|e| e.to_string())? {
        raw_group(&p)?
    } else if let Some(source) = sources.first() {
        local::read_group(&Path::new(source).join("capture-group.json"))?
    } else {
        return Err("找不到原父会话清单；已有清理请从清理记录重新预览".into());
    };
    if g.id != id {
        return Err("父会话文件与所选身份冲突".into());
    }
    local::ensure_inactive(&g)?;
    Ok(g)
}
fn check_shared_ownership(root: &Path, g: &Group, sources: &[String]) -> Result<(), String> {
    let ids = g.session_ids();
    let selected_sources = sources.iter().map(PathBuf::from).collect::<Vec<_>>();
    for entry in fs::read_dir(root).map_err(|e| e.to_string())? {
        let p = entry.map_err(|e| e.to_string())?.path();
        if p.extension().and_then(|s| s.to_str()) != Some("json") {
            continue;
        }
        let other = raw_group(&p)?;
        if other.id != g.id && !ids.is_disjoint(&other.session_ids()) {
            return Err("子 session 被另一个父会话引用；不能永久清理".into());
        }
    }
    for entry in trash::list_at(root)? {
        if entry.group.id == g.id {
            continue;
        }
        let retained = entry
            .retained_session_ids
            .iter()
            .copied()
            .collect::<BTreeSet<_>>();
        if !ids.is_disjoint(&entry.group.session_ids()) || !ids.is_disjoint(&retained) {
            return Err("子 session 仍被其他回收站父会话引用".into());
        }
        for foreign in entry.imported_roots {
            let foreign = local::safe_path(Path::new(&foreign))?;
            let foreign = foreign.as_path();
            if selected_sources
                .iter()
                .any(|s| s.starts_with(foreign) || foreign.starts_with(s))
            {
                return Err("导入来源仍被另一个父会话引用".into());
            }
        }
    }
    for j in list_journals(root)? {
        if j.group.id != g.id
            && j.local.imported_roots.iter().any(|foreign| {
                selected_sources
                    .iter()
                    .any(|s| s.starts_with(foreign) || Path::new(foreign).starts_with(s))
            })
        {
            return Err("导入来源被另一个清理日志引用".into());
        }
        if j.group.id != g.id && !ids.is_disjoint(&j.group.session_ids()) {
            return Err("子 session 被其他清理日志引用；请先检查归属".into());
        }
    }
    Ok(())
}
fn needs_device(g: &Group) -> bool {
    !g.session_ids().is_empty()
        || g.stages
            .iter()
            .flat_map(|s| &s.attempts)
            .any(|a| a.remote_artifact_root.is_some())
}
fn device_preview(snapshot: &purge_device::DeviceSnapshot) -> DevicePreview {
    DevicePreview {
        status: "ready".into(),
        entries: purge_device::preview_entries(snapshot),
        warnings: snapshot.preserved.clone(),
    }
}
fn unavailable_device(error: String) -> DevicePreview {
    DevicePreview {
        status: if error.starts_with("device_offline:") {
            "offline"
        } else {
            "blocked"
        }
        .into(),
        entries: vec![],
        warnings: vec![error],
    }
}
fn token(parent: Uuid) -> String {
    format!("永久清理 {parent}")
}
fn remaining_local_entries(snapshot: &local::Snapshot) -> Vec<Entry> {
    let paths = snapshot
        .items
        .iter()
        .filter(|i| !i.removed)
        .map(|i| {
            Path::new(&i.root)
                .join(&i.relative)
                .to_string_lossy()
                .into_owned()
        })
        .collect::<BTreeSet<_>>();
    snapshot
        .entries
        .iter()
        .filter(|e| paths.contains(&e.path))
        .cloned()
        .collect()
}
fn plan_from(j: &mut Journal) {
    let now = now_millis();
    j.plan.created_unix_ms = now;
    j.plan.expires_unix_ms = now.saturating_add(TTL_MS);
    j.plan.confirmation_token = Uuid::new_v4().to_string();
    // Re-preview only existing approved remaining paths; never discovers a new root.
    j.plan.local_entries = remaining_local_entries(&j.local);
    j.report.updated_unix_ms = now;
}

#[tauri::command]
pub async fn prepare_kernsight_group_purge(
    app: tauri::AppHandle,
    parent_id: Uuid,
    imported_roots: Vec<String>,
    local_only: bool,
) -> Result<Plan, String> {
    prepare_at(root(&app)?, parent_id, imported_roots, local_only).await
}
async fn prepare_at(
    root: PathBuf,
    parent_id: Uuid,
    imported_roots: Vec<String>,
    local_only: bool,
) -> Result<Plan, String> {
    let (group, local) = {
        let _guard = IO_LOCK.lock().map_err(|e| e.to_string())?;
        create_durable_directory(&root)?;
        local::safe_path(&root)?;
        ensure_no_other_started(&root, parent_id, None)?;
        let g = chosen_group(&root, parent_id, &imported_roots)?;
        let local = local::inspect(&root, &g, &imported_roots)?;
        check_shared_ownership(&root, &g, &local.imported_roots)?;
        (g, local)
    };
    let prior_device_done = {
        let _guard = IO_LOCK.lock().map_err(|e| e.to_string())?;
        let encoded = serde_json::to_value(&group).map_err(|e| e.to_string())?;
        list_journals(&root)?.iter().any(|j| {
            j.group.id == group.id
                && j.report.state == "completed"
                && ["completed", "not_required"].contains(&j.report.device_state.as_str())
                && serde_json::to_value(&j.group).ok().as_ref() == Some(&encoded)
        })
    };
    let needed = needs_device(&group) && !prior_device_done;
    let (device, preview) = if !needed {
        (
            None,
            DevicePreview {
                status: "not_required".into(),
                entries: vec![],
                warnings: vec![],
            },
        )
    } else if local_only {
        (
            None,
            DevicePreview {
                status: "offline".into(),
                entries: vec![],
                warnings: vec!["本次明确仅清理本地；手机未检查、未清理，待单独预览确认".into()],
            },
        )
    } else {
        match purge_device::inspect(&group).await {
            Ok(s) => {
                let p = device_preview(&s);
                (Some(s), p)
            }
            Err(e) => (None, unavailable_device(e)),
        }
    };
    let id = Uuid::new_v4();
    let now = now_millis();
    let j = Journal {
        plan: Plan {
            schema: SCHEMA.into(),
            id,
            parent_id,
            serial: group.serial.clone(),
            package: group.package.clone(),
            created_unix_ms: now,
            expires_unix_ms: now.saturating_add(TTL_MS),
            confirmation_token: Uuid::new_v4().to_string(),
            confirmation_text: token(parent_id),
            local_entries: local.entries.clone(),
            device: preview,
            warnings: local.warnings.clone(),
            local_only,
        },
        report: Report {
            id,
            parent_id,
            serial: group.serial.clone(),
            package: group.package.clone(),
            imported_roots: local::selected_roots(&local),
            retained_session_ids: group.session_ids().into_iter().collect(),
            updated_unix_ms: now,
            state: "prepared".into(),
            local_state: "pending".into(),
            device_state: if needed { "pending" } else { "not_required" }.into(),
            removed_local_files: 0,
            removed_local_allocated_bytes: if cfg!(unix) { Some(0) } else { None },
            warnings: local.warnings.clone(),
            error: None,
        },
        group,
        local,
        device,
        started: false,
        device_attempted: false,
    };
    let _guard = IO_LOCK.lock().map_err(|e| e.to_string())?;
    // Device lookup can take time; re-check all local files before publishing the preview.
    local::verify(&j.local)?;
    ensure_no_other_started(&root, parent_id, None)?;
    write_journal(&root, &j)?;
    Ok(j.plan)
}

#[tauri::command]
pub fn list_kernsight_group_purges(app: tauri::AppHandle) -> Result<Vec<Report>, String> {
    let _guard = IO_LOCK.lock().map_err(|e| e.to_string())?;
    let root = root(&app)?;
    let active = *ACTIVE_PLAN.lock().map_err(|e| e.to_string())?;
    reports_at(&root, active)
}
fn reports_at(root: &Path, active: Option<Uuid>) -> Result<Vec<Report>, String> {
    let mut reports = Vec::new();
    for mut j in list_journals(&root)? {
        if j.report.state == "running" && active != Some(j.plan.id) {
            j.report.state = "partial".into();
            j.report.error =
                Some("上次清理执行中断，已保存的精确清单仍保留；请重新预览剩余范围并确认".into());
            j.report.updated_unix_ms = now_millis();
            write_journal(&root, &j)?;
        }
        reports.push(j.report);
    }
    reports.sort_by_key(|r| std::cmp::Reverse(r.updated_unix_ms));
    Ok(reports)
}
#[tauri::command]
pub async fn prepare_kernsight_group_purge_retry(
    app: tauri::AppHandle,
    plan_id: Uuid,
    local_only: Option<bool>,
) -> Result<Plan, String> {
    let local_only = local_only.unwrap_or(false);
    let _execution = EXECUTION_LOCK.lock().await;
    let root = root(&app)?;
    let mut j = {
        let _guard = IO_LOCK.lock().map_err(|e| e.to_string())?;
        read_journal(&root, plan_id)?
    };
    if !j.started || j.report.state == "completed" {
        return Err("此清理记录无需重试".into());
    }
    local::ensure_inactive(&j.group)?;
    local::verify(&j.local)?;
    if local_only && j.report.device_state != "completed" && j.report.device_state != "not_required"
    {
        j.plan.device = DevicePreview {
            status: "offline".into(),
            entries: vec![],
            warnings: vec!["本次明确只重试本地剩余范围；手机仍待清理，需之后单独预览确认".into()],
        };
    } else if j.report.device_state != "completed" && j.report.device_state != "not_required" {
        let result = if let Some(old) = j.device.as_ref() {
            purge_device::inspect_remaining(old).await
        } else {
            purge_device::inspect(&j.group).await
        };
        match result {
            Ok(s) => {
                j.plan.device = device_preview(&s);
                j.device = Some(s);
            }
            Err(e) => {
                j.plan.device = unavailable_device(e);
            }
        }
    } else {
        j.plan.device = DevicePreview {
            status: "not_required".into(),
            entries: vec![],
            warnings: vec!["该记录的手机清理已经确认，无需重复".into()],
        };
    }
    j.plan.local_only = local_only;
    plan_from(&mut j);
    let _guard = IO_LOCK.lock().map_err(|e| e.to_string())?;
    ensure_no_other_started(&root, j.group.id, Some(j.plan.id))?;
    check_shared_ownership(&root, &j.group, &j.local.imported_roots)?;
    write_journal(&root, &j)?;
    Ok(j.plan)
}

#[tauri::command]
pub async fn execute_kernsight_group_purge(
    app: tauri::AppHandle,
    plan_id: Uuid,
    confirmation_token: String,
) -> Result<Report, String> {
    let _execution = EXECUTION_LOCK.lock().await;
    execute_at(root(&app)?, plan_id, &confirmation_token).await
}
async fn execute_at(root: PathBuf, id: Uuid, confirmation: &str) -> Result<Report, String> {
    *ACTIVE_PLAN.lock().map_err(|e| e.to_string())? = Some(id);
    let _active_guard = ActivePlan;
    let mut j = {
        let _guard = IO_LOCK.lock().map_err(|e| e.to_string())?;
        let mut j = read_journal(&root, id)?;
        if j.report.state == "completed" {
            return Ok(j.report);
        }
        if confirmation != j.plan.confirmation_token || j.plan.confirmation_token.is_empty() {
            return Err("永久清理确认文本不匹配；未执行".into());
        }
        if now_millis() > j.plan.expires_unix_ms || now_millis() < j.plan.created_unix_ms {
            return Err("清理预览已过期；请重新预览并确认".into());
        }
        if !j.plan.local_only && !["ready", "not_required"].contains(&j.plan.device.status.as_str())
        {
            return Err("手机未连接或归属/终态未确认；未执行配对清理".into());
        }
        ensure_no_other_started(&root, j.group.id, Some(id))?;
        local::ensure_inactive(&j.group)?;
        local::verify(&j.local)?;
        check_shared_ownership(&root, &j.group, &j.local.imported_roots)?;
        j.started = true;
        j.plan.confirmation_token.clear();
        j.report.state = "running".into();
        j.report.error = None;
        j.report.updated_unix_ms = now_millis();
        write_journal(&root, &j)?;
        j
    };
    if !j.plan.local_only
        && j.report.device_state != "completed"
        && j.report.device_state != "not_required"
    {
        j.device_attempted = true;
        {
            let _guard = IO_LOCK.lock().map_err(|e| e.to_string())?;
            write_journal(&root, &j)?;
        }
        let result = purge_device::execute(j.device.as_ref().ok_or("缺手机预览快照")?).await;
        match result {
            Ok(outcome) if outcome.errors.is_empty() && outcome.status == "completed" => {
                j.report.device_state = "completed".into();
                j.report.warnings.push(format!("手机确认移除 {} 个文件路径；保留归属/生命周期控制记录及共享内容，不把逻辑字节声称为释放空间",outcome.removed_files));
            }
            Ok(outcome) => {
                j.report.device_state = "failed".into();
                j.report.error = Some(outcome.errors.join("；"));
            }
            Err(e) => {
                j.report.device_state = "failed".into();
                j.report.error = Some(e);
            }
        }
        let _guard = IO_LOCK.lock().map_err(|e| e.to_string())?;
        write_journal(&root, &j)?;
        if j.report.device_state == "failed" {
            j.report.state = "partial".into();
            j.report.updated_unix_ms = now_millis();
            write_journal(&root, &j)?;
            return Ok(j.report);
        }
    }
    // No async device work while holding IO_LOCK. The durable started marker
    // prevents new producer stages and exports while this transaction is active.
    let _guard = IO_LOCK.lock().map_err(|e| e.to_string())?;
    if let Err(e) = local::verify(&j.local) {
        j.report.local_state = "failed".into();
        j.report.error = Some(e);
    } else {
        // Persist authorization of this fixed complete local range once before
        // unlink. Checkpoint completed prefixes in bounded batches; a crash can
        // undercount physical removals, never invent them or lose the inventory.
        for item in j.local.items.iter_mut().filter(|i| !i.removed) {
            item.attempted = true;
        }
        write_journal(&root, &j)?;
        for index in 0..j.local.items.len() {
            if j.local.items[index].removed {
                continue;
            }
            match local::remove(&j.local.items[index]) {
                Ok(allocation) => {
                    j.local.items[index].removed = true;
                    if let Some(bytes) = allocation {
                        j.report.removed_local_files += 1;
                        j.report.removed_local_allocated_bytes = j
                            .report
                            .removed_local_allocated_bytes
                            .and_then(|n| n.checked_add(bytes));
                    } else {
                        j.report.warnings.push(format!(
                            "路径已不存在，未计入本次释放量：{}",
                            j.local.items[index].relative
                        ));
                    }
                    if index % 32 == 31 {
                        write_journal(&root, &j)?;
                    }
                }
                Err(e) => {
                    j.report.local_state = "failed".into();
                    j.report.error = Some(e);
                    break;
                }
            }
        }
        if j.local.items.iter().all(|i| i.removed) {
            j.report.local_state = "completed".into();
        }
    }
    j.report.updated_unix_ms = now_millis();
    j.report.state = if j.report.local_state == "completed"
        && ["completed", "not_required"].contains(&j.report.device_state.as_str())
    {
        "completed"
    } else {
        "partial"
    }
    .into();
    if j.plan.local_only && j.report.device_state == "pending" {
        j.report
            .warnings
            .push("本地选中范围已处理；手机尚未清理，需连接原设备后重新预览并明确确认".into());
    }
    write_journal(&root, &j)?;
    Ok(j.report)
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Fixture(PathBuf);
    impl Fixture {
        fn new() -> Self {
            let p = std::env::temp_dir().join(format!("me-purge-journal-test-{}", Uuid::new_v4()));
            fs::create_dir_all(&p).unwrap();
            Self(p)
        }
        fn group(&self) -> Group {
            let g = super::super::tests::group();
            save(&self.0, &g).unwrap();
            g
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    #[tokio::test]
    async fn preview_does_not_delete_and_wrong_or_expired_confirmation_cannot_execute() {
        let f = Fixture::new();
        let g = f.group();
        let plan = prepare_at(f.0.clone(), g.id, vec![], true).await.unwrap();
        assert!(path(&f.0, g.id).exists());
        assert!(!read_journal(&f.0, plan.id).unwrap().started);
        assert!(execute_at(f.0.clone(), plan.id, "wrong").await.is_err());
        let mut j = read_journal(&f.0, plan.id).unwrap();
        j.plan.expires_unix_ms = 0;
        write_journal(&f.0, &j).unwrap();
        assert!(execute_at(f.0.clone(), plan.id, &plan.confirmation_token)
            .await
            .is_err());
        assert!(path(&f.0, g.id).exists());
    }
    #[tokio::test]
    async fn permanent_local_execution_is_idempotent_and_journal_survives_manifest() {
        let f = Fixture::new();
        let g = f.group();
        let other = f.group();
        let plan = prepare_at(f.0.clone(), g.id, vec![], true).await.unwrap();
        let report = execute_at(f.0.clone(), plan.id, &plan.confirmation_token)
            .await
            .unwrap();
        assert_eq!(report.state, "completed");
        assert_eq!(report.local_state, "completed");
        assert_eq!(report.removed_local_files, 1);
        assert!(!path(&f.0, g.id).exists());
        assert!(path(&f.0, other.id).exists());
        assert!(read_journal(&f.0, plan.id).unwrap().started);
        assert!(ensure_not_purging(&f.0, g.id).is_err());
        assert_eq!(
            execute_at(f.0.clone(), plan.id, &plan.confirmation_token)
                .await
                .unwrap()
                .removed_local_files,
            1
        );
    }
    #[tokio::test]
    async fn refreshed_preview_rotates_nonce_and_old_local_only_authority_is_rejected() {
        let f = Fixture::new();
        let g = f.group();
        let old = prepare_at(f.0.clone(), g.id, vec![], true).await.unwrap();
        let mut j = read_journal(&f.0, old.id).unwrap();
        plan_from(&mut j);
        j.plan.local_only = false;
        write_journal(&f.0, &j).unwrap();
        assert_ne!(old.confirmation_token, j.plan.confirmation_token);
        assert!(execute_at(f.0.clone(), old.id, &old.confirmation_token)
            .await
            .is_err());
        assert!(path(&f.0, g.id).exists());
    }
    #[tokio::test]
    async fn changed_parent_and_shared_child_are_not_purged() {
        let f = Fixture::new();
        let g = f.group();
        let plan = prepare_at(f.0.clone(), g.id, vec![], true).await.unwrap();
        let mut changed = g.clone();
        changed.cancel_requested = true;
        save(&f.0, &changed).unwrap();
        assert!(execute_at(f.0.clone(), plan.id, &plan.confirmation_token)
            .await
            .is_err());
        assert!(path(&f.0, g.id).exists());
    }
    #[tokio::test]
    async fn unchanged_local_listing_does_not_rewrite_preview_inode() {
        let f = Fixture::new();
        let g = f.group();
        let plan = prepare_at(f.0.clone(), g.id, vec![], true).await.unwrap();
        let _ = load(&f.0, g.id).unwrap();
        let j = read_journal(&f.0, plan.id).unwrap();
        local::verify(&j.local).unwrap();
        assert_eq!(
            execute_at(f.0.clone(), plan.id, &plan.confirmation_token)
                .await
                .unwrap()
                .state,
            "completed"
        );
    }
    #[tokio::test]
    async fn interrupted_prefix_retains_plan_and_counts_only_verified_removals() {
        let f = Fixture::new();
        let g = f.group();
        let plan = prepare_at(f.0.clone(), g.id, vec![], true).await.unwrap();
        let mut j = read_journal(&f.0, plan.id).unwrap();
        j.started = true;
        j.report.state = "running".into();
        j.local.items[0].attempted = true;
        write_journal(&f.0, &j).unwrap();
        local::remove(&j.local.items[0]).unwrap();
        // Simulate a crash after unlink but before the success checkpoint.
        let mut recovered = read_journal(&f.0, plan.id).unwrap();
        local::verify(&recovered.local).unwrap();
        plan_from(&mut recovered);
        write_journal(&f.0, &recovered).unwrap();
        let result = execute_at(f.0.clone(), plan.id, &recovered.plan.confirmation_token)
            .await
            .unwrap();
        assert_eq!(result.state, "completed");
        assert_eq!(result.removed_local_files, 0);
        assert_eq!(result.removed_local_allocated_bytes, Some(0));
    }
    #[tokio::test]
    async fn legacy_direct_cleanup_never_reaches_a_device() {
        assert!(
            cleanup_kernsight_session("fixture-serial".into(), Uuid::new_v4().to_string())
                .await
                .unwrap_err()
                .contains("旧版直接删除已停用")
        );
    }
    fn terminal(f: &Fixture) -> Group {
        let mut g = f.group();
        let r = g.start("l0", epoch()).unwrap();
        g.finish(
            &r,
            Some(Uuid::new_v4()),
            None,
            Some("synthetic partial".into()),
        )
        .unwrap();
        g.stages[0].attempts[0].remote_lifecycle = Some(serde_json::json!({
            "schema":"kernsight.capture-lifecycle/v1","relation":{"parent_id":r.parent_id,"stage_id":r.stage_id,"attempt_id":r.attempt_id,"attempt":1,"stage_key":"l0"},
            "token":Uuid::new_v4(),"target_pause":"forbidden","stop_request_recorded":false,"stop_acknowledged":false,
            "collection_returned":true,"collection_status":"partial","agent_exited_confirmed":true,"cleanup":"producer_scope_returned"}));
        save(&f.0, &g).unwrap();
        g
    }
    #[tokio::test]
    async fn local_only_retains_device_work_and_child_ownership_after_manifest_is_gone() {
        let f = Fixture::new();
        let g = terminal(&f);
        let plan = prepare_at(f.0.clone(), g.id, vec![], true).await.unwrap();
        let report = execute_at(f.0.clone(), plan.id, &plan.confirmation_token)
            .await
            .unwrap();
        assert_eq!(report.state, "partial");
        assert_eq!(report.device_state, "pending");
        assert_eq!(report.local_state, "completed");
        assert_eq!(
            report.retained_session_ids,
            g.session_ids().into_iter().collect::<Vec<_>>()
        );
        let j = read_journal(&f.0, plan.id).unwrap();
        assert_eq!(j.group.id, g.id);
        assert!(j.device.is_none());
        assert!(j.plan.confirmation_token.is_empty());
        assert!(!path(&f.0, g.id).exists());
        assert!(execute_at(f.0.clone(), plan.id, &plan.confirmation_token)
            .await
            .is_err());
    }
    #[tokio::test]
    async fn orphan_running_report_is_retryable_but_live_run_stays_running() {
        let f = Fixture::new();
        let g = f.group();
        let p = prepare_at(f.0.clone(), g.id, vec![], true).await.unwrap();
        let mut j = read_journal(&f.0, p.id).unwrap();
        j.started = true;
        j.report.state = "running".into();
        write_journal(&f.0, &j).unwrap();
        assert_eq!(reports_at(&f.0, Some(p.id)).unwrap()[0].state, "running");
        assert_eq!(reports_at(&f.0, None).unwrap()[0].state, "partial");
        assert!(read_journal(&f.0, p.id)
            .unwrap()
            .report
            .error
            .unwrap()
            .contains("中断"));
    }
    #[tokio::test]
    async fn shared_session_between_distinct_parents_blocks_preview() {
        let f = Fixture::new();
        let g = terminal(&f);
        let mut other = super::super::tests::group();
        let r = other.start("l0", epoch()).unwrap();
        other
            .finish(&r, g.stages[0].attempts[0].session_id, None, None)
            .unwrap();
        save(&f.0, &other).unwrap();
        let e = prepare_at(f.0.clone(), g.id, vec![], true)
            .await
            .unwrap_err();
        assert!(e.contains("另一个父会话"));
        assert!(path(&f.0, g.id).exists());
    }
    #[tokio::test]
    async fn another_selected_copy_can_be_cleaned_after_prior_exact_scope_completed() {
        let f = Fixture::new();
        let g = f.group();
        let p = prepare_at(f.0.clone(), g.id, vec![], true).await.unwrap();
        execute_at(f.0.clone(), p.id, &p.confirmation_token)
            .await
            .unwrap();
        let copy = Fixture::new();
        fs::write(
            copy.0.join("capture-group.json"),
            serde_json::to_vec(&g).unwrap(),
        )
        .unwrap();
        fs::write(
            copy.0.join("dump-report.json"),
            serde_json::to_vec(&serde_json::json!({"package":g.package})).unwrap(),
        )
        .unwrap();
        let next = prepare_at(
            f.0.clone(),
            g.id,
            vec![copy.0.to_string_lossy().into_owned()],
            true,
        )
        .await
        .unwrap();
        assert_ne!(next.id, p.id);
        let done = execute_at(f.0.clone(), next.id, &next.confirmation_token)
            .await
            .unwrap();
        assert_eq!(done.state, "completed");
        assert!(!copy.0.join("capture-group.json").exists());
        assert!(ensure_not_purging(&f.0, g.id).is_err());
    }
    #[tokio::test]
    async fn restored_journal_cannot_redirect_an_item_outside_the_selected_roots() {
        let f = Fixture::new();
        let g = f.group();
        let p = prepare_at(f.0.clone(), g.id, vec![], true).await.unwrap();
        let mut j = read_journal(&f.0, p.id).unwrap();
        j.local.items[0].root = "/tmp".into();
        write_journal(&f.0, &j).unwrap();
        assert!(read_journal(&f.0, p.id).is_err());
        assert!(execute_at(f.0.clone(), p.id, &p.confirmation_token)
            .await
            .is_err());
        assert!(path(&f.0, g.id).exists());
    }
    #[tokio::test]
    async fn legacy_package_wide_cleanup_never_reaches_a_device() {
        assert!(cleanup_kernsight_package_dump(
            "fixture-serial".into(),
            "org.example.fixture".into()
        )
        .await
        .unwrap_err()
        .contains("批量清理已停用"));
    }
    #[tokio::test]
    async fn preview_display_cannot_omit_backend_delete_paths() {
        let f = Fixture::new();
        let g = f.group();
        let p = prepare_at(f.0.clone(), g.id, vec![], true).await.unwrap();
        let mut j = read_journal(&f.0, p.id).unwrap();
        j.plan.local_entries.clear();
        write_journal(&f.0, &j).unwrap();
        assert!(read_journal(&f.0, p.id).is_err());
        assert!(path(&f.0, g.id).exists());
    }
}
