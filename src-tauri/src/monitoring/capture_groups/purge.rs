//! Two-phase irreversible cleanup. Preview data is server-side, one-parent scoped,
//! durable across partial failures, and never treated as authorization by itself.
use super::purge_local::{self as local, Entry};
use super::*;
use std::fs::{self, OpenOptions};

const SCHEMA: &str = "mobilee.capture-group-purge/v1";
const TTL_MS: u64 = 5 * 60 * 1000;
const JOURNAL_LIMIT: u64 = 64 * 1024 * 1024;
const METADATA_TOTAL_LIMIT: u64 = 32 * 1024 * 1024;
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

const PREPARE_SECONDS: u64 = 20;
const EXECUTE_SECONDS: u64 = 30;
struct Operation {
    cancelled: tokio::sync::watch::Sender<bool>,
    deadline: std::time::Instant,
}
static CANCELLED_PREPARATIONS: Mutex<BTreeMap<Uuid, std::time::Instant>> =
    Mutex::new(BTreeMap::new());
static CANCELLED_EXECUTIONS: Mutex<BTreeMap<Uuid, std::time::Instant>> =
    Mutex::new(BTreeMap::new());
static OPERATIONS: Mutex<BTreeMap<Uuid, Operation>> = Mutex::new(BTreeMap::new());
struct OperationGuard(Uuid);
impl Drop for OperationGuard {
    fn drop(&mut self) {
        if let Ok(mut operations) = OPERATIONS.lock() {
            operations.remove(&self.0);
        }
    }
}
fn register_operation(
    id: Uuid,
    seconds: u64,
) -> Result<(OperationGuard, tokio::sync::watch::Receiver<bool>), String> {
    // Keep the tombstone lock until insertion: cancellation cannot slip between
    // the cancelled check and registration of its active receiver.
    let mut tombstones = CANCELLED_PREPARATIONS.lock().map_err(|e| e.to_string())?;
    tombstones.retain(|_, until| *until > std::time::Instant::now());
    if tombstones.contains_key(&id) {
        return Err("该预览请求已取消；拒绝迟到请求".into());
    }
    register_active_operation(id, seconds)
}
fn register_active_operation(
    id: Uuid,
    seconds: u64,
) -> Result<(OperationGuard, tokio::sync::watch::Receiver<bool>), String> {
    let mut operations = OPERATIONS.lock().map_err(|e| e.to_string())?;
    if operations.contains_key(&id) {
        return Err("该清理操作已经运行".into());
    }
    let (cancelled, receiver) = tokio::sync::watch::channel(false);
    operations.insert(
        id,
        Operation {
            cancelled,
            deadline: std::time::Instant::now() + std::time::Duration::from_secs(seconds),
        },
    );
    Ok((OperationGuard(id), receiver))
}
fn check_operation(id: Uuid) -> Result<(), String> {
    let operations = OPERATIONS.lock().map_err(|e| e.to_string())?;
    if let Some(operation) = operations.get(&id) {
        if *operation.cancelled.borrow() {
            return Err("清理已取消；保留原清单".into());
        }
        if std::time::Instant::now() >= operation.deadline {
            return Err("清理整体期限已到；保留原清单".into());
        }
    }
    Ok(())
}
async fn supervise<T>(
    id: Uuid,
    seconds: u64,
    future: impl std::future::Future<Output = Result<T, String>>,
) -> Result<T, String> {
    let (_guard, mut cancelled) = register_operation(id, seconds)?;
    tokio::select! {
        biased;
        _ = cancelled.changed() => Err("清理已取消；保留原清单".into()),
        result = tokio::time::timeout(std::time::Duration::from_secs(seconds), future) => {
            let result = result.map_err(|_| "清理整体期限已到；保留原清单".to_string())?;
            check_operation(id)?;
            result
        },
    }
}
#[tauri::command]
pub fn cancel_kernsight_group_purge_preparation(request_id: Uuid) -> Result<(), String> {
    {
        let mut cancelled = CANCELLED_PREPARATIONS.lock().map_err(|e| e.to_string())?;
        cancelled.retain(|_, until| *until > std::time::Instant::now());
        if cancelled.len() >= 4096 && !cancelled.contains_key(&request_id) {
            return Err("取消请求登记已满；未丢弃已有取消标记".into());
        }
        cancelled.insert(
            request_id,
            std::time::Instant::now() + std::time::Duration::from_secs(60),
        );
    }
    signal_cancel(request_id)
}
fn signal_cancel(request_id: Uuid) -> Result<(), String> {
    if let Some(operation) = OPERATIONS
        .lock()
        .map_err(|e| e.to_string())?
        .get(&request_id)
    {
        operation.cancelled.send_replace(true);
    }
    Ok(())
}
fn interrupted_at(root: &Path, id: Uuid, reason: String) -> Result<Report, String> {
    let _guard = IO_LOCK.lock().map_err(|e| e.to_string())?;
    let mut journal = read_journal(root, id)?;
    if journal.report.state != "completed" && journal.started {
        journal.report.state = "partial".into();
        journal.report.error = Some(reason);
        journal.report.updated_unix_ms = now_millis();
        write_journal(root, &journal)?;
    }
    Ok(journal.report)
}
fn cancel_execution(id: Uuid) -> Result<(), String> {
    // Serialize cancellation with execution registration, including the period
    // before a late IPC has registered its receiver. Keep this past preview TTL.
    let mut tombstones = CANCELLED_EXECUTIONS.lock().map_err(|e| e.to_string())?;
    tombstones.retain(|_, until| *until > std::time::Instant::now());
    if tombstones.len() >= 4096 && !tombstones.contains_key(&id) {
        return Err("执行取消登记已满；未丢弃已有标记".into());
    }
    tombstones.insert(
        id,
        std::time::Instant::now() + std::time::Duration::from_millis(TTL_MS + 60_000),
    );
    signal_cancel(id)
}
#[tauri::command]
pub fn cancel_kernsight_group_purge(
    app: tauri::AppHandle,
    plan_id: Uuid,
) -> Result<Report, String> {
    cancel_execution(plan_id)?;
    interrupted_at(
        &root(&app)?,
        plan_id,
        "清理执行已中断；未知完成前缀不计释放量，原范围可恢复".into(),
    )
}

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
    read_journal_bounded(root, id, JOURNAL_LIMIT)
}
fn read_journal_bounded(root: &Path, id: Uuid, limit: u64) -> Result<Journal, String> {
    let p = journal_path(root, id);
    local::safe_path(&p)?;
    let j: Journal = serde_json::from_str(&read_bounded_text(&p, limit.min(JOURNAL_LIMIT))?)
        .map_err(|e| e.to_string())?;
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
fn metadata_inventory(
    root: &Path,
    directories: &[&str],
    check: &dyn Fn() -> Result<(), String>,
) -> Result<BTreeMap<PathBuf, u64>, String> {
    let mut files = BTreeMap::new();
    let mut total = 0u64;
    for directory in directories {
        check()?;
        let dir = root.join(directory);
        if !dir.try_exists().map_err(|e| e.to_string())? {
            continue;
        }
        local::safe_path(&dir)?;
        for entry in fs::read_dir(&dir).map_err(|e| e.to_string())? {
            check()?;
            let p = entry.map_err(|e| e.to_string())?.path();
            if p.extension().and_then(|s| s.to_str()) != Some("json") {
                continue;
            }
            local::safe_path(&p)?;
            let metadata = fs::symlink_metadata(&p).map_err(|e| e.to_string())?;
            if !metadata.is_file() {
                return Err("归属 metadata 不是普通文件".into());
            }
            total = total
                .checked_add(metadata.len())
                .ok_or("归属 metadata 字节溢出")?;
            if total > METADATA_TOTAL_LIMIT || files.len() >= 4096 {
                return Err("归属 metadata 总量超限；未扫描证据内容".into());
            }
            files.insert(p, metadata.len());
        }
    }
    check()?;
    Ok(files)
}
fn list_journals(root: &Path) -> Result<Vec<Journal>, String> {
    list_journals_checked(root, &|| Ok(()))
}
fn list_journals_checked(
    root: &Path,
    check: &dyn Fn() -> Result<(), String>,
) -> Result<Vec<Journal>, String> {
    let files = metadata_inventory(root, &["purges"], check)?;
    let mut out = vec![];
    for (p, size) in files {
        check()?;
        let id = p
            .file_stem()
            .and_then(|s| s.to_str())
            .and_then(|s| Uuid::parse_str(s).ok())
            .ok_or("未知清理日志名")?;
        out.push(read_journal_bounded(root, id, size)?);
        check()?;
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
fn ensure_no_other_started(
    root: &Path,
    id: Uuid,
    allowed: Option<Uuid>,
    check: &dyn Fn() -> Result<(), String>,
) -> Result<(), String> {
    if list_journals_checked(root, check)?.iter().any(|j| {
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
fn chosen_group(
    root: &Path,
    id: Uuid,
    sources: &[String],
    check: &dyn Fn() -> Result<(), String>,
) -> Result<Group, String> {
    check()?;
    if id.is_nil() {
        return Err("父会话身份无效".into());
    }
    let p = path(root, id);
    let g = if p.try_exists().map_err(|e| e.to_string())? {
        raw_group(&p)?
    } else if let Some(source) = sources.first() {
        local::read_group_candidate(&Path::new(source).join("capture-group.json"))?
    } else {
        let journals = list_journals_checked(root, check)?
            .into_iter()
            .filter(|j| j.group.id == id)
            .collect::<Vec<_>>();
        let first = journals
            .first()
            .ok_or("找不到原父会话或经核验清理日志；未按目录猜测范围")?;
        let encoded = serde_json::to_value(&first.group).map_err(|e| e.to_string())?;
        if journals
            .iter()
            .any(|j| serde_json::to_value(&j.group).ok().as_ref() != Some(&encoded))
        {
            return Err("同父会话清理日志身份/配置不一致；未重建范围".into());
        }
        if journals.iter().any(|j| j.report.state != "completed") {
            return Err(
                "原父清单已移除，未完成清理必须沿原日志的剩余范围重试；不能扩大范围".into(),
            );
        }
        first.group.clone()
    };
    if g.id != id {
        return Err("父会话文件与所选身份冲突".into());
    }
    local::ensure_purge_candidate(&g)?;
    Ok(g)
}
fn check_shared_ownership(
    root: &Path,
    g: &Group,
    sources: &[String],
    check: &dyn Fn() -> Result<(), String>,
) -> Result<(), String> {
    let inventory = metadata_inventory(root, &["", "trash", "purges"], check)?;
    let ids = g.session_ids();
    let selected_sources = sources.iter().map(PathBuf::from).collect::<Vec<_>>();
    for (p, size) in inventory.iter().filter(|(p, _)| p.parent() == Some(root)) {
        check()?;
        let other: Group = serde_json::from_str(&read_bounded_text(p, (*size).min(1024 * 1024))?)
            .map_err(|e| e.to_string())?;
        other.validate()?;
        if other.id != g.id && !ids.is_disjoint(&other.session_ids()) {
            return Err("子 session 被另一个父会话引用；不能永久清理".into());
        }
    }
    for (p, size) in inventory
        .iter()
        .filter(|(p, _)| p.parent() == Some(root.join("trash").as_path()))
    {
        check()?;
        let id = p
            .file_stem()
            .and_then(|s| s.to_str())
            .and_then(|s| Uuid::parse_str(s).ok())
            .ok_or("未知回收站记录名")?;
        let entry: trash::TrashEntry =
            serde_json::from_str(&read_bounded_text(p, (*size).min(2 * 1024 * 1024))?)
                .map_err(|e| e.to_string())?;
        entry.group.validate()?;
        if entry.schema != "mobilee.capture-group-trash/v1"
            || entry.group.id != id
            || entry.imported_roots.len() > 128
            || entry.retained_session_ids.len() > 16384
            || entry.retained_session_ids.iter().any(Uuid::is_nil)
        {
            return Err("回收站归属记录无效".into());
        }
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
    for (p, size) in inventory
        .iter()
        .filter(|(p, _)| p.parent() == Some(root.join("purges").as_path()))
    {
        check()?;
        let id = p
            .file_stem()
            .and_then(|s| s.to_str())
            .and_then(|s| Uuid::parse_str(s).ok())
            .ok_or("未知清理日志名")?;
        let j = read_journal_bounded(root, id, *size)?;
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
    g.stages.iter().flat_map(|s| &s.attempts).any(|a| {
        a.session_id.is_some()
            || a.remote_artifact_root.is_some()
            || !g.budget.as_ref().is_some_and(|budget| {
                budget
                    .reservations
                    .iter()
                    .any(|r| r.id == a.relation.attempt_id.to_string() && r.status == "not_started")
            })
    })
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
    request_id: Option<Uuid>,
) -> Result<Plan, String> {
    let request_id = request_id.unwrap_or_else(Uuid::new_v4);
    supervise(
        request_id,
        PREPARE_SECONDS,
        prepare_at_checked(
            root(&app)?,
            parent_id,
            imported_roots,
            local_only,
            Some(request_id),
        ),
    )
    .await
}
#[cfg(test)]
async fn prepare_at(
    root: PathBuf,
    parent_id: Uuid,
    imported_roots: Vec<String>,
    local_only: bool,
) -> Result<Plan, String> {
    prepare_at_checked(root, parent_id, imported_roots, local_only, None).await
}
async fn prepare_at_checked(
    root: PathBuf,
    parent_id: Uuid,
    imported_roots: Vec<String>,
    local_only: bool,
    operation_id: Option<Uuid>,
) -> Result<Plan, String> {
    let check = || operation_id.map_or(Ok(()), check_operation);
    check()?;
    let (group, local) = {
        let _guard = IO_LOCK.lock().map_err(|e| e.to_string())?;
        create_durable_directory(&root)?;
        local::safe_path(&root)?;
        ensure_no_other_started(&root, parent_id, None, &check)?;
        let g = chosen_group(&root, parent_id, &imported_roots, &check)?;
        let local = local::inspect_checked(&root, &g, &imported_roots, local_only, &check)?;
        check_shared_ownership(&root, &g, &local.imported_roots, &check)?;
        (g, local)
    };
    let prior_device_done = {
        let _guard = IO_LOCK.lock().map_err(|e| e.to_string())?;
        let encoded = serde_json::to_value(&group).map_err(|e| e.to_string())?;
        list_journals_checked(&root, &check)?.iter().any(|j| {
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
    local::verify_checked(&j.local, &check)?;
    check()?;
    ensure_no_other_started(&root, parent_id, None, &check)?;
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
                Some("上次清理执行中断，已确认的精确清单仍保留；可恢复原范围，无需再次确认".into());
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
    request_id: Option<Uuid>,
) -> Result<Plan, String> {
    let request_id = request_id.unwrap_or_else(Uuid::new_v4);
    supervise(
        request_id,
        PREPARE_SECONDS,
        prepare_retry_at(root(&app)?, plan_id, local_only, request_id),
    )
    .await
}
async fn prepare_retry_at(
    root: PathBuf,
    plan_id: Uuid,
    local_only: Option<bool>,
    operation_id: Uuid,
) -> Result<Plan, String> {
    let check = || check_operation(operation_id);
    check()?;
    let local_only = local_only.unwrap_or(false);
    let _execution = EXECUTION_LOCK.lock().await;
    let mut j = {
        let _guard = IO_LOCK.lock().map_err(|e| e.to_string())?;
        read_journal(&root, plan_id)?
    };
    if !j.started || j.report.state == "completed" {
        return Err("此清理记录无需重试".into());
    }
    if local_only {
        local::ensure_inactive(&j.group)?;
    } else {
        local::ensure_purge_candidate(&j.group)?;
    }
    local::verify_checked(&j.local, &check)?;
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
    check()?;
    plan_from(&mut j);
    let _guard = IO_LOCK.lock().map_err(|e| e.to_string())?;
    ensure_no_other_started(&root, j.group.id, Some(j.plan.id), &check)?;
    check_shared_ownership(&root, &j.group, &j.local.imported_roots, &check)?;
    write_journal(&root, &j)?;
    Ok(j.plan)
}

#[tauri::command]
pub async fn execute_kernsight_group_purge(
    app: tauri::AppHandle,
    plan_id: Uuid,
    confirmation_token: String,
) -> Result<Report, String> {
    run_execution(root(&app)?, plan_id, Some(confirmation_token)).await
}
#[tauri::command]
pub fn get_kernsight_group_purge_plan(
    app: tauri::AppHandle,
    plan_id: Uuid,
) -> Result<Plan, String> {
    let _guard = IO_LOCK.lock().map_err(|e| e.to_string())?;
    Ok(read_journal(&root(&app)?, plan_id)?.plan)
}
#[tauri::command]
pub async fn resume_kernsight_group_purge(
    app: tauri::AppHandle,
    plan_id: Uuid,
) -> Result<Report, String> {
    resume_at(root(&app)?, plan_id).await
}
async fn resume_at(root: PathBuf, id: Uuid) -> Result<Report, String> {
    run_execution(root, id, None).await
}
async fn run_execution(
    root: PathBuf,
    id: Uuid,
    confirmation: Option<String>,
) -> Result<Report, String> {
    // Registration failure must not mutate another live operation's journal.
    let (_operation, mut cancelled) = {
        let mut tombstones = CANCELLED_EXECUTIONS.lock().map_err(|e| e.to_string())?;
        tombstones.retain(|_, until| *until > std::time::Instant::now());
        if confirmation.is_some() && tombstones.contains_key(&id) {
            return Err("原执行已取消；拒绝迟到的确认请求".into());
        }
        if confirmation.is_none() {
            let _guard = IO_LOCK.lock().map_err(|e| e.to_string())?;
            let journal = read_journal(&root, id)?;
            if !journal.started || !journal.plan.confirmation_token.is_empty() {
                return Err("恢复只接受已确认的原范围".into());
            }
        }
        // Register first: a duplicate resume cannot clear a live cancellation.
        let registration = register_active_operation(id, EXECUTE_SECONDS)?;
        if confirmation.is_none() {
            tombstones.remove(&id);
        }
        registration
    };
    let result = tokio::select! {
        biased;
        _ = cancelled.changed() => Err("清理已取消；保留原清单".to_string()),
        result = tokio::time::timeout(std::time::Duration::from_secs(EXECUTE_SECONDS), async {
            let _execution = EXECUTION_LOCK.lock().await;
            execute_inner(root.clone(), id, confirmation.as_deref()).await
        }) => result.unwrap_or_else(|_| Err("清理整体期限已到；保留原清单".into())),
    };
    match result {
        Ok(report) => Ok(report),
        Err(error) => {
            let report = interrupted_at(&root, id, error.clone())?;
            if report.state == "partial" {
                Ok(report)
            } else {
                Err(error)
            }
        }
    }
}
#[cfg(test)]
async fn execute_at(root: PathBuf, id: Uuid, confirmation: &str) -> Result<Report, String> {
    execute_inner(root, id, Some(confirmation)).await
}
async fn execute_inner(
    root: PathBuf,
    id: Uuid,
    confirmation: Option<&str>,
) -> Result<Report, String> {
    *ACTIVE_PLAN.lock().map_err(|e| e.to_string())? = Some(id);
    let _active_guard = ActivePlan;
    let mut j = {
        let _guard = IO_LOCK.lock().map_err(|e| e.to_string())?;
        let mut j = read_journal(&root, id)?;
        if j.report.state == "completed" {
            return Ok(j.report);
        }
        if let Some(confirmation) = confirmation {
            if confirmation != j.plan.confirmation_token || j.plan.confirmation_token.is_empty() {
                return Err("永久清理确认文本不匹配；未执行".into());
            }
            if now_millis() > j.plan.expires_unix_ms || now_millis() < j.plan.created_unix_ms {
                return Err("清理预览已过期；请重新预览并确认".into());
            }
        } else if !j.started || !j.plan.confirmation_token.is_empty() {
            return Err("恢复只接受已经确认并消耗 nonce 的原清理日志".into());
        }
        check_operation(id)?;
        if !j.plan.local_only && !["ready", "not_required"].contains(&j.plan.device.status.as_str())
        {
            return Err("手机未连接或归属/终态未确认；未执行配对清理".into());
        }
        ensure_no_other_started(&root, j.group.id, Some(id), &|| check_operation(id))?;
        if j.plan.local_only {
            local::ensure_inactive(&j.group)?;
        } else {
            local::ensure_purge_candidate(&j.group)?;
            if needs_device(&j.group)
                && j.report.device_state != "completed"
                && j.report.device_state != "not_required"
            {
                purge_device::validate_snapshot(j.device.as_ref().ok_or("缺独立已封存手机证明")?)?;
            }
        }
        local::verify_checked(&j.local, &|| check_operation(id))?;
        check_shared_ownership(&root, &j.group, &j.local.imported_roots, &|| {
            check_operation(id)
        })?;
        check_operation(id)?;
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
                j.report.warnings.push("手机已核验原授权目录清理完成；保留控制记录与全局共享内容，文件数量和释放字节未计量".into());
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
    check_operation(id)?;
    if let Err(e) = local::verify_checked(&j.local, &|| check_operation(id)) {
        j.report.local_state = "failed".into();
        j.report.error = Some(e);
    } else {
        check_operation(id)?;
        // Persist authorization of this fixed complete local range once before
        // unlink. Checkpoint completed prefixes in bounded batches; a crash can
        // undercount physical removals, never invent them or lose the inventory.
        for item in j.local.items.iter_mut().filter(|i| !i.removed) {
            item.attempted = true;
        }
        write_journal(&root, &j)?;
        for index in 0..j.local.items.len() {
            if let Err(error) = check_operation(id) {
                j.report.local_state = "interrupted".into();
                j.report.error = Some(error);
                break;
            }
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
    if let Err(error) = check_operation(id) {
        j.report.error = Some(error);
        j.report.local_state = "interrupted".into();
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
    #[tokio::test]
    async fn cancellation_drops_pending_future_without_execution_lock() {
        let id = Uuid::new_v4();
        let task = tokio::spawn(supervise(
            id,
            20,
            std::future::pending::<Result<(), String>>(),
        ));
        tokio::task::yield_now().await;
        cancel_kernsight_group_purge_preparation(id).unwrap();
        assert!(task.await.unwrap().unwrap_err().contains("取消"));
        assert!(!OPERATIONS.lock().unwrap().contains_key(&id));
    }
    #[tokio::test]
    #[ignore = "explicit user-authorized deletion of the fixed 18770817 failed parent only"]
    async fn physical_explicit_failed_parent_purge() {
        assert_eq!(
            std::env::var("ME_EXPLICIT_PURGE_187").unwrap(),
            "authorized-by-user"
        );
        let root = PathBuf::from(
            "/Users/swyiic/Library/Application Support/com.swyiic.mobilee/kernsight-captures",
        );
        let parent: Uuid = "18770817-9590-448a-a578-671dc10c3e58".parse().unwrap();
        let group = load(&root, parent).unwrap();
        assert_eq!(group.serial, "35251JEGR12568");
        assert_eq!(group.package, "com.immomo.momo");
        let plan = prepare_at(root.clone(), parent, vec![], false)
            .await
            .unwrap();
        assert_eq!(plan.device.status, "ready");
        let journal = read_journal(&root, plan.id).unwrap();
        let device = journal.device.as_ref().unwrap();
        assert_eq!(device.roots.len(), 2);
        let expected: std::collections::BTreeSet<_> = [
            "/data/local/tmp/ksight/spool/b5964193-118d-41fa-b5b7-ada854144b5e",
            "/data/local/tmp/ksight/spool/d75d58e8-be5d-4a4c-856a-31ca52ebc9bf",
        ]
        .into_iter()
        .collect();
        assert_eq!(
            device
                .roots
                .iter()
                .map(|r| r.path.as_str())
                .collect::<std::collections::BTreeSet<_>>(),
            expected
        );
        let output = PathBuf::from(std::env::var("ME_EXPLICIT_PURGE_REPORT").unwrap());
        fs::write(
            &output,
            serde_json::to_vec_pretty(&serde_json::json!({"plan":plan,"executed":false})).unwrap(),
        )
        .unwrap();
        let report = run_execution(root, plan.id, Some(plan.confirmation_token))
            .await
            .unwrap();
        fs::write(
            output,
            serde_json::to_vec_pretty(&serde_json::json!({"report":report,"executed":true}))
                .unwrap(),
        )
        .unwrap();
        assert_eq!(report.state, "completed");
    }

    #[tokio::test]
    async fn cancellation_before_execution_registration_blocks_late_nonce_but_allows_confirmed_resume(
    ) {
        let f = Fixture::new();
        let g = f.group();
        let plan = prepare_at(f.0.clone(), g.id, vec![], true).await.unwrap();
        cancel_execution(plan.id).unwrap();
        assert!(
            run_execution(f.0.clone(), plan.id, Some(plan.confirmation_token.clone()))
                .await
                .is_err()
        );
        assert!(path(&f.0, g.id).exists());
        let mut journal = read_journal(&f.0, plan.id).unwrap();
        assert!(!journal.started);
        assert!(resume_at(f.0.clone(), plan.id).await.is_err());
        journal.started = true;
        journal.plan.confirmation_token.clear();
        journal.report.state = "partial".into();
        write_journal(&f.0, &journal).unwrap();
        // Preparation cancellation uses a distinct request namespace and must
        // not block an explicitly resumed, previously confirmed transaction.
        cancel_kernsight_group_purge_preparation(plan.id).unwrap();
        assert_eq!(
            resume_at(f.0.clone(), plan.id).await.unwrap().state,
            "completed"
        );
        assert!(read_journal(&f.0, plan.id)
            .unwrap()
            .plan
            .confirmation_token
            .is_empty());
        assert!(!path(&f.0, g.id).exists());
    }
    #[test]
    fn cancelled_preparation_rejects_late_registration() {
        let id = Uuid::new_v4();
        cancel_kernsight_group_purge_preparation(id).unwrap();
        assert!(register_operation(id, 20).is_err());
    }
    #[tokio::test]
    async fn duplicate_execution_cannot_rewrite_live_journal() {
        let f = Fixture::new();
        let g = f.group();
        let plan = prepare_at(f.0.clone(), g.id, vec![], true).await.unwrap();
        let mut j = read_journal(&f.0, plan.id).unwrap();
        j.started = true;
        j.plan.confirmation_token.clear();
        j.report.state = "running".into();
        write_journal(&f.0, &j).unwrap();
        let (_guard, _receiver) = register_operation(plan.id, 30).unwrap();
        assert!(resume_at(f.0.clone(), plan.id).await.is_err());
        assert_eq!(read_journal(&f.0, plan.id).unwrap().report.state, "running");
        assert!(path(&f.0, g.id).exists());
    }
    #[tokio::test]
    async fn elapsed_deadline_drops_pending_future() {
        let id = Uuid::new_v4();
        assert!(
            supervise(id, 0, std::future::pending::<Result<(), String>>())
                .await
                .unwrap_err()
                .contains("期限")
        );
        assert!(!OPERATIONS.lock().unwrap().contains_key(&id));
    }
    #[tokio::test]
    async fn cancelled_resume_waiting_on_execution_lock_is_durable_without_unlink() {
        let f = Fixture::new();
        let g = f.group();
        let p = prepare_at(f.0.clone(), g.id, vec![], true).await.unwrap();
        let mut j = read_journal(&f.0, p.id).unwrap();
        j.started = true;
        j.plan.confirmation_token.clear();
        j.report.state = "partial".into();
        write_journal(&f.0, &j).unwrap();
        let before = serde_json::to_value(&j.local).unwrap();
        let lock = EXECUTION_LOCK.lock().await;
        let root = f.0.clone();
        let id = p.id;
        let task = tokio::spawn(async move { resume_at(root, id).await });
        tokio::task::yield_now().await;
        signal_cancel(id).unwrap();
        let report = tokio::time::timeout(std::time::Duration::from_secs(1), task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(report.state, "partial");
        assert_eq!(report.removed_local_files, 0);
        assert_eq!(
            before,
            serde_json::to_value(&read_journal(&f.0, id).unwrap().local).unwrap()
        );
        assert!(path(&f.0, g.id).exists());
        drop(lock);
    }
    #[tokio::test]
    async fn resume_rejects_unconfirmed_preview_and_preserves_scope() {
        let f = Fixture::new();
        let g = f.group();
        let p = prepare_at(f.0.clone(), g.id, vec![], true).await.unwrap();
        assert!(resume_at(f.0.clone(), p.id).await.is_err());
        assert!(path(&f.0, g.id).exists());
        let mut j = read_journal(&f.0, p.id).unwrap();
        j.started = true;
        j.plan.confirmation_token.clear();
        j.report.state = "partial".into();
        j.plan.expires_unix_ms = 0;
        write_journal(&f.0, &j).unwrap();
        let before = serde_json::to_value(&j.local).unwrap();
        let report = resume_at(f.0.clone(), p.id).await.unwrap();
        assert_eq!(report.state, "completed");
        let after = read_journal(&f.0, p.id).unwrap();
        assert_eq!(
            before["entries"],
            serde_json::to_value(&after.local).unwrap()["entries"]
        );
    }
    #[tokio::test]
    #[ignore = "explicit authorized original-journal resume; performs real deletion"]
    async fn physical_authorized_original_journal_resume() {
        let root = PathBuf::from(std::env::var("ME_PURGE_RESUME_ROOT").expect("AppData root"));
        let id = Uuid::parse_str(&std::env::var("ME_PURGE_RESUME_PLAN").expect("plan")).unwrap();
        assert_eq!(id.to_string(), "1d66c2cf-9266-49c6-acfe-cdd0211467b9");
        let j = read_journal(&root, id).unwrap();
        assert_eq!(
            j.group.id.to_string(),
            "409f90ab-842b-4fc1-99bb-16a47893cf31"
        );
        assert_eq!(j.group.serial, "35251JEGR12568");
        assert!(j.started && j.plan.confirmation_token.is_empty());
        let report = resume_at(root, id).await.unwrap();
        fs::write(
            std::env::var("ME_PURGE_RESUME_REPORT").expect("report"),
            serde_json::to_vec_pretty(&report).unwrap(),
        )
        .unwrap();
    }
    #[test]
    fn oversized_aggregate_metadata_is_rejected_before_json_parse() {
        let f = Fixture::new();
        fs::create_dir_all(f.0.join("purges")).unwrap();
        let p = f.0.join("purges").join(format!("{}.json", Uuid::new_v4()));
        File::create(&p)
            .unwrap()
            .set_len(METADATA_TOTAL_LIMIT + 1)
            .unwrap();
        assert!(list_journals(&f.0).unwrap_err().contains("总量超限"));
        assert!(
            metadata_inventory(&f.0, &["purges"], &|| Err("cancel checkpoint".into()))
                .unwrap_err()
                .contains("checkpoint")
        );
    }
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
    #[test]
    fn failed_before_session_still_needs_device_terminal_verification() {
        let f = Fixture::new();
        let mut group = terminal(&f);
        group.stages[0].attempts[0].session_id = None;
        assert!(needs_device(&group));
        group.budget = Some(
            session_budget::Contract::new(session_budget::Limits::default(), now_millis()).unwrap(),
        );
        group
            .budget
            .as_mut()
            .unwrap()
            .reservations
            .push(session_budget::Reservation {
                id: group.stages[0].attempts[0].relation.attempt_id.to_string(),
                kind: "l0".into(),
                reserved_bytes: 0,
                charged_bytes: Some(0),
                status: "not_started".into(),
            });
        assert!(!needs_device(&group));
    }
    #[tokio::test]
    async fn missing_parent_after_completed_scope_is_idempotent_from_exact_journal() {
        let f = Fixture::new();
        let group = f.group();
        let first = prepare_at(f.0.clone(), group.id, vec![], true)
            .await
            .unwrap();
        execute_at(f.0.clone(), first.id, &first.confirmation_token)
            .await
            .unwrap();
        assert!(!path(&f.0, group.id).exists());
        let again = prepare_at(f.0.clone(), group.id, vec![], false)
            .await
            .unwrap();
        assert!(again.local_entries.is_empty());
        assert_eq!(again.device.status, "not_required");
        assert_ne!(again.confirmation_token, first.confirmation_token);
    }
    #[tokio::test]
    #[ignore = "explicit read-only phone preparation in a shadow metadata root; never execute"]
    async fn physical_readonly_shadow_prepare_uses_fresh_terminal_proof() {
        use sha2::{Digest, Sha256};
        let original =
            PathBuf::from(std::env::var("ME_PURGE_ORIGINAL_ROOT").expect("original root"));
        let shadow = PathBuf::from(std::env::var("ME_PURGE_SHADOW_ROOT").expect("new shadow root"));
        let parent =
            Uuid::parse_str(&std::env::var("ME_PURGE_PARENT_ID").expect("parent")).unwrap();
        let output = PathBuf::from(std::env::var("ME_PURGE_PLAN_REPORT").expect("report"));
        assert!(!shadow.exists());
        assert!(!shadow.starts_with(&original) && !original.starts_with(&shadow));
        fs::create_dir_all(&shadow).unwrap();
        let mut originals = BTreeMap::new();
        // Copy every existing ownership reference. Journal path strings are
        // adapted only in the shadow so their managed-file scope remains exact.
        for directory in ["", "trash", "purges"] {
            let source = original.join(directory);
            if !source.exists() {
                continue;
            }
            let dest = shadow.join(directory);
            fs::create_dir_all(&dest).unwrap();
            for entry in fs::read_dir(source).unwrap() {
                let path = entry.unwrap().path();
                if path.extension().and_then(|v| v.to_str()) != Some("json") {
                    continue;
                }
                assert!(fs::symlink_metadata(&path).unwrap().is_file());
                let bytes = fs::read(&path).unwrap();
                originals.insert(path.clone(), format!("{:x}", Sha256::digest(&bytes)));
                let copy = if directory == "purges" {
                    String::from_utf8(bytes)
                        .unwrap()
                        .replace(original.to_str().unwrap(), shadow.to_str().unwrap())
                        .into_bytes()
                } else {
                    bytes
                };
                fs::write(dest.join(path.file_name().unwrap()), copy).unwrap();
            }
        }
        let started = std::time::Instant::now();
        let plan = prepare_at(shadow.clone(), parent, vec![], false)
            .await
            .unwrap();
        assert_eq!(plan.device.status, "ready");
        let journal = read_journal(&shadow, plan.id).unwrap();
        purge_device::validate_snapshot(journal.device.as_ref().unwrap()).unwrap();
        for (path, before) in &originals {
            assert_eq!(
                *before,
                format!("{:x}", Sha256::digest(fs::read(path).unwrap()))
            );
        }
        fs::write(output,serde_json::to_vec_pretty(&serde_json::json!({"elapsedSeconds":started.elapsed().as_secs_f64(),"originalMetadataFilesUnchanged":originals.len(),"shadowRoot":shadow,"plan":plan,"deviceSnapshot":journal.device,"executed":false})).unwrap()).unwrap();
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
