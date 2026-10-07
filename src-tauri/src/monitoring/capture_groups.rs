//! Durable identities for an automatic capture. Package names are never parent identities.
use super::*;
use std::sync::{Mutex, OnceLock};
use tauri::Manager;

pub mod trash;

const SCHEMA: &str = "mobilee.capture-group/v1";
static IO_LOCK: Mutex<()> = Mutex::new(());
static EPOCH: OnceLock<Uuid> = OnceLock::new();

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Relation {
    pub parent_id: Uuid,
    pub stage_id: Uuid,
    pub attempt_id: Uuid,
    pub attempt: u32,
    pub stage_key: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Attempt {
    pub relation: Relation,
    pub owner_epoch: Uuid,
    pub state: String,
    pub started_unix_ms: u64,
    pub finished_unix_ms: Option<u64>,
    pub session_id: Option<Uuid>,
    pub error: Option<String>,
    /// Bounded display-only output, kept separate from policy-classified errors.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub diagnostic_tail: Option<String>,
    pub remote_artifact_root: Option<String>,
    #[serde(default)]
    pub process_instances: Vec<Value>,
    #[serde(default)]
    pub observation_error: Option<String>,
    #[serde(default)]
    pub omitted_process_instances: usize,
    #[serde(default)]
    pub stage_records: Vec<Value>,
    /// Independent remote stop/return/exit facts; missing legacy data is unknown.
    #[serde(default)]
    pub remote_lifecycle: Option<Value>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Stage {
    pub id: Uuid,
    pub key: String,
    pub mode: String,
    pub duration_seconds: u64,
    pub launch_after_attach: bool,
    pub required: bool,
    pub attempts: Vec<Attempt>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Group {
    pub schema: String,
    pub id: Uuid,
    pub serial: String,
    pub package: String,
    pub created_unix_ms: u64,
    pub cancel_requested: bool,
    #[serde(default)]
    pub unified: bool,
    #[serde(default)]
    pub budget: Option<session_budget::Contract>,
    pub state: String,
    pub base: Value,
    pub stages: Vec<Stage>,
}
impl Group {
    pub fn validate(&self) -> Result<(), String> {
        if let Some(paths) = runtime_paths_from_group(Some(self))? {
            paths.validate()?;
        }
        if self.schema != SCHEMA || self.id.is_nil() {
            return Err("无效主会话 schema/id".into());
        }
        if let Some(b) = self.budget.as_ref() {
            b.validate()?;
        }
        validate_serial(&self.serial)?;
        validate_package(&self.package)?;
        if self.stages.len() != 4 {
            return Err("主会话阶段集合不完整".into());
        }
        let mut ids = BTreeSet::from([self.id]);
        let mut keys = BTreeSet::new();
        let mut sessions = BTreeSet::new();
        for stage in &self.stages {
            if !stage.required
                || stage.attempts.len() > 128
                || (stage.key != "dump" && !(1..=300).contains(&stage.duration_seconds))
            {
                return Err("阶段必需性/时长/attempt 上限无效".into());
            }
            if stage.id.is_nil()
                || !ids.insert(stage.id)
                || !keys.insert(stage.key.as_str())
                || !["l0", "l1", "linker", "dump"].contains(&stage.key.as_str())
            {
                return Err("阶段身份无效/重复".into());
            }
            for (index, a) in stage.attempts.iter().enumerate() {
                if let Some(note) = &a.remote_lifecycle {
                    if note["schema"] == "kernsight.capture-lifecycle/v1" {
                        let expected = if self.unified && stage.key != "dump" {
                            &self.stages[0]
                                .attempts
                                .get(index)
                                .ok_or("共享controller attempt缺失")?
                                .relation
                        } else {
                            &a.relation
                        };
                        validate_remote_lifecycle(note, expected)?;
                    }
                }

                if a.relation.parent_id != self.id
                    || a.relation.stage_id != stage.id
                    || a.relation.stage_key != stage.key
                    || a.relation.attempt != index as u32 + 1
                    || a.relation.attempt_id.is_nil()
                    || !ids.insert(a.relation.attempt_id)
                    || ![
                        "running",
                        "succeeded",
                        "failed",
                        "partial",
                        "cancelled",
                        "interrupted",
                        "unknown",
                    ]
                    .contains(&a.state.as_str())
                    || a.session_id
                        .is_some_and(|s| s.is_nil() || (!sessions.insert(s) && !self.unified))
                {
                    return Err("attempt 归属/状态冲突".into());
                }
            }
        }
        Ok(())
    }
    fn refresh(&mut self) {
        self.state = if self
            .stages
            .iter()
            .any(|s| s.attempts.last().is_some_and(|a| a.state == "running"))
        {
            "running"
        } else if self.cancel_requested {
            "cancelled"
        } else if self
            .stages
            .iter()
            .filter(|s| s.required)
            .all(|s| s.attempts.last().is_some_and(|a| a.state == "succeeded"))
            && !self
                .budget
                .as_ref()
                .is_some_and(|b| b.reservations.iter().any(|r| r.status == "partial"))
        {
            "succeeded"
        } else if self
            .stages
            .iter()
            .any(|s| s.attempts.last().is_some_and(|a| a.state == "partial"))
            || self
                .budget
                .as_ref()
                .is_some_and(|b| b.reservations.iter().any(|r| r.status == "partial"))
        {
            "partial"
        } else if self
            .stages
            .iter()
            .any(|s| s.attempts.last().is_some_and(|a| a.state == "failed"))
        {
            "failed"
        } else if self
            .stages
            .iter()
            .any(|s| s.attempts.last().is_some_and(|a| a.state == "interrupted"))
        {
            "interrupted"
        } else {
            "planned"
        }
        .into();
    }

    pub fn evidence_edges(&self) -> Vec<Value> {
        let mut edges = vec![];
        for stage in &self.stages {
            edges.push(
                serde_json::json!({"from":self.id,"relation":"contains_stage","to":stage.id}),
            );
            for attempt in &stage.attempts {
                edges.push(serde_json::json!({"from":stage.id,"relation":"has_attempt","to":attempt.relation.attempt_id}));
                if let Some(session) = attempt.session_id {
                    edges.push(serde_json::json!({"from":attempt.relation.attempt_id,"relation":"captured_session","to":session}));
                }
                if let Some(root) = attempt.remote_artifact_root.as_ref() {
                    edges.push(serde_json::json!({"from":attempt.relation.attempt_id,"relation":"artifact_source","to":root,"state":attempt.state}));
                }
            }
        }
        edges
    }
    pub fn session_ids(&self) -> BTreeSet<Uuid> {
        self.stages
            .iter()
            .flat_map(|s| s.attempts.iter().filter_map(|a| a.session_id))
            .collect()
    }
    fn recover(&mut self, epoch: Uuid) {
        for stage in &mut self.stages {
            for attempt in &mut stage.attempts {
                if attempt.state == "running" && attempt.owner_epoch != epoch {
                    attempt.state = "interrupted".into();
                    attempt.finished_unix_ms = Some(now_millis());
                    attempt.error = Some("编排进程已重启；设备采集完成/资源清理尚未确认".into());
                }
            }
        }
        self.refresh();
    }
    // Coverage and producer cleanup are separate facts. Only a settled byte-quota
    // partial may precede an independent cold start; legacy/missing facts fail closed.
    fn quota_partial_closed(&self, stage: &Stage) -> bool {
        let Some(a) = stage.attempts.last() else {
            return false;
        };
        let Some(note) = a.remote_lifecycle.as_ref() else {
            return false;
        };
        a.state == "partial"
            && (if stage.key == "dump" {
                a.remote_artifact_root.is_some()
            } else {
                a.session_id.is_some()
            })
            && remote_terminal_confirmed(note)
            && validate_remote_lifecycle(note, &a.relation).is_ok()
            && note["collection_status"] == "partial"
            && note["stop_reason"] == "output_budget_exhausted"
            && (stage.key == "dump" || note["startup"]["timing"]["launcher_status"] == "completed")
            && self.budget.as_ref().is_some_and(|b| {
                b.reservations.iter().any(|r| {
                    r.id == a.relation.attempt_id.to_string()
                        && r.kind == stage.key
                        && r.charged_bytes.is_some()
                        && r.status == "partial"
                })
            })
    }
    fn check_predecessors(&self, index: usize) -> Result<(), String> {
        let next = &self.stages[index];
        for (i, previous) in self.stages[..index].iter().enumerate() {
            if !previous.required
                || previous
                    .attempts
                    .last()
                    .is_some_and(|a| a.state == "succeeded")
            {
                continue;
            }
            // A snapshot depends on its immediate source stage succeeding. An
            // earlier quota partial is safe only after a later successful cold start.
            let independent = next.key != "dump" && next.launch_after_attach;
            let replaced = next.key == "dump"
                && i + 1 < index
                && self.stages[i + 1..index].iter().any(|s| {
                    s.launch_after_attach
                        && s.attempts.last().is_some_and(|a| a.state == "succeeded")
                });
            if !(self.quota_partial_closed(previous) && (independent || replaced)) {
                return Err("前置必需阶段未成功或依赖/清理未确认".into());
            }
        }
        Ok(())
    }
    fn continue_after_partial(&self, key: &str) -> bool {
        let Some(index) = self.stages.iter().position(|s| s.key == key) else {
            return false;
        };
        !self.cancel_requested
            && self.quota_partial_closed(&self.stages[index])
            && self.budget.as_ref().is_some_and(|b| {
                b.remaining() >= 262144 && b.deadline().is_ok_and(|d| d.check().is_ok())
            })
            && self
                .stages
                .get(index + 1)
                .is_some_and(|s| s.key != "dump" && s.launch_after_attach)
            && self.check_predecessors(index + 1).is_ok()
    }
    fn start(&mut self, key: &str, epoch: Uuid) -> Result<Relation, String> {
        if let Some(b) = &self.budget {
            b.deadline()?.check()?;
            if b.remaining() < 262144 {
                return Err("父输出额度不足，不能启动新阶段".into());
            }
        }
        if self.cancel_requested {
            return Err("主会话已取消；不能继续阶段".into());
        }
        if self
            .stages
            .iter()
            .any(|s| s.attempts.last().is_some_and(|a| a.state == "running"))
        {
            return Err("主会话已有运行阶段".into());
        }
        let index = self
            .stages
            .iter()
            .position(|s| s.key == key)
            .ok_or("未知阶段")?;
        self.check_predecessors(index)?;
        ensure_previous_shutdown(&self.stages[index], self.budget.as_ref())?;
        let stage = &mut self.stages[index];
        if stage.attempts.len() >= 128 {
            return Err("阶段 attempt 上限达到，历史证据保留".into());
        }
        if stage
            .attempts
            .last()
            .is_some_and(|a| a.state == "succeeded")
        {
            return Err("已成功阶段无需重试".into());
        }
        let r = Relation {
            parent_id: self.id,
            stage_id: stage.id,
            attempt_id: Uuid::new_v4(),
            attempt: stage.attempts.len() as u32 + 1,
            stage_key: key.into(),
        };
        stage.attempts.push(Attempt {
            relation: r.clone(),
            owner_epoch: epoch,
            state: "running".into(),
            started_unix_ms: now_millis(),
            finished_unix_ms: None,
            session_id: None,
            error: None,
            diagnostic_tail: None,
            remote_artifact_root: None,
            process_instances: vec![],
            observation_error: None,
            omitted_process_instances: 0,
            stage_records: vec![],
            remote_lifecycle: None,
        });
        self.refresh();
        Ok(r)
    }
    fn finish(
        &mut self,
        r: &Relation,
        session: Option<Uuid>,
        root: Option<String>,
        error: Option<String>,
    ) -> Result<(), String> {
        let a = self
            .stages
            .iter_mut()
            .flat_map(|s| s.attempts.iter_mut())
            .find(|a| a.relation == *r)
            .ok_or("attempt 不属于本主会话")?;
        if error.is_none() && r.stage_key != "dump" && session.is_none() {
            return Err("成功阶段缺少子 session ID".into());
        }
        let desired = if error
            .as_deref()
            .is_some_and(|e| e.contains("parent_cancelled"))
        {
            "cancelled"
        } else if error.as_deref().is_some_and(|e| {
            session_deadline::is_stop(e)
                || (e.contains("remote_terminal_unconfirmed")
                    || e.contains("remote_collection_partial"))
        }) {
            "partial"
        } else if error.is_some() {
            "failed"
        } else {
            "succeeded"
        };
        if a.state != "running" {
            if a.state == desired
                && a.session_id == session
                && a.remote_artifact_root == root
                && a.error == error
            {
                return Ok(());
            }
            return Err("attempt 终态冲突，拒绝覆盖历史".into());
        }
        a.state = desired.into();
        a.finished_unix_ms = Some(now_millis());
        a.session_id = session;
        a.remote_artifact_root = root;
        a.error = error;
        self.refresh();
        self.validate()
    }
}
fn epoch() -> Uuid {
    *EPOCH.get_or_init(Uuid::new_v4)
}
pub(super) fn root(app: &tauri::AppHandle) -> Result<PathBuf, String> {
    Ok(app
        .path()
        .app_data_dir()
        .map_err(|e| e.to_string())?
        .join("kernsight-captures"))
}
fn path(root: &Path, id: Uuid) -> PathBuf {
    root.join(format!("{id}.json"))
}
fn save(root: &Path, g: &Group) -> Result<(), String> {
    g.validate()?;
    let encoded = serde_json::to_vec_pretty(g).map_err(|e| e.to_string())?;
    if encoded.len() > 1024 * 1024 {
        return Err("主会话清单超过 1MiB，拒绝覆盖旧清单；状态未确认".into());
    }
    std::fs::create_dir_all(root).map_err(|e| e.to_string())?;
    let temp = root.join(format!(".{}.tmp", Uuid::new_v4()));
    let result = (|| {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp)
            .map_err(|e| e.to_string())?;
        f.write_all(&encoded).map_err(|e| e.to_string())?;
        f.sync_all().map_err(|e| e.to_string())?;
        std::fs::rename(&temp, path(root, g.id)).map_err(|e| e.to_string())?;
        File::open(root)
            .and_then(|f| f.sync_all())
            .map_err(|e| e.to_string())?;
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(temp);
    }
    result
}
fn load(root: &Path, id: Uuid) -> Result<Group, String> {
    let mut g: Group = serde_json::from_str(&read_bounded_text(&path(root, id), 1024 * 1024)?)
        .map_err(|e| e.to_string())?;
    if g.id != id {
        return Err("主会话清单与文件身份冲突".into());
    }
    g.validate()?;
    g.recover(epoch());
    save(root, &g)?;
    Ok(g)
}
pub fn read_import(root: &Path) -> Result<Option<Group>, String> {
    let p = root.join("capture-group.json");
    if !p.exists() {
        return Ok(None);
    }
    let mut g: Group =
        serde_json::from_str(&read_bounded_text(&p, 1024 * 1024)?).map_err(|e| e.to_string())?;
    g.validate()?;
    let relation_path = root.join("capture-relation.json");
    if relation_path.is_file() {
        let note: Value = serde_json::from_str(&read_bounded_text(&relation_path, 32768)?)
            .map_err(|e| e.to_string())?;
        let relation = &note["relation"];
        let matched = g.stages.iter().flat_map(|s| s.attempts.iter()).any(|a| {
            relation["parent_id"].as_str() == Some(g.id.to_string().as_str())
                && relation["stage_id"].as_str() == Some(a.relation.stage_id.to_string().as_str())
                && relation["attempt_id"].as_str()
                    == Some(a.relation.attempt_id.to_string().as_str())
                && relation["attempt"].as_u64() == Some(a.relation.attempt as u64)
                && relation["stage_key"].as_str() == Some("dump")
                && note["package"].as_str() == Some(g.package.as_str())
        });
        if !matched {
            return Err("agent 原始 dump 关联与 parent 清单冲突".into());
        }
    }
    g.refresh();
    Ok(Some(g))
}
/// Dedicated IPC prevents an old Me backend silently discarding the new runtime field.
#[tauri::command]
pub fn begin_kernsight_isolated_group(
    app: tauri::AppHandle,
    request: KernSightCaptureRequest,
    durations: Vec<u64>,
    startup_replay: bool,
) -> Result<Group, String> {
    request
        .runtime_paths
        .as_ref()
        .ok_or("隔离主会话缺运行目录配置")?
        .validate()?;
    begin_kernsight_group(app, request, durations, startup_replay)
}
#[tauri::command]
pub fn begin_kernsight_group(
    app: tauri::AppHandle,
    request: KernSightCaptureRequest,
    durations: Vec<u64>,
    startup_replay: bool,
) -> Result<Group, String> {
    begin_group_at(root(&app)?, request, durations, startup_replay)
}
fn begin_group_at(
    root: PathBuf,
    request: KernSightCaptureRequest,
    durations: Vec<u64>,
    startup_replay: bool,
) -> Result<Group, String> {
    validate_serial(&request.serial)?;
    if request.collect_keys || request.collect_private || request.collect_memory_windows {
        return Err("额外密钥/私有存储/通用窗口范围尚未验证，不能用于一键采集；未启动任何阶段。旧 CLI 显式操作保留。".into());
    }
    let package = request.package.as_deref().ok_or("自动采集缺包名")?;
    validate_package(package)?;
    if durations.len() != 3
        || durations.iter().any(|n| !(1..=300).contains(n))
        || request.mirror_burp.is_some()
        || request.inspect_stages.is_some()
    {
        return Err("无效自动采集计划".into());
    }
    let order = if startup_replay {
        vec!["l0", "l1", "dump", "linker"]
    } else {
        vec!["l0", "l1", "linker", "dump"]
    };
    let stages = order
        .into_iter()
        .map(|key| Stage {
            id: Uuid::new_v4(),
            key: key.into(),
            mode: if key == "dump" {
                "snapshot"
            } else if key == "l0" {
                "observe"
            } else {
                "inspect"
            }
            .into(),
            duration_seconds: match key {
                "l0" => durations[0],
                "l1" => durations[1],
                "linker" => durations[2],
                _ => 0,
            },
            launch_after_attach: key != "dump" && (startup_replay || key == "l0"),
            required: true,
            attempts: vec![],
        })
        .collect();
    let mut base = serde_json::to_value(&request).map_err(|e| e.to_string())?;
    base.as_object_mut().unwrap().remove("captureRelation");
    base.as_object_mut().unwrap().remove("captureRelations");
    let g = Group {
        schema: SCHEMA.into(),
        id: Uuid::new_v4(),
        serial: request.serial.clone(),
        package: package.into(),
        created_unix_ms: now_millis(),
        cancel_requested: false,
        unified: !startup_replay,
        state: "planned".into(),
        budget: Some(session_budget::Contract::new(
            request.session_budget.clone().unwrap_or_default(),
            now_millis(),
        )?),
        base,
        stages,
    };
    let _guard = IO_LOCK.lock().map_err(|e| e.to_string())?;
    save(&root, &g)?;
    Ok(g)
}
#[tauri::command]
pub fn list_kernsight_groups(
    app: tauri::AppHandle,
    serial: Option<String>,
) -> Result<Vec<Group>, String> {
    let _guard = IO_LOCK.lock().map_err(|e| e.to_string())?;
    let root = root(&app)?;
    if !root.exists() {
        return Ok(vec![]);
    }
    let mut out = vec![];
    for entry in std::fs::read_dir(&root).map_err(|e| e.to_string())? {
        let p = entry.map_err(|e| e.to_string())?.path();
        if let Some(id) = p
            .file_stem()
            .and_then(|s| s.to_str())
            .and_then(|s| Uuid::parse_str(s).ok())
        {
            if trash::managed_is_trashed(&root, id)? {
                continue;
            }
            let g = load(&root, id)?;
            if serial.as_deref().is_none_or(|s| s == g.serial) {
                out.push(g);
            }
        }
    }
    out.sort_by_key(|g| std::cmp::Reverse(g.created_unix_ms));
    Ok(out)
}
#[tauri::command]
pub fn cancel_kernsight_group(app: tauri::AppHandle, parent_id: Uuid) -> Result<Group, String> {
    let _guard = IO_LOCK.lock().map_err(|e| e.to_string())?;
    let root = root(&app)?;
    let mut g = load(&root, parent_id)?;
    g.cancel_requested = true;
    if let Some(b) = &g.budget {
        if let Ok(d) = b.deadline() {
            d.cancel();
        }
    }
    g.refresh();
    save(&root, &g)?;
    Ok(g)
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StageResult {
    pub group: Group,
    pub result: Option<KernSightCaptureResult>,
    pub error: Option<String>,
    pub continue_after_partial: bool,
}

const MAX_CAPTURE_DIAGNOSTIC_BYTES: usize = 3072;

fn capture_diagnostic_tail(result: &KernSightCaptureResult) -> Option<String> {
    let (source, text) = if !result.stderr.trim().is_empty() {
        ("stderr", result.stderr.trim())
    } else {
        ("stdout", result.stdout.trim())
    };
    if text.is_empty() {
        return None;
    }
    let mut prefix = format!("[{source}]\n");
    if prefix.len() + text.len() > MAX_CAPTURE_DIAGNOSTIC_BYTES {
        prefix = format!("[{source} tail; earlier output omitted]\n");
    }
    let mut start = text
        .len()
        .saturating_sub(MAX_CAPTURE_DIAGNOSTIC_BYTES - prefix.len());
    while !text.is_char_boundary(start) {
        start += 1;
    }
    Some(format!("{prefix}{}", &text[start..]))
}

/// Run after terminal and budget classification. Output is diagnostic evidence,
/// never a stop reason, cleanup receipt, or permission to advance another stage.
fn retain_capture_diagnostic(attempt: &mut Attempt, result: Option<&KernSightCaptureResult>) {
    if !matches!(attempt.state.as_str(), "running" | "succeeded") {
        attempt.diagnostic_tail = result.and_then(capture_diagnostic_tail);
    }
}

#[tauri::command]
pub async fn run_kernsight_group_stage(
    app: tauri::AppHandle,
    parent_id: Uuid,
    stage_key: String,
) -> Result<StageResult, String> {
    run_group_stage_at(root(&app)?, parent_id, stage_key).await
}
async fn run_group_stage_at(
    root: PathBuf,
    parent_id: Uuid,
    stage_key: String,
) -> Result<StageResult, String> {
    let (mut g, r, stage) = {
        let _guard = IO_LOCK.lock().map_err(|e| e.to_string())?;
        trash::ensure_not_trashed(&root, parent_id)?;
        let mut g = load(&root, parent_id)?;
        if let Ok(entries) = std::fs::read_dir(&root) {
            for entry in entries {
                let p = entry.map_err(|e| e.to_string())?.path();
                if let Some(id) = p
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .and_then(|s| Uuid::parse_str(s).ok())
                {
                    let other = load(&root, id)?;
                    if other.id != g.id && other.serial == g.serial && other.state == "running" {
                        return Err("该设备已有运行的主会话；拒绝并行覆盖".into());
                    }
                }
            }
        }
        if g.unified && stage_key != "dump" {
            return Err("统一主会话需共享阶段执行入口".into());
        }
        g.budget
            .as_ref()
            .ok_or("旧父会话deadline未知，未启动")?
            .deadline()?
            .check()?;
        let r = g.start(&stage_key, epoch())?;
        let stage = g
            .stages
            .iter()
            .find(|s| s.key == stage_key)
            .unwrap()
            .clone();
        save(&root, &g)?;
        (g, r, stage)
    };
    let deadline = g
        .budget
        .as_ref()
        .ok_or("旧父会话deadline未知")?
        .deadline()?;
    let run = deadline.run(async {
        let busy=run_device_root_script(&g.serial,r#"for p in $(pidof ksightd 2>/dev/null); do c=$(tr '\0' ' ' < /proc/$p/cmdline); case "$c" in *ksightd*\ capture*) echo capture_busy; exit 73;; esac; done"#).await?;
        if busy.code!=Some(0) {return Err("设备已有采集进程或状态未知；未启动/重试，不强杀其他会话".into());}

        let mut request: KernSightCaptureRequest =
            serde_json::from_value(g.base.clone()).map_err(|e| e.to_string())?;
        request.capture_relation = Some(r.clone());

        let(n,t)=reserve_attempt(&root,&mut g,r.attempt_id.to_string(),&stage.key)?;request.output_budget_bytes=Some(n-65536);request.output_budget_ms=Some(t);
        request.capture_relations=None;
        request.package = Some(g.package.clone());
        request.serial = g.serial.clone();
        request.duration_seconds = stage.duration_seconds;
        request.launch_after_attach = stage.launch_after_attach;
        request.inspect_tls = stage.key == "l1";
        request.inspect_jni = stage.key == "l1";
        request.inspect_linker = stage.key == "linker";
        request.inspect_adapter = (stage.key == "l1").then(|| "binder_userspace".into());
        request.inspect_stages = None;
        if stage.key == "dump" {
            let previous=g.stages[..g.stages.iter().position(|s|s.key=="dump").unwrap_or(0)].iter().rev().find_map(|s|s.attempts.last().and_then(|a|a.remote_lifecycle.as_ref()));
            request.expected_code_sources=Some(super::qualified_dump_sources(previous,&g.package)?);
            dump_kernsight_package_scoped(
                g.serial.clone(),
                g.package.clone(),
                request.hide_debug,
                true,
                Some(request.code_only),
                Some(r.clone()),
                Some(&request),
            )
            .await
        } else {
            start_kernsight_capture(request).await
        }
    })
    .await;
    let (result, mut error, session) = match run {
        Ok(result) => {
            let error = if result.exit_code == Some(0)
                && (stage.key == "dump" || result.session_id.is_some())
            {
                None
            } else {
                Some(format!("阶段退出状态未确认成功: {:?}", result.exit_code))
            };
            let session = result.session_id;
            (Some(result), error, session)
        }
        Err(e) => (None, Some(e), None),
    };
    let remote_lifecycle =
        if result.is_some() || error.as_deref().is_some_and(session_deadline::is_stop) {
            Some(
                observe_remote_lifecycle(
                    &g.serial,
                    &r,
                    error.as_deref(),
                    runtime_paths_from_group(Some(&g))?.as_ref(),
                )
                .await,
            )
        } else {
            None
        };
    if remote_lifecycle
        .as_ref()
        .is_some_and(|n| !remote_terminal_confirmed(n))
        && error.is_none()
    {
        error=Some("remote_terminal_unconfirmed：停止请求、远端返回与退出尚未全部确认；保留原件，不能标完整成功".into());
    }
    if remote_lifecycle
        .as_ref()
        .is_some_and(|n| n["collection_status"] == "partial")
        && error.is_none()
    {
        error = Some("remote_collection_partial：producer已返回，采集partial，原件保留".into());
    }
    let (instances, observation_error) = if let Some(session) = session {
        match deadline
            .run(get_kernsight_session_report_scoped(
                g.serial.clone(),
                session.to_string(),
                runtime_paths_from_group(Some(&g))?.as_ref(),
            ))
            .await
        {
            Ok(report) => (
                report.report["processes"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter(|p| p["package"].as_str() == Some(g.package.as_str()))
                    .flat_map(|p| p["instances"].as_array().into_iter().flatten().cloned())
                    .collect::<Vec<_>>(),
                None,
            ),
            Err(e) => (vec![], Some(format!("子会话实例证据未取得：{e}"))),
        }
    } else {
        (
            vec![],
            Some("无子会话进程实例证据；dump 实例见原报告".into()),
        )
    };
    let paths = runtime_paths_from_group(Some(&g))?;
    let artifact = if stage.key == "dump" {
        Some(runtime_paths::route(
            paths.as_ref(),
            &format!(
                "/data/local/tmp/ksight/captures/{}/{}/{}/dump",
                r.parent_id, r.stage_id, r.attempt_id
            ),
        )?)
    } else {
        None
    };
    {
        let _guard = IO_LOCK.lock().map_err(|e| e.to_string())?;
        g = load(&root, parent_id)?;
        if let Err(stop) = deadline.check() {
            if error.is_none() {
                error = Some(stop);
            } else if !error.as_deref().is_some_and(session_deadline::is_stop) {
                error = Some(format!("{}; {stop}", error.as_deref().unwrap()));
            }
        }
        g.finish(&r, session, artifact, error.clone())?;
        mark_stopped_budget(&mut g, error.as_deref());
        if result.is_none()
            && error.as_deref().is_some_and(|e| {
                e.contains("代码一键范围门禁未通过") || e.contains("代码采集范围能力未知")
            })
        {
            if let Some(b) = g.budget.as_mut() {
                b.release_unstarted(&r.attempt_id.to_string())?;
            }
        }
        if let (Some(b), Some(result)) = (g.budget.as_mut(), result.as_ref()) {
            if let Some(note) = result
                .stderr
                .lines()
                .filter_map(|l| serde_json::from_str::<Value>(l).ok())
                .find(|v| v["schema"] == "kernsight.output-budget/v1")
            {
                let settlement = b.settle(&r.attempt_id.to_string(), &note);
                let settled = settlement.is_ok();
                if let Err(e) = settlement {
                    if let Some(a) = g
                        .stages
                        .iter_mut()
                        .flat_map(|s| s.attempts.iter_mut())
                        .find(|a| a.relation == r)
                    {
                        a.state = "failed".into();
                        a.error = Some(format!("预算收据不可信: {e}"));
                    }
                    g.refresh();
                }
                if note["partial"] == true && settled {
                    if let Some(a) = g
                        .stages
                        .iter_mut()
                        .flat_map(|s| s.attempts.iter_mut())
                        .find(|a| a.relation == r)
                    {
                        a.state = "partial".into();
                        a.error = Some("输出预算耗尽；已保存证据可拉取，覆盖 partial".into());
                    }
                    g.refresh();
                }
            }
        }
        let attempt = g
            .stages
            .iter_mut()
            .flat_map(|s| s.attempts.iter_mut())
            .find(|a| a.relation == r)
            .unwrap();
        attempt.omitted_process_instances = instances.len().saturating_sub(16);
        attempt.process_instances = instances.into_iter().take(16).collect();
        attempt.observation_error = observation_error;
        attempt.remote_lifecycle = remote_lifecycle;
        retain_capture_diagnostic(attempt, result.as_ref());
        save(&root, &g)?;
    }
    let continue_after_partial = g.continue_after_partial(&stage_key);
    Ok(StageResult {
        group: g,
        result,
        error,
        continue_after_partial,
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    pub(super) fn group() -> Group {
        Group {
            schema: SCHEMA.into(),
            id: Uuid::new_v4(),
            serial: "synthetic".into(),
            package: "org.example.fixture".into(),
            created_unix_ms: 1,
            cancel_requested: false,
            budget: None,
            unified: false,
            state: "planned".into(),
            base: serde_json::json!({}),
            stages: ["l0", "l1", "dump", "linker"]
                .map(|key| Stage {
                    id: Uuid::new_v4(),
                    key: key.into(),
                    mode: "fixture".into(),
                    duration_seconds: 1,
                    launch_after_attach: true,
                    required: true,
                    attempts: vec![],
                })
                .to_vec(),
        }
    }
    fn diagnostic_result(stdout: &str, stderr: &str) -> KernSightCaptureResult {
        KernSightCaptureResult {
            session_id: Some(Uuid::new_v4()),
            started_unix_ms: 1,
            finished_unix_ms: 2,
            command_preview: "synthetic diagnostic fixture".into(),
            stdout: stdout.into(),
            stderr: stderr.into(),
            exit_code: Some(1),
            hide_debug: false,
        }
    }

    #[test]
    fn diagnostic_tail_prefers_stderr_falls_back_to_stdout_and_omits_empty_output() {
        assert_eq!(
            capture_diagnostic_tail(&diagnostic_result("stdout detail", " stderr detail \n")),
            Some("[stderr]\nstderr detail".into())
        );
        assert_eq!(
            capture_diagnostic_tail(&diagnostic_result(" stdout detail \n", " \n")),
            Some("[stdout]\nstdout detail".into())
        );
        assert!(capture_diagnostic_tail(&diagnostic_result(" \n", "\t")).is_none());
    }

    #[test]
    fn diagnostic_tail_bounds_bytes_without_splitting_utf8_and_keeps_the_end() {
        for text in ["x".repeat(20_000), "诊断🙂".repeat(5_000)] {
            let output = format!("{text}\nfinal failure detail");
            let tail = capture_diagnostic_tail(&diagnostic_result("", &output)).unwrap();
            assert!(tail.len() <= MAX_CAPTURE_DIAGNOSTIC_BYTES);
            assert!(tail.starts_with("[stderr tail; earlier output omitted]\n"));
            assert!(tail.ends_with("\nfinal failure detail"));
        }
    }

    #[test]
    fn diagnostic_tail_persists_without_changing_failure_policy_or_retry_history() {
        let mut g = group();
        let relation = g.start("l0", epoch()).unwrap();
        let output = diagnostic_result("", "parent_cancelled remote_collection_partial");
        let error = Some("阶段退出状态未确认成功: Some(1)".to_owned());
        g.finish(&relation, output.session_id, None, error.clone())
            .unwrap();
        retain_capture_diagnostic(&mut g.stages[0].attempts[0], Some(&output));
        // The display-only log must neither classify a stop nor change idempotency.
        g.finish(&relation, output.session_id, None, error.clone())
            .unwrap();
        assert_eq!(g.state, "failed");
        assert_eq!(g.stages[0].attempts[0].error, error);
        assert!(!g.continue_after_partial("l0"));
        assert!(g.start("l1", epoch()).is_err());

        let root = std::env::temp_dir().join(format!("me-diagnostic-test-{}", Uuid::new_v4()));
        save(&root, &g).unwrap();
        let mut restored = load(&root, g.id).unwrap();
        assert_eq!(
            restored.stages[0].attempts[0].diagnostic_tail,
            Some("[stderr]\nparent_cancelled remote_collection_partial".into())
        );
        let retry = restored.start("l0", epoch()).unwrap();
        assert_eq!(retry.attempt, 2);
        assert_eq!(restored.stages[0].attempts[0].state, "failed");
        assert!(restored.stages[0].attempts[0].diagnostic_tail.is_some());
        assert!(restored.stages[0].attempts[1].diagnostic_tail.is_none());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn diagnostic_tail_does_not_store_success_logs_and_accepts_legacy_manifests() {
        let mut g = group();
        let relation = g.start("l0", epoch()).unwrap();
        let output = diagnostic_result("ordinary success output", "warning");
        g.finish(&relation, output.session_id, None, None).unwrap();
        retain_capture_diagnostic(&mut g.stages[0].attempts[0], Some(&output));
        assert!(g.stages[0].attempts[0].diagnostic_tail.is_none());
        let encoded = serde_json::to_value(&g).unwrap();
        assert!(encoded["stages"][0]["attempts"][0]
            .get("diagnosticTail")
            .is_none());
        let restored: Group = serde_json::from_value(encoded).unwrap();
        restored.validate().unwrap();
        assert!(restored.stages[0].attempts[0].diagnostic_tail.is_none());
    }

    fn quota_partial_group() -> Group {
        let mut g = group();
        g.stages[2].launch_after_attach = false;
        g.budget = Some(
            session_budget::Contract::new(
                session_budget::Limits {
                    total_bytes: 67108864,
                    max_seconds: 60,
                },
                now_millis(),
            )
            .unwrap(),
        );
        let r = g.start("l0", epoch()).unwrap();
        g.budget
            .as_mut()
            .unwrap()
            .reserve(r.attempt_id.to_string(), "l0", now_millis())
            .unwrap();
        g.budget
            .as_mut()
            .unwrap()
            .settle(
                &r.attempt_id.to_string(),
                &serde_json::json!({"admitted_write_bytes":100000,"partial":true}),
            )
            .unwrap();
        g.finish(
            &r,
            Some(Uuid::new_v4()),
            None,
            Some("remote_collection_partial".into()),
        )
        .unwrap();
        g.stages[0].attempts[0].remote_lifecycle = Some(serde_json::json!({
            "schema":"kernsight.capture-lifecycle/v1", "relation":{"parent_id":r.parent_id,"stage_id":r.stage_id,"attempt_id":r.attempt_id,"attempt":r.attempt,"stage_key":r.stage_key}, "token":Uuid::new_v4(),
            "stop_request_recorded":true,"stop_acknowledged":true,
            "collection_status":"partial", "collection_returned":true,
            "agent_exited_confirmed":true, "cleanup":"producer_scope_returned",
            "target_pause":"forbidden", "stop_reason":"output_budget_exhausted",
            "startup":{"timing":{"launcher_status":"completed"}}
        }));
        g
    }
    #[test]
    fn quota_partial_retains_evidence_and_allows_independent_cold_start() {
        let mut g = quota_partial_group();
        let old = g.stages[0].attempts[0].clone();
        assert!(g.continue_after_partial("l0"));
        let r = g.start("l1", epoch()).unwrap();
        g.finish(&r, Some(Uuid::new_v4()), None, None).unwrap();
        assert_eq!(g.state, "partial");
        assert_eq!(g.stages[0].attempts[0].session_id, old.session_id);
        assert_eq!(g.stages[0].attempts[0].state, "partial");
        // L1 is a successful new source; earlier L0 partial does not poison it.
        assert!(g.start("dump", epoch()).is_ok());
    }
    #[test]
    fn quota_partial_missing_or_unsafe_facts_do_not_continue() {
        for (key, value) in [
            ("agent_exited_confirmed", serde_json::json!(false)),
            ("collection_returned", serde_json::json!(false)),
            ("cleanup", serde_json::json!("unconfirmed")),
            (
                "stop_reason",
                serde_json::json!("parent_deadline_exhausted"),
            ),
            ("stop_reason", serde_json::json!("parent_cancelled")),
            ("stop_reason", serde_json::json!("output_io_failed")),
            ("relation", serde_json::Value::Null),
            ("startup", serde_json::Value::Null),
        ] {
            let mut g = quota_partial_group();
            g.stages[0].attempts[0].remote_lifecycle.as_mut().unwrap()[key] = value;
            assert!(!g.continue_after_partial("l0"), "{key}");
            assert!(g.start("l1", epoch()).is_err(), "{key}");
        }
        let mut g = quota_partial_group();
        g.budget.as_mut().unwrap().reservations[0].charged_bytes = None;
        assert!(!g.continue_after_partial("l0"));
        assert!(g.start("l1", epoch()).is_err());
        let mut g = quota_partial_group();
        g.stages[1].launch_after_attach = false;
        assert!(g.start("l1", epoch()).is_err());
        let mut g = quota_partial_group();
        g.budget.as_ref().unwrap().deadline().unwrap().cancel();
        assert!(!g.continue_after_partial("l0"));
        assert!(g.start("l1", epoch()).is_err());
        let mut g = quota_partial_group();
        for i in 0..16 {
            let _ =
                g.budget
                    .as_mut()
                    .unwrap()
                    .reserve(format!("occupied-{i}"), "dump", now_millis());
        }
        assert!(g.budget.as_ref().unwrap().remaining() < 262144);
        assert!(!g.continue_after_partial("l0"));
        assert!(g.start("l1", epoch()).is_err());
        let mut g = quota_partial_group();
        g.cancel_requested = true;
        assert!(!g.continue_after_partial("l0"));
        assert!(g.start("l1", epoch()).is_err());
    }
    fn closed_partial_dump_group() -> Group {
        let mut g = quota_partial_group();
        let r = g.start("l1", epoch()).unwrap();
        g.finish(&r, Some(Uuid::new_v4()), None, None).unwrap();
        let r = g.start("dump", epoch()).unwrap();
        g.budget
            .as_mut()
            .unwrap()
            .reserve(r.attempt_id.to_string(), "dump", now_millis())
            .unwrap();
        g.budget
            .as_mut()
            .unwrap()
            .settle(
                &r.attempt_id.to_string(),
                &serde_json::json!({"admitted_write_bytes":1000,"partial":true}),
            )
            .unwrap();
        g.finish(
            &r,
            None,
            Some("owned-fixture-dump".into()),
            Some("remote_collection_partial".into()),
        )
        .unwrap();
        let mut note = g.stages[0].attempts[0].remote_lifecycle.clone().unwrap();
        note["relation"] = serde_json::json!({"parent_id":r.parent_id,"stage_id":r.stage_id,"attempt_id":r.attempt_id,"attempt":r.attempt,"stage_key":r.stage_key});
        note["startup"] = Value::Null;
        g.stages[2].attempts[0].remote_lifecycle = Some(note);
        g
    }
    #[test]
    fn closed_quota_partial_dump_allows_only_independent_linker_and_keeps_partial() {
        let mut g = closed_partial_dump_group();
        assert!(g.continue_after_partial("dump"));
        let mut unsafe_group = g.clone();
        unsafe_group.stages[2].attempts[0]
            .remote_lifecycle
            .as_mut()
            .unwrap()["agent_exited_confirmed"] = serde_json::json!(false);
        assert!(!unsafe_group.continue_after_partial("dump"));
        assert!(unsafe_group.start("linker", epoch()).is_err());
        let r = g.start("linker", epoch()).unwrap();
        g.finish(&r, Some(Uuid::new_v4()), None, None).unwrap();
        assert_eq!(g.state, "partial");
    }
    #[test]
    fn partial_dump_missing_cleanup_cancel_and_unsettled_budget_stop_linker() {
        for (key, value) in [
            ("cleanup", serde_json::json!("unconfirmed")),
            ("collection_returned", Value::Null),
            ("relation", Value::Null),
            ("stop_reason", serde_json::json!("output_io_failed")),
        ] {
            let mut g = closed_partial_dump_group();
            g.stages[2].attempts[0].remote_lifecycle.as_mut().unwrap()[key] = value;
            assert!(!g.continue_after_partial("dump"), "{key}");
            assert!(g.start("linker", epoch()).is_err(), "{key}");
            assert_eq!(g.stages[2].attempts[0].state, "partial");
        }
        let mut cancelled = closed_partial_dump_group();
        cancelled.cancel_requested = true;
        assert!(cancelled.start("linker", epoch()).is_err());
        let mut unsettled = closed_partial_dump_group();
        unsettled
            .budget
            .as_mut()
            .unwrap()
            .reservations
            .last_mut()
            .unwrap()
            .charged_bytes = None;
        assert!(unsettled.start("linker", epoch()).is_err());
    }

    #[tokio::test]
    async fn partial_dump_linker_directory_import_preserves_one_parent_and_artifact() {
        let mut g = closed_partial_dump_group();
        let dump = g.stages[2].attempts[0].relation.clone();
        let r = g.start("linker", epoch()).unwrap();
        g.finish(&r, Some(Uuid::new_v4()), None, None).unwrap();
        let root = std::env::temp_dir().join(format!("mobilee-partial-dump-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&root).unwrap();
        for (name, value) in [
            ("capture-group.json", serde_json::to_value(&g).unwrap()),
            (
                "capture-relation.json",
                serde_json::json!({"package":g.package,"relation":{"parent_id":dump.parent_id,"stage_id":dump.stage_id,"attempt_id":dump.attempt_id,"attempt":dump.attempt,"stage_key":dump.stage_key}}),
            ),
            (
                "dump-report.json",
                serde_json::json!({"package":g.package,"dump_id":Uuid::new_v4(),"status":"partial","artifacts":[]}),
            ),
        ] {
            std::fs::write(root.join(name), serde_json::to_vec(&value).unwrap()).unwrap();
        }
        let imported = import_kernsight_evidence_directory(root.to_string_lossy().into_owned())
            .await
            .unwrap();
        let parent = &imported.session_report.as_ref().unwrap()["mobilee_capture_group"];
        assert_eq!(parent["id"], g.id.to_string());
        assert_eq!(parent["state"], "partial");
        assert_eq!(parent["stages"][2]["attempts"][0]["state"], "partial");
        assert_eq!(parent["stages"][3]["attempts"][0]["state"], "succeeded");
        assert_eq!(imported.dump_report["status"], "partial");
        assert_eq!(g.session_ids().len(), 3);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn failed_transfer_releases_only_unstarted_export_phases() {
        let mut g = quota_partial_group();
        let root = std::env::temp_dir().join(format!("me-export-release-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&root).unwrap();
        save(&root, &g).unwrap();
        let output = root.join("fixture.mee");
        reserve_export_at(&root, &mut g, &output).unwrap();
        settle_export_at(
            &root,
            &mut g,
            &output,
            "transfer",
            &serde_json::json!({"admitted_write_bytes":1000,"partial":true}),
        )
        .unwrap();
        release_unstarted_export_at(&root, &mut g, &output, &["archive", "import"]).unwrap();
        let budget = g.budget.as_ref().unwrap();
        budget.validate().unwrap();
        for kind in ["archive", "import"] {
            let r = budget.reservations.iter().find(|r| r.kind == kind).unwrap();
            assert_eq!(r.status, "not_started");
            assert_eq!(r.charged_bytes, Some(0));
        }
        assert_eq!(
            budget
                .reservations
                .iter()
                .find(|r| r.kind == "transfer")
                .unwrap()
                .status,
            "partial"
        );
        assert_eq!(g.state, "partial");
        std::fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn quota_partial_same_instance_dump_dependency_still_blocks() {
        let mut g = quota_partial_group();
        let r = g.start("l1", epoch()).unwrap();
        g.budget
            .as_mut()
            .unwrap()
            .reserve(r.attempt_id.to_string(), "l1", now_millis())
            .unwrap();
        g.budget
            .as_mut()
            .unwrap()
            .settle(
                &r.attempt_id.to_string(),
                &serde_json::json!({"admitted_write_bytes":100,"partial":true}),
            )
            .unwrap();
        g.finish(
            &r,
            Some(Uuid::new_v4()),
            None,
            Some("remote_collection_partial".into()),
        )
        .unwrap();
        let mut note = g.stages[0].attempts[0].remote_lifecycle.clone().unwrap();
        note["relation"] = serde_json::json!({"parent_id":r.parent_id,"stage_id":r.stage_id,"attempt_id":r.attempt_id,"attempt":r.attempt,"stage_key":r.stage_key});
        g.stages[1].attempts[0].remote_lifecycle = Some(note);
        assert!(!g.continue_after_partial("l1"));
        assert!(g.start("dump", epoch()).is_err());
    }
    #[test]
    fn repeated_package_runs_have_disjoint_ids() {
        let a = group();
        let b = group();
        assert_ne!(a.id, b.id);
        assert_eq!(a.package, b.package);
        assert_ne!(a.stages[0].id, b.stages[0].id);
    }
    #[test]
    fn retry_retains_failed_attempt_and_source() {
        let mut g = group();
        let r = g.start("l0", epoch()).unwrap();
        let s = Uuid::new_v4();
        g.finish(&r, Some(s), None, Some("failed".into())).unwrap();
        let r2 = g.start("l0", epoch()).unwrap();
        assert_eq!(r2.attempt, 2);
        assert_ne!(r.attempt_id, r2.attempt_id);
        g.finish(&r2, Some(Uuid::new_v4()), None, None).unwrap();
        assert_eq!(g.stages[0].attempts[0].state, "failed");
        assert_eq!(g.session_ids().len(), 2);
        assert_ne!(g.state, "succeeded");
    }
    #[test]
    fn terminal_idempotency_and_conflict() {
        let mut g = group();
        let r = g.start("l0", epoch()).unwrap();
        let s = Uuid::new_v4();
        g.finish(&r, Some(s), None, None).unwrap();
        g.finish(&r, Some(s), None, None).unwrap();
        assert!(g.finish(&r, Some(Uuid::new_v4()), None, None).is_err());
        assert_eq!(g.session_ids().len(), 1);
    }
    #[test]
    fn cancellation_waits_for_current_stage() {
        let mut g = group();
        let r = g.start("l0", epoch()).unwrap();
        g.cancel_requested = true;
        g.refresh();
        assert_eq!(g.state, "running");
        g.finish(&r, Some(Uuid::new_v4()), None, None).unwrap();
        assert_eq!(g.state, "cancelled");
        assert!(g.start("l1", epoch()).is_err());
    }
    #[test]
    fn restart_preserves_parent_and_marks_interrupted() {
        let mut g = group();
        let id = g.id;
        g.start("l0", epoch()).unwrap();
        let dir = std::env::temp_dir().join(format!("mobilee-group-test-{}", Uuid::new_v4()));
        save(&dir, &g).unwrap();
        let mut h: Group =
            serde_json::from_str(&std::fs::read_to_string(path(&dir, id)).unwrap()).unwrap();
        h.recover(Uuid::new_v4());
        assert_eq!(h.id, id);
        assert_eq!(h.state, "interrupted");
        assert!(h.stages[0].attempts[0].session_id.is_none());
        save(&dir, &h).unwrap();
        assert_eq!(load(&dir, id).unwrap().id, id);
        std::fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn foreign_session_membership_and_required_failure() {
        let mut a = group();
        let mut b = group();
        let r = a.start("l0", epoch()).unwrap();
        let rb = b.start("l0", epoch()).unwrap();
        let s = Uuid::new_v4();
        a.finish(&r, Some(s), None, Some("bad".into())).unwrap();
        b.finish(&rb, Some(Uuid::new_v4()), None, None).unwrap();
        assert!(!b.session_ids().contains(&s));
        assert!(a.start("l1", epoch()).is_err());
        assert_eq!(a.state, "failed");
    }

    #[tokio::test]
    async fn legacy_export_never_replays_device_history() {
        let root =
            std::env::temp_dir().join(format!("mobilee-legacy-no-device-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&root).unwrap();
        append_device_sessions_to_package_evidence(
            "NO_DEVICE_CONFIGURED",
            "org.example.fixture",
            &root,
            None,
        )
        .await
        .unwrap();
        let value: Value =
            serde_json::from_slice(&std::fs::read(root.join("session-index.json")).unwrap())
                .unwrap();
        assert_eq!(value["scope"], "legacy-parent-unknown");
        assert_eq!(value["includedSessions"], serde_json::json!([]));
        assert!(!root.join("sessions").exists());
        std::fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn duplicate_import_and_forged_parent_validation() {
        let mut g = group();
        let r = g.start("l0", epoch()).unwrap();
        g.finish(&r, Some(Uuid::new_v4()), None, None).unwrap();
        let root = std::env::temp_dir().join(format!("mobilee-group-import-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(
            root.join("capture-group.json"),
            serde_json::to_vec(&g).unwrap(),
        )
        .unwrap();
        let a = read_import(&root).unwrap().unwrap();
        let b = read_import(&root).unwrap().unwrap();
        assert_eq!(a.id, b.id);
        assert_eq!(a.session_ids(), b.session_ids());
        g.stages[0].attempts[0].relation.parent_id = Uuid::new_v4();
        std::fs::write(
            root.join("capture-group.json"),
            serde_json::to_vec(&g).unwrap(),
        )
        .unwrap();
        assert!(read_import(&root).is_err());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn production_archive_import_keeps_parent_child_and_honest_expanded_storage() {
        let root =
            std::env::temp_dir().join(format!("mobilee-parent-archive-test-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&root).unwrap();
        let mut g = group();
        let mut dump_relation = None;
        for key in ["l0", "l1", "dump", "linker"] {
            let r = g.start(key, epoch()).unwrap();
            let session = if key == "dump" {
                dump_relation = Some(r.clone());
                None
            } else {
                Some(Uuid::new_v4())
            };
            g.finish(&r, session, None, None).unwrap();
            if let Some(id) = session {
                let dir = root.join("sessions").join(id.to_string());
                std::fs::create_dir_all(&dir).unwrap();
                std::fs::write(
                    dir.join("session-report.json"),
                    serde_json::to_vec(&serde_json::json!({"session_id":id,"total_events":1}))
                        .unwrap(),
                )
                .unwrap();
            }
        }
        assert_eq!(g.state, "succeeded");
        let dr = dump_relation.unwrap();
        std::fs::write(
            root.join("capture-group.json"),
            serde_json::to_vec(&g).unwrap(),
        )
        .unwrap();
        std::fs::write(root.join("capture-relation.json"),serde_json::to_vec(&serde_json::json!({"package":g.package,"relation":{"parent_id":g.id,"stage_id":dr.stage_id,"attempt_id":dr.attempt_id,"attempt":dr.attempt,"stage_key":"dump"}})).unwrap()).unwrap();
        std::fs::write(
            root.join("dump-report.json"),
            serde_json::to_vec(
                &serde_json::json!({"package":g.package,"dump_id":Uuid::new_v4(),"artifacts":[]}),
            )
            .unwrap(),
        )
        .unwrap();
        std::fs::write(root.join("asset.bin"), b"full actual source bytes").unwrap();
        std::fs::hard_link(root.join("asset.bin"), root.join("alias.bin")).unwrap();
        let archive = root.with_extension("mee");
        write_kernsight_evidence_archive_v1(&root, &archive).unwrap();
        let a = import_kernsight_evidence_archive(archive.to_string_lossy().into_owned())
            .await
            .unwrap();
        let b = import_kernsight_evidence_archive(archive.to_string_lossy().into_owned())
            .await
            .unwrap();
        assert_eq!(
            a.session_report.as_ref().unwrap()["mobilee_capture_group"]["id"],
            g.id.to_string()
        );
        assert_eq!(
            a.session_report.as_ref().unwrap()["mobilee_capture_group"]["id"],
            b.session_report.as_ref().unwrap()["mobilee_capture_group"]["id"]
        );
        assert_eq!(
            a.session_report.as_ref().unwrap()["mobilee_capture_source_status"],
            "agent_relation_matched"
        );
        let child = *g.session_ids().iter().next().unwrap();
        let report = get_local_kernsight_child_report(a.root.clone(), g.id, child).unwrap();
        assert_eq!(report.session_id, child);
        assert!(get_local_kernsight_child_report(a.root.clone(), g.id, Uuid::new_v4()).is_err());
        if cfg!(unix) {
            assert_eq!(
                a.dump_report["local_storage_accounting"]["shared_inode_logical_bytes"],
                0
            );
        }
        assert_eq!(g.session_ids().len(), 3);
        std::fs::remove_dir_all(Path::new(&a.root).parent().unwrap()).unwrap();
        std::fs::remove_dir_all(Path::new(&b.root).parent().unwrap()).unwrap();
        std::fs::remove_file(archive).unwrap();
        std::fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn legacy_import_does_not_invent_group() {
        let dir = std::env::temp_dir();
        assert!(read_import(&dir).unwrap().is_none());
    }
    #[test]
    fn changed_process_does_not_merge_sessions() {
        let mut g = group();
        let r = g.start("l0", epoch()).unwrap();
        g.finish(
            &r,
            Some(Uuid::new_v4()),
            None,
            Some("process exited".into()),
        )
        .unwrap();
        let r2 = g.start("l0", epoch()).unwrap();
        g.finish(&r2, Some(Uuid::new_v4()), None, None).unwrap();
        assert_eq!(g.session_ids().len(), 2);
    }
}

pub fn selected(
    app: &tauri::AppHandle,
    id: Uuid,
    serial: &str,
    package: &str,
) -> Result<Group, String> {
    selected_at(&root(app)?, id, serial, package)
}
pub(super) fn selected_at(
    r: &Path,
    id: Uuid,
    serial: &str,
    package: &str,
) -> Result<Group, String> {
    let _guard = IO_LOCK.lock().map_err(|e| e.to_string())?;
    let g = load(r, id)?;
    if g.serial != serial || g.package != package {
        return Err("所选主会话设备/包不一致".into());
    }
    Ok(g)
}
pub(super) fn verify_session_relation(g: &Group, id: Uuid, note: &Value) -> Result<(), String> {
    if note["session_id"].as_str() != Some(id.to_string().as_str())
        || note["package"].as_str() != Some(g.package.as_str())
        || note["relation"]["parent_id"].as_str() != Some(g.id.to_string().as_str())
    {
        return Err("原始 session 关联不属于此 parent/package，未回放".into());
    }
    let relation = &note["relation"];
    let attempts = g
        .stages
        .iter()
        .flat_map(|s| s.attempts.iter())
        .filter(|a| a.session_id == Some(id))
        .collect::<Vec<_>>();
    let primary = attempts.iter().any(|a| {
        relation["stage_id"].as_str() == Some(a.relation.stage_id.to_string().as_str())
            && relation["attempt_id"].as_str() == Some(a.relation.attempt_id.to_string().as_str())
            && relation["attempt"].as_u64() == Some(a.relation.attempt as u64)
            && relation["stage_key"].as_str() == Some(a.relation.stage_key.as_str())
    });
    if !primary {
        return Err("原始 stage/attempt 与 parent 引用冲突，未回放".into());
    }
    if g.unified {
        let links = relation["stage_links"]
            .as_array()
            .ok_or("统一 session 缺阶段映射，未回放")?;
        if attempts.iter().any(|a| {
            !links
                .iter()
                .any(|link| link == &serde_json::to_value(&a.relation).unwrap())
        }) {
            return Err("统一 stage links 不完整，未回放".into());
        }
    }
    Ok(())
}
pub fn export_root(g: &Group) -> Result<String, String> {
    g.stages
        .iter()
        .find(|s| s.key == "dump")
        .and_then(|s| s.attempts.last())
        .filter(|a| a.state == "succeeded" || a.state == "partial" || a.state == "failed")
        .and_then(|a| a.remote_artifact_root.clone())
        .ok_or("主会话没有成功的 dump 产物；不会拉取同包其他轮次".into())
}

#[tauri::command]
pub fn get_local_kernsight_child_report(
    root: String,
    parent_id: Uuid,
    session_id: Uuid,
) -> Result<KernSightSessionReport, String> {
    let root = resolve_local_path(&root, "主会话证据目录")?;
    if std::fs::symlink_metadata(&root)
        .map_err(|e| e.to_string())?
        .file_type()
        .is_symlink()
    {
        return Err("根目录为符号链接，拒绝读取".into());
    }
    let g = read_import(&root)?.ok_or("旧数据无父 ID，不能猜测子会话")?;
    if g.id != parent_id || !g.session_ids().contains(&session_id) {
        return Err("子 session 不属于此主会话".into());
    }
    let path = root
        .join("sessions")
        .join(session_id.to_string())
        .join("session-report.json");
    let mut current = root.clone();
    for component in [
        "sessions",
        session_id.to_string().as_str(),
        "session-report.json",
    ] {
        current = current.join(component);
        if std::fs::symlink_metadata(&current)
            .map_err(|e| e.to_string())?
            .file_type()
            .is_symlink()
        {
            return Err("子证据含符号链接，拒绝读取".into());
        }
    }
    let mut report: Value = serde_json::from_str(&read_bounded_text(&path, 64 * 1024 * 1024)?)
        .map_err(|e| e.to_string())?;
    if report["session_id"].as_str() != Some(session_id.to_string().as_str()) {
        return Err("子报告原 session ID 不匹配".into());
    }
    let relation_path = path.with_file_name("capture-relation.json");
    if relation_path.is_file() {
        if std::fs::symlink_metadata(&relation_path)
            .map_err(|e| e.to_string())?
            .file_type()
            .is_symlink()
        {
            return Err("子关联含符号链接，拒绝读取".into());
        }
        let note: Value = serde_json::from_str(&read_bounded_text(&relation_path, 32768)?)
            .map_err(|e| e.to_string())?;
        verify_session_relation(&g, session_id, &note)?;
        report["mobilee_child_source_status"] = serde_json::json!("agent_relation_matched");
    } else {
        report["mobilee_child_source_status"] = serde_json::json!("unknown_missing_agent_relation");
    }
    report["mobilee_capture_group"] = serde_json::to_value(&g).map_err(|e| e.to_string())?;
    report["mobilee_capture_edges"] = serde_json::json!(g.evidence_edges());
    Ok(KernSightSessionReport {
        session_id,
        report_schema: "mobilee.kernsight-session-report/v1".into(),
        report,
    })
}

fn stage_rows(result: &KernSightCaptureResult) -> Vec<Value> {
    [result.stdout.as_str(), result.stderr.as_str()]
        .into_iter()
        .flat_map(str::lines)
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .filter(|v| v["schema"] == "kernsight.capture-stage/v1")
        .collect()
}
impl Group {
    fn start_unified(&mut self, owner: Uuid) -> Result<Vec<Relation>, String> {
        if let Some(b) = &self.budget {
            b.deadline()?.check()?;
        }
        if !self.unified
            || self.cancel_requested
            || self
                .stages
                .iter()
                .any(|s| s.attempts.last().is_some_and(|a| a.state == "running"))
        {
            return Err("统一阶段不允许启动/并发/已取消".into());
        }
        if self.stages[..3]
            .iter()
            .all(|s| s.attempts.last().is_some_and(|a| a.state == "succeeded"))
        {
            return Err("统一阶段已成功，无需重试".into());
        }
        if self.stages[..3]
            .iter()
            .map(|s| s.key.as_str())
            .collect::<Vec<_>>()
            != ["l0", "l1", "linker"]
        {
            return Err("统一计划阶段不匹配".into());
        }
        for stage in &self.stages[..3] {
            ensure_previous_shutdown(stage, self.budget.as_ref())?;
        }
        let mut out = vec![];
        for stage in &mut self.stages[..3] {
            if stage.attempts.len() >= 128 {
                return Err("attempt 上限达到，拒绝覆盖历史".into());
            }
            let r = Relation {
                parent_id: self.id,
                stage_id: stage.id,
                attempt_id: Uuid::new_v4(),
                attempt: stage.attempts.len() as u32 + 1,
                stage_key: stage.key.clone(),
            };
            stage.attempts.push(Attempt {
                relation: r.clone(),
                owner_epoch: owner,
                state: "running".into(),
                started_unix_ms: now_millis(),
                finished_unix_ms: None,
                session_id: None,
                error: None,
                diagnostic_tail: None,
                remote_artifact_root: None,
                process_instances: vec![],
                observation_error: None,
                omitted_process_instances: 0,
                stage_records: vec![],
                remote_lifecycle: None,
            });
            out.push(r);
        }
        self.refresh();
        self.validate()?;
        Ok(out)
    }
    fn finish_unified(
        &mut self,
        relations: &[Relation],
        result: Option<&KernSightCaptureResult>,
        error: Option<&str>,
    ) -> Result<(), String> {
        let rows = result.map(stage_rows).unwrap_or_default();
        let session = result.and_then(|r| r.session_id);
        let mut identity = None;
        for (index, r) in relations.iter().enumerate() {
            let selected = rows
                .iter()
                .filter(|row| {
                    row["index"].as_u64() == Some(index as u64)
                        && row["stage"].as_str() == Some(r.stage_key.as_str())
                        && row["session"].as_str() == session.map(|id| id.to_string()).as_deref()
                })
                .cloned()
                .collect::<Vec<_>>();
            let terminal = selected.get(1);
            let instance = terminal.and_then(|t| {
                Some((
                    t["pid"].as_u64().filter(|p| *p > 0)?,
                    t["process_start_ticks"]
                        .as_str()
                        .filter(|v| v.parse::<u64>().is_ok_and(|n| n > 0))?
                        .to_owned(),
                ))
            });
            let duration = self.stages[index].duration_seconds;
            let started = selected
                .first()
                .and_then(|t| t["recorded_unix_ms"].as_u64());
            let ended = terminal.and_then(|t| t["recorded_unix_ms"].as_u64());
            let ok = error.is_none()
                && result.is_some_and(|o| o.exit_code == Some(0))
                && session.is_some()
                && selected.len() == 2
                && selected[0]["state"] == "started"
                && terminal.is_some_and(|t| {
                    t["state"] == "window_elapsed"
                        && t["planned_seconds"].as_u64() == Some(duration)
                })
                && selected
                    .iter()
                    .all(|t| t["parent_relation"] == serde_json::to_value(r).unwrap())
                && started.is_some()
                && ended.is_some()
                && ended >= started
                && instance.is_some()
                && identity
                    .as_ref()
                    .is_none_or(|old| Some(old) == instance.as_ref());
            if identity.is_none() {
                identity = instance.clone();
            }
            let failure = (!ok).then(|| {
                error
                    .unwrap_or("统一阶段缺/冲突/失败或进程实例不一致；不降级重启")
                    .to_owned()
            });
            self.finish(r, session, None, failure)?;
            let attempt = self.stages[index].attempts.last_mut().unwrap();
            if let Some(t) = started {
                attempt.started_unix_ms = t;
            }
            if let Some(t) = ended {
                attempt.finished_unix_ms = Some(t);
            }
            if let Some((pid, ticks)) = instance {
                attempt.process_instances = vec![
                    serde_json::json!({"pid":pid,"process_start_ticks":ticks,"source":"agent-capture-stage"}),
                ];
            }
            attempt.stage_records = selected.into_iter().take(8).collect();
            attempt.observation_error =
                Some("阶段窗口结束不认证完整覆盖；perf tail/未触发以原阶段记录为准".into());
        }
        self.refresh();
        self.validate()
    }
}
#[tauri::command]
pub async fn run_kernsight_unified_group(
    app: tauri::AppHandle,
    parent_id: Uuid,
) -> Result<StageResult, String> {
    let root = root(&app)?;
    let (mut g, relations) = {
        let _guard = IO_LOCK.lock().map_err(|e| e.to_string())?;
        trash::ensure_not_trashed(&root, parent_id)?;
        let mut g = load(&root, parent_id)?;
        for entry in std::fs::read_dir(&root).map_err(|e| e.to_string())? {
            let p = entry.map_err(|e| e.to_string())?.path();
            if let Some(id) = p
                .file_stem()
                .and_then(|p| p.to_str())
                .and_then(|p| Uuid::parse_str(p).ok())
            {
                let other = load(&root, id)?;
                if other.id != g.id && other.serial == g.serial && other.state == "running" {
                    return Err("设备已有运行主会话".into());
                }
            }
        }
        g.budget
            .as_ref()
            .ok_or("旧父会话deadline未知，未启动")?
            .deadline()?
            .check()?;
        let relations = g.start_unified(epoch())?;
        save(&root, &g)?;
        (g, relations)
    };
    let deadline = g
        .budget
        .as_ref()
        .ok_or("旧父会话deadline未知")?
        .deadline()?;
    let run=deadline.run(async {
        let busy=run_device_root_script(&g.serial,r#"for p in $(pidof ksightd 2>/dev/null); do c=$(tr '\0' ' ' < /proc/$p/cmdline); case "$c" in *ksightd*\ capture*) echo capture_busy; exit 73;; esac; done"#).await?;
        if busy.code!=Some(0){return Err("设备已有采集或状态未知；未启动/重试".into());}
        let mut request:KernSightCaptureRequest=serde_json::from_value(g.base.clone()).map_err(|e|e.to_string())?;

        let(n,t)=reserve_attempt(&root,&mut g,relations[0].attempt_id.to_string(),"unified")?;request.output_budget_bytes=Some(n-65536);request.output_budget_ms=Some(t);
        request.serial=g.serial.clone();request.package=Some(g.package.clone());request.capture_relation=Some(relations[0].clone());request.capture_relations=Some(relations.clone());
        request.duration_seconds=g.stages[..3].iter().map(|s|s.duration_seconds).sum();request.launch_after_attach=true;
        request.inspect_tls=false;request.inspect_jni=false;request.inspect_linker=false;request.inspect_adapter=None;
        request.inspect_stages=Some(g.stages[..3].iter().map(|s|format!("{}:{}",s.key,s.duration_seconds)).collect::<Vec<_>>().join(","));
        start_kernsight_capture(request).await
    }).await;
    let (result, mut error) = match run {
        Ok(r) => (Some(r), None),
        Err(e) => (None, Some(e)),
    };
    let remote_lifecycle =
        if result.is_some() || error.as_deref().is_some_and(session_deadline::is_stop) {
            Some(
                observe_remote_lifecycle(
                    &g.serial,
                    &relations[0],
                    error.as_deref(),
                    runtime_paths_from_group(Some(&g))?.as_ref(),
                )
                .await,
            )
        } else {
            None
        };
    if remote_lifecycle
        .as_ref()
        .is_some_and(|n| !remote_terminal_confirmed(n))
        && error.is_none()
    {
        error =
            Some("remote_terminal_unconfirmed：统一producer远端终态未确认，保留原session".into());
    }
    if remote_lifecycle
        .as_ref()
        .is_some_and(|n| n["collection_status"] == "partial")
        && error.is_none()
    {
        error = Some("remote_collection_partial：统一producer返回partial，原session保留".into());
    }
    {
        let _guard = IO_LOCK.lock().map_err(|e| e.to_string())?;
        g = load(&root, parent_id)?;
        if let Err(stop) = deadline.check() {
            if error.is_none() {
                error = Some(stop);
            } else if !error.as_deref().is_some_and(session_deadline::is_stop) {
                error = Some(format!("{}; {stop}", error.as_deref().unwrap()));
            }
        }
        g.finish_unified(&relations, result.as_ref(), error.as_deref())?;
        mark_stopped_budget(&mut g, error.as_deref());
        for attempt in g.stages[..3]
            .iter_mut()
            .flat_map(|s| s.attempts.iter_mut())
            .filter(|a| relations.contains(&a.relation))
        {
            attempt.remote_lifecycle = remote_lifecycle.clone();
        }
        if result.is_none()
            && error.as_deref().is_some_and(|e| {
                e.contains("代码一键范围门禁未通过") || e.contains("代码采集范围能力未知")
            })
        {
            if let Some(b) = g.budget.as_mut() {
                b.release_unstarted(&relations[0].attempt_id.to_string())?;
            }
        }
        if let (Some(b), Some(result)) = (g.budget.as_mut(), result.as_ref()) {
            if let Some(note) = result
                .stderr
                .lines()
                .filter_map(|l| serde_json::from_str::<Value>(l).ok())
                .find(|v| v["schema"] == "kernsight.output-budget/v1")
            {
                if let Err(e) = b.settle(&relations[0].attempt_id.to_string(), &note) {
                    for a in g.stages[..3]
                        .iter_mut()
                        .flat_map(|s| s.attempts.iter_mut())
                        .filter(|a| relations.contains(&a.relation))
                    {
                        a.state = "failed".into();
                        a.error = Some(format!("预算收据不可信: {e}"));
                    }
                    g.refresh();
                }
                if note["partial"] == true {
                    for a in g.stages[..3]
                        .iter_mut()
                        .flat_map(|s| s.attempts.iter_mut())
                        .filter(|a| relations.contains(&a.relation))
                    {
                        a.state = "partial".into();
                        a.error = Some("统一采集预算耗尽，保留原 session，覆盖 partial".into());
                    }
                    g.refresh();
                }
            }
        }
        for attempt in g.stages[..3]
            .iter_mut()
            .flat_map(|s| s.attempts.iter_mut())
            .filter(|a| relations.contains(&a.relation))
        {
            retain_capture_diagnostic(attempt, result.as_ref());
        }
        save(&root, &g)?;
    }
    let error = error.or_else(|| {
        (g.state != "running"
            && g.stages[..3]
                .iter()
                .any(|s| s.attempts.last().is_none_or(|a| a.state != "succeeded")))
        .then(|| "统一阶段未确认全部成功，未执行 dump".into())
    });
    Ok(StageResult {
        group: g,
        result,
        error,
        continue_after_partial: false,
    })
}

#[cfg(test)]
mod unified_tests {
    use super::*;
    fn group() -> Group {
        Group {
            schema: SCHEMA.into(),
            id: Uuid::new_v4(),
            serial: "synthetic".into(),
            package: "org.example.fixture".into(),
            created_unix_ms: 1,
            cancel_requested: false,
            budget: None,
            unified: true,
            state: "planned".into(),
            base: serde_json::json!({}),
            stages: ["l0", "l1", "linker", "dump"]
                .map(|key| Stage {
                    id: Uuid::new_v4(),
                    key: key.into(),
                    mode: "fixture".into(),
                    duration_seconds: 2,
                    launch_after_attach: key == "l0",
                    required: true,
                    attempts: vec![],
                })
                .to_vec(),
        }
    }
    fn result(relations: &[Relation], session: Uuid) -> KernSightCaptureResult {
        let rows=relations.iter().enumerate().flat_map(|(i,r)|["started","window_elapsed"].into_iter().enumerate().map(move |(j,state)|serde_json::json!({"schema":"kernsight.capture-stage/v1","session":session,"index":i,"stage":r.stage_key,"planned_seconds":2,"state":state,"pid":42,"process_start_ticks":"949","recorded_unix_ms":1000+i as u64*2000+j as u64*1900,"parent_relation":r}))).collect::<Vec<_>>();
        KernSightCaptureResult {
            session_id: Some(session),
            started_unix_ms: 1000,
            finished_unix_ms: 7000,
            command_preview: "synthetic".into(),
            stdout: rows
                .into_iter()
                .map(|r| r.to_string())
                .collect::<Vec<_>>()
                .join("\n"),
            stderr: "".into(),
            exit_code: Some(0),
            hide_debug: false,
        }
    }
    #[test]
    fn unified_production_receipt_uses_three_stage_ids_one_entity() {
        let mut g = group();
        let r = g.start_unified(epoch()).unwrap();
        let id = Uuid::new_v4();
        let output = result(&r, id);
        g.finish_unified(&r, Some(&output), None).unwrap();
        assert_eq!(g.session_ids(), BTreeSet::from([id]));
        assert_eq!(
            g.stages[..3]
                .iter()
                .filter(|s| s.attempts.last().unwrap().state == "succeeded")
                .count(),
            3
        );
        assert_eq!(g.state, "planned");
        assert_eq!(g.stages[1].attempts[0].started_unix_ms, 3000);
        assert_eq!(g.stages[2].attempts[0].finished_unix_ms, Some(6900));
        assert_ne!(r[0].stage_id, r[1].stage_id);
    }
    #[tokio::test]
    async fn deadline_parent_child_terminal_and_next_stage_refusal() {
        let mut g = group();
        let mut budget =
            session_budget::Contract::new(session_budget::Limits::default(), now_millis()).unwrap();
        budget.deadline_token = Some(session_deadline::Deadline::register(Duration::from_millis(
            35,
        )));
        let d = budget.deadline().unwrap();
        g.budget = Some(budget);
        let r = g.start_unified(epoch()).unwrap();
        g.budget
            .as_mut()
            .unwrap()
            .reserve(r[0].attempt_id.to_string(), "unified", now_millis())
            .unwrap();
        let error = d
            .run(std::future::pending::<Result<(), String>>())
            .await
            .unwrap_err();
        g.finish_unified(&r, None, Some(&error)).unwrap();
        mark_stopped_budget(&mut g, Some(&error));
        assert_eq!(g.state, "partial");
        for s in &g.stages[..3] {
            let a = s.attempts.last().unwrap();
            assert_eq!(a.state, "partial");
            assert!(a.finished_unix_ms.is_some());
        }
        assert_eq!(g.budget.as_ref().unwrap().reservations[0].status, "partial");
        assert!(g.budget.as_ref().unwrap().reservations[0]
            .charged_bytes
            .is_none());
        assert!(g.start("dump", epoch()).is_err());
        assert!(g.start_unified(epoch()).is_err());
        assert_eq!(g.stages[0].attempts.len(), 1);
    }
    #[test]
    fn deadline_cancelled_child_is_not_failed_or_successful() {
        let mut g = group();
        let r = g.start_unified(epoch()).unwrap();
        g.cancel_requested = true;
        g.finish_unified(
            &r,
            None,
            Some("parent_cancelled; owned_host_children_reaped=true; remote_cleanup=unconfirmed"),
        )
        .unwrap();
        assert_eq!(g.state, "cancelled");
        assert!(g.stages[..3]
            .iter()
            .all(|s| s.attempts[0].state == "cancelled"));
    }
    #[test]
    fn lifecycle_retry_requires_confirmed_previous_controller_and_keeps_parent_clock() {
        let mut g = group();
        g.budget = Some(
            session_budget::Contract::new(session_budget::Limits::default(), now_millis()).unwrap(),
        );
        let token = g.budget.as_ref().unwrap().deadline_token;
        let r = g.start_unified(epoch()).unwrap();
        g.budget
            .as_mut()
            .unwrap()
            .reserve(r[0].attempt_id.to_string(), "unified", now_millis())
            .unwrap();
        g.finish_unified(&r, None, Some("remote_terminal_unconfirmed"))
            .unwrap();
        assert!(g.start_unified(epoch()).is_err());
        assert_eq!(g.stages[0].attempts.len(), 1);
        let primary = &r[0];
        let note = serde_json::json!({"schema":"kernsight.capture-lifecycle/v1","relation":{"parent_id":primary.parent_id,"stage_id":primary.stage_id,"attempt_id":primary.attempt_id,"attempt":primary.attempt,"stage_key":primary.stage_key},"token":Uuid::new_v4(),"stop_request_recorded":false,"stop_acknowledged":false,"stop_reason":null,"collection_returned":true,"collection_status":"partial","agent_exited_confirmed":true,"cleanup":"producer_scope_returned","target_pause":"forbidden"});
        for stage in &mut g.stages[..3] {
            stage.attempts[0].remote_lifecycle = Some(note.clone());
        }
        g.validate().unwrap();
        let retry = g.start_unified(epoch()).unwrap();
        assert_eq!(retry[0].attempt, 2);
        assert_ne!(retry[0].attempt_id, r[0].attempt_id);
        assert_eq!(g.budget.as_ref().unwrap().deadline_token, token);
        assert_eq!(
            g.stages[0].attempts[0].remote_lifecycle.as_ref().unwrap(),
            &note
        );
    }
    #[test]
    fn failed_identity_retry_never_erases_previous_attempts() {
        let mut g = group();
        let r = g.start_unified(epoch()).unwrap();
        let mut output = result(&r, Uuid::new_v4());
        output.stdout = output.stdout.replace("949", "0");
        g.finish_unified(&r, Some(&output), None).unwrap();
        assert_eq!(g.state, "failed");
        let r2 = g.start_unified(epoch()).unwrap();
        assert_eq!(r2[0].attempt, 2);
        let output = result(&r2, Uuid::new_v4());
        g.finish_unified(&r2, Some(&output), None).unwrap();
        assert_eq!(g.session_ids().len(), 2);
        assert_eq!(g.stages[0].attempts[0].state, "failed");
    }
    #[test]
    fn forged_relation_and_missing_boundary_never_green() {
        let mut g = group();
        let r = g.start_unified(epoch()).unwrap();
        let mut output = result(&r, Uuid::new_v4());
        output.stdout = output
            .stdout
            .replace(&r[1].stage_id.to_string(), &Uuid::new_v4().to_string());
        g.finish_unified(&r, Some(&output), None).unwrap();
        assert_eq!(g.stages[1].attempts[0].state, "failed");
        assert_ne!(g.state, "succeeded");
        let mut g = group();
        let r = g.start_unified(epoch()).unwrap();
        let mut output = result(&r, Uuid::new_v4());
        output.stdout = output.stdout.lines().take(5).collect::<Vec<_>>().join("\n");
        g.finish_unified(&r, Some(&output), None).unwrap();
        assert_eq!(g.stages[2].attempts[0].state, "failed");
    }
    #[test]
    fn unified_cancel_and_restart_preserve_ids() {
        let mut g = group();
        let r = g.start_unified(epoch()).unwrap();
        g.cancel_requested = true;
        let output = result(&r, Uuid::new_v4());
        g.finish_unified(&r, Some(&output), None).unwrap();
        assert_eq!(g.state, "cancelled");
        assert!(g.start("dump", epoch()).is_err());
        let mut g = group();
        let id = g.id;
        g.start_unified(epoch()).unwrap();
        g.recover(Uuid::new_v4());
        assert_eq!(g.id, id);
        assert_eq!(g.state, "interrupted");
        assert_eq!(
            g.stages[..3]
                .iter()
                .filter(|s| s.attempts[0].state == "interrupted")
                .count(),
            3
        );
    }
}

#[cfg(test)]
mod source_relation_tests {
    use super::*;
    #[test]
    fn original_scope_proof_rejects_foreign_parent_before_event_replay() {
        let id = Uuid::new_v4();
        let stage = Uuid::new_v4();
        let attempt = Uuid::new_v4();
        let parent = Uuid::new_v4();
        let relation = Relation {
            parent_id: parent,
            stage_id: stage,
            attempt_id: attempt,
            attempt: 1,
            stage_key: "l0".into(),
        };
        let mut g = Group {
            schema: SCHEMA.into(),
            id: parent,
            serial: "synthetic".into(),
            package: "org.example.fixture".into(),
            created_unix_ms: 1,
            cancel_requested: false,
            budget: None,
            unified: false,
            state: "planned".into(),
            base: serde_json::json!({}),
            stages: vec![Stage {
                id: stage,
                key: "l0".into(),
                mode: "observe".into(),
                duration_seconds: 2,
                launch_after_attach: true,
                required: true,
                attempts: vec![Attempt {
                    relation: relation.clone(),
                    owner_epoch: epoch(),
                    state: "succeeded".into(),
                    started_unix_ms: 1,
                    finished_unix_ms: Some(2),
                    session_id: Some(id),
                    error: None,
                    diagnostic_tail: None,
                    remote_artifact_root: None,
                    process_instances: vec![],
                    observation_error: None,
                    omitted_process_instances: 0,
                    stage_records: vec![],
                    remote_lifecycle: None,
                }],
            }],
        };
        let note = serde_json::json!({"package":g.package,"session_id":id,"relation":{"parent_id":parent,"stage_id":stage,"attempt_id":attempt,"attempt":1,"stage_key":"l0"}});
        verify_session_relation(&g, id, &note).unwrap();
        g.id = Uuid::new_v4();
        assert!(verify_session_relation(&g, id, &note).is_err());
        g.id = parent;
        assert!(verify_session_relation(&g, Uuid::new_v4(), &note).is_err());
        let mut bad = note;
        bad["package"] = serde_json::json!("org.example.other");
        assert!(verify_session_relation(&g, id, &bad).is_err());
    }
}

pub(super) fn reserve_export(
    app: &tauri::AppHandle,
    g: &mut Group,
    output: &Path,
) -> Result<Option<(u64, u64, u64, u64)>, String> {
    reserve_export_at(&root(app)?, g, output)
}
pub(super) fn reserve_export_at(
    r: &Path,
    g: &mut Group,
    output: &Path,
) -> Result<Option<(u64, u64, u64, u64)>, String> {
    let _lock = IO_LOCK.lock().map_err(|e| e.to_string())?;
    *g = load(r, g.id)?;
    let Some(b) = g.budget.as_mut() else {
        return Ok(None);
    };
    let key = format!("export:{}", output.display());
    let (transfer, ms) = b.reserve(format!("{key}:transfer"), "transfer", now_millis())?;
    let (archive, _) = b.reserve(format!("{key}:archive"), "archive", now_millis())?;
    let (import, _) = b.reserve(format!("{key}:import"), "import", now_millis())?;
    save(&r, g)?;
    Ok(Some((transfer, archive, import, ms)))
}
pub(super) fn settle_export(
    app: &tauri::AppHandle,
    g: &mut Group,
    output: &Path,
    kind: &str,
    note: &Value,
) -> Result<(), String> {
    settle_export_at(&root(app)?, g, output, kind, note)
}
pub(super) fn settle_export_at(
    r: &Path,
    g: &mut Group,
    output: &Path,
    kind: &str,
    note: &Value,
) -> Result<(), String> {
    let _lock = IO_LOCK.lock().map_err(|e| e.to_string())?;
    *g = load(r, g.id)?;
    if let Some(b) = g.budget.as_mut() {
        b.settle(&format!("export:{}:{kind}", output.display()), note)?;
    }
    g.refresh();
    save(&r, g)
}

pub(super) fn release_unstarted_export_at(
    r: &Path,
    g: &mut Group,
    output: &Path,
    kinds: &[&str],
) -> Result<(), String> {
    let _lock = IO_LOCK.lock().map_err(|e| e.to_string())?;
    *g = load(r, g.id)?;
    if let Some(b) = g.budget.as_mut() {
        for kind in kinds {
            b.release_unstarted(&format!("export:{}:{kind}", output.display()))?;
        }
    }
    g.refresh();
    save(r, g)
}

fn reserve_attempt(
    root: &Path,
    g: &mut Group,
    id: String,
    kind: &str,
) -> Result<(u64, u64), String> {
    let _lock = IO_LOCK.lock().map_err(|e| e.to_string())?;
    *g = load(root, g.id)?;
    if g.cancel_requested {
        return Err("父会话已取消，未启动".into());
    }
    let b = g
        .budget
        .as_mut()
        .ok_or("旧会话预算未知；仅保留只读证据，新采集请新建父会话")?;
    let quota = b.reserve(id, kind, now_millis())?;
    save(root, g)?;
    Ok(quota)
}

fn mark_stopped_budget(g: &mut Group, error: Option<&str>) {
    if error.is_some_and(session_deadline::is_stop) {
        if let Some(b) = g.budget.as_mut() {
            for r in &mut b.reservations {
                if r.status == "reserved" {
                    r.status = "partial".into();
                }
            }
        }
        g.refresh();
    }
}

fn validate_remote_lifecycle(note: &Value, r: &Relation) -> Result<(), String> {
    let rel = &note["relation"];
    if note["schema"] != "kernsight.capture-lifecycle/v1"
        || rel["parent_id"].as_str() != Some(r.parent_id.to_string().as_str())
        || rel["stage_id"].as_str() != Some(r.stage_id.to_string().as_str())
        || rel["attempt_id"].as_str() != Some(r.attempt_id.to_string().as_str())
        || rel["attempt"].as_u64() != Some(r.attempt as u64)
        || rel["stage_key"].as_str() != Some(r.stage_key.as_str())
        || note["token"]
            .as_str()
            .and_then(|v| Uuid::parse_str(v).ok())
            .is_none_or(|v| v.is_nil())
        || note["target_pause"] != "forbidden"
        || !note["collection_returned"].is_boolean()
        || !note["stop_request_recorded"].is_boolean()
        || !note["stop_acknowledged"].is_boolean()
        || !(note["agent_exited_confirmed"].is_boolean()
            || note["agent_exited_confirmed"].is_null())
    {
        return Err("远端生命周期身份/状态合同未知或冲突".into());
    }
    let returned = note["collection_returned"] == true;
    if (returned
        && (!matches!(
            note["collection_status"].as_str(),
            Some("completed" | "partial")
        ) || note["cleanup"] != "producer_scope_returned"))
        || (!returned && (!note["collection_status"].is_null() || note["cleanup"] != "unconfirmed"))
        || (note["stop_acknowledged"] == true
            && note["stop_reason"]
                .as_str()
                .is_none_or(|s| s.is_empty() || s.len() > 128))
    {
        return Err("远端生命周期返回/清理事实缺失，不能升级为成功".into());
    }
    Ok(())
}
fn remote_terminal_confirmed(note: &Value) -> bool {
    note["schema"] == "kernsight.capture-lifecycle/v1"
        && matches!(
            note["collection_status"].as_str(),
            Some("completed" | "partial")
        )
        && note["collection_returned"] == true
        && note["agent_exited_confirmed"] == true
        && note["cleanup"] == "producer_scope_returned"
        && note["target_pause"] == "forbidden"
}
async fn observe_remote_lifecycle(
    serial: &str,
    r: &Relation,
    error: Option<&str>,
    paths: Option<&runtime_paths::RuntimePaths>,
) -> Value {
    let owned_serial = serial.to_owned();
    let paths = paths.cloned();
    observe_remote_lifecycle_with(r, error, Duration::from_secs(2), move |script| {
        let serial = owned_serial.clone();
        let paths = paths.clone();
        async move {
            let script = runtime_paths::route(paths.as_ref(), &script)?;
            run_device_root_script(&serial, &script).await
        }
    })
    .await
}
async fn observe_remote_lifecycle_with<F, Fut>(
    r: &Relation,
    error: Option<&str>,
    allowance: Duration,
    mut rpc: F,
) -> Value
where
    F: FnMut(String) -> Fut,
    Fut: std::future::Future<Output = Result<crate::RawOutput, String>>,
{
    let stop = error.is_some_and(session_deadline::is_stop);
    let cause = if error.is_some_and(|e| e.contains("parent_cancelled")) {
        "parent_cancelled"
    } else {
        "parent_deadline_exhausted"
    };
    let control=format!("{KSIGHT_AGENT} capture-control --parent-session {} --stage-id {} --attempt-id {} --stage-attempt {} --stage-key {}",r.parent_id,r.stage_id,r.attempt_id,r.attempt,r.stage_key);
    // A distinct, bounded recovery allowance; it never permits collection or target signals.
    let recovery = session_deadline::Deadline::new(allowance);
    let mut latest: Option<Value> = None;
    let result = recovery
        .run(async {
            let mut command = if stop {
                format!("{control} --action stop --reason {cause}")
            } else {
                format!("{control} --action status")
            };
            let mut token = None;
            loop {
                let response = rpc(command.clone()).await?;
                if response.code != Some(0) || response.stdout.len() > 16384 {
                    return Err("远端control RPC未确认".into());
                }
                let mut note: Value =
                    serde_json::from_str(&response.stdout).map_err(|_| "远端control JSON未知")?;
                validate_remote_lifecycle(&note, r)?;
                if token.as_ref().is_some_and(|v| v != &note["token"]) {
                    return Err("远端owner token发生变化".into());
                }
                token = Some(note["token"].clone());
                note["stop_command_attempted"] = serde_json::json!(stop);
                note["observed_at_unix_ms"] = serde_json::json!(now_millis());
                latest = Some(note.clone());
                if note["agent_exited_confirmed"] == true || recovery.remaining_ms()? < 100 {
                    return Ok(note);
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
                command = format!("{control} --action status");
            }
        })
        .await;
    result.unwrap_or_else(|e| {
        if let Some(mut note)=latest { note["recovery_error"]=serde_json::json!(e);note["freshness"]=serde_json::json!("last_confirmed_observation");note }
        else {serde_json::json!({"schema":"mobilee.remote-lifecycle-unconfirmed/v1","controller_relation":r,"stop_command_attempted":stop,"stop_request_recorded":null,"stop_acknowledged":null,"collection_returned":null,"agent_exited_confirmed":null,"cleanup":"unconfirmed","error":e})}
    })
}

#[cfg(test)]
mod remote_lifecycle_tests {
    use super::*;
    fn relation() -> Relation {
        Relation {
            parent_id: Uuid::new_v4(),
            stage_id: Uuid::new_v4(),
            attempt_id: Uuid::new_v4(),
            attempt: 1,
            stage_key: "l0".into(),
        }
    }
    fn note(r: &Relation, token: Uuid, returned: bool, exited: bool) -> Value {
        serde_json::json!({"schema":"kernsight.capture-lifecycle/v1","relation":{"parent_id":r.parent_id,"stage_id":r.stage_id,"attempt_id":r.attempt_id,"attempt":r.attempt,"stage_key":r.stage_key},"token":token,"target_pause":"forbidden","stop_request_recorded":true,"stop_acknowledged":returned,"collection_returned":returned,"collection_status":if returned{Some("partial")}else{None},"stop_reason":if returned{Some("parent_cancelled")}else{None},"agent_exited_confirmed":exited,"cleanup":if returned{"producer_scope_returned"}else{"unconfirmed"}})
    }
    fn response(note: Value) -> crate::RawOutput {
        crate::RawOutput {
            stdout: note.to_string(),
            stderr: String::new(),
            code: Some(0),
        }
    }
    #[tokio::test]
    async fn lifecycle_remote_stop_ack_return_exit_require_distinct_receipts() {
        let r = relation();
        let token = Uuid::new_v4();
        let mut calls = 0;
        let result = observe_remote_lifecycle_with(
            &r,
            Some("parent_cancelled"),
            Duration::from_millis(350),
            |cmd| {
                calls += 1;
                assert!(cmd.contains(&format!("--attempt-id {}", r.attempt_id)));
                assert!(!cmd.contains("kill"));
                if calls == 1 {
                    assert!(cmd.contains("--action stop --reason parent_cancelled"));
                } else {
                    assert!(cmd.contains("--action status"));
                }
                let n = note(&r, token, calls >= 2, calls >= 3);
                async move { Ok(response(n)) }
            },
        )
        .await;
        assert_eq!(calls, 3);
        assert!(remote_terminal_confirmed(&result));
        assert_eq!(result["stop_request_recorded"], true);
        assert_eq!(result["stop_acknowledged"], true);
    }
    #[tokio::test]
    async fn lifecycle_remote_disconnect_preserves_previously_recorded_request() {
        let r = relation();
        let token = Uuid::new_v4();
        let mut calls = 0;
        let result = observe_remote_lifecycle_with(
            &r,
            Some("parent_deadline_exhausted"),
            Duration::from_millis(350),
            |_| {
                calls += 1;
                let n = note(&r, token, false, false);
                let first = calls == 1;
                async move {
                    if first {
                        Ok(response(n))
                    } else {
                        Err("connection disconnected".into())
                    }
                }
            },
        )
        .await;
        assert_eq!(calls, 2);
        assert_eq!(result["stop_request_recorded"], true);
        assert_eq!(result["stop_acknowledged"], false);
        assert_eq!(result["freshness"], "last_confirmed_observation");
        assert!(!remote_terminal_confirmed(&result));
    }
    #[tokio::test]
    async fn lifecycle_remote_timeout_and_old_schema_remain_unknown() {
        let r = relation();
        let start = Instant::now();
        let result = observe_remote_lifecycle_with(
            &r,
            Some("parent_cancelled"),
            Duration::from_millis(25),
            |_| std::future::pending::<Result<crate::RawOutput, String>>(),
        )
        .await;
        assert!(start.elapsed() < Duration::from_secs(1));
        assert_eq!(result["stop_command_attempted"], true);
        assert!(result["stop_request_recorded"].is_null());
        assert!(result["agent_exited_confirmed"].is_null());
        assert!(!remote_terminal_confirmed(&result));
        let old = observe_remote_lifecycle_with(&r, None, Duration::from_millis(25), |_| async {
            Ok(response(serde_json::json!({})))
        })
        .await;
        assert!(!remote_terminal_confirmed(&old));
    }
    #[tokio::test]
    async fn lifecycle_remote_agent_exit_alone_and_foreign_attempt_cannot_be_success() {
        let r = relation();
        let token = Uuid::new_v4();
        let result = observe_remote_lifecycle_with(&r, None, Duration::from_millis(25), |_| {
            let n = note(&r, token, false, true);
            async move { Ok(response(n)) }
        })
        .await;
        assert_eq!(result["agent_exited_confirmed"], true);
        assert_eq!(result["cleanup"], "unconfirmed");
        assert!(!remote_terminal_confirmed(&result));
        let other = relation();
        assert!(validate_remote_lifecycle(&note(&other, token, true, true), &r).is_err());
    }
}

// Unknown cleanup must not be retried into a concurrent producer. No-reservation/not-started
// attempts are read-only preflight refusals and can retry within the original parent clock.
fn ensure_previous_shutdown(
    stage: &Stage,
    budget: Option<&session_budget::Contract>,
) -> Result<(), String> {
    let (Some(previous), Some(budget)) = (stage.attempts.last(), budget) else {
        return Ok(());
    };
    if let Some(note) = &previous.remote_lifecycle {
        if remote_terminal_confirmed(note) {
            return Ok(());
        }
    }
    if budget
        .reservations
        .iter()
        .find(|r| r.id == previous.relation.attempt_id.to_string())
        .is_some_and(|r| r.status != "not_started")
    {
        return Err("前attempt远端终态/清理未确认，不能重试并发；保留旧证据与主时限".into());
    }
    Ok(())
}

#[cfg(test)]
mod approved_device_acceptance;
