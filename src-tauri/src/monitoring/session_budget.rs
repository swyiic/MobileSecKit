//! Opt-in output-write budget. Scope is this invocation's registered roots, not system disk.
use serde::Serialize;
use std::{
    collections::BTreeMap,
    fs::{File, OpenOptions},
    io::{self, Write},
    path::{Component, Path, PathBuf},
    sync::{Mutex, OnceLock},
    time::{Duration, Instant},
};
#[derive(Clone, Debug, Serialize)]
pub struct Receipt {
    pub schema: &'static str,
    pub limit_bytes: u64,
    pub admitted_write_bytes: u64,
    pub rejected_writes: u64,
    pub partial: bool,
    pub reason: Option<String>,
}
struct State {
    roots: Vec<PathBuf>,
    deadline: Instant,
    receipt: Receipt,
}
static STATES: OnceLock<Mutex<BTreeMap<u64, State>>> = OnceLock::new();
static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
fn states() -> &'static Mutex<BTreeMap<u64, State>> {
    STATES.get_or_init(|| Mutex::new(BTreeMap::new()))
}
pub struct Guard(u64);
impl Guard {
    pub fn install(roots: Vec<PathBuf>, bytes: u64, max_ms: u64) -> io::Result<Self> {
        if roots.is_empty()
            || max_ms == 0
            || max_ms > 3600000
            || bytes > 16 * 1024 * 1024 * 1024
            || roots.iter().any(|p| {
                !p.is_absolute() || p.components().any(|c| matches!(c, Component::ParentDir))
            })
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid output budget scope",
            ));
        }
        let mut all = states()
            .lock()
            .map_err(|_| io::Error::other("budget lock"))?;
        if all.values().any(|s| {
            roots.iter().any(|r| {
                s.roots
                    .iter()
                    .any(|old| r.starts_with(old) || old.starts_with(r))
            })
        }) {
            return Err(io::Error::other("overlapping budget scope"));
        }
        let id = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        all.insert(
            id,
            State {
                roots,
                deadline: Instant::now()
                    + Duration::from_millis(
                        super::session_deadline::remaining_ms(max_ms).map_err(io::Error::other)?,
                    ),
                receipt: Receipt {
                    schema: "mobilee.output-budget/v1",
                    limit_bytes: bytes,
                    admitted_write_bytes: 0,
                    rejected_writes: 0,
                    partial: false,
                    reason: None,
                },
            },
        );
        Ok(Self(id))
    }
    /// Acceptance checkpoint writes keep their existing counter; a later phase
    /// may only shorten this guard's original deadline, never renew it.
    #[cfg(test)]
    pub(super) fn constrain_time(&self, max_ms: u64) -> io::Result<()> {
        if max_ms == 0 || max_ms > 3600000 {
            return Err(io::Error::other("invalid phase time cap"));
        }
        let remaining = super::session_deadline::remaining_ms(max_ms).map_err(io::Error::other)?;
        let bound = Instant::now() + Duration::from_millis(remaining);
        let mut all = states()
            .lock()
            .map_err(|_| io::Error::other("budget lock"))?;
        let state = all
            .get_mut(&self.0)
            .ok_or_else(|| io::Error::other("missing budget guard"))?;
        state.deadline = state.deadline.min(bound);
        Ok(())
    }
    pub fn receipt(&self) -> Receipt {
        states()
            .lock()
            .unwrap()
            .get(&self.0)
            .unwrap()
            .receipt
            .clone()
    }
}
impl Drop for Guard {
    fn drop(&mut self) {
        if let Ok(mut s) = states().lock() {
            s.remove(&self.0);
        }
    }
}
pub fn charge(path: &Path, n: u64) -> io::Result<()> {
    if let Err(e) = super::session_deadline::check() {
        record_failure(path, &e);
        return Err(io::Error::other(e));
    }
    let mut all = states()
        .lock()
        .map_err(|_| io::Error::other("budget lock"))?;
    for s in all
        .values_mut()
        .filter(|s| s.roots.iter().any(|r| path.starts_with(r)))
    {
        let unsafe_path = path.components().any(|c| matches!(c, Component::ParentDir))
            || path
                .ancestors()
                .filter(|p| s.roots.iter().any(|r| p.starts_with(r)))
                .any(|p| std::fs::symlink_metadata(p).is_ok_and(|m| m.file_type().is_symlink()));
        let reason = if unsafe_path {
            Some("output_path_escape")
        } else if Instant::now() >= s.deadline {
            Some("time_budget_exhausted")
        } else if n > s
            .receipt
            .limit_bytes
            .saturating_sub(s.receipt.admitted_write_bytes)
        {
            Some("output_budget_exhausted")
        } else {
            None
        };
        if let Some(reason) = reason {
            s.receipt.partial = true;
            s.receipt.reason = Some(reason.into());
            s.receipt.rejected_writes = s.receipt.rejected_writes.saturating_add(1);
            return Err(io::Error::other(reason));
        }
        s.receipt.admitted_write_bytes += n;
    }
    Ok(())
}
pub fn remaining_ms(path: &Path, fallback: u64) -> io::Result<u64> {
    charge(path, 0)?;
    let now = Instant::now();
    let local = states()
        .lock()
        .map_err(|_| io::Error::other("budget lock"))?
        .values()
        .filter(|s| s.roots.iter().any(|r| path.starts_with(r)))
        .map(|s| s.deadline.saturating_duration_since(now).as_millis() as u64)
        .min()
        .unwrap_or(fallback);
    let ms =
        super::session_deadline::remaining_ms(local.min(fallback)).map_err(io::Error::other)?;
    if ms == 0 {
        return Err(io::Error::other("time_budget_exhausted"));
    }
    Ok(ms)
}

pub fn record_failure(path: &Path, reason: &str) {
    if let Ok(mut all) = states().lock() {
        for s in all
            .values_mut()
            .filter(|s| s.roots.iter().any(|r| path.starts_with(r)))
        {
            s.receipt.partial = true;
            if s.receipt.reason.is_none() {
                s.receipt.reason = Some(reason.into());
            }
        }
    }
}
pub fn write(path: impl AsRef<Path>, bytes: impl AsRef<[u8]>) -> io::Result<()> {
    let path = path.as_ref();
    let b = bytes.as_ref();
    charge(path, b.len() as u64)?;
    let result = std::fs::write(path, b);
    if result.is_err() {
        record_failure(path, "output_io_failed");
    }
    result?;
    charge(path, 0)
}
/// Finite per-document limit, shared with the evidence importer. Parent quota still wins.
pub const MAX_EVIDENCE_JSON_BYTES: u64 = 64 * 1024 * 1024;

pub struct ReplayEnvelope {
    bytes: u64,
    events: usize,
}
impl Default for ReplayEnvelope {
    fn default() -> Self {
        Self {
            bytes: 2,
            events: 0,
        }
    }
}
impl ReplayEnvelope {
    pub fn admit(&mut self, batch_bytes: u64, count: usize) -> io::Result<()> {
        let additional = batch_bytes.saturating_sub(2) + u64::from(self.events > 0 && count > 0);
        let bytes = self
            .bytes
            .checked_add(additional)
            .ok_or_else(|| io::Error::other("replay byte overflow"))?;
        let events = self
            .events
            .checked_add(count)
            .ok_or_else(|| io::Error::other("replay count overflow"))?;
        if bytes > MAX_EVIDENCE_JSON_BYTES || events > 100_000 {
            return Err(io::Error::other(
                "event replay exceeds 64MiB/100000 event bound; incomplete, not truncated success",
            ));
        }
        self.bytes = bytes;
        self.events = events;
        Ok(())
    }
}

struct JsonMeasure<'a> {
    path: &'a Path,
    bytes: u64,
    next_check: u64,
}
impl Write for JsonMeasure<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.bytes >= self.next_check {
            charge(self.path, 0)?;
            self.next_check = self.bytes.saturating_add(65536);
        }
        self.bytes = self
            .bytes
            .checked_add(bytes.len() as u64)
            .ok_or_else(|| io::Error::other("JSON size overflow"))?;
        if self.bytes > MAX_EVIDENCE_JSON_BYTES {
            record_failure(self.path, "evidence_json_limit_exceeded");
            return Err(io::Error::other(
                "evidence JSON exceeds 64MiB document bound",
            ));
        }
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        charge(self.path, 0)
    }
}

pub fn measure_json(path: &Path, value: &impl Serialize) -> io::Result<u64> {
    charge(path, 0)?;
    let mut measure = JsonMeasure {
        path,
        bytes: 0,
        next_check: 65536,
    };
    serde_json::to_writer(&mut measure, value).map_err(io::Error::other)?;
    charge(path, 0)?;
    Ok(measure.bytes)
}

/// Encode without allocating a second complete JSON buffer. Admit the complete
/// document before creating a file; publish only complete, synced bytes and never
/// replace retained evidence. Failed temporary output stays charged to the parent.
pub fn write_json(path: impl AsRef<Path>, value: &impl Serialize) -> io::Result<u64> {
    let path = path.as_ref();
    charge(path, 0)?;
    if path.exists() {
        return Err(io::Error::other("retained JSON target already exists"));
    }
    let required = measure_json(path, value)?;
    let remaining = states()
        .lock()
        .map_err(|_| io::Error::other("budget lock"))?
        .values()
        .filter(|s| s.roots.iter().any(|r| path.starts_with(r)))
        .map(|s| {
            s.receipt
                .limit_bytes
                .saturating_sub(s.receipt.admitted_write_bytes)
        })
        .min()
        .unwrap_or(MAX_EVIDENCE_JSON_BYTES);
    if required > remaining {
        record_failure(path, "output_budget_exhausted");
        return Err(io::Error::other(format!(
            "output_budget_exhausted: JSON requires {required} bytes, remaining {remaining} bytes"
        )));
    }
    let temporary = path.with_extension(format!("json.pending-{}", uuid::Uuid::new_v4()));
    let result = (|| {
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)?;
        let file = BudgetFile {
            file,
            path: temporary.clone(),
        };
        let mut writer = io::BufWriter::with_capacity(65536, file);
        serde_json::to_writer(&mut writer, value).map_err(io::Error::other)?;
        writer.flush()?;
        writer.get_ref().sync_all()?;
        charge(path, 0)?;
        std::fs::hard_link(&temporary, path)?;
        Ok(required)
    })();
    if result.is_err() {
        record_failure(path, "evidence_json_write_failed");
    }
    let _ = std::fs::remove_file(&temporary);
    result
}

/// Preserve small original provenance notes byte-for-byte without overwriting.
pub fn write_new_bytes(path: impl AsRef<Path>, bytes: &[u8]) -> io::Result<()> {
    let path = path.as_ref();
    if bytes.len() > 32768 {
        return Err(io::Error::other("provenance note exceeds 32KiB"));
    }
    charge(path, 0)?;
    if path.exists() {
        return Err(io::Error::other(
            "retained provenance target already exists",
        ));
    }
    let temporary = path.with_extension(format!("pending-{}", uuid::Uuid::new_v4()));
    let result = (|| {
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)?;
        let mut file = BudgetFile {
            file,
            path: temporary.clone(),
        };
        file.write_all(bytes)?;
        file.sync_all()?;
        charge(path, 0)?;
        std::fs::hard_link(&temporary, path)?;
        Ok(())
    })();
    if result.is_err() {
        record_failure(path, "provenance_write_failed");
    }
    let _ = std::fs::remove_file(temporary);
    result
}

pub struct BudgetFile {
    file: File,
    path: PathBuf,
}
impl BudgetFile {
    pub fn create(path: impl AsRef<Path>) -> io::Result<Self> {
        let p = path.as_ref();
        charge(p, 0)?;
        Ok(Self {
            file: File::create(p).inspect_err(|_| record_failure(p, "output_open_failed"))?,
            path: p.to_owned(),
        })
    }
    pub fn sync_all(&self) -> io::Result<()> {
        charge(&self.path, 0)?;
        self.file.sync_all()?;
        charge(&self.path, 0)
    }
}
impl Write for BudgetFile {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        charge(&self.path, b.len() as u64)?;
        let result = self.file.write(b);
        if result.is_err() {
            record_failure(&self.path, "output_io_failed");
        }
        let count = result?;
        charge(&self.path, 0)?;
        Ok(count)
    }
    fn flush(&mut self) -> io::Result<()> {
        charge(&self.path, 0)?;
        self.file.flush()?;
        charge(&self.path, 0)
    }
}
pub fn copy(src: impl AsRef<Path>, dest: impl AsRef<Path>) -> io::Result<u64> {
    if !states()
        .lock()
        .map_err(|_| io::Error::other("budget lock"))?
        .values()
        .any(|s| s.roots.iter().any(|r| dest.as_ref().starts_with(r)))
    {
        return std::fs::copy(src, dest);
    }
    let mut src = File::open(src)?;
    let mut dest = BudgetFile::create(dest)?;
    io::copy(&mut src, &mut dest)
}
pub fn write_open(path: &Path, options: &OpenOptions, bytes: &[u8]) -> io::Result<()> {
    charge(path, bytes.len() as u64)?;
    let mut f = options.open(path)?;
    f.write_all(bytes)
}

#[derive(Clone, Debug, Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Limits {
    pub total_bytes: u64,
    pub max_seconds: u64,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            total_bytes: 2 * 1024 * 1024 * 1024,
            max_seconds: 300,
        }
    }
}
#[derive(Clone, Debug, Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Reservation {
    pub id: String,
    pub kind: String,
    pub reserved_bytes: u64,
    pub charged_bytes: Option<u64>,
    pub status: String,
}
#[derive(Clone, Debug, Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Contract {
    pub schema: String,
    pub limits: Limits,
    pub deadline_unix_ms: u64,
    /// Runtime token is deliberately not recoverable into a fresh deadline after restart.
    #[serde(default)]
    pub deadline_token: Option<uuid::Uuid>,
    pub reservations: Vec<Reservation>,
    #[serde(default = "manager_reserve")]
    pub manager_reserve_bytes: u64,
    /// Only newly created automatic parents preallocate later work. Legacy receipts stay unchanged.
    #[serde(default)]
    pub planned_allocation: bool,
    /// New parents only. Missing on retained contracts preserves the prior export plan.
    #[serde(default)]
    pub coordinated_exports: bool,
    /// Missing on retained parents: never infer or renew a time plan.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub time_plan: Option<TimePlan>,
}
#[derive(Clone, Debug, Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TimePhase {
    pub kind: String,
    pub cap_ms: u64,
    /// Parent remaining-time coordinate, not a new clock/token.
    pub stop_at_parent_remaining_ms: Option<u64>,
    pub completed: bool,
}
#[derive(Clone, Debug, Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TimePlan {
    pub schema: String,
    pub final_reserve_ms: u64,
    pub phases: Vec<TimePhase>,
}
fn manager_reserve() -> u64 {
    2 * 1024 * 1024
}
impl Contract {
    pub fn deadline(&self) -> Result<super::session_deadline::Deadline, String> {
        super::session_deadline::Deadline::lookup(self.deadline_token)
    }
    pub fn validate(&self) -> Result<(), String> {
        if self.schema != "mobilee.session-output-budget/v1"
            || self.manager_reserve_bytes != manager_reserve()
            || self.limits.total_bytes < 4 * 1024 * 1024
            || self.limits.total_bytes > 16 * 1024 * 1024 * 1024
            || !(30..=3600).contains(&self.limits.max_seconds)
            || self.reservations.len() > 1024
        {
            return Err("预算合同未知/无效".into());
        }
        if let Some(plan) = &self.time_plan {
            plan.validate(self.limits.max_seconds * 1000)?;
            if !self.planned_allocation {
                return Err("时间预留缺少新父字节计划".into());
            }
        }
        if self.coordinated_exports && (!self.planned_allocation || self.time_plan.is_none()) {
            return Err("协调导出额度缺少新父计划".into());
        }
        if self.planned_allocation {
            for (kind, expected) in [
                ("transfer", self.limits.total_bytes / 4),
                (
                    "archive",
                    if self.coordinated_exports {
                        self.limits.total_bytes / 4
                    } else {
                        self.limits.total_bytes / 8
                    },
                ),
                (
                    "import",
                    if self.coordinated_exports {
                        self.limits.total_bytes / 4
                    } else {
                        self.limits.total_bytes * 3 / 16
                    },
                ),
            ] {
                let slots = self
                    .reservations
                    .iter()
                    .filter(|r| r.kind == kind)
                    .collect::<Vec<_>>();
                if slots.len() != 1 || slots[0].reserved_bytes != expected {
                    return Err("事前导出预留缺失或额度改变".into());
                }
            }
        }
        let mut ids = std::collections::BTreeSet::new();
        let mut sum = self.manager_reserve_bytes;
        for r in &self.reservations {
            if r.id.len() > 4096
                || !ids.insert(&r.id)
                || r.charged_bytes.is_some_and(|n| n > r.reserved_bytes)
            {
                return Err("预算操作身份/计量冲突".into());
            }
            sum = sum
                .checked_add(r.charged_bytes.unwrap_or(r.reserved_bytes))
                .ok_or("预算总数溢出")?;
        }
        if sum > self.limits.total_bytes {
            return Err("预算总额度超过合同".into());
        }
        Ok(())
    }
    pub fn release_unstarted(&mut self, id: &str) -> Result<(), String> {
        let Some(r) = self.reservations.iter_mut().find(|r| r.id == id) else {
            return Ok(());
        };
        if r.status == "not_started" {
            return Ok(());
        }
        if r.charged_bytes.is_some() {
            return Err("已执行/未知终态，不能退回额度".into());
        }
        let kind = r.kind.clone();
        if self.time_plan.as_ref().is_some_and(|plan| {
            plan.phases
                .iter()
                .any(|p| p.kind == kind && p.stop_at_parent_remaining_ms.is_some())
        }) {
            return Err("已启动时间阶段不能作为未启动释放".into());
        }
        r.charged_bytes = Some(0);
        r.status = "not_started".into();
        if let Some(plan) = self.time_plan.as_mut() {
            if let Some(phase) = plan.phases.iter_mut().find(|p| p.kind == kind) {
                phase.completed = true;
            }
        }
        Ok(())
    }

    pub fn new(limits: Limits, now: u64) -> Result<Self, String> {
        if !(4 * 1024 * 1024..=16 * 1024 * 1024 * 1024).contains(&limits.total_bytes)
            || !(30..=3600).contains(&limits.max_seconds)
        {
            return Err("会话预算须4MiB–16GiB、30–3600秒".into());
        }
        let deadline = now
            .checked_add(limits.max_seconds * 1000)
            .ok_or("期限溢出")?;
        Ok(Self {
            schema: "mobilee.session-output-budget/v1".into(),
            limits: limits.clone(),
            deadline_unix_ms: deadline,
            deadline_token: Some(super::session_deadline::Deadline::register(
                Duration::from_secs(limits.max_seconds),
            )),
            reservations: vec![],
            manager_reserve_bytes: manager_reserve(),
            planned_allocation: false,
            coordinated_exports: false,
            time_plan: None,
        })
    }
    /// Reserve later work before any producer starts, without extending the parent.
    pub fn new_planned(limits: Limits, now: u64, separate_linker: bool) -> Result<Self, String> {
        let mut contract = Self::new(limits, now)?;
        let total = contract.limits.total_bytes;
        let mut holds = vec![
            ("transfer", total / 4),
            ("archive", total / 8),
            ("import", total * 3 / 16),
        ];
        if separate_linker {
            holds.push(("linker", total / 16));
        }
        let held = holds.iter().try_fold(0u64, |sum, (kind, bytes)| {
            let minimum = if *kind == "linker" { 131072 } else { 65536 };
            if *bytes < minimum {
                return Err("新父会话后续阶段/终态预留不可行".to_owned());
            }
            sum.checked_add(*bytes)
                .ok_or_else(|| "计划额度溢出".to_owned())
        })?;
        // Separate l0/l1/dump or unified/dump need at least one producer block
        // and its terminal reserve each. Reject infeasible plans before capture.
        let active_minimum = if separate_linker {
            4 * 131072
        } else {
            2 * 131072
        };
        if held
            .checked_add(active_minimum)
            .is_none_or(|n| n > contract.remaining())
        {
            return Err("新父会话预算不足以同时保留采集、后续导出和终态；未启动".into());
        }
        for (kind, bytes) in holds {
            contract.reservations.push(Reservation {
                id: format!("planned:{kind}"),
                kind: kind.into(),
                reserved_bytes: bytes,
                charged_bytes: None,
                status: "planned".into(),
            });
        }
        contract.planned_allocation = true;
        contract.validate()?;
        Ok(contract)
    }
    pub fn remaining(&self) -> u64 {
        self.limits
            .total_bytes
            .saturating_sub(self.manager_reserve_bytes)
            .saturating_sub(self.reservations.iter().fold(0u64, |sum, r| {
                sum.saturating_add(r.charged_bytes.unwrap_or(r.reserved_bytes))
            }))
    }
    pub fn reserve(&mut self, id: String, kind: &str, now: u64) -> Result<(u64, u64), String> {
        let monotonic_ms = self.deadline()?.remaining_ms()?;
        if now >= self.deadline_unix_ms {
            return Err("parent_deadline_exhausted".into());
        }
        if self
            .reservations
            .iter()
            .any(|r| r.id == id && r.kind != kind)
        {
            return Err("预算操作身份冲突".into());
        }
        let allowance = if self.time_plan.is_some() {
            if matches!(kind, "transfer" | "archive" | "import") {
                self.collection_remaining_ms(now)?
            } else {
                self.begin_time_phase(kind, now)?
            }
        } else {
            self.deadline_unix_ms.saturating_sub(now).min(monotonic_ms)
        };
        if let Some(r) = self.reservations.iter().find(|r| r.id == id) {
            if r.kind != kind {
                return Err("预算操作身份冲突".into());
            }
            return Ok((r.reserved_bytes, allowance));
        }
        if self.planned_allocation {
            if let Some(slot) = self
                .reservations
                .iter_mut()
                .find(|r| r.kind == kind && r.status == "planned")
            {
                slot.id = id;
                slot.status = "reserved".into();
                return Ok((slot.reserved_bytes, allowance));
            }
            if matches!(kind, "transfer" | "archive" | "import" | "linker") {
                return Err("事前预留已使用；不重复增加后续额度".into());
            }
        }
        let quota = match kind {
            "dump" if self.coordinated_exports => {
                let export = self.limits.total_bytes / 4;
                self.remaining().min(super::planned_transfer_payload_limit(
                    export, export, export,
                ))
            }
            "dump" if self.planned_allocation => self.remaining(),
            "l0" | "l1" | "linker" | "unified" | "dump" => self.remaining() / 2,
            "transfer" => self.limits.total_bytes / 4,
            "archive" => self.limits.total_bytes / 8,
            "import" => self.limits.total_bytes * 3 / 16,
            _ => self.limits.total_bytes / 16,
        }
        .min(self.remaining());
        let minimum = if matches!(kind, "l0" | "l1" | "linker" | "unified" | "dump") {
            131072
        } else {
            65536
        };
        if quota < minimum {
            return Err("父会话输出额度耗尽；终态另有已预留64KiB，不启动新阶段".into());
        }
        self.reservations.push(Reservation {
            id,
            kind: kind.into(),
            reserved_bytes: quota,
            charged_bytes: None,
            status: "reserved".into(),
        });
        Ok((quota, allowance))
    }
    pub fn settle(&mut self, id: &str, receipt: &serde_json::Value) -> Result<(), String> {
        let r = self
            .reservations
            .iter_mut()
            .find(|r| r.id == id)
            .ok_or("没有预算预留")?;
        let n = receipt["admitted_write_bytes"]
            .as_u64()
            .ok_or("缺实际写入计量")?
            .checked_add(65536)
            .ok_or("终态计量溢出")?;
        if n > r.reserved_bytes {
            return Err("实际写入超过预留，拒绝完整成功".into());
        }
        if r.charged_bytes.is_some_and(|old| old != n) {
            return Err("预算终态冲突，未重复计量".into());
        }
        let kind = r.kind.clone();
        r.charged_bytes = Some(n);
        r.status = if receipt["partial"].as_bool() == Some(true) {
            "partial"
        } else {
            "admitted_plus_terminal_reserve"
        }
        .into();
        if let Some(plan) = self.time_plan.as_mut() {
            if let Some(phase) = plan.phases.iter_mut().find(|p| p.kind == kind) {
                phase.completed = true;
            }
        }
        Ok(())
    }
}
#[cfg(test)]
mod contract_tests {
    use super::*;
    #[test]
    fn capture_reservation_uses_remaining_budget_and_returns_unused_quota() {
        let mut b = Contract::new(
            Limits {
                total_bytes: 67108864,
                max_seconds: 60,
            },
            1,
        )
        .unwrap();
        let (quota, _) = b.reserve("l0".into(), "l0", 2).unwrap();
        assert_eq!(quota, 31 * 1024 * 1024);
        assert_eq!(quota, b.reserve("l0".into(), "l0", 2).unwrap().0);
        b.settle(
            "l0",
            &serde_json::json!({"admitted_write_bytes":4117281,"partial":true}),
        )
        .unwrap();
        let remaining = b.remaining();
        assert_eq!(remaining, 67108864 - 2097152 - 4117281 - 65536);
        assert_eq!(b.reserve("l1".into(), "l1", 2).unwrap().0, remaining / 2);
        b.validate().unwrap();
        assert!(b
            .settle(
                "l1",
                &serde_json::json!({"admitted_write_bytes":67108864,"partial":true})
            )
            .is_err());
        b.settle(
            "l1",
            &serde_json::json!({"admitted_write_bytes":1000000,"partial":false}),
        )
        .unwrap();
        let remaining = b.remaining();
        let snapshot = b.reserve("dump".into(), "dump", 2).unwrap().0;
        assert_eq!(snapshot, remaining / 2);
        assert!(snapshot > 16 * 1024 * 1024 + 65536);
        b.validate().unwrap();
        assert!(b.reserve("late".into(), "linker", 60001).is_err());
    }
    #[test]
    fn recorded_partial_dump_leaves_linker_bytes_and_time_inside_same_parent_limit() {
        let mut b = Contract::new(
            Limits {
                total_bytes: 67108864,
                max_seconds: 60,
            },
            1,
        )
        .unwrap();
        assert_eq!(b.reserve("l0".into(), "l0", 1).unwrap().0, 32505856);
        b.settle(
            "l0",
            &serde_json::json!({"admitted_write_bytes":113353,"partial":false}),
        )
        .unwrap();
        assert_eq!(b.reserve("l1".into(), "l1", 9349).unwrap().0, 32416411);
        b.settle(
            "l1",
            &serde_json::json!({"admitted_write_bytes":65985,"partial":false}),
        )
        .unwrap();
        assert_eq!(b.reserve("dump".into(), "dump", 26907).unwrap().0, 32350651);
        b.settle(
            "dump",
            &serde_json::json!({"admitted_write_bytes":32237930,"partial":true}),
        )
        .unwrap();
        assert_eq!(b.remaining(), 32397836);
        let (quota, ms) = b.reserve("linker".into(), "linker", 33200).unwrap();
        assert_eq!(quota, 16198918);
        assert_eq!(ms, 26801);
        assert!(ms >= 5000);
        b.validate().unwrap();
        assert_eq!(b.reservations[2].status, "partial");
        assert!(b.reserve("late".into(), "linker", 60001).is_err());
    }
    #[test]
    fn retries_zero_and_parent_isolation() {
        let mut a = Contract::new(
            Limits {
                total_bytes: 4194304,
                max_seconds: 30,
            },
            0,
        )
        .unwrap();
        let mut b = a.clone();
        let x = a.reserve("attempt-a".into(), "l0", 1).unwrap();
        assert_eq!(x, a.reserve("attempt-a".into(), "l0", 1).unwrap());
        assert_eq!(a.reservations.len(), 1);
        a.settle(
            "attempt-a",
            &serde_json::json!({"admitted_write_bytes":0,"partial":true}),
        )
        .unwrap();
        a.settle(
            "attempt-a",
            &serde_json::json!({"admitted_write_bytes":0,"partial":true}),
        )
        .unwrap();
        assert_eq!(a.remaining(), 2097152 - 65536);
        assert_eq!(b.remaining(), 2097152);
        assert!(b.reserve("late".into(), "dump", 30000).is_err());
    }
    #[test]
    fn legacy_absence_is_unknown() {
        let g: serde_json::Value = serde_json::json!({"package":"x"});
        assert!(g.get("budget").is_none());
    }
    #[test]
    fn streamed_copy_and_archive_phase_hard_stops() {
        let root = std::env::temp_dir().join(format!("me-budget-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&root).unwrap();
        let g = Guard::install(vec![root.clone()], 3, 1000).unwrap();
        write(root.join("original"), b"abc").unwrap();
        assert!(write(root.join("archive.part"), b"x").is_err());
        assert_eq!(std::fs::read(root.join("original")).unwrap(), b"abc");
        assert!(g.receipt().partial);
        drop(g);
        std::fs::remove_dir_all(root).unwrap();
    }
}

impl std::io::Seek for BudgetFile {
    fn seek(&mut self, p: std::io::SeekFrom) -> io::Result<u64> {
        charge(&self.path, 0)?;
        let pos = std::io::Seek::seek(&mut self.file, p)?;
        charge(&self.path, 0)?;
        Ok(pos)
    }
}

pub async fn stream_verified<R: tokio::io::AsyncRead + Unpin>(
    mut reader: R,
    path: &Path,
    expected: u64,
    hash: &str,
) -> Result<(), String> {
    use sha2::{Digest, Sha256};
    use tokio::io::AsyncReadExt;
    if path.exists() {
        return Err("传输目标已存在，拒绝覆盖原始证据".into());
    }
    if let Some(p) = path.parent() {
        std::fs::create_dir_all(p).map_err(|e| e.to_string())?;
    }
    let temp = path.with_extension(format!("partial-{}", uuid::Uuid::new_v4()));
    let mut f = BudgetFile::create(&temp).map_err(|e| e.to_string())?;
    let mut count = 0u64;
    let mut h = Sha256::new();
    let mut b = [0; 65536];
    loop {
        let n = reader
            .read(&mut b)
            .await
            .map_err(|e| format!("读取失败，保留 {}: {e}", temp.display()))?;
        if n == 0 {
            break;
        }
        if n as u64 > expected.saturating_sub(count) {
            return Err(format!(
                "源增长/声明范围错误，保留 partial {}",
                temp.display()
            ));
        }
        f.write_all(&b[..n])
            .map_err(|e| format!("传输预算/落盘失败，保留 partial {}: {e}", temp.display()))?;
        count += n as u64;
        h.update(&b[..n]);
    }
    if count != expected || format!("{:x}", h.finalize()) != hash {
        return Err(format!("短读/hash不一致，保留 partial {}", temp.display()));
    }
    f.sync_all().map_err(|e| e.to_string())?;
    drop(f);
    std::fs::rename(temp, path).map_err(|e| e.to_string())
}
#[cfg(test)]
mod stream_tests {
    use super::*;
    use sha2::{Digest, Sha256};
    #[tokio::test]
    async fn production_stream_budget_short_read_failure_and_reuse() {
        let root = std::env::temp_dir().join(format!("budget-stream-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&root).unwrap();
        let hash = format!("{:x}", Sha256::digest(b"abcdef"));
        let g = Guard::install(vec![root.clone()], 3, 1000).unwrap();
        assert!(stream_verified(&b"abcdef"[..], &root.join("apk"), 6, &hash)
            .await
            .is_err());
        assert!(g.receipt().partial);
        assert!(!root.join("apk").exists());
        drop(g);
        let g = Guard::install(vec![root.clone()], 64, 1000).unwrap();
        assert!(stream_verified(&b"abc"[..], &root.join("short"), 6, &hash)
            .await
            .is_err());
        stream_verified(&b"abcdef"[..], &root.join("good"), 6, &hash)
            .await
            .unwrap();
        assert!(
            stream_verified(&b"abcdef"[..], &root.join("good"), 6, &hash)
                .await
                .is_err()
        );
        assert_eq!(std::fs::read(root.join("good")).unwrap(), b"abcdef");
        drop(g);
        std::fs::remove_dir_all(root).unwrap();
    }
}

#[cfg(test)]
mod cancellation_tests {
    use super::*;
    #[test]
    fn cancel_before_launch_and_retry_never_double_charge() {
        let mut b = Contract::new(Limits::default(), 1).unwrap();
        let initial = b.remaining();
        b.reserve("attempt".into(), "l0", 2).unwrap();
        b.release_unstarted("attempt").unwrap();
        b.release_unstarted("attempt").unwrap();
        assert_eq!(b.remaining(), initial);
        b.reserve("next".into(), "l0", 2).unwrap();
        assert_eq!(b.reservations.len(), 2);
        b.validate().unwrap();
        let mut invalid = b.clone();
        invalid.reservations.push(invalid.reservations[1].clone());
        assert!(invalid.validate().is_err());
    }
}

#[cfg(test)]
mod deadline_tests {
    use super::super::session_deadline::Deadline;
    use super::*;
    #[tokio::test]
    async fn deadline_stream_wait_preserves_prefix_and_refuses_late_write() {
        use tokio::io::AsyncWriteExt;
        let root = std::env::temp_dir().join(format!("deadline-prefix-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&root).unwrap();
        let d = Deadline::new(Duration::from_millis(50));
        let (read, mut send) = tokio::io::duplex(16);
        send.write_all(b"prefix").await.unwrap(); // Keep sender alive: reader waits for more bytes.
        let e = d
            .run(async {
                let _guard = Guard::install(vec![root.clone()], 64, 1000).unwrap();
                stream_verified(read, &root.join("original"), 16, &"0".repeat(64)).await
            })
            .await
            .unwrap_err();
        assert!(e.contains("parent_deadline_exhausted"));
        let paths = std::fs::read_dir(&root)
            .unwrap()
            .map(|p| p.unwrap().path())
            .collect::<Vec<_>>();
        assert_eq!(paths.len(), 1);
        assert_eq!(std::fs::read(&paths[0]).unwrap(), b"prefix");
        assert!(!root.join("original").exists());
        let retry = d
            .run(async { write(root.join("late"), b"bad").map_err(|e| e.to_string()) })
            .await;
        assert!(retry.is_err());
        assert!(!root.join("late").exists());
        drop(send);
        std::fs::remove_dir_all(root).unwrap();
    }
    #[tokio::test]
    async fn deadline_write_guard_and_reservations_do_not_reset_on_retry() {
        let mut b = Contract::new(Limits::default(), 0).unwrap();
        b.deadline_token = Some(Deadline::register(Duration::from_millis(40)));
        let d = b.deadline().unwrap();
        let (a, ms) = b.reserve("same".into(), "l0", 1).unwrap();
        assert!(a > 0 && ms <= 40);
        let root = std::env::temp_dir().join(format!("deadline-write-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&root).unwrap();
        let e = d
            .run(async {
                let guard = Guard::install(vec![root.clone()], 64, 1000).unwrap();
                write(root.join("original"), b"retained").unwrap();
                tokio::time::sleep(Duration::from_millis(10)).await;
                let left = b.reserve("same".into(), "l0", 0).unwrap().1;
                assert!(left < ms);
                // Waiting in a phase transition cannot grant a new deadline.
                tokio::time::sleep(Duration::from_secs(1)).await;
                write(root.join("late"), b"bad").unwrap();
                drop(guard);
                Ok(())
            })
            .await
            .unwrap_err();
        assert!(e.contains("parent_deadline_exhausted"));
        assert_eq!(std::fs::read(root.join("original")).unwrap(), b"retained");
        assert!(!root.join("late").exists());
        assert!(b.reserve("same".into(), "l0", 0).is_err());
        assert!(b.reserve("new".into(), "dump", 0).is_err());
        std::fs::remove_dir_all(root).unwrap();
    }
}

#[cfg(test)]
mod retained_json_tests {
    use super::*;
    fn root() -> PathBuf {
        let p = std::env::temp_dir().join(format!("me-retained-json-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&p).unwrap();
        p
    }
    #[test]
    fn raw_events_over_twelve_mib_preserved_with_explicit_finite_budget() {
        let root = root();
        let value = serde_json::json!({"events":[{"payload":"x".repeat(13 * 1024 * 1024)}],"execution_complete":false});
        let path = root.join("events.json");
        let expected = measure_json(&path, &value).unwrap();
        let guard = Guard::install(vec![root.clone()], expected, 30000).unwrap();
        assert_eq!(write_json(&path, &value).unwrap(), expected);
        assert_eq!(
            serde_json::from_reader::<_, serde_json::Value>(File::open(&path).unwrap()).unwrap(),
            value
        );
        assert_eq!(guard.receipt().admitted_write_bytes, expected);
        assert!(!guard.receipt().partial);
        drop(guard);
        std::fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn insufficient_quota_reports_exact_required_bytes_and_publishes_nothing() {
        let root = root();
        let value = vec!["x".repeat(13 * 1024 * 1024)];
        let path = root.join("events.json");
        let required = measure_json(&path, &value).unwrap();
        let guard = Guard::install(vec![root.clone()], 12 * 1024 * 1024, 30000).unwrap();
        let error = write_json(&path, &value).unwrap_err().to_string();
        assert!(error.contains(&format!("requires {required} bytes")));
        assert!(!path.exists());
        assert_eq!(guard.receipt().admitted_write_bytes, 0);
        assert!(guard.receipt().partial);
        assert_eq!(
            guard.receipt().reason.as_deref(),
            Some("output_budget_exhausted")
        );
        drop(guard);
        std::fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn retained_target_is_never_overwritten() {
        let root = root();
        let path = root.join("events.json");
        std::fs::write(&path, b"original").unwrap();
        assert!(write_json(&path, &vec![1, 2]).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"original");
        std::fs::remove_dir_all(root).unwrap();
    }
}

#[cfg(test)]
mod offline_retained_acceptance {
    use super::*;
    #[tokio::test]
    #[ignore = "requires explicitly selected existing local retained evidence; never accesses a device"]
    async fn imports_existing_failed_parent_without_inventing_raw_events() {
        let source = PathBuf::from(
            std::env::var_os("ME_OFFLINE_RETAINED_ROOT").expect("explicit existing local source"),
        );
        let group: super::super::capture_groups::Group =
            serde_json::from_reader(File::open(source.join("capture-group.json")).unwrap())
                .unwrap();
        group.validate().unwrap();
        assert_eq!(group.state, "failed");
        let bundle = super::super::import_kernsight_evidence_directory(
            source.to_string_lossy().into_owned(),
        )
        .await
        .unwrap();
        let report = bundle.session_report.unwrap();
        assert_eq!(report["mobilee_capture_group"]["state"], "failed");
        assert_ne!(report["execution_complete"], true);
        let mut copied_reports = 0;
        let root =
            std::env::temp_dir().join(format!("me-offline-retained-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&root).unwrap();
        let guard = Guard::install(vec![root.clone()], 12 * 1024 * 1024, 30000).unwrap();
        for entry in std::fs::read_dir(source.join("sessions")).unwrap() {
            let entry = entry.unwrap();
            let relation: serde_json::Value = serde_json::from_reader(
                File::open(entry.path().join("capture-relation.json")).unwrap(),
            )
            .unwrap();
            let id = uuid::Uuid::parse_str(&entry.file_name().to_string_lossy()).unwrap();
            super::super::capture_groups::verify_session_relation(&group, id, &relation).unwrap();
            let value: serde_json::Value = serde_json::from_reader(
                File::open(entry.path().join("session-report.json")).unwrap(),
            )
            .unwrap();
            let destination = root.join(format!("{id}.json"));
            write_json(&destination, &value).unwrap();
            let copied: serde_json::Value =
                serde_json::from_reader(File::open(destination).unwrap()).unwrap();
            assert_eq!(copied, value);
            // Missing raw events remain missing. A summary is not a replacement.
            assert!(!entry.path().join("events.json").exists());
            copied_reports += 1;
        }
        assert!(copied_reports > 0);
        assert!(!guard.receipt().partial);
        println!(
            "offline_failed_parent={} preserved_reports={} raw_events_missing=true complete=false",
            group.id, copied_reports
        );
        drop(guard);
        std::fs::remove_dir_all(root).unwrap();
    }
}

#[cfg(test)]
mod replay_envelope_tests {
    use super::*;
    #[test]
    fn batch_delimiters_empty_batches_and_exact_byte_boundary() {
        let mut envelope = ReplayEnvelope::default();
        envelope.admit(2, 0).unwrap();
        envelope.admit(MAX_EVIDENCE_JSON_BYTES - 3, 1).unwrap();
        envelope.admit(4, 1).unwrap();
        assert_eq!(envelope.bytes, MAX_EVIDENCE_JSON_BYTES);
        envelope.admit(2, 0).unwrap();
        assert!(envelope.admit(4, 1).is_err());
    }
    #[test]
    fn event_count_limit_is_cumulative_and_failure_does_not_admit_batch() {
        let mut envelope = ReplayEnvelope::default();
        envelope.admit(2, 50_000).unwrap();
        envelope.admit(2, 50_000).unwrap();
        assert!(envelope.admit(2, 1).is_err());
        assert_eq!(envelope.events, 100_000);
    }
    #[test]
    fn replay_time_uses_scoped_guard_and_rejects_expired_deadline() {
        let root = std::env::temp_dir().join(format!("me-replay-time-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&root).unwrap();
        let guard = Guard::install(vec![root.clone()], 1024, 20).unwrap();
        assert!(remaining_ms(&root, 60000).unwrap() <= 20);
        std::thread::sleep(Duration::from_millis(25));
        assert!(remaining_ms(&root, 60000).is_err());
        assert!(guard.receipt().partial);
        drop(guard);
        std::fs::remove_dir_all(root).unwrap();
    }
}

#[cfg(test)]
mod provenance_bytes_tests {
    use super::*;
    #[test]
    fn original_provenance_whitespace_is_retained_and_not_overwritten() {
        let root = std::env::temp_dir().join(format!("me-provenance-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&root).unwrap();
        let path = root.join("capture-relation.json");
        let bytes = b"{ \"parent\": \"original\" }\n";
        write_new_bytes(&path, bytes).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), bytes);
        assert!(write_new_bytes(&path, b"{}").is_err());
        assert_eq!(std::fs::read(&path).unwrap(), bytes);
        std::fs::remove_dir_all(root).unwrap();
    }
}

#[cfg(test)]
mod planned_allocation_tests {
    use super::*;
    #[test]
    fn downstream_slots_are_owned_before_capture_and_transferred_without_double_charge() {
        let mut b = Contract::new_planned(Limits::default(), 1, true).unwrap();
        let total = b.limits.total_bytes;
        assert_eq!(b.remaining(), total - manager_reserve() - total * 10 / 16);
        let before = b.remaining();
        let linker = b.reserve("linker-attempt".into(), "linker", 2).unwrap();
        assert_eq!(linker.0, total / 16);
        assert_eq!(b.remaining(), before);
        assert_eq!(
            b.reserve("linker-attempt".into(), "linker", 2).unwrap(),
            linker
        );
        assert!(b.reserve("another-linker".into(), "linker", 2).is_err());
        for (kind, expected) in [
            ("transfer", total / 4),
            ("archive", total / 8),
            ("import", total * 3 / 16),
        ] {
            assert_eq!(
                b.reserve(format!("export:{kind}"), kind, 2).unwrap().0,
                expected
            );
            assert_eq!(b.remaining(), before);
        }
        let l0 = b.reserve("l0".into(), "l0", 2).unwrap().0;
        assert_eq!(l0, before / 2);
        b.settle(
            "l0",
            &serde_json::json!({"admitted_write_bytes":1000,"partial":false}),
        )
        .unwrap();
        let l1 = b.reserve("l1".into(), "l1", 2).unwrap().0;
        assert!(l1 > 131072);
        b.settle(
            "l1",
            &serde_json::json!({"admitted_write_bytes":2000,"partial":false}),
        )
        .unwrap();
        let available = b.remaining();
        assert_eq!(b.reserve("dump".into(), "dump", 2).unwrap().0, available);
        assert_eq!(b.remaining(), 0);
        b.validate().unwrap();
        assert!(b.reserve("late".into(), "dump", 300001).is_err());
    }
    #[test]
    fn unified_plan_does_not_hold_a_second_linker_and_small_infeasible_plan_is_rejected() {
        let b = Contract::new_planned(Limits::default(), 1, false).unwrap();
        assert!(!b.reservations.iter().any(|r| r.kind == "linker"));
        assert_eq!(
            b.remaining(),
            b.limits.total_bytes - manager_reserve() - b.limits.total_bytes * 9 / 16
        );
        for separate in [false, true] {
            assert!(Contract::new_planned(
                Limits {
                    total_bytes: 4 * 1024 * 1024,
                    max_seconds: 30
                },
                1,
                separate
            )
            .is_err());
        }
    }
    #[test]
    fn minimum_sequential_plan_survives_full_l0_and_l1_reservations() {
        let limits = Limits {
            total_bytes: 6990501,
            max_seconds: 30,
        };
        assert!(Contract::new_planned(
            Limits {
                total_bytes: 6990500,
                max_seconds: 30
            },
            1,
            true
        )
        .is_err());
        let mut b = Contract::new_planned(limits, 1, true).unwrap();
        assert_eq!(b.remaining(), 4 * 131072);
        for kind in ["l0", "l1"] {
            let quota = b.reserve(kind.into(), kind, 2).unwrap().0;
            assert!(quota >= 131072);
            b.settle(
                kind,
                &serde_json::json!({"admitted_write_bytes":quota - 65536,"partial":true}),
            )
            .unwrap();
        }
        assert_eq!(b.reserve("dump".into(), "dump", 2).unwrap().0, 131072);
        // Later slots remain available even when all active reservations are full.
        assert!(b.reserve("linker".into(), "linker", 2).unwrap().0 >= 131072);
        for kind in ["transfer", "archive", "import"] {
            assert!(b.reserve(format!("export:{kind}"), kind, 2).unwrap().0 >= 65536);
        }
        b.validate().unwrap();
    }
    #[test]
    fn legacy_contracts_keep_original_policy_and_retired_tokens_are_not_recreated() {
        let b = Contract::new(Limits::default(), 1).unwrap();
        let mut value = serde_json::to_value(&b).unwrap();
        value.as_object_mut().unwrap().remove("plannedAllocation");
        value["deadlineToken"] = serde_json::Value::Null;
        let mut restored: Contract = serde_json::from_value(value).unwrap();
        assert!(!restored.planned_allocation);
        assert!(restored.reserve("retired".into(), "dump", 2).is_err());
        let mut live = b;
        let before = live.remaining();
        assert_eq!(
            live.reserve("legacy-dump".into(), "dump", 2).unwrap().0,
            before / 2
        );
    }
}

/// New contracts share added time between dump and transfer. Existing plans
/// retain their serialized caps and original monotonic stop coordinates.
fn planned_dump_ms(total_ms: u64) -> u64 {
    (95_000 + total_ms.saturating_sub(600_000) / 2).min(300_000)
}

impl TimePlan {
    fn validate(&self, total_ms: u64) -> Result<(), String> {
        let (archive_ms, import_ms, final_ms) = match self.schema.as_str() {
            "mobilee.session-time-plan/v1" => (60000, 75000, 140000),
            "mobilee.session-time-plan/v2"
            | "mobilee.session-time-plan/v3"
            | "mobilee.session-time-plan/v4"
                if total_ms >= 600000 =>
            {
                (120000, 120000, 245000)
            }
            _ => return Err("时间计划schema/总期限无效".into()),
        };
        if self.final_reserve_ms != final_ms {
            return Err("时间计划schema/终态预留无效".into());
        }
        let mut names = std::collections::BTreeSet::new();
        let mut sum = 0u64;
        for p in &self.phases {
            if !names.insert(p.kind.as_str())
                || p.cap_ms == 0
                || p.stop_at_parent_remaining_ms.is_some_and(|n| n > total_ms)
            {
                return Err("时间阶段身份/边界无效".into());
            }
            sum = sum.checked_add(p.cap_ms).ok_or("时间总数溢出")?;
        }
        for (kind, cap) in [
            ("archive", archive_ms),
            ("import", import_ms),
            ("terminal", 5000),
        ] {
            if !self
                .phases
                .iter()
                .any(|p| p.kind == kind && p.cap_ms == cap)
            {
                return Err("最终时间预留缺失或改变".into());
            }
        }
        let separate = names.contains("l0")
            && names.contains("l1")
            && names.contains("linker")
            && !names.contains("unified");
        let unified = names.contains("unified")
            && !names.contains("l0")
            && !names.contains("l1")
            && !names.contains("linker");
        if !(separate || unified)
            || !names.contains("dump")
            || !names.contains("transfer")
            || names.len() != if separate { 8 } else { 6 }
            || sum != total_ms
        {
            return Err("时间计划阶段/总期限无效".into());
        }
        Ok(())
    }
}
impl Contract {
    /// Explicit new-parent schedule. Observation windows are not silently shortened.
    pub fn new_planned_with_time(
        limits: Limits,
        now: u64,
        separate: bool,
        durations: &[u64],
    ) -> Result<Self, String> {
        if durations.len() != 3 || durations.iter().any(|n| !(1..=300).contains(n)) {
            return Err("无效显式采集时间计划".into());
        }
        let total = limits.max_seconds.checked_mul(1000).ok_or("时间额度溢出")?;
        let long_plan = limits.max_seconds >= 600;
        let l1_padding = if long_plan { 15 } else { 10 };
        let (archive_ms, import_ms, final_ms) = if long_plan {
            (120000, 120000, 245000)
        } else {
            (60000, 75000, 140000)
        };
        let mut caps = if separate {
            vec![
                ("l0", (durations[0] + 10) * 1000),
                ("l1", (durations[1] + l1_padding) * 1000),
                ("linker", (durations[2] + 10) * 1000),
            ]
        } else {
            vec![(
                "unified",
                (durations.iter().sum::<u64>() + l1_padding) * 1000,
            )]
        };
        caps.extend([
            (
                "dump",
                if long_plan {
                    planned_dump_ms(total)
                } else {
                    55000
                },
            ),
            ("archive", archive_ms),
            ("import", import_ms),
            ("terminal", 5000),
        ]);
        let held = caps.iter().map(|(_, n)| *n).sum::<u64>();
        let transfer = total.checked_sub(held).filter(|n| *n >= 30000).ok_or(
            "总期限不足以保留观察、Dump阶段、传输至少30秒和最终处理；90秒观察建议新父600秒，未启动",
        )?;
        caps.push(("transfer", transfer));
        let mut c = Self::new_planned(limits, now, separate)?;
        // A retained payload must fit transfer, archive and import. Fund equal
        // bounded export slots before producers start; never mutate old contracts.
        for slot in &mut c.reservations {
            if matches!(slot.kind.as_str(), "archive" | "import") {
                slot.reserved_bytes = c.limits.total_bytes / 4;
            }
        }
        c.coordinated_exports = true;
        if c.remaining() < if separate { 4 * 131072 } else { 2 * 131072 } {
            return Err("协调采集/导出容量不足；未启动".into());
        }
        c.time_plan = Some(TimePlan {
            schema: if long_plan {
                "mobilee.session-time-plan/v4"
            } else {
                "mobilee.session-time-plan/v1"
            }
            .into(),
            final_reserve_ms: final_ms,
            phases: caps
                .into_iter()
                .map(|(kind, cap_ms)| TimePhase {
                    kind: kind.into(),
                    cap_ms,
                    stop_at_parent_remaining_ms: None,
                    completed: false,
                })
                .collect(),
        });
        c.validate()?;
        Ok(c)
    }
    fn parent_remaining_ms(&self, now: u64) -> Result<u64, String> {
        let mono = self.deadline()?.remaining_ms()?;
        if now >= self.deadline_unix_ms {
            return Err("parent_deadline_exhausted".into());
        }
        // New leases use only the monotonic coordinate; wall-clock rollback cannot renew them.
        Ok(if self.time_plan.is_some() {
            mono
        } else {
            mono.min(self.deadline_unix_ms - now)
        })
    }
    /// Shared collection boundary protects final work even before transfer begins.
    pub fn collection_remaining_ms(&self, now: u64) -> Result<u64, String> {
        let remaining = self.parent_remaining_ms(now)?;
        let Some(plan) = &self.time_plan else {
            return Ok(remaining);
        };
        plan.validate(self.limits.max_seconds * 1000)?;
        remaining
            .checked_sub(plan.final_reserve_ms)
            .filter(|n| *n > 0)
            .ok_or_else(|| {
                format!(
                    "collection_time_holdback_exhausted: final{}秒已预留，未续期",
                    plan.final_reserve_ms / 1000
                )
            })
    }
    /// Persist the first lease before starting the phase. Repeat calls never reset it.
    pub fn begin_time_phase(&mut self, kind: &str, now: u64) -> Result<u64, String> {
        let remaining = self.parent_remaining_ms(now)?;
        let Some(plan) = self.time_plan.as_mut() else {
            return Ok(remaining);
        };
        plan.validate(self.limits.max_seconds * 1000)?;
        let index = plan
            .phases
            .iter()
            .position(|p| p.kind == kind)
            .ok_or("未知时间阶段")?;
        if plan.phases[index].completed {
            return Err("时间阶段已终结，不能重开".into());
        }
        if let Some(stop) = plan.phases[index].stop_at_parent_remaining_ms {
            return remaining
                .checked_sub(stop)
                .map(|n| n.min(plan.phases[index].cap_ms))
                .filter(|n| *n > 0)
                .ok_or("phase_time_exhausted: 不重置原阶段期限".into());
        }
        let held = plan
            .phases
            .iter()
            .enumerate()
            .filter(|(i, p)| *i != index && !p.completed)
            .map(|(_, p)| p.cap_ms)
            .sum::<u64>();
        let available = remaining
            .checked_sub(held)
            .filter(|n| *n > 0)
            .ok_or("phase_time_holdback_exhausted: 后续时间已预留".to_owned())?;
        let grant = available.min(plan.phases[index].cap_ms);
        plan.phases[index].stop_at_parent_remaining_ms = Some(remaining - grant);
        Ok(grant)
    }
}

#[cfg(test)]
mod time_plan_tests {
    use super::*;
    fn new() -> Contract {
        Contract::new_planned_with_time(
            Limits {
                total_bytes: 4 * 1024 * 1024 * 1024,
                max_seconds: 300,
            },
            1,
            true,
            &[5, 30, 10],
        )
        .unwrap()
    }
    #[test]
    fn long_new_parent_preserves_observations_and_reserves_finite_closeout() {
        for (separate, transfer) in [(true, 105000), (false, 125000)] {
            let c = Contract::new_planned_with_time(
                Limits {
                    total_bytes: 4 * 1024 * 1024 * 1024,
                    max_seconds: 600,
                },
                1,
                separate,
                &[15, 90, 15],
            )
            .unwrap();
            let p = c.time_plan.as_ref().unwrap();
            assert_eq!(p.schema, "mobilee.session-time-plan/v4");
            assert_eq!(p.final_reserve_ms, 245000);
            p.validate(600000).unwrap();
            p.validate_observations(separate, &[15, 90, 15]).unwrap();
            assert!(p.validate_observations(separate, &[15, 89, 15]).is_err());
            for (kind, cap) in [
                ("dump", 95000),
                ("transfer", transfer),
                ("archive", 120000),
                ("import", 120000),
                ("terminal", 5000),
            ] {
                assert!(p
                    .phases
                    .iter()
                    .any(|phase| phase.kind == kind && phase.cap_ms == cap));
            }
        }
    }

    #[test]
    fn larger_new_contract_shares_time_without_renewing_retained_v3() {
        for (seconds, dump, transfer) in [(900, 245_000, 255_000), (1200, 300_000, 500_000)] {
            let c = Contract::new_planned_with_time(
                Limits {
                    total_bytes: 8 * 1024 * 1024 * 1024,
                    max_seconds: seconds,
                },
                1,
                true,
                &[15, 90, 15],
            )
            .unwrap();
            let plan = c.time_plan.as_ref().unwrap();
            plan.validate(seconds * 1000).unwrap();
            plan.validate_observations(true, &[15, 90, 15]).unwrap();
            assert_eq!(
                plan.phases
                    .iter()
                    .find(|p| p.kind == "dump")
                    .unwrap()
                    .cap_ms,
                dump
            );
            assert_eq!(
                plan.phases
                    .iter()
                    .find(|p| p.kind == "transfer")
                    .unwrap()
                    .cap_ms,
                transfer
            );
            assert_eq!(
                plan.phases.iter().map(|p| p.cap_ms).sum::<u64>(),
                seconds * 1000
            );
            assert!(plan
                .phases
                .iter()
                .filter(|p| matches!(p.kind.as_str(), "archive" | "import"))
                .all(|p| p.cap_ms == 120_000));
        }
        let mut old = Contract::new_planned_with_time(
            Limits {
                total_bytes: 4 * 1024 * 1024 * 1024,
                max_seconds: 900,
            },
            1,
            true,
            &[15, 90, 15],
        )
        .unwrap();
        let plan = old.time_plan.as_mut().unwrap();
        plan.schema = "mobilee.session-time-plan/v3".into();
        for phase in &mut plan.phases {
            if phase.kind == "dump" {
                phase.cap_ms = 95_000;
                phase.stop_at_parent_remaining_ms = Some(400_000);
            }
            if phase.kind == "transfer" {
                phase.cap_ms = 405_000;
            }
        }
        let before = serde_json::to_vec(&old).unwrap();
        let restored: Contract = serde_json::from_slice(&before).unwrap();
        restored.validate().unwrap();
        restored
            .time_plan
            .as_ref()
            .unwrap()
            .validate_observations(true, &[15, 90, 15])
            .unwrap();
        assert_eq!(serde_json::to_vec(&restored).unwrap(), before);
        // The original issued stop coordinate still rejects an expired attempt.
        old.deadline_token = Some(super::super::session_deadline::Deadline::register(
            Duration::from_millis(399_999),
        ));
        let issued = old
            .time_plan
            .as_ref()
            .unwrap()
            .phases
            .iter()
            .find(|p| p.kind == "dump")
            .unwrap()
            .stop_at_parent_remaining_ms;
        assert!(old.begin_time_phase("dump", 1).is_err());
        assert_eq!(
            old.time_plan
                .as_ref()
                .unwrap()
                .phases
                .iter()
                .find(|p| p.kind == "dump")
                .unwrap()
                .stop_at_parent_remaining_ms,
            issued
        );
    }

    #[test]
    fn actual_ui_dump_elapsed_replay_keeps_old_failure_and_new_original_boundary() {
        // Retained 409f90ab UI attempt: 1791436111847 -> 1791436174889.
        let elapsed_ms = 1_791_436_174_889u64 - 1_791_436_111_847;
        let initial_remaining_ms = 485_274u64;
        let remaining_ms = initial_remaining_ms - elapsed_ms;
        for (schema, dump_ms, transfer_ms, should_pass) in [
            ("mobilee.session-time-plan/v2", 55_000, 145_000, false),
            ("mobilee.session-time-plan/v3", 95_000, 105_000, true),
        ] {
            let mut c = Contract::new_planned_with_time(
                Limits {
                    total_bytes: 4 * 1024 * 1024 * 1024,
                    max_seconds: 600,
                },
                1,
                true,
                &[15, 90, 15],
            )
            .unwrap();
            let plan = c.time_plan.as_mut().unwrap();
            plan.schema = schema.into();
            for phase in &mut plan.phases {
                match phase.kind.as_str() {
                    "dump" => {
                        phase.cap_ms = dump_ms;
                        phase.stop_at_parent_remaining_ms = Some(initial_remaining_ms - dump_ms);
                    }
                    "transfer" => phase.cap_ms = transfer_ms,
                    _ => {}
                }
            }
            c.deadline_token = Some(super::super::session_deadline::Deadline::register(
                Duration::from_millis(remaining_ms),
            ));
            let result = c.check_time_phase("dump", 1);
            assert_eq!(result.is_ok(), should_pass);
            if !should_pass {
                assert!(result.unwrap_err().contains("original lease"));
            }
            // A new parent must still fail if its original 95s boundary is crossed.
            c.deadline_token = Some(super::super::session_deadline::Deadline::register(
                Duration::from_millis(initial_remaining_ms - dump_ms - 1),
            ));
            assert!(c.check_time_phase("dump", 1).is_err());
        }
    }

    #[test]
    fn retained_v2_dump_lease_is_not_upgraded_by_new_parent_policy() {
        let current = Contract::new_planned_with_time(
            Limits {
                total_bytes: 4 * 1024 * 1024 * 1024,
                max_seconds: 600,
            },
            1,
            true,
            &[15, 90, 15],
        )
        .unwrap();
        let mut original = current.time_plan.unwrap();
        original.schema = "mobilee.session-time-plan/v2".into();
        for phase in &mut original.phases {
            match phase.kind.as_str() {
                "dump" => {
                    phase.cap_ms = 55_000;
                    phase.stop_at_parent_remaining_ms = Some(430_274);
                    phase.completed = true;
                }
                "transfer" => phase.cap_ms = 145_000,
                _ => {}
            }
        }
        let bytes = serde_json::to_vec(&original).unwrap();
        let restored: TimePlan = serde_json::from_slice(&bytes).unwrap();
        restored.validate(600_000).unwrap();
        restored.validate_observations(true, &[15, 90, 15]).unwrap();
        assert_eq!(serde_json::to_vec(&restored).unwrap(), bytes);
        let dump = restored.phases.iter().find(|p| p.kind == "dump").unwrap();
        assert_eq!(dump.cap_ms, 55_000);
        assert_eq!(dump.stop_at_parent_remaining_ms, Some(430_274));
        assert!(dump.completed);
    }

    #[test]
    fn serialized_v1_long_parent_is_not_upgraded_or_renewed() {
        let c = new();
        let mut old = c.time_plan.unwrap();
        old.phases
            .iter_mut()
            .find(|p| p.kind == "transfer")
            .unwrap()
            .cap_ms += 300000;
        old.validate(600000).unwrap();
        let bytes = serde_json::to_vec(&old).unwrap();
        let restored: TimePlan = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(restored.schema, "mobilee.session-time-plan/v1");
        assert_eq!(restored.final_reserve_ms, 140000);
        restored.validate_observations(true, &[5, 30, 10]).unwrap();
        assert_eq!(serde_json::to_vec(&restored).unwrap(), bytes);
    }
    #[test]
    fn explicit_short_plan_holds_final140_and_refuses_old_long_windows_before_clock() {
        assert!(Contract::new_planned_with_time(
            Limits {
                total_bytes: 4 * 1024 * 1024 * 1024,
                max_seconds: 300
            },
            1,
            true,
            &[15, 90, 15]
        )
        .is_err());
        let mut c = new();
        let token = c.deadline_token;
        let p = c.time_plan.as_ref().unwrap();
        assert_eq!(p.final_reserve_ms, 140000);
        for (kind, cap) in [
            ("l0", 15000),
            ("l1", 40000),
            ("dump", 55000),
            ("linker", 20000),
            ("transfer", 30000),
            ("archive", 60000),
            ("import", 75000),
            ("terminal", 5000),
        ] {
            assert_eq!(
                p.phases.iter().find(|p| p.kind == kind).unwrap().cap_ms,
                cap
            );
        }
        assert!(c.collection_remaining_ms(1).unwrap() <= 160000);
        let grant = c.reserve("l0-attempt".into(), "l0", 1).unwrap().1;
        assert!(grant <= 15000 && grant > 14000);
        assert_eq!(c.deadline_token, token);
        assert_eq!(c.limits.max_seconds, 300);
    }
    #[test]
    fn lease_repetition_and_wall_rollback_never_renew_or_reopen() {
        let mut c = new();
        let first = c.reserve("a".into(), "l0", 2000).unwrap().1;
        let boundary = c.time_plan.as_ref().unwrap().phases[0].stop_at_parent_remaining_ms;
        std::thread::sleep(Duration::from_millis(4));
        let repeat = c.reserve("a".into(), "l0", 0).unwrap().1;
        assert!(repeat < first);
        assert_eq!(
            boundary,
            c.time_plan.as_ref().unwrap().phases[0].stop_at_parent_remaining_ms
        );
        c.settle(
            "a",
            &serde_json::json!({"admitted_write_bytes":10,"partial":false}),
        )
        .unwrap();
        assert!(c.reserve("a".into(), "l0", 0).is_err());
        assert!(c.reserve("b".into(), "l0", 0).is_err());
    }
    #[test]
    fn export_byte_reservation_does_not_start_its_phase_and_unknown_token_fails() {
        let mut c = new();
        let token = c.deadline_token;
        for kind in ["transfer", "archive", "import"] {
            c.reserve(format!("export:{kind}"), kind, 1).unwrap();
        }
        assert!(c
            .time_plan
            .as_ref()
            .unwrap()
            .phases
            .iter()
            .all(|p| p.stop_at_parent_remaining_ms.is_none()));
        let phase = c.begin_time_phase("transfer", 1).unwrap();
        assert!(phase <= 30000);
        assert!(c.release_unstarted("export:transfer").is_err());
        assert_eq!(
            c.reservations
                .iter()
                .find(|r| r.kind == "transfer")
                .unwrap()
                .charged_bytes,
            None
        );
        assert_eq!(c.deadline_token, token);
        c.deadline_token = None;
        assert!(c.collection_remaining_ms(1).is_err());
        assert!(c.begin_time_phase("import", 1).is_err());
    }
    #[test]
    fn persisted_legacy_has_no_time_plan_and_keeps_original_clock() {
        let old = Contract::new_planned(Limits::default(), 1, true).unwrap();
        let mut value = serde_json::to_value(&old).unwrap();
        value.as_object_mut().unwrap().remove("timePlan");
        let mut decoded: Contract = serde_json::from_value(value).unwrap();
        assert!(decoded.time_plan.is_none());
        let token = decoded.deadline_token;
        assert!(decoded.reserve("a".into(), "l0", 1).unwrap().1 > 140000);
        assert_eq!(decoded.deadline_token, token);
        decoded.deadline().unwrap().cancel();
        assert!(decoded.reserve("b".into(), "l1", 1).is_err());
        assert!(decoded.time_plan.is_none());
    }
    #[test]
    fn tampered_final_plan_or_phase_boundaries_fail_validation() {
        let mut c = new();
        c.time_plan
            .as_mut()
            .unwrap()
            .phases
            .iter_mut()
            .find(|p| p.kind == "import")
            .unwrap()
            .cap_ms = 74000;
        assert!(c.validate().is_err());
        let mut c = new();
        c.time_plan.as_mut().unwrap().phases[0].stop_at_parent_remaining_ms = Some(300001);
        assert!(c.validate().is_err());
    }
    #[test]
    fn original_monotonic_expiry_and_final_holdback_are_not_new_clocks() {
        let mut c = new();
        c.deadline_token = Some(super::super::session_deadline::Deadline::register(
            Duration::from_millis(140010),
        ));
        assert!(c.collection_remaining_ms(1).unwrap() <= 10);
        std::thread::sleep(Duration::from_millis(15));
        assert!(c.collection_remaining_ms(1).is_err());
        assert!(c.deadline().unwrap().check().is_ok()); // parent still has final time
        c.deadline().unwrap().cancel();
        assert!(c.begin_time_phase("archive", 1).is_err());
    }
}

impl TimePlan {
    pub fn validate_observations(&self, separate: bool, durations: &[u64]) -> Result<(), String> {
        if durations.len() != 3 {
            return Err("时间计划观察窗口缺失".into());
        }
        let l1_padding = if matches!(
            self.schema.as_str(),
            "mobilee.session-time-plan/v2"
                | "mobilee.session-time-plan/v3"
                | "mobilee.session-time-plan/v4"
        ) {
            15
        } else {
            10
        };
        let caps = if separate {
            vec![
                ("l0", (durations[0] + 10) * 1000),
                ("l1", (durations[1] + l1_padding) * 1000),
                ("linker", (durations[2] + 10) * 1000),
            ]
        } else {
            vec![(
                "unified",
                (durations.iter().sum::<u64>() + l1_padding) * 1000,
            )]
        };
        for (kind, ms) in caps {
            if !self.phases.iter().any(|p| p.kind == kind && p.cap_ms == ms) {
                return Err("父观察窗口与事前时间计划不一致".into());
            }
        }
        let total_ms = self.phases.iter().try_fold(0u64, |sum, p| {
            sum.checked_add(p.cap_ms).ok_or("时间总数溢出")
        })?;
        let dump_ms = match self.schema.as_str() {
            "mobilee.session-time-plan/v4" => planned_dump_ms(total_ms),
            "mobilee.session-time-plan/v3" => 95_000,
            _ => 55_000,
        };
        if !self
            .phases
            .iter()
            .any(|p| p.kind == "dump" && p.cap_ms == dump_ms)
            || !self
                .phases
                .iter()
                .any(|p| p.kind == "transfer" && p.cap_ms >= 30000)
        {
            return Err("Dump/transfer时间预留无效".into());
        }
        Ok(())
    }
}

impl Contract {
    /// Completion fence: read the first lease without starting, renewing or settling it.
    pub fn check_time_phase(&self, kind: &str, now: u64) -> Result<(), String> {
        if self.time_plan.is_none() {
            return self.deadline()?.check();
        }
        let remaining = self.parent_remaining_ms(now)?;
        let plan = self.time_plan.as_ref().unwrap();
        plan.validate(self.limits.max_seconds * 1000)?;
        let phase = plan
            .phases
            .iter()
            .find(|p| p.kind == kind)
            .ok_or("phase_time_unknown: missing phase")?;
        if phase.completed {
            return Err("phase_time_finished: cannot report another completion".into());
        }
        let stop = phase
            .stop_at_parent_remaining_ms
            .ok_or("phase_time_unknown: original lease not started")?;
        if remaining <= stop {
            return Err(format!("phase_time_exhausted: {kind} crossed its original lease; original evidence retained"));
        }
        Ok(())
    }
    /// Keep real admitted bytes/source fields; only the host's completion claim changes.
    pub fn phase_settlement_note(
        &self,
        kind: &str,
        receipt: &serde_json::Value,
        now: u64,
    ) -> (serde_json::Value, Option<String>) {
        let mut note = receipt.clone();
        let failure = self.check_time_phase(kind, now).err();
        if let Some(error) = failure.as_ref() {
            note["partial"] = serde_json::json!(true);
            note["host_time_fence"] = serde_json::json!(error);
        }
        (note, failure)
    }
}
#[cfg(test)]
mod phase_completion_tests {
    use super::*;
    fn new() -> Contract {
        Contract::new_planned_with_time(
            Limits {
                total_bytes: 4294967296,
                max_seconds: 300,
            },
            1,
            true,
            &[5, 30, 10],
        )
        .unwrap()
    }
    #[test]
    fn completion_check_cannot_start_or_renew_a_lease() {
        let mut c = new();
        assert!(c.check_time_phase("l0", 1).is_err());
        let token = c.deadline_token;
        c.reserve("a".into(), "l0", 1).unwrap();
        let boundary = c.time_plan.as_ref().unwrap().phases[0].stop_at_parent_remaining_ms;
        c.check_time_phase("l0", 1).unwrap();
        assert_eq!(
            boundary,
            c.time_plan.as_ref().unwrap().phases[0].stop_at_parent_remaining_ms
        );
        assert_eq!(c.deadline_token, token);
        c.time_plan.as_mut().unwrap().phases[0].stop_at_parent_remaining_ms = Some(300000);
        assert!(c.check_time_phase("l0", 1).is_err());
        assert_eq!(
            c.time_plan.as_ref().unwrap().phases[0].stop_at_parent_remaining_ms,
            Some(300000)
        );
    }
    #[test]
    fn expired_phase_keeps_real_source_and_bytes_but_settles_partial() {
        let mut c = new();
        c.reserve("a".into(), "l0", 1).unwrap();
        let token = c.deadline_token;
        c.time_plan.as_mut().unwrap().phases[0].stop_at_parent_remaining_ms = Some(300000);
        let original = serde_json::json!({"schema":"kernsight.output-budget/v1","admitted_write_bytes":12345,"partial":false,"reason":null,"source":{"pid":42}});
        let (note, failure) = c.phase_settlement_note("l0", &original, 1);
        assert!(failure.is_some());
        assert_eq!(note["source"], original["source"]);
        assert_eq!(note["admitted_write_bytes"], 12345);
        assert_eq!(original["partial"], false);
        assert_eq!(note["partial"], true);
        c.settle("a", &note).unwrap();
        let r = c.reservations.iter().find(|r| r.id == "a").unwrap();
        assert_eq!(r.charged_bytes, Some(12345 + 65536));
        assert_eq!(r.status, "partial");
        assert_eq!(c.deadline_token, token);
        assert!(c.check_time_phase("l0", 1).is_err());
    }
    #[test]
    fn legacy_completion_keeps_none_and_unknown_or_expired_parent_fails() {
        let mut c = Contract::new(Limits::default(), 1).unwrap();
        c.check_time_phase("l0", 1).unwrap();
        assert!(c.time_plan.is_none());
        c.deadline().unwrap().cancel();
        assert!(c.check_time_phase("l0", 1).is_err());
        c.deadline_token = None;
        assert!(c.check_time_phase("l0", 1).is_err());
        assert!(c.time_plan.is_none());
    }
}

impl Contract {
    /// Caller must have proved no payload operation began (e.g. Guard install failed).
    /// Lease issuance alone is not payload IO. Keep its coordinate and retire it forever.
    pub fn release_granted_before_payload(&mut self, id: &str) -> Result<(), String> {
        self.release_known_unstarted_lease(id, true)
    }
    /// Only an explicit pre-capture capability refusal may release a granted stage lease.
    pub fn release_stage_granted_before_capture(&mut self, id: &str) -> Result<(), String> {
        self.release_known_unstarted_lease(id, false)
    }
    fn release_known_unstarted_lease(&mut self, id: &str, export: bool) -> Result<(), String> {
        let index = self
            .reservations
            .iter()
            .position(|r| r.id == id)
            .ok_or("缺已预留导出操作")?;
        let r = &self.reservations[index];
        let allowed = if export {
            matches!(r.kind.as_str(), "transfer" | "archive" | "import")
        } else {
            matches!(r.kind.as_str(), "l0" | "l1" | "dump" | "linker" | "unified")
        };
        if !allowed {
            return Err("操作类型与明确未启动payload证明不一致".into());
        }
        if r.status == "not_started" && r.charged_bytes == Some(0) {
            return Ok(());
        }
        if r.charged_bytes.is_some() || r.status != "reserved" {
            return Err("已有计量/未知终态，不能记为未启动".into());
        }
        let kind = r.kind.clone();
        if let Some(plan) = self.time_plan.as_mut() {
            let phase = plan
                .phases
                .iter_mut()
                .find(|p| p.kind == kind)
                .ok_or("导出时间阶段缺失")?;
            if phase.completed {
                return Err("时间阶段已完成，不能退回未知payload".into());
            }
            phase.completed = true; // original stop coordinate stays immutable
        }
        self.reservations[index].charged_bytes = Some(0);
        self.reservations[index].status = "not_started".into();
        Ok(())
    }
}
#[cfg(test)]
mod before_payload_release_tests {
    use super::*;
    #[test]
    fn guard_failure_retires_issued_lease_without_renewal_or_unknown_zero() {
        let mut c = Contract::new_planned_with_time(
            Limits {
                total_bytes: 4294967296,
                max_seconds: 300,
            },
            1,
            true,
            &[5, 30, 10],
        )
        .unwrap();
        let token = c.deadline_token;
        c.reserve("export:import".into(), "import", 1).unwrap();
        c.begin_time_phase("import", 1).unwrap();
        let boundary = c
            .time_plan
            .as_ref()
            .unwrap()
            .phases
            .iter()
            .find(|p| p.kind == "import")
            .unwrap()
            .stop_at_parent_remaining_ms;
        c.release_granted_before_payload("export:import").unwrap();
        assert_eq!(c.deadline_token, token);
        let p = c
            .time_plan
            .as_ref()
            .unwrap()
            .phases
            .iter()
            .find(|p| p.kind == "import")
            .unwrap();
        assert_eq!(p.stop_at_parent_remaining_ms, boundary);
        assert!(p.completed);
        assert!(c.begin_time_phase("import", 1).is_err());
        c.release_granted_before_payload("export:import").unwrap();
        c.reserve("export:transfer".into(), "transfer", 1).unwrap();
        c.begin_time_phase("transfer", 1).unwrap();
        c.settle(
            "export:transfer",
            &serde_json::json!({"admitted_write_bytes":7,"partial":true}),
        )
        .unwrap();
        assert!(c.release_granted_before_payload("export:transfer").is_err());
        assert_eq!(
            c.reservations
                .iter()
                .find(|r| r.id == "export:transfer")
                .unwrap()
                .charged_bytes,
            Some(7 + 65536)
        );
    }
}

#[cfg(test)]
mod capability_time_release_tests {
    use super::*;
    #[test]
    fn explicit_pre_capture_gate_can_retire_stage_lease_but_export_api_cannot() {
        let mut c = Contract::new_planned_with_time(
            Limits {
                total_bytes: 4294967296,
                max_seconds: 300,
            },
            1,
            true,
            &[5, 30, 10],
        )
        .unwrap();
        c.reserve("stage".into(), "l0", 1).unwrap();
        let token = c.deadline_token;
        let boundary = c.time_plan.as_ref().unwrap().phases[0].stop_at_parent_remaining_ms;
        assert!(c.release_granted_before_payload("stage").is_err());
        c.release_stage_granted_before_capture("stage").unwrap();
        assert_eq!(
            c.time_plan.as_ref().unwrap().phases[0].stop_at_parent_remaining_ms,
            boundary
        );
        assert_eq!(c.deadline_token, token);
        assert!(c.time_plan.as_ref().unwrap().phases[0].completed);
        assert!(c.begin_time_phase("l0", 1).is_err());
    }
}

#[cfg(test)]
mod phase_guard_tests {
    use super::*;
    #[test]
    fn constraining_guard_keeps_charges_and_cannot_extend_deadline() {
        let root = std::env::temp_dir().join(format!("me-constrain-{}", uuid::Uuid::new_v4()));
        let guard = Guard::install(vec![root.clone()], 1024, 10000).unwrap();
        charge(&root.join("evidence"), 123).unwrap();
        guard.constrain_time(100).unwrap();
        let first = states().lock().unwrap().get(&guard.0).unwrap().deadline;
        guard.constrain_time(10000).unwrap();
        assert_eq!(
            states().lock().unwrap().get(&guard.0).unwrap().deadline,
            first
        );
        assert_eq!(guard.receipt().admitted_write_bytes, 123);
        assert_eq!(guard.receipt().limit_bytes, 1024);
        assert!(guard.constrain_time(0).is_err());
        assert_eq!(guard.receipt().admitted_write_bytes, 123);
    }
}

#[cfg(test)]
mod coordinated_export_tests {
    use super::*;
    #[test]
    fn retained_5333_payload_fits_new_plan_and_original_contract_is_unchanged() {
        let limits = Limits {
            total_bytes: 4 * 1024 * 1024 * 1024,
            max_seconds: 600,
        };
        let mut c =
            Contract::new_planned_with_time(limits.clone(), 1, true, &[15, 90, 15]).unwrap();
        let deadline = c.deadline_token;
        assert!(c.coordinated_exports);
        for (kind, charge) in [("l0", 2_373_938), ("l1", 1_892_290)] {
            c.reserve(kind.into(), kind, 2).unwrap();
            c.settle(
                kind,
                &serde_json::json!({"admitted_write_bytes":charge,"partial":false}),
            )
            .unwrap();
        }
        let dump = c.reserve("dump".into(), "dump", 3).unwrap().0;
        assert!(dump >= 487_996_765);
        let export = limits.total_bytes / 4;
        let payload = super::super::planned_transfer_payload_limit(export, export, export);
        assert!(dump <= payload);
        // Actual original unique source bytes plus previously omitted base.apk.
        assert!(317_344_486_u64 + 166_864_204 <= payload);
        c.settle(
            "dump",
            &serde_json::json!({"admitted_write_bytes":487_931_229_u64,"partial":true}),
        )
        .unwrap();
        for kind in ["transfer", "archive", "import"] {
            assert_eq!(
                c.reserve(format!("export:{kind}"), kind, 4).unwrap().0,
                export
            );
        }
        assert_eq!(c.deadline_token, deadline);
        c.validate().unwrap();
        let old = Contract::new_planned(limits.clone(), 1, true).unwrap();
        let mut json = serde_json::to_value(&old).unwrap();
        json.as_object_mut().unwrap().remove("coordinatedExports");
        let restored: Contract = serde_json::from_value(json).unwrap();
        assert!(!restored.coordinated_exports);
        restored.validate().unwrap();
        assert_eq!(
            restored
                .reservations
                .iter()
                .find(|r| r.kind == "archive")
                .unwrap()
                .reserved_bytes,
            limits.total_bytes / 8
        );
    }
    #[test]
    fn infeasible_small_new_plan_fails_before_any_producer() {
        assert!(Contract::new_planned_with_time(
            Limits {
                total_bytes: 4 * 1024 * 1024,
                max_seconds: 600
            },
            1,
            true,
            &[15, 90, 15]
        )
        .is_err());
    }
}
