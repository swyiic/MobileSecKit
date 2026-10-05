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
        r.charged_bytes = Some(0);
        r.status = "not_started".into();
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
        })
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
        if let Some(r) = self.reservations.iter().find(|r| r.id == id) {
            if r.kind != kind {
                return Err("预算操作身份冲突".into());
            }
            return Ok((
                r.reserved_bytes,
                self.deadline_unix_ms.saturating_sub(now).min(monotonic_ms),
            ));
        }
        let quota = match kind {
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
        Ok((quota, (self.deadline_unix_ms - now).min(monotonic_ms)))
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
        r.charged_bytes = Some(n);
        r.status = if receipt["partial"].as_bool() == Some(true) {
            "partial"
        } else {
            "admitted_plus_terminal_reserve"
        }
        .into();
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
