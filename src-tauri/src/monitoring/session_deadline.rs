//! Process-local monotonic parent deadline. Persisted wall time is display only.
//! An expired or restarted parent cannot acquire a new clock through a retry.
use std::{
    collections::BTreeMap,
    future::Future,
    process::{Output, Stdio},
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc, Mutex, OnceLock,
    },
    time::Duration,
};
use tokio::{process::Command, sync::Notify};
use uuid::Uuid;

// Keep production on the system clock; unit tests can opt into paused time.
#[cfg(not(test))]
use std::time::Instant;
#[cfg(test)]
use tokio::time::Instant;

#[derive(Clone)]
pub struct Deadline(Arc<Inner>);
struct Inner {
    at: Instant,
    cancelled: Arc<AtomicBool>,
    changed: Arc<Notify>,
    children: Arc<AtomicUsize>,
    cleanup_failed: Arc<AtomicBool>,
}
static PARENTS: OnceLock<Mutex<BTreeMap<Uuid, Deadline>>> = OnceLock::new();
tokio::task_local! { static CURRENT: Deadline; }
impl Deadline {
    pub fn new(duration: Duration) -> Self {
        Self(Arc::new(Inner {
            at: Instant::now() + duration,
            cancelled: Arc::new(AtomicBool::new(false)),
            changed: Arc::new(Notify::new()),
            children: Arc::new(AtomicUsize::new(0)),
            cleanup_failed: Arc::new(AtomicBool::new(false)),
        }))
    }
    /// Derive a fixed boundary from the original parent clock. No registration,
    /// rolling now+duration lease or cancellation reset is permitted.
    pub fn before_parent_remaining(&self, remaining_ms: u64) -> Result<Self, String> {
        self.check()?;
        let at = self
            .0
            .at
            .checked_sub(Duration::from_millis(remaining_ms))
            .ok_or("phase_deadline_invalid")?;
        if Instant::now() >= at {
            return Err("parent_deadline_exhausted: fixed capture/phase boundary".into());
        }
        Ok(Self(Arc::new(Inner {
            at,
            cancelled: Arc::clone(&self.0.cancelled),
            changed: Arc::clone(&self.0.changed),
            children: Arc::clone(&self.0.children),
            cleanup_failed: Arc::clone(&self.0.cleanup_failed),
        })))
    }
    /// Monotonic elapsed time from a recorded parent remaining-time coordinate;
    /// available after expiry for truthful terminal accounting.
    pub fn elapsed_from_remaining(&self, started_remaining_ms: u64) -> Result<u64, String> {
        let started = self
            .0
            .at
            .checked_sub(Duration::from_millis(started_remaining_ms))
            .ok_or("phase_start_invalid")?;
        Ok(u64::try_from(
            Instant::now()
                .saturating_duration_since(started)
                .as_millis(),
        )
        .unwrap_or(u64::MAX))
    }
    pub fn register(duration: Duration) -> Uuid {
        let token = Uuid::new_v4();
        PARENTS
            .get_or_init(Default::default)
            .lock()
            .unwrap()
            .insert(token, Self::new(duration));
        token
    }
    pub fn lookup(token: Option<Uuid>) -> Result<Self, String> {
        token.and_then(|id| PARENTS.get_or_init(Default::default).lock().ok()?.get(&id).cloned())
            .ok_or_else(|| "parent_deadline_unknown: 编排进程重启/旧合同，不能重建总时限；保留证据，新采集须新父会话".into())
    }
    pub fn cancel(&self) {
        self.0.cancelled.store(true, Ordering::SeqCst);
        self.0.changed.notify_waiters();
    }
    pub fn remaining_ms(&self) -> Result<u64, String> {
        self.check()?;
        // Floor, never give a child more time than its parent has remaining.
        let ms = self
            .0
            .at
            .saturating_duration_since(Instant::now())
            .as_millis() as u64;
        if ms == 0 {
            Err("parent_deadline_exhausted".into())
        } else {
            Ok(ms)
        }
    }
    pub fn check(&self) -> Result<(), String> {
        if self.0.cancelled.load(Ordering::SeqCst) {
            Err("parent_cancelled".into())
        } else if Instant::now() >= self.0.at {
            Err("parent_deadline_exhausted".into())
        } else {
            Ok(())
        }
    }
    async fn stopped(&self) -> String {
        loop {
            let notified = self.0.changed.notified();
            // Register before checking cancellation, so a wake cannot be lost.
            tokio::pin!(notified);
            notified.as_mut().enable();
            if let Err(e) = self.check() {
                return e;
            }
            tokio::select! {
                _ = tokio::time::sleep_until(self.0.at.into()) => {},
                _ = &mut notified => {},
            }
        }
    }
    pub async fn run<T>(
        &self,
        future: impl Future<Output = Result<T, String>>,
    ) -> Result<T, String> {
        self.check()?;
        let result = CURRENT
            .scope(self.clone(), async {
                tokio::select! { biased;
                    reason = self.stopped() => Err(reason),
                    result = future => result,
                }
            })
            .await;
        // Child supervisors are separate tasks: dropping the caller cannot abandon ownership.
        if result.as_ref().err().is_some_and(|e| is_stop(e)) {
            let clean = tokio::time::timeout(Duration::from_secs(2), async {
                loop {
                    let notified = self.0.changed.notified();
                    tokio::pin!(notified);
                    notified.as_mut().enable();
                    if self.0.children.load(Ordering::SeqCst) == 0 {
                        break;
                    }
                    notified.await;
                }
            })
            .await
            .is_ok()
                && !self.0.cleanup_failed.load(Ordering::SeqCst);
            return Err(format!(
                "{}; owned_host_children_reaped={clean}; remote_cleanup=unconfirmed",
                result.err().unwrap()
            ));
        }
        self.check()?;
        result
    }
}
pub fn is_stop(s: &str) -> bool {
    s.contains("parent_deadline_exhausted") || s.contains("parent_cancelled")
}
pub fn current() -> Option<Deadline> {
    CURRENT.try_with(Clone::clone).ok()
}
pub fn check() -> Result<(), String> {
    current().map_or(Ok(()), |d| d.check())
}
pub fn remaining_ms(fallback: u64) -> Result<u64, String> {
    current().map_or(Ok(fallback), |d| d.remaining_ms().map(|n| n.min(fallback)))
}

// Only this client's newly created process group. Never pidof/pkill or the shared adb server.
#[cfg(unix)]
fn kill_owned_group(pid: u32) -> bool {
    unsafe extern "C" {
        fn kill(pid: i32, sig: i32) -> i32;
    }
    // The supervisor still owns the unreaped leader, so its PID cannot have been reused.
    let result = unsafe { kill(-(pid as i32), 9) };
    let errno = std::io::Error::last_os_error().raw_os_error();
    #[cfg(test)]
    if result != 0 && errno != Some(3) {
        eprintln!("owned_group_signal_failed pid={pid} result={result} errno={errno:?}");
    }
    result == 0 || errno == Some(3)
}
struct Count(Deadline);
impl Drop for Count {
    fn drop(&mut self) {
        self.0 .0.children.fetch_sub(1, Ordering::SeqCst);
        self.0 .0.changed.notify_waiters();
    }
}
/// Deadline-aware subprocess output; ownership survives cancellation of the caller.
pub async fn output(command: &mut Command, local_limit: Duration) -> Result<Output, String> {
    let Some(parent) = current() else {
        return tokio::time::timeout(local_limit, command.kill_on_drop(true).output())
            .await
            .map_err(|_| "command_timeout".to_string())?
            .map_err(|e| e.to_string());
    };
    parent.check()?;
    #[cfg(unix)]
    command.process_group(0);
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    let mut child = command.spawn().map_err(|e| e.to_string())?;
    let pid = child.id().ok_or("spawned child missing PID")?;
    let out = child.stdout.take().ok_or("missing stdout")?;
    let err = child.stderr.take().ok_or("missing stderr")?;
    parent.0.children.fetch_add(1, Ordering::SeqCst);
    let supervisor = tokio::spawn(async move {
        use tokio::io::AsyncReadExt;
        let _count = Count(parent.clone());
        let out_task = tokio::spawn(async move {
            let mut r = out;
            let mut b = Vec::new();
            r.read_to_end(&mut b).await.map(|_| b)
        });
        let err_task = tokio::spawn(async move {
            let mut r = err;
            let mut b = Vec::new();
            r.read_to_end(&mut b).await.map(|_| b)
        });
        // Local cap also remains absolute while waiting for both child and pipe EOF.
        let local = tokio::time::Instant::now() + local_limit;
        // Keep reader handles outside the wait future so timeout can abort and join them.
        let mut out_task = out_task;
        let mut err_task = err_task;
        let completed = async {
            let stdout = (&mut out_task)
                .await
                .map_err(|e| e.to_string())?
                .map_err(|e| e.to_string())?;
            let stderr = (&mut err_task)
                .await
                .map_err(|e| e.to_string())?
                .map_err(|e| e.to_string())?;
            let status = child.wait().await.map_err(|e| e.to_string())?;
            Ok(Output {
                status,
                stdout,
                stderr,
            })
        };
        let result = tokio::select! { biased;
            reason = parent.stopped() => Err(reason),
            _ = tokio::time::sleep_until(local) => Err("command_timeout".into()),
            result = completed => result,
        };
        if result.is_err() {
            #[cfg(unix)]
            {
                let mut delivered = false;
                for _ in 0..10 {
                    // Keep the leader unreaped while pending forks/inherited pipes settle.
                    // Stop signalling as soon as owned pipe readers have reached EOF.
                    if delivered && out_task.is_finished() && err_task.is_finished() {
                        break;
                    }
                    let signalled = kill_owned_group(pid);
                    if signalled {
                        delivered = true;
                    } else if !(delivered && out_task.is_finished() && err_task.is_finished()) {
                        parent.0.cleanup_failed.store(true, Ordering::SeqCst);
                    }
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
                if !out_task.is_finished() || !err_task.is_finished() {
                    parent.0.cleanup_failed.store(true, Ordering::SeqCst);
                }
            }
            #[cfg(not(unix))]
            parent.0.cleanup_failed.store(true, Ordering::SeqCst);
            let _ = child.start_kill();
            let waited = tokio::time::timeout(Duration::from_secs(1), child.wait()).await;
            #[cfg(test)]
            eprintln!("owned_child_wait pid={pid} result={waited:?}");
            if !matches!(waited, Ok(Ok(_))) {
                parent.0.cleanup_failed.store(true, Ordering::SeqCst);
            }
            out_task.abort();
            err_task.abort();
            let _ = out_task.await;
            let _ = err_task.await;
        }
        result
    });
    supervisor.await.map_err(|e| e.to_string())?
}

/// Stream a child's stdout while a separate supervisor retains process ownership.
/// The consumer must finish at EOF; parser errors retain its already written output.
pub(super) async fn stream_output<T, F, Fut>(
    mut command: Command,
    cap: Duration,
    consume: F,
) -> Result<T, String>
where
    T: Send + 'static,
    F: FnOnce(tokio::process::ChildStdout) -> Fut + Send + 'static,
    Fut: Future<Output = Result<T, String>> + Send + 'static,
{
    struct Caller(tokio::sync::oneshot::Sender<()>);
    // Dropping the caller must notify, rather than abort, the owning supervisor.
    // A Sender's drop wakes the receiver even when no value was sent.
    let parent = current();
    if let Some(parent) = &parent {
        parent.check()?;
    }
    let local = tokio::time::Instant::now() + cap;
    #[cfg(unix)]
    command.process_group(0);
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    let mut child = command.spawn().map_err(|e| e.to_string())?;
    let pid = child.id().ok_or("spawned stream child missing PID")?;
    let stdout = child.stdout.take().ok_or("missing stream stdout")?;
    if let Some(parent) = &parent {
        parent.0.children.fetch_add(1, Ordering::SeqCst);
    }
    let (cancel, mut cancelled) = tokio::sync::oneshot::channel();
    let caller = Caller(cancel);
    let supervisor = tokio::spawn(async move {
        let _count = parent.clone().map(Count);
        let consumer_parent = parent.clone();
        let mut consumer = tokio::spawn(async move {
            if let Some(parent) = consumer_parent {
                CURRENT.scope(parent, consume(stdout)).await
            } else {
                consume(stdout).await
            }
        });
        let mut consumer_joined = false;
        let completed = async {
            let joined = (&mut consumer).await;
            consumer_joined = true;
            let result = joined.map_err(|e| e.to_string())??;
            let status = child.wait().await.map_err(|e| e.to_string())?;
            if !status.success() {
                return Err(format!(
                    "stream source command failed ({status}); verified output retained"
                ));
            }
            Ok(result)
        };
        let result = tokio::select! { biased;
            reason = async {
                match &parent {
                    Some(parent) => parent.stopped().await,
                    None => std::future::pending().await,
                }
            } => Err(reason),
            _ = &mut cancelled => Err("stream_caller_cancelled".into()),
            _ = tokio::time::sleep_until(local) => Err("command_timeout".into()),
            result = completed => result,
        };
        match result {
            Ok(value) => Ok(value),
            Err(error) => {
                let mut clean = true;
                // Never signal a PID after wait() has reaped it; it may be reused.
                if child.id() == Some(pid) {
                    #[cfg(unix)]
                    {
                        let mut delivered = false;
                        for _ in 0..10 {
                            if delivered && consumer.is_finished() {
                                break;
                            }
                            if kill_owned_group(pid) {
                                delivered = true;
                            } else {
                                clean = false;
                            }
                            tokio::time::sleep(Duration::from_millis(5)).await;
                        }
                    }
                    #[cfg(not(unix))]
                    {
                        clean = false; // Descendant cleanup is unconfirmed off Unix.
                    }
                    let _ = child.start_kill();
                    if !matches!(
                        tokio::time::timeout(Duration::from_secs(1), child.wait()).await,
                        Ok(Ok(_))
                    ) {
                        clean = false;
                    }
                }
                if !consumer_joined {
                    consumer.abort();
                    if tokio::time::timeout(Duration::from_secs(1), &mut consumer)
                        .await
                        .is_err()
                    {
                        clean = false;
                    }
                }
                if !clean {
                    if let Some(parent) = &parent {
                        parent.0.cleanup_failed.store(true, Ordering::SeqCst);
                    }
                }
                Err(format!(
                    "{error}; owned_host_child_reaped={clean}; remote_cleanup=unconfirmed"
                ))
            }
        }
    });
    let result = supervisor.await.map_err(|e| e.to_string())?;
    // Keep the cancellation sender alive across the complete supervisor await.
    drop(caller.0);
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn deadline_pending_wait_and_retry_share_one_clock() {
        let d = Deadline::new(Duration::from_millis(40));
        let start = Instant::now();
        d.run(async {
            tokio::time::sleep(Duration::from_millis(15)).await;
            Ok(())
        })
        .await
        .unwrap();
        let left = d.remaining_ms().unwrap();
        assert!(left < 40);
        let e = d
            .run(std::future::pending::<Result<(), String>>())
            .await
            .unwrap_err();
        assert!(e.contains("parent_deadline_exhausted"));
        assert!(start.elapsed() < Duration::from_secs(1));
        assert!(d.run(async { Ok(()) }).await.is_err());
    }
    #[cfg(unix)]
    #[tokio::test]
    async fn deadline_owned_subprocess_group_is_killed_and_reaped_on_cancel() {
        let root = std::env::temp_dir().join(format!("deadline-{}", Uuid::new_v4()));
        std::fs::create_dir(&root).unwrap();
        let marker = root.join("should-never-write");
        let pidfile = root.join("pid");
        let ready = root.join("descendant-ready");
        let release = root.join("release");
        let mut command = Command::new("sh");
        // Controlled local fixture, not adb or a device. Child's child inherits pipes.
        command
            .arg("-c")
            .arg("echo $$ > \"$1\"; (echo ready > \"$3\"; while [ ! -f \"$4\" ]; do sleep 0.005; done; echo leaked > \"$2\") & wait")
            .arg("fixture")
            .arg(&pidfile)
            .arg(&marker)
            .arg(&ready)
            .arg(&release);
        let d = Deadline::new(Duration::from_secs(2));
        let cancel = d.clone();
        let ready_copy = ready.clone();
        let cancellation = tokio::spawn(async move {
            for _ in 0..100 {
                if ready_copy.exists() {
                    cancel.cancel();
                    return;
                }
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
            panic!("fixture failed to start");
        });
        let e = d
            .run(output(&mut command, Duration::from_secs(10)))
            .await
            .unwrap_err();
        cancellation.await.unwrap();
        assert!(e.contains("parent_cancelled"));
        assert!(e.contains("owned_host_children_reaped=true"), "{e}");
        let pid: u32 = std::fs::read_to_string(pidfile)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        let status = std::process::Command::new("kill")
            .args(["-0", &pid.to_string()])
            .stderr(Stdio::null())
            .status()
            .unwrap();
        assert!(!status.success(), "owned leader was not reaped");
        std::fs::write(&release, b"release").unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(!marker.exists(), "owned descendant survived cancellation");
        std::fs::remove_dir_all(root).unwrap();
    }
    #[cfg(unix)]
    #[tokio::test]
    async fn deadline_expired_child_pipe_and_wait_are_bounded() {
        let d = Deadline::new(Duration::from_millis(40));
        let mut command = Command::new("sh");
        // Leader exits but child retains stdout. We must not reap leader before EOF.
        command.args(["-c", "sleep 30 & exit 0"]);
        let e = d
            .run(output(&mut command, Duration::from_secs(60)))
            .await
            .unwrap_err();
        assert!(e.contains("parent_deadline_exhausted"));
        assert!(e.contains("owned_host_children_reaped=true"), "{e}");
    }
    #[cfg(unix)]
    fn stream_fixture() -> Command {
        let mut command = Command::new("sh");
        command.args(["-c", "sleep 30 & printf '%s\\n' $$; wait"]);
        command
    }
    #[cfg(unix)]
    async fn stream_until_eof(
        stdout: tokio::process::ChildStdout,
        started: tokio::sync::oneshot::Sender<u32>,
    ) -> Result<Vec<u8>, String> {
        use tokio::io::{AsyncBufReadExt, AsyncReadExt, BufReader};
        let mut reader = BufReader::new(stdout);
        let mut line = String::new();
        reader
            .read_line(&mut line)
            .await
            .map_err(|e| e.to_string())?;
        started
            .send(
                line.trim()
                    .parse()
                    .map_err(|e: std::num::ParseIntError| e.to_string())?,
            )
            .map_err(|_| "fixture receiver closed".to_string())?;
        let mut bytes = Vec::new();
        reader
            .read_to_end(&mut bytes)
            .await
            .map_err(|e| e.to_string())?;
        Ok(bytes)
    }
    #[cfg(unix)]
    fn assert_stream_leader_reaped(pid: u32) {
        let status = std::process::Command::new("kill")
            .args(["-0", &pid.to_string()])
            .stderr(Stdio::null())
            .status()
            .unwrap();
        assert!(!status.success(), "owned stream leader was not reaped");
    }
    #[cfg(unix)]
    #[tokio::test]
    async fn stream_success_preserves_bytes_and_parent_scope() {
        use tokio::io::AsyncReadExt;
        let d = Deadline::new(Duration::from_secs(3));
        let mut command = Command::new("sh");
        command.args(["-c", "printf 'verified-stream'"]);
        let bytes = d
            .run(stream_output(
                command,
                Duration::from_secs(2),
                |mut stdout| async move {
                    assert!(current().is_some(), "stream consumer lost its parent scope");
                    let mut bytes = Vec::new();
                    stdout
                        .read_to_end(&mut bytes)
                        .await
                        .map_err(|e| e.to_string())?;
                    Ok(bytes)
                },
            ))
            .await
            .unwrap();
        assert_eq!(bytes, b"verified-stream");
        assert_eq!(d.0.children.load(Ordering::SeqCst), 0);
        assert!(!d.0.cleanup_failed.load(Ordering::SeqCst));
    }
    #[cfg(unix)]
    #[tokio::test]
    async fn stream_parser_error_kills_and_reaps_its_child() {
        use tokio::io::{AsyncBufReadExt, BufReader};
        let d = Deadline::new(Duration::from_secs(3));
        let (started, pid) = tokio::sync::oneshot::channel();
        let error = d
            .run(stream_output(
                stream_fixture(),
                Duration::from_secs(2),
                |stdout| async move {
                    let mut reader = BufReader::new(stdout);
                    let mut line = String::new();
                    reader
                        .read_line(&mut line)
                        .await
                        .map_err(|e| e.to_string())?;
                    started.send(line.trim().parse::<u32>().unwrap()).unwrap();
                    Err::<(), _>("fixture SHA mismatch".to_string())
                },
            ))
            .await
            .unwrap_err();
        assert!(error.contains("fixture SHA mismatch"));
        assert!(error.contains("owned_host_child_reaped=true"), "{error}");
        assert_stream_leader_reaped(pid.await.unwrap());
        assert_eq!(d.0.children.load(Ordering::SeqCst), 0);
    }
    #[cfg(unix)]
    #[tokio::test]
    async fn stream_local_timeout_bounds_inherited_pipe_and_wait() {
        let d = Deadline::new(Duration::from_secs(3));
        let (started, pid) = tokio::sync::oneshot::channel();
        let mut command = Command::new("sh");
        command.args(["-c", "sleep 30 & printf '%s\\n' $$; exit 0"]);
        let start = Instant::now();
        let error = d
            .run(stream_output(
                command,
                Duration::from_millis(200),
                |stdout| stream_until_eof(stdout, started),
            ))
            .await
            .unwrap_err();
        assert!(error.contains("command_timeout"), "{error}");
        assert!(error.contains("owned_host_child_reaped=true"), "{error}");
        assert!(start.elapsed() < Duration::from_secs(2));
        assert_stream_leader_reaped(pid.await.unwrap());
        assert_eq!(d.0.children.load(Ordering::SeqCst), 0);
    }
    #[cfg(unix)]
    #[tokio::test]
    async fn stream_parent_cancel_waits_for_owned_reaping() {
        let d = Deadline::new(Duration::from_secs(3));
        let cancel = d.clone();
        let (started, pid) = tokio::sync::oneshot::channel();
        let cancellation = tokio::spawn(async move {
            let pid = pid.await.unwrap();
            cancel.cancel();
            pid
        });
        let error = d
            .run(stream_output(
                stream_fixture(),
                Duration::from_secs(2),
                |stdout| stream_until_eof(stdout, started),
            ))
            .await
            .unwrap_err();
        assert!(error.contains("parent_cancelled"), "{error}");
        assert!(error.contains("owned_host_children_reaped=true"), "{error}");
        assert_stream_leader_reaped(cancellation.await.unwrap());
        assert_eq!(d.0.children.load(Ordering::SeqCst), 0);
    }
    #[cfg(unix)]
    #[tokio::test]
    async fn stream_caller_drop_notifies_independent_owner() {
        let root = std::env::temp_dir().join(format!("stream-caller-{}", Uuid::new_v4()));
        std::fs::create_dir(&root).unwrap();
        let marker = root.join("should-never-write");
        let ready = root.join("descendant-ready");
        let release = root.join("release");
        let mut command = Command::new("sh");
        command
            .arg("-c")
            .arg("(echo ready > \"$2\"; while [ ! -f \"$3\" ]; do sleep 0.005; done; echo leaked > \"$1\") & printf '%s\\n' $$; wait")
            .arg("fixture")
            .arg(&marker)
            .arg(&ready)
            .arg(&release);
        let d = Deadline::new(Duration::from_secs(3));
        let parent = d.clone();
        let (started, pid) = tokio::sync::oneshot::channel();
        let caller = tokio::spawn(async move {
            CURRENT
                .scope(
                    parent,
                    stream_output(command, Duration::from_secs(2), |stdout| {
                        stream_until_eof(stdout, started)
                    }),
                )
                .await
        });
        let pid = pid.await.unwrap();
        tokio::time::timeout(Duration::from_secs(1), async {
            while !ready.exists() {
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        })
        .await
        .unwrap();
        caller.abort();
        assert!(caller.await.unwrap_err().is_cancelled());
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let changed = d.0.changed.notified();
                tokio::pin!(changed);
                changed.as_mut().enable();
                if d.0.children.load(Ordering::SeqCst) == 0 {
                    break;
                }
                changed.await;
            }
        })
        .await
        .unwrap();
        assert_stream_leader_reaped(pid);
        assert!(!d.0.cleanup_failed.load(Ordering::SeqCst));
        std::fs::write(&release, b"release").unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(
            !marker.exists(),
            "owned stream descendant survived caller drop"
        );
        std::fs::remove_dir_all(root).unwrap();
    }
    #[cfg(unix)]
    #[tokio::test]
    async fn stream_nonzero_source_exit_does_not_report_success() {
        use tokio::io::AsyncReadExt;
        let mut command = Command::new("sh");
        command.args(["-c", "printf 'verified-prefix'; exit 17"]);
        let error = stream_output(command, Duration::from_secs(2), |mut stdout| async move {
            let mut bytes = Vec::new();
            stdout
                .read_to_end(&mut bytes)
                .await
                .map_err(|e| e.to_string())?;
            assert_eq!(bytes, b"verified-prefix");
            Ok(bytes)
        })
        .await
        .unwrap_err();
        assert!(error.contains("stream source command failed"), "{error}");
        assert!(error.contains("17"), "{error}");
    }

    #[tokio::test]
    async fn deadline_restart_never_reconstructs_clock_from_unix_time() {
        assert!(Deadline::lookup(None).is_err());
        assert!(Deadline::lookup(Some(Uuid::new_v4())).is_err());
    }
    #[tokio::test]
    async fn deadline_blocking_io_counterexample_is_detected_but_not_preempted() {
        let d = Deadline::new(Duration::from_millis(10));
        let start = Instant::now();
        let e = d
            .run(async {
                std::thread::sleep(Duration::from_millis(60));
                Ok(())
            })
            .await
            .unwrap_err();
        assert!(is_stop(&e));
        assert!(start.elapsed() >= Duration::from_millis(60));
        // Intentional negative guarantee: synchronous blocked IO cannot be killed by a Future.
    }
}

#[cfg(test)]
mod manual_time_v5_deadline {
    use super::*;
    #[tokio::test]
    async fn outer_parent_cancel_reaps_phase_owned_stream_and_shared_counter() {
        use tokio::io::AsyncReadExt;
        let parent = Deadline::new(Duration::from_secs(10));
        let phase = parent.before_parent_remaining(1000).unwrap();
        assert!(Arc::ptr_eq(&parent.0.children, &phase.0.children));
        assert!(Arc::ptr_eq(
            &parent.0.cleanup_failed,
            &phase.0.cleanup_failed
        ));
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
        let outer = parent.clone();
        let task = tokio::spawn(async move {
            outer
                .run(async move {
                    phase
                        .run(async move {
                            let mut cmd = Command::new("/bin/sh");
                            cmd.args(["-c", "printf x; sleep 30"]);
                            stream_output(
                                cmd,
                                Duration::from_secs(30),
                                move |mut stdout| async move {
                                    let mut b = [0u8; 1];
                                    stdout.read_exact(&mut b).await.map_err(|e| e.to_string())?;
                                    let _ = ready_tx.send(());
                                    let mut rest = Vec::new();
                                    stdout
                                        .read_to_end(&mut rest)
                                        .await
                                        .map_err(|e| e.to_string())?;
                                    Ok::<(), String>(())
                                },
                            )
                            .await
                        })
                        .await
                })
                .await
        });
        tokio::time::timeout(Duration::from_secs(3), ready_rx)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(parent.0.children.load(Ordering::SeqCst), 1);
        parent.cancel();
        let error = tokio::time::timeout(Duration::from_secs(3), task)
            .await
            .unwrap()
            .unwrap()
            .unwrap_err();
        assert!(error.contains("parent_cancelled"));
        assert!(error.contains("owned_host_children_reaped=true"));
        assert_eq!(parent.0.children.load(Ordering::SeqCst), 0);
        assert!(!parent.0.cleanup_failed.load(Ordering::SeqCst));
    }
    #[tokio::test]
    async fn fixed_phase_timeout_preserves_accepted_prefix_and_reaps_child() {
        use tokio::io::AsyncReadExt;
        let parent = Deadline::new(Duration::from_millis(200));
        let phase = parent.before_parent_remaining(150).unwrap();
        let prefix = Arc::new(Mutex::new(Vec::new()));
        let accepted = Arc::clone(&prefix);
        let result = parent
            .run(phase.run(async move {
                let mut cmd = Command::new("/bin/sh");
                cmd.args(["-c", "printf retained; sleep 30"]);
                stream_output(cmd, Duration::from_secs(30), move |mut stdout| async move {
                    let mut b = [0u8; 8];
                    stdout.read_exact(&mut b).await.map_err(|e| e.to_string())?;
                    accepted.lock().unwrap().extend_from_slice(&b);
                    let mut rest = Vec::new();
                    stdout
                        .read_to_end(&mut rest)
                        .await
                        .map_err(|e| e.to_string())?;
                    Ok::<(), String>(())
                })
                .await
            }))
            .await;
        assert!(result.unwrap_err().contains("parent_deadline_exhausted"));
        assert_eq!(prefix.lock().unwrap().as_slice(), b"retained");
        assert_eq!(parent.0.children.load(Ordering::SeqCst), 0);
        assert!(parent.check().is_ok());
    }
    #[test]
    fn original_instant_clipping_is_fixed_and_failed_cleanup_propagates() {
        let parent = Deadline::new(Duration::from_millis(100));
        let phase = parent.before_parent_remaining(20).unwrap();
        let original = phase.0.at;
        std::thread::sleep(Duration::from_millis(10));
        assert_eq!(parent.before_parent_remaining(20).unwrap().0.at, original);
        phase.0.cleanup_failed.store(true, Ordering::SeqCst);
        assert!(parent.0.cleanup_failed.load(Ordering::SeqCst));
        parent.cancel();
        assert!(phase.check().unwrap_err().contains("parent_cancelled"));
    }
}
