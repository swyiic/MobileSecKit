//! Exact-file, parent-owned local purge inventory. Never follow evidence references.
use super::*;
use std::fs::{self, Metadata};

const FILE_CAP: usize = 100_000;
const BYTE_CAP: u64 = 16 * 1024 * 1024 * 1024;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Entry {
    pub path: String,
    pub kind: String,
    pub logical_bytes: u64,
    pub allocated_bytes: Option<u64>,
    pub files: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub(super) struct Fingerprint {
    bytes: u64,
    modified_ns: u128,
    dev: u64,
    ino: u64,
    links: u64,
    allocated: Option<u64>,
    sha256: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(super) struct Item {
    pub root: String,
    pub relative: String,
    fingerprint: Fingerprint,
    // Set and durably saved before this particular path is unlinked. Absent
    // paths on retry are never reported as newly freed bytes.
    pub attempted: bool,
    pub removed: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub(super) struct Snapshot {
    pub entries: Vec<Entry>,
    pub items: Vec<Item>,
    pub imported_roots: Vec<String>,
    pub source_aliases: BTreeMap<String, String>,
    pub warnings: Vec<String>,
}

pub(super) fn read_group_candidate(p: &Path) -> Result<Group, String> {
    read_group_at(p, false)
}
pub(super) fn read_group(p: &Path) -> Result<Group, String> {
    read_group_at(p, true)
}
fn read_group_at(p: &Path, strict: bool) -> Result<Group, String> {
    safe_path(p)?;
    let value: Group = serde_json::from_str(&read_bounded_text(p, 1024 * 1024)?)
        .map_err(|e| format!("主会话清单无效：{e}"))?;
    value.validate()?;
    if strict {
        ensure_inactive(&value)?;
    } else {
        ensure_purge_candidate(&value)?;
    }
    Ok(value)
}

pub(super) fn ensure_purge_candidate(g: &Group) -> Result<(), String> {
    ensure_inactive_at(g, false)
}
pub(super) fn ensure_inactive(g: &Group) -> Result<(), String> {
    ensure_inactive_at(g, true)
}
fn ensure_inactive_at(g: &Group, strict: bool) -> Result<(), String> {
    if !["planned", "succeeded", "failed", "partial", "cancelled"].contains(&g.state.as_str()) {
        return Err("主会话正在运行或状态未知；未清理".into());
    }
    for a in g.stages.iter().flat_map(|s| &s.attempts) {
        if a.finished_unix_ms.is_none()
            || !["succeeded", "failed", "partial", "cancelled"].contains(&a.state.as_str())
        {
            return Err("存在运行中或未确认终态的 attempt；未清理".into());
        }
        let never_started = a.session_id.is_none()
            && a.remote_artifact_root.is_none()
            && g.budget.as_ref().is_some_and(|b| {
                b.reservations
                    .iter()
                    .any(|r| r.id == a.relation.attempt_id.to_string() && r.status == "not_started")
            });
        if !never_started && !strict {
            let relation = if g.unified && a.relation.stage_key != "dump" {
                &g.stages[0]
                    .attempts
                    .get((a.relation.attempt - 1) as usize)
                    .ok_or("统一 controller 证据缺失")?
                    .relation
            } else {
                &a.relation
            };
            let note = purge_device::original_lifecycle(g, relation)?;
            validate_remote_lifecycle(&note, relation)?;
            if note["collection_returned"] != true
                || note["cleanup"] != "producer_scope_returned"
                || note["target_pause"] != "forbidden"
            {
                return Err("原 producer 返回/清理状态未知，不能重建清理资格".into());
            }
        }
        if strict
            && !never_started
            && !a
                .remote_lifecycle
                .as_ref()
                .is_some_and(remote_terminal_confirmed)
        {
            return Err("producer 退出/清理收据未知；须先确认远端封存，不能永久清理".into());
        }
    }
    Ok(())
}

fn identity_matches(a: &Group, b: &Group) -> bool {
    a.id == b.id
        && a.serial == b.serial
        && a.package == b.package
        && a.created_unix_ms == b.created_unix_ms
}

pub(super) fn safe_path(p: &Path) -> Result<PathBuf, String> {
    use std::path::Component;
    if !p.is_absolute()
        || p.components()
            .any(|c| matches!(c, Component::ParentDir | Component::CurDir))
    {
        return Err("清理路径必须是无跳转的绝对路径".into());
    }
    let m = fs::symlink_metadata(p).map_err(|e| format!("无法确认路径 {}：{e}", p.display()))?;
    if m.file_type().is_symlink() || !(m.is_file() || m.is_dir()) {
        return Err(format!("清理路径含链接或特殊文件：{}", p.display()));
    }
    let canonical = p.canonicalize().map_err(|e| e.to_string())?;
    // System aliases in the initial source path are resolved once. Every
    // destructive operation later traverses this canonical path with openat.
    Ok(canonical)
}

fn same_metadata(a: &Metadata, f: &Fingerprint) -> bool {
    let m = metadata_fingerprint(a);
    m.bytes == f.bytes
        && m.modified_ns == f.modified_ns
        && m.dev == f.dev
        && m.ino == f.ino
        && m.allocated == f.allocated
}
fn metadata_fingerprint(m: &Metadata) -> Fingerprint {
    #[cfg(unix)]
    let (dev, ino, links, allocated) = {
        use std::os::unix::fs::MetadataExt;
        (
            m.dev(),
            m.ino(),
            m.nlink(),
            Some(m.blocks().saturating_mul(512)),
        )
    };
    #[cfg(not(unix))]
    let (dev, ino, links, allocated) = (0, 0, 0, None);
    Fingerprint {
        bytes: m.len(),
        modified_ns: m
            .modified()
            .ok()
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map(|d| d.as_nanos())
            .unwrap_or(0),
        dev,
        ino,
        links,
        allocated,
        sha256: String::new(),
    }
}
fn same_fingerprint(a: &Fingerprint, b: &Fingerprint) -> bool {
    a.bytes == b.bytes
        && a.modified_ns == b.modified_ns
        && a.dev == b.dev
        && a.ino == b.ino
        && a.allocated == b.allocated
        && a.sha256 == b.sha256
}
fn fingerprint_file(mut file: File) -> Result<Fingerprint, String> {
    let before = file.metadata().map_err(|e| e.to_string())?;
    if !before.is_file() {
        return Err("清理对象不是普通文件".into());
    }
    let mut f = metadata_fingerprint(&before);
    let mut hash = Sha256::new();
    let mut buf = [0; 65536];
    let mut total = 0u64;
    loop {
        let n = std::io::Read::read(&mut file, &mut buf).map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        }
        total = total.checked_add(n as u64).ok_or("清理文件大小溢出")?;
        if total > f.bytes {
            return Err("清理对象在读取时增长；请重新预览".into());
        }
        hash.update(&buf[..n]);
    }
    if total != f.bytes || !same_metadata(&file.metadata().map_err(|e| e.to_string())?, &f) {
        return Err("清理对象在读取时变更；请重新预览".into());
    }
    f.sha256 = format!("{:x}", hash.finalize());
    Ok(f)
}

// Scope is the named evidence tree only, never paths mentioned in reports.
// Unknown top-level content is retained instead of guessed to be disposable.
fn known_evidence_path(rel: &str, g: &Group) -> bool {
    let mut parts = rel.split('/');
    let first = parts.next().unwrap_or("");
    if first == "sessions" {
        return parts
            .next()
            .and_then(|s| Uuid::parse_str(s).ok())
            .is_some_and(|id| g.session_ids().contains(&id))
            && matches!(
                parts.next(),
                Some("capture-relation.json" | "session-report.json" | "events.json")
            )
            && parts.next().is_none();
    }
    if rel.contains('/') {
        return [
            "runtime",
            "apk-dex",
            "apk-assets",
            "lib",
            "oat",
            "readable-dex",
            "code-evidence",
            "dex-classification",
            "metadata",
            "repaired",
        ]
        .contains(&first);
    }
    [
        "capture-group.json",
        "capture-relation.json",
        "dump-report.json",
        "bounded-code-report.json",
        "session-report.json",
        "session-index.json",
        "CAPTURE.txt",
        "HOWTO.txt",
        "EVIDENCE.txt",
        "static-references.json",
        "runtime-dex-verification.json",
        "archive-output-limits.json",
        "archive-cache-identity.json",
        "transfer-reference.json",
        "dump-trace.json",
        "memory-index.json",
    ]
    .contains(&rel)
        || (rel.starts_with("transport-partial-") && rel.ends_with(".json"))
        || (rel.starts_with("archive-content-references-") && rel.ends_with(".json"))
}

#[cfg(target_os = "linux")]
fn reject_nested_mounts(root: &Path) -> Result<(), String> {
    let text = fs::read_to_string("/proc/self/mountinfo")
        .map_err(|e| format!("无法确认清理目录挂载边界：{e}"))?;
    reject_mountinfo(root, &text)
}
#[cfg(target_os = "linux")]
fn reject_mountinfo(root: &Path, text: &str) -> Result<(), String> {
    if text.is_empty() || text.len() > 8 * 1024 * 1024 {
        return Err("挂载清单缺失/超限".into());
    }
    for line in text.lines() {
        let encoded = line.split_whitespace().nth(4).ok_or("挂载清单格式未知")?;
        let decoded = encoded
            .replace("\\040", " ")
            .replace("\\011", "\t")
            .replace("\\012", "\n")
            .replace("\\134", "\\");
        let mount = Path::new(&decoded);
        if !mount.is_absolute() {
            return Err("挂载清单路径未知".into());
        }
        if mount.starts_with(root) {
            return Err("清理来源包含挂载点（含 bind mount）；保留并拒绝".into());
        }
    }
    Ok(())
}
#[cfg(target_os = "macos")]
fn reject_nested_mounts(root: &Path) -> Result<(), String> {
    use std::os::unix::ffi::OsStrExt;
    // Use an owned snapshot; getmntinfo's shared static buffer can be replaced
    // by another thread and is unsuitable across concurrent preview requests.
    let count = unsafe { libc::getfsstat(std::ptr::null_mut(), 0, libc::MNT_NOWAIT) };
    if count <= 0 || count > 16384 {
        return Err("无法确认清理目录挂载边界".into());
    }
    let capacity = (count as usize).checked_add(16).ok_or("挂载清单过大")?;
    let mut entries: Vec<libc::statfs> = Vec::with_capacity(capacity);
    let bytes = capacity
        .checked_mul(std::mem::size_of::<libc::statfs>())
        .ok_or("挂载清单过大")?;
    let filled =
        unsafe { libc::getfsstat(entries.as_mut_ptr(), bytes as libc::c_int, libc::MNT_NOWAIT) };
    if filled <= 0 || filled as usize >= capacity {
        return Err("挂载清单在读取期间变更/超限".into());
    }
    // SAFETY: getfsstat initialized exactly filled entries within capacity.
    unsafe {
        entries.set_len(filled as usize);
    }
    for item in &entries {
        let name = unsafe { std::ffi::CStr::from_ptr(item.f_mntonname.as_ptr()) };
        if Path::new(std::ffi::OsStr::from_bytes(name.to_bytes())).starts_with(root) {
            return Err("清理来源包含挂载点；保留并拒绝".into());
        }
    }
    Ok(())
}
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn reject_nested_mounts(_root: &Path) -> Result<(), String> {
    Err("此平台不能核实清理挂载边界".into())
}

fn walk(root: &Path, dir: &Path, out: &mut Vec<PathBuf>) -> Result<(), String> {
    for item in fs::read_dir(dir).map_err(|e| e.to_string())? {
        let p = item.map_err(|e| e.to_string())?.path();
        if out.len() >= FILE_CAP {
            return Err("本地清理清单超出 100000 文件上限".into());
        }
        let m = fs::symlink_metadata(&p).map_err(|e| e.to_string())?;
        if m.file_type().is_symlink() || !(m.is_file() || m.is_dir()) {
            return Err(format!("证据内含链接/特殊文件，未清理：{}", p.display()));
        }
        if !p
            .canonicalize()
            .map_err(|e| e.to_string())?
            .starts_with(root)
        {
            return Err("证据目录越出原始来源".into());
        }
        if m.is_dir() {
            walk(root, &p, out)?;
        } else {
            out.push(p);
        }
    }
    Ok(())
}

pub(super) fn inspect(root: &Path, g: &Group, sources: &[String]) -> Result<Snapshot, String> {
    inspect_at(root, g, sources, true)
}
pub(super) fn inspect_candidate(
    root: &Path,
    g: &Group,
    sources: &[String],
) -> Result<Snapshot, String> {
    inspect_at(root, g, sources, false)
}
fn inspect_at(
    root: &Path,
    g: &Group,
    sources: &[String],
    strict: bool,
) -> Result<Snapshot, String> {
    if strict {
        ensure_inactive(g)?;
    } else {
        ensure_purge_candidate(g)?;
    }
    if sources.len() > 128 {
        return Err("选中的导入目录过多".into());
    }
    let mut out = Snapshot::default();
    let mut known = BTreeSet::new();
    let managed = path(root, g.id);
    if managed.try_exists().map_err(|e| e.to_string())? {
        let current = if strict {
            read_group(&managed)?
        } else {
            read_group_candidate(&managed)?
        };
        if !identity_matches(&current, g) {
            return Err("本地主会话身份冲突".into());
        }
        add_item(
            &mut out,
            &safe_path(root)?,
            managed
                .file_name()
                .unwrap()
                .to_str()
                .ok_or("路径编码无效")?,
            "parent_manifest",
        )?;
    }
    // Only an already verified parent-owned trash marker may be removed.
    let marker = root.join("trash").join(format!("{}.json", g.id));
    if marker.try_exists().map_err(|e| e.to_string())? {
        let entry = trash::read_entry(root, g.id)?;
        if !identity_matches(&entry.group, g) {
            return Err("回收站身份冲突".into());
        }
        add_item(
            &mut out,
            &safe_path(&root.join("trash"))?,
            &format!("{}.json", g.id),
            "trash_marker",
        )?;
    }
    let app_root = safe_path(root)?;
    for source in sources {
        let original_source = source.clone();
        let source = safe_path(Path::new(source))?;
        if !source.is_dir()
            || source == app_root
            || source.starts_with(&app_root)
            || app_root.starts_with(&source)
            || source.parent().is_none()
        {
            return Err("导入来源不能是应用目录、其父目录或根目录".into());
        }
        out.source_aliases
            .insert(original_source, source.to_string_lossy().into_owned());
        if !known.insert(source.clone()) {
            continue;
        }
        if known
            .iter()
            .any(|p| p != &source && (p.starts_with(&source) || source.starts_with(p)))
        {
            return Err("选中的导入目录相互重叠".into());
        }
        reject_nested_mounts(&source)?;
        let imported = if strict {
            read_group(&source.join("capture-group.json"))?
        } else {
            read_group_candidate(&source.join("capture-group.json"))?
        };
        if !identity_matches(&imported, g) {
            return Err("导入来源不属于所选父会话/设备".into());
        }
        if source
            .join("capture-relation.json")
            .try_exists()
            .map_err(|e| e.to_string())?
        {
            safe_path(&source.join("capture-relation.json"))?;
            read_import(&source)?.ok_or("导入原始归属清单缺失")?;
        }
        for stage in &imported.stages {
            let matched = g
                .stages
                .iter()
                .find(|s| s.id == stage.id && s.key == stage.key)
                .ok_or("导入 stage 与原父会话冲突")?;
            for attempt in &stage.attempts {
                if !matched.attempts.iter().any(|a| {
                    a.relation == attempt.relation
                        && a.session_id == attempt.session_id
                        && a.remote_artifact_root == attempt.remote_artifact_root
                }) {
                    return Err("导入 attempt 与原父会话来源冲突".into());
                }
            }
        }
        if !imported.session_ids().is_subset(&g.session_ids()) {
            return Err("导入来源含未在原父清单确认的子会话；请先对齐清单".into());
        }
        let report_path = if source.join("dump-report.json").is_file() {
            source.join("dump-report.json")
        } else {
            source.join("bounded-code-report.json")
        };
        safe_path(&report_path)?;
        let report: Value =
            serde_json::from_str(&read_bounded_text(&report_path, 64 * 1024 * 1024)?)
                .map_err(|e| e.to_string())?;
        if report["package"]
            .as_str()
            .or_else(|| report["identity"]["package"].as_str())
            != Some(g.package.as_str())
        {
            return Err("证据报告包身份不符".into());
        }
        let mut files = vec![];
        walk(&source, &source, &mut files)?;
        files.sort();
        let mut retained = 0;
        for p in files {
            let rel = p
                .strip_prefix(&source)
                .map_err(|e| e.to_string())?
                .to_str()
                .ok_or("路径编码无效")?;
            if rel.ends_with("capture-group.json") && rel != "capture-group.json" {
                return Err("来源包含嵌套父会话；不能猜测共享目录归属".into());
            }
            if known_evidence_path(rel, &imported) {
                if rel.starts_with("sessions/") && rel.ends_with("capture-relation.json") {
                    let id = Uuid::parse_str(rel.split('/').nth(1).unwrap())
                        .map_err(|e| e.to_string())?;
                    let note: Value = serde_json::from_str(&read_bounded_text(&p, 32768)?)
                        .map_err(|e| e.to_string())?;
                    verify_session_relation(&imported, id, &note)?;
                }
                add_item(&mut out, &source, rel, "imported_evidence")?;
            } else {
                retained += 1;
            }
        }
        if retained > 0 {
            return Err(format!("来源 {} 含 {retained} 个非支持证据文件（APK 原件、私有数据或未知文件）；保留整个来源，请取消该目录选择后重试", source.display()));
        }
        let after = if strict {
            read_group(&source.join("capture-group.json"))?
        } else {
            read_group_candidate(&source.join("capture-group.json"))?
        };
        if serde_json::to_value(&after).map_err(|e| e.to_string())?
            != serde_json::to_value(&imported).map_err(|e| e.to_string())?
        {
            return Err("导入父清单在预览期间改变".into());
        }
        read_import(&source)?.ok_or("导入归属清单缺失")?;
        out.imported_roots
            .push(source.to_string_lossy().into_owned());
    }
    out.items.sort_by_key(|item| {
        (
            item.relative.ends_with("capture-group.json")
                || item.root == app_root.to_string_lossy(),
            item.root.clone(),
            item.relative.clone(),
        )
    });
    out.warnings.push(
        "只删除清单内路径；外部原始 APK、应用私有文件、导出归档及共享内容池不在范围内".into(),
    );
    if out.items.iter().any(|i| i.fingerprint.links > 1) {
        out.warnings.push(
            "存在硬链接共享内容：仅移除所选路径，不修改其他引用；共享部分不计为释放空间".into(),
        );
    }
    Ok(out)
}
fn add_item(out: &mut Snapshot, root: &Path, rel: &str, kind: &str) -> Result<(), String> {
    validate_evidence_relative_path(rel)?;
    if out.items.len() >= FILE_CAP {
        return Err("清理文件数超上限".into());
    }
    let fp = fingerprint_file(secure::open_file(root, rel)?)?;
    let bytes = out
        .items
        .iter()
        .try_fold(fp.bytes, |n, i| n.checked_add(i.fingerprint.bytes))
        .ok_or("清理总量溢出")?;
    if bytes > BYTE_CAP {
        return Err("本地清理超出 16GiB 安全上限，请分批选择来源".into());
    }
    out.entries.push(Entry {
        path: root.join(rel).to_string_lossy().into_owned(),
        kind: kind.into(),
        logical_bytes: fp.bytes,
        allocated_bytes: fp.allocated,
        files: 1,
    });
    out.items.push(Item {
        root: root.to_string_lossy().into_owned(),
        relative: rel.into(),
        fingerprint: fp,
        attempted: false,
        removed: false,
    });
    Ok(())
}

pub(super) fn selected_roots(snapshot: &Snapshot) -> Vec<String> {
    snapshot
        .imported_roots
        .iter()
        .cloned()
        .chain(snapshot.source_aliases.keys().cloned())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

/// Reject corrupted/restored records before they can become filesystem authority.
/// The journal is app-private; these checks bind every file to the original
/// declared source root and parent ID instead of trusting arbitrary Item paths.
pub(super) fn validate_snapshot(
    managed: &Path,
    group: &Group,
    snapshot: &Snapshot,
) -> Result<(), String> {
    if snapshot.items.len() > FILE_CAP
        || snapshot.entries.len() != snapshot.items.len()
        || snapshot.imported_roots.len() > 128
    {
        return Err("清理日志范围超限/不完整".into());
    }
    let managed = safe_path(managed)?;
    let trash = managed.join("trash");
    let mut sources = BTreeSet::new();
    for source in &snapshot.imported_roots {
        let p = Path::new(source);
        if !p.is_absolute()
            || p.components().any(|c| {
                matches!(
                    c,
                    std::path::Component::ParentDir | std::path::Component::CurDir
                )
            })
            || p.parent().is_none()
            || p.starts_with(&managed)
            || managed.starts_with(p)
            || !sources.insert(source.clone())
        {
            return Err("清理日志来源不安全/重复".into());
        }
        if p.try_exists().map_err(|e| e.to_string())? && safe_path(p)? != p {
            return Err("清理日志来源已变为路径别名".into());
        }
    }
    if snapshot.source_aliases.len() > 128 {
        return Err("清理日志路径别名过多".into());
    }
    for (alias, canonical) in &snapshot.source_aliases {
        let alias_path = Path::new(alias);
        if !sources.contains(canonical)
            || !alias_path.is_absolute()
            || alias_path.components().any(|c| {
                matches!(
                    c,
                    std::path::Component::ParentDir | std::path::Component::CurDir
                )
            })
            || (alias_path.try_exists().map_err(|e| e.to_string())?
                && safe_path(alias_path)? != Path::new(canonical))
        {
            return Err("清理日志来源别名指向已改变".into());
        }
    }
    let entries = snapshot
        .entries
        .iter()
        .map(|e| (e.path.as_str(), e))
        .collect::<BTreeMap<_, _>>();
    if entries.len() != snapshot.entries.len() {
        return Err("清理日志存在重复显示路径".into());
    }
    let mut seen = BTreeSet::new();
    let mut total = 0u64;
    for item in &snapshot.items {
        validate_evidence_relative_path(&item.relative)?;
        let root = Path::new(&item.root);
        let owned = if root == managed || root == trash {
            item.relative == format!("{}.json", group.id)
        } else {
            sources.contains(&item.root) && known_evidence_path(&item.relative, group)
        };
        let p = root.join(&item.relative).to_string_lossy().into_owned();
        let entry = entries.get(p.as_str()).ok_or("清理日志缺少精确显示路径")?;
        if !owned
            || !seen.insert(p)
            || entry.files != 1
            || entry.logical_bytes != item.fingerprint.bytes
            || item.fingerprint.sha256.len() != 64
            || !item
                .fingerprint
                .sha256
                .bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
        {
            return Err("清理日志文件越界/身份冲突".into());
        }
        total = total
            .checked_add(item.fingerprint.bytes)
            .ok_or("清理日志总量溢出")?;
    }
    if total > BYTE_CAP {
        return Err("清理日志总量超限".into());
    }
    Ok(())
}

pub(super) fn verify(snapshot: &Snapshot) -> Result<(), String> {
    for root in snapshot
        .items
        .iter()
        .filter(|i| !i.removed)
        .map(|i| i.root.as_str())
        .collect::<BTreeSet<_>>()
    {
        reject_nested_mounts(Path::new(root))?;
    }
    for item in snapshot.items.iter().filter(|i| !i.removed) {
        let file = match secure::open_file(Path::new(&item.root), &item.relative) {
            Ok(file) => file,
            Err(_)
                if item.attempted
                    && !Path::new(&item.root)
                        .join(&item.relative)
                        .try_exists()
                        .map_err(|e| e.to_string())? =>
            {
                continue
            }
            Err(e) => return Err(e),
        };
        if !same_fingerprint(&fingerprint_file(file)?, &item.fingerprint) {
            return Err(format!("清理预览已过期，文件变更：{}", item.relative));
        }
    }
    Ok(())
}

/// Returns verified unlinked allocation (not disk free-space delta). The caller
/// must save `attempted=true` before calling and `removed=true` afterwards.
pub(super) fn remove(item: &Item) -> Result<Option<u64>, String> {
    reject_nested_mounts(Path::new(&item.root))?;
    let path = Path::new(&item.root).join(&item.relative);
    if !path.try_exists().map_err(|e| e.to_string())? {
        if item.attempted {
            return Ok(None);
        }
        return Err("清理对象在执行前消失；请重新预览".into());
    }
    let file = secure::open_file(Path::new(&item.root), &item.relative)?;
    if !same_fingerprint(&fingerprint_file(file)?, &item.fingerprint) {
        return Err("清理对象已变化；保留并停止".into());
    }
    let allocation = secure::unlink(Path::new(&item.root), &item.relative, &item.fingerprint)?;
    if path.try_exists().map_err(|e| e.to_string())? {
        return Err("删除后路径仍存在；结果未确认".into());
    }
    Ok(allocation)
}

#[cfg(unix)]
mod secure {
    use super::*;
    use std::{
        ffi::CString,
        os::{
            fd::{AsRawFd, FromRawFd},
            unix::ffi::OsStrExt,
        },
    };
    fn component(s: &std::ffi::OsStr) -> Result<CString, String> {
        CString::new(s.as_bytes()).map_err(|_| "文件名含 NUL".into())
    }
    fn child(parent: &File, name: &std::ffi::OsStr, directory: bool) -> Result<File, String> {
        let name = component(name)?;
        let flags = libc::O_RDONLY
            | libc::O_NOFOLLOW
            | libc::O_CLOEXEC
            | if directory { libc::O_DIRECTORY } else { 0 };
        // SAFETY: name is terminated; fd ownership is transferred only on success.
        let fd = unsafe { libc::openat(parent.as_raw_fd(), name.as_ptr(), flags) };
        if fd < 0 {
            return Err(format!(
                "安全打开清理路径失败：{}",
                std::io::Error::last_os_error()
            ));
        }
        Ok(unsafe { File::from_raw_fd(fd) })
    }
    fn parent(root: &Path, rel: &str) -> Result<(File, CString), String> {
        validate_evidence_relative_path(rel)?;
        if !root.is_absolute() {
            return Err("非绝对根".into());
        }
        let mut current = File::open("/").map_err(|e| e.to_string())?;
        for part in root.components() {
            match part {
                std::path::Component::RootDir => {}
                std::path::Component::Normal(name) => {
                    current = child(&current, name, true)?;
                }
                _ => return Err("不安全根组件".into()),
            }
        }
        let relative = Path::new(rel);
        if let Some(dir) = relative.parent() {
            for part in dir.components() {
                if let std::path::Component::Normal(name) = part {
                    current = child(&current, name, true)?;
                } else {
                    return Err("不安全子目录".into());
                }
            }
        }
        Ok((current, component(relative.file_name().ok_or("缺文件名")?)?))
    }
    pub(super) fn open_file(root: &Path, rel: &str) -> Result<File, String> {
        let (parent, name) = parent(root, rel)?;
        let fd = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(format!(
                "安全读取清理对象失败：{}",
                std::io::Error::last_os_error()
            ));
        }
        Ok(unsafe { File::from_raw_fd(fd) })
    }
    pub(super) fn unlink(
        root: &Path,
        rel: &str,
        expected: &Fingerprint,
    ) -> Result<Option<u64>, String> {
        let (parent, name) = parent(root, rel)?;
        let fd = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error().to_string());
        }
        let file = unsafe { File::from_raw_fd(fd) };
        let current = file.metadata().map_err(|e| e.to_string())?;
        if !same_metadata(&current, expected) {
            return Err("清理对象身份已变更".into());
        }
        let live = metadata_fingerprint(&current);
        let allocation = live.allocated.map(|n| if live.links == 1 { n } else { 0 });
        if unsafe { libc::unlinkat(parent.as_raw_fd(), name.as_ptr(), 0) } != 0 {
            return Err(std::io::Error::last_os_error().to_string());
        }
        parent.sync_all().map_err(|e| e.to_string())?;
        Ok(allocation)
    }
}
#[cfg(not(unix))]
mod secure {
    use super::*;
    pub(super) fn open_file(_root: &Path, _rel: &str) -> Result<File, String> {
        Err("此平台尚无安全目录句柄清理实现；未清理".into())
    }
    pub(super) fn unlink(
        _root: &Path,
        _rel: &str,
        _expected: &Fingerprint,
    ) -> Result<Option<u64>, String> {
        Err("此平台不支持永久清理".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    pub(super) struct Fixture(pub PathBuf);
    impl Fixture {
        pub(super) fn new() -> Self {
            let p = std::env::temp_dir().join(format!("me-purge-test-{}", Uuid::new_v4()));
            fs::create_dir_all(p.join("managed")).unwrap();
            Self(p)
        }
        fn group(&self) -> Group {
            let g = super::super::tests::group();
            save(&self.0.join("managed"), &g).unwrap();
            g
        }
        fn evidence(&self, g: &Group, name: &str) -> PathBuf {
            let p = self.0.join(name);
            fs::create_dir_all(p.join("runtime")).unwrap();
            fs::write(p.join("capture-group.json"), serde_json::to_vec(g).unwrap()).unwrap();
            fs::write(
                p.join("dump-report.json"),
                serde_json::to_vec(
                    &serde_json::json!({"package":g.package,"dump_id":Uuid::new_v4()}),
                )
                .unwrap(),
            )
            .unwrap();
            fs::write(
                p.join("runtime/bounded-fixture.code"),
                b"synthetic evidence only",
            )
            .unwrap();
            p
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    #[test]
    fn exact_local_inventory_and_unlink_preserve_neighbor_and_external_original() {
        let f = Fixture::new();
        let g = f.group();
        let source = f.evidence(&g, "source");
        let neighbor = f.evidence(&g, "unselected");
        let original = f.0.join("original.apk");
        fs::write(&original, b"untouched").unwrap();
        let mut snap = inspect(
            &f.0.join("managed"),
            &g,
            &[source.to_string_lossy().into_owned()],
        )
        .unwrap();
        assert_eq!(snap.items.len(), 4);
        verify(&snap).unwrap();
        for item in &mut snap.items {
            item.attempted = true;
            remove(item).unwrap();
            item.removed = true;
        }
        assert!(!path(&f.0.join("managed"), g.id).exists());
        assert!(!source.join("runtime/bounded-fixture.code").exists());
        assert_eq!(fs::read(original).unwrap(), b"untouched");
        assert!(neighbor.join("capture-group.json").exists());
        verify(&snap).unwrap();
    }
    #[test]
    fn unknown_and_apk_private_content_never_deleted() {
        for name in ["personal.txt", "apk/original.apk", "data-private/user.db"] {
            let f = Fixture::new();
            let g = f.group();
            let p = f.evidence(&g, "source");
            let extra = p.join(name);
            fs::create_dir_all(extra.parent().unwrap()).unwrap();
            fs::write(&extra, b"not cleanup-owned").unwrap();
            assert!(inspect(
                &f.0.join("managed"),
                &g,
                &[p.to_string_lossy().into_owned()]
            )
            .is_err());
            assert!(extra.exists());
            assert!(path(&f.0.join("managed"), g.id).exists());
        }
    }
    #[test]
    fn same_package_foreign_parent_and_traversal_fail_closed() {
        let f = Fixture::new();
        let a = f.group();
        let mut b = a.clone();
        b.id = Uuid::new_v4();
        let p = f.evidence(&b, "other");
        assert!(inspect(
            &f.0.join("managed"),
            &a,
            &[p.to_string_lossy().into_owned()]
        )
        .is_err());
        assert!(safe_path(&p.join("../other")).is_err());
        assert!(inspect(
            &f.0.join("managed"),
            &a,
            &[f.0.to_string_lossy().into_owned()]
        )
        .is_err());
    }
    #[test]
    fn unknown_running_and_unconfirmed_attempts_are_protected() {
        let f = Fixture::new();
        let mut g = f.group();
        let relation = g.start("l0", epoch()).unwrap();
        assert!(ensure_inactive(&g).is_err());
        g.finish(
            &relation,
            Some(Uuid::new_v4()),
            None,
            Some("failure".into()),
        )
        .unwrap();
        assert!(ensure_inactive(&g).is_err());
        g.state = "unknown".into();
        assert!(ensure_inactive(&g).is_err());
    }
    #[test]
    fn content_change_same_size_invalidates_preview() {
        let f = Fixture::new();
        let g = f.group();
        let p = f.evidence(&g, "source");
        let snap = inspect(
            &f.0.join("managed"),
            &g,
            &[p.to_string_lossy().into_owned()],
        )
        .unwrap();
        fs::write(
            p.join("runtime/bounded-fixture.code"),
            b"changed!! evidence only",
        )
        .unwrap();
        assert!(verify(&snap).is_err());
        assert!(path(&f.0.join("managed"), g.id).exists());
    }
    #[cfg(unix)]
    #[test]
    fn symlink_leaf_and_parent_swaps_never_follow_outside() {
        use std::os::unix::fs::symlink;
        let f = Fixture::new();
        let g = f.group();
        let p = f.evidence(&g, "source");
        let external = f.0.join("external");
        fs::create_dir(&external).unwrap();
        fs::write(external.join("bounded-fixture.code"), b"external original").unwrap();
        let snap = inspect(
            &f.0.join("managed"),
            &g,
            &[p.to_string_lossy().into_owned()],
        )
        .unwrap();
        fs::rename(p.join("runtime"), p.join("runtime-original")).unwrap();
        symlink(&external, p.join("runtime")).unwrap();
        assert!(verify(&snap).is_err());
        let item = snap
            .items
            .iter()
            .find(|i| i.relative.starts_with("runtime/"))
            .unwrap();
        assert!(remove(item).is_err());
        assert_eq!(
            fs::read(external.join("bounded-fixture.code")).unwrap(),
            b"external original"
        );
        assert!(inspect(
            &f.0.join("managed"),
            &g,
            &[p.to_string_lossy().into_owned()]
        )
        .is_err());
    }
    #[cfg(unix)]
    #[test]
    fn shared_hardlink_survives_and_new_link_never_claims_freed_allocation() {
        let f = Fixture::new();
        let g = f.group();
        let p = f.evidence(&g, "source");
        let mut snap = inspect(
            &f.0.join("managed"),
            &g,
            &[p.to_string_lossy().into_owned()],
        )
        .unwrap();
        let item = snap
            .items
            .iter_mut()
            .find(|i| i.relative.starts_with("runtime/"))
            .unwrap();
        let other = f.0.join("external-shared-object");
        fs::hard_link(p.join(&item.relative), &other).unwrap();
        item.attempted = true;
        assert_eq!(remove(item).unwrap(), Some(0));
        assert!(other.exists());
        assert_eq!(fs::read(other).unwrap(), b"synthetic evidence only");
    }
    #[test]
    fn idempotent_missing_only_after_durable_attempt_and_no_freed_claim() {
        let f = Fixture::new();
        let g = f.group();
        let mut snap = inspect(&f.0.join("managed"), &g, &[]).unwrap();
        let item = &mut snap.items[0];
        fs::remove_file(Path::new(&item.root).join(&item.relative)).unwrap();
        assert!(remove(item).is_err());
        item.attempted = true;
        assert_eq!(remove(item).unwrap(), None);
        verify(&snap).unwrap();
    }
    #[test]
    fn original_dump_owner_conflict_prevents_local_cleanup() {
        let f = Fixture::new();
        let g = f.group();
        let p = f.evidence(&g, "source");
        fs::write(p.join("capture-relation.json"),serde_json::to_vec(&serde_json::json!({
            "package":g.package,"relation":{"parent_id":Uuid::new_v4(),"stage_id":Uuid::new_v4(),"attempt_id":Uuid::new_v4(),"attempt":1,"stage_key":"dump"}})).unwrap()).unwrap();
        assert!(inspect(
            &f.0.join("managed"),
            &g,
            &[p.to_string_lossy().into_owned()]
        )
        .unwrap_err()
        .contains("关联"));
        assert!(p.join("runtime/bounded-fixture.code").exists());
    }
    #[cfg(target_os = "linux")]
    #[test]
    fn nested_same_device_bind_mount_is_rejected_from_synthetic_mountinfo() {
        let root = Path::new("/tmp/owned-evidence");
        let safe = "1 0 0:1 / / rw - overlay overlay rw\n2 1 0:2 / /tmp rw - tmpfs tmpfs rw\n";
        reject_mountinfo(root, safe).unwrap();
        let bad = format!(
            "{safe}3 2 0:2 /private-original /tmp/owned-evidence/runtime rw - tmpfs tmpfs rw\n"
        );
        assert!(reject_mountinfo(root, &bad).is_err());
        assert!(reject_mountinfo(root, "").is_err());
    }
    #[cfg(unix)]
    #[test]
    fn canonical_ancestor_alias_keeps_exact_user_selected_copy_identity() {
        use std::os::unix::fs::symlink;
        let f = Fixture::new();
        let g = f.group();
        let source = f.evidence(&g, "source");
        symlink(&f.0, f.0.join("alias-parent")).unwrap();
        let alias = f.0.join("alias-parent/source");
        let snap = inspect(
            &f.0.join("managed"),
            &g,
            &[alias.to_string_lossy().into_owned()],
        )
        .unwrap();
        assert!(selected_roots(&snap).contains(&alias.to_string_lossy().into_owned()));
        assert!(selected_roots(&snap).contains(
            &source
                .canonicalize()
                .unwrap()
                .to_string_lossy()
                .into_owned()
        ));
        validate_snapshot(&f.0.join("managed"), &g, &snap).unwrap();
    }
}
