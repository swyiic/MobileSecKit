//! Identity-bound, bounded cleanup of exact device files selected in a preview.
//!
//! No package-name discovery, recursive deletion, wildcard deletion, capture stop,
//! or app-private access. Control records and empty directories are retained so a
//! disconnected/partially completed operation can be verified and retried.
use super::*;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use sha2::{Digest, Sha256};
use std::future::Future;

const MAX_ENTRIES: usize = 4096;
const MAX_WIRE: usize = 2 * 1024 * 1024;
const MAX_RECORD: usize = 64 * 1024;
const MAX_ROOTS: usize = 128;
const STAT_FORMAT: &str = "%f:%d:%i:%h:%s:%b:%Y:%Z";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceSnapshot {
    pub parent_id: Uuid,
    pub serial: String,
    /// SHA-256 of ADB serial, hardware serial properties and OS build fingerprint.
    pub fingerprint: String,
    pub logical_bytes: u64,
    pub allocated_bytes: Option<u64>,
    pub roots: Vec<DeviceRoot>,
    pub preserved: Vec<String>,
    group: Group,
    identity_evidence: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceRoot {
    pub path: String,
    pub kind: String,
    pub logical_bytes: u64,
    pub allocated_bytes: Option<u64>,
    pub files: usize,
    relation: Relation,
    session_id: Option<Uuid>,
    /// The immutable owner/terminal JSON bytes are bound to preview inventory.
    evidence: BTreeMap<String, String>,
    entries: Vec<Entry>,
    absent: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct Entry {
    path: String,
    mode: u32,
    device: u64,
    inode: u64,
    links: u64,
    size: u64,
    blocks: u64,
    modified: i64,
    changed: i64,
    preserve: bool,
    sha256: Option<String>,
}
impl Entry {
    fn directory(&self) -> bool {
        self.mode & 0xf000 == 0x4000
    }
    fn stamp(&self) -> String {
        format!(
            "{:x}:{}:{}:{}:{}:{}:{}:{}",
            self.mode,
            self.device,
            self.inode,
            self.links,
            self.size,
            self.blocks,
            self.modified,
            self.changed
        )
    }
    fn same_identity(&self, other: &Self) -> bool {
        self.path == other.path
            && self.mode == other.mode
            && self.device == other.device
            && self.inode == other.inode
            && (self.directory() || self.stamp() == other.stamp() && self.sha256 == other.sha256)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceOutcome {
    pub status: String,
    pub logical_bytes_removed: u64,
    pub allocated_bytes_removed: Option<u64>,
    pub removed_files: usize,
    pub already_absent_files: usize,
    pub errors: Vec<String>,
}

fn clean_path(path: &str) -> bool {
    path.starts_with("/data/local/tmp/")
        && path.len() <= 1024
        && !path.ends_with('/')
        && !path.contains("//")
        && path.split('/').all(|c| c != "." && c != "..")
        && path
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"/._-".contains(&b))
}
fn runtime_root(group: &Group) -> Result<String, String> {
    if let Some(paths) = runtime_paths_from_group(Some(group))? {
        paths.validate()?;
        Ok(paths.root)
    } else {
        Ok("/data/local/tmp/ksight".into())
    }
}
/// st_dev alone cannot distinguish same-filesystem bind mounts. Read the
/// current shell namespace's mount table before scanning or unlinking. Kernel
/// mountinfo escapes whitespace/backslashes in fields; we deliberately keep
/// those bytes escaped. Our allowlisted paths contain none of those bytes, so
/// equality/ancestor checks stay literal, while descendants match before any
/// escaped component. No mount-derived text is evaluated or passed as a command.
fn mount_checks(path: &str) -> Result<String, String> {
    if !clean_path(path) {
        return Err("设备 mount 检查路径不在规范 allowlist 内".into());
    }
    Ok(format!(
        r#"# me-purge:mount-guard
me_mount_root={root}
[ -r /proc/self/mountinfo ] || exit 81
LC_ALL=C; export LC_ALL
me_mountinfo=$(head -c 1048577 /proc/self/mountinfo && printf '.') || exit 81
me_mountinfo=${{me_mountinfo%.}}
[ "${{#me_mountinfo}}" -le 1048576 ] || exit 81
case "$me_mountinfo" in *'
') me_mountinfo=${{me_mountinfo%?}};; *) exit 81;; esac
me_mount_count=0
while IFS=' ' read -r me_mid me_mparent me_mdev me_msource me_mpath me_mopts me_mrest; do
    [ -n "$me_mid" ] && [ -n "$me_mparent" ] && [ -n "$me_mopts" ] || exit 81
    case "$me_mid$me_mparent" in *[!0-9]*) exit 81;; esac
    case "$me_mdev" in *:*) ;; *) exit 81;; esac
    me_mmajor=${{me_mdev%%:*}}; me_mminor=${{me_mdev#*:}}
    [ -n "$me_mmajor" ] && [ -n "$me_mminor" ] || exit 81
    case "$me_mmajor$me_mminor" in *[!0-9]*) exit 81;; esac
    case "$me_msource" in /*) ;; *) exit 81;; esac
    case "$me_mpath" in /*) ;; *) exit 81;; esac
    case " $me_mrest " in *" - "*) ;; *) exit 81;; esac
    me_mount_count=$((me_mount_count + 1))
    [ "$me_mount_count" -le 4096 ] || exit 81
    case "$me_mpath" in "$me_mount_root"|"$me_mount_root"/*) exit 82;; esac
    case "$me_mpath" in
        /data/local/tmp|/data/local/tmp/*)
            case "$me_mount_root" in "$me_mpath"/*) exit 82;; esac;;
    esac
done <<__ME_MOUNTINFO__
$me_mountinfo
__ME_MOUNTINFO__
[ "$me_mount_count" -gt 0 ] || exit 81
unset me_mountinfo
"#,
        root = crate::shell_quote(path)
    ))
}

fn canonical_checks(path: &str, allow_absent_leaf: bool) -> Result<String, String> {
    if !clean_path(path) {
        return Err("设备清理路径不在规范 allowlist 内".into());
    }
    let mut script = String::new();
    let mut current = String::new();
    for component in path.split('/').filter(|c| !c.is_empty()) {
        current.push('/');
        current.push_str(component);
        let q = crate::shell_quote(&current);
        script.push_str(&format!("[ ! -L {q} ] || exit 71\n"));
        if allow_absent_leaf {
            // Missing ancestors are allowed only for retry, but existing symlink
            // ancestors (including dangling links) are rejected independently.
            script.push_str(&format!(
                "if [ -e {q} ]; then [ \"$(readlink -f {q})\" = {q} ] || exit 72; fi\n"
            ));
        } else {
            script.push_str(&format!("[ \"$(readlink -f {q})\" = {q} ] || exit 72\n"));
        }
    }
    Ok(script)
}
fn expected_roots(group: &Group) -> Result<Vec<DeviceRoot>, String> {
    group.validate()?;
    if matches!(group.state.as_str(), "running" | "unknown") {
        return Err("设备清理禁止运行中/未知主会话".into());
    }
    let base = runtime_root(group)?;
    let mut roots = BTreeMap::new();
    for stage in &group.stages {
        for (index, attempt) in stage.attempts.iter().enumerate() {
            if matches!(attempt.state.as_str(), "running" | "unknown") {
                return Err("设备清理禁止运行中/未知 attempt".into());
            }

            let relation = if group.unified && stage.key != "dump" {
                &group.stages[0]
                    .attempts
                    .get(index)
                    .ok_or("统一 controller 缺失")?
                    .relation
            } else {
                &attempt.relation
            };
            let lifecycle = attempt
                .remote_lifecycle
                .as_ref()
                .ok_or("设备终态缺少证据，清理已阻止")?;
            validate_remote_lifecycle(lifecycle, relation)?;
            if !remote_terminal_confirmed(lifecycle) {
                return Err("设备 producer 返回/退出未知，清理已阻止".into());
            }
            if attempt.session_id.is_none() && attempt.remote_artifact_root.is_none() {
                return Err("attempt 缺少可验证设备文件身份，未按目录名猜测清理范围".into());
            }
            if let Some(session_id) = attempt.session_id {
                let path = format!("{base}/spool/{session_id}");
                let root = roots.entry(path.clone()).or_insert_with(|| DeviceRoot {
                    path,
                    kind: "sessionSpool".into(),
                    logical_bytes: 0,
                    allocated_bytes: Some(0),
                    files: 0,
                    relation: relation.clone(),
                    session_id: Some(session_id),
                    evidence: BTreeMap::new(),
                    entries: vec![],
                    absent: false,
                });
                if root.relation != *relation {
                    return Err("共享 spool 的 controller 归属冲突".into());
                }
            }
            if let Some(path) = &attempt.remote_artifact_root {
                let expected = format!(
                    "{base}/captures/{}/{}/{}/dump",
                    group.id, stage.id, attempt.relation.attempt_id
                );
                if stage.key != "dump" || path != &expected || !clean_path(path) {
                    return Err("设备 artifact root 不符合 manifest UUID/attempt allowlist；不支持按包名清理".into());
                }
                if roots
                    .insert(
                        path.clone(),
                        DeviceRoot {
                            path: path.clone(),
                            kind: "dumpArtifacts".into(),
                            logical_bytes: 0,
                            allocated_bytes: Some(0),
                            files: 0,
                            relation: relation.clone(),
                            session_id: None,
                            evidence: BTreeMap::new(),
                            entries: vec![],
                            absent: false,
                        },
                    )
                    .is_some()
                {
                    return Err("重复设备 artifact root".into());
                }
            }
        }
    }
    if roots.len() > MAX_ROOTS {
        return Err("设备清理 roots 超过128上限".into());
    }
    Ok(roots.into_values().collect())
}

fn transport_offline(text: &str) -> bool {
    text.contains("device offline")
        || text.contains("device not found")
        || text.contains("no devices/emulators found")
        || (text.contains("device '") && text.contains("' not found"))
}

async fn adb(serial: &str, script: String) -> Result<crate::RawOutput, String> {
    // No auto-discovery/reconnect to a different serial and no global selection.
    // Preserve the distinct offline classification only for recognized transport errors.
    let command = format!("su -c {}", crate::shell_quote(&script));
    crate::run_device_adb_with_timeout(
        serial,
        &["shell", &command],
        Duration::from_secs(30),
        "会话设备清理",
    )
    .await
    .map_err(|error| {
        let lower = error.to_ascii_lowercase();
        if transport_offline(&lower) {
            format!("device_offline: {error}")
        } else {
            error
        }
    })
}
fn checked_output(output: crate::RawOutput, limit: usize) -> Result<String, String> {
    if output.code == Some(81) {
        return Err(
            "设备 mountinfo 不可读/格式未知/超预算，无法排除 bind mount，清理已阻止".into(),
        );
    }
    if output.code == Some(82) {
        return Err("设备会话路径与挂载点重叠（含同文件系统 bind mount），清理已阻止".into());
    }
    if output.code != Some(0) {
        let msg = format!("{} {}", output.stderr, output.stdout);
        let lower = msg.to_ascii_lowercase();
        if transport_offline(&lower) {
            return Err(format!("device_offline: {}", msg.trim()));
        }
        return Err(format!(
            "设备身份/权限/规范路径检查失败（{:?}）: {}",
            output.code,
            msg.chars().take(256).collect::<String>()
        ));
    }
    if output.stdout.len() > limit {
        return Err("设备预览响应超出有界预算".into());
    }
    Ok(output.stdout)
}
fn identity_script() -> String {
    "# me-purge:identity\nprintf 'MEIDENTITY'; for key in ro.serialno ro.boot.serialno ro.build.fingerprint; do printf '|'; getprop \"$key\" | tr -d '\\r\\n' | base64 | tr -d '\\r\\n'; done; printf '\\n'".into()
}
fn parse_identity(serial: &str, text: &str) -> Result<String, String> {
    let fields = text.trim().split('|').collect::<Vec<_>>();
    if fields.len() != 4 || fields[0] != "MEIDENTITY" {
        return Err("设备稳定身份不可读".into());
    }
    let values = fields[1..]
        .iter()
        .map(|s| {
            STANDARD
                .decode(s)
                .map_err(|_| "设备稳定身份编码无效".to_string())
                .and_then(|b| String::from_utf8(b).map_err(|_| "设备稳定身份格式无效".to_string()))
        })
        .collect::<Result<Vec<_>, _>>()?;
    if values
        .iter()
        .any(|v| v.len() > 512 || v.chars().any(char::is_control))
        || (values[0].is_empty() && values[1].is_empty())
        || values[2].is_empty()
    {
        return Err("硬件序列号/构建指纹缺失，不能确认配对手机".into());
    }
    let bytes = serde_json::to_vec(&(serial, &values)).map_err(|e| e.to_string())?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}
fn lifecycle_script(group: &Group, relation: &Relation) -> Result<String, String> {
    let base = runtime_root(group)?;
    let path = format!(
        "{base}/captures/{}/{}/{}/control",
        relation.parent_id, relation.stage_id, relation.attempt_id
    );
    let mut script = format!("# me-purge:lifecycle\n{}", canonical_checks(&path, false)?);
    let command = format!("{KSIGHT_AGENT} capture-control --parent-session {} --stage-id {} --attempt-id {} --stage-attempt {} --stage-key {} --action status",
        relation.parent_id, relation.stage_id, relation.attempt_id, relation.attempt, relation.stage_key);
    script.push_str(&runtime_paths::route(
        runtime_paths_from_group(Some(group))?.as_ref(),
        &command,
    )?);
    Ok(script)
}
async fn check_lifecycles<F, Fut>(
    group: &Group,
    roots: &[DeviceRoot],
    rpc: &mut F,
) -> Result<(), String>
where
    F: FnMut(String) -> Fut,
    Fut: Future<Output = Result<crate::RawOutput, String>>,
{
    let mut seen = BTreeSet::new();
    for root in roots {
        if !seen.insert(root.relation.attempt_id) {
            continue;
        }
        let response = rpc(lifecycle_script(group, &root.relation)?).await?;
        if response.code != Some(0) {
            return Err(checked_output(response, MAX_REMOTE_CONTROL_BYTES).unwrap_err());
        }
        let note = decode_remote_lifecycle(&response, &root.relation)?;
        if !remote_terminal_confirmed(&note) {
            return Err("设备正在运行或终态未知，清理已阻止".into());
        }
        let original = group
            .stages
            .iter()
            .flat_map(|s| &s.attempts)
            .find(|a| a.relation == root.relation)
            .and_then(|a| a.remote_lifecycle.as_ref())
            .ok_or("设备 controller 身份证据缺失")?;
        if note["token"] != original["token"] {
            return Err("设备生命周期 token 已变化，清理已阻止".into());
        }
    }
    Ok(())
}
fn inventory_script(path: &str) -> Result<String, String> {
    let q = crate::shell_quote(path);
    // find never follows links. The path is encoded independently of its bytes,
    // so newlines/tabs cannot inject a second inventory record. A terminal marker
    // and bounded head make truncation/error a hard failure, never an empty tree.
    Ok(format!(
        r#"# me-purge:inventory
{mount_guard}
{checks}
if [ ! -e {q} ]; then printf 'MEABSENT\n'; exit 0; fi
[ -d {q} ] || exit 73
(
find {q} -xdev -exec sh -c 'for p do s=$(stat -c "{stat}" "$p") || exit 74; h="-"; if [ -f "$p" ] && [ ! -L "$p" ]; then h=$(sha256sum "$p") || exit 74; h=${{h%% *}}; fi; [ "$s" = "$(stat -c "{stat}" "$p")" ] || exit 74; n=$(printf "%s" "$p" | base64 | tr -d "\r\n") || exit 74; printf "MEENTRY|%s|%s|%s\n" "$n" "$s" "$h"; done' sh {{}} +
s=$?; printf 'MEEND|%s\n' "$s"
) | head -c {bound}
"#,
        checks = canonical_checks(path, true)?,
        mount_guard = mount_checks(path)?,
        stat = STAT_FORMAT,
        bound = MAX_WIRE + 1
    ))
}
fn parse_inventory(path: &str, text: &str) -> Result<Option<Vec<Entry>>, String> {
    if text.trim() == "MEABSENT" {
        return Ok(None);
    }
    if text.len() > MAX_WIRE || !text.trim_end().ends_with("MEEND|0") {
        return Err("设备目录清单不完整/超限，清理已阻止".into());
    }
    let mut entries = BTreeMap::new();
    for line in text.lines().filter(|line| *line != "MEEND|0") {
        if entries.len() >= MAX_ENTRIES {
            return Err("设备清理超过4096条目上限".into());
        }
        let fields = line.split('|').collect::<Vec<_>>();
        if fields.len() != 4 || fields[0] != "MEENTRY" {
            return Err("设备目录清单格式无效".into());
        }
        let p = String::from_utf8(STANDARD.decode(fields[1]).map_err(|_| "设备路径编码无效")?)
            .map_err(|_| "设备路径编码无效")?;
        if !clean_path(&p) || !(p == path || p.starts_with(&format!("{path}/"))) {
            return Err("设备目录清单包含非规范/越界路径".into());
        }
        let nums = fields[2].split(':').collect::<Vec<_>>();
        if nums.len() != 8 {
            return Err("设备 stat 格式未知".into());
        }
        let unsigned = |i: usize| {
            nums[i]
                .parse::<u64>()
                .map_err(|_| "设备 stat 数值未知".to_string())
        };
        let entry = Entry {
            path: p.clone(),
            mode: u32::from_str_radix(nums[0], 16).map_err(|_| "设备 stat 类型未知")?,
            device: unsigned(1)?,
            inode: unsigned(2)?,
            links: unsigned(3)?,
            size: unsigned(4)?,
            blocks: unsigned(5)?,
            modified: nums[6].parse().map_err(|_| "设备 stat 时间未知")?,
            changed: nums[7].parse().map_err(|_| "设备 stat 时间未知")?,
            preserve: false,
            sha256: (fields[3] != "-").then(|| fields[3].into()),
        };
        if (!entry.directory()
            && entry.sha256.as_ref().is_none_or(|h| {
                h.len() != 64
                    || !h
                        .bytes()
                        .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
            }))
            || (entry.directory() && entry.sha256.is_some())
        {
            return Err("设备文件内容哈希缺失/无效".into());
        }
        if !matches!(entry.mode & 0xf000, 0x4000 | 0x8000) || entry.inode == 0 || entry.links == 0 {
            return Err("设备清理拒绝 symlink/特殊文件/未知 inode".into());
        }
        if entries.insert(p, entry).is_some() {
            return Err("设备清单有重复路径".into());
        }
    }
    let root = entries.get(path).ok_or("设备清单缺少根目录")?;
    if !root.directory() {
        return Err("设备根不是目录".into());
    }
    for entry in entries.values() {
        if entry.device != root.device {
            return Err("设备清理拒绝跨文件系统/mount".into());
        }
        if entry.path != path {
            let parent = entry.path.rsplit_once('/').unwrap().0;
            if !entries.get(parent).is_some_and(Entry::directory) {
                return Err("设备清单父目录缺失".into());
            }
        }
    }
    Ok(Some(entries.into_values().collect()))
}
fn evidence_script(path: &str) -> Result<String, String> {
    Ok(format!(
        "# me-purge:evidence\n{}head -c {} {}",
        canonical_checks(path, false)?,
        MAX_RECORD + 1,
        crate::shell_quote(path)
    ))
}
fn validate_evidence(group: &Group, root: &DeviceRoot) -> Result<(), String> {
    let owner: Value = serde_json::from_str(
        root.evidence
            .get("capture-relation.json")
            .ok_or("设备根缺少 capture-relation.json")?,
    )
    .map_err(|_| "设备 owner JSON 无效")?;
    if owner["relation"]["schema"] != "kernsight.capture-relation/v1" {
        return Err("未知设备 owner schema".into());
    }
    if let Some(session) = root.session_id {
        verify_session_relation(group, session, &owner)?;
        let manifest: Value = serde_json::from_str(
            root.evidence
                .get("session.json")
                .ok_or("设备 spool 缺少 session.json")?,
        )
        .map_err(|_| "设备 session manifest 无效")?;
        if manifest["session_id"] != session.to_string()
            || !matches!(
                manifest["state"].as_str(),
                Some("completed" | "interrupted" | "rotated" | "storage_limited")
            )
        {
            return Err("设备 session UUID/终态未知，清理已阻止".into());
        }
    } else {
        let r = &root.relation;
        let expected = serde_json::json!({"parent_id":r.parent_id,"stage_id":r.stage_id,"attempt_id":r.attempt_id,"attempt":r.attempt,"stage_key":r.stage_key});
        if !owner["session_id"].is_null()
            || owner["package"] != group.package
            || expected
                .as_object()
                .unwrap()
                .iter()
                .any(|(key, value)| owner["relation"][key] != *value)
        {
            return Err("设备 dump 归属与 parent/attempt/package 不符".into());
        }
    }
    Ok(())
}
fn summarize(root: &mut DeviceRoot) -> Result<(), String> {
    root.files = 0;
    root.logical_bytes = 0;
    root.allocated_bytes = Some(0);
    for entry in &root.entries {
        if entry.directory() || entry.preserve {
            continue;
        }
        root.files += 1;
        root.logical_bytes = root
            .logical_bytes
            .checked_add(entry.size)
            .ok_or("设备字节数溢出")?;
        root.allocated_bytes = Some(
            root.allocated_bytes
                .unwrap()
                .checked_add(entry.blocks.checked_mul(512).ok_or("设备块数溢出")?)
                .ok_or("设备块数溢出")?,
        );
    }
    Ok(())
}
fn snapshot(
    group: &Group,
    fingerprint: String,
    identity_evidence: String,
    roots: Vec<DeviceRoot>,
) -> Result<DeviceSnapshot, String> {
    let logical_bytes = roots.iter().try_fold(0u64, |n, r| {
        n.checked_add(r.logical_bytes).ok_or("设备总字节溢出")
    })?;
    let allocated_bytes = Some(roots.iter().try_fold(0u64, |n, r| {
        n.checked_add(r.allocated_bytes.unwrap_or(0))
            .ok_or("设备总块数溢出")
    })?);
    let mut preserved = vec![
        "原始安装 APK、App 私有目录、共享 CAS、生命周期 control 记录及空目录不在清理范围".into(),
    ];
    for root in &roots {
        for entry in root.entries.iter().filter(|e| e.preserve && !e.directory()) {
            preserved.push(format!("保留共享/归属元数据：{}", entry.path));
        }
    }
    Ok(DeviceSnapshot {
        parent_id: group.id,
        serial: group.serial.clone(),
        fingerprint,
        logical_bytes,
        allocated_bytes,
        roots,
        preserved,
        group: group.clone(),
        identity_evidence,
    })
}

/// Read-only preview. The caller retains this complete snapshot server-side and
/// binds confirmation to it; never execute a client-supplied file list.
pub async fn inspect(group: &Group) -> Result<DeviceSnapshot, String> {
    inspect_with(group, |script| adb(&group.serial, script)).await
}
async fn inspect_with<F, Fut>(group: &Group, mut rpc: F) -> Result<DeviceSnapshot, String>
where
    F: FnMut(String) -> Fut,
    Fut: Future<Output = Result<crate::RawOutput, String>>,
{
    let mut roots = expected_roots(group)?;
    let identity_evidence = checked_output(rpc(identity_script()).await?, 8192)?;
    let fingerprint = parse_identity(&group.serial, &identity_evidence)?;
    check_lifecycles(group, &roots, &mut rpc).await?;
    for root in &mut roots {
        let text = checked_output(rpc(inventory_script(&root.path)?).await?, MAX_WIRE)?;
        let Some(entries) = parse_inventory(&root.path, &text)? else {
            root.absent = true;
            continue;
        };
        root.entries = entries;
        let names = if root.session_id.is_some() {
            vec!["capture-relation.json", "session.json"]
        } else {
            vec!["capture-relation.json"]
        };
        for name in names {
            let path = format!("{}/{name}", root.path);
            let entry = root
                .entries
                .iter()
                .find(|e| e.path == path && !e.directory())
                .ok_or("设备归属文件缺失")?;
            if entry.size > MAX_RECORD as u64 || entry.links != 1 {
                return Err("设备归属文件超限或共享".into());
            }
            let data = checked_output(rpc(evidence_script(&path)?).await?, MAX_RECORD)?;
            root.evidence.insert(name.into(), data);
        }
        validate_evidence(group, root)?;
        // Shared hard links and potential shared-object namespaces are retained.
        // Their owner/terminal metadata remains with them as evidence.
        let shared = root
            .entries
            .iter()
            .any(|e| !e.directory() && (e.links != 1 || shared_namespace(&root.path, &e.path)));
        for entry in &mut root.entries {
            let name = entry.path.rsplit('/').next().unwrap_or("");
            entry.preserve = entry.directory()
                || entry.links != 1
                || shared_namespace(&root.path, &entry.path)
                || (shared && root.evidence.contains_key(name));
        }
        // A second inventory closes the read/stat window around ownership reads.
        let again = checked_output(rpc(inventory_script(&root.path)?).await?, MAX_WIRE)?;
        let again = parse_inventory(&root.path, &again)?.ok_or("设备根在预览期间消失")?;
        if root.entries.len() != again.len()
            || root
                .entries
                .iter()
                .zip(&again)
                .any(|(a, b)| !a.same_identity(b))
        {
            return Err("设备文件在预览期间改变，请重新预览".into());
        }
        summarize(root)?;
    }
    snapshot(group, fingerprint, identity_evidence, roots)
}
fn shared_namespace(root: &str, path: &str) -> bool {
    path.strip_prefix(&format!("{root}/")).is_some_and(|p| {
        p.split('/')
            .any(|c| matches!(c, "objects" | ".objects" | "cas" | ".cas"))
    })
}

/// Refresh only the remaining subset of the original confirmed inventory. New
/// files, changed identity, changed owner evidence, or lifecycle uncertainty fail
/// closed; an offline retry can never grow its deletion scope automatically.
pub async fn inspect_remaining(original: &DeviceSnapshot) -> Result<DeviceSnapshot, String> {
    remaining_with(original, |script| adb(&original.serial, script)).await
}
async fn remaining_with<F, Fut>(
    original: &DeviceSnapshot,
    mut rpc: F,
) -> Result<DeviceSnapshot, String>
where
    F: FnMut(String) -> Fut,
    Fut: Future<Output = Result<crate::RawOutput, String>>,
{
    validate_snapshot(original)?;
    let fingerprint = parse_identity(
        &original.serial,
        &checked_output(rpc(identity_script()).await?, 8192)?,
    )?;
    if fingerprint != original.fingerprint {
        return Err("配对手机稳定指纹已变化，清理已阻止".into());
    }
    check_lifecycles(&original.group, &original.roots, &mut rpc).await?;
    let mut roots = original.roots.clone();
    for root in &mut roots {
        let text = checked_output(rpc(inventory_script(&root.path)?).await?, MAX_WIRE)?;
        let current = parse_inventory(&root.path, &text)?.unwrap_or_default();
        let old: BTreeMap<_, _> = root.entries.iter().map(|e| (e.path.as_str(), e)).collect();
        for entry in &current {
            if !old
                .get(entry.path.as_str())
                .is_some_and(|before| before.same_identity(entry))
            {
                return Err("设备文件新增/替换/改变，原确认不再有效".into());
            }
        }
        for (name, expected) in &root.evidence {
            let path = format!("{}/{name}", root.path);
            if current.iter().any(|e| e.path == path) {
                let actual = checked_output(rpc(evidence_script(&path)?).await?, MAX_RECORD)?;
                if &actual != expected {
                    return Err("设备归属/终态 manifest 已改变".into());
                }
            } else if current.iter().any(|e| {
                !e.directory()
                    && !root
                        .evidence
                        .contains_key(e.path.rsplit('/').next().unwrap_or(""))
            }) {
                return Err("设备 owner 先于 payload 消失，清理已阻止".into());
            }
        }
        root.absent = current.is_empty();
        root.entries = current
            .into_iter()
            .map(|mut e| {
                e.preserve = old[e.path.as_str()].preserve;
                e
            })
            .collect();
        summarize(root)?;
    }
    snapshot(
        &original.group,
        fingerprint,
        original.identity_evidence.clone(),
        roots,
    )
}
pub(super) fn preview_entries(snapshot: &DeviceSnapshot) -> Vec<super::purge_local::Entry> {
    snapshot
        .roots
        .iter()
        .flat_map(|root| {
            root.entries
                .iter()
                .filter(|entry| !entry.directory() && !entry.preserve)
                .map(|entry| super::purge_local::Entry {
                    path: entry.path.clone(),
                    kind: root.kind.clone(),
                    logical_bytes: entry.size,
                    allocated_bytes: entry.blocks.checked_mul(512),
                    files: 1,
                })
        })
        .collect()
}

pub(super) fn matches_group(snapshot: &DeviceSnapshot, group: &Group) -> bool {
    snapshot.parent_id == group.id
        && snapshot.serial == group.serial
        && serde_json::to_value(&snapshot.group).ok() == serde_json::to_value(group).ok()
}

fn validate_snapshot(snapshot: &DeviceSnapshot) -> Result<(), String> {
    if snapshot.parent_id != snapshot.group.id || snapshot.serial != snapshot.group.serial {
        return Err("设备快照与主会话身份冲突".into());
    }
    if parse_identity(&snapshot.serial, &snapshot.identity_evidence)? != snapshot.fingerprint {
        return Err("设备快照稳定身份冲突".into());
    }
    let expected = expected_roots(&snapshot.group)?;
    if expected.len() != snapshot.roots.len() {
        return Err("设备快照范围冲突".into());
    }
    for (expected, root) in expected.iter().zip(&snapshot.roots) {
        if expected.path != root.path
            || expected.kind != root.kind
            || expected.relation != root.relation
            || expected.session_id != root.session_id
        {
            return Err("设备快照路径/关系冲突".into());
        }
        if root.entries.len() > MAX_ENTRIES {
            return Err("设备快照超限".into());
        }
        for entry in &root.entries {
            if !clean_path(&entry.path)
                || !(entry.path == root.path || entry.path.starts_with(&format!("{}/", root.path)))
                || !matches!(entry.mode & 0xf000, 0x4000 | 0x8000)
                || (!entry.preserve
                    && (entry.directory()
                        || entry.links != 1
                        || shared_namespace(&root.path, &entry.path)))
            {
                return Err("设备快照文件范围/类型冲突".into());
            }
        }
        if !root.evidence.is_empty() {
            validate_evidence(&snapshot.group, root)?;
        }
    }
    Ok(())
}
fn remove_script(
    root: &DeviceRoot,
    entry: &Entry,
    identity_evidence: &str,
) -> Result<String, String> {
    if entry.directory() || entry.preserve || entry.links != 1 {
        return Err("不能清理目录/共享文件".into());
    }
    let (parent, basename) = entry.path.rsplit_once('/').ok_or("文件父路径缺失")?;
    let parent_entry = root
        .entries
        .iter()
        .find(|e| e.path == parent && e.directory())
        .ok_or("文件父目录身份缺失")?;
    // cd pins the verified directory inode. All subsequent operations use one
    // validated basename; a parent-path replacement cannot redirect unlink.
    // rm never follows a replacement final symlink, and there is no rm -r/-f.
    let name = crate::shell_quote(&format!("./{basename}"));
    let identity_check = format!(
        "[ \"$({})\" = {} ] || exit 80\n",
        identity_script(),
        crate::shell_quote(identity_evidence.trim())
    );
    let hash = entry.sha256.as_ref().ok_or("设备文件内容哈希缺失")?;
    let hash_check = format!(
        "h=$(sha256sum {name}) || exit 76; h=${{h%% *}}; [ \"$h\" = {} ] || exit 76\n",
        crate::shell_quote(hash)
    );
    let mount_guard = mount_checks(&root.path)?;
    Ok(format!("# me-purge:remove\n{identity_check}{}cd -P {} || exit 75\n[ \"$(stat -c '%d:%i' .)\" = '{}:{}' ] || exit 75\nif [ ! -e {name} ] && [ ! -L {name} ]; then printf 'MEALREADY\\n'; exit 0; fi\n[ ! -L {name} ] && [ -f {name} ] || exit 76\n[ \"$(stat -c '{}' {name})\" = {} ] || exit 76\n{hash_check}{mount_guard}rm -- {name} || exit 78\n[ ! -e {name} ] && [ ! -L {name} ] || exit 79\nprintf 'MEREMOVED\\n'\n",
        canonical_checks(parent, false)?, crate::shell_quote(parent), parent_entry.device, parent_entry.inode, STAT_FORMAT, crate::shell_quote(&entry.stamp())))
}

/// Called only after explicit confirmation of a server-retained preview. Known
/// partial results are returned, so failures remain visible and retryable.
pub async fn execute(original: &DeviceSnapshot) -> Result<DeviceOutcome, String> {
    execute_with(original, |script| adb(&original.serial, script)).await
}
async fn execute_with<F, Fut>(
    original: &DeviceSnapshot,
    mut rpc: F,
) -> Result<DeviceOutcome, String>
where
    F: FnMut(String) -> Fut,
    Fut: Future<Output = Result<crate::RawOutput, String>>,
{
    let current = remaining_with(original, &mut rpc).await?;
    let original_count = original.roots.iter().map(|r| r.files).sum::<usize>();
    let current_count = current.roots.iter().map(|r| r.files).sum::<usize>();
    let mut outcome = DeviceOutcome {
        status: "completed".into(),
        logical_bytes_removed: 0,
        allocated_bytes_removed: Some(0),
        removed_files: 0,
        already_absent_files: original_count.saturating_sub(current_count),
        errors: vec![],
    };
    for root in &current.roots {
        // Revalidate live controller immediately before the first unlink in each
        // owned tree. Never signal/stop a producer as a side effect of deletion.
        if let Err(error) =
            check_lifecycles(&current.group, std::slice::from_ref(root), &mut rpc).await
        {
            outcome.errors.push(error);
            break;
        }
        let mut entries = root
            .entries
            .iter()
            .filter(|e| !e.directory() && !e.preserve)
            .collect::<Vec<_>>();
        entries.sort_by_key(|e| {
            let name = e.path.rsplit('/').next().unwrap_or("");
            // Remove owner last; preserve ownership evidence across all payload failures.
            (
                if name == "capture-relation.json" {
                    2
                } else if root.evidence.contains_key(name) {
                    1
                } else {
                    0
                },
                e.path.clone(),
            )
        });
        for entry in entries {
            let result = async {
                let output = rpc(remove_script(root, entry, &current.identity_evidence)?).await?;
                checked_output(output, 4096)
            }
            .await;
            match result.as_deref().map(str::trim) {
                Ok("MEREMOVED") => {
                    outcome.removed_files += 1;
                    outcome.logical_bytes_removed =
                        outcome.logical_bytes_removed.saturating_add(entry.size);
                    outcome.allocated_bytes_removed = outcome
                        .allocated_bytes_removed
                        .and_then(|n| entry.blocks.checked_mul(512).and_then(|b| n.checked_add(b)));
                }
                Ok("MEALREADY") => outcome.already_absent_files += 1,
                Ok(_) => {
                    outcome
                        .errors
                        .push(format!("{}: 删除回执未知；请重试核实", entry.path));
                    break;
                }
                Err(error) => {
                    outcome.errors.push(format!("{}: {error}", entry.path));
                    break;
                }
            }
        }
        if !outcome.errors.is_empty() {
            break;
        }
    }
    if !outcome.errors.is_empty() {
        outcome.status = "partial".into();
    }
    Ok(outcome)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::rc::Rc;

    fn terminal() -> Group {
        let mut group = super::super::tests::group();
        let relation = group.start("l0", epoch()).unwrap();
        group
            .finish(&relation, Some(Uuid::new_v4()), None, None)
            .unwrap();
        group.stages[0].attempts[0].remote_lifecycle = Some(serde_json::json!({
            "schema":"kernsight.capture-lifecycle/v1", "relation":{
                "parent_id":relation.parent_id,"stage_id":relation.stage_id,
                "attempt_id":relation.attempt_id,"attempt":relation.attempt,"stage_key":relation.stage_key},
            "token":Uuid::new_v4(), "target_pause":"forbidden", "collection_returned":true,
            "collection_status":"completed", "cleanup":"producer_scope_returned",
            "stop_request_recorded":false,"stop_acknowledged":false,"agent_exited_confirmed":true
        }));
        group
    }
    fn identity() -> String {
        format!(
            "MEIDENTITY|{}|{}|{}",
            STANDARD.encode("phone-123"),
            STANDARD.encode("boot-serial-123"),
            STANDARD.encode("test/device/build:version")
        )
    }
    fn output(text: String) -> crate::RawOutput {
        crate::RawOutput {
            stdout: text,
            stderr: String::new(),
            code: Some(0),
        }
    }
    fn directory(path: String, inode: u64) -> Entry {
        Entry {
            path,
            mode: 0x41c0,
            device: 10,
            inode,
            links: 2,
            size: 4096,
            blocks: 8,
            modified: 1,
            changed: 1,
            preserve: true,
            sha256: None,
        }
    }
    fn file(path: String, inode: u64, content: &str) -> Entry {
        Entry {
            path,
            mode: 0x8180,
            device: 10,
            inode,
            links: 1,
            size: content.len() as u64,
            blocks: 8,
            modified: 1,
            changed: 1,
            preserve: false,
            sha256: Some(format!("{:x}", Sha256::digest(content.as_bytes()))),
        }
    }
    fn inventory(entries: &[Entry]) -> String {
        entries
            .iter()
            .map(|e| {
                format!(
                    "MEENTRY|{}|{}|{}\n",
                    STANDARD.encode(&e.path),
                    e.stamp(),
                    e.sha256.as_deref().unwrap_or("-")
                )
            })
            .collect::<String>()
            + "MEEND|0\n"
    }
    struct Mock {
        group: Group,
        entries: Vec<Entry>,
        contents: BTreeMap<String, String>,
        identity: String,
        removed: Vec<String>,
        calls: Vec<String>,
        fail_after: Option<usize>,
    }
    impl Mock {
        fn new() -> Self {
            let group = terminal();
            let root = expected_roots(&group).unwrap().remove(0);
            let r = &root.relation;
            let owner = serde_json::json!({"session_id":root.session_id,"package":group.package,"relation":{
                "schema":"kernsight.capture-relation/v1","parent_id":r.parent_id,"stage_id":r.stage_id,
                "attempt_id":r.attempt_id,"attempt":r.attempt,"stage_key":r.stage_key}}).to_string();
            let session = serde_json::json!({"session_id":root.session_id,"state":"completed"})
                .to_string()
                + "\n";
            let contents: BTreeMap<String, String> = [
                ("capture-relation.json", owner),
                ("session.json", session),
                ("batch-000001.json.lz4", "fixture payload".into()),
            ]
            .into_iter()
            .map(|(name, data)| (format!("{}/{name}", root.path), data))
            .collect();
            let mut entries = vec![directory(root.path, 1)];
            entries.extend(
                contents
                    .iter()
                    .enumerate()
                    .map(|(i, (path, data))| file(path.clone(), i as u64 + 2, data)),
            );
            Self {
                group,
                entries,
                contents,
                identity: identity(),
                removed: vec![],
                calls: vec![],
                fail_after: None,
            }
        }
        fn call(&mut self, script: String) -> Result<crate::RawOutput, String> {
            self.calls.push(script.clone());
            if script.starts_with("# me-purge:identity\n") {
                return Ok(output(self.identity.clone()));
            }
            if script.starts_with("# me-purge:lifecycle\n") {
                return Ok(output(
                    self.group.stages[0].attempts[0]
                        .remote_lifecycle
                        .as_ref()
                        .unwrap()
                        .to_string(),
                ));
            }
            if script.starts_with("# me-purge:inventory\n") {
                return Ok(output(if self.entries.is_empty() {
                    "MEABSENT".into()
                } else {
                    inventory(&self.entries)
                }));
            }
            if script.starts_with("# me-purge:evidence\n") {
                let (_, data) = self
                    .contents
                    .iter()
                    .find(|(path, _)| {
                        script.contains(&format!(
                            "head -c {} {}",
                            MAX_RECORD + 1,
                            crate::shell_quote(path)
                        ))
                    })
                    .expect("exact known evidence path");
                return Ok(output(data.clone()));
            }
            if script.starts_with("# me-purge:remove\n") {
                if self.fail_after.is_some_and(|n| self.removed.len() >= n) {
                    return Err("device_offline: fixture disconnect".into());
                }
                let candidate = self
                    .entries
                    .iter()
                    .find(|e| {
                        script.contains(&format!(
                            "rm -- {}",
                            crate::shell_quote(&format!(
                                "./{}",
                                e.path.rsplit('/').next().unwrap()
                            ))
                        ))
                    })
                    .map(|e| e.path.clone());
                if let Some(path) = candidate {
                    self.entries.retain(|e| e.path != path);
                    self.contents.remove(&path);
                    self.removed.push(path);
                    return Ok(output("MEREMOVED".into()));
                }
                return Ok(output("MEALREADY".into()));
            }
            panic!("unknown mock operation");
        }
    }
    async fn preview(mock: &Rc<RefCell<Mock>>) -> DeviceSnapshot {
        let group = mock.borrow().group.clone();
        inspect_with(&group, |s| std::future::ready(mock.borrow_mut().call(s)))
            .await
            .unwrap()
    }
    #[tokio::test]
    async fn preview_is_read_only_and_counts_actual_logical_and_allocated_bytes() {
        let mock = Rc::new(RefCell::new(Mock::new()));
        let plan = preview(&mock).await;
        assert_eq!(plan.roots.len(), 1);
        assert_eq!(plan.roots[0].files, 3);
        assert_eq!(
            plan.logical_bytes,
            mock.borrow()
                .contents
                .values()
                .map(|s| s.len() as u64)
                .sum::<u64>()
        );
        assert_eq!(plan.allocated_bytes, Some(3 * 4096));
        assert!(mock.borrow().removed.is_empty());
        assert!(mock.borrow().calls.iter().all(|s| !s.contains("rm --")));
        assert!(plan.roots[0]
            .entries
            .iter()
            .filter(|e| !e.directory())
            .all(|e| e.sha256.is_some()));
    }
    #[tokio::test]
    async fn exact_execution_then_retry_is_idempotent_and_removes_owner_last() {
        let mock = Rc::new(RefCell::new(Mock::new()));
        let plan = preview(&mock).await;
        let first = execute_with(&plan, |s| std::future::ready(mock.borrow_mut().call(s)))
            .await
            .unwrap();
        assert_eq!(first.status, "completed");
        assert_eq!(first.removed_files, 3);
        assert_eq!(first.logical_bytes_removed, plan.logical_bytes);
        assert!(mock
            .borrow()
            .removed
            .last()
            .unwrap()
            .ends_with("capture-relation.json"));
        let retry = execute_with(&plan, |s| std::future::ready(mock.borrow_mut().call(s)))
            .await
            .unwrap();
        assert_eq!(retry.removed_files, 0);
        assert_eq!(retry.already_absent_files, 3);
    }
    #[tokio::test]
    async fn disconnect_returns_partial_and_retry_preserves_original_allowlist() {
        let mock = Rc::new(RefCell::new(Mock::new()));
        let plan = preview(&mock).await;
        mock.borrow_mut().fail_after = Some(1);
        let result = execute_with(&plan, |s| std::future::ready(mock.borrow_mut().call(s)))
            .await
            .unwrap();
        assert_eq!(result.status, "partial");
        assert_eq!(result.removed_files, 1);
        assert_eq!(result.errors.len(), 1);
        assert!(mock
            .borrow()
            .entries
            .iter()
            .any(|e| e.path.ends_with("capture-relation.json")));
        mock.borrow_mut().fail_after = None;
        let refreshed = remaining_with(&plan, |s| std::future::ready(mock.borrow_mut().call(s)))
            .await
            .unwrap();
        assert_eq!(refreshed.roots[0].files, 2);
        let result = execute_with(&refreshed, |s| {
            std::future::ready(mock.borrow_mut().call(s))
        })
        .await
        .unwrap();
        assert_eq!(result.status, "completed");
        assert_eq!(result.removed_files, 2);
    }
    #[tokio::test]
    async fn new_file_changed_hash_wrong_device_and_missing_owner_fail_closed() {
        for scenario in [
            "new-file",
            "same-stat-new-content",
            "wrong-device",
            "owner-missing",
            "running",
            "wrong-token",
        ] {
            let mock = Rc::new(RefCell::new(Mock::new()));
            let plan = preview(&mock).await;
            {
                let mut m = mock.borrow_mut();
                match scenario {
                    "new-file" => {
                        let path = format!("{}/foreign.bin", plan.roots[0].path);
                        m.entries.push(file(path, 80, "foreign"));
                    }
                    "same-stat-new-content" => {
                        m.entries
                            .iter_mut()
                            .find(|e| e.path.contains("batch-"))
                            .unwrap()
                            .sha256 = Some("f".repeat(64));
                    }
                    "wrong-device" => {
                        m.identity = format!(
                            "MEIDENTITY|{}||{}",
                            STANDARD.encode("other-phone"),
                            STANDARD.encode("test/device/build:version")
                        )
                    }
                    "owner-missing" => m
                        .entries
                        .retain(|e| !e.path.ends_with("capture-relation.json")),
                    "running" => {
                        m.group.stages[0].attempts[0]
                            .remote_lifecycle
                            .as_mut()
                            .unwrap()["agent_exited_confirmed"] = serde_json::json!(false)
                    }
                    "wrong-token" => {
                        m.group.stages[0].attempts[0]
                            .remote_lifecycle
                            .as_mut()
                            .unwrap()["token"] = serde_json::json!(Uuid::new_v4())
                    }
                    _ => unreachable!(),
                }
            }
            assert!(
                execute_with(&plan, |s| std::future::ready(mock.borrow_mut().call(s)))
                    .await
                    .is_err(),
                "{scenario}"
            );
            assert!(mock.borrow().removed.is_empty(), "{scenario}");
        }
    }
    #[tokio::test]
    async fn shared_links_preserve_payload_and_ownership_metadata() {
        let mock = Rc::new(RefCell::new(Mock::new()));
        mock.borrow_mut()
            .entries
            .iter_mut()
            .find(|e| e.path.contains("batch-"))
            .unwrap()
            .links = 2;
        let plan = preview(&mock).await;
        assert_eq!(plan.logical_bytes, 0);
        assert_eq!(plan.roots[0].files, 0);
        assert!(plan.preserved.iter().any(|p| p.contains("batch-")));
        let result = execute_with(&plan, |s| std::future::ready(mock.borrow_mut().call(s)))
            .await
            .unwrap();
        assert_eq!(result.removed_files, 0);
        assert!(mock.borrow().removed.is_empty());
    }
    #[test]
    fn hostile_paths_types_mounts_and_unbounded_lists_are_rejected() {
        for path in [
            "/data/data/com.app",
            "/data/local/tmp/ksight/spool/../other",
            "/data/local/tmp/ksight/$(id)",
            "/data/local/tmp/ksight/x;id",
            "/data/local/tmp/ksight/x\ny",
            "/data/local/tmp/ksight//x",
            "/data/local/tmp/ksight/*",
        ] {
            assert!(!clean_path(path), "{path}");
        }
        let mock = Mock::new();
        let root = &mock.entries[0].path;
        for mode in [0xa1ff, 0x11ff, 0x21ff, 0x61ff] {
            let mut entries = mock.entries.clone();
            entries[1].mode = mode;
            assert!(parse_inventory(root, &inventory(&entries)).is_err());
        }
        let mut entries = mock.entries.clone();
        entries[1].device = 99;
        assert!(parse_inventory(root, &inventory(&entries)).is_err());
        assert!(parse_inventory(root, "MEEND|1").is_err());
        assert!(parse_inventory(root, "MEEND|").is_err());
        assert!(parse_inventory(root, &"x".repeat(MAX_WIRE + 1)).is_err());
        let mut entries = mock.entries.clone();
        entries[1].path = format!("{root}/../foreign");
        assert!(parse_inventory(root, &inventory(&entries)).is_err());
    }
    #[test]
    fn legacy_root_unknown_lifecycle_and_parent_spoof_are_rejected_before_rpc() {
        let mut group = terminal();
        group.stages[0].attempts[0].remote_lifecycle = None;
        assert!(expected_roots(&group).is_err());
        let mut group = terminal();
        group.stages[0].attempts[0].state = "unknown".into();
        assert!(expected_roots(&group).is_err());
        let mut group = terminal();
        group.stages[0].attempts[0].remote_artifact_root =
            Some("/data/local/tmp/ksight/packages/org.example.fixture".into());
        assert!(expected_roots(&group).is_err());
        let mut group = terminal();
        group.stages[0].attempts[0].relation.parent_id = Uuid::new_v4();
        assert!(expected_roots(&group).is_err());
        assert!(parse_identity("serial", "MEIDENTITY|||").is_err());
    }
    #[tokio::test]
    async fn scripts_have_no_recursive_delete_and_parse_without_executing() {
        let mock = Rc::new(RefCell::new(Mock::new()));
        let plan = preview(&mock).await;
        let root = &plan.roots[0];
        let entry = root.entries.iter().find(|e| !e.directory()).unwrap();
        let script = remove_script(root, entry, &plan.identity_evidence).unwrap();
        assert!(!script.contains("rm -r"));
        assert!(!script.contains("rm -f"));
        assert!(script.contains("sha256sum"));
        assert!(script.contains("stat -c '%d:%i' ."));
        assert!(script.contains("MEIDENTITY"));
        assert!(script.contains("rm -- './"));
        #[cfg(unix)]
        for script in [
            script,
            inventory_script(&root.path).unwrap(),
            identity_script(),
            lifecycle_script(&plan.group, &root.relation).unwrap(),
        ] {
            use std::io::Write;
            let mut child = std::process::Command::new("sh")
                .arg("-n")
                .stdin(std::process::Stdio::piped())
                .spawn()
                .unwrap();
            child
                .stdin
                .take()
                .unwrap()
                .write_all(script.as_bytes())
                .unwrap();
            assert!(child.wait().unwrap().success());
        }
    }
    #[test]
    fn dump_root_is_exactly_manifest_owned_and_isolated_routes_are_preserved() {
        let mut group = terminal();
        let mut attempt = group.stages[0].attempts.remove(0);
        let index = group.stages.iter().position(|s| s.key == "dump").unwrap();
        attempt.relation.stage_id = group.stages[index].id;
        attempt.relation.stage_key = "dump".into();
        attempt.session_id = None;
        let relation = attempt.relation.clone();
        attempt.remote_lifecycle.as_mut().unwrap()["relation"] = serde_json::json!({
            "parent_id":relation.parent_id,"stage_id":relation.stage_id,"attempt_id":relation.attempt_id,
            "attempt":relation.attempt,"stage_key":relation.stage_key});
        group.base["runtimePaths"] = serde_json::json!({"root":"/data/local/tmp/ksight-fixture",
            "agentPath":"/data/local/tmp/ksight-fixture/bin/ksightd","expectedSha256":"a".repeat(64)});
        attempt.remote_artifact_root = Some(format!(
            "/data/local/tmp/ksight-fixture/captures/{}/{}/{}/dump",
            group.id, relation.stage_id, relation.attempt_id
        ));
        group.stages[index].attempts.push(attempt);
        let mut root = expected_roots(&group).unwrap().remove(0);
        assert_eq!(root.kind, "dumpArtifacts");
        let owner = serde_json::json!({"session_id":null,"package":group.package,"relation":{
            "schema":"kernsight.capture-relation/v1","parent_id":relation.parent_id,"stage_id":relation.stage_id,
            "attempt_id":relation.attempt_id,"attempt":relation.attempt,"stage_key":relation.stage_key}});
        root.evidence
            .insert("capture-relation.json".into(), owner.to_string());
        validate_evidence(&group, &root).unwrap();
        let script = lifecycle_script(&group, &relation).unwrap();
        assert!(script.contains("/data/local/tmp/ksight-fixture/bin/ksightd"));
        assert!(!script.contains("/data/local/tmp/ksight/"));
        let mut foreign = owner;
        foreign["relation"]["attempt_id"] = serde_json::json!(Uuid::new_v4());
        root.evidence
            .insert("capture-relation.json".into(), foreign.to_string());
        assert!(validate_evidence(&group, &root).is_err());
        group.stages[index].attempts[0].remote_artifact_root =
            Some("/data/local/tmp/ksight-fixture/captures/foreign/dump".into());
        assert!(expected_roots(&group).is_err());
    }
    #[test]
    fn unified_shared_session_requires_complete_stage_links() {
        let mut group = terminal();
        let primary = group.stages[0].attempts[0].clone();
        group.stages.sort_by_key(|s| match s.key.as_str() {
            "l0" => 0,
            "l1" => 1,
            "linker" => 2,
            _ => 3,
        });
        group.unified = true;
        for stage in &mut group.stages[1..3] {
            let mut attempt = primary.clone();
            attempt.relation.stage_id = stage.id;
            attempt.relation.stage_key = stage.key.clone();
            attempt.relation.attempt_id = Uuid::new_v4();
            stage.attempts.push(attempt);
        }
        let roots = expected_roots(&group).unwrap();
        assert_eq!(roots.len(), 1);
        let mut root = roots[0].clone();
        let relation = &root.relation;
        let mut owner = serde_json::json!({"session_id":root.session_id,"package":group.package,"relation":{
            "schema":"kernsight.capture-relation/v1","parent_id":relation.parent_id,"stage_id":relation.stage_id,
            "attempt_id":relation.attempt_id,"attempt":relation.attempt,"stage_key":relation.stage_key,
            "stage_links":group.stages[..3].iter().map(|s|s.attempts[0].relation.clone()).collect::<Vec<_>>()}});
        root.evidence
            .insert("capture-relation.json".into(), owner.to_string());
        root.evidence.insert(
            "session.json".into(),
            serde_json::json!({"session_id":root.session_id,"state":"storage_limited"}).to_string(),
        );
        validate_evidence(&group, &root).unwrap();
        owner["relation"]["stage_links"] = serde_json::json!([]);
        root.evidence
            .insert("capture-relation.json".into(), owner.to_string());
        assert!(validate_evidence(&group, &root).is_err());
    }
    #[cfg(unix)]
    fn synthetic_mount_guard(contents: Option<&str>, selected: &str) -> i32 {
        let directory =
            std::env::temp_dir().join(format!("me-purge-mountinfo-test-{}", Uuid::new_v4()));
        std::fs::create_dir(&directory).unwrap();
        let input = directory.join("mountinfo");
        if let Some(contents) = contents {
            std::fs::write(&input, contents).unwrap();
        }
        let script = mount_checks(selected).unwrap().replace(
            "/proc/self/mountinfo",
            &crate::shell_quote(input.to_str().unwrap()),
        );
        // Only the read-only guard runs here. No mount, ADB, find, rm or device
        // path operation is performed; the input is a generated temporary file.
        assert!(!script.contains("rm --"));
        assert!(!script.contains("eval"));
        let code = std::process::Command::new("sh")
            .arg("-c")
            .arg(script)
            .status()
            .unwrap()
            .code()
            .unwrap();
        if input.exists() {
            std::fs::remove_file(input).unwrap();
        }
        std::fs::remove_dir(directory).unwrap();
        code
    }
    #[cfg(unix)]
    #[test]
    fn mount_guard_rejects_same_device_binds_and_overlapping_mounts() {
        let selected = "/data/local/tmp/ksight/spool/fixture";
        let base =
            "1 0 8:1 / / rw - ext4 /dev/root rw\n2 1 8:2 / /data rw shared:1 - ext4 /dev/data rw\n";
        // Device 8:2 is deliberately identical to /data. st_dev cannot detect
        // any of these bind-mount overlaps, but mountinfo still exposes them.
        for mount in [
            selected.to_owned(),
            format!("{selected}/private"),
            format!("{selected}/batch.json"),
            format!("{selected}/escaped\\040name"),
            "/data/local/tmp".into(),
            "/data/local/tmp/ksight".into(),
            "/data/local/tmp/ksight/spool".into(),
        ] {
            let data =
                format!("{base}3 2 8:2 /data/data/original {mount} rw - ext4 /dev/data rw\n");
            assert_eq!(synthetic_mount_guard(Some(&data), selected), 82, "{mount}");
        }
        for mount in [
            "/data/local/tmp/ksight/spool/fixture-other",
            "/data/local/tmp/ksight/spool/other",
            "/mnt/unrelated",
            "/data/local/tmp/ksight\\040different",
        ] {
            let data = format!("{base}3 2 8:2 /private {mount} rw - ext4 /dev/data rw\n");
            assert_eq!(synthetic_mount_guard(Some(&data), selected), 0, "{mount}");
        }
        assert_eq!(synthetic_mount_guard(Some(base), selected), 0);
    }
    #[cfg(unix)]
    #[test]
    fn mount_guard_fails_closed_on_missing_malformed_and_truncated_inventory() {
        let selected = "/data/local/tmp/ksight/spool/fixture";
        assert_eq!(synthetic_mount_guard(None, selected), 81);
        for data in [
            "",
            "\n",
            "not mountinfo\n",
            "1 0 8:1 / / rw missing_separator ext4 root rw\n",
            "1 0 invalid / / rw - ext4 root rw\n",
            "1 0 8:1 / relative rw - ext4 root rw\n",
            "1 0 8:1 / / rw - ext4 root rw",
        ] {
            assert_eq!(synthetic_mount_guard(Some(data), selected), 81, "{data:?}");
        }
        let too_many = "1 0 8:1 / / rw - ext4 root rw\n".repeat(4097);
        assert_eq!(synthetic_mount_guard(Some(&too_many), selected), 81);
        let oversized = format!("1 0 8:1 / / rw - ext4 {} rw\n", "a".repeat(1048576));
        assert_eq!(synthetic_mount_guard(Some(&oversized), selected), 81);
        // Bounds count bytes before trailing newlines are stripped.
        let newline_overflow = format!("1 0 8:1 / / rw - ext4 root rw\n{}", "\n".repeat(1048576));
        assert_eq!(synthetic_mount_guard(Some(&newline_overflow), selected), 81);
    }
    #[tokio::test]
    async fn every_inventory_and_unlink_checks_current_root_mounts() {
        let mock = Rc::new(RefCell::new(Mock::new()));
        let plan = preview(&mock).await;
        let root = &plan.roots[0];
        let inventory = inventory_script(&root.path).unwrap();
        assert!(
            inventory.find("# me-purge:mount-guard").unwrap() < inventory.find("find '").unwrap()
        );
        let file = root.entries.iter().find(|e| !e.directory()).unwrap();
        let removal = remove_script(root, file, &plan.identity_evidence).unwrap();
        let guard = removal.find("# me-purge:mount-guard").unwrap();
        assert!(guard < removal.find("rm --").unwrap());
        assert!(guard > removal.find("sha256sum").unwrap());
        assert!(removal.contains(&format!("me_mount_root={}", crate::shell_quote(&root.path))));
        assert!(!removal.contains("awk"));
    }
}
