//! Join only the source report's named initial candidate snapshot. These are
//! producer metadata counts, never payload verification or whole-App coverage.
use super::*;
use std::collections::BTreeMap;

const SCOPE: &str = "initial_main_process_candidate_snapshot";
const DOCUMENT_LIMIT: u64 = 256 * 1024;
const TOTAL_METADATA_LIMIT: u64 = 16 * 1024 * 1024;
const CANDIDATE_LIMIT: usize = 65_536;

fn number(value: &Value, key: &str) -> Result<u64, String> {
    value[key]
        .as_u64()
        .ok_or_else(|| format!("候选元数据缺少有效 {key}"))
}
fn add(total: &mut u64, value: u64) -> Result<(), String> {
    *total = total.checked_add(value).ok_or("候选字节计数溢出")?;
    Ok(())
}
fn bounds(value: &Value) -> Result<(u64, u64), String> {
    let start = number(value, "start")?;
    let end = number(value, "end")?;
    if end <= start {
        return Err("候选地址范围无效".into());
    }
    Ok((start, end))
}
fn read_metadata(
    root: &Path,
    relative: &str,
    remaining: &mut u64,
    document_limit: u64,
) -> Result<Value, String> {
    let mut file = super::open_anchored(root, relative)?;
    let before = file.metadata().map_err(|e| e.to_string())?;
    if before.len() > document_limit || before.len() > *remaining {
        return Err("候选快照元数据超过有界读取额度".into());
    }
    let mut bytes = Vec::with_capacity(before.len() as usize);
    file.by_ref()
        .take(before.len() + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    *remaining = remaining.saturating_sub(bytes.len() as u64);
    let current = super::open_anchored(root, relative)?
        .metadata()
        .map_err(|e| e.to_string())?;
    if bytes.len() as u64 != before.len()
        || !super::same_snapshot(&before, &file.metadata().map_err(|e| e.to_string())?)
        || !super::same_snapshot(&before, &current)
    {
        return Err("候选快照在读取期间变化".into());
    }
    super::super::session_deadline::check()?;
    serde_json::from_slice(&bytes).map_err(|e| format!("候选快照 JSON 无效：{e}"))
}

fn source_records(
    root: &Path,
    source_report: &str,
    note: &Value,
    remaining: &mut u64,
) -> Result<(Vec<Value>, u64, Value), String> {
    let count = match note.get("shard_count") {
        None => 1,
        Some(value) => value
            .as_u64()
            .filter(|n| (1..=16).contains(n))
            .ok_or("来源分片数无效或超限")?,
    };
    let current = note["records"].as_array().ok_or("来源缺少记录")?;
    if count == 1 {
        if note
            .get("shard_index")
            .is_some_and(|v| v.as_u64() != Some(0))
            || note
                .get("record_start")
                .is_some_and(|v| v.as_u64() != Some(0))
        {
            return Err("单份来源分片序号或起点无效".into());
        }
        return Ok((current.clone(), count, note["candidate_result"].clone()));
    }
    let index = number(note, "shard_index")?;
    if index >= count {
        return Err("当前来源分片序号越界".into());
    }
    let source_path = Path::new(source_report);
    let filename = source_path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or("来源文件名无效")?;
    let suffix = format!("-{index:02}.json");
    let stem = filename
        .strip_suffix(&suffix)
        .ok_or("来源分片文件名与序号不一致")?;
    let prefix = format!("bound-source-{}-", number(&note["source"], "pid")?);
    let identity = stem
        .strip_prefix(&prefix)
        .ok_or("来源分片文件名与进程身份不一致")?;
    uuid::Uuid::parse_str(identity).map_err(|_| "来源分片清单身份无效")?;
    let parent = source_path.parent().unwrap_or(Path::new(""));
    let total = number(&note["candidate_result"], "total_attempted")?;
    if total > CANDIDATE_LIMIT as u64 {
        return Err("来源总记录数超限".into());
    }
    let mut records = Vec::new();
    let mut offset_mode = None;
    let mut terminal = Value::Null;
    for shard_index in 0..count {
        let relative = parent.join(format!("{stem}-{shard_index:02}.json"));
        let shard = if shard_index == index {
            note.clone()
        } else {
            read_metadata(
                root,
                relative.to_str().ok_or("来源分片名无效")?,
                remaining,
                super::super::storage_evidence::BOUND_SOURCE_BYTE_LIMIT,
            )?
        };
        if shard["schema"] != "kernsight.bound-code-copy/v1"
            || shard["source"] != note["source"]
            || shard["candidate_manifest"] != note["candidate_manifest"]
            || number(&shard, "shard_index")? != shard_index
            || number(&shard, "shard_count")? != count
            || number(&shard["candidate_result"], "total_attempted")? != total
            || shard["partial"] != note["partial"]
        {
            return Err("来源分片身份、候选快照或总尝试数冲突".into());
        }
        let rows = shard["records"].as_array().ok_or("来源分片缺记录")?;
        if number(&shard["candidate_result"], "attempted")? != rows.len() as u64
            || records.len().saturating_add(rows.len()) > CANDIDATE_LIMIT
        {
            return Err("来源分片记录数冲突或超限".into());
        }
        let start = shard
            .get("record_start")
            .or_else(|| shard["candidate_result"].get("record_start"));
        let has_offset = start.is_some();
        if offset_mode.is_some_and(|prior| prior != has_offset)
            || start.is_some_and(|value| value.as_u64() != Some(records.len() as u64))
        {
            return Err("来源分片 record_start 缺页、重复或不连续".into());
        }
        offset_mode = Some(has_offset);
        records.extend(rows.iter().cloned());
        terminal = shard["candidate_result"].clone();
    }
    if records.len() as u64 != total {
        return Err("来源分片未覆盖声明的总尝试数".into());
    }
    if fs::symlink_metadata(root.join(parent.join(format!("{stem}-{count:02}.json")))).is_ok() {
        return Err("来源终片后仍有额外分片".into());
    }
    Ok((records, count, terminal))
}

pub(super) fn summarize(root: &Path, source_report: &str, note: &Value) -> Value {
    match joined(root, source_report, note) {
        Ok(value) => value,
        Err(reason) => {
            json!({"status":"unknown","reason":reason,"scope":SCOPE,"metadataOnly":true})
        }
    }
}

fn joined(root: &Path, source_report: &str, note: &Value) -> Result<Value, String> {
    let package = note["source"]["package"].as_str().ok_or("来源包身份缺失")?;
    let pid = number(&note["source"], "pid")?;
    let manifest = note["candidate_manifest"]
        .as_str()
        .ok_or("旧来源未提供关联的初始候选清单")?;
    let prefix = format!("bound-candidates-{pid}-");
    let identity = manifest
        .strip_prefix(&prefix)
        .ok_or("候选清单与来源进程不匹配")?;
    uuid::Uuid::parse_str(identity)
        .map_err(|_| "候选清单身份无效；不使用其他快照或 before-static 清单")?;
    let parent = Path::new(source_report).parent().unwrap_or(Path::new(""));
    let mut candidates = BTreeMap::new();
    let mut eligible = None;
    let mut total_bytes = 0;
    let mut listed = 0;
    let mut metadata_left = TOTAL_METADATA_LIMIT;
    let (records, source_shards, terminal) =
        source_records(root, source_report, note, &mut metadata_left)?;
    let mut finished = false;
    let mut paths_complete = true;
    for index in 0..128 {
        let relative = parent.join(format!("{manifest}-{index:02}.json"));
        let relative = relative.to_str().ok_or("候选文件名无效")?;
        let shard = read_metadata(root, relative, &mut metadata_left, DOCUMENT_LIMIT)?;
        if shard["schema"] != "kernsight.code-candidates/v1"
            || shard["mapping_observation_scope"]
                != "initial_bound_maps_snapshot; later mappings not observed"
            || number(&shard, "shard_index")? != index
            || shard.get("phase").is_some_and(|v| !v.is_null())
            || shard
                .get("source")
                .is_some_and(|source| !source.is_null() && source != &note["source"])
        {
            return Err("候选分片不是本来源关联的初始快照".into());
        }
        let count = number(&shard, "eligible_count")?;
        if count > CANDIDATE_LIMIT as u64 || eligible.is_some_and(|n| n != count) {
            return Err("候选总数超过上限或分片计数冲突".into());
        }
        eligible = Some(count);
        let rows = shard["candidates"].as_array().ok_or("候选分片缺记录")?;
        if number(&shard, "listed_count")? != rows.len() as u64
            || listed + rows.len() as u64 > count
        {
            return Err("候选分片记录数不一致".into());
        }
        for candidate in rows {
            if number(candidate, "rank")? != listed {
                return Err("候选 rank 重复或不连续".into());
            }
            let key = bounds(candidate)?;
            let bytes = number(candidate, "requested_mapping_bytes")?;
            if bytes != key.1 - key.0 || candidates.insert(key, candidate.clone()).is_some() {
                return Err("候选地址重复或声明长度不一致".into());
            }
            paths_complete &= candidate["path"].is_string() && candidate["path_truncated"] == false;
            add(&mut total_bytes, bytes)?;
            listed += 1;
        }
        let omitted = number(&shard, "omitted_count")?;
        if omitted != count - listed {
            return Err("候选遗漏计数不一致".into());
        }
        if omitted == 0 {
            if !shard["omitted_reason"].is_null() {
                return Err("候选终片原因冲突".into());
            }
            let extra = parent.join(format!("{manifest}-{:02}.json", index + 1));
            if fs::symlink_metadata(root.join(extra)).is_ok() {
                return Err("候选终片后仍有额外分片".into());
            }
            finished = true;
            break;
        }
        if rows.is_empty() || shard["omitted_reason"] != "continued_in_next_candidate_shard" {
            return Err("候选分片缺页或截断，不能推算完整初始候选".into());
        }
    }
    if !finished {
        return Err("候选分片超过有界读取数量".into());
    }
    let rows = &records;
    if note["candidate_result"]
        .get("total_attempted")
        .or_else(|| note["candidate_result"].get("attempted"))
        .is_some_and(|n| n.as_u64() != Some(rows.len() as u64))
    {
        return Err("来源尝试数与原始记录不一致".into());
    }
    let mut attempted = BTreeMap::new();
    let mut admitted = 0;
    let mut admitted_bytes = 0;
    let mut excluded = 0;
    let mut rejected = 0;
    let mut install_total = 0;
    let mut install_admitted = 0;
    let mut install_remaining = 0;
    for row in rows {
        let key = bounds(&row["mapping"])?;
        let candidate = candidates.get(&key).ok_or("来源记录不属于关联候选快照")?;
        if row["source"] != note["source"]
            || attempted.insert(key, row).is_some()
            || (candidate["path_truncated"] == false && row["mapping"]["path"] != candidate["path"])
        {
            return Err("来源记录身份、路径或地址关联冲突".into());
        }
        let actual = number(&row["read"], "actual_length")?;
        if actual > key.1 - key.0 {
            return Err("来源实际长度超过候选范围".into());
        }
        match row["admitted"].as_bool() {
            Some(true)
                if row["excluded_local_window"] != true
                    && row["read"]["admission"] == "qualified_live_copy"
                    && row["read"]["read_status"] == "complete"
                    && row["read"]["write_status"] == "complete" =>
            {
                admitted += 1;
                add(&mut admitted_bytes, actual)?;
            }
            Some(false) => {
                if row["excluded_local_window"] == true {
                    excluded += 1;
                } else {
                    rejected += 1;
                }
            }
            _ => return Err("来源 admission 与读取状态不一致".into()),
        }
    }
    let mut unattempted_bytes = 0;
    for (key, candidate) in &candidates {
        let bytes = key.1 - key.0;
        let row = attempted.get(key);
        if row.is_none() {
            add(&mut unattempted_bytes, bytes)?;
        }
        let path = candidate["path"].as_str().unwrap_or("");
        if path.starts_with("/data/app/") && path.contains(&format!("/{package}-")) {
            install_total += 1;
            if let Some(row) = row.filter(|row| row["admitted"] == true) {
                install_admitted += 1;
                add(
                    &mut install_remaining,
                    bytes - number(&row["read"], "actual_length")?,
                )?;
            } else {
                add(&mut install_remaining, bytes)?;
            }
        }
    }
    Ok(
        json!({"status":"available","scope":SCOPE,"metadataOnly":true,"candidateManifest":manifest,
        "eligibleRanges":listed,"eligibleBytes":total_bytes,"attemptedRanges":rows.len(),
        "sourceShardCount":source_shards,"currentSourceRecords":note["records"].as_array().map_or(0,Vec::len),"globalAttemptedRanges":rows.len(),
        "terminalStopScope":terminal["stop_scope"],"terminalUnattemptedState":terminal["unattempted_state"],
        "admittedRanges":admitted,"admittedBytes":admitted_bytes,"excludedRanges":excluded,"rejectedRanges":rejected,
        "unattemptedRanges":candidates.len()-attempted.len(),"unattemptedBytes":unattempted_bytes,"remainingBytes":total_bytes-admitted_bytes,
        "appInstall":if paths_complete {json!({"eligibleRanges":install_total,"admittedRanges":install_admitted,"remainingRanges":install_total-install_admitted,"remainingBytes":install_remaining})} else {Value::Null}}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    const MANIFEST: &str = "bound-candidates-7-00000000-0000-4000-8000-000000000001";
    const SOURCE: &str = "runtime/bound-source-fixture.json";

    fn fixture() -> (std::path::PathBuf, Value) {
        let root =
            std::env::temp_dir().join(format!("me-candidate-coverage-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(root.join("runtime")).unwrap();
        let source = json!({"package":"org.example.app","pid":7,"uid":10234,"birth_ns":123,"exec_id":2,"boot_id":"fixture-boot"});
        let candidates: Vec<_> = (0..4).map(|rank| {
            let start = 1000 + rank * 100;
            json!({"rank":rank,"start":start,"end":start+100,"requested_mapping_bytes":100,
                "selection_limit_bytes":100,"path_truncated":false,
                "path":if rank==0 {"/data/app/fixture/org.example.app-test/base.apk".to_string()} else {format!("/system/lib64/fixture-{rank}.so")}})
        }).collect();
        for index in 0..2 {
            let end = (index + 1) * 2;
            let shard = json!({"schema":"kernsight.code-candidates/v1","mapping_observation_scope":"initial_bound_maps_snapshot; later mappings not observed",
                "shard_index":index,"eligible_count":4,"listed_count":2,"omitted_count":4-end,
                "omitted_reason":if index==0 {json!("continued_in_next_candidate_shard")} else {Value::Null},
                "candidates":candidates[index*2..end]});
            fs::write(
                root.join(format!("runtime/{MANIFEST}-{index:02}.json")),
                serde_json::to_vec(&shard).unwrap(),
            )
            .unwrap();
        }
        let records: Vec<_> = [0,1,3].into_iter().map(|rank| {
            let candidate = &candidates[rank];
            json!({"source":source,"mapping":{"start":candidate["start"],"end":candidate["end"],"path":candidate["path"]},
                "admitted":rank==0,"excluded_local_window":rank==1,"raw_evidence":format!("fixture-{rank}.code"),
                "read":{"actual_length":if rank==0 {100} else {0},"admission":if rank==0 {"qualified_live_copy"} else {"rejected_identity"},
                    "read_status":if rank==0 {"complete"} else {"not_attempted"},"write_status":"complete"}})
        }).collect();
        let note = json!({"schema":"kernsight.bound-code-copy/v1","source":source,"shard_count":1,
            "partial":true,"candidate_manifest":MANIFEST,"candidate_result":{"total_attempted":3},"records":records});
        (root, note)
    }

    #[test]
    fn joined_initial_snapshot_distinguishes_unattempted_excluded_and_rejected() {
        let (root, note) = fixture();
        fs::write(
            root.join("runtime/bound-candidates-before-static-unrelated-00.json"),
            b"not the named initial snapshot",
        )
        .unwrap();
        let summary = summarize(&root, SOURCE, &note);
        assert_eq!(summary["status"], "available");
        assert_eq!(summary["eligibleRanges"], 4);
        assert_eq!(summary["eligibleBytes"], 400);
        assert_eq!(summary["attemptedRanges"], 3);
        assert_eq!(summary["admittedRanges"], 1);
        assert_eq!(summary["admittedBytes"], 100);
        assert_eq!(summary["excludedRanges"], 1);
        assert_eq!(summary["rejectedRanges"], 1);
        assert_eq!(summary["unattemptedRanges"], 1);
        assert_eq!(summary["unattemptedBytes"], 100);
        assert_eq!(summary["remainingBytes"], 300);
        assert_eq!(summary["appInstall"]["eligibleRanges"], 1);
        assert_eq!(summary["appInstall"]["remainingRanges"], 0);
        assert_eq!(summary["metadataOnly"], true);
        assert_eq!(note["partial"], true);
        assert!(
            !root.join("runtime/fixture-0.code").exists(),
            "summary must not read or invent payload verification"
        );
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn missing_candidate_shard_never_reports_complete_counts() {
        let (root, note) = fixture();
        fs::remove_file(root.join(format!("runtime/{MANIFEST}-01.json"))).unwrap();
        let summary = summarize(&root, SOURCE, &note);
        assert_eq!(summary["status"], "unknown");
        assert!(summary.get("remainingBytes").is_none());
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn duplicate_rank_never_reports_complete_counts() {
        let (root, note) = fixture();
        let path = root.join(format!("runtime/{MANIFEST}-01.json"));
        let mut shard: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        shard["candidates"][0]["rank"] = json!(0);
        fs::write(path, serde_json::to_vec(&shard).unwrap()).unwrap();
        let summary = summarize(&root, SOURCE, &note);
        assert_eq!(summary["status"], "unknown");
        assert!(summary.get("eligibleRanges").is_none());
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn foreign_manifest_or_before_static_cannot_supply_initial_coverage() {
        let (root, mut note) = fixture();
        for manifest in [
            "bound-candidates-8-00000000-0000-4000-8000-000000000001",
            "bound-candidates-before-static-7-00000000-0000-4000-8000-000000000001",
        ] {
            note["candidate_manifest"] = json!(manifest);
            let summary = summarize(&root, SOURCE, &note);
            assert_eq!(summary["status"], "unknown");
            assert!(summary.get("admittedRanges").is_none());
        }
        fs::remove_dir_all(root).unwrap();
    }

    const SOURCE_STEM: &str = "bound-source-7-00000000-0000-4000-8000-000000000002";
    fn split_source_fixture(root: &Path, note: &Value) -> Vec<Value> {
        let rows = note["records"].as_array().unwrap();
        let mut shards = Vec::new();
        for index in 0..2 {
            let mut shard = note.clone();
            let (start, end) = if index == 0 { (0, 1) } else { (1, rows.len()) };
            shard["shard_index"] = json!(index);
            shard["shard_count"] = json!(2);
            shard["record_start"] = json!(start);
            shard["records"] = json!(rows[start..end]);
            shard["candidate_result"]["attempted"] = json!(end - start);
            shard["candidate_result"]["stop_scope"] = if index == 0 {
                json!("none_or_parent_budget")
            } else {
                json!("local_copy_window")
            };
            fs::write(
                root.join(format!("runtime/{SOURCE_STEM}-{index:02}.json")),
                serde_json::to_vec(&shard).unwrap(),
            )
            .unwrap();
            shards.push(shard);
        }
        shards
    }
    #[test]
    fn two_source_shards_aggregate_one_initial_snapshot_from_either_page() {
        let (root, note) = fixture();
        let shards = split_source_fixture(&root, &note);
        for (index, shard) in shards.iter().enumerate() {
            let path = format!("runtime/{SOURCE_STEM}-{index:02}.json");
            let result = summarize(&root, &path, shard);
            assert_eq!(result["status"], "available");
            assert_eq!(result["sourceShardCount"], 2);
            assert_eq!(
                result["currentSourceRecords"],
                shard["records"].as_array().unwrap().len()
            );
            assert_eq!(result["globalAttemptedRanges"], 3);
            assert_eq!(result["attemptedRanges"], 3);
            assert_eq!(result["unattemptedRanges"], 1);
            assert_eq!(result["admittedRanges"], 1);
            assert_eq!(result["remainingBytes"], 300);
            assert_eq!(result["terminalStopScope"], "local_copy_window");
        }
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn missing_second_source_shard_keeps_global_coverage_unknown() {
        let (root, note) = fixture();
        let shards = split_source_fixture(&root, &note);
        fs::remove_file(root.join(format!("runtime/{SOURCE_STEM}-01.json"))).unwrap();
        let summary = summarize(&root, &format!("runtime/{SOURCE_STEM}-00.json"), &shards[0]);
        assert_eq!(summary["status"], "unknown");
        assert!(summary.get("unattemptedRanges").is_none());
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn source_shard_offset_identity_and_mapping_conflicts_are_not_merged() {
        for kind in ["offset", "identity", "mapping", "total"] {
            let (root, note) = fixture();
            let mut shards = split_source_fixture(&root, &note);
            match kind {
                "offset" => shards[1]["record_start"] = json!(2),
                "identity" => shards[1]["source"]["exec_id"] = json!(999),
                "mapping" => shards[1]["records"][0] = shards[0]["records"][0].clone(),
                _ => shards[1]["candidate_result"]["total_attempted"] = json!(4),
            }
            fs::write(
                root.join(format!("runtime/{SOURCE_STEM}-01.json")),
                serde_json::to_vec(&shards[1]).unwrap(),
            )
            .unwrap();
            let summary = summarize(&root, &format!("runtime/{SOURCE_STEM}-00.json"), &shards[0]);
            assert_eq!(summary["status"], "unknown", "{kind}");
            fs::remove_dir_all(root).unwrap();
        }
    }
}
