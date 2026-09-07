use super::AppAnalysis;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File},
    io::Write,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

const CASE_SCHEMA: &str = "mobilee/analysis-case/v1";
const LEGACY_CASE_SCHEMA: &str = "mobile-security-kits/analysis-case/v1";

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AnalysisCase {
    pub schema_version: String,
    pub saved_at: u64,
    pub analysis: AppAnalysis,
    #[serde(default)]
    pub verdicts: BTreeMap<String, String>,
    #[serde(default)]
    pub notes: String,
    #[serde(default)]
    pub runtime_history: Vec<CaseRuntimeEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CaseRuntimeEntry {
    pub time: u64,
    pub command: String,
    pub output: String,
    pub success: bool,
    pub app_id: Option<String>,
    pub device_id: Option<String>,
    pub platform: Option<String>,
    pub source: Option<String>,
    #[serde(default)]
    pub runtime_step: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SaveAnalysisCaseRequest {
    pub output_path: String,
    pub analysis: AppAnalysis,
    #[serde(default)]
    pub verdicts: BTreeMap<String, String>,
    #[serde(default)]
    pub notes: String,
    #[serde(default)]
    pub runtime_history: Vec<CaseRuntimeEntry>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CompareAnalysisCaseRequest {
    pub baseline_path: String,
    pub current: AppAnalysis,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AnalysisBaselineDiff {
    pub baseline_file_name: String,
    pub baseline_sha256: String,
    pub current_sha256: String,
    pub added_findings: Vec<String>,
    pub resolved_findings: Vec<String>,
    pub added_sensitive_items: Vec<String>,
    pub resolved_sensitive_items: Vec<String>,
    pub added_libraries: Vec<String>,
    pub removed_libraries: Vec<String>,
    pub changed: bool,
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn read_case(path: &str) -> Result<AnalysisCase, String> {
    let content = fs::read_to_string(path).map_err(|error| format!("读取分析快照失败：{error}"))?;
    let mut case: AnalysisCase = serde_json::from_str(&content)
        .map_err(|error| format!("分析快照不是有效 JSON：{error}"))?;
    if case.schema_version == LEGACY_CASE_SCHEMA {
        case.schema_version = CASE_SCHEMA.into();
    } else if case.schema_version != CASE_SCHEMA {
        return Err(format!("不支持的分析快照版本：{}", case.schema_version));
    }
    Ok(case)
}

pub fn save(request: SaveAnalysisCaseRequest) -> Result<String, String> {
    let path = Path::new(&request.output_path);
    if let Ok(metadata) = fs::symlink_metadata(path) {
        if metadata.file_type().is_symlink() {
            return Err("拒绝覆盖符号链接快照文件".into());
        }
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|error| format!("创建快照目录失败：{error}"))?;
    }
    let case = AnalysisCase {
        schema_version: CASE_SCHEMA.into(),
        saved_at: now(),
        analysis: request.analysis,
        verdicts: request.verdicts,
        notes: request.notes,
        runtime_history: request.runtime_history,
    };
    let content =
        serde_json::to_vec_pretty(&case).map_err(|error| format!("序列化分析快照失败：{error}"))?;
    let file_name = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("analysis.mskcase");
    let temp = path.with_file_name(format!(".{file_name}.{}.tmp", std::process::id()));
    let write_result = (|| -> Result<(), String> {
        let mut file = File::create(&temp).map_err(|error| format!("创建临时快照失败：{error}"))?;
        file.write_all(&content)
            .map_err(|error| format!("写入临时快照失败：{error}"))?;
        file.sync_all()
            .map_err(|error| format!("同步临时快照失败：{error}"))?;
        fs::rename(&temp, path).map_err(|error| format!("原子替换分析快照失败：{error}"))
    })();
    if write_result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    write_result?;
    Ok(path.display().to_string())
}

pub fn load(path: String) -> Result<AnalysisCase, String> {
    read_case(&path)
}

fn finding_keys(analysis: &AppAnalysis) -> BTreeSet<String> {
    analysis
        .findings
        .iter()
        .map(|item| format!("{} · {}", item.title, item.detail))
        .chain(
            analysis
                .protection
                .indicators
                .iter()
                .map(|item| format!("加固/保护 · {item}")),
        )
        .collect()
}

fn sensitive_keys(analysis: &AppAnalysis) -> BTreeSet<String> {
    analysis
        .sensitive_items
        .iter()
        .map(|item| {
            let value = item
                .value
                .as_deref()
                .unwrap_or("文件名线索")
                .chars()
                .take(180)
                .collect::<String>();
            format!("{} · {} · {value}", item.kind, item.location)
        })
        .collect()
}

fn difference(left: &BTreeSet<String>, right: &BTreeSet<String>) -> Vec<String> {
    left.difference(right).take(300).cloned().collect()
}

pub fn compare(request: CompareAnalysisCaseRequest) -> Result<AnalysisBaselineDiff, String> {
    let baseline = read_case(&request.baseline_path)?;
    let current_findings = finding_keys(&request.current);
    let baseline_findings = finding_keys(&baseline.analysis);
    let current_sensitive = sensitive_keys(&request.current);
    let baseline_sensitive = sensitive_keys(&baseline.analysis);
    let current_libraries = request
        .current
        .third_party_libraries
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    let baseline_libraries = baseline
        .analysis
        .third_party_libraries
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    let added_findings = difference(&current_findings, &baseline_findings);
    let resolved_findings = difference(&baseline_findings, &current_findings);
    let added_sensitive_items = difference(&current_sensitive, &baseline_sensitive);
    let resolved_sensitive_items = difference(&baseline_sensitive, &current_sensitive);
    let added_libraries = difference(&current_libraries, &baseline_libraries);
    let removed_libraries = difference(&baseline_libraries, &current_libraries);
    let changed = [
        &added_findings,
        &resolved_findings,
        &added_sensitive_items,
        &resolved_sensitive_items,
        &added_libraries,
        &removed_libraries,
    ]
    .iter()
    .any(|items| !items.is_empty());
    Ok(AnalysisBaselineDiff {
        baseline_file_name: baseline.analysis.file_name,
        baseline_sha256: baseline.analysis.artifact_sha256,
        current_sha256: request.current.artifact_sha256,
        added_findings,
        resolved_findings,
        added_sensitive_items,
        resolved_sensitive_items,
        added_libraries,
        removed_libraries,
        changed,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn differences_are_directional() {
        let left = ["new".to_string(), "same".to_string()]
            .into_iter()
            .collect();
        let right = ["old".to_string(), "same".to_string()]
            .into_iter()
            .collect();
        assert_eq!(difference(&left, &right), vec!["new"]);
        assert_eq!(difference(&right, &left), vec!["old"]);
    }

    #[test]
    fn runtime_history_entry_keeps_app_and_device_scope() {
        let entry = CaseRuntimeEntry {
            time: 1_700_000_000_000,
            command: "frida attach com.example.app".into(),
            output: "URLSession request https://api.example.test".into(),
            success: true,
            app_id: Some("com.example.app".into()),
            device_id: Some("device-1".into()),
            platform: Some("ios".into()),
            source: Some("frida".into()),
            runtime_step: Some("network-tls".into()),
        };
        let value = serde_json::to_value(&entry).expect("serialize runtime entry");
        assert_eq!(value["appId"], "com.example.app");
        assert_eq!(value["deviceId"], "device-1");
        assert_eq!(value["runtimeStep"], "network-tls");
        let restored: CaseRuntimeEntry =
            serde_json::from_value(value).expect("deserialize runtime entry");
        assert_eq!(restored.app_id.as_deref(), Some("com.example.app"));
        assert_eq!(restored.platform.as_deref(), Some("ios"));
        assert_eq!(restored.runtime_step.as_deref(), Some("network-tls"));
    }
}
