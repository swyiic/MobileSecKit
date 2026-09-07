use super::{assessment, DataBoundaryObservation};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ToolStatus {
    pub name: String,
    pub executable: String,
    pub available: bool,
    pub version: Option<String>,
    pub path: Option<String>,
    pub category: String,
    pub group: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EnvironmentReport {
    pub host_os: String,
    pub host_arch: String,
    pub tools: Vec<ToolStatus>,
    pub device_frida_version: Option<String>,
    pub device_frida_reachable: bool,
    pub device_frida_requires_developer_image: bool,
    pub device_architecture: Option<String>,
    pub recommended_frida_server: Option<String>,
    pub frida_version_match: Option<bool>,
    pub host_frida_tools_match: Option<bool>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EnvironmentRequest {
    pub serial: Option<String>,
    pub platform: Option<String>,
    pub tool_directory: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AdvancedCommandResult {
    pub success: bool,
    pub command: String,
    pub output: String,
    pub exit_code: Option<i32>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ShellRequest {
    pub serial: String,
    pub command: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProxyRequest {
    pub serial: String,
    pub action: String,
    pub host: Option<String>,
    pub port: Option<u16>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CertificateInfo {
    pub path: String,
    pub subject_hash: String,
    pub sha256: String,
    pub system_target: String,
    pub note: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CertificateRequest {
    pub serial: String,
    pub path: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FridaProcess {
    pub pid: Option<u32>,
    pub name: String,
    pub identifier: String,
    pub platform: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FridaScriptRequest {
    pub serial: Option<String>,
    pub process: String,
    pub pid: Option<u32>,
    pub script: String,
    pub mode: String,
    pub script_path: Option<String>,
    #[serde(default)]
    pub duration_seconds: Option<u64>,
    #[serde(default)]
    pub compatibility_profile: Option<String>,
    #[serde(default)]
    pub platform: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DexDumpRequest {
    pub serial: String,
    pub package: String,
    pub script_path: String,
    pub destination_directory: Option<String>,
    pub duration_seconds: Option<u64>,
    #[serde(default)]
    pub mode: Option<String>,
    #[serde(default)]
    pub pid: Option<u32>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SoDumpRequest {
    pub serial: String,
    pub package: String,
    pub script_path: String,
    pub destination_directory: Option<String>,
    pub duration_seconds: Option<u64>,
    #[serde(default)]
    pub mode: Option<String>,
    #[serde(default)]
    pub pid: Option<u32>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IosDumpRequest {
    pub serial: String,
    pub bundle_id: String,
    pub destination_directory: Option<String>,
    #[serde(default)]
    pub mode: Option<String>,
    #[serde(default)]
    pub compatibility_profile: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FridaScriptEntry {
    pub id: String,
    pub name: String,
    pub description: String,
    pub category: String,
    pub path: String,
    pub platform: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FridaServerRequest {
    pub serial: String,
    pub action: String,
    pub path: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FridaDownloadRequest {
    pub serial: String,
    pub destination_directory: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IosDeveloperImageRequest {
    pub serial: String,
    pub directory: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AppFinding {
    pub severity: String,
    pub title: String,
    pub detail: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProtectionAssessment {
    pub status: String,
    pub packers: Vec<String>,
    pub indicators: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AnalyzeAppRequest {
    pub path: String,
    pub apktool_path: Option<String>,
    pub jadx_path: Option<String>,
    #[serde(default)]
    pub excluded_url_patterns: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SensitiveItem {
    pub item: String,
    pub location: String,
    pub kind: String,
    pub severity: String,
    pub value: Option<String>,
    pub line_number: Option<usize>,
    pub context: Option<String>,
    #[serde(default)]
    pub source: String,
    #[serde(default)]
    pub filtered: bool,
    #[serde(default)]
    pub filter_reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RawInventoryItem {
    pub source: String,
    pub value: String,
    pub frequency: u32,
    pub covered: bool,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BinaryInsight {
    pub category: String,
    pub target: String,
    pub severity: String,
    pub detail: String,
    pub evidence: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CodeInsight {
    pub platform: String,
    pub kind: String,
    pub binary: String,
    pub class_name: Option<String>,
    pub name: String,
    pub signature: Option<String>,
    pub address: Option<String>,
    pub module_offset: Option<String>,
    pub source_file: Option<String>,
    pub line_number: Option<usize>,
    pub runtime_target: Option<String>,
    pub references: Vec<String>,
    pub snippet: Vec<String>,
    pub confidence: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AntiInstrumentationCandidate {
    pub label: String,
    pub signal: String,
    pub source: String,
    #[serde(default)]
    pub location: String,
    #[serde(default = "pending_runtime_status")]
    pub runtime: String,
    #[serde(default)]
    pub evidence: Vec<String>,
    #[serde(default)]
    pub filtered: bool,
    #[serde(default)]
    pub filter_reason: Option<String>,
}

fn pending_runtime_status() -> String {
    "pending".into()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AntiInstrumentationAssessment {
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub candidates: Vec<AntiInstrumentationCandidate>,
    #[serde(default)]
    pub indicators: Vec<String>,
}

impl Default for AntiInstrumentationAssessment {
    fn default() -> Self {
        Self {
            status: "not-detected".into(),
            candidates: Vec::new(),
            indicators: Vec::new(),
        }
    }
}

#[derive(Debug, Default)]
pub(super) struct StaticToolAnalysis {
    pub(super) sensitive_items: Vec<SensitiveItem>,
    pub(super) code_insights: Vec<CodeInsight>,
    pub(super) manifest_xml: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AppAnalysis {
    pub platform: String,
    pub path: String,
    pub file_name: String,
    pub file_size: u64,
    #[serde(default)]
    pub artifact_sha256: String,
    pub package_id: Option<String>,
    pub display_name: Option<String>,
    pub version_name: Option<String>,
    pub version_code: Option<String>,
    pub min_sdk: Option<String>,
    pub target_sdk: Option<String>,
    pub architectures: Vec<String>,
    pub frameworks: Vec<String>,
    pub third_party_libraries: Vec<String>,
    pub protection: ProtectionAssessment,
    #[serde(default)]
    pub anti_instrumentation: AntiInstrumentationAssessment,
    pub permissions: Vec<String>,
    pub components: Vec<String>,
    pub exported_components: Vec<String>,
    pub intent_filters: Vec<String>,
    pub manifest_flags: Vec<String>,
    pub files: Vec<String>,
    pub manifest_xml: Option<String>,
    pub sensitive_items: Vec<SensitiveItem>,
    #[serde(default)]
    pub raw_inventory: Vec<RawInventoryItem>,
    pub binary_insights: Vec<BinaryInsight>,
    pub code_insights: Vec<CodeInsight>,
    #[serde(default)]
    pub data_boundaries: Vec<DataBoundaryObservation>,
    #[serde(default)]
    pub scan_coverage: assessment::ScanCoverage,
    #[serde(default)]
    pub masvs_observations: Vec<assessment::MasvsObservation>,
    #[serde(default)]
    pub verification_recipes: Vec<assessment::VerificationRecipe>,
    pub signature: Option<String>,
    pub findings: Vec<AppFinding>,
    pub tools_used: Vec<String>,
    pub missing_dependencies: Vec<String>,
}
