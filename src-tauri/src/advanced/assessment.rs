use super::AppAnalysis;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanCoverage {
    pub archive_entries_total: usize,
    pub archive_entries_indexed: usize,
    pub archive_entries_omitted: usize,
    pub binary_candidates_total: usize,
    pub binary_candidates_selected: usize,
    pub binary_candidates_scanned: usize,
    pub oversized_binary_candidates: usize,
    pub unreadable_binary_candidates: usize,
    pub sensitive_items_discovered: usize,
    pub sensitive_items_returned: usize,
    pub code_insights_discovered: usize,
    pub code_insights_returned: usize,
    pub complete: bool,
    pub warnings: Vec<String>,
}

impl ScanCoverage {
    pub fn finalize(&mut self) {
        self.archive_entries_omitted = self
            .archive_entries_total
            .saturating_sub(self.archive_entries_indexed);
        self.complete = self.archive_entries_omitted == 0
            && self.binary_candidates_total == self.binary_candidates_selected
            && self.oversized_binary_candidates == 0
            && self.unreadable_binary_candidates == 0
            && self.sensitive_items_discovered == self.sensitive_items_returned
            && self.code_insights_discovered == self.code_insights_returned;
        self.warnings.clear();
        if self.archive_entries_omitted > 0 {
            self.warnings.push(format!(
                "归档条目过多：有 {} 个文件未进入索引。",
                self.archive_entries_omitted
            ));
        }
        if self.binary_candidates_total > self.binary_candidates_selected {
            self.warnings.push(format!(
                "二进制候选超过深度扫描预算：已选择 {}/{} 个。",
                self.binary_candidates_selected, self.binary_candidates_total
            ));
        }
        if self.oversized_binary_candidates > 0 {
            self.warnings.push(format!(
                "有 {} 个超大二进制超过单文件扫描上限。",
                self.oversized_binary_candidates
            ));
        }
        if self.unreadable_binary_candidates > 0 {
            self.warnings.push(format!(
                "有 {} 个二进制无法读取或解压。",
                self.unreadable_binary_candidates
            ));
        }
        if self.sensitive_items_discovered > self.sensitive_items_returned {
            self.warnings.push(format!(
                "敏感信息结果已按优先级保留 {}/{} 条。",
                self.sensitive_items_returned, self.sensitive_items_discovered
            ));
        }
        if self.code_insights_discovered > self.code_insights_returned {
            self.warnings.push(format!(
                "代码入口结果已按优先级保留 {}/{} 条。",
                self.code_insights_returned, self.code_insights_discovered
            ));
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MasvsObservation {
    pub control_id: String,
    pub group: String,
    pub title: String,
    pub status: String,
    pub severity: String,
    pub confidence: String,
    pub summary: String,
    pub evidence: Vec<String>,
    pub verification_steps: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerificationRecipe {
    pub id: String,
    pub title: String,
    pub platform: String,
    pub goal: String,
    pub related_controls: Vec<String>,
    pub prerequisites: Vec<String>,
    pub steps: Vec<String>,
    pub expected_evidence: Vec<String>,
}

struct ControlDefinition {
    id: &'static str,
    group: &'static str,
    title: &'static str,
    markers: &'static [&'static str],
    steps: &'static [&'static str],
}

const CONTROLS: &[ControlDefinition] = &[
    ControlDefinition {
        id: "MASVS-STORAGE-1",
        group: "STORAGE",
        title: "敏感数据本地存储",
        markers: &["sharedpreferences", "keychain", "keystore", "sqlite", "realm", "userdefaults", "database"],
        steps: &["运行登录、业务查询和退出流程后，检查 App 私有目录、数据库、Preferences/UserDefaults。", "确认 Token、口令、证件信息是否明文落盘，并验证退出登录后的清理行为。"],
    },
    ControlDefinition {
        id: "MASVS-CRYPTO-1",
        group: "CRYPTO",
        title: "加密算法与使用方式",
        markers: &["aes/ecb", "desede", "md5", "cccrypt", "cipher.getinstance", "commoncrypto", "cryptoswift"],
        steps: &["在运行时记录 Cipher/CommonCrypto 的算法、Key/IV 长度和调用堆栈。", "确认不存在 ECB、固定 IV、弱哈希签名或业务自制加密协议。"],
    },
    ControlDefinition {
        id: "MASVS-AUTH-1",
        group: "AUTH",
        title: "身份认证与会话",
        markers: &["login", "oauth", "authorization", "bearer", "token", "session", "credential", "biometric"],
        steps: &["记录登录、刷新 Token、退出登录和密码修改请求，检查会话失效与重放。", "切换账号、清理本地状态并恢复备份，确认不会复用上一账号凭据。"],
    },
    ControlDefinition {
        id: "MASVS-NETWORK-1",
        group: "NETWORK",
        title: "网络传输安全",
        markers: &["http://", "usescleartexttraffic=true", "nsallowsarbitraryloads", "endpoint", "baseurl", "urlsession", "okhttp", "afnetworking", "alamofire"],
        steps: &["通过受控代理覆盖登录、上传、支付/审批等关键流程，记录明文 HTTP、协议降级和敏感响应。", "将静态 BaseURL 与代理流量关联，确认测试覆盖全部业务域名。"],
    },
    ControlDefinition {
        id: "MASVS-NETWORK-2",
        group: "NETWORK",
        title: "服务端身份与证书校验",
        markers: &["pinning", "certificatepinner", "securitypolicy", "allowinvalidcertificates", "validatesdomainname", "sectrust", "challenge"],
        steps: &["分别使用合法证书、用户 CA、错误域名证书和过期证书验证信任策略。", "若存在 Pinning，记录证书/公钥来源、更新机制和失败路径；仅出现 API 名不能直接判定配置。"],
    },
    ControlDefinition {
        id: "MASVS-PLATFORM-1",
        group: "PLATFORM",
        title: "组件、IPC 与 Deep Link",
        markers: &["exported=true", "intent-filter", "deeplink", "url scheme", "contentprovider", "broadcastreceiver", "openurl"],
        steps: &["逐个验证导出 Activity/Service/Receiver/Provider 的权限、参数和登录态。", "对 Deep Link/Scheme 测试 Host/Path 白名单、参数注入和跨 App 劫持。"],
    },
    ControlDefinition {
        id: "MASVS-PLATFORM-2",
        group: "PLATFORM",
        title: "WebView 与原生桥接",
        markers: &["webview", "wkwebview", "javascriptinterface", "scriptmessagehandler", "jsbridge", "loadhtmlstring"],
        steps: &["枚举 JavaScript Bridge/MessageHandler，确认来源、方法和参数白名单。", "验证任意跳转、file:// 访问、混合内容以及不可信页面调用原生能力。"],
    },
    ControlDefinition {
        id: "MASVS-CODE-4",
        group: "CODE",
        title: "第三方组件与动态代码",
        markers: &["third-party", "sdk", "dexclassloader", "pathclassloader", "dlopen", "loadlibrary", "hotupdate", "jspatch"],
        steps: &["确认第三方 SDK 的准确版本、来源、初始化配置和权限范围。", "验证动态加载内容的来源校验、签名校验、更新回滚与传输保护。"],
    },
    ControlDefinition {
        id: "MASVS-RESILIENCE-1",
        group: "RESILIENCE",
        title: "运行环境完整性与调试面",
        markers: &["root", "jailbreak", "ptrace", "sysctl", "debuggable=true", "get-task-allow", "frida"],
        steps: &["在 Root/越狱、调试器附加和 Frida 环境下记录检测点与业务响应。", "区分提示、功能降级和进程终止，确认不会因检测逻辑产生敏感数据泄漏或拒绝服务。"],
    },
    ControlDefinition {
        id: "MASVS-RESILIENCE-2",
        group: "RESILIENCE",
        title: "完整性保护与代码保护",
        markers: &["packer", "加固", "codeprotect", "cryptid", "tamper", "integrity", "签名"],
        steps: &["将 FairPlay cryptid、第三方代码保护和业务完整性校验分别验证，避免混为同一结论。", "记录被保护模块、运行时恢复位置和修改后的失败行为。"],
    },
    ControlDefinition {
        id: "MASVS-PRIVACY-1",
        group: "PRIVACY",
        title: "隐私数据采集与流转",
        markers: &["camera", "contacts", "location", "phone", "email", "identity", "privacy", "usage description"],
        steps: &["将权限申请、实际 API 调用、网络目的地和隐私政策逐项对应。", "验证拒绝授权、撤销授权和最小化采集场景，记录仍被收集的数据。"],
    },
];

fn searchable_records(analysis: &AppAnalysis) -> Vec<(String, String, String)> {
    let mut values = Vec::new();
    for finding in &analysis.findings {
        values.push((
            format!("Finding: {}", finding.title),
            format!("{} {}", finding.title, finding.detail),
            finding.severity.clone(),
        ));
    }
    for flag in &analysis.manifest_flags {
        values.push((format!("Config: {flag}"), flag.clone(), "review".into()));
    }
    for component in &analysis.exported_components {
        values.push((
            format!("Exported: {component}"),
            component.clone(),
            "review".into(),
        ));
    }
    for item in &analysis.sensitive_items {
        if item.filtered {
            continue;
        }
        values.push((
            format!("{} · {}", item.item, item.location),
            format!(
                "{} {} {} {}",
                item.item,
                item.kind,
                item.location,
                item.value.as_deref().unwrap_or_default()
            ),
            item.severity.clone(),
        ));
    }
    for item in &analysis.binary_insights {
        values.push((
            format!("{} · {}", item.category, item.target),
            format!(
                "{} {} {}",
                item.category,
                item.target,
                item.evidence.join(" ")
            ),
            item.severity.clone(),
        ));
    }
    for item in &analysis.code_insights {
        values.push((
            format!("{} · {}", item.kind, item.name),
            format!(
                "{} {} {} {}",
                item.kind,
                item.class_name.as_deref().unwrap_or_default(),
                item.name,
                item.references.join(" ")
            ),
            "review".into(),
        ));
    }
    for item in &analysis.data_boundaries {
        values.push((
            format!("Boundary: {} · {}", item.boundary, item.title),
            format!(
                "{} {} {} {} {}",
                item.boundary,
                item.title,
                item.summary,
                item.endpoint.as_deref().unwrap_or_default(),
                item.evidence.join(" ")
            ),
            item.severity.clone(),
        ));
    }
    for item in &analysis.anti_instrumentation.candidates {
        if item.filtered {
            continue;
        }
        values.push((
            format!("Anti-Instrumentation: {} · {}", item.label, item.signal),
            format!(
                "anti-instrumentation {} {} {} {} {}",
                item.label, item.signal, item.source, item.location, item.runtime
            ),
            if item.runtime == "blocked" {
                "high"
            } else {
                "review"
            }
            .into(),
        ));
    }
    values
}

pub fn derive_masvs_observations(analysis: &AppAnalysis) -> Vec<MasvsObservation> {
    let records = searchable_records(analysis);
    CONTROLS
        .iter()
        .map(|control| {
            let mut seen = HashSet::new();
            let mut evidence = Vec::new();
            let mut severity = "info";
            for (label, searchable, item_severity) in &records {
                let lower = searchable.to_ascii_lowercase();
                if control.markers.iter().any(|marker| lower.contains(marker))
                    && seen.insert(label.clone())
                {
                    if item_severity == "high" {
                        severity = "high";
                    } else if severity != "high" {
                        severity = "review";
                    }
                    evidence.push(label.clone());
                    if evidence.len() >= 10 {
                        break;
                    }
                }
            }
            let has_runtime = analysis.data_boundaries.iter().any(|item| {
                matches!(item.source_type.as_str(), "runtime" | "static-correlated")
                    && control.markers.iter().any(|marker| {
                        format!("{} {} {}", item.boundary, item.title, item.summary)
                            .to_ascii_lowercase()
                            .contains(marker)
                    })
            });
            let status = if evidence.is_empty() {
                "not-assessed"
            } else if has_runtime {
                "runtime-observed"
            } else {
                "static-candidate"
            };
            MasvsObservation {
                control_id: control.id.into(),
                group: control.group.into(),
                title: control.title.into(),
                status: status.into(),
                severity: severity.into(),
                confidence: if has_runtime {
                    "high"
                } else if evidence.is_empty() {
                    "none"
                } else {
                    "medium"
                }
                .into(),
                summary: if evidence.is_empty() {
                    "当前证据中没有足够线索；这不代表该控制已通过，需要按步骤补测。".into()
                } else {
                    format!(
                        "发现 {} 条相关证据；先作为测试入口，完成运行时验证后再形成漏洞结论。",
                        evidence.len()
                    )
                },
                evidence,
                verification_steps: control.steps.iter().map(|value| (*value).into()).collect(),
            }
        })
        .collect()
}

pub fn derive_verification_recipes(
    platform: &str,
    observations: &[MasvsObservation],
) -> Vec<VerificationRecipe> {
    observations
        .iter()
        .filter(|item| {
            item.status != "not-assessed" || matches!(item.group.as_str(), "AUTH" | "PRIVACY")
        })
        .map(|item| VerificationRecipe {
            id: format!("verify-{}", item.control_id.to_ascii_lowercase()),
            title: format!("{} · {}", item.control_id, item.title),
            platform: platform.into(),
            goal: item.summary.clone(),
            related_controls: vec![item.control_id.clone()],
            prerequisites: match platform {
                "android" => vec![
                    "已连接 Android 测试设备或模拟器".into(),
                    "需要动态观察时已启动匹配版本的 frida-server".into(),
                ],
                _ => vec![
                    "已连接可调试/越狱 iOS 测试设备".into(),
                    "需要动态观察时 Frida 主机与设备版本兼容".into(),
                ],
            },
            steps: item.verification_steps.clone(),
            expected_evidence: vec![
                "保存命令/Frida 日志以及操作时间".into(),
                "记录实际类、方法、Endpoint 或本地文件位置".into(),
                "标记 confirmed / rejected / not-applicable，并写明判断依据".into(),
            ],
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::advanced::{AntiInstrumentationAssessment, AppFinding, ProtectionAssessment};

    fn analysis() -> AppAnalysis {
        AppAnalysis {
            platform: "ios".into(),
            path: "/tmp/app.ipa".into(),
            file_name: "app.ipa".into(),
            file_size: 1,
            artifact_sha256: "fixture".into(),
            package_id: None,
            display_name: None,
            version_name: None,
            version_code: None,
            min_sdk: None,
            target_sdk: None,
            architectures: vec![],
            frameworks: vec!["AFNetworking".into()],
            third_party_libraries: vec!["AFNetworking".into()],
            protection: ProtectionAssessment {
                status: "未命中".into(),
                packers: vec![],
                indicators: vec![],
            },
            anti_instrumentation: AntiInstrumentationAssessment::default(),
            permissions: vec![],
            components: vec![],
            exported_components: vec![],
            intent_filters: vec![],
            manifest_flags: vec![],
            files: vec![],
            manifest_xml: None,
            sensitive_items: vec![],
            raw_inventory: vec![],
            binary_insights: vec![],
            code_insights: vec![],
            data_boundaries: vec![],
            scan_coverage: ScanCoverage::default(),
            masvs_observations: vec![],
            verification_recipes: vec![],
            signature: None,
            findings: vec![AppFinding {
                severity: "high".into(),
                title: "iOS ATS 允许任意明文传输".into(),
                detail: "NSAllowsArbitraryLoads=true".into(),
            }],
            tools_used: vec![],
            missing_dependencies: vec![],
        }
    }

    #[test]
    fn maps_static_network_evidence_without_claiming_a_pass() {
        let items = derive_masvs_observations(&analysis());
        let network = items
            .iter()
            .find(|item| item.control_id == "MASVS-NETWORK-1")
            .unwrap();
        assert_eq!(network.status, "static-candidate");
        assert_eq!(network.severity, "high");
        assert!(!network.verification_steps.is_empty());
    }

    #[test]
    fn coverage_reports_every_truncation_source() {
        let mut coverage = ScanCoverage {
            archive_entries_total: 60_000,
            archive_entries_indexed: 50_000,
            binary_candidates_total: 120,
            binary_candidates_selected: 96,
            sensitive_items_discovered: 700,
            sensitive_items_returned: 500,
            ..Default::default()
        };
        coverage.finalize();
        assert!(!coverage.complete);
        assert!(coverage.warnings.len() >= 3);
    }
}
