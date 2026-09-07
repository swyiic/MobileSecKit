use super::{AppAnalysis, BinaryInsight, CodeInsight, SensitiveItem};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DataBoundaryObservation {
    pub id: String,
    pub boundary: String,
    pub direction: String,
    pub title: String,
    pub summary: String,
    pub source_type: String,
    pub source_location: Option<String>,
    pub platform: String,
    pub framework: Option<String>,
    pub data_types: Vec<String>,
    pub producer: Option<String>,
    pub consumer: Option<String>,
    pub operation: Option<String>,
    pub endpoint: Option<String>,
    pub runtime_target: Option<String>,
    pub severity: String,
    pub confidence: String,
    pub evidence: Vec<String>,
    pub correlation_key: Option<String>,
    pub observed_at: Option<u64>,
}

#[derive(Default)]
struct Draft {
    boundary: String,
    direction: String,
    title: String,
    summary: String,
    source_type: String,
    source_location: Option<String>,
    framework: Option<String>,
    data_types: Vec<String>,
    producer: Option<String>,
    consumer: Option<String>,
    operation: Option<String>,
    endpoint: Option<String>,
    runtime_target: Option<String>,
    severity: String,
    confidence: String,
    evidence: Vec<String>,
}

fn stable_id(value: &str) -> String {
    let mut hash = 0xcbf29ce484222325_u64;
    for byte in value.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("boundary-{hash:016x}")
}

fn normalize(value: &str) -> String {
    value
        .trim()
        .trim_matches(|c: char| {
            matches!(
                c,
                '"' | '\'' | '(' | ')' | '[' | ']' | '{' | '}' | ',' | ';'
            )
        })
        .to_ascii_lowercase()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

fn clean_lines(values: impl IntoIterator<Item = String>) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut output = Vec::new();
    for value in values {
        for line in value.lines() {
            let line = line.trim().trim_matches('\0');
            if line.is_empty() {
                continue;
            }
            let line: String = line.chars().take(420).collect();
            if seen.insert(line.clone()) {
                output.push(line);
            }
        }
    }
    output
}

fn endpoint_from(values: &[String]) -> Option<String> {
    values.iter().find_map(|value| {
        value.split_whitespace().find_map(|token| {
            let token = token.trim_matches(|c: char| {
                matches!(
                    c,
                    '"' | '\'' | '(' | ')' | '[' | ']' | '{' | '}' | ',' | ';'
                )
            });
            let lower = token.to_ascii_lowercase();
            ["https://", "http://", "wss://", "ws://"]
                .iter()
                .any(|prefix| lower.starts_with(prefix))
                .then(|| token.chars().take(320).collect())
        })
    })
}

fn infer_framework(searchable: &str) -> Option<String> {
    let lower = searchable.to_ascii_lowercase();
    [
        (
            "AFNetworking",
            &["afnetworking", "afhttp", "afurlsession"] as &[&str],
        ),
        ("Alamofire", &["alamofire"]),
        ("Moya", &["moya", "targettype"]),
        (
            "URLSession / CFNetwork",
            &["urlsession", "nsurlsession", "cfnetwork"],
        ),
        ("OkHttp", &["okhttp"]),
        ("Retrofit", &["retrofit", "@get(", "@post("]),
        ("WebKit", &["wkwebview", "webkit", "javascriptcore"]),
        (
            "Android WebView",
            &["addjavascriptinterface", "android.webkit", "webview"],
        ),
        ("Flutter", &["flutter", "methodchannel"]),
        ("React Native", &["react native", "rctbridge"]),
        ("Cordova / Capacitor", &["cordova", "capacitor"]),
        ("Keychain", &["keychain", "secitem"]),
        (
            "Android Keystore",
            &["androidkeystore", "android.security.keystore"],
        ),
        (
            "SQLite / Room",
            &["sqlite", "room database", "room.database"],
        ),
        ("CommonCrypto", &["commoncrypto", "cccrypt"]),
        (
            "JMCodeProtect",
            &["jmcodeprotect", "ipacodeprotect", "jmprotection"],
        ),
    ]
    .iter()
    .find(|(_, needles)| needles.iter().any(|needle| lower.contains(needle)))
    .map(|(name, _)| (*name).to_string())
}

fn infer_data_types(searchable: &str) -> Vec<String> {
    let lower = searchable.to_ascii_lowercase();
    let mut values = [
        (
            "credential",
            &["credential", "password", "username", "login"] as &[&str],
        ),
        ("token", &["token", "bearer", "authorization"]),
        ("cookie", &["cookie", "sessionid"]),
        ("certificate", &["certificate", "x509", "trust", "pinning"]),
        (
            "key",
            &["keychain", "keystore", "private key", "secret key"],
        ),
        (
            "PII",
            &["email", "phone", "location", "contacts", "biometric"],
        ),
        (
            "database record",
            &["sqlite", "realm", "core data", "room database"],
        ),
        (
            "JavaScript message",
            &["javascript", "webview", "js bridge"],
        ),
        (
            "request / response",
            &["http", "url", "request", "response", "endpoint"],
        ),
        (
            "code / module",
            &["dex", "dlopen", "loadlibrary", "dynamic code"],
        ),
    ]
    .iter()
    .filter(|(_, needles)| needles.iter().any(|needle| lower.contains(needle)))
    .map(|(label, _)| (*label).to_string())
    .collect::<Vec<_>>();
    if values.is_empty() {
        values.push("application data".into());
    }
    values
}

fn classify(searchable: &str) -> Option<(&'static str, &'static str)> {
    let lower = searchable.to_ascii_lowercase();
    let contains = |needles: &[&str]| needles.iter().any(|value| lower.contains(value));
    if contains(&[
        "tls",
        "trust",
        "certificate",
        "pinning",
        "hostnameverifier",
        "x509",
    ]) {
        Some(("tls", "egress"))
    } else if contains(&[
        "webview",
        "javascript",
        "js bridge",
        "wkwebview",
        "methodchannel",
        "rctbridge",
    ]) {
        Some(("webview", "bidirectional"))
    } else if contains(&[
        "http",
        "urlsession",
        "endpoint",
        "baseurl",
        "okhttp",
        "retrofit",
        "libcurl",
        "alamofire",
        "moya",
        "swiftnio",
    ]) {
        Some(("network", "egress"))
    } else if contains(&[
        "keychain",
        "sharedpreferences",
        "sqlite",
        "room",
        "realm",
        "core data",
        "userdefaults",
    ]) {
        Some(("storage", "internal"))
    } else if contains(&[
        "cipher",
        "crypto",
        "commoncrypto",
        "cccrypt",
        "keystore",
        "secure enclave",
        "aes",
        "rsa",
    ]) {
        Some(("crypto", "internal"))
    } else if contains(&[
        "dexclassloader",
        "dynamic dex",
        "dlopen",
        "loadlibrary",
        "dynamic load",
        "plugin",
    ]) {
        Some(("dynamic-code", "internal"))
    } else if contains(&["jni", "native bridge", "system.loadlibrary", "unity native"]) {
        Some(("native-bridge", "bidirectional"))
    } else if contains(&[
        "anti-debug",
        "jailbreak",
        "rooted",
        "ptrace",
        "sysctl",
        "codeprotect",
        "runtime integrity",
    ]) {
        Some(("runtime-integrity", "internal"))
    } else {
        None
    }
}

fn boundary_title(boundary: &str) -> &'static str {
    match boundary {
        "ingress" => "外部输入",
        "ipc" => "IPC / App 间通信",
        "webview" => "WebView / JS 桥接",
        "network" => "网络出口",
        "tls" => "TLS / 信任决策",
        "identity" => "身份 / 会话",
        "storage" => "本地存储",
        "crypto" => "密码学处理",
        "native-bridge" => "Native / Managed 桥接",
        "dynamic-code" => "动态代码 / 插件",
        "device" => "系统 / 设备数据",
        "runtime-integrity" => "运行时完整性 / 保护",
        _ => "数据边界",
    }
}

fn boundary_consumer(boundary: &str) -> &'static str {
    match boundary {
        "network" => "remote service",
        "tls" => "trust evaluator",
        "identity" => "identity / session subsystem",
        "storage" => "local data store",
        "crypto" => "cryptographic primitive",
        "webview" => "native / JavaScript bridge",
        "dynamic-code" => "runtime-loaded code",
        "runtime-integrity" => "integrity policy",
        _ => "application subsystem",
    }
}

fn push(output: &mut Vec<DataBoundaryObservation>, platform: &str, mut draft: Draft) {
    draft.evidence = clean_lines(draft.evidence);
    draft.data_types.sort();
    draft.data_types.dedup();
    let target = draft
        .endpoint
        .as_deref()
        .or(draft.runtime_target.as_deref())
        .or(draft.operation.as_deref())
        .or(draft.source_location.as_deref())
        .unwrap_or(&draft.title);
    let correlation_key = format!("{}|{}|{}", platform, draft.boundary, normalize(target));
    output.push(DataBoundaryObservation {
        id: stable_id(&correlation_key),
        boundary: draft.boundary,
        direction: draft.direction,
        title: draft.title,
        summary: draft.summary,
        source_type: draft.source_type,
        source_location: draft.source_location,
        platform: platform.into(),
        framework: draft.framework,
        data_types: draft.data_types,
        producer: draft.producer,
        consumer: draft.consumer,
        operation: draft.operation,
        endpoint: draft.endpoint,
        runtime_target: draft.runtime_target,
        severity: draft.severity,
        confidence: draft.confidence,
        evidence: draft.evidence,
        correlation_key: Some(correlation_key),
        observed_at: None,
    });
}

fn from_code(output: &mut Vec<DataBoundaryObservation>, platform: &str, item: &CodeInsight) {
    let searchable = format!(
        "{} {} {} {} {} {}",
        item.kind,
        item.class_name.as_deref().unwrap_or_default(),
        item.name,
        item.signature.as_deref().unwrap_or_default(),
        item.references.join(" "),
        item.snippet.join(" ")
    );
    let mapped = if item.kind.contains("network-entry") {
        Some(("network", "egress"))
    } else if item.kind.contains("tls-entry") {
        Some(("tls", "egress"))
    } else if item.kind.contains("webview-entry") {
        Some(("webview", "bidirectional"))
    } else if item.kind.contains("storage-entry") {
        Some(("storage", "internal"))
    } else if item.kind.contains("crypto-entry") {
        Some(("crypto", "internal"))
    } else if item.kind.contains("loader-entry") {
        Some(("dynamic-code", "internal"))
    } else if item.kind == "ios-codeprotect-map" {
        Some(("runtime-integrity", "internal"))
    } else {
        classify(&searchable)
    };
    let Some((boundary, direction)) = mapped else {
        return;
    };
    let owner = item
        .class_name
        .as_deref()
        .map(|class_name| format!("{class_name} :: {}", item.name))
        .unwrap_or_else(|| item.name.clone());
    let mut evidence = item.references.clone();
    evidence.extend(item.snippet.iter().take(5).cloned());
    if let Some(signature) = &item.signature {
        evidence.insert(0, signature.clone());
    }
    let endpoint = endpoint_from(&evidence);
    let (producer, consumer) = match boundary {
        "network" => (owner.clone(), "remote service".into()),
        "tls" => ("network client".into(), owner.clone()),
        "webview" => ("Web content / JavaScript".into(), owner.clone()),
        "storage" => (owner.clone(), "local data store".into()),
        "crypto" => ("application data".into(), owner.clone()),
        "dynamic-code" => (owner.clone(), "loaded code / native module".into()),
        _ => ("application process".into(), owner.clone()),
    };
    let source_location = item
        .source_file
        .as_ref()
        .map(|source| {
            item.line_number
                .map(|line| format!("{source}:{line}"))
                .unwrap_or_else(|| source.clone())
        })
        .or_else(|| Some(item.binary.clone()));
    push(
        output,
        platform,
        Draft {
            boundary: boundary.into(),
            direction: direction.into(),
            title: format!("{} · {owner}", boundary_title(boundary)),
            summary: format!(
                "静态代码中发现{}候选入口；需要运行时命中后才能确认真实数据流。",
                boundary_title(boundary)
            ),
            source_type: "static-code".into(),
            source_location,
            framework: infer_framework(&searchable),
            data_types: infer_data_types(&searchable),
            producer: Some(producer),
            consumer: Some(consumer),
            operation: Some(item.name.clone()),
            endpoint,
            runtime_target: item.runtime_target.clone(),
            severity: if matches!(boundary, "tls" | "webview" | "dynamic-code") {
                "review".into()
            } else {
                "info".into()
            },
            confidence: item.confidence.clone(),
            evidence,
        },
    );
}

fn from_binary(output: &mut Vec<DataBoundaryObservation>, platform: &str, item: &BinaryInsight) {
    let searchable = format!(
        "{} {} {} {}",
        item.category,
        item.target,
        item.detail,
        item.evidence.join(" ")
    );
    let Some((boundary, direction)) = classify(&searchable) else {
        return;
    };
    push(
        output,
        platform,
        Draft {
            boundary: boundary.into(),
            direction: direction.into(),
            title: format!("{} · {}", boundary_title(boundary), item.category),
            summary: item.detail.clone(),
            source_type: "binary".into(),
            source_location: Some(item.target.clone()),
            framework: infer_framework(&searchable),
            data_types: infer_data_types(&searchable),
            producer: Some("application binary".into()),
            consumer: Some(boundary_consumer(boundary).into()),
            operation: item.evidence.first().cloned(),
            endpoint: endpoint_from(&item.evidence),
            runtime_target: None,
            severity: item.severity.clone(),
            confidence: "medium".into(),
            evidence: item.evidence.clone(),
        },
    );
}

fn from_sensitive(output: &mut Vec<DataBoundaryObservation>, platform: &str, item: &SensitiveItem) {
    let value = item.value.as_deref().unwrap_or_default();
    let (boundary, direction, item_title, data_type) = match item.kind.as_str() {
        "url" | "api-endpoint" | "ip" => {
            ("network", "egress", "可见网络目标", "request / response")
        }
        "token" | "api-key" | "access-key" | "credential" | "secret" => {
            ("identity", "internal", "身份/会话材料", "token")
        }
        "private-key" => ("crypto", "internal", "私钥材料", "key"),
        "email" if item.severity == "high" => ("identity", "internal", "身份数据", "PII"),
        _ => return,
    };
    push(
        output,
        platform,
        Draft {
            boundary: boundary.into(),
            direction: direction.into(),
            title: format!("{item_title} · {}", item.item),
            summary: "在归档、反编译源码或二进制可见字符串中发现边界线索；不等同于运行时实际使用。"
                .into(),
            source_type: "sensitive".into(),
            source_location: Some(item.location.clone()),
            framework: infer_framework(item.context.as_deref().unwrap_or_default()),
            data_types: vec![data_type.into()],
            producer: Some("application package".into()),
            consumer: Some(boundary_consumer(boundary).into()),
            operation: Some(item.kind.clone()),
            endpoint: (boundary == "network" && !value.is_empty()).then(|| value.into()),
            runtime_target: None,
            severity: item.severity.clone(),
            confidence: "medium".into(),
            evidence: if item.kind == "private-key" {
                vec!["完整 PEM 私钥块已在 Sensitive information 中确认；原文和上下文未复制到 Data Boundaries。".into()]
            } else {
                vec![value.into(), item.context.clone().unwrap_or_default()]
            },
        },
    );
}

fn deduplicate(items: Vec<DataBoundaryObservation>) -> Vec<DataBoundaryObservation> {
    let mut positions = HashMap::<String, usize>::new();
    let mut output: Vec<DataBoundaryObservation> = Vec::new();
    for item in items {
        let key = item
            .correlation_key
            .clone()
            .unwrap_or_else(|| item.id.clone());
        if let Some(index) = positions.get(&key).copied() {
            let current = &mut output[index];
            current.evidence.extend(item.evidence);
            current.evidence = clean_lines(std::mem::take(&mut current.evidence));
            current.data_types.extend(item.data_types);
            current.data_types.sort();
            current.data_types.dedup();
            if current.source_type != item.source_type {
                current.source_type = "static-merged".into();
            }
            if current.endpoint.is_none() {
                current.endpoint = item.endpoint;
            }
            if current.runtime_target.is_none() {
                current.runtime_target = item.runtime_target;
            }
            if super::severity_rank(&item.severity) < super::severity_rank(&current.severity) {
                current.severity = item.severity;
            }
            if item.confidence.eq_ignore_ascii_case("high") {
                current.confidence = "high".into();
            }
        } else {
            positions.insert(key, output.len());
            output.push(item);
        }
    }
    output.sort_by(|left, right| {
        super::severity_rank(&left.severity)
            .cmp(&super::severity_rank(&right.severity))
            .then(left.boundary.cmp(&right.boundary))
            .then(left.title.cmp(&right.title))
    });
    output
}

pub fn derive_data_boundaries(analysis: &AppAnalysis) -> Vec<DataBoundaryObservation> {
    let mut output = Vec::new();
    for item in &analysis.code_insights {
        from_code(&mut output, &analysis.platform, item);
    }
    for item in &analysis.binary_insights {
        from_binary(&mut output, &analysis.platform, item);
    }
    for item in &analysis.sensitive_items {
        if !item.filtered {
            from_sensitive(&mut output, &analysis.platform, item);
        }
    }
    for component in &analysis.exported_components {
        push(
            &mut output,
            &analysis.platform,
            Draft {
                boundary: "ipc".into(),
                direction: "ingress".into(),
                title: format!("外部可达组件 · {component}"),
                summary: "组件可能接收来自其他 App、URL Scheme、Intent 或系统调度的输入；需校验权限、参数和调用前置条件。".into(),
                source_type: "manifest".into(),
                source_location: Some(if analysis.platform == "android" {
                    "AndroidManifest.xml".into()
                } else {
                    "Info.plist / entitlements".into()
                }),
                framework: None,
                data_types: vec!["IPC message".into()],
                producer: Some("external App / OS".into()),
                consumer: Some(component.clone()),
                operation: Some("component dispatch".into()),
                endpoint: None,
                runtime_target: None,
                severity: if component.contains("permission=") {
                    "review".into()
                } else {
                    "high".into()
                },
                confidence: "high".into(),
                evidence: vec![component.clone()],
            },
        );
    }
    for intent in &analysis.intent_filters {
        push(
            &mut output,
            &analysis.platform,
            Draft {
                boundary: "ingress".into(),
                direction: "ingress".into(),
                title: "Deep Link / Intent 输入".into(),
                summary: "声明的 URL Scheme、Universal Link 或 Intent Filter 构成外部输入边界。"
                    .into(),
                source_type: "manifest".into(),
                source_location: Some(if analysis.platform == "android" {
                    "AndroidManifest.xml".into()
                } else {
                    "Info.plist / entitlements".into()
                }),
                framework: None,
                data_types: vec!["URL / intent parameters".into()],
                producer: Some("browser / external App / OS".into()),
                consumer: Some("application route handler".into()),
                operation: Some("route dispatch".into()),
                endpoint: Some(intent.clone()),
                runtime_target: None,
                severity: "review".into(),
                confidence: "high".into(),
                evidence: vec![intent.clone()],
            },
        );
    }
    for permission in &analysis.permissions {
        let upper = permission.to_ascii_uppercase();
        let data_type = if upper.contains("CAMERA") {
            Some("camera frames")
        } else if upper.contains("LOCATION") {
            Some("location")
        } else if upper.contains("CONTACTS") {
            Some("contacts")
        } else if upper.contains("MICROPHONE") || upper.contains("RECORD_AUDIO") {
            Some("audio")
        } else if upper.contains("PHOTO") {
            Some("photos")
        } else if upper.contains("BIOMETRIC") || upper.contains("FACE_ID") {
            Some("biometric decision")
        } else {
            None
        };
        let Some(data_type) = data_type else {
            continue;
        };
        push(
            &mut output,
            &analysis.platform,
            Draft {
                boundary: "device".into(),
                direction: "ingress".into(),
                title: format!("系统数据访问 · {permission}"),
                summary: "权限声明表明 App 可能从操作系统或设备传感器读取数据；需在运行时确认调用时机与数据去向。".into(),
                source_type: "manifest".into(),
                source_location: Some(if analysis.platform == "android" {
                    "AndroidManifest.xml".into()
                } else {
                    "Info.plist".into()
                }),
                framework: None,
                data_types: vec![data_type.into()],
                producer: Some("OS / device sensor".into()),
                consumer: Some("application".into()),
                operation: Some(permission.clone()),
                endpoint: None,
                runtime_target: None,
                severity: "review".into(),
                confidence: "medium".into(),
                evidence: vec![permission.clone()],
            },
        );
    }
    for indicator in analysis
        .protection
        .indicators
        .iter()
        .chain(analysis.protection.packers.iter())
    {
        push(
            &mut output,
            &analysis.platform,
            Draft {
                boundary: "runtime-integrity".into(),
                direction: "internal".into(),
                title: "运行时保护 / 完整性边界".into(),
                summary: "静态包中命中代码保护、反调试、完整性校验或运行时恢复线索；这会影响 Attach/Spawn、代码可见性和采集稳定性。".into(),
                source_type: "protection".into(),
                source_location: Some(analysis.file_name.clone()),
                framework: infer_framework(indicator),
                data_types: vec!["process state".into(), "code / module".into()],
                producer: Some("instrumentation / process environment".into()),
                consumer: Some("integrity policy".into()),
                operation: Some("integrity / anti-debug check".into()),
                endpoint: None,
                runtime_target: None,
                severity: "review".into(),
                confidence: "medium".into(),
                evidence: vec![indicator.clone()],
            },
        );
    }
    for candidate in &analysis.anti_instrumentation.candidates {
        if candidate.filtered {
            continue;
        }
        let classloader_takeover = candidate.label.contains("类加载器接管")
            || matches!(
                candidate.signal.to_ascii_lowercase().as_str(),
                "mclassloader"
                    | "loadedapk"
                    | "dexpathlist"
                    | "dexelements"
                    | "combinedexelements"
                    | "inmemorydexclassloader"
            );
        push(
            &mut output,
            &analysis.platform,
            Draft {
                boundary: if classloader_takeover {
                    "dynamic-code".into()
                } else {
                    "anti-instrumentation".into()
                },
                direction: "internal".into(),
                title: candidate.label.clone(),
                summary: format!(
                    "命中 {}；运行时确认状态为 {}。{}",
                    candidate.signal,
                    candidate.runtime,
                    if classloader_takeover {
                        "可能来自整体加固、自研加载器或正常热修复，需枚举 ClassLoader 与 dexElements 确认。"
                    } else {
                        "静态候选不等同于真实拦截。"
                    }
                ),
                source_type: if candidate.runtime == "pending" {
                    "static-candidate".into()
                } else {
                    "runtime-observed".into()
                },
                source_location: Some(candidate.location.clone()),
                framework: None,
                data_types: if classloader_takeover {
                    vec!["dex / runtime code".into()]
                } else {
                    vec!["process instrumentation state".into()]
                },
                producer: Some(if classloader_takeover {
                    "ClassLoader / hotfix framework".into()
                } else {
                    "instrumentation runtime".into()
                }),
                consumer: Some(if classloader_takeover {
                    "runtime-loaded code".into()
                } else {
                    "anti-instrumentation policy".into()
                }),
                operation: Some(candidate.signal.clone()),
                endpoint: None,
                runtime_target: None,
                severity: if candidate.runtime == "blocked" {
                    "high".into()
                } else {
                    "review".into()
                },
                confidence: if candidate.runtime == "pending" {
                    "medium".into()
                } else {
                    "high".into()
                },
                evidence: candidate.evidence.clone(),
            },
        );
    }
    deduplicate(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::advanced::{AntiInstrumentationAssessment, AppFinding, ProtectionAssessment};

    fn empty_analysis() -> AppAnalysis {
        AppAnalysis {
            platform: "ios".into(),
            path: "/tmp/Test.ipa".into(),
            file_name: "Test.ipa".into(),
            file_size: 1,
            artifact_sha256: "fixture".into(),
            package_id: None,
            display_name: None,
            version_name: None,
            version_code: None,
            min_sdk: None,
            target_sdk: None,
            architectures: Vec::new(),
            frameworks: Vec::new(),
            third_party_libraries: Vec::new(),
            protection: ProtectionAssessment {
                status: "unknown".into(),
                packers: Vec::new(),
                indicators: Vec::new(),
            },
            anti_instrumentation: AntiInstrumentationAssessment::default(),
            permissions: Vec::new(),
            components: Vec::new(),
            exported_components: Vec::new(),
            intent_filters: Vec::new(),
            manifest_flags: Vec::new(),
            files: Vec::new(),
            manifest_xml: None,
            sensitive_items: Vec::new(),
            raw_inventory: Vec::new(),
            binary_insights: Vec::new(),
            code_insights: Vec::new(),
            data_boundaries: Vec::new(),
            scan_coverage: Default::default(),
            masvs_observations: Vec::new(),
            verification_recipes: Vec::new(),
            signature: None,
            findings: Vec::<AppFinding>::new(),
            tools_used: Vec::new(),
            missing_dependencies: Vec::new(),
        }
    }

    #[test]
    fn maps_objc_network_entry() {
        let mut analysis = empty_analysis();
        analysis.code_insights.push(CodeInsight {
            platform: "ios".into(),
            kind: "ios-network-entry".into(),
            binary: "Payload/Test.app/Test".into(),
            class_name: Some("AFHTTPSessionManager".into()),
            name: "dataTaskWithRequest:".into(),
            signature: None,
            address: None,
            module_offset: None,
            source_file: None,
            line_number: None,
            runtime_target: Some("-[AFHTTPSessionManager dataTaskWithRequest:]".into()),
            references: vec![
                "AFNetworking".into(),
                "https://api.example.test/v1/login".into(),
            ],
            snippet: Vec::new(),
            confidence: "high".into(),
        });
        let boundaries = derive_data_boundaries(&analysis);
        assert_eq!(boundaries.len(), 1);
        assert_eq!(boundaries[0].boundary, "network");
        assert_eq!(boundaries[0].framework.as_deref(), Some("AFNetworking"));
        assert_eq!(
            boundaries[0].endpoint.as_deref(),
            Some("https://api.example.test/v1/login")
        );
    }

    #[test]
    fn maps_classloader_takeover_review_to_dynamic_code() {
        let mut analysis = empty_analysis();
        analysis.platform = "android".into();
        analysis
            .anti_instrumentation
            .candidates
            .push(super::super::AntiInstrumentationCandidate {
                label: "类加载器接管 / 整体加固 / 热修复线索".into(),
                signal: "dexElements".into(),
                source: "content".into(),
                location: "classes.dex".into(),
                runtime: "pending".into(),
                evidence: vec!["classes.dex 命中 dexElements".into()],
                filtered: false,
                filter_reason: None,
            });
        let boundaries = derive_data_boundaries(&analysis);
        assert_eq!(boundaries.len(), 1);
        assert_eq!(boundaries[0].boundary, "dynamic-code");
        assert_eq!(boundaries[0].severity, "review");
        assert_eq!(boundaries[0].source_type, "static-candidate");
    }

    #[test]
    fn splits_evidence_and_deduplicates_target() {
        let mut analysis = empty_analysis();
        analysis.binary_insights.push(BinaryInsight {
            category: "URLSession / CFNetwork 网络入口".into(),
            target: "Payload/Test.app/Test".into(),
            severity: "review".into(),
            detail: "network entry".into(),
            evidence: vec!["https://api.example.test/v1\nNSURLSession".into()],
        });
        analysis.sensitive_items.push(SensitiveItem {
            item: "URL / API endpoint".into(),
            location: "Payload/Test.app/Test:10".into(),
            kind: "url".into(),
            severity: "review".into(),
            value: Some("https://api.example.test/v1".into()),
            line_number: None,
            context: None,
            source: "text-resource".into(),
            filtered: false,
            filter_reason: None,
        });
        let boundaries = derive_data_boundaries(&analysis);
        assert_eq!(boundaries.len(), 1);
        assert_eq!(boundaries[0].source_type, "static-merged");
        assert!(boundaries[0]
            .evidence
            .iter()
            .all(|line| !line.contains('\n')));
    }

    #[test]
    fn private_key_boundary_omits_value_and_context() {
        let mut analysis = empty_analysis();
        analysis.sensitive_items.push(SensitiveItem {
            item: "私钥内容（完整 PEM）".into(),
            location: "Config.pem".into(),
            kind: "private-key".into(),
            severity: "high".into(),
            value: Some(
                "-----BEGIN PRIVATE KEY-----\nDO_NOT_COPY_KEY\n-----END PRIVATE KEY-----".into(),
            ),
            line_number: Some(1),
            context: Some("1 | -----BEGIN PRIVATE KEY-----\n2 | DO_NOT_COPY_CONTEXT".into()),
            source: "text-resource".into(),
            filtered: false,
            filter_reason: None,
        });
        let boundaries = derive_data_boundaries(&analysis);
        assert_eq!(boundaries.len(), 1);
        let serialized = serde_json::to_string(&boundaries).expect("serialize boundaries");
        assert!(!serialized.contains("DO_NOT_COPY_KEY"));
        assert!(!serialized.contains("DO_NOT_COPY_CONTEXT"));
        assert!(serialized.contains("原文和上下文未复制"));
    }

    #[test]
    fn creates_manifest_boundaries() {
        let mut analysis = empty_analysis();
        analysis.platform = "android".into();
        analysis
            .exported_components
            .push("activity: com.example.DeepLinkActivity exported=true".into());
        analysis
            .permissions
            .push("android.permission.CAMERA".into());
        let boundaries = derive_data_boundaries(&analysis);
        assert!(boundaries
            .iter()
            .any(|item| item.boundary == "ipc" && item.severity == "high"));
        assert!(boundaries.iter().any(|item| {
            item.boundary == "device" && item.data_types.contains(&"camera frames".into())
        }));
    }
}
