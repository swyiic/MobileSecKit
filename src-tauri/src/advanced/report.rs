use super::*;
use serde::Deserialize;

fn report_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn report_opt(value: Option<&String>) -> String {
    value
        .map(|value| report_escape(value))
        .unwrap_or_else(|| "—".into())
}

fn report_list(items: &[String], empty: &str) -> String {
    if items.is_empty() {
        return format!("<p class=\"report-empty\">{}</p>", report_escape(empty));
    }
    items
        .iter()
        .map(|item| format!("<li><code>{}</code></li>", report_escape(item)))
        .collect::<String>()
}

fn report_badge(severity: &str) -> String {
    let class = match severity.to_ascii_lowercase().as_str() {
        "high" | "critical" => "high",
        "review" | "medium" => "review",
        _ => "info",
    };
    format!(
        "<span class=\"report-badge {class}\">{}</span>",
        report_escape(severity)
    )
}

fn render_binary_report_rows(items: &[BinaryInsight]) -> String {
    items
        .iter()
        .map(|item| {
            let search = report_escape(&format!(
                "{} {} {} {}",
                item.category,
                item.target,
                item.detail,
                item.evidence.join(" ")
            ));
            let evidence = if item.evidence.is_empty() {
                "<span class=\"muted\">没有附加字符串证据</span>".into()
            } else {
                item.evidence
                    .iter()
                    .map(|value| format!("<code>{}</code>", report_escape(value)))
                    .collect::<String>()
            };
            format!(
                "<article class=\"report-row\" data-search=\"{search}\"><div class=\"report-row-head\"><div>{badge}<strong>{category}</strong><span class=\"report-target\">{target}</span></div><button class=\"copy-button\" onclick=\"copyRow(this)\">复制</button></div><p>{detail}</p><div class=\"evidence-list\">{evidence}</div></article>",
                badge = report_badge(&item.severity),
                category = report_escape(&item.category),
                target = report_escape(&item.target),
                detail = report_escape(&item.detail),
                evidence = evidence
            )
        })
        .collect()
}

fn render_code_report_rows(items: &[CodeInsight]) -> String {
    items
        .iter()
        .map(|item| {
            let location = [
                item.address.clone(),
                item.module_offset
                    .as_ref()
                    .map(|value| format!("module+{value}")),
                item.source_file.as_ref().map(|value| {
                    format!(
                        "{}{}",
                        value,
                        item.line_number.map(|line| format!(":{line}")).unwrap_or_default()
                    )
                }),
                Some(item.binary.clone()),
            ]
            .into_iter()
            .flatten()
            .collect::<Vec<_>>()
            .join(" · ");
            let title = format!(
                "{} {} {} {} {} {}",
                item.kind,
                item.binary,
                item.class_name.as_deref().unwrap_or_default(),
                item.name,
                item.signature.as_deref().unwrap_or_default(),
                location
            );
            let references = if item.references.is_empty() {
                String::new()
            } else {
                format!(
                    "<dt>References</dt><dd>{}</dd>",
                    item.references
                        .iter()
                        .map(|value| format!("<code>{}</code>", report_escape(value)))
                        .collect::<String>()
                )
            };
            let snippet = if item.snippet.is_empty() {
                "<p class=\"muted\">没有附加源码/反汇编片段</p>".into()
            } else {
                format!("<pre>{}</pre>", report_escape(&item.snippet.join("\\n")))
            };
            format!(
                "<article class=\"report-row\" data-search=\"{}\"><div class=\"report-row-head\"><div>{badge}<strong>{kind}</strong><span class=\"report-target\">{name}</span></div><button class=\"copy-button\" onclick=\"copyRow(this)\">复制</button></div><dl class=\"report-meta\"><dt>Binary</dt><dd><code>{binary}</code></dd>{class_name}{signature}{location}{runtime}{references}</dl>{snippet}</article>",
                report_escape(&title),
                badge = report_badge(&item.confidence),
                kind = report_escape(&item.kind),
                name = report_escape(&item.name),
                binary = report_escape(&item.binary),
                class_name = item.class_name.as_ref().map(|value| format!("<dt>Class</dt><dd><code>{}</code></dd>", report_escape(value))).unwrap_or_default(),
                signature = item.signature.as_ref().map(|value| format!("<dt>Signature</dt><dd><code>{}</code></dd>", report_escape(value))).unwrap_or_default(),
                location = if location.is_empty() { String::new() } else { format!("<dt>Location</dt><dd><code>{}</code></dd>", report_escape(&location)) },
                runtime = item.runtime_target.as_ref().map(|value| format!("<dt>Frida target</dt><dd><code>{}</code></dd>", report_escape(value))).unwrap_or_default(),
                references = references,
                snippet = snippet
            )
        })
        .collect()
}

fn private_key_report_summary(value: Option<&String>) -> String {
    let Some(value) = value else {
        return "仅命中文件名或 PEM 开头；没有可导出的完整值".into();
    };
    let digest = format!("{:x}", Sha256::digest(value.as_bytes()));
    let complete = value.contains("-----END ") && value.contains("PRIVATE KEY-----");
    format!(
        "{} · {} 字符 · SHA-256 {} · 原文未写入 HTML，请在 App Analyzer 中显式复制或导出",
        if complete {
            "完整 PEM"
        } else {
            "PEM 开头（未找到 END）"
        },
        value.chars().count(),
        digest
    )
}

pub(super) fn render_sensitive_report_rows(items: &[SensitiveItem]) -> String {
    items
        .iter()
        .map(|item| {
            let is_private_key = item.kind == "private-key";
            let context = if is_private_key {
                "<p class=\"muted\">PEM 上下文可能包含密钥材料，已从 HTML 报告中省略。</p>".into()
            } else {
                item.context
                    .as_ref()
                    .map(|value| format!("<pre>{}</pre>", report_escape(value)))
                    .unwrap_or_default()
            };
            let searchable_value = if is_private_key { "PEM private key redacted" } else { item.value.as_deref().unwrap_or_default() };
            let search = report_escape(&format!("{} {} {} {}", item.item, item.location, searchable_value, item.kind));
            let value = if is_private_key {
                report_escape(&private_key_report_summary(item.value.as_ref()))
            } else {
                report_opt(item.value.as_ref())
            };
            format!(
                "<article class=\"report-row\" data-search=\"{search}\"><div class=\"report-row-head\"><div>{badge}<strong>{item_name}</strong><span class=\"report-target\">{location}</span></div><button class=\"copy-button\" onclick=\"copyRow(this)\">复制</button></div><p><b>类型：</b>{kind}　<b>值：</b>{value}</p>{context}</article>",
                search = search,
                badge = report_badge(&item.severity),
                item_name = report_escape(&item.item),
                location = report_escape(&item.location),
                kind = report_escape(&item.kind),
                value = value,
                context = context
            )
        })
        .collect()
}

fn render_boundary_report_rows(items: &[DataBoundaryObservation]) -> String {
    items.iter().map(|item| {
        let search = report_escape(&format!("{} {} {} {} {} {} {} {}", item.boundary, item.direction, item.title, item.summary, item.framework.as_deref().unwrap_or_default(), item.endpoint.as_deref().unwrap_or_default(), item.source_location.as_deref().unwrap_or_default(), item.evidence.join(" ")));
        let evidence = if item.evidence.is_empty() { "<p class=\"muted\">没有附加证据</p>".into() } else { format!("<ul class=\"boundary-evidence\">{}</ul>", item.evidence.iter().map(|value| format!("<li><code>{}</code></li>", report_escape(value))).collect::<String>()) };
        let data = if item.data_types.is_empty() { "—".into() } else { item.data_types.iter().map(|value| format!("<code>{}</code>", report_escape(value))).collect::<Vec<_>>().join(" ") };
        format!("<article class=\"report-row boundary-row\" data-search=\"{search}\"><div class=\"report-row-head\"><div>{badge}<strong>{boundary}</strong><span class=\"report-target\">{title}</span></div><button class=\"copy-button\" onclick=\"copyRow(this)\">复制</button></div><dl class=\"report-meta\"><dt>Direction</dt><dd>{direction}</dd><dt>Data</dt><dd>{data}</dd><dt>Producer → Consumer</dt><dd>{producer} → {consumer}</dd>{framework}{endpoint}{operation}{source}{runtime}<dt>Summary</dt><dd>{summary}</dd></dl>{evidence}</article>",
            search=search, badge=report_badge(&item.severity), boundary=report_escape(&item.boundary), title=report_escape(&item.title), direction=report_escape(&item.direction), data=data,
            producer=report_escape(item.producer.as_deref().unwrap_or("—")), consumer=report_escape(item.consumer.as_deref().unwrap_or("—")),
            framework=item.framework.as_ref().map(|value| format!("<dt>Framework</dt><dd><code>{}</code></dd>", report_escape(value))).unwrap_or_default(),
            endpoint=item.endpoint.as_ref().map(|value| format!("<dt>Endpoint</dt><dd><code>{}</code></dd>", report_escape(value))).unwrap_or_default(),
            operation=item.operation.as_ref().map(|value| format!("<dt>Operation</dt><dd><code>{}</code></dd>", report_escape(value))).unwrap_or_default(),
            source=item.source_location.as_ref().map(|value| format!("<dt>Source</dt><dd><code>{}</code></dd>", report_escape(value))).unwrap_or_default(),
            runtime=item.runtime_target.as_ref().map(|value| format!("<dt>Runtime target</dt><dd><code>{}</code></dd>", report_escape(value))).unwrap_or_default(),
            summary=report_escape(&item.summary), evidence=evidence)
    }).collect()
}

fn render_anti_instrumentation_rows(items: &[AntiInstrumentationCandidate]) -> String {
    items
        .iter()
        .map(|item| {
            let severity = if item.filtered {
                "info"
            } else { match item.runtime.as_str() {
                "blocked" => "high",
                "passed" => "info",
                _ => "review",
            }};
            let evidence = if item.evidence.is_empty() {
                "<p class=\"muted\">没有附加证据</p>".into()
            } else {
                format!(
                    "<ul class=\"boundary-evidence\">{}</ul>",
                    item.evidence
                        .iter()
                        .map(|value| format!("<li><code>{}</code></li>", report_escape(value)))
                        .collect::<String>()
                )
            };
            format!(
                "<article class=\"report-row\" data-search=\"{}\"><div class=\"report-row-head\"><div>{}<strong>{}</strong><code>{}</code></div></div><dl class=\"report-meta\"><dt>Source</dt><dd>{}</dd><dt>Location</dt><dd><code>{}</code></dd><dt>Runtime</dt><dd><b>{}</b></dd></dl>{}</article>",
                report_escape(&format!("{} {} {} {} {}", item.label, item.signal, item.source, item.location, item.runtime)),
                report_badge(severity),
                report_escape(&item.label),
                report_escape(&item.signal),
                report_escape(&item.source),
                report_escape(&item.location),
                report_escape(if item.filtered { "filtered" } else { &item.runtime }),
                evidence,
            )
        })
        .collect()
}

fn render_masvs_report_rows(
    items: &[assessment::MasvsObservation],
    verdicts: &HashMap<String, String>,
) -> String {
    items
        .iter()
        .map(|item| {
            let evidence = if item.evidence.is_empty() {
                "<p class=\"muted\">当前没有直接证据；不能据此判定通过。</p>".into()
            } else {
                format!(
                    "<ul class=\"boundary-evidence\">{}</ul>",
                    item.evidence
                        .iter()
                        .map(|value| format!("<li><code>{}</code></li>", report_escape(value)))
                        .collect::<String>()
                )
            };
            let steps = item
                .verification_steps
                .iter()
                .map(|value| format!("<li>{}</li>", report_escape(value)))
                .collect::<String>();
            let verdict = verdicts
                .get(&item.control_id)
                .map(String::as_str)
                .filter(|value| !value.is_empty())
                .unwrap_or("pending");
            format!(
                "<article class=\"report-row\" data-search=\"{search}\"><div class=\"report-row-head\"><div>{badge}<strong>{id}</strong><span class=\"report-target\">{title}</span></div><span>{status} · verdict={verdict}</span></div><p>{summary}</p>{evidence}<h3>验证步骤</h3><ol>{steps}</ol></article>",
                search = report_escape(&format!(
                    "{} {} {} {} {}",
                    item.control_id,
                    item.group,
                    item.title,
                    item.summary,
                    item.evidence.join(" ")
                )),
                badge = report_badge(&item.severity),
                id = report_escape(&item.control_id),
                title = report_escape(&item.title),
                status = report_escape(&item.status),
                verdict = report_escape(verdict),
                summary = report_escape(&item.summary),
                evidence = evidence,
                steps = steps,
            )
        })
        .collect()
}

pub(super) fn code_insight_focus_score(item: &CodeInsight) -> i32 {
    let kind = item.kind.as_str();
    let searchable = format!(
        "{} {} {} {} {}",
        item.name,
        item.class_name.as_deref().unwrap_or_default(),
        item.signature.as_deref().unwrap_or_default(),
        item.references.join(" "),
        item.binary
    )
    .to_ascii_lowercase();
    let name = item
        .name
        .trim_matches(|character| matches!(character, '+' | '-' | ' ' | ':'))
        .to_ascii_lowercase();
    const GENERIC_NAMES: &[&str] = &[
        "tx",
        "misuse",
        "error",
        "s",
        "local",
        "illegal",
        "either",
        "group",
        "task",
        "isincluded",
        "allocwithzone",
        "automaticallynotifiesobserversforkey",
        "initwithcoder",
        "swift",
        "std",
        "http",
        "https",
        "isempty",
        "iscancelled",
        "hastaskgroupstatusrecord",
        "distribution",
        "a",
    ];
    if GENERIC_NAMES.contains(&name.as_str()) {
        return -100;
    }
    const SIGNAL_MARKERS: &[&str] = &[
        "baseurl",
        "endpoint",
        "request",
        "response",
        "session",
        "urlsession",
        "afnetwork",
        "alamofire",
        "moya",
        "retrofit",
        "okhttp",
        "socket",
        "websocket",
        "challenge",
        "trust",
        "certificate",
        "pinning",
        "pinner",
        "keychain",
        "secureenclave",
        "encrypt",
        "decrypt",
        "signature",
        "verify",
        "authentication",
        "authorize",
        "login",
        "logout",
        "token",
        "password",
        "credential",
        "fido",
        "webview",
        "javascript",
        "openurl",
        "deep link",
        "jailbreak",
        "ptrace",
        "sysctl",
        "dlopen",
        "dlsym",
        "sectrust",
        "secitem",
        "cccrypt",
        "crypto",
    ];
    let marker_hit = SIGNAL_MARKERS
        .iter()
        .any(|marker| searchable.contains(marker));
    let third_party_binary = {
        let lower = item.binary.to_ascii_lowercase();
        lower.contains("/frameworks/")
            || lower.contains("/pods/")
            || lower.contains("libswift")
            || lower.contains("swiftstdlib")
            || lower.ends_with(".dylib")
    };
    match kind {
        "ios-codeprotect-map" => 140,
        "ios-network-entry"
        | "ios-tls-entry"
        | "ios-webview-entry"
        | "ios-crypto-entry"
        | "ios-security-entry"
        | "android-network-entry"
        | "android-tls-entry"
        | "android-webview-entry"
        | "android-crypto-entry"
        | "android-storage-entry"
        | "android-loader-entry" => 120,
        "ios-native-import" if marker_hit => 110,
        "ios-native-symbol" if marker_hit => 100,
        "ios-objc-method" | "android-method" if marker_hit => 95,
        "ios-objc-class" | "android-class" if marker_hit => 85,
        "ios-objc-class" | "android-class"
            if !third_party_binary && name.len() >= 4 && name.chars().any(char::is_alphabetic) =>
        {
            55
        }
        "ios-objc-method" | "android-method"
            if !third_party_binary
                && name.len() >= 4
                && item
                    .class_name
                    .as_deref()
                    .is_some_and(|class_name| class_name.len() >= 4) =>
        {
            50
        }
        _ => 10,
    }
}

pub(super) fn low_signal_binary_evidence(value: &str) -> bool {
    let trimmed = value.trim();
    let lower = trimmed.to_ascii_lowercase();
    if trimmed.is_empty() || contains_format_placeholder(trimmed) {
        return true;
    }
    if lower.contains("/runner/work/")
        || lower.contains("/deriveddata/")
        || (lower.contains("/modules/")
            && [".cpp", ".cc", ".cxx"]
                .iter()
                .any(|suffix| lower.contains(suffix)))
    {
        return true;
    }
    const GENERIC: &[&str] = &[
        "tx",
        "misuse",
        "error",
        "s",
        "local",
        "illegal",
        "either",
        "group",
        "task",
        "isincluded",
        "allocwithzone",
        "automaticallynotifiesobserversforkey",
        "initwithcoder",
        "swift",
        "std",
        "http",
        "https",
        "distribution",
        "sd",
        "a",
    ];
    GENERIC.contains(&lower.as_str())
        || (trimmed.len() <= 2
            && !trimmed.contains('/')
            && !trimmed.contains(':')
            && !trimmed.contains('.'))
}

fn compact_analysis_for_report(analysis: &mut AppAnalysis) {
    analysis.code_insights.sort_by(|left, right| {
        code_insight_focus_score(right)
            .cmp(&code_insight_focus_score(left))
            .then(left.kind.cmp(&right.kind))
            .then(left.class_name.cmp(&right.class_name))
            .then(left.name.cmp(&right.name))
    });
    analysis
        .code_insights
        .retain(|item| code_insight_focus_score(item) >= 50);
    analysis.code_insights.truncate(600);
    for item in &mut analysis.code_insights {
        let score = code_insight_focus_score(item);
        item.references
            .retain(|value| !low_signal_binary_evidence(value));
        item.references.truncate(8);
        if score < 90 {
            item.snippet.clear();
        } else {
            item.snippet.truncate(5);
            for line in &mut item.snippet {
                *line = line.chars().take(260).collect();
            }
        }
    }

    analysis.binary_insights.sort_by(|left, right| {
        severity_rank(&left.severity)
            .cmp(&severity_rank(&right.severity))
            .then(left.category.cmp(&right.category))
            .then(left.target.cmp(&right.target))
    });
    for insight in &mut analysis.binary_insights {
        insight
            .evidence
            .retain(|value| !low_signal_binary_evidence(value));
        insight.evidence.truncate(20);
    }
    analysis
        .binary_insights
        .retain(|insight| !insight.evidence.is_empty());
    analysis.binary_insights.truncate(100);

    analysis.sensitive_items.sort_by(|left, right| {
        severity_rank(&left.severity)
            .cmp(&severity_rank(&right.severity))
            .then(sensitive_kind_rank(&left.kind).cmp(&sensitive_kind_rank(&right.kind)))
            .then(left.location.cmp(&right.location))
    });
    analysis.sensitive_items.truncate(140);
    for item in &mut analysis.sensitive_items {
        if let Some(context) = &mut item.context {
            *context = context
                .lines()
                .take(3)
                .map(|line| line.chars().take(320).collect::<String>())
                .collect::<Vec<_>>()
                .join("\n");
        }
    }
    analysis.data_boundaries.sort_by(|left, right| {
        severity_rank(&left.severity)
            .cmp(&severity_rank(&right.severity))
            .then(left.boundary.cmp(&right.boundary))
            .then(left.title.cmp(&right.title))
    });
    analysis.data_boundaries.truncate(240);
    for item in &mut analysis.data_boundaries {
        item.evidence.truncate(10);
    }
    analysis.files.clear();
    analysis.manifest_xml = None;
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExportSensitiveValueRequest {
    pub value: String,
    pub output_path: String,
}

pub fn export_sensitive_value(request: ExportSensitiveValueRequest) -> Result<String, String> {
    const MAX_EXPORT_BYTES: usize = 64 * 1024;
    let value = request.value;
    let output_path = request.output_path.trim();
    if value.trim().is_empty() {
        return Err("敏感值为空，无法导出".into());
    }
    if value.len() > MAX_EXPORT_BYTES {
        return Err(format!(
            "敏感值超过 {} KiB 导出上限",
            MAX_EXPORT_BYTES / 1024
        ));
    }
    if output_path.is_empty() {
        return Err("导出路径不能为空".into());
    }
    let path = std::path::Path::new(output_path);
    if fs::symlink_metadata(path).is_ok_and(|metadata| metadata.file_type().is_symlink()) {
        return Err("拒绝覆盖符号链接导出文件".into());
    }
    fs::write(output_path, value.as_bytes()).map_err(|error| format!("写入敏感值失败：{error}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut permissions = fs::metadata(output_path)
            .map_err(|error| format!("读取导出文件权限失败：{error}"))?
            .permissions();
        permissions.set_mode(0o600);
        fs::set_permissions(output_path, permissions)
            .map_err(|error| format!("设置导出文件权限失败：{error}"))?;
    }
    Ok(output_path.to_string())
}

pub fn export_analysis_html(
    analysis: AppAnalysis,
    output_path: String,
    verdicts: Option<HashMap<String, String>>,
    notes: Option<String>,
) -> Result<String, String> {
    export_analysis_html_internal(analysis, output_path, false, verdicts, notes)
}

pub fn export_analysis_html_compact(
    analysis: AppAnalysis,
    output_path: String,
    verdicts: Option<HashMap<String, String>>,
    notes: Option<String>,
) -> Result<String, String> {
    export_analysis_html_internal(analysis, output_path, true, verdicts, notes)
}

fn export_analysis_html_internal(
    mut analysis: AppAnalysis,
    output_path: String,
    compact: bool,
    verdicts: Option<HashMap<String, String>>,
    notes: Option<String>,
) -> Result<String, String> {
    if output_path.trim().is_empty() {
        return Err("HTML 输出路径不能为空".into());
    }
    if compact {
        compact_analysis_for_report(&mut analysis);
    }
    let verdicts = verdicts.unwrap_or_default();
    let assessment_notes = notes
        .filter(|value| !value.trim().is_empty())
        .map(|value| {
            format!(
                "<section class=\"report-section\"><h2>项目复核备注</h2><pre>{}</pre></section>",
                report_escape(&value)
            )
        })
        .unwrap_or_default();
    let app_title = analysis
        .display_name
        .as_deref()
        .unwrap_or(&analysis.file_name);
    let title = report_escape(app_title);
    let framework_list = report_list(&analysis.frameworks, "未识别到已知框架");
    let library_list = report_list(&analysis.third_party_libraries, "未识别到第三方库");
    let permission_list = report_list(&analysis.permissions, "未读取到权限");
    let component_list = report_list(&analysis.components, "未读取到组件");
    let exported_list = report_list(&analysis.exported_components, "未发现导出组件");
    let intent_list = report_list(&analysis.intent_filters, "未发现 Intent Filter / Deep Link");
    let flag_list = report_list(&analysis.manifest_flags, "未显式配置安全 Flag");
    let file_list = report_list(&analysis.files, "没有归档条目");
    let missing_list = report_list(&analysis.missing_dependencies, "没有已知缺失依赖");
    let findings = analysis
        .findings
        .iter()
        .map(|finding| {
            format!(
                "<article class=\"finding-card\">{}{}</article>",
                report_badge(&finding.severity),
                format!(
                    "<div><strong>{}</strong><p>{}</p></div>",
                    report_escape(&finding.title),
                    report_escape(&finding.detail)
                )
            )
        })
        .collect::<String>();
    let manifest = analysis.manifest_xml.as_ref().map(|value| format!("<section class=\"report-section\"><h2>AndroidManifest.xml</h2><pre>{}</pre></section>", report_escape(value))).unwrap_or_default();
    let html = format!(
        r##"<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{title} · App Analyzer</title>
<style>
:root{{color-scheme:dark;--bg:#0b1020;--panel:#111a2d;--panel2:#17233b;--line:#263653;--text:#e8eefc;--muted:#91a1bd;--accent:#71d3ff;--high:#ff6b7d;--review:#ffc66d;--info:#7fdbb3;--shadow:0 18px 50px #0005}}
*{{box-sizing:border-box}}body{{margin:0;background:radial-gradient(circle at 10% 0,#1d3860 0,transparent 35%),var(--bg);color:var(--text);font:14px/1.55 ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}}main{{max-width:1500px;margin:0 auto;padding:34px 28px 80px}}header.hero{{display:flex;justify-content:space-between;gap:28px;align-items:flex-end;padding:28px;border:1px solid #ffffff12;border-radius:24px;background:linear-gradient(135deg,#172b4cdd,#10192ddd);box-shadow:var(--shadow)}}h1{{margin:4px 0 6px;font-size:32px;letter-spacing:-.02em}}h2{{margin:0 0 14px;font-size:20px}}h3{{margin:0;font-size:16px}}p{{color:var(--muted);margin:8px 0}}.eyebrow{{color:var(--accent);font-size:11px;letter-spacing:.16em;font-weight:800}}.hero-meta{{display:grid;grid-template-columns:repeat(2,minmax(130px,1fr));gap:10px;min-width:360px}}.metric,.meta-card{{padding:13px 15px;background:#ffffff08;border:1px solid #ffffff12;border-radius:14px}}.metric span,.meta-card span{{display:block;color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.08em}}.metric strong,.meta-card strong{{display:block;margin-top:3px;word-break:break-word}}.toolbar{{position:sticky;top:12px;z-index:4;display:flex;gap:12px;align-items:center;margin:18px 0;padding:12px 14px;background:#10192df2;border:1px solid var(--line);border-radius:16px;backdrop-filter:blur(12px)}}input,select{{border:1px solid var(--line);background:#0b1324;color:var(--text);border-radius:10px;padding:10px 12px}}input{{flex:1;min-width:180px}}button{{border:0;border-radius:9px;padding:8px 11px;background:#ffffff10;color:var(--text);cursor:pointer}}button:hover{{background:#ffffff20}}.report-section{{margin-top:18px;padding:22px;border:1px solid var(--line);border-radius:20px;background:linear-gradient(180deg,#111a2df2,#0f1729e8);box-shadow:0 10px 35px #0002}}.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:10px}}.list-grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:10px}}ul{{margin:0;padding:0;list-style:none}}li{{padding:8px 11px;border-bottom:1px solid #ffffff0a;overflow-wrap:anywhere}}code,pre{{font-family:ui-monospace,SFMono-Regular,Menlo,monospace}}code{{color:#c9e8ff;overflow-wrap:anywhere}}pre{{white-space:pre-wrap;overflow:auto;padding:14px;background:#070d19;border:1px solid #ffffff0d;border-radius:10px;color:#c8d4e9;font-size:12px;max-height:520px}}.report-row{{padding:15px 0;border-top:1px solid #ffffff12}}.report-row:first-child{{border-top:0}}.report-row-head{{display:flex;justify-content:space-between;gap:12px;align-items:flex-start}}.report-row-head>div{{display:flex;gap:9px;align-items:center;flex-wrap:wrap}}.report-target{{color:var(--muted);overflow-wrap:anywhere}}.report-badge{{display:inline-block;padding:2px 8px;border-radius:999px;font-size:11px;font-weight:800;text-transform:uppercase;background:#ffffff12;color:var(--info)}}.report-badge.high{{background:#ff6b7d22;color:var(--high)}}.report-badge.review{{background:#ffc66d22;color:var(--review)}}.evidence-list{{display:flex;flex-wrap:wrap;gap:7px;margin-top:10px}}.evidence-list code{{padding:4px 7px;border-radius:6px;background:#ffffff0b}}.boundary-evidence{{display:grid;gap:5px;margin:10px 0 0;padding:0;list-style:none}}.boundary-evidence li{{padding:6px 8px;border:1px solid #ffffff0b;border-radius:7px;background:#070d19}}.boundary-evidence code{{display:block;white-space:pre-wrap;word-break:break-all;font-size:11px}}.report-meta{{display:grid;grid-template-columns:120px 1fr;gap:5px 12px;margin:10px 0;color:var(--muted)}}.report-meta dt{{font-size:12px}}.report-meta dd{{margin:0;overflow-wrap:anywhere}}.muted,.report-empty{{color:var(--muted)}}.finding-card{{display:flex;gap:12px;padding:13px 0;border-top:1px solid #ffffff12}}.finding-card:first-child{{border-top:0}}.finding-card strong{{display:block}}.finding-card p{{margin:3px 0}}.count{{color:var(--muted);font-size:12px}}.copy-button{{font-size:12px;white-space:nowrap}}.hidden{{display:none!important}}.print-note{{color:var(--muted);font-size:12px}}@media(max-width:760px){{main{{padding:18px 12px 50px}}header.hero{{display:block}}.hero-meta{{margin-top:20px;min-width:0}}.toolbar{{position:static;flex-wrap:wrap}}.toolbar input{{flex-basis:100%}}}}
@media print{{body{{background:#fff;color:#111}}main{{max-width:none;padding:0}}header.hero,.toolbar,.report-section{{box-shadow:none;background:#fff;border-color:#bbb;color:#111}}p,.muted,.report-target,.count,.print-note{{color:#444}}pre,.metric,.meta-card{{background:#f5f5f5;color:#111;border-color:#ccc}}.report-row{{break-inside:avoid}}.copy-button{{display:none}}}}
</style></head><body><main>
<header class="hero"><div><div class="eyebrow">LOCAL APP ANALYSIS REPORT</div><h1>{title}</h1><p>{platform} · {file_name} · {report_mode}</p><p class="print-note">生成时间：{generated} · 数据来自本机静态分析，静态命中需要结合运行时验证。</p></div><div class="hero-meta"><div class="metric"><span>Code intelligence</span><strong>{code_count}</strong></div><div class="metric"><span>Binary intelligence</span><strong>{binary_count}</strong></div><div class="metric"><span>Sensitive items</span><strong>{sensitive_count}</strong></div><div class="metric"><span>Frameworks</span><strong>{framework_count}</strong></div></div></header>
<div class="toolbar"><input id="search" placeholder="搜索类、方法、Selector、Endpoint、域名、地址、Framework…"><select id="severity"><option value="">全部置信度/严重性</option><option value="high">high / critical</option><option value="review">review / medium</option><option value="info">info / low</option></select><button onclick="window.print()">打印 / PDF</button><span id="visible" class="count"></span></div>
<section class="report-section"><h2>Overview</h2><div class="grid"><div class="meta-card"><span>Bundle / Package</span><strong>{package_id}</strong></div><div class="meta-card"><span>{version_label}</span><strong>{version}</strong></div><div class="meta-card"><span>Size</span><strong>{size}</strong></div><div class="meta-card"><span>Architectures</span><strong>{architectures}</strong></div><div class="meta-card"><span>Protection</span><strong>{protection}</strong></div><div class="meta-card"><span>Signature</span><strong>{signature}</strong></div><div class="meta-card"><span>Artifact SHA-256</span><strong>{artifact_sha256}</strong></div><div class="meta-card"><span>Source path</span><strong>{path}</strong></div></div></section>
<section class="report-section"><h2>Scan coverage · {coverage_state}</h2><div class="grid"><div class="meta-card"><span>Archive index</span><strong>{archive_indexed} / {archive_total}</strong></div><div class="meta-card"><span>Deep binaries</span><strong>{binary_scanned} / {binary_candidates}</strong></div><div class="meta-card"><span>Sensitive results</span><strong>{sensitive_returned} / {sensitive_discovered}</strong></div><div class="meta-card"><span>Code results</span><strong>{code_returned} / {code_discovered}</strong></div></div><ul>{coverage_warnings}</ul></section>
<section class="report-section"><h2>Frameworks & Libraries</h2><div class="list-grid"><div><h3>Detected frameworks</h3><ul>{framework_list}</ul></div><div><h3>Third-party libraries</h3><ul>{library_list}</ul></div></div></section>
<section class="report-section"><h2>Protection</h2><p><b>Status：</b>{protection_status}</p><p><b>Packer / SDK hints：</b>{packers}</p><ul>{indicators}</ul></section>
<section class="report-section"><h2>Anti-Instrumentation <span class="count">{anti_count} candidates</span></h2><p><b>Status：</b>{anti_status}。静态候选仅表示存在检测或插桩线索，runtime 字段来自零 Hook 探针确认。</p><div id="anti-instrumentation-list">{anti_rows}</div></section>
<section class="report-section"><h2>MASVS verification matrix <span class="count">{masvs_count} controls</span></h2><p>static-candidate 仅表示存在测试入口；没有证据也不能视为通过。请按验证步骤补充运行时证据和人工结论。</p><div id="masvs-list">{masvs_rows}</div></section>
{assessment_notes}
<section class="report-section"><h2>Data boundaries <span class="count">{boundary_count} observations</span></h2><p>将静态代码、二进制、Manifest、敏感项和保护线索统一为数据边界候选；每一条证据独占一行。correlated 表示多个静态来源指向同一目标，不等于运行时确认。</p><div id="boundary-list">{boundary_rows}</div></section>
<section class="report-section"><h2>Binary / Framework intelligence <span class="count">{binary_count} entries</span></h2><p>每一条证据单独成行；可搜索、复制，并保留目标文件、入口类别和静态证据。</p><div id="binary-list">{binary_rows}</div></section>
<section class="report-section"><h2>Code intelligence <span class="count">{code_count} entries</span></h2><p>保留类、方法、Selector、签名、IMP/地址、module offset、Frida target、引用和源码/反汇编片段。</p><div id="code-list">{code_rows}</div></section>
<section class="report-section"><h2>Sensitive information / location <span class="count">{sensitive_count} entries</span></h2><div id="sensitive-list">{sensitive_rows}</div></section>
<section class="report-section"><h2>Findings <span class="count">{finding_count}</span></h2>{findings}</section>
<section class="report-section"><h2>{configuration_title} & entry points</h2><div class="list-grid"><div><h3>Permissions / Privacy usage</h3><ul>{permission_list}</ul></div><div><h3>Components</h3><ul>{component_list}</ul></div><div><h3>Exported components</h3><ul>{exported_list}</ul></div><div><h3>Intent filters / URL schemes</h3><ul>{intent_list}</ul></div><div><h3>Security flags / Entitlements</h3><ul>{flag_list}</ul></div></div></section>
{manifest}
<section class="report-section"><h2>Archive files <span class="count">{file_count}</span></h2><ul>{file_list}</ul></section>
<section class="report-section"><h2>Missing dependencies / limits</h2><ul>{missing_list}</ul></section>
</main><script>
const rows=[...document.querySelectorAll('.report-row')];const search=document.querySelector('#search');const severity=document.querySelector('#severity');const visible=document.querySelector('#visible');
function filter(){{const q=(search.value||'').toLowerCase().trim(),s=severity.value;let n=0;rows.forEach(row=>{{const text=(row.dataset.search||'').toLowerCase(),badge=row.querySelector('.report-badge')?.textContent.toLowerCase()||'';const ok=(!q||text.includes(q))&&(!s||((s==='high'&&/high|critical/.test(badge))||(s==='review'&&/review|medium/.test(badge))||(s==='info'&&/info|low/.test(badge))));row.classList.toggle('hidden',!ok);if(ok)n++}});visible.textContent=`显示 ${{n}} / ${{rows.length}} 条`;}}
function copyRow(button){{const row=button.closest('.report-row');if(!row)return;navigator.clipboard?.writeText(row.innerText).then(()=>{{button.textContent='已复制';setTimeout(()=>button.textContent='复制',1200)}})}}
search.addEventListener('input',filter);severity.addEventListener('change',filter);filter();
</script></body></html>"##,
        title = title,
        platform = report_escape(&analysis.platform.to_uppercase()),
        file_name = report_escape(&analysis.file_name),
        generated = report_escape(&format!("{}", chrono_like_now())),
        report_mode = if compact {
            "重点紧凑版"
        } else {
            "完整证据版"
        },
        code_count = analysis.code_insights.len(),
        binary_count = analysis.binary_insights.len(),
        boundary_count = analysis.data_boundaries.len(),
        boundary_rows = render_boundary_report_rows(&analysis.data_boundaries),
        sensitive_count = analysis.sensitive_items.len(),
        framework_count = analysis.frameworks.len(),
        package_id = report_opt(analysis.package_id.as_ref()),
        version_label = if analysis.platform == "ios" {
            "Version / Build"
        } else {
            "Version"
        },
        version = report_escape(&format!(
            "{} ({})",
            analysis.version_name.as_deref().unwrap_or("—"),
            analysis.version_code.as_deref().unwrap_or("—")
        )),
        size = report_escape(&format_bytes(analysis.file_size)),
        architectures = report_escape(&if analysis.architectures.is_empty() {
            "未解析".to_string()
        } else {
            analysis.architectures.join(", ")
        }),
        protection = report_escape(&analysis.protection.status),
        signature = report_opt(analysis.signature.as_ref()),
        artifact_sha256 = report_escape(&analysis.artifact_sha256),
        path = report_escape(&analysis.path),
        coverage_state = if analysis.scan_coverage.complete {
            "COMPLETE"
        } else {
            "PARTIAL"
        },
        archive_indexed = analysis.scan_coverage.archive_entries_indexed,
        archive_total = analysis.scan_coverage.archive_entries_total,
        binary_scanned = analysis.scan_coverage.binary_candidates_scanned,
        binary_candidates = analysis.scan_coverage.binary_candidates_total,
        sensitive_returned = analysis.scan_coverage.sensitive_items_returned,
        sensitive_discovered = analysis.scan_coverage.sensitive_items_discovered,
        code_returned = analysis.scan_coverage.code_insights_returned,
        code_discovered = analysis.scan_coverage.code_insights_discovered,
        coverage_warnings = analysis
            .scan_coverage
            .warnings
            .iter()
            .map(|value| format!("<li>{}</li>", report_escape(value)))
            .collect::<String>(),
        masvs_count = analysis.masvs_observations.len(),
        masvs_rows = render_masvs_report_rows(&analysis.masvs_observations, &verdicts),
        assessment_notes = assessment_notes,
        protection_status = report_escape(&analysis.protection.status),
        anti_count = analysis.anti_instrumentation.candidates.len(),
        anti_status = report_escape(&analysis.anti_instrumentation.status),
        anti_rows = render_anti_instrumentation_rows(&analysis.anti_instrumentation.candidates),
        packers = report_escape(&if analysis.protection.packers.is_empty() {
            "未命中".into()
        } else {
            analysis.protection.packers.join("、")
        }),
        indicators = analysis
            .protection
            .indicators
            .iter()
            .map(|value| format!("<li>{}</li>", report_escape(value)))
            .collect::<String>(),
        binary_rows = render_binary_report_rows(&analysis.binary_insights),
        code_rows = render_code_report_rows(&analysis.code_insights),
        sensitive_rows = render_sensitive_report_rows(&analysis.sensitive_items),
        finding_count = analysis.findings.len(),
        findings = findings,
        configuration_title = if analysis.platform == "ios" {
            "Info.plist / Entitlements"
        } else {
            "Android Manifest"
        },
        permission_list = permission_list,
        component_list = component_list,
        exported_list = exported_list,
        intent_list = intent_list,
        flag_list = flag_list,
        file_count = analysis.files.len(),
        file_list = file_list,
        missing_list = missing_list,
        manifest = manifest,
    );
    fs::write(&output_path, html).map_err(|error| format!("写入 HTML 报告失败：{error}"))?;
    Ok(output_path)
}
