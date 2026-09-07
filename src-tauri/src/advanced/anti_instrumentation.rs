use super::{
    is_deep_binary_candidate, rules, AntiInstrumentationAssessment, AntiInstrumentationCandidate,
};
use serde::Deserialize;
use std::{collections::HashSet, fs::File, io::Read};
use zip::ZipArchive;

const CONTENT_SCAN_BUDGET: u64 = 256 * 1024 * 1024;
const ENTRY_SCAN_LIMIT: u64 = 128 * 1024 * 1024;
const RESULT_PREFIX: &str = "ME_ANTI_INSTRUMENTATION_RESULT:";

fn candidate(
    rule: &rules::SignalRule,
    signal: &str,
    source: &str,
    location: &str,
    context: &str,
    rule_set: &rules::RuleSet,
) -> AntiInstrumentationCandidate {
    let strong_context = [
        "p_traced",
        "pt_deny_attach",
        "ptrace(",
        "ptrace_traceme",
        "process terminated",
        "me_ios_termination_call",
        "me_ios_fatal_exception",
    ]
    .iter()
    .any(|marker| context.to_ascii_lowercase().contains(marker));
    let exclusion = (!strong_context)
        .then(|| {
            let value = format!("{signal}\n{context}");
            rule_set
                .exclusions
                .iter()
                .find(|item| item.matches_narrow_context("runtime-integrity", &value))
                .or_else(|| {
                    rule_set
                        .exclusions
                        .iter()
                        .find(|item| item.matches_narrow_context("anti-instrumentation", &value))
                })
        })
        .flatten();
    AntiInstrumentationCandidate {
        label: rule.label.clone(),
        signal: signal.into(),
        source: source.into(),
        location: location.into(),
        runtime: "pending".into(),
        evidence: vec![format!("{source}:{location} 命中 {signal}")],
        filtered: exclusion.is_some(),
        filter_reason: exclusion
            .map(|item| format!("{}（{}）", item.data.reason, item.data.exclusion_id)),
    }
}

fn signal_context(text: &str, signal: &str) -> String {
    let lines = text.lines().collect::<Vec<_>>();
    let needle = signal.to_ascii_lowercase();
    let Some(index) = lines
        .iter()
        .position(|line| line.to_ascii_lowercase().contains(&needle))
    else {
        return signal.to_string();
    };
    lines[index.saturating_sub(2)..=(index + 2).min(lines.len().saturating_sub(1))].join("\n")
}

fn content_candidate(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    is_deep_binary_candidate(name)
        || [
            ".xml", ".json", ".plist", ".txt", ".js", ".smali", ".java", ".kt", ".swift", ".m",
            ".mm", ".c", ".cc", ".cpp", ".h", ".strings",
        ]
        .iter()
        .any(|suffix| lower.ends_with(suffix))
}

pub(super) fn assess(
    archive: &mut ZipArchive<File>,
    files: &[String],
    rule_set: &rules::RuleSet,
) -> AntiInstrumentationAssessment {
    let mut candidates = Vec::new();
    let mut seen = HashSet::new();

    for rule in rule_set
        .anti_instrumentation
        .iter()
        .filter(|rule| rule.scope.as_deref() == Some("archive"))
    {
        for name in files {
            let lower = name.to_ascii_lowercase();
            for signal in &rule.trigger_signals {
                if lower.contains(&signal.to_ascii_lowercase())
                    && seen.insert((rule.label.clone(), signal.clone(), name.clone()))
                {
                    candidates.push(candidate(rule, signal, "archive", name, name, rule_set));
                }
            }
        }
    }

    let content_rules = rule_set
        .anti_instrumentation
        .iter()
        .filter(|rule| rule.scope.as_deref() == Some("content"))
        .collect::<Vec<_>>();
    let mut scanned = 0u64;
    for name in files.iter().filter(|name| content_candidate(name)) {
        if scanned >= CONTENT_SCAN_BUDGET {
            break;
        }
        let Ok(mut entry) = archive.by_name(name) else {
            continue;
        };
        if entry.size() == 0 || entry.size() > ENTRY_SCAN_LIMIT {
            continue;
        }
        let allowance = CONTENT_SCAN_BUDGET.saturating_sub(scanned);
        if entry.size() > allowance {
            break;
        }
        let mut bytes = Vec::with_capacity(entry.size().min(16 * 1024 * 1024) as usize);
        if entry.read_to_end(&mut bytes).is_err() {
            continue;
        }
        scanned = scanned.saturating_add(bytes.len() as u64);
        let text = if is_deep_binary_candidate(name) || bytes.starts_with(b"bplist") {
            super::extracted_binary_strings(&bytes, 4)
        } else {
            String::from_utf8_lossy(&bytes).into_owned()
        };
        let lower = text.to_ascii_lowercase();
        for rule in &content_rules {
            for signal in &rule.trigger_signals {
                if lower.contains(&signal.to_ascii_lowercase())
                    && seen.insert((rule.label.clone(), signal.clone(), name.clone()))
                {
                    let context = signal_context(&text, signal);
                    candidates.push(candidate(rule, signal, "content", name, &context, rule_set));
                }
            }
        }
    }

    candidates.sort_by(|left, right| {
        left.label
            .cmp(&right.label)
            .then(left.location.cmp(&right.location))
            .then(left.signal.cmp(&right.signal))
    });
    candidates.truncate(500);
    let indicators = candidates
        .iter()
        .filter(|item| !item.filtered)
        .map(|item| {
            format!(
                "{} · {} · {}:{}",
                item.label, item.signal, item.source, item.location
            )
        })
        .collect::<Vec<_>>();
    AntiInstrumentationAssessment {
        status: if candidates.iter().all(|item| item.filtered) {
            "not-detected".into()
        } else {
            "pending".into()
        },
        candidates,
        indicators,
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConfirmAntiInstrumentationRequest {
    pub assessment: AntiInstrumentationAssessment,
    #[serde(default)]
    pub runtime_output: String,
    pub exit_code: Option<i32>,
    #[serde(default)]
    pub app_id: Option<String>,
}

fn excerpt(value: &str) -> String {
    let cleaned = value.trim();
    if cleaned.chars().count() <= 2_000 {
        cleaned.into()
    } else {
        let tail = cleaned
            .chars()
            .rev()
            .take(2_000)
            .collect::<String>()
            .chars()
            .rev()
            .collect::<String>();
        format!("…{tail}")
    }
}

pub(super) fn confirm(
    mut request: ConfirmAntiInstrumentationRequest,
) -> AntiInstrumentationAssessment {
    let lower = request.runtime_output.to_ascii_lowercase();
    let pre_script_blocked = [
        "refused to load frida-agent",
        "terminated during injection",
        "unexpected early end-of-stream",
        "unexpected error while probing dyld",
        "unexpected error while resuming process",
    ]
    .iter()
    .any(|marker| lower.contains(marker));
    let probe_entered = request.runtime_output.contains(RESULT_PREFIX);
    let injection_only = request.runtime_output.contains("ME_IOS_INJECTION_OK");
    let observed_termination = request.runtime_output.contains("ME_IOS_TERMINATION_CALL")
        || request.runtime_output.contains("ME_IOS_FATAL_EXCEPTION");
    let runtime_contradicts_filter = pre_script_blocked
        || observed_termination
        || lower.contains("process terminated")
        || lower.contains("p_traced");
    // Android's dedicated probe can confirm these candidates. The iOS
    // zero-Hook marker only confirms that agent + JavaScript entered; it does
    // not test anti-instrumentation behavior and therefore remains pending.
    let runtime = if probe_entered {
        "passed"
    } else if observed_termination {
        "blocked"
    } else if injection_only {
        "pending"
    } else if pre_script_blocked {
        "blocked"
    } else if request.exit_code.is_some_and(|code| code != 0)
        && !request
            .runtime_output
            .contains("ME_IOS_TERMINATION_TRACE_READY")
    {
        "blocked"
    } else {
        "pending"
    };
    let evidence = if request.runtime_output.trim().is_empty() {
        format!("Frida exitCode={:?}，没有探针输出", request.exit_code)
    } else {
        excerpt(&request.runtime_output)
    };
    for item in &mut request.assessment.candidates {
        if item.filtered && !runtime_contradicts_filter {
            continue;
        }
        if item.filtered {
            item.filtered = false;
            item.filter_reason = None;
        }
        item.runtime = runtime.into();
        if runtime != "pending" {
            item.evidence.push(evidence.clone());
        }
    }
    let active_candidates = request
        .assessment
        .candidates
        .iter()
        .filter(|item| !item.filtered)
        .count();
    request.assessment.status = if active_candidates == 0 && runtime == "passed" {
        "passed".into()
    } else if runtime == "pending" && active_candidates == 0 {
        "not-detected".into()
    } else {
        runtime.into()
    };
    request.assessment
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        io::Write,
        path::PathBuf,
        time::{SystemTime, UNIX_EPOCH},
    };
    use zip::{write::SimpleFileOptions, ZipWriter};

    fn assessment() -> AntiInstrumentationAssessment {
        AntiInstrumentationAssessment {
            status: "pending".into(),
            candidates: vec![AntiInstrumentationCandidate {
                label: "ptrace".into(),
                signal: "ptrace(".into(),
                source: "content".into(),
                location: "Payload/App".into(),
                runtime: "pending".into(),
                evidence: Vec::new(),
                filtered: false,
                filter_reason: None,
            }],
            indicators: Vec::new(),
        }
    }

    #[test]
    fn scans_archive_paths_and_binary_content_as_pending_candidates() {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let path: PathBuf = std::env::temp_dir().join(format!(
            "mobilee-anti-instrumentation-{}-{stamp}.apk",
            std::process::id()
        ));
        let file = File::create(&path).unwrap();
        let mut writer = ZipWriter::new(file);
        writer
            .start_file(
                "lib/arm64-v8a/libfrida-helper.so",
                SimpleFileOptions::default(),
            )
            .unwrap();
        writer
            .write_all(b"binary-prefix\0/proc/self/status\0TracerPid\0")
            .unwrap();
        writer.finish().unwrap();

        let mut archive = ZipArchive::new(File::open(&path).unwrap()).unwrap();
        let files = vec!["lib/arm64-v8a/libfrida-helper.so".into()];
        let rules = rules::RuleSet {
            sensitive: Vec::new(),
            frameworks: Vec::new(),
            protection: Vec::new(),
            anti_instrumentation: vec![
                rules::SignalRule {
                    label: "Frida file".into(),
                    trigger_signals: vec!["libfrida".into()],
                    scope: Some("archive".into()),
                    indicator: None,
                },
                rules::SignalRule {
                    label: "proc check".into(),
                    trigger_signals: vec!["TracerPid".into()],
                    scope: Some("content".into()),
                    indicator: None,
                },
            ],
            exclusions: Vec::new(),
        };
        let result = assess(&mut archive, &files, &rules);
        assert_eq!(result.status, "pending");
        assert!(result
            .candidates
            .iter()
            .any(|item| item.source == "archive"));
        assert!(result
            .candidates
            .iter()
            .any(|item| item.source == "content"));
        assert!(result
            .candidates
            .iter()
            .all(|item| item.runtime == "pending"));
        let _ = fs::remove_file(path);
    }

    #[test]
    fn classloader_takeover_content_remains_a_pending_review_candidate() {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let path: PathBuf = std::env::temp_dir().join(format!(
            "mobilee-classloader-review-{}-{stamp}.apk",
            std::process::id()
        ));
        let file = File::create(&path).unwrap();
        let mut writer = ZipWriter::new(file);
        writer
            .start_file("assets/patch-loader.js", SimpleFileOptions::default())
            .unwrap();
        writer
            .write_all(b"LoadedApk.mClassLoader pathList.dexElements")
            .unwrap();
        writer.finish().unwrap();

        let mut archive = ZipArchive::new(File::open(&path).unwrap()).unwrap();
        let files = vec!["assets/patch-loader.js".into()];
        let rules = rules::RuleSet {
            sensitive: Vec::new(),
            frameworks: Vec::new(),
            protection: Vec::new(),
            anti_instrumentation: vec![rules::SignalRule {
                label: "类加载器接管 / 整体加固 / 热修复线索".into(),
                trigger_signals: vec!["mClassLoader".into(), "dexElements".into()],
                scope: Some("content".into()),
                indicator: Some("review：需运行时确认".into()),
            }],
            exclusions: Vec::new(),
        };
        let result = assess(&mut archive, &files, &rules);
        assert_eq!(result.status, "pending");
        assert!(result.candidates.iter().any(|candidate| {
            candidate.label.contains("类加载器接管")
                && candidate.source == "content"
                && candidate.runtime == "pending"
        }));
        let _ = fs::remove_file(path);
    }

    #[test]
    fn runtime_integrity_exclusion_filters_sysctl_metadata_but_not_p_traced() {
        fn assessment_for(contents: &[u8]) -> AntiInstrumentationAssessment {
            let stamp = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "mobilee-sysctl-exclusion-{}-{stamp}.ipa",
                std::process::id()
            ));
            let file = File::create(&path).unwrap();
            let mut writer = ZipWriter::new(file);
            writer
                .start_file("Payload/App.app/App", SimpleFileOptions::default())
                .unwrap();
            writer.write_all(contents).unwrap();
            writer.finish().unwrap();
            let mut archive = ZipArchive::new(File::open(&path).unwrap()).unwrap();
            let rules = rules::RuleSet {
                sensitive: Vec::new(),
                frameworks: Vec::new(),
                protection: Vec::new(),
                anti_instrumentation: vec![rules::SignalRule {
                    label: "sysctl review".into(),
                    trigger_signals: vec!["sysctl".into()],
                    scope: Some("content".into()),
                    indicator: None,
                }],
                exclusions: vec![rules::CompiledExclusionRule {
                    data: rules::ExclusionRule {
                        exclusion_id: "sysctl-device-metadata".into(),
                        applies_to_kind: "runtime-integrity".into(),
                        exclude_signals: vec!["sysctl".into()],
                        exclude_patterns: vec![r#"sysctlbyname\("hw\.machine"#.into()],
                        reason: "设备型号采集".into(),
                        verified_in: Vec::new(),
                    },
                    exclude_patterns: vec![
                        regex::Regex::new(r#"sysctlbyname\("hw\.machine"#).unwrap()
                    ],
                }],
            };
            let result = assess(&mut archive, &["Payload/App.app/App".into()], &rules);
            let _ = fs::remove_file(path);
            result
        }

        let metadata = assessment_for(b"sysctlbyname(\"hw.machine\", value, size)");
        assert_eq!(metadata.status, "not-detected");
        assert!(metadata.candidates[0].filtered);

        let traced = assessment_for(
            b"sysctlbyname(\"hw.machine\", value, size)\nflags & P_TRACED\nprocess terminated",
        );
        assert_eq!(traced.status, "pending");
        assert!(!traced.candidates[0].filtered);
    }

    #[test]
    fn successful_probe_marks_candidates_passed() {
        let result = confirm(ConfirmAntiInstrumentationRequest {
            assessment: assessment(),
            runtime_output: format!("{RESULT_PREFIX}{{\"modules\":[]}}"),
            exit_code: Some(0),
            app_id: None,
        });
        assert_eq!(result.status, "passed");
        assert_eq!(result.candidates[0].runtime, "passed");
    }

    #[test]
    fn ios_injection_probe_does_not_claim_anti_instrumentation_pass() {
        let result = confirm(ConfirmAntiInstrumentationRequest {
            assessment: assessment(),
            runtime_output: "{\"type\":\"ME_IOS_INJECTION_OK\",\"pid\":42}\nProcess terminated"
                .into(),
            exit_code: Some(1),
            app_id: Some("com.example.app".into()),
        });
        assert_eq!(result.status, "pending");
        assert_eq!(result.candidates[0].runtime, "pending");
    }

    #[test]
    fn ready_only_termination_trace_does_not_claim_an_interception() {
        let result = confirm(ConfirmAntiInstrumentationRequest {
            assessment: assessment(),
            runtime_output: "ME_IOS_TERMINATION_TRACE_READY\nProcess terminated".into(),
            exit_code: Some(1),
            app_id: Some("com.example.app".into()),
        });
        assert_eq!(result.status, "pending");
    }

    #[test]
    fn pre_script_termination_marks_candidates_blocked() {
        let result = confirm(ConfirmAntiInstrumentationRequest {
            assessment: assessment(),
            runtime_output: "Failed: refused to load frida-agent".into(),
            exit_code: Some(1),
            app_id: None,
        });
        assert_eq!(result.status, "blocked");
    }

    #[test]
    fn early_end_of_stream_marks_candidates_blocked() {
        let result = confirm(ConfirmAntiInstrumentationRequest {
            assessment: assessment(),
            runtime_output: "Failed to attach: unexpected early end-of-stream".into(),
            exit_code: Some(1),
            app_id: Some("com.asiainfo.ima.base".into()),
        });
        assert_eq!(result.status, "blocked");
        assert_eq!(result.candidates[0].runtime, "blocked");
    }

    #[test]
    fn successful_spawn_fallback_is_not_poisoned_by_first_attach_error() {
        let result = confirm(ConfirmAntiInstrumentationRequest {
            assessment: assessment(),
            runtime_output: "Failed to attach: unexpected early end-of-stream\n{\"type\":\"ME_IOS_INJECTION_OK\",\"pid\":42}".into(),
            exit_code: Some(0),
            app_id: Some("com.asiainfo.ima.base".into()),
        });
        assert_eq!(result.status, "pending");
        assert_eq!(result.candidates[0].runtime, "pending");
    }
}
