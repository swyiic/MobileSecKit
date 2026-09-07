use regex::Regex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs,
    path::{Path, PathBuf},
};
use tauri::{AppHandle, Manager};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SensitiveRuleData {
    pub label: String,
    pub kind: String,
    pub severity: String,
    pub pattern: String,
    #[serde(default)]
    pub require_context: Vec<String>,
    #[serde(default)]
    pub exclude_signals: Vec<String>,
    #[serde(default)]
    pub exclude_patterns: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct SensitiveRule {
    pub data: SensitiveRuleData,
    pub label: String,
    pub kind: String,
    pub severity: String,
    pub regex: Regex,
    pub require_context: Vec<String>,
    pub exclude_signals: Vec<String>,
    pub exclude_patterns: Vec<Regex>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ExclusionRule {
    pub exclusion_id: String,
    pub applies_to_kind: String,
    #[serde(default)]
    pub exclude_signals: Vec<String>,
    #[serde(default)]
    pub exclude_patterns: Vec<String>,
    pub reason: String,
    #[serde(default)]
    pub verified_in: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct CompiledExclusionRule {
    pub data: ExclusionRule,
    pub exclude_patterns: Vec<Regex>,
}

impl CompiledExclusionRule {
    pub fn matches_narrow_context(&self, kind: &str, value: &str) -> bool {
        if self.data.applies_to_kind != "*" && !self.data.applies_to_kind.eq_ignore_ascii_case(kind)
        {
            return false;
        }
        let signal_match = self.data.exclude_signals.is_empty()
            || contains_any(value, &self.data.exclude_signals, false);
        let pattern_match = self.exclude_patterns.is_empty()
            || self
                .exclude_patterns
                .iter()
                .any(|pattern| pattern.is_match(value));
        signal_match && pattern_match
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExclusionMutation {
    pub created: bool,
    pub rule: ExclusionRule,
    pub total: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignalRule {
    pub label: String,
    #[serde(default)]
    pub trigger_signals: Vec<String>,
    #[serde(default)]
    pub scope: Option<String>,
    #[serde(default)]
    pub indicator: Option<String>,
}

#[derive(Debug, Clone)]
pub struct RuleSet {
    pub sensitive: Vec<SensitiveRule>,
    pub frameworks: Vec<SignalRule>,
    pub protection: Vec<SignalRule>,
    pub anti_instrumentation: Vec<SignalRule>,
    pub exclusions: Vec<CompiledExclusionRule>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RuleInventory {
    pub sensitive: Vec<SensitiveRuleData>,
    pub frameworks: Vec<SignalRule>,
    pub protection: Vec<SignalRule>,
    pub anti_instrumentation: Vec<SignalRule>,
    pub exclusions: Vec<ExclusionRule>,
}

pub fn contains_any(haystack: &str, signals: &[String], case_sensitive: bool) -> bool {
    if case_sensitive {
        signals
            .iter()
            .any(|signal| !signal.is_empty() && haystack.contains(signal))
    } else {
        let haystack = haystack.to_lowercase();
        signals
            .iter()
            .map(|signal| signal.to_lowercase())
            .any(|signal| !signal.is_empty() && haystack.contains(&signal))
    }
}

pub fn resolve_rules_dir(app: Option<&AppHandle>) -> Result<PathBuf, String> {
    if let Some(path) = std::env::var_os("ME_RULES_DIR").map(PathBuf::from) {
        if path.is_dir() {
            return Ok(path);
        }
        return Err(format!("ME_RULES_DIR 不是有效目录：{}", path.display()));
    }

    let development = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("rules");
    if development.is_dir() {
        return Ok(development);
    }
    if let Some(app) = app {
        let packaged = app
            .path()
            .resource_dir()
            .map_err(|error| format!("无法确定规则资源目录：{error}"))?
            .join("rules");
        if packaged.is_dir() {
            return Ok(packaged);
        }
    }
    if let Ok(executable) = std::env::current_exe() {
        for candidate in [
            executable.parent().map(|path| path.join("rules")),
            executable
                .parent()
                .and_then(Path::parent)
                .map(|path| path.join("Resources/rules")),
        ]
        .into_iter()
        .flatten()
        {
            if candidate.is_dir() {
                return Ok(candidate);
            }
        }
    }
    Err("找不到 rules 规则目录；请检查应用资源或设置 ME_RULES_DIR".into())
}

fn load_json<T: for<'de> Deserialize<'de>>(directory: &Path, name: &str) -> Result<Vec<T>, String> {
    let path = directory.join(name);
    let content = fs::read_to_string(&path)
        .map_err(|error| format!("读取规则文件 {} 失败：{error}", path.display()))?;
    serde_json::from_str(&content)
        .map_err(|error| format!("解析规则文件 {} 失败：{error}", path.display()))
}

pub fn load_rules_from(directory: &Path) -> Result<RuleSet, String> {
    let sensitive_data: Vec<SensitiveRuleData> = load_json(directory, "sensitive.json")?;
    let sensitive = sensitive_data
        .into_iter()
        .map(|rule| {
            let data = rule.clone();
            let label = rule.label.clone();
            let regex = Regex::new(&rule.pattern)
                .map_err(|error| format!("敏感规则 {} 的正则无效：{error}", rule.label))?;
            Ok(SensitiveRule {
                data,
                label: rule.label,
                kind: rule.kind,
                severity: rule.severity,
                regex,
                require_context: rule.require_context,
                exclude_signals: rule.exclude_signals,
                exclude_patterns: rule
                    .exclude_patterns
                    .into_iter()
                    .map(|pattern| {
                        Regex::new(&pattern)
                            .map_err(|error| format!("敏感规则 {label} 的排除正则无效：{error}"))
                    })
                    .collect::<Result<Vec<_>, _>>()?,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    let frameworks = load_json(directory, "frameworks.json")?;
    let protection = load_json(directory, "protection.json")?;
    let anti_instrumentation = load_json(directory, "anti-instrumentation.json")?;
    let exclusion_data: Vec<ExclusionRule> = load_json(directory, "exclusions.json")?;
    let exclusions = exclusion_data
        .into_iter()
        .map(|data| {
            let patterns = data
                .exclude_patterns
                .iter()
                .map(|pattern| {
                    Regex::new(pattern).map_err(|error| {
                        format!("排除规则 {} 的正则无效：{error}", data.exclusion_id)
                    })
                })
                .collect::<Result<Vec<_>, _>>()?;
            Ok(CompiledExclusionRule {
                data,
                exclude_patterns: patterns,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    Ok(RuleSet {
        sensitive,
        frameworks,
        protection,
        anti_instrumentation,
        exclusions,
    })
}

pub fn load_rules(app: Option<&AppHandle>) -> Result<RuleSet, String> {
    let mut rules = load_rules_from(&resolve_rules_dir(app)?)?;
    for data in list_user_exclusions()? {
        rules.exclusions.push(compile_exclusion(data)?);
    }
    Ok(rules)
}

pub fn list_inventory(app: Option<&AppHandle>) -> Result<RuleInventory, String> {
    let rules = load_rules(app)?;
    Ok(RuleInventory {
        sensitive: rules.sensitive.into_iter().map(|rule| rule.data).collect(),
        frameworks: rules.frameworks,
        protection: rules.protection,
        anti_instrumentation: rules.anti_instrumentation,
        exclusions: rules.exclusions.into_iter().map(|rule| rule.data).collect(),
    })
}

fn compile_exclusion(data: ExclusionRule) -> Result<CompiledExclusionRule, String> {
    let exclude_patterns = data
        .exclude_patterns
        .iter()
        .map(|pattern| {
            Regex::new(pattern)
                .map_err(|error| format!("排除规则 {} 的正则无效：{error}", data.exclusion_id))
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(CompiledExclusionRule {
        data,
        exclude_patterns,
    })
}

fn normalize_user_pattern(pattern: &str) -> Option<String> {
    let pattern = pattern.trim();
    if pattern.is_empty() {
        return None;
    }
    Some(if Regex::new(pattern).is_ok() {
        pattern.to_string()
    } else {
        // AI frequently labels literal code snippets as "regex". Persist a
        // safely escaped literal instead of rejecting the entire reviewed rule.
        regex::escape(pattern)
    })
}

fn user_exclusions_path() -> Result<PathBuf, String> {
    let base = if cfg!(target_os = "macos") {
        std::env::var_os("HOME")
            .map(PathBuf::from)
            .map(|path| path.join("Library/Application Support"))
    } else if cfg!(target_os = "windows") {
        std::env::var_os("APPDATA").map(PathBuf::from)
    } else {
        std::env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .or_else(|| {
                std::env::var_os("HOME")
                    .map(PathBuf::from)
                    .map(|p| p.join(".config"))
            })
    }
    .ok_or_else(|| "无法确定当前用户的配置目录".to_string())?;
    Ok(base.join("com.swyiic.mobilee").join("exclusions.json"))
}

fn legacy_user_exclusions_path() -> Result<PathBuf, String> {
    user_exclusions_path().map(|path| {
        path.parent()
            .and_then(|parent| parent.parent())
            .unwrap_or_else(|| std::path::Path::new(""))
            .join("com.swyiic.me")
            .join("exclusions.json")
    })
}

pub fn list_user_exclusions() -> Result<Vec<ExclusionRule>, String> {
    let current = user_exclusions_path()?;
    let path = if current.exists() {
        current
    } else {
        legacy_user_exclusions_path()?
    };
    if !path.exists() {
        return Ok(Vec::new());
    }
    let content = fs::read_to_string(&path)
        .map_err(|error| format!("读取排除规则 {} 失败：{error}", path.display()))?;
    serde_json::from_str(&content)
        .map_err(|error| format!("解析排除规则 {} 失败：{error}", path.display()))
}

pub fn merge_user_exclusion(mut rule: ExclusionRule) -> Result<ExclusionMutation, String> {
    rule.applies_to_kind = rule.applies_to_kind.trim().to_ascii_lowercase();
    rule.reason = rule.reason.trim().to_string();
    rule.exclude_signals = rule
        .exclude_signals
        .into_iter()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .collect();
    rule.exclude_signals.sort();
    rule.exclude_signals.dedup();
    rule.exclude_patterns = rule
        .exclude_patterns
        .iter()
        .filter_map(|value| normalize_user_pattern(value))
        .collect();
    rule.exclude_patterns.sort();
    rule.exclude_patterns.dedup();
    if rule.applies_to_kind.is_empty() || rule.reason.is_empty() {
        return Err("排除规则必须包含 appliesToKind 和 reason".into());
    }
    if rule.exclude_signals.is_empty() && rule.exclude_patterns.is_empty() {
        return Err("排除规则至少需要一个 excludeSignal 或 excludePattern".into());
    }
    if rule
        .exclude_patterns
        .iter()
        .any(|pattern| matches!(pattern.as_str(), ".*" | ".+" | "(?s).*"))
    {
        return Err("排除正则过于宽泛，请提供稳定的调用参数或上下文".into());
    }
    compile_exclusion(rule.clone())?;
    if rule.exclusion_id.trim().is_empty() {
        let source = serde_json::to_vec(&rule).map_err(|error| error.to_string())?;
        let digest = Sha256::digest(source);
        let short_hash = digest[..8]
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        rule.exclusion_id = format!("excl-user-{short_hash}");
    }
    let mut rules = list_user_exclusions()?;
    let existing = rules
        .iter()
        .position(|item| item.exclusion_id == rule.exclusion_id);
    let created = existing.is_none();
    if let Some(index) = existing {
        rules[index] = rule.clone();
    } else {
        rules.push(rule.clone());
    }
    rules.sort_by(|a, b| a.exclusion_id.cmp(&b.exclusion_id));
    let path = user_exclusions_path()?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|error| format!("创建排除规则目录失败：{error}"))?;
    }
    let temp = path.with_extension("json.tmp");
    fs::write(
        &temp,
        serde_json::to_vec_pretty(&rules).map_err(|error| error.to_string())?,
    )
    .map_err(|error| format!("写入排除规则失败：{error}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&temp, fs::Permissions::from_mode(0o600))
            .map_err(|error| format!("设置排除规则权限失败：{error}"))?;
    }
    fs::rename(&temp, &path).map_err(|error| format!("保存排除规则失败：{error}"))?;
    Ok(ExclusionMutation {
        created,
        rule,
        total: rules.len(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_dir(label: &str) -> PathBuf {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let path =
            std::env::temp_dir().join(format!("me-rules-{label}-{}-{stamp}", std::process::id()));
        fs::create_dir_all(&path).expect("create rules fixture directory");
        path
    }

    fn write_fixture(directory: &Path, sensitive: &str) {
        fs::write(directory.join("sensitive.json"), sensitive).expect("write sensitive rules");
        fs::write(
            directory.join("frameworks.json"),
            r#"[{"label":"Fixture SDK","triggerSignals":["FixtureSDK"]}]"#,
        )
        .expect("write framework rules");
        fs::write(
            directory.join("protection.json"),
            r#"[{"label":"Fixture protector","scope":"archive","triggerSignals":["FixtureProtect"]}]"#,
        )
        .expect("write protection rules");
        fs::write(
            directory.join("anti-instrumentation.json"),
            r#"[{"label":"Fixture anti instrumentation","scope":"content","triggerSignals":["TracerPid"]}]"#,
        )
        .expect("write anti-instrumentation rules");
        fs::write(directory.join("exclusions.json"), "[]").expect("write exclusion rules");
    }

    #[test]
    fn loads_external_rules_and_compiles_sensitive_regexes() {
        let directory = temp_dir("load");
        write_fixture(
            &directory,
            r#"[{"label":"Fixture secret","kind":"secret","severity":"high","pattern":"FIXTURE-[0-9]+"}]"#,
        );
        let rules = load_rules_from(&directory).expect("load fixture rules");
        assert_eq!(rules.sensitive.len(), 1);
        assert_eq!(rules.frameworks.len(), 1);
        assert_eq!(rules.protection.len(), 1);
        assert_eq!(rules.anti_instrumentation.len(), 1);
        assert!(rules.sensitive[0].regex.is_match("FIXTURE-42"));
        assert!(contains_any(
            "prefix fixturesdk suffix",
            &rules.frameworks[0].trigger_signals,
            false
        ));
        let _ = fs::remove_dir_all(directory);
    }

    #[test]
    fn reloading_after_rule_append_does_not_use_a_stale_cache() {
        let directory = temp_dir("reload");
        let first = r#"[{"label":"First","kind":"secret","severity":"review","pattern":"FIRST"}]"#;
        write_fixture(&directory, first);
        assert_eq!(load_rules_from(&directory).unwrap().sensitive.len(), 1);

        let second = r#"[
          {"label":"First","kind":"secret","severity":"review","pattern":"FIRST"},
          {"label":"Appended","kind":"secret","severity":"high","pattern":"APPENDED"}
        ]"#;
        fs::write(directory.join("sensitive.json"), second).expect("append rule fixture");
        let reloaded = load_rules_from(&directory).expect("reload fixture rules");
        assert_eq!(reloaded.sensitive.len(), 2);
        assert!(reloaded.sensitive[1].regex.is_match("APPENDED"));
        let _ = fs::remove_dir_all(directory);
    }

    #[test]
    fn builtin_rule_files_match_expected_shape() {
        let rules = load_rules(None).expect("load bundled rules");
        assert_eq!(rules.sensitive.len(), 21);
        assert!(rules.frameworks.len() >= 40);
        assert!(rules.protection.len() >= 10);
        assert!(rules.anti_instrumentation.len() >= 10);
        let classloader_rule = rules
            .anti_instrumentation
            .iter()
            .find(|rule| rule.label.contains("类加载器接管"))
            .expect("classloader takeover review rule");
        assert_eq!(classloader_rule.scope.as_deref(), Some("content"));
        assert!(classloader_rule
            .trigger_signals
            .iter()
            .any(|signal| signal == "InMemoryDexClassLoader"));
        assert!(classloader_rule
            .indicator
            .as_deref()
            .is_some_and(|indicator| indicator.contains("review")));
        assert!(rules
            .frameworks
            .iter()
            .any(|rule| rule.label == "AFNetworking"));
        assert!(rules.protection.iter().any(|rule| rule
            .trigger_signals
            .iter()
            .any(|signal| signal == "jmcodeprotectkit.framework")));
    }

    #[test]
    fn inventory_preserves_raw_patterns_and_all_rule_categories() {
        let inventory = list_inventory(None).expect("list bundled rule inventory");
        assert_eq!(inventory.sensitive.len(), 21);
        assert!(inventory
            .sensitive
            .iter()
            .all(|rule| !rule.pattern.trim().is_empty()));
        assert!(inventory.frameworks.len() >= 40);
        assert!(inventory.protection.len() >= 10);
        assert!(inventory.anti_instrumentation.len() >= 10);
        assert!(!inventory.exclusions.is_empty());

        let json = serde_json::to_value(inventory).expect("serialize rule inventory");
        assert!(json.get("antiInstrumentation").is_some());
        assert!(json["sensitive"][0].get("pattern").is_some());
        assert!(json["exclusions"][0].get("exclusionId").is_some());
    }

    #[test]
    fn invalid_ai_regex_is_safely_normalized_to_a_literal() {
        let normalized =
            normalize_user_pattern("sysctlbyname(\"hw.machine").expect("literal pattern");
        assert_eq!(normalized, r#"sysctlbyname\("hw\.machine"#);
        let regex = Regex::new(&normalized).expect("escaped regex");
        assert!(regex.is_match("sysctlbyname(\"hw.machine\")"));
    }

    #[test]
    fn narrow_exclusion_requires_signal_and_context_when_both_are_present() {
        let rule = compile_exclusion(ExclusionRule {
            exclusion_id: "sysctl-device-info".into(),
            applies_to_kind: "runtime-integrity".into(),
            exclude_signals: vec!["sysctl".into()],
            exclude_patterns: vec![r#"sysctlbyname\("hw\.machine"#.into()],
            reason: "legitimate device metadata".into(),
            verified_in: Vec::new(),
        })
        .expect("compiled exclusion");
        assert!(rule.matches_narrow_context(
            "runtime-integrity",
            "sysctlbyname(\"hw.machine\", value, size)"
        ));
        assert!(!rule.matches_narrow_context("runtime-integrity", "sysctl mib contains P_TRACED"));
    }
}
