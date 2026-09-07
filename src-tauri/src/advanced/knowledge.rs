use super::rules::contains_any;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};
use tauri::{AppHandle, Manager};

const KNOWLEDGE_FILE_NAME: &str = "knowledge.json";
const KNOWLEDGE_EXPORT_SCHEMA: &str = "mobilee.knowledge-library/v1";
const MAX_KNOWLEDGE_IMPORT_BYTES: u64 = 8 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct KnowledgePattern {
    pub pattern_id: String,
    pub boundary: String,
    pub title: String,
    #[serde(default, alias = "trigger_signals")]
    pub trigger_signals: Vec<String>,
    #[serde(default)]
    pub playbook: Vec<String>,
    #[serde(default, alias = "evidence_schema")]
    pub evidence_schema: Value,
    #[serde(default, alias = "reusable_for")]
    pub reusable_for: Vec<String>,
    #[serde(default, alias = "verified_in")]
    pub verified_in: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KnowledgeMutation {
    pub pattern: KnowledgePattern,
    pub created: bool,
    pub total: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KnowledgeBundle {
    pub schema_version: String,
    pub exported_at: u64,
    pub patterns: Vec<KnowledgePattern>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KnowledgeImportReport {
    pub imported: usize,
    pub created: usize,
    pub merged: usize,
    pub total: usize,
}

pub fn signal_fingerprint(signals: &[String]) -> String {
    let mut normalized: Vec<String> = signals
        .iter()
        .map(|value| value.trim().to_lowercase())
        .filter(|value| !value.is_empty())
        .collect();
    normalized.sort();
    normalized.dedup();
    let mut digest = Sha256::new();
    for signal in normalized {
        digest.update(signal.as_bytes());
        digest.update([0]);
    }
    format!("{:x}", digest.finalize())
}

pub fn pattern_matches(pattern: &KnowledgePattern, boundary: &str, haystack: &str) -> bool {
    pattern.boundary == boundary && contains_any(haystack, &pattern.trigger_signals, false)
}

pub fn seed_patterns() -> Vec<KnowledgePattern> {
    vec![
        KnowledgePattern {
            pattern_id: "pem-hardcoded-lic-decrypt".into(),
            boundary: "key-lifecycle".into(),
            title: "RSA 私钥硬编码 + .lic 授权文件解密".into(),
            trigger_signals: vec![
                "BEGIN PRIVATE KEY",
                "getVersionNewLicKey",
                "NLPRSA",
                ".lic",
                "NLPSDKLICAuthManager",
            ]
            .into_iter()
            .map(str::to_string)
            .collect(),
            playbook: vec![
                "扫描 PEM 标记提取私钥",
                "Ghidra 字符串→cfstring→getter→调用链",
                "定位 .lic 校验逻辑",
                "openssl rsautl -decrypt 验证",
            ]
            .into_iter()
            .map(str::to_string)
            .collect(),
            evidence_schema: json!({"private_key": ".pem", "license_file": ".lic", "leaked": ["encryptKey", "appSecret", "baseUrl"]}),
            reusable_for: vec!["NLPCAS", "License SDK", "几维安全加固"]
                .into_iter()
                .map(str::to_string)
                .collect(),
            verified_in: vec!["com.asiainfo.ima.base".into()],
        },
        KnowledgePattern {
            pattern_id: "jmcode-protect-packer-signals".into(),
            boundary: "runtime-integrity".into(),
            title: "JMCodeProtectKit / IPACodeProtectTwoSDk 加固特征".into(),
            trigger_signals: vec![
                "JMCodeProtectKit",
                "IPACodeProtectTwoSDk",
                "JMProtection",
                "IPACodeProtectTwoSDk_arm64_filter.json",
            ]
            .into_iter()
            .map(str::to_string)
            .collect(),
            playbook: vec![
                "识别加固文件",
                "注意字符串段被清空需运行时提取",
                "反调试 hook：ptrace/sysctl/task_get_exception_ports",
                "双进程保护：kill 同名不同 pid 的看护进程",
            ]
            .into_iter()
            .map(str::to_string)
            .collect(),
            evidence_schema: json!({"packer_files": [], "cleared_strings": [], "watchdog": "同名不同pid"}),
            reusable_for: vec!["几维安全".into()],
            verified_in: vec!["com.asiainfo.ima.base".into(), "com.central.mbomc".into()],
        },
        KnowledgePattern {
            pattern_id: "license-embedded-aes-key".into(),
            boundary: "crypto".into(),
            title: "授权文件内嵌 AES encryptKey 可解密业务流量".into(),
            trigger_signals: vec![
                "encryptKey",
                "isEncrypt",
                "CCCrypt",
                "AESEncrypt",
                "setDynamicPiv",
            ]
            .into_iter()
            .map(str::to_string)
            .collect(),
            playbook: vec![
                "解密授权文件取 encryptKey(32hex=AES-128)与 dynamicPiv(IV)",
                "确认 CCCrypt/AESEncrypt 使用点",
                "抓包验证密文",
                "openssl enc -aes-128-cbc -d -K <key> -iv <iv> 解密验证",
            ]
            .into_iter()
            .map(str::to_string)
            .collect(),
            evidence_schema: json!({"aes_key": "encryptKey", "iv": "dynamicPiv", "cipher": "AES-CBC"}),
            reusable_for: vec!["NLPCAS".into(), "授权文件类".into()],
            verified_in: vec!["com.asiainfo.ima.base".into()],
        },
        KnowledgePattern {
            pattern_id: "classloader-takeover-packer".into(),
            boundary: "dynamic-code".into(),
            title: "类加载器接管 / 整体加固 / 热修复".into(),
            trigger_signals: vec![
                "mClassLoader",
                "LoadedApk",
                "DexPathList",
                "dexElements",
                "combineDexElements",
                "currentActivityThread",
                "attachBaseContext",
            ]
            .into_iter()
            .map(str::to_string)
            .collect(),
            playbook: vec![
                "识别类加载器接管信号（content 命中）",
                "运行 inspect_classloader 枚举委派链与 dexElements",
                "定位解密出的隐藏 dex / 热修复补丁",
                "dump 目标 dex 做进一步静态分析",
            ]
            .into_iter()
            .map(str::to_string)
            .collect(),
            evidence_schema: json!({
                "classLoaderChain": [],
                "hiddenDex": [],
                "hotfixPatch": []
            }),
            reusable_for: vec!["整体加固壳", "Tinker/AndFix/Sophix"]
                .into_iter()
                .map(str::to_string)
                .collect(),
            verified_in: Vec::new(),
        },
        anti_instrumentation_pattern(),
    ]
}

pub fn anti_instrumentation_pattern() -> KnowledgePattern {
    KnowledgePattern {
        pattern_id: "anti-frida-block-confirmation".into(),
        boundary: "anti-instrumentation".into(),
        title: "Anti-Frida 拦截确认".into(),
        trigger_signals: vec![
            "frida-agent",
            "gum-js-loop",
            "TracerPid",
            "27042",
            "libdobby",
            "libsubstrate",
            "ptrace(",
            "task_get_exception_ports",
            "rebind_symbols",
        ]
        .into_iter()
        .map(str::to_string)
        .collect(),
        playbook: vec![
            "先跑零 Hook 探针",
            "命中 blocked 则取证（信号/栈/模块偏移）",
            "未命中则直接进入 dump/网络/JSBridge 抓取",
        ]
        .into_iter()
        .map(str::to_string)
        .collect(),
        evidence_schema: json!({
            "runtimeStatus": "pending|blocked|passed",
            "signal": "static candidate",
            "runtimeLog": "Frida probe excerpt",
            "moduleOffset": "optional"
        }),
        reusable_for: vec![
            "Android Anti-Frida".into(),
            "iOS Anti-Instrumentation".into(),
        ],
        verified_in: Vec::new(),
    }
}

fn knowledge_path(app: &AppHandle) -> Result<PathBuf, String> {
    let directory = app
        .path()
        .app_config_dir()
        .map_err(|error| format!("无法确定知识库目录：{error}"))?;
    fs::create_dir_all(&directory).map_err(|error| format!("创建知识库目录失败：{error}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))
            .map_err(|error| format!("设置知识库目录权限失败：{error}"))?;
    }
    let path = directory.join(KNOWLEDGE_FILE_NAME);
    if !path.exists() {
        if let Some(parent) = directory.parent() {
            let legacy = parent.join("com.swyiic.me").join(KNOWLEDGE_FILE_NAME);
            if legacy.is_file() {
                let patterns = read_patterns_file(&legacy)?;
                write_patterns(&path, &patterns)?;
            }
        }
    }
    Ok(path)
}

fn read_patterns_file(path: &Path) -> Result<Vec<KnowledgePattern>, String> {
    let metadata =
        fs::symlink_metadata(path).map_err(|error| format!("检查知识库失败：{error}"))?;
    if metadata.file_type().is_symlink() {
        return Err(format!("拒绝读取符号链接知识库：{}", path.display()));
    }
    if metadata.len() > MAX_KNOWLEDGE_IMPORT_BYTES {
        return Err(format!(
            "知识库文件超过 {} MiB 限制：{}",
            MAX_KNOWLEDGE_IMPORT_BYTES / 1024 / 1024,
            path.display()
        ));
    }
    let content = fs::read_to_string(path)
        .map_err(|error| format!("读取知识库 {} 失败：{error}", path.display()))?;
    let value: Value = serde_json::from_str(&content)
        .map_err(|error| format!("解析知识库 {} 失败：{error}", path.display()))?;
    if value.is_array() {
        serde_json::from_value(value).map_err(|error| format!("知识库条目结构错误：{error}"))
    } else {
        let bundle: KnowledgeBundle = serde_json::from_value(value)
            .map_err(|error| format!("知识库导出文件结构错误：{error}"))?;
        if bundle.schema_version != KNOWLEDGE_EXPORT_SCHEMA {
            return Err(format!(
                "不支持的知识库 schemaVersion：{}",
                bundle.schema_version
            ));
        }
        Ok(bundle.patterns)
    }
}

pub fn read_or_seed(path: &Path) -> Result<Vec<KnowledgePattern>, String> {
    if !path.exists() {
        let seeds = seed_patterns();
        write_patterns(path, &seeds)?;
        return Ok(seeds);
    }
    let mut patterns = read_patterns_file(path)?;
    let mut changed = false;
    let original_len = patterns.len();
    patterns.retain(|pattern| !placeholder_title(&pattern.title));
    changed |= patterns.len() != original_len;
    for seed in seed_patterns() {
        if !patterns
            .iter()
            .any(|existing| existing.pattern_id == seed.pattern_id)
        {
            patterns.push(seed);
            changed = true;
        }
    }
    if changed {
        write_patterns(path, &patterns)?;
    }
    Ok(patterns)
}

pub fn load_for_app(app: &AppHandle) -> Result<Vec<KnowledgePattern>, String> {
    read_or_seed(&knowledge_path(app)?)
}

fn write_patterns(path: &Path, patterns: &[KnowledgePattern]) -> Result<(), String> {
    let output = serde_json::to_string_pretty(patterns)
        .map_err(|error| format!("序列化知识库失败：{error}"))?;
    write_private_atomic(path, output.as_bytes())
}

fn write_private_atomic(path: &Path, output: &[u8]) -> Result<(), String> {
    if path.exists()
        && fs::symlink_metadata(path)
            .map_err(|error| error.to_string())?
            .file_type()
            .is_symlink()
    {
        return Err(format!("拒绝写入符号链接知识库：{}", path.display()));
    }
    let parent = path
        .parent()
        .ok_or_else(|| "知识库缺少父目录".to_string())?;
    fs::create_dir_all(parent).map_err(|error| format!("创建知识库目录失败：{error}"))?;
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let temporary = parent.join(format!(".{KNOWLEDGE_FILE_NAME}.{stamp}.tmp"));
    let result = (|| {
        let mut file = fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temporary)
            .map_err(|error| format!("创建知识库临时文件失败：{error}"))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            file.set_permissions(fs::Permissions::from_mode(0o600))
                .map_err(|error| format!("设置知识库权限失败：{error}"))?;
        }
        file.write_all(output)
            .map_err(|error| format!("写入知识库失败：{error}"))?;
        file.sync_all()
            .map_err(|error| format!("同步知识库失败：{error}"))?;
        drop(file);
        fs::rename(&temporary, path).map_err(|error| format!("替换知识库失败：{error}"))
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn validate_pattern(pattern: &KnowledgePattern) -> Result<(), String> {
    if placeholder_title(&pattern.title) {
        return Err(
            "知识模式必须包含明确名称，不能使用空标题、未命名模式、Untitled 或 Unknown".into(),
        );
    }
    if pattern.boundary.trim().is_empty() {
        return Err(format!("知识模式 {} 的 boundary 不能为空", pattern.title));
    }
    if pattern
        .trigger_signals
        .iter()
        .all(|value| value.trim().is_empty())
    {
        return Err(format!(
            "知识模式 {} 至少需要一个 triggerSignal",
            pattern.title
        ));
    }
    Ok(())
}

fn placeholder_title(value: &str) -> bool {
    let value = value.trim().to_ascii_lowercase();
    value.is_empty()
        || matches!(
            value.as_str(),
            "未命名" | "未命名模式" | "无标题" | "untitled" | "unknown" | "n/a" | "none"
        )
}

fn append_unique(target: &mut Vec<String>, values: Vec<String>) {
    for value in values {
        if !target
            .iter()
            .any(|current| current.eq_ignore_ascii_case(&value))
        {
            target.push(value);
        }
    }
}

fn merge_values(existing: &mut KnowledgePattern, incoming: KnowledgePattern) {
    if !incoming.title.trim().is_empty() {
        existing.title = incoming.title;
    }
    if !incoming.boundary.trim().is_empty() {
        existing.boundary = incoming.boundary;
    }
    append_unique(&mut existing.trigger_signals, incoming.trigger_signals);
    append_unique(&mut existing.playbook, incoming.playbook);
    append_unique(&mut existing.reusable_for, incoming.reusable_for);
    append_unique(&mut existing.verified_in, incoming.verified_in);
    if !incoming.evidence_schema.is_null() {
        existing.evidence_schema = incoming.evidence_schema;
    }
}

pub fn merge_at(path: &Path, mut pattern: KnowledgePattern) -> Result<KnowledgeMutation, String> {
    validate_pattern(&pattern)?;
    let fingerprint = signal_fingerprint(&pattern.trigger_signals);
    // AI proposals may omit an id. Use the normalized trigger-signal
    // fingerprint as the stable identity in that case. Seed entries keep their
    // human-readable ids, while deduplication still checks both identities.
    if pattern.pattern_id.trim().is_empty() {
        pattern.pattern_id = fingerprint.clone();
    }
    let mut patterns = read_or_seed(path)?;
    let existing = patterns.iter().position(|item| {
        item.pattern_id == pattern.pattern_id
            || signal_fingerprint(&item.trigger_signals) == fingerprint
    });
    let created = existing.is_none();
    let stored = if let Some(index) = existing {
        merge_values(&mut patterns[index], pattern);
        patterns[index].clone()
    } else {
        patterns.push(pattern.clone());
        pattern
    };
    write_patterns(path, &patterns)?;
    Ok(KnowledgeMutation {
        pattern: stored,
        created,
        total: patterns.len(),
    })
}

pub fn export_for_app(app: &AppHandle, output_path: &Path) -> Result<String, String> {
    let patterns = read_or_seed(&knowledge_path(app)?)?;
    let bundle = KnowledgeBundle {
        schema_version: KNOWLEDGE_EXPORT_SCHEMA.into(),
        exported_at: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
        patterns,
    };
    let output = serde_json::to_string_pretty(&bundle)
        .map_err(|error| format!("序列化知识库导出失败：{error}"))?;
    write_private_atomic(output_path, output.as_bytes())?;
    Ok(output_path.display().to_string())
}

pub fn import_for_app(app: &AppHandle, input_path: &Path) -> Result<KnowledgeImportReport, String> {
    let incoming = read_patterns_file(input_path)?;
    if incoming.is_empty() {
        return Err("导入文件中没有知识模式".into());
    }
    let store_path = knowledge_path(app)?;
    let mut patterns = read_or_seed(&store_path)?;
    let mut created = 0usize;
    let mut merged = 0usize;
    for mut pattern in incoming.iter().cloned() {
        validate_pattern(&pattern)?;
        let fingerprint = signal_fingerprint(&pattern.trigger_signals);
        if pattern.pattern_id.trim().is_empty() {
            pattern.pattern_id = fingerprint.clone();
        }
        if let Some(index) = patterns.iter().position(|item| {
            item.pattern_id == pattern.pattern_id
                || signal_fingerprint(&item.trigger_signals) == fingerprint
        }) {
            merge_values(&mut patterns[index], pattern);
            merged += 1;
        } else {
            patterns.push(pattern);
            created += 1;
        }
    }
    write_patterns(&store_path, &patterns)?;
    Ok(KnowledgeImportReport {
        imported: incoming.len(),
        created,
        merged,
        total: patterns.len(),
    })
}

pub fn list_knowledge(app: AppHandle) -> Result<Vec<KnowledgePattern>, String> {
    read_or_seed(&knowledge_path(&app)?)
}

pub fn add_pattern(app: AppHandle, pattern: KnowledgePattern) -> Result<KnowledgeMutation, String> {
    merge_at(&knowledge_path(&app)?, pattern)
}

pub fn merge_pattern(
    app: AppHandle,
    pattern: KnowledgePattern,
) -> Result<KnowledgeMutation, String> {
    merge_at(&knowledge_path(&app)?, pattern)
}

pub fn export_knowledge(app: AppHandle, output_path: String) -> Result<String, String> {
    export_for_app(&app, Path::new(&output_path))
}

pub fn import_knowledge(
    app: AppHandle,
    input_path: String,
) -> Result<KnowledgeImportReport, String> {
    import_for_app(&app, Path::new(&input_path))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_path(label: &str) -> PathBuf {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "me-knowledge-{label}-{}-{stamp}.json",
            std::process::id()
        ))
    }

    fn pattern(id: &str, boundary: &str, signals: &[&str]) -> KnowledgePattern {
        KnowledgePattern {
            pattern_id: id.into(),
            boundary: boundary.into(),
            title: "test pattern".into(),
            trigger_signals: signals.iter().map(|value| (*value).into()).collect(),
            playbook: vec!["first step".into()],
            evidence_schema: json!({"kind": "test"}),
            reusable_for: vec!["test".into()],
            verified_in: vec!["fixture".into()],
        }
    }

    #[test]
    fn first_read_seeds_all_builtin_patterns() {
        let path = temp_path("seed");
        let patterns = read_or_seed(&path).expect("seed knowledge library");
        assert_eq!(patterns.len(), seed_patterns().len());
        let classloader = patterns
            .iter()
            .find(|item| item.pattern_id == "classloader-takeover-packer")
            .expect("classloader takeover seed");
        assert_eq!(classloader.boundary, "dynamic-code");
        assert!(classloader
            .trigger_signals
            .iter()
            .any(|signal| signal == "dexElements"));
        assert!(path.is_file());
        let persisted: Vec<KnowledgePattern> =
            serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(persisted, patterns);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn existing_library_receives_new_builtin_seed_without_losing_experience() {
        let path = temp_path("seed-migration");
        let custom = pattern("custom-team-rule", "network", &["team-only-signal"]);
        write_patterns(&path, std::slice::from_ref(&custom)).unwrap();
        let patterns = read_or_seed(&path).unwrap();
        assert!(patterns
            .iter()
            .any(|item| item.pattern_id == custom.pattern_id));
        assert!(patterns
            .iter()
            .any(|item| item.pattern_id == "anti-frida-block-confirmation"));
        assert_eq!(patterns.len(), seed_patterns().len() + 1);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn portable_bundle_round_trips_and_rejects_unknown_schema() {
        let path = temp_path("portable-bundle");
        let bundle = KnowledgeBundle {
            schema_version: KNOWLEDGE_EXPORT_SCHEMA.into(),
            exported_at: 1_700_000_000,
            patterns: vec![pattern("portable", "network", &["URLSession"])],
        };
        write_private_atomic(
            &path,
            serde_json::to_string_pretty(&bundle).unwrap().as_bytes(),
        )
        .expect("write portable bundle");
        let restored = read_patterns_file(&path).expect("read portable bundle");
        assert_eq!(restored, bundle.patterns);

        let invalid = KnowledgeBundle {
            schema_version: "unrelated/v1".into(),
            ..bundle
        };
        write_private_atomic(
            &path,
            serde_json::to_string_pretty(&invalid).unwrap().as_bytes(),
        )
        .expect("write invalid bundle");
        assert!(read_patterns_file(&path)
            .expect_err("unknown schema must fail")
            .contains("不支持的知识库 schemaVersion"));
        let _ = fs::remove_file(path);
    }

    #[test]
    fn merge_deduplicates_by_id_or_signal_fingerprint() {
        let path = temp_path("merge");
        let initial = vec![pattern(
            "stable-id",
            "network",
            &["Bearer", "Authorization"],
        )];
        write_patterns(&path, &initial).expect("write fixture");

        let same_id = merge_at(
            &path,
            KnowledgePattern {
                title: "updated title".into(),
                playbook: vec!["second step".into()],
                ..pattern("stable-id", "network", &["new-signal"])
            },
        )
        .expect("merge by id");
        assert!(!same_id.created);
        assert_eq!(same_id.total, seed_patterns().len() + 1);
        assert_eq!(same_id.pattern.title, "updated title");
        assert!(same_id
            .pattern
            .trigger_signals
            .iter()
            .any(|value| value == "new-signal"));
        assert!(same_id
            .pattern
            .playbook
            .iter()
            .any(|value| value == "second step"));

        let same_signals = merge_at(
            &path,
            pattern(
                "different-id",
                "network",
                &["AUTHORIZATION", "bearer", "new-signal"],
            ),
        )
        .expect("merge by signal fingerprint");
        assert!(!same_signals.created);
        assert_eq!(same_signals.total, seed_patterns().len() + 1);

        let new_pattern = merge_at(&path, pattern("new-id", "crypto", &["CCCrypt"])).unwrap();
        assert!(new_pattern.created);
        assert_eq!(new_pattern.total, seed_patterns().len() + 2);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn empty_pattern_id_is_derived_from_signal_fingerprint() {
        let path = temp_path("derived-id");
        let incoming = pattern("", "crypto", &["CCCrypt", "AES"]);
        let expected = signal_fingerprint(&incoming.trigger_signals);
        let mutation = merge_at(&path, incoming).expect("derive pattern id");
        assert_eq!(mutation.pattern.pattern_id, expected);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn unnamed_patterns_are_rejected_before_persistence() {
        let pattern = KnowledgePattern {
            pattern_id: "placeholder-pattern".into(),
            boundary: "runtime-integrity".into(),
            title: "未命名模式".into(),
            trigger_signals: vec!["sysctl".into()],
            playbook: Vec::new(),
            evidence_schema: json!({}),
            reusable_for: Vec::new(),
            verified_in: Vec::new(),
        };
        assert!(validate_pattern(&pattern)
            .expect_err("placeholder title must fail")
            .contains("明确名称"));
    }

    #[test]
    fn pattern_matching_requires_boundary_and_signal() {
        let item = pattern("id", "crypto", &["CCCrypt"]);
        assert!(pattern_matches(&item, "crypto", "call CCCrypt here"));
        assert!(!pattern_matches(&item, "network", "call CCCrypt here"));
        assert!(!pattern_matches(&item, "crypto", "call URLSession here"));
    }
}
