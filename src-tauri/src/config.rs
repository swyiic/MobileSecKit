use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    fs,
    io::Write,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};
use tauri::{AppHandle, Manager};

const CONFIG_FILE_NAME: &str = "config.ini";
const DEFAULT_PROFILE: &str = "minimal";
const DEFAULT_PROVIDER_KIND: &str = "ollama";
const DEFAULT_PROVIDER_BASE_URL: &str = "http://127.0.0.1:11434";
const DEFAULT_TIMEOUT: u64 = 120;
const DEFAULT_OUTPUT_TOKENS: usize = 2000;
const DEFAULT_MONITOR_DEPLOYMENT_MODE: &str = "auto";
const DEFAULT_MONITOR_LOCAL_PORT: u16 = 18_080;
const DEFAULT_MONITOR_BATCH_SIZE: usize = 500;
const DEFAULT_MONITOR_SPOOL_LIMIT_MB: usize = 512;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct AppConfig {
    pub tool_directory: String,
    pub frida_script_directory: String,
    pub frida_script_path: String,
    pub frida_server_path: String,
    pub ios_developer_image_directory: String,
    pub dex_destination: String,
    pub so_destination: String,
    pub ios_dump_destination: String,
    pub ios_compatibility_profile: String,
    pub harden_frida_by_default: bool,
    pub apktool_path: String,
    pub jadx_path: String,
    pub excluded_urls: String,
    pub ai_provider_kind: String,
    pub ai_provider_base_url: String,
    pub ai_provider_model: String,
    pub ai_provider_api_key: String,
    pub ai_provider_timeout: u64,
    pub ai_provider_output_tokens: usize,
    pub android_monitor_deployment_mode: String,
    pub android_monitor_auto_reconnect: bool,
    pub android_monitor_auto_provision: bool,
    pub android_monitor_local_port: u16,
    pub android_monitor_batch_size: usize,
    pub android_monitor_spool_limit_mb: usize,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            tool_directory: String::new(),
            frida_script_directory: String::new(),
            frida_script_path: String::new(),
            frida_server_path: String::new(),
            ios_developer_image_directory: String::new(),
            dex_destination: String::new(),
            so_destination: String::new(),
            ios_dump_destination: String::new(),
            ios_compatibility_profile: DEFAULT_PROFILE.into(),
            harden_frida_by_default: false,
            apktool_path: String::new(),
            jadx_path: String::new(),
            excluded_urls: String::new(),
            ai_provider_kind: DEFAULT_PROVIDER_KIND.into(),
            ai_provider_base_url: DEFAULT_PROVIDER_BASE_URL.into(),
            ai_provider_model: String::new(),
            ai_provider_api_key: String::new(),
            ai_provider_timeout: DEFAULT_TIMEOUT,
            ai_provider_output_tokens: DEFAULT_OUTPUT_TOKENS,
            android_monitor_deployment_mode: DEFAULT_MONITOR_DEPLOYMENT_MODE.into(),
            android_monitor_auto_reconnect: true,
            android_monitor_auto_provision: false,
            android_monitor_local_port: DEFAULT_MONITOR_LOCAL_PORT,
            android_monitor_batch_size: DEFAULT_MONITOR_BATCH_SIZE,
            android_monitor_spool_limit_mb: DEFAULT_MONITOR_SPOOL_LIMIT_MB,
        }
    }
}

impl AppConfig {
    fn normalized(mut self) -> Result<Self, String> {
        for (name, value) in [
            ("toolDirectory", &self.tool_directory),
            ("fridaScriptDirectory", &self.frida_script_directory),
            ("fridaScriptPath", &self.frida_script_path),
            ("fridaServerPath", &self.frida_server_path),
            (
                "iosDeveloperImageDirectory",
                &self.ios_developer_image_directory,
            ),
            ("dexDestination", &self.dex_destination),
            ("soDestination", &self.so_destination),
            ("iosDumpDestination", &self.ios_dump_destination),
            ("apktoolPath", &self.apktool_path),
            ("jadxPath", &self.jadx_path),
            ("aiProviderBaseUrl", &self.ai_provider_base_url),
            ("aiProviderModel", &self.ai_provider_model),
            ("aiProviderApiKey", &self.ai_provider_api_key),
        ] {
            if value.contains('\0') || value.contains('\n') || value.contains('\r') {
                return Err(format!("配置项 {name} 不能包含换行或 NUL 字符"));
            }
        }

        self.ios_compatibility_profile = match self.ios_compatibility_profile.as_str() {
            "compat" | "aggressive" => self.ios_compatibility_profile,
            _ => DEFAULT_PROFILE.into(),
        };
        self.ai_provider_kind = match self.ai_provider_kind.as_str() {
            "openai-compatible" => "openai-compatible".into(),
            _ => DEFAULT_PROVIDER_KIND.into(),
        };
        self.ai_provider_timeout = self.ai_provider_timeout.clamp(10, 600);
        self.ai_provider_output_tokens = self.ai_provider_output_tokens.clamp(400, 32_000);
        self.android_monitor_deployment_mode = match self.android_monitor_deployment_mode.as_str() {
            "development" | "system" => self.android_monitor_deployment_mode,
            _ => DEFAULT_MONITOR_DEPLOYMENT_MODE.into(),
        };
        self.android_monitor_local_port = self.android_monitor_local_port.max(1);
        self.android_monitor_batch_size = self.android_monitor_batch_size.clamp(50, 5_000);
        self.android_monitor_spool_limit_mb = self.android_monitor_spool_limit_mb.clamp(64, 16_384);
        if self.ai_provider_base_url.trim().is_empty() {
            self.ai_provider_base_url = DEFAULT_PROVIDER_BASE_URL.into();
        }
        Ok(self)
    }
}

#[tauri::command]
pub fn load_app_config(app: AppHandle) -> Result<AppConfig, String> {
    let path = config_path(&app)?;
    if !path.exists() {
        if let Some(legacy) = legacy_config_path(&path) {
            if legacy.is_file() {
                let content = fs::read_to_string(&legacy).map_err(|error| {
                    format!("迁移旧版 MobileE 配置 {} 失败：{error}", legacy.display())
                })?;
                let config = parse_ini(&content)?.normalized()?;
                write_config(&path, &config)?;
                return Ok(config);
            }
        }
        let config = AppConfig::default();
        write_config(&path, &config)?;
        return Ok(config);
    }

    let content = fs::read_to_string(&path)
        .map_err(|error| format!("读取配置文件 {} 失败：{error}", path.display()))?;
    let config = parse_ini(&content)?.normalized()?;
    // Do not rewrite an existing file during startup: this keeps user comments and
    // future/unknown sections intact. Normalized values are persisted on the next edit.
    Ok(config)
}

fn legacy_config_path(current: &Path) -> Option<PathBuf> {
    let app_directory = current.parent()?;
    let root = app_directory.parent()?;
    Some(root.join("com.swyiic.me").join(CONFIG_FILE_NAME))
}

#[tauri::command]
pub fn save_app_config(app: AppHandle, config: AppConfig) -> Result<String, String> {
    let path = config_path(&app)?;
    let config = config.normalized()?;
    write_config(&path, &config)?;
    Ok(path.display().to_string())
}

fn config_path(app: &AppHandle) -> Result<PathBuf, String> {
    let directory = app
        .path()
        .app_config_dir()
        .map_err(|error| format!("无法确定应用配置目录：{error}"))?;
    fs::create_dir_all(&directory)
        .map_err(|error| format!("创建应用配置目录 {} 失败：{error}", directory.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))
            .map_err(|error| format!("设置应用配置目录权限失败：{error}"))?;
    }
    Ok(directory.join(CONFIG_FILE_NAME))
}

fn write_config(path: &Path, config: &AppConfig) -> Result<(), String> {
    if path.exists() {
        let metadata = fs::symlink_metadata(path)
            .map_err(|error| format!("检查配置文件 {} 失败：{error}", path.display()))?;
        if metadata.file_type().is_symlink() {
            return Err(format!("拒绝写入符号链接配置文件：{}", path.display()));
        }
    }

    let parent = path
        .parent()
        .ok_or_else(|| "配置文件缺少父目录".to_string())?;
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let temporary = parent.join(format!(".{CONFIG_FILE_NAME}.{stamp}.tmp"));
    let result = (|| {
        let mut file = fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temporary)
            .map_err(|error| format!("创建临时配置文件失败：{error}"))?;
        set_private_permissions(&file)?;
        file.write_all(format_ini(config).as_bytes())
            .map_err(|error| format!("写入配置文件失败：{error}"))?;
        file.sync_all()
            .map_err(|error| format!("同步配置文件失败：{error}"))?;
        drop(file);
        fs::rename(&temporary, path)
            .map_err(|error| format!("替换配置文件 {} 失败：{error}", path.display()))?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn set_private_permissions(file: &fs::File) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(|error| format!("设置配置文件权限失败：{error}"))?;
    }
    Ok(())
}

fn parse_ini(content: &str) -> Result<AppConfig, String> {
    let mut values: HashMap<(String, String), String> = HashMap::new();
    let mut section = String::new();
    for (index, raw_line) in content.lines().enumerate() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if let Some(name) = line
            .strip_prefix('[')
            .and_then(|value| value.strip_suffix(']'))
        {
            section = name.trim().to_ascii_lowercase();
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            return Err(format!("config.ini 第 {} 行缺少 '='", index + 1));
        };
        values.insert(
            (section.clone(), key.trim().to_ascii_lowercase()),
            decode_value(value.trim()),
        );
    }

    let mut config = AppConfig::default();
    config.tool_directory = value(&values, "app", "tool_directory", config.tool_directory);
    config.frida_script_directory = value(
        &values,
        "frida",
        "script_directory",
        config.frida_script_directory,
    );
    config.frida_script_path = value(&values, "frida", "script_path", config.frida_script_path);
    config.frida_server_path = value(&values, "frida", "server_path", config.frida_server_path);
    config.ios_developer_image_directory = value(
        &values,
        "frida",
        "ios_developer_image_directory",
        config.ios_developer_image_directory,
    );
    config.dex_destination = value(&values, "frida", "dex_destination", config.dex_destination);
    config.so_destination = value(&values, "frida", "so_destination", config.so_destination);
    config.ios_dump_destination = value(
        &values,
        "frida",
        "ios_dump_destination",
        config.ios_dump_destination,
    );
    config.ios_compatibility_profile = value(
        &values,
        "frida",
        "ios_compatibility_profile",
        config.ios_compatibility_profile,
    );
    config.harden_frida_by_default = values
        .get(&("frida".into(), "harden_by_default".into()))
        .map(|value| {
            matches!(
                value.trim().to_ascii_lowercase().as_str(),
                "true" | "1" | "yes" | "on"
            )
        })
        .unwrap_or(config.harden_frida_by_default);
    config.apktool_path = value(&values, "analyzer", "apktool_path", config.apktool_path);
    config.jadx_path = value(&values, "analyzer", "jadx_path", config.jadx_path);
    config.excluded_urls = value(&values, "analyzer", "excluded_urls", config.excluded_urls);
    config.ai_provider_kind = value(&values, "ai", "provider_kind", config.ai_provider_kind);
    config.ai_provider_base_url = value(
        &values,
        "ai",
        "provider_base_url",
        config.ai_provider_base_url,
    );
    config.ai_provider_model = value(&values, "ai", "provider_model", config.ai_provider_model);
    config.ai_provider_api_key = value(
        &values,
        "ai",
        "provider_api_key",
        config.ai_provider_api_key,
    );
    config.ai_provider_timeout = numeric_value(
        &values,
        "ai",
        "provider_timeout",
        config.ai_provider_timeout,
    );
    config.ai_provider_output_tokens = numeric_value(
        &values,
        "ai",
        "provider_output_tokens",
        config.ai_provider_output_tokens,
    );
    config.android_monitor_deployment_mode = value(
        &values,
        "android_monitor",
        "deployment_mode",
        config.android_monitor_deployment_mode,
    );
    config.android_monitor_auto_reconnect = bool_value(
        &values,
        "android_monitor",
        "auto_reconnect",
        config.android_monitor_auto_reconnect,
    );
    config.android_monitor_auto_provision = bool_value(
        &values,
        "android_monitor",
        "auto_provision",
        config.android_monitor_auto_provision,
    );
    config.android_monitor_local_port = numeric_value(
        &values,
        "android_monitor",
        "local_port",
        config.android_monitor_local_port,
    );
    config.android_monitor_batch_size = numeric_value(
        &values,
        "android_monitor",
        "batch_size",
        config.android_monitor_batch_size,
    );
    config.android_monitor_spool_limit_mb = numeric_value(
        &values,
        "android_monitor",
        "spool_limit_mb",
        config.android_monitor_spool_limit_mb,
    );
    Ok(config)
}

fn bool_value(
    values: &HashMap<(String, String), String>,
    section: &str,
    key: &str,
    default: bool,
) -> bool {
    values
        .get(&(section.into(), key.into()))
        .map(|value| {
            matches!(
                value.trim().to_ascii_lowercase().as_str(),
                "true" | "1" | "yes" | "on"
            )
        })
        .unwrap_or(default)
}

fn value(
    values: &HashMap<(String, String), String>,
    section: &str,
    key: &str,
    default: String,
) -> String {
    values
        .get(&(section.into(), key.into()))
        .cloned()
        .unwrap_or(default)
}

fn numeric_value<T>(
    values: &HashMap<(String, String), String>,
    section: &str,
    key: &str,
    default: T,
) -> T
where
    T: std::str::FromStr,
{
    values
        .get(&(section.into(), key.into()))
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}

fn decode_value(value: &str) -> String {
    let mut decoded = String::with_capacity(value.len());
    let mut escaped = false;
    for character in value.chars() {
        if escaped {
            match character {
                'n' => decoded.push('\n'),
                'r' => decoded.push('\r'),
                '\\' => decoded.push('\\'),
                other => {
                    decoded.push('\\');
                    decoded.push(other);
                }
            }
            escaped = false;
        } else if character == '\\' {
            escaped = true;
        } else {
            decoded.push(character);
        }
    }
    if escaped {
        decoded.push('\\');
    }
    decoded
}

fn encode_value(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('\r', "\\r")
        .replace('\n', "\\n")
}

fn format_ini(config: &AppConfig) -> String {
    format!(
        "# MobileE local configuration. File permissions are restricted to the current user.\n\n[app]\ntool_directory={}\n\n[frida]\nscript_directory={}\nscript_path={}\nserver_path={}\nios_developer_image_directory={}\ndex_destination={}\nso_destination={}\nios_dump_destination={}\nios_compatibility_profile={}\nharden_by_default={}\n\n[analyzer]\napktool_path={}\njadx_path={}\nexcluded_urls={}\n\n[ai]\nprovider_kind={}\nprovider_base_url={}\nprovider_model={}\nprovider_api_key={}\nprovider_timeout={}\nprovider_output_tokens={}\n\n[android_monitor]\ndeployment_mode={}\nauto_reconnect={}\nauto_provision={}\nlocal_port={}\nbatch_size={}\nspool_limit_mb={}\n",
        encode_value(&config.tool_directory),
        encode_value(&config.frida_script_directory),
        encode_value(&config.frida_script_path),
        encode_value(&config.frida_server_path),
        encode_value(&config.ios_developer_image_directory),
        encode_value(&config.dex_destination),
        encode_value(&config.so_destination),
        encode_value(&config.ios_dump_destination),
        encode_value(&config.ios_compatibility_profile),
        config.harden_frida_by_default,
        encode_value(&config.apktool_path),
        encode_value(&config.jadx_path),
        encode_value(&config.excluded_urls),
        encode_value(&config.ai_provider_kind),
        encode_value(&config.ai_provider_base_url),
        encode_value(&config.ai_provider_model),
        encode_value(&config.ai_provider_api_key),
        config.ai_provider_timeout,
        config.ai_provider_output_tokens,
        encode_value(&config.android_monitor_deployment_mode),
        config.android_monitor_auto_reconnect,
        config.android_monitor_auto_provision,
        config.android_monitor_local_port,
        config.android_monitor_batch_size,
        config.android_monitor_spool_limit_mb,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_decodes_known_values() {
        let config = parse_ini("[analyzer]\nexcluded_urls=example.com\\n*.analytics.example.com\n[ai]\nprovider_timeout=120\n").unwrap();
        assert_eq!(config.excluded_urls, "example.com\n*.analytics.example.com");
        assert_eq!(config.ai_provider_timeout, 120);
    }

    #[test]
    fn persists_api_key_for_reuse() {
        let config = AppConfig {
            ai_provider_api_key: "sk-local-test".into(),
            ..AppConfig::default()
        };
        let formatted = format_ini(&config);
        let parsed = parse_ini(&formatted).unwrap();
        assert_eq!(parsed.ai_provider_api_key, "sk-local-test");
        assert!(formatted.contains("[frida]"));
        assert!(formatted.contains("[ai]"));
        assert!(formatted.contains("[android_monitor]"));
    }

    #[test]
    fn monitor_settings_round_trip_and_normalize() {
        let config = AppConfig {
            android_monitor_deployment_mode: "system".into(),
            android_monitor_auto_reconnect: false,
            android_monitor_batch_size: 1_000,
            android_monitor_spool_limit_mb: 2_048,
            ..AppConfig::default()
        };
        let parsed = parse_ini(&format_ini(&config))
            .unwrap()
            .normalized()
            .unwrap();
        assert_eq!(parsed.android_monitor_deployment_mode, "system");
        assert!(!parsed.android_monitor_auto_reconnect);
        assert_eq!(parsed.android_monitor_batch_size, 1_000);
        assert_eq!(parsed.android_monitor_spool_limit_mb, 2_048);
    }

    #[test]
    fn round_trips_windows_paths_and_multiline_filters() {
        let config = AppConfig {
            tool_directory: r#"C:\\Android\platform-tools"#.into(),
            excluded_urls: "example.com\n*.cdn.example.com".into(),
            harden_frida_by_default: true,
            ..AppConfig::default()
        };
        let parsed = parse_ini(&format_ini(&config)).unwrap();
        assert_eq!(parsed.tool_directory, config.tool_directory);
        assert_eq!(parsed.excluded_urls, config.excluded_urls);
        assert!(parsed.harden_frida_by_default);
    }

    #[test]
    fn normalizes_unsafe_and_out_of_range_values() {
        let config = AppConfig {
            ios_compatibility_profile: "unknown".into(),
            ai_provider_kind: "unknown".into(),
            ai_provider_timeout: 1,
            ai_provider_output_tokens: 1,
            ..AppConfig::default()
        }
        .normalized()
        .unwrap();
        assert_eq!(config.ios_compatibility_profile, DEFAULT_PROFILE);
        assert_eq!(config.ai_provider_kind, DEFAULT_PROVIDER_KIND);
        assert_eq!(config.ai_provider_timeout, 10);
        assert_eq!(config.ai_provider_output_tokens, 400);
    }
}
