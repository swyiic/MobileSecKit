//! Discover a reusable CLI path, including Finder launches with a minimal PATH.
use std::path::{Path, PathBuf};

pub(crate) fn java_home() -> Option<PathBuf> {
    #[cfg(target_os = "macos")]
    {
        for version in ["21", "17"] {
            let brew = PathBuf::from(format!(
                "/opt/homebrew/opt/openjdk@{version}/libexec/openjdk.jdk/Contents/Home"
            ));
            if executable(&brew.join("bin/java")) {
                return Some(brew);
            }
            let arch = if cfg!(target_arch = "aarch64") {
                "arm64"
            } else {
                "x86_64"
            };
            let output = std::process::Command::new("/usr/libexec/java_home")
                .args(["-F", "-v", version, "-a", arch])
                .output()
                .ok()?;
            if output.status.success() {
                let home = PathBuf::from(String::from_utf8_lossy(&output.stdout).trim());
                if executable(&home.join("bin/java")) {
                    return Some(home);
                }
            }
        }
    }
    None
}

fn executable(path: &Path) -> bool {
    let Ok(metadata) = path.metadata() else {
        return false;
    };
    if !metadata.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        metadata.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    {
        true
    }
}

fn sdk_version(name: &str) -> Option<(Vec<u64>, bool, Vec<u64>)> {
    let (base, preview) = name
        .split_once('-')
        .map_or((name, None), |(base, suffix)| (base, Some(suffix)));
    let version = base
        .split('.')
        .map(|part| part.parse::<u64>().ok())
        .collect::<Option<Vec<_>>>()?;
    let preview_numbers = preview
        .unwrap_or("")
        .split(|c: char| !c.is_ascii_digit())
        .filter(|part| !part.is_empty())
        .filter_map(|part| part.parse().ok())
        .collect();
    Some((version, preview.is_none(), preview_numbers))
}

fn build_tool_directories_in(roots: &[PathBuf]) -> Vec<PathBuf> {
    let mut directories = Vec::new();
    for root in roots {
        let Ok(entries) = std::fs::read_dir(root.join("build-tools")) else {
            continue;
        };
        let mut versions = entries
            .filter_map(Result::ok)
            .filter(|entry| entry.path().is_dir())
            .filter_map(|entry| Some((sdk_version(entry.file_name().to_str()?)?, entry.path())))
            .collect::<Vec<_>>();
        versions.sort_by(|left, right| right.0.cmp(&left.0).then(left.1.cmp(&right.1)));
        for (_, directory) in versions {
            if !directories.contains(&directory) {
                directories.push(directory);
            }
        }
    }
    directories
}

fn android_sdk_roots() -> Vec<PathBuf> {
    let mut roots = Vec::new();
    for key in ["ANDROID_SDK_ROOT", "ANDROID_HOME"] {
        if let Some(root) = std::env::var_os(key).filter(|value| !value.is_empty()) {
            roots.push(PathBuf::from(root));
        }
    }
    if let Some(home) = std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE")) {
        let home = PathBuf::from(home);
        roots.extend([
            home.join("Library/Android/sdk"),
            home.join("Android/Sdk"),
            home.join("AppData/Local/Android/Sdk"),
        ]);
    }
    if let Some(local) = std::env::var_os("LOCALAPPDATA") {
        roots.push(PathBuf::from(local).join("Android/Sdk"));
    }
    roots.extend([
        PathBuf::from("/opt/android-sdk"),
        PathBuf::from("/usr/local/lib/android/sdk"),
        PathBuf::from("/usr/lib/android-sdk"),
    ]);
    roots
}

pub(crate) fn android_build_tool_directories() -> Vec<PathBuf> {
    build_tool_directories_in(&android_sdk_roots())
}

fn discover_build_tool_in(
    name: &str,
    explicit_directory: Option<&Path>,
    path_directories: &[PathBuf],
    sdk_roots: &[PathBuf],
) -> Option<PathBuf> {
    let mut directories = Vec::new();
    if let Some(directory) = explicit_directory {
        directories.push(directory.to_owned());
    }
    directories.extend_from_slice(path_directories);
    directories.extend(build_tool_directories_in(sdk_roots));
    for directory in directories {
        let candidate = directory.join(name);
        if executable(&candidate) {
            return Some(candidate);
        }
        #[cfg(windows)]
        for extension in ["bat", "exe", "cmd"] {
            let candidate = directory.join(format!("{name}.{extension}"));
            if executable(&candidate) {
                return Some(candidate);
            }
        }
    }
    None
}

pub(crate) fn discover_android_build_tool(
    name: &str,
    explicit_directory: Option<&Path>,
) -> Option<PathBuf> {
    let paths = std::env::var_os("PATH")
        .map(|path| std::env::split_paths(&path).collect::<Vec<_>>())
        .unwrap_or_default();
    discover_build_tool_in(name, explicit_directory, &paths, &android_sdk_roots())
}

pub(crate) fn discover_jadx_cli(configured: &str, tool_directory: &str) -> Option<PathBuf> {
    let mut directories = Vec::new();
    let configured = Path::new(configured.trim());
    if configured.is_dir() {
        directories.extend([configured.join("bin"), configured.to_owned()]);
    } else if configured.is_file() {
        let name = configured.file_name()?.to_str()?.to_ascii_lowercase();
        if matches!(name.as_str(), "jadx" | "jadx-cli" | "jadx.bat" | "jadx.cmd")
            && executable(configured)
        {
            return Some(configured.to_owned());
        }
        if let Some(parent) = configured.parent() {
            directories.extend([parent.to_owned(), parent.join("../bin")]);
        }
    }
    if !tool_directory.trim().is_empty() {
        directories.push(PathBuf::from(tool_directory.trim()));
    }
    if let Some(path) = std::env::var_os("PATH") {
        directories.extend(std::env::split_paths(&path));
    }
    directories.extend([
        PathBuf::from("/opt/homebrew/bin"),
        PathBuf::from("/usr/local/bin"),
    ]);
    if let Some(home) = std::env::var_os("HOME") {
        directories.push(PathBuf::from(home).join(".local/bin"));
    }
    for directory in directories {
        for name in ["jadx", "jadx-cli", "jadx.bat", "jadx.cmd"] {
            let candidate = directory.join(name);
            if executable(&candidate) {
                // Keep a stable Homebrew symlink rather than pinning its Cellar version.
                return Some(if candidate.is_absolute() {
                    candidate
                } else {
                    std::env::current_dir().ok()?.join(candidate)
                });
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture_executable(path: &Path) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, b"#!/bin/sh\nexit 0\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
    }

    #[test]
    fn sdk_build_tools_use_numeric_versions_stable_release_and_explicit_priority() {
        let root = std::env::temp_dir().join(format!("me-sdk-discovery-{}", uuid::Uuid::new_v4()));
        let sdk = root.join("sdk");
        for version in ["9.0.0", "34.0.0", "35.0.0-rc3", "35.0.0", "invalid"] {
            fixture_executable(&sdk.join("build-tools").join(version).join("apksigner"));
        }
        std::fs::create_dir_all(sdk.join("build-tools/36.0.0")).unwrap();
        let roots = vec![sdk.clone()];
        assert_eq!(
            discover_build_tool_in("apksigner", None, &[], &roots),
            Some(sdk.join("build-tools/35.0.0/apksigner"))
        );
        let explicit = root.join("configured");
        fixture_executable(&explicit.join("apksigner"));
        assert_eq!(
            discover_build_tool_in("apksigner", Some(&explicit), &[], &roots),
            Some(explicit.join("apksigner"))
        );
        assert!(discover_build_tool_in("missing-tool", None, &[], &roots).is_none());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn jar_setting_is_migrated_to_its_executable_cli_without_opening_the_gui() {
        let root = std::env::temp_dir().join(format!("me-jadx-discovery-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(root.join("bin")).unwrap();
        let jar = root.join("bin/jadx-gui.jar");
        let cli = root.join("bin/jadx");
        std::fs::write(&jar, b"unused").unwrap();
        std::fs::write(&cli, b"#!/bin/sh\nexit 0\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&cli, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        assert_eq!(discover_jadx_cli(jar.to_str().unwrap(), ""), Some(cli));
        std::fs::remove_dir_all(root).unwrap();
    }
}
