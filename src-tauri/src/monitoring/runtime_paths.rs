//! Explicit isolated command routing. No process-global selection or device operations in validation.
use serde::{Deserialize, Serialize};
use serde_json::Value;
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimePaths {
    pub root: String,
    pub agent_path: String,
    pub expected_sha256: String,
}
impl RuntimePaths {
    pub fn validate(&self) -> Result<(), String> {
        fn clean(p: &str) -> bool {
            p.starts_with("/data/local/tmp/")
                && !p.ends_with('/')
                && !p.contains("//")
                && p.split('/').all(|c| c != "." && c != "..")
                && p.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"/._-".contains(&b))
        }
        if !clean(&self.root)
            || self.root == "/data/local/tmp/ksight"
            || self.root.starts_with("/data/local/tmp/ksight/")
            || !clean(&self.agent_path)
            || !self.agent_path.starts_with(&format!("{}/", self.root))
            || !self.agent_path.ends_with("/ksightd")
            || self.expected_sha256.len() != 64
            || !self
                .expected_sha256
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        {
            return Err("隔离根/agent路径/完整SHA无效，未执行设备命令".into());
        }
        Ok(())
    }
    pub fn route(&self, script: &str) -> Result<String, String> {
        self.validate()?;
        let remapped = script.replace("/data/local/tmp/ksight/", &format!("{}/", self.root));
        Ok(remapped.replace(
            &format!("{}/ksightd ", self.root),
            &format!(
                "{} --runtime-root {} --expected-agent-sha256 {} --expected-agent-path {} ",
                self.agent_path, self.root, self.expected_sha256, self.agent_path
            ),
        ))
    }
    pub fn check_capability(&self, code: Option<i32>, text: &str) -> Result<(), String> {
        self.validate()?;
        let note: Value =
            serde_json::from_str(text).map_err(|_| "隔离能力回执缺失，旧agent不降级")?;
        if code != Some(0)
            || note["schema"] != "kernsight.code-capabilities/v1"
            || note["runtime_paths_schema"] != "kernsight.runtime-paths/v1"
            || note["runtime_root"] != self.root
            || note["agent_sha256"] != self.expected_sha256
            || note["agent_path"] != self.agent_path
        {
            return Err("隔离根/agent身份或能力未验证，未启动目标".into());
        }
        Ok(())
    }
}
pub fn route(paths: Option<&RuntimePaths>, script: &str) -> Result<String, String> {
    paths.map_or_else(|| Ok(script.into()), |p| p.route(script))
}
#[cfg(test)]
mod tests {
    use super::*;
    fn config() -> RuntimePaths {
        RuntimePaths {
            root: "/data/local/tmp/ksight-candidate-fixture".into(),
            agent_path: "/data/local/tmp/ksight-candidate-fixture/bin/ksightd".into(),
            expected_sha256: "a".repeat(64),
        }
    }
    #[test]
    fn production_route_covers_assets_spool_log_and_control_without_changing_legacy() {
        let p = config();
        let script="/data/local/tmp/ksight/ksightd capture --object /data/local/tmp/ksight/file_open.bpf.o --spool-dir /data/local/tmp/ksight/spool > /data/local/tmp/ksight/capture.log";
        let text = p.route(script).unwrap();
        assert!(
            text.contains("/bin/ksightd --runtime-root /data/local/tmp/ksight-candidate-fixture")
        );
        assert!(text.contains("--expected-agent-sha256"));
        assert!(text.contains(&p.expected_sha256));
        assert!(text.contains(
            "--expected-agent-path /data/local/tmp/ksight-candidate-fixture/bin/ksightd capture"
        ));
        assert!(!text.contains("/data/local/tmp/ksight/"));
        assert!(text.contains("fixture/spool"));
        assert!(text.contains("fixture/capture.log"));
        assert_eq!(route(None, script).unwrap(), script);
    }
    #[test]
    fn production_route_refuses_bad_paths_wrong_hash_and_old_agent() {
        let mut p = config();
        for root in [
            "relative",
            "/data/local/tmp/ksight",
            "/data/local/tmp/ksight/old",
            "/data/local/tmp/x/../y",
            "/data/local/tmp/x;id",
        ] {
            p.root = root.into();
            assert!(p.validate().is_err());
        }
        let p = config();
        assert!(p.check_capability(Some(0), "{\"supported\":true}").is_err());
        let mut note = serde_json::json!({"schema":"kernsight.code-capabilities/v1","runtime_paths_schema":"kernsight.runtime-paths/v1","runtime_root":p.root,"agent_sha256":p.expected_sha256,"agent_path":p.agent_path});
        assert!(p.check_capability(Some(0), &note.to_string()).is_ok());
        note["agent_sha256"] = serde_json::json!("b".repeat(64));
        assert!(p.check_capability(Some(0), &note.to_string()).is_err());
    }
}
