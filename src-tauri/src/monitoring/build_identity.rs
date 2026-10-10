//! Display metadata comes only from the selected device's agent, never this checkout.
use serde::Serialize;
use serde_json::Value;

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct AgentBuildIdentity {
    pub version: String,
    pub git_commit: Option<String>,
    pub git_dirty: Option<bool>,
    pub source: String,
    pub binary_sha256: Option<String>,
}

pub(super) fn parse(
    code: Option<i32>,
    text: &str,
    handshake_version: &str,
) -> Option<AgentBuildIdentity> {
    let note: Value = serde_json::from_str(text).ok()?;
    if code != Some(0)
        || note["schema"] != "kernsight.code-capabilities/v1"
        || note["agent_version"].as_str()? != handshake_version
    {
        return None;
    }
    let source = note["agent_build_identity_source"].as_str()?;
    if !matches!(source, "git" | "override" | "unknown") {
        return None;
    }
    let commit = note["agent_git_commit"]
        .as_str()
        .filter(|s| matches!(s.len(), 40 | 64) && s.bytes().all(|b| b.is_ascii_hexdigit()));
    let dirty = note["agent_git_dirty"].as_bool();
    let reported = note["agent_build_version"].as_str()?;
    let expected = match (source, commit, dirty) {
        ("git" | "override", Some(commit), Some(dirty_flag)) => {
            let short = &commit[..7];
            let underscore = format!("{handshake_version}_{short}");
            let plus = format!("{handshake_version}+{short}");
            let legacy_dirty = format!("{plus}.dirty");
            let fresh = reported
                .strip_prefix(&format!("{plus}+"))
                .is_some_and(|suffix| {
                    suffix.len() == 8 && suffix.bytes().all(|byte| byte.is_ascii_hexdigit())
                });
            let build_token = reported
                .strip_prefix(&format!("{handshake_version}_"))
                .is_some_and(|suffix| {
                    suffix.len() == 8 && suffix.bytes().all(|byte| byte.is_ascii_hexdigit())
                });
            if reported == underscore
                || reported == plus
                || build_token
                || (dirty_flag && (reported == legacy_dirty || fresh))
            {
                reported.to_owned()
            } else {
                return None;
            }
        }
        ("git", Some(commit), None) if note["agent_git_dirty"].is_null() => {
            format!("{handshake_version}+{}.dirty-unknown", &commit[..7])
        }
        ("unknown", None, None)
            if note["agent_git_commit"].is_null() && note["agent_git_dirty"].is_null() =>
        {
            format!("{handshake_version}+unknown")
        }
        _ => return None,
    };
    if reported != expected {
        return None;
    }
    Some(AgentBuildIdentity {
        version: expected,
        git_commit: commit.map(str::to_string),
        git_dirty: dirty,
        source: source.into(),
        binary_sha256: note["agent_sha256"]
            .as_str()
            .filter(|s| s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit()))
            .map(str::to_string),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn note() -> Value {
        serde_json::json!({"schema":"kernsight.code-capabilities/v1","agent_version":"0.2.12","agent_build_version":"0.2.12+03e97b4.dirty","agent_git_commit":format!("03e97b4{}", "0".repeat(33)),"agent_git_dirty":true,"agent_build_identity_source":"git","agent_sha256":"a".repeat(64),"supported":false})
    }
    #[test]
    fn accepts_identity_even_when_capture_capability_is_refused() {
        let build = parse(Some(0), &note().to_string(), "0.2.12").unwrap();
        assert_eq!(build.version, "0.2.12+03e97b4.dirty");
        let mut fresh = note();
        fresh["agent_build_version"] = "0.2.12+03e97b4+707c2f0f".into();
        let fresh_build = parse(Some(0), &fresh.to_string(), "0.2.12").unwrap();
        assert_eq!(fresh_build.version, "0.2.12+03e97b4+707c2f0f");
        fresh["agent_build_version"] = "0.2.12_03e97b4".into();
        assert_eq!(
            parse(Some(0), &fresh.to_string(), "0.2.12")
                .unwrap()
                .version,
            "0.2.12_03e97b4"
        );
        fresh["agent_build_version"] = "0.2.12+03e97b4+short".into();
        assert!(parse(Some(0), &fresh.to_string(), "0.2.12").is_none());
        assert_eq!(build.git_commit.unwrap().len(), 40);
        assert_eq!(build.git_dirty, Some(true));
        assert_eq!(build.binary_sha256.unwrap().len(), 64);
    }
    #[test]
    fn old_failed_foreign_and_inconsistent_metadata_stay_unknown() {
        assert!(parse(Some(0), "{}", "0.2.12").is_none());
        assert!(parse(Some(1), &note().to_string(), "0.2.12").is_none());
        assert!(parse(Some(0), &note().to_string(), "0.2.11").is_none());
        for (key, value) in [
            ("agent_build_version", Value::String("0.2.12+other".into())),
            ("agent_git_commit", Value::String("short".into())),
            ("agent_git_dirty", Value::Null),
            (
                "agent_build_identity_source",
                Value::String("local-checkout".into()),
            ),
        ] {
            let mut n = note();
            n[key] = value;
            assert!(parse(Some(0), &n.to_string(), "0.2.12").is_none());
        }
    }
    #[test]
    fn clean_override_and_unavailable_dirty_status_remain_distinct() {
        let mut n = note();
        n["agent_build_identity_source"] = "override".into();
        n["agent_git_dirty"] = false.into();
        n["agent_build_version"] = "0.2.12+03e97b4".into();
        assert_eq!(
            parse(Some(0), &n.to_string(), "0.2.12").unwrap().git_dirty,
            Some(false)
        );
        n["agent_build_identity_source"] = "git".into();
        n["agent_git_dirty"] = Value::Null;
        n["agent_build_version"] = "0.2.12+03e97b4.dirty-unknown".into();
        let build = parse(Some(0), &n.to_string(), "0.2.12").unwrap();
        assert!(build.git_dirty.is_none());
        assert!(build.git_commit.is_some());
    }
    #[test]
    fn explicit_unknown_never_invents_clean_or_a_commit() {
        let mut n = note();
        n["agent_build_identity_source"] = "unknown".into();
        n["agent_build_version"] = "0.2.12+unknown".into();
        n["agent_git_commit"] = Value::Null;
        n["agent_git_dirty"] = Value::Null;
        let build = parse(Some(0), &n.to_string(), "0.2.12").unwrap();
        assert_eq!(build.version, "0.2.12+unknown");
        assert!(build.git_commit.is_none() && build.git_dirty.is_none());
    }
}
