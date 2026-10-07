//! Preserve diagnostic version output without changing first-line version comparisons.
use crate::RawOutput;
const MAX_VERSION_OUTPUT_BYTES: usize = 32 * 1024;

#[derive(Default)]
pub(super) struct ToolVersion {
    pub version: Option<String>,
    pub output: Option<String>,
    pub truncated: bool,
    pub error: Option<String>,
}

pub(super) fn describe(result: Result<RawOutput, String>) -> ToolVersion {
    let output = match result {
        Ok(output) => output,
        Err(error) => {
            return ToolVersion {
                error: Some(error),
                ..Default::default()
            }
        }
    };
    let mut text = super::output_text(&output);
    // Keep the legacy first-line value intact for compatibility/version matching.
    let version = text
        .lines()
        .next()
        .filter(|line| !line.is_empty())
        .map(str::to_string);
    let truncated = text.len() > MAX_VERSION_OUTPUT_BYTES;
    if truncated {
        let mut end = MAX_VERSION_OUTPUT_BYTES;
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        text.truncate(end);
    }
    ToolVersion {
        version,
        output: (!text.is_empty()).then_some(text),
        truncated,
        error: if output.code != Some(0) {
            Some(format!(
                "版本检测未成功（退出状态 {}），输出仅供诊断",
                output
                    .code
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "未知".into())
            ))
        } else {
            None
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn preserves_multiline_stdout_and_stderr_without_changing_version() {
        let v = describe(Ok(RawOutput { stdout: "curl 8.7.1 (aarch64-apple-darwin23.0) libcurl/8.7.1\nProtocols: http https\nFeatures: SSL zstd".into(), stderr: "warning: test diagnostic".into(), code: Some(0) }));
        assert_eq!(
            v.version.as_deref(),
            Some("curl 8.7.1 (aarch64-apple-darwin23.0) libcurl/8.7.1")
        );
        assert!(v.output.unwrap().ends_with("warning: test diagnostic"));
        assert!(!v.truncated);
        assert!(v.error.is_none());
    }
    #[test]
    fn bounds_output_on_utf8_boundary_and_reports_failure_or_missing_output() {
        let v = describe(Ok(RawOutput {
            stdout: "版".repeat(MAX_VERSION_OUTPUT_BYTES),
            stderr: String::new(),
            code: Some(2),
        }));
        assert!(v.truncated);
        assert_eq!(
            v.version.as_deref(),
            Some("版".repeat(MAX_VERSION_OUTPUT_BYTES).as_str())
        );
        assert!(v.output.unwrap().len() <= MAX_VERSION_OUTPUT_BYTES);
        assert!(v.error.unwrap().contains('2'));
        let v = describe(Ok(RawOutput {
            stdout: String::new(),
            stderr: String::new(),
            code: Some(0),
        }));
        assert!(v.version.is_none() && v.output.is_none());
        let v = describe(Err("version query timed out".into()));
        assert!(v.version.is_none() && v.output.is_none() && v.error.is_some());
    }
}
