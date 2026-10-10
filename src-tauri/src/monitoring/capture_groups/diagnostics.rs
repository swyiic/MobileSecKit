//! Bounded, display-only failure evidence. Never classify capture success from logs.
use super::*;

const DIAGNOSTIC_SCHEMA: &str = "mobilee.capture-diagnostic/v1";
const FAILURE_SCHEMA: &str = "kernsight.qualified-source-failure/v1";
const MAX_FAILURE_RECORD_BYTES: usize = 16 * 1024;
const MAX_ERROR_EXCERPT_BYTES: usize = 4096;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CaptureDiagnostic {
    pub schema: String,
    /// Display-only original counter records; never authorize continuation.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub coverage_records: Vec<Value>,
    /// Exact matched lifecycle terminal facts, independent from diagnostic output.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub terminal_record: Option<Value>,
    /// Original output retained in the parent file, within its terminal byte reserve.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw_output: Option<RawOutput>,
    /// Unified siblings reference the controller's single retained output.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw_output_attempt_id: Option<Uuid>,
    /// A matched lifecycle receipt or display-only output from this command.
    pub source: Option<String>,
    pub record: Option<Value>,
    pub error_excerpt: Option<String>,
    pub stdout_bytes: Option<usize>,
    pub stderr_bytes: Option<usize>,
    pub raw_tail_truncated: bool,
    pub error_excerpt_truncated: bool,
    pub structured_record_omitted: bool,
}

// At most half of the existing 64KiB terminal reserve is used by raw logs.
const RAW_OUTPUT_JSON_LIMIT: usize = 32 * 1024;
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RawOutput {
    pub stdout: String,
    pub stderr: String,
    pub complete: bool,
}
fn raw_output(result: &KernSightCaptureResult) -> RawOutput {
    let mut output = RawOutput {
        stdout: result.stdout.clone(),
        stderr: result.stderr.clone(),
        complete: true,
    };
    // Keep the beginning of stderr: final lifecycle JSON must not hide the first cause.
    while serde_json::to_vec(&output).map_or(usize::MAX, |v| v.len()) > RAW_OUTPUT_JSON_LIMIT {
        output.complete = false;
        let text = if !output.stdout.is_empty() {
            &mut output.stdout
        } else {
            &mut output.stderr
        };
        let mut end = text.len() * 3 / 4;
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        text.truncate(end);
    }
    output
}

pub(super) fn coverage_observation(stderr: &str) -> Option<String> {
    let poll = stderr.lines().find_map(|line| {
        let value: Value = serde_json::from_str(line).ok()?;
        (value["schema"] == "kernsight.perf-poll-budget/v1" && value["coverage_partial"] == true)
            .then_some(value)
    })?;
    let drain = stderr.lines().find_map(|line| {
        let value: Value = serde_json::from_str(line).ok()?;
        (value["schema"] == "kernsight.capture-drain/v1").then_some(value)
    });
    let lost = drain
        .as_ref()
        .and_then(|value| value["lost_samples"].as_u64())
        .unwrap_or(0);
    let unread = drain
        .as_ref()
        .is_some_and(|value| value["unknown_tail"] == true)
        || poll["unread_tail_possible"] == true;
    let skipped = poll["budget_skipped_raw"].as_u64().unwrap_or(0);
    Some(format!(
        "覆盖记录：内核丢样 {lost}；未读尾部 {}；适配器省略 {skipped}。采集已结束，这些数留给分析。",
        if unread { "有" } else { "无" }
    ))
}

pub(super) fn partial_stage_error(
    stage: &str,
    reason: &str,
    parent_remaining_ms: u64,
    original: Option<&str>,
) -> String {
    let mut text = format!("阶段 {stage} 覆盖 partial（{reason}）；父预算剩余 {parent_remaining_ms}ms；已保存证据可拉取");
    if let Some(original) = original.filter(|s| !s.is_empty()) {
        text.push_str("；");
        text.push_str(original);
    }
    text
}

fn valid_failure_shape(record: &Value) -> bool {
    record["schema"] == FAILURE_SCHEMA
        && record["failure"].is_object()
        && record["failure"]["kind"].is_string()
        && record["failure"]["cause"].is_string()
}

fn bounded_record(record: &Value) -> bool {
    serde_json::to_vec(record).is_ok_and(|encoded| encoded.len() <= MAX_FAILURE_RECORD_BYTES)
}

fn matched_lifecycle_record(note: &Value, attempt: &Attempt, record: &Value) -> bool {
    // Unified stages share a controller. Match the receipt to that exact
    // controller rather than inventing a separate receipt for every stage.
    note["schema"] == "kernsight.capture-lifecycle/v1"
        && note["relation"]["parent_id"].as_str()
            == Some(attempt.relation.parent_id.to_string().as_str())
        && note["token"]
            .as_str()
            .and_then(|s| Uuid::parse_str(s).ok())
            .is_some_and(|id| !id.is_nil())
        && record["relation"] == note["relation"]
        && record["token"] == note["token"]
}

fn output_record(text: &str, omitted: &mut bool) -> Option<Value> {
    for line in text.lines().rev() {
        // Producer failure receipts are compact JSON lines. Do not mine an
        // unrelated lifecycle JSON or turn arbitrary text into a receipt.
        let line = line.trim();
        if !line.starts_with('{') || !line.contains(FAILURE_SCHEMA) {
            continue;
        }
        if line.len() > MAX_FAILURE_RECORD_BYTES {
            *omitted = true;
            continue;
        }
        let Ok(record) = serde_json::from_str::<Value>(line) else {
            *omitted = true;
            continue;
        };
        if record["schema"] != FAILURE_SCHEMA {
            continue;
        }
        if !valid_failure_shape(&record) || !bounded_record(&record) {
            *omitted = true;
            continue;
        }
        return Some(record);
    }
    None
}

fn prefix_at_boundary(text: &str, bytes: usize) -> &str {
    let mut end = text.len().min(bytes);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[..end]
}

fn error_excerpt(source: &str, text: &str) -> (Option<String>, bool) {
    let lines: Vec<_> = text.lines().collect();
    let primary_error = lines.iter().rposition(|line| {
        let lower = line.trim().to_ascii_lowercase();
        lower.starts_with("error:") || lower.starts_with("error ")
    });
    let index = primary_error.or_else(|| {
        lines.iter().rposition(|line| {
            let line = line.trim();
            if line.starts_with('{') || line.starts_with('"') {
                return false;
            }
            let lower = line.to_ascii_lowercase();
            (lower.contains("qualified capture ")
                && [
                    "failed",
                    "failure",
                    "task exited",
                    "identity_changed",
                    "no numeric replacement",
                    "revalidation",
                ]
                .iter()
                .any(|marker| lower.contains(marker)))
                || lower.starts_with("capture loop stopped with error")
        })
    });
    let Some(index) = index else {
        return (None, false);
    };
    let mut chosen = vec![lines[index]];
    for line in &lines[index + 1..] {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if trimmed.starts_with('{') || trimmed.starts_with('[') {
            break;
        }
        if !line.starts_with(char::is_whitespace) && !trimmed.starts_with("Caused by:") {
            break;
        }
        chosen.push(line);
    }
    let text = chosen.join("\n");
    let prefix = format!("[{source} selected error; full output not retained]\n");
    let truncated = prefix.len() + text.len() > MAX_ERROR_EXCERPT_BYTES;
    let suffix = if truncated {
        "\n[error excerpt truncated]"
    } else {
        ""
    };
    let retained = prefix_at_boundary(&text, MAX_ERROR_EXCERPT_BYTES - prefix.len() - suffix.len());
    (Some(format!("{prefix}{retained}{suffix}")), truncated)
}

const TERMINAL_SCHEMA: &str = "mobilee.capture-terminal/v1";
const MAX_TERMINAL_RECORD_BYTES: usize = 4096;

fn terminal_record(
    attempt: &Attempt,
    result: Option<&KernSightCaptureResult>,
    omitted: &mut bool,
) -> Option<Value> {
    let note = attempt.remote_lifecycle.as_ref()?;
    // A sibling's controller receipt is retained on the controller attempt.
    // No parent-only match can manufacture terminal facts for another attempt.
    let r = &attempt.relation;
    let relation = &note["relation"];
    let matched = note["schema"] == "kernsight.capture-lifecycle/v1"
        && relation["parent_id"] == r.parent_id.to_string()
        && relation["stage_id"] == r.stage_id.to_string()
        && relation["attempt_id"] == r.attempt_id.to_string()
        && relation["attempt"] == r.attempt
        && relation["stage_key"] == r.stage_key
        && note["token"]
            .as_str()
            .and_then(|s| Uuid::parse_str(s).ok())
            .is_some_and(|id| !id.is_nil());
    if !matched {
        *omitted = true;
        return None;
    }
    if note["collection_returned"] != true {
        return None;
    }
    if !matches!(
        note["collection_status"].as_str(),
        Some("completed" | "partial")
    ) {
        *omitted = true;
        return None;
    }
    let mut record = serde_json::json!({
        "schema": TERMINAL_SCHEMA,
        "source": "matched_remote_lifecycle",
        "relation": relation,
        "token": note["token"],
        // Exit status is the owned command result, never inferred from lifecycle.
        "exit_code": result.and_then(|r| r.exit_code),
    });
    for key in [
        "stop_reason",
        "collection_returned",
        "collection_status",
        "agent_exited_confirmed",
        "cleanup",
        "target_pause",
    ] {
        record[key] = note[key].clone();
    }
    if let Some(coverage) = note.get("dump_coverage").filter(|v| !v.is_null()) {
        if coverage["schema"] == "kernsight.dump-coverage/v1"
            && serde_json::to_vec(coverage).is_ok_and(|v| v.len() <= 2048)
        {
            record["dump_coverage"] = coverage.clone();
        } else {
            *omitted = true;
            // Only a valid proof omitted for its size can preserve base terminal
            // facts. Invalid proof shapes remain mismatched in presentation.
            if coverage["schema"] == "kernsight.dump-coverage/v1"
                && serde_json::to_vec(coverage).is_ok_and(|v| v.len() > 2048)
            {
                record["dumpCoverageOmitted"] = true.into();
            }
        }
    }
    if serde_json::to_vec(&record).is_ok_and(|v| v.len() <= MAX_TERMINAL_RECORD_BYTES) {
        Some(record)
    } else {
        *omitted = true;
        None
    }
}

// Contract reasons allow 16 x 256 Unicode characters. Preserve all of those
// reasons even when quota detail or other producer fields need a projection.
const MAX_BUDGET_RECORD_BYTES: usize = 20 * 1024;
const MAX_COUNTER_RECORD_BYTES: usize = 4096;
const MAX_SOURCE_COUNTER_BYTES: usize = 128 * 1024;
const MAX_DIAGNOSTIC_JSON_BYTES: usize = 60 * 1024;

fn projected_counter(record: Value, omitted: &mut bool) -> Option<Value> {
    let encoded = serde_json::to_vec(&record).ok()?;
    if encoded.len() <= 2048 {
        return Some(record);
    }
    *omitted = true;
    let schema = record["schema"].as_str()?;
    let mut projected = serde_json::json!({"schema":schema,
        "diagnostic_projection":true,"source_record_bytes":encoded.len()});
    let keys: &[&str] = match schema {
        "kernsight.output-budget/v1" => &[
            "limit_bytes",
            "admitted_write_bytes",
            "rejected_writes",
            "partial",
        ],
        "kernsight.perf-poll-budget/v1" => &[
            "bounded_slice_yields",
            "unread_tail_possible",
            "unread_tail_count",
            "scope_failures",
            "perf_read_failures",
            "budget_skipped_raw",
            "quota_omitted_future_events",
            "coverage_partial",
        ],
        "kernsight.capture-drain/v1" => &[
            "producers_stopped",
            "queues_observed_empty",
            "unknown_tail",
            "rounds",
            "lost_samples",
        ],
        _ => return None,
    };
    for key in keys {
        if let Some(value) = record
            .get(*key)
            .filter(|v| v.is_boolean() || v.is_number() || v.is_null())
        {
            projected[*key] = value.clone();
        }
    }
    if schema == "kernsight.output-budget/v1" {
        if let Some(reason) = record["reason"].as_str() {
            projected["reason"] = reason.chars().take(256).collect::<String>().into();
            projected["reason_truncated"] = (reason.chars().count() > 256).into();
        }
        if let Some(reasons) = record["failure_reasons"].as_array() {
            projected["failure_reasons_count"] = reasons.len().into();
            if reasons.len() <= 16
                && reasons
                    .iter()
                    .all(|v| v.as_str().is_some_and(|s| s.chars().count() <= 256))
            {
                projected["failure_reasons"] = record["failure_reasons"].clone();
            } else {
                projected["failure_reasons_omitted"] = true.into();
            }
        }
        for key in ["admitted_by_kind", "admission_calls_by_kind"] {
            if let Some(value) = record
                .get(key)
                .filter(|v| serde_json::to_vec(v).is_ok_and(|b| b.len() <= 1024))
            {
                projected[key] = value.clone();
            }
        }
    }
    if schema == "kernsight.perf-poll-budget/v1" {
        if let Some(reasons) = record["coverage_reasons"].as_object() {
            let mut kept = serde_json::Map::new();
            for key in [
                "probe_quota",
                "shortened_window",
                "unread_tail",
                "scope_failure",
                "read_failure",
                "perf_loss",
            ] {
                if let Some(value) = reasons.get(key).filter(|v| v.is_boolean()) {
                    kept.insert(key.into(), value.clone());
                }
            }
            projected["coverage_reasons"] = kept.into();
        }
        projected["quota_stops_count"] = record["quota_stops"].as_array().map(Vec::len).into();
        projected["quota_stops_omitted"] = true.into();
    }
    let missing: Vec<_> = record
        .as_object()?
        .keys()
        .filter(|key| projected.get(*key).is_none())
        .cloned()
        .collect();
    projected["omitted_fields"] = missing.into();
    let limit = if schema == "kernsight.output-budget/v1" {
        MAX_BUDGET_RECORD_BYTES
    } else {
        MAX_COUNTER_RECORD_BYTES
    };
    serde_json::to_vec(&projected)
        .is_ok_and(|v| v.len() <= limit)
        .then_some(projected)
}

fn coverage_records(result: Option<&KernSightCaptureResult>, omitted: &mut bool) -> Vec<Value> {
    let mut records = Vec::new();
    for schema in [
        "kernsight.capture-drain/v1",
        "kernsight.perf-poll-budget/v1",
        "kernsight.output-budget/v1",
    ] {
        for line in result.into_iter().flat_map(|r| r.stderr.lines()).rev() {
            if !line.contains(schema) {
                continue;
            }
            if line.len() > MAX_SOURCE_COUNTER_BYTES {
                *omitted = true;
                break;
            }
            let Ok(record) = serde_json::from_str::<Value>(line) else {
                *omitted = true;
                continue;
            };
            if record["schema"] != schema {
                continue;
            }
            if let Some(record) = projected_counter(record, omitted) {
                records.push(record);
            } else {
                *omitted = true;
            }
            break;
        }
    }
    records
}

fn bound_diagnostic(mut diagnostic: CaptureDiagnostic) -> CaptureDiagnostic {
    // Leave room for the existing 3KiB tail and attempt metadata inside the
    // 64KiB terminal reserve. The 32KiB raw-output ceiling is never raised.
    while serde_json::to_vec(&diagnostic).map_or(usize::MAX, |v| v.len())
        > MAX_DIAGNOSTIC_JSON_BYTES
    {
        if let Some(raw) = diagnostic.raw_output.as_mut() {
            raw.complete = false;
            let text = if raw.stdout.is_empty() {
                &mut raw.stderr
            } else {
                &mut raw.stdout
            };
            if text.is_empty() {
                diagnostic.raw_output = None;
                continue;
            }
            let mut end = text.len() * 3 / 4;
            while !text.is_char_boundary(end) {
                end -= 1;
            }
            text.truncate(end);
        } else if diagnostic.coverage_records.pop().is_some() {
            diagnostic.structured_record_omitted = true;
        } else if diagnostic.terminal_record.take().is_some() || diagnostic.record.take().is_some()
        {
            diagnostic.structured_record_omitted = true;
        } else {
            diagnostic.error_excerpt = None;
            diagnostic.error_excerpt_truncated = true;
            break;
        }
    }
    diagnostic
}

pub(super) fn collect(
    attempt: &Attempt,
    result: Option<&KernSightCaptureResult>,
) -> Option<CaptureDiagnostic> {
    let mut omitted = false;
    let mut record = None;
    let mut source = None;
    if let Some(note) = attempt.remote_lifecycle.as_ref() {
        if let Some(candidate) = note.get("qualification_failure").filter(|r| !r.is_null()) {
            if valid_failure_shape(candidate)
                && bounded_record(candidate)
                && matched_lifecycle_record(note, attempt, candidate)
            {
                record = Some(candidate.clone());
                source = Some("remote_lifecycle".into());
            } else {
                omitted = true;
            }
        }
    }
    if let Some(result) = result {
        for (name, text) in [("stderr", &result.stderr), ("stdout", &result.stdout)] {
            if record.is_none() {
                record = output_record(text, &mut omitted);
                if record.is_some() {
                    source = Some(name.into());
                }
            }
        }
    }
    let terminal_record = terminal_record(attempt, result, &mut omitted);
    let coverage_records = coverage_records(result, &mut omitted);
    if result.is_none() && record.is_none() && terminal_record.is_none() && !omitted {
        return None;
    }
    let (excerpt, excerpt_truncated) = result
        .map(|result| {
            let stderr = error_excerpt("stderr", &result.stderr);
            if stderr.0.is_some() {
                stderr
            } else {
                error_excerpt("stdout", &result.stdout)
            }
        })
        .unwrap_or((None, false));
    let raw_tail_truncated = result.is_some_and(|result| {
        let (name, text) = if result.stderr.trim().is_empty() {
            ("stdout", result.stdout.trim())
        } else {
            ("stderr", result.stderr.trim())
        };
        text.len() + format!("[{name}]\n").len() > MAX_CAPTURE_DIAGNOSTIC_BYTES
    });
    Some(bound_diagnostic(CaptureDiagnostic {
        coverage_records,
        terminal_record,
        schema: DIAGNOSTIC_SCHEMA.into(),
        raw_output: result.map(raw_output),
        raw_output_attempt_id: None,
        source,
        record,
        error_excerpt: excerpt,
        stdout_bytes: result.map(|r| r.stdout.len()),
        stderr_bytes: result.map(|r| r.stderr.len()),
        raw_tail_truncated,
        error_excerpt_truncated: excerpt_truncated,
        structured_record_omitted: omitted,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn coverage_counters_survive_large_unretained_output_as_display_only_records() {
        let drain = serde_json::json!({"schema":"kernsight.capture-drain/v1", "producers_stopped":true,"queues_observed_empty":true,"unknown_tail":false,"lost_samples":123});
        let poll = serde_json::json!({"schema":"kernsight.perf-poll-budget/v1", "unread_tail_possible":false,"scope_failures":0,"perf_read_failures":0,"coverage_partial":true});
        let stderr = format!(
            "{}\n{drain}\n{poll}\nError: capture coverage partial",
            "x".repeat(100000)
        );
        let a = attempt();
        let diagnostic = collect(&a, Some(&output("", &stderr))).unwrap();
        assert_eq!(diagnostic.coverage_records, vec![drain, poll]);
        assert!(diagnostic.raw_tail_truncated);
        assert_eq!(a.state, "failed");
        assert!(collect(&a, None).is_none());
    }

    #[test]
    fn matched_partial_terminal_keeps_all_reasons_and_loss_without_raw_log_growth() {
        let mut a = attempt();
        let mut note = lifecycle(&a, "not a qualification failure");
        note.as_object_mut()
            .unwrap()
            .remove("qualification_failure");
        note["collection_returned"] = true.into();
        note["collection_status"] = "partial".into();
        note["stop_reason"] = "perf_poll_backlog_or_scope_gap_at_observation_end".into();
        note["agent_exited_confirmed"] = true.into();
        a.remote_lifecycle = Some(note.clone());
        let budget = serde_json::json!({"schema":"kernsight.output-budget/v1", "partial":true,
            "reason":"perf_poll_backlog_or_scope_gap_at_observation_end", "failure_reasons":["perf_loss","unread_tail"]});
        let drain = serde_json::json!({"schema":"kernsight.capture-drain/v1", "lost_samples":169234,"unknown_tail":true});
        let poll = serde_json::json!({"schema":"kernsight.perf-poll-budget/v1", "coverage_partial":true,
            "coverage_reasons":{"perf_loss":true,"unread_tail":true}, "budget_skipped_raw":7773});
        let stderr = format!("{}\n{budget}\n{drain}\n{poll}", "x".repeat(100000));
        let d = collect(&a, Some(&output("", &stderr))).unwrap();
        assert_eq!(d.coverage_records, vec![drain, poll, budget]);
        let terminal = d.terminal_record.unwrap();
        assert_eq!(terminal["relation"], note["relation"]);
        assert_eq!(terminal["token"], note["token"]);
        assert_eq!(terminal["stop_reason"], note["stop_reason"]);
        assert_eq!(terminal["collection_status"], "partial");
        assert_eq!(terminal["exit_code"], 1);
        assert!(terminal.get("target_exit_confirmed").is_none());
        let raw = d.raw_output.unwrap();
        assert!(!raw.complete);
        assert!(serde_json::to_vec(&raw).unwrap().len() <= RAW_OUTPUT_JSON_LIMIT);
        assert!(serde_json::to_vec(&terminal).unwrap().len() <= MAX_TERMINAL_RECORD_BYTES);
    }

    #[test]
    fn unmatched_terminal_and_output_only_claims_never_become_terminal_facts() {
        for field in [
            "parent_id",
            "stage_id",
            "attempt_id",
            "attempt",
            "stage_key",
            "token",
        ] {
            let mut a = attempt();
            let mut note = lifecycle(&a, "irrelevant");
            note.as_object_mut()
                .unwrap()
                .remove("qualification_failure");
            note["collection_returned"] = true.into();
            note["collection_status"] = "partial".into();
            if field == "token" {
                note["token"] = "unknown-owner".into();
            } else {
                note["relation"][field] = serde_json::json!("foreign");
            }
            a.remote_lifecycle = Some(note);
            let d = collect(&a, None).unwrap();
            assert!(d.terminal_record.is_none());
            assert!(d.structured_record_omitted);
        }
        let a = attempt();
        let mut note = lifecycle(&a, "output cannot prove return");
        note["collection_returned"] = true.into();
        note["collection_status"] = "completed".into();
        let d = collect(&a, Some(&output("", &note.to_string()))).unwrap();
        assert!(d.terminal_record.is_none());
    }

    #[test]
    fn legacy_missing_terminal_stays_unknown_and_oversized_records_are_explicit() {
        let mut a = attempt();
        a.remote_lifecycle = Some(lifecycle(&a, "legacy qualification only"));
        assert!(collect(&a, None).unwrap().terminal_record.is_none());
        let note = a.remote_lifecycle.as_mut().unwrap();
        note["collection_returned"] = true.into();
        note["collection_status"] = "partial".into();
        note["stop_reason"] = "身份🙂".repeat(5000).into();
        let d = collect(&a, None).unwrap();
        assert!(d.terminal_record.is_none());
        assert!(d.structured_record_omitted);
        let budget = serde_json::json!({"schema":"kernsight.output-budget/v1", "failure_reasons":["x".repeat(3000)]});
        let d = collect(&attempt(), Some(&output("", &budget.to_string()))).unwrap();
        assert_eq!(d.coverage_records[0]["failure_reasons_omitted"], true);
        assert!(d.structured_record_omitted);
    }

    #[test]
    fn large_counter_projection_keeps_all_contract_reasons_and_loss_with_total_bound() {
        let reasons: Vec<_> = (0..16)
            .map(|i| format!("{i}{}", "🙂".repeat(253)))
            .collect();
        let budget = serde_json::json!({"schema":"kernsight.output-budget/v1", "limit_bytes":100,
            "admitted_write_bytes":99,"rejected_writes":0,"partial":true,"failure_reasons":reasons});
        let poll = serde_json::json!({"schema":"kernsight.perf-poll-budget/v1", "budget_skipped_raw":7773,
            "coverage_reasons":{"perf_loss":true,"unread_tail":true}, "quota_stops":["x".repeat(3000),"y".repeat(3000)]});
        let drain = serde_json::json!({"schema":"kernsight.capture-drain/v1", "lost_samples":169234,"unknown_tail":true});
        let failure = failure(&"x".repeat(10000));
        let stderr = format!(
            "{failure}\n{}\n{budget}\n{poll}\n{drain}",
            "z".repeat(100000)
        );
        let d = collect(&attempt(), Some(&output("", &stderr))).unwrap();
        assert_eq!(d.coverage_records[0], drain);
        assert_eq!(d.coverage_records[1]["budget_skipped_raw"], 7773);
        assert_eq!(d.coverage_records[1]["coverage_reasons"]["perf_loss"], true);
        assert_eq!(d.coverage_records[1]["quota_stops_count"], 2);
        assert_eq!(d.coverage_records[1]["quota_stops_omitted"], true);
        assert_eq!(
            d.coverage_records[2]["failure_reasons"],
            serde_json::json!(reasons)
        );
        assert!(d.structured_record_omitted);
        assert!(serde_json::to_vec(&d).unwrap().len() <= MAX_DIAGNOSTIC_JSON_BYTES);
        assert!(
            serde_json::to_vec(d.raw_output.as_ref().unwrap())
                .unwrap()
                .len()
                <= RAW_OUTPUT_JSON_LIMIT
        );
        assert!(!d.raw_output.as_ref().unwrap().complete);
    }

    #[test]
    fn legal_large_dump_proof_omission_keeps_base_terminal_and_explicit_marker() {
        let mut a = attempt();
        a.relation.stage_key = "dump".into();
        let mut note = lifecycle(&a, "not a qualification failure");
        note.as_object_mut()
            .unwrap()
            .remove("qualification_failure");
        note["collection_returned"] = true.into();
        note["collection_status"] = "partial".into();
        note["stop_reason"] = "bound_code_copy_partial".into();
        note["dump_coverage"] = serde_json::json!({"schema":"kernsight.dump-coverage/v1",
            "catalog_complete":true,"payload_coverage_complete":false,
            "coverage_causes":(0..16).map(|i|format!("{i}{}", "x".repeat(253))).collect::<Vec<_>>()});
        a.remote_lifecycle = Some(note.clone());
        let d = collect(&a, None).unwrap();
        let terminal = d.terminal_record.unwrap();
        assert_eq!(terminal["dumpCoverageOmitted"], true);
        assert!(terminal.get("dump_coverage").is_none());
        assert_eq!(terminal["stop_reason"], "bound_code_copy_partial");
        assert_eq!(terminal["relation"], note["relation"]);
        assert_eq!(terminal["token"], note["token"]);
        assert!(d.structured_record_omitted);
        assert_eq!(a.remote_lifecycle.unwrap(), note);
    }

    #[test]
    fn invalid_dump_proof_cannot_gain_a_legal_omission_marker() {
        let mut a = attempt();
        let mut note = lifecycle(&a, "not a qualification failure");
        note["collection_returned"] = true.into();
        note["collection_status"] = "partial".into();
        note["dump_coverage"] =
            serde_json::json!({"schema":"foreign/v1", "noisy":"x".repeat(3000)});
        a.remote_lifecycle = Some(note);
        let d = collect(&a, None).unwrap();
        assert!(d
            .terminal_record
            .unwrap()
            .get("dumpCoverageOmitted")
            .is_none());
        assert!(d.structured_record_omitted);
    }

    fn attempt() -> Attempt {
        serde_json::from_value(serde_json::json!({
            "relation":{"parentId":Uuid::new_v4(),"stageId":Uuid::new_v4(),"attemptId":Uuid::new_v4(),"attempt":1,"stageKey":"l1"},
            "ownerEpoch":Uuid::new_v4(),"state":"failed","startedUnixMs":1,"finishedUnixMs":2,
            "sessionId":null,"error":"stage failed","remoteArtifactRoot":null,
            "omittedProcessInstances":0
        })).unwrap()
    }
    fn output(stdout: &str, stderr: &str) -> KernSightCaptureResult {
        KernSightCaptureResult {
            session_id: Some(Uuid::new_v4()),
            started_unix_ms: 1,
            finished_unix_ms: 2,
            command_preview: "synthetic fixture; no device".into(),
            stdout: stdout.into(),
            stderr: stderr.into(),
            exit_code: Some(1),
            hide_debug: false,
        }
    }
    fn failure(cause: &str) -> Value {
        serde_json::json!({"schema":FAILURE_SCHEMA,"failure":{
            "kind":"requalification_failed","cause":cause,"errno":13,
            "expected":{"pid":10892,"birth_ns":530999312825352_u64,"exec_id":4},
            "observed":null,"target_exit_confirmed":null
        }})
    }
    fn lifecycle(attempt: &Attempt, cause: &str) -> Value {
        let relation = serde_json::json!({"parent_id":attempt.relation.parent_id,"stage_id":attempt.relation.stage_id,"attempt_id":attempt.relation.attempt_id,"attempt":attempt.relation.attempt,"stage_key":attempt.relation.stage_key});
        let token = Uuid::new_v4();
        let mut record = failure(cause);
        record["relation"] = relation.clone();
        record["token"] = serde_json::json!(token);
        serde_json::json!({"schema":"kernsight.capture-lifecycle/v1","relation":relation,"token":token,"qualification_failure":record})
    }

    #[test]
    fn important_error_before_verbose_lifecycle_is_preserved_separately_from_tail() {
        let stderr = format!("Error: qualified capture requalification_failed: metadata observation empty\nCaused by:\n    iterator returned no matching source\n{}", serde_json::json!({"schema":"kernsight.capture-lifecycle/v1","startup":{"previous_instances":"x".repeat(20000)}}));
        let result = output("", &stderr);
        let diagnostic = collect(&attempt(), Some(&result)).unwrap();
        assert!(diagnostic
            .error_excerpt
            .as_ref()
            .unwrap()
            .contains("metadata observation empty"));
        assert!(diagnostic
            .error_excerpt
            .as_ref()
            .unwrap()
            .contains("iterator returned no matching source"));
        assert!(!diagnostic
            .error_excerpt
            .as_ref()
            .unwrap()
            .contains("previous_instances"));
        assert!(diagnostic.raw_tail_truncated);
        assert_eq!(diagnostic.stderr_bytes, Some(stderr.len()));
    }

    #[test]
    fn anyhow_blank_line_does_not_discard_the_underlying_cause_chain() {
        let stderr = "Error: capture failed\n\nCaused by:\n    0: qualified capture requalification_failed\n    1: physical observation denied (os error 13)\n{\"schema\":\"unrelated\"}";
        let diagnostic = collect(&attempt(), Some(&output("", stderr))).unwrap();
        let excerpt = diagnostic.error_excerpt.unwrap();
        assert!(excerpt.contains("Error: capture failed"));
        assert!(excerpt.contains("physical observation denied (os error 13)"));
        assert!(!excerpt.contains("unrelated"));
    }

    #[test]
    fn structured_stderr_receipt_before_large_json_survives_without_inventing_exit() {
        let record = failure("read qualification denied: Permission denied (os error 13)");
        let stderr = format!(
            "{record}\n{}",
            serde_json::json!({"startup":"x".repeat(12000)})
        );
        let diagnostic = collect(&attempt(), Some(&output("", &stderr))).unwrap();
        assert_eq!(diagnostic.source.as_deref(), Some("stderr"));
        assert_eq!(diagnostic.record, Some(record));
        assert!(diagnostic.record.as_ref().unwrap()["failure"]["target_exit_confirmed"].is_null());
        assert!(diagnostic.raw_tail_truncated);
    }

    #[test]
    fn structured_stdout_is_not_hidden_by_nonempty_stderr_noise() {
        let record = failure("sampler counterexample");
        let diagnostic = collect(
            &attempt(),
            Some(&output(&record.to_string(), "unrelated stderr status")),
        )
        .unwrap();
        assert_eq!(diagnostic.source.as_deref(), Some("stdout"));
        assert_eq!(diagnostic.record, Some(record));
    }

    #[test]
    fn matched_lifecycle_receipt_is_available_without_raw_command_result() {
        let mut attempt = attempt();
        let note = lifecycle(&attempt, "retained reason");
        attempt.remote_lifecycle = Some(note.clone());
        let diagnostic = collect(&attempt, None).unwrap();
        assert_eq!(diagnostic.source.as_deref(), Some("remote_lifecycle"));
        assert_eq!(
            diagnostic.record,
            Some(note["qualification_failure"].clone())
        );
        assert!(!diagnostic.structured_record_omitted);
        assert!(diagnostic.stdout_bytes.is_none());
        assert!(diagnostic.stderr_bytes.is_none());
    }

    #[test]
    fn foreign_parent_relation_or_token_is_not_promoted_to_a_matched_receipt() {
        for field in ["parent", "relation", "token"] {
            let mut attempt = attempt();
            let mut note = lifecycle(&attempt, "must not be trusted");
            match field {
                "parent" => note["relation"]["parent_id"] = serde_json::json!(Uuid::new_v4()),
                "relation" => {
                    note["qualification_failure"]["relation"]["attempt_id"] =
                        serde_json::json!(Uuid::new_v4())
                }
                _ => note["qualification_failure"]["token"] = serde_json::json!(Uuid::new_v4()),
            }
            attempt.remote_lifecycle = Some(note);
            let diagnostic = collect(&attempt, None).unwrap();
            assert!(diagnostic.record.is_none());
            assert!(diagnostic.structured_record_omitted);
        }
    }

    #[test]
    fn shared_controller_receipt_keeps_its_original_relation() {
        let mut attempt = attempt();
        let mut note = lifecycle(&attempt, "shared controller refused");
        note["relation"]["stage_key"] = serde_json::json!("l0");
        note["relation"]["stage_id"] = serde_json::json!(Uuid::new_v4());
        note["qualification_failure"]["relation"] = note["relation"].clone();
        attempt.remote_lifecycle = Some(note.clone());
        let record = collect(&attempt, None).unwrap().record.unwrap();
        assert_eq!(record["relation"]["stage_key"], "l0");
        assert_eq!(attempt.relation.stage_key, "l1");
    }

    #[test]
    fn oversized_record_is_explicitly_omitted_without_partial_json() {
        let record = failure(&"x".repeat(MAX_FAILURE_RECORD_BYTES));
        let diagnostic = collect(&attempt(), Some(&output("", &record.to_string()))).unwrap();
        assert!(diagnostic.record.is_none());
        assert!(diagnostic.structured_record_omitted);
        assert!(diagnostic.raw_tail_truncated);
    }

    #[test]
    fn malformed_failure_json_is_flagged_instead_of_silently_disappearing() {
        let text = format!("{{\"schema\":\"{FAILURE_SCHEMA}\",\"failure\":");
        let diagnostic = collect(&attempt(), Some(&output("", &text))).unwrap();
        assert!(diagnostic.record.is_none());
        assert!(diagnostic.structured_record_omitted);
    }

    #[test]
    fn error_excerpt_truncation_is_utf8_safe_and_explicit() {
        let stderr = format!("Error: qualified capture {}", "身份🙂".repeat(4000));
        let diagnostic = collect(&attempt(), Some(&output("", &stderr))).unwrap();
        let excerpt = diagnostic.error_excerpt.unwrap();
        assert!(excerpt.len() <= MAX_ERROR_EXCERPT_BYTES);
        assert!(excerpt.contains("Error: qualified capture"));
        assert!(excerpt.ends_with("[error excerpt truncated]"));
        assert!(diagnostic.error_excerpt_truncated);
    }

    #[test]
    fn json_without_failure_schema_does_not_become_an_error_or_receipt() {
        let text =
            serde_json::json!({"startup":{"status":"failed","cause":"Error: qualified capture"}})
                .to_string();
        let diagnostic = collect(&attempt(), Some(&output("", &text))).unwrap();
        assert!(diagnostic.record.is_none());
        assert!(diagnostic.error_excerpt.is_none());
    }

    #[test]
    fn informational_qualification_line_is_not_mislabeled_as_failure_cause() {
        let diagnostic = collect(
            &attempt(),
            Some(&output(
                "",
                "INFO qualified capture started with pinned source",
            )),
        )
        .unwrap();
        assert!(diagnostic.error_excerpt.is_none());
    }

    #[test]
    fn legacy_empty_and_transport_only_diagnostics_remain_unknown() {
        assert!(collect(&attempt(), None).is_none());
        let diagnostic = collect(&attempt(), Some(&output("", ""))).unwrap();
        assert!(diagnostic.record.is_none());
        assert!(diagnostic.error_excerpt.is_none());
        assert_eq!(diagnostic.stderr_bytes, Some(0));
        assert!(!diagnostic.raw_tail_truncated);
    }

    #[test]
    fn original_stderr_is_retained_even_when_display_tail_is_truncated() {
        let stderr = format!("first root cause\n{}", "x".repeat(14_346));
        let d = collect(&attempt(), Some(&output("", &stderr))).unwrap();
        assert!(d.raw_tail_truncated);
        let raw = d.raw_output.unwrap();
        assert!(raw.complete);
        assert_eq!(raw.stderr, stderr);
    }
    #[test]
    fn raw_output_is_json_byte_bounded_and_preserves_first_cause() {
        let stderr = format!("first root cause\n{}", "身份🙂\n".repeat(40_000));
        let raw = raw_output(&output(&"large stdout".repeat(10_000), &stderr));
        assert!(!raw.complete);
        assert!(raw.stderr.starts_with("first root cause"));
        assert!(serde_json::to_vec(&raw).unwrap().len() <= RAW_OUTPUT_JSON_LIMIT);
    }
    #[test]
    fn phase_error_is_not_replaced_by_a_generic_parent_reason() {
        let text = partial_stage_error(
            "l1",
            "parent_deadline_exhausted",
            465_199,
            Some("phase_time_exhausted: l1 crossed its original lease"),
        );
        assert!(text.contains("阶段 l1"));
        assert!(text.contains("父预算剩余 465199ms"));
        assert!(text.contains("phase_time_exhausted"));
    }

    #[test]
    fn diagnostic_serialization_preserves_raw_receipt_and_flags() {
        let result = output(
            "",
            &failure("parent_cancelled remote_collection_partial are display text").to_string(),
        );
        let diagnostic = collect(&attempt(), Some(&result)).unwrap();
        let encoded = serde_json::to_value(&diagnostic).unwrap();
        assert_eq!(encoded["schema"], DIAGNOSTIC_SCHEMA);
        assert_eq!(encoded["record"]["failure"]["errno"], 13);
        assert!(encoded["record"]["failure"]["target_exit_confirmed"].is_null());
        assert_eq!(encoded["rawTailTruncated"], false);
        let restored: CaptureDiagnostic = serde_json::from_value(encoded.clone()).unwrap();
        assert_eq!(serde_json::to_value(restored).unwrap(), encoded);
    }
}
