//! Separate retained data coverage from producer execution safety.
use super::*;
pub(super) const LOSS_REASON: &str = "perf_poll_backlog_or_scope_gap_at_observation_end";
pub(super) const ABSENT: &str = "qualified_dump_sources_absent_before_start";

fn unique_record(result: &KernSightCaptureResult, schema: &str) -> Option<Value> {
    let mut records = Vec::new();
    for line in result.stderr.lines().filter(|line| line.contains(schema)) {
        if line.len() > 2048 {
            return None;
        }
        let record: Value = serde_json::from_str(line).ok()?;
        if record["schema"] == schema {
            records.push(record);
        } else {
            return None;
        }
    }
    (records.len() == 1).then(|| records[0].clone())
}
pub(super) fn proof(
    group: &Group,
    relation: &Relation,
    session: Uuid,
    result: &KernSightCaptureResult,
    lifecycle: &Value,
    manifest: &Value,
    source_relation: &Value,
) -> Option<Value> {
    if group.unified
        || relation.stage_key != "l1"
        || group.cancel_requested
        || group.base["inspectStages"].as_str().is_some()
        || result.session_id != Some(session)
        || result.exit_code != Some(1)
        || !remote_terminal_confirmed(lifecycle)
        || validate_remote_lifecycle(lifecycle, relation).is_err()
        || lifecycle["collection_status"] != "partial"
        || lifecycle["stop_reason"] != LOSS_REASON
        || lifecycle["stop_command_attempted"] != false
        || lifecycle["stop_request_recorded"] != false
        || lifecycle["startup"]["timing"]["launcher_status"] != "completed"
        || lifecycle
            .get("qualification_failure")
            .is_some_and(|v| !v.is_null())
        || super::super::qualified_dump_sources(Some(lifecycle), &group.package).is_err()
        || source_relation["session_id"].as_str() != Some(session.to_string().as_str())
        || source_relation["package"] != group.package
        || source_relation["relation"] != lifecycle["relation"]
        || manifest["session_id"].as_str() != Some(session.to_string().as_str())
        || !matches!(manifest["state"].as_str(), Some("interrupted" | "stopped"))
    {
        return None;
    }
    let writer = &manifest["writer"];
    let accepted = writer["accepted_events"].as_u64()?;
    if writer["terminal_finalized"] != true
        || writer["committed_events"] != accepted
        || manifest["event_count"] != accepted
        || writer["unpersisted_events_at_exit"] != 0
        || writer["pending_events"] != 0
        || writer["write_failures"] != 0
        || writer["rejected_events"] != 0
        || !writer.get("terminal_flush_error")?.is_null()
        || !writer.get("terminal_manifest_error")?.is_null()
        || !writer.get("last_failure")?.is_null()
    {
        return None;
    }
    let drain = unique_record(result, "kernsight.capture-drain/v1")?;
    let poll = unique_record(result, "kernsight.perf-poll-budget/v1")?;
    if !safe_closed_coverage(&drain, &poll) {
        return None;
    }
    Some(
        serde_json::json!({"schema":"mobilee.coverage-continuation/v1",
        "relation":relation,"sessionId":session,"token":lifecycle["token"],
        "source":"owned capture result plus fresh matched sealed spool",
        "coverage":if drain["unknown_tail"] == true || poll["unread_tail_possible"] == true {"incomplete_tail"}else{"loss_only"},"drain":drain,"poll":poll,
        "acceptedEvents":accepted,"committedEvents":accepted,"sealed":true}),
    )
}
// Queue coverage is independent of closed-producer and original-source safety.
// Require explicit, internally consistent diagnostics; never infer absent fields.
fn safe_closed_coverage(drain: &Value, poll: &Value) -> bool {
    drain["schema"] == "kernsight.capture-drain/v1"
        && poll["schema"] == "kernsight.perf-poll-budget/v1"
        && drain["producers_stopped"] == true
        && drain["queues_observed_empty"].as_bool().is_some()
        && drain["unknown_tail"].as_bool()
            == drain["queues_observed_empty"].as_bool().map(|empty| !empty)
        && drain["rounds"].as_u64().is_some_and(|n| n > 0)
        && drain["lost_samples"].as_u64().is_some()
        && poll["scope_failures"] == 0
        && poll["perf_read_failures"] == 0
        && poll["unread_tail_possible"].as_bool().is_some()
        && poll["coverage_partial"] == true
        && (drain["lost_samples"].as_u64().is_some_and(|n| n > 0)
            || drain["unknown_tail"] == true
            || poll["unread_tail_possible"] == true)
}
pub(super) fn authorize_phase(proof: Option<Value>, safe: bool) -> Option<Value> {
    if !safe {
        return None;
    }
    proof.map(|mut p| {
        p["hostPhaseSafe"] = serde_json::json!(true);
        p
    })
}
pub(super) fn verified(group: &Group, stage: &Stage) -> bool {
    let Some(a) = stage.attempts.last() else {
        return false;
    };
    let (Some(p), Some(n)) = (
        a.coverage_continuation.as_ref(),
        a.remote_lifecycle.as_ref(),
    ) else {
        return false;
    };
    !group.unified
        && stage.key == "l1"
        && a.state == "partial"
        && p["schema"] == "mobilee.coverage-continuation/v1"
        && p["hostPhaseSafe"] == true
        && p["relation"] == serde_json::to_value(&a.relation).unwrap()
        && p["sessionId"] == serde_json::json!(a.session_id)
        && p["token"] == n["token"]
        && p["sealed"] == true
        && matches!(
            p["coverage"].as_str(),
            Some("loss_only" | "incomplete_tail")
        )
        && p["acceptedEvents"].as_u64().is_some()
        && p["acceptedEvents"] == p["committedEvents"]
        && safe_closed_coverage(&p["drain"], &p["poll"])
        && n["stop_command_attempted"] == false
        && n["stop_request_recorded"] == false
        && n["startup"]["timing"]["launcher_status"] == "completed"
        && n.get("qualification_failure").is_none_or(Value::is_null)
        && remote_terminal_confirmed(n)
        && validate_remote_lifecycle(n, &a.relation).is_ok()
        && n["stop_reason"] == LOSS_REASON
        && super::super::qualified_dump_sources(Some(n), &group.package).is_ok()
        && group.budget.as_ref().is_some_and(|b| {
            b.reservations.iter().any(|r| {
                r.id == a.relation.attempt_id.to_string()
                    && r.kind == stage.key
                    && r.charged_bytes.is_some()
                    && r.status == "partial"
            })
        })
}
pub(super) async fn observe(
    group: &Group,
    relation: &Relation,
    result: &KernSightCaptureResult,
    lifecycle: &Value,
) -> Option<Value> {
    let session = result.session_id?;
    if group.unified || relation.stage_key != "l1" || lifecycle["stop_reason"] != LOSS_REASON {
        return None;
    }
    let paths = runtime_paths_from_group(Some(group)).ok()?;
    let root = runtime_paths::route(paths.as_ref(), &format!("{KSIGHT_SPOOL}/{session}")).ok()?;
    let mut documents = Vec::new();
    for name in ["session.json", "capture-relation.json"] {
        let response = run_device_root_script(
            &group.serial,
            &format!(
                "head -c 16385 {}",
                crate::shell_quote(&format!("{root}/{name}"))
            ),
        )
        .await
        .ok()?;
        if response.code != Some(0) || response.stdout.len() > 16384 {
            return None;
        }
        documents.push(serde_json::from_str::<Value>(&response.stdout).ok()?);
    }
    proof(
        group,
        relation,
        session,
        result,
        lifecycle,
        &documents[0],
        &documents[1],
    )
}

/// Explicit ENOENT for every exact original PID, twice; permission failures stay unknown.
pub(super) async fn sources_absent(serial: &str, sources: &Value) -> Result<bool, String> {
    let sources = sources
        .as_array()
        .filter(|s| !s.is_empty())
        .ok_or("原实例来源未知")?;
    let mut script = "test $(id -u) = 0 && test -r /proc/self/stat || exit 70; ".to_owned();
    for _ in 0..2 {
        for source in sources {
            let pid = source["pid"]
                .as_u64()
                .filter(|p| *p > 0 && *p <= u32::MAX as u64)
                .ok_or("原来源PID未知")?;
            script.push_str(&format!("if stat /proc/{pid} >/dev/null 2>&1; then echo present; exit 0; fi; e=$(LC_ALL=C stat /proc/{pid} 2>&1); case \"$e\" in *'/proc/{pid}'*'No such file or directory'*) ;; *) echo unknown; exit 71;; esac; "));
        }
    }
    script.push_str("echo absent");
    let result = run_device_root_script(serial, &script).await?;
    if result.code != Some(0) {
        return Err("原来源状态未知，未放行Dump或Linker".into());
    }
    match result.stdout.trim() {
        "absent" => Ok(true),
        "present" => Ok(false),
        _ => Err("原来源状态响应未知".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    fn fixture() -> (Group, Relation, KernSightCaptureResult, Value, Value, Value) {
        let mut g = super::super::tests::group();
        g.stages[2].launch_after_attach = false;
        g.budget = Some(
            session_budget::Contract::new(
                session_budget::Limits {
                    total_bytes: 67108864,
                    max_seconds: 60,
                },
                now_millis(),
            )
            .unwrap(),
        );
        let first = g.start("l0", epoch()).unwrap();
        g.finish(&first, Some(Uuid::new_v4()), None, None).unwrap();
        let r = g.start("l1", epoch()).unwrap();
        let session = Uuid::new_v4();
        let token = Uuid::new_v4();
        let relation = json!({"schema":"kernsight.capture-relation/v1","parent_id":r.parent_id,"stage_id":r.stage_id,"attempt_id":r.attempt_id,"attempt":r.attempt,"stage_key":"l1","stage_links":[]});
        let n = json!({"schema":"kernsight.capture-lifecycle/v1","relation":relation,"token":token,
            "collection_status":"partial","collection_returned":true,"agent_exited_confirmed":true,
            "cleanup":"producer_scope_returned","target_pause":"forbidden","stop_reason":LOSS_REASON,
            "stop_request_recorded":false,"stop_command_attempted":false,"stop_acknowledged":true,
            "startup":{"timing":{"launcher_status":"completed"}},
            "qualification":{"schema":"kernsight.qualified-source/v1","relation":relation,"token":token,"source":"MetadataObserver physical pidfd lease",
                "sources":[{"package":g.package,"pid":123,"birth_ns":9,"uid":10001,"exec_id":4,"boot_id":"fixture"}]}});
        let drain = json!({"schema":"kernsight.capture-drain/v1","producers_stopped":true,"queues_observed_empty":true,"unknown_tail":false,"rounds":2,"lost_samples":498319});
        let poll = json!({"schema":"kernsight.perf-poll-budget/v1","scope_failures":0,"perf_read_failures":0,"unread_tail_possible":false,"coverage_partial":true});
        let result = KernSightCaptureResult {
            session_id: Some(session),
            started_unix_ms: 1,
            finished_unix_ms: 2,
            command_preview: "offline synthetic positive; not old capture diagnostics".into(),
            stdout: String::new(),
            stderr: format!("{drain}\n{poll}\nError: capture coverage partial"),
            exit_code: Some(1),
            hide_debug: false,
        };
        let m = json!({"session_id":session,"state":"interrupted","event_count":9694,"writer":{"accepted_events":9694,"committed_events":9694,"pending_events":0,"unpersisted_events_at_exit":0,"terminal_finalized":true,"write_failures":0,"rejected_events":0,"terminal_flush_error":null,"terminal_manifest_error":null,"last_failure":null}});
        let source = json!({"session_id":session,"package":g.package,"relation":relation});
        (g, r, result, n, m, source)
    }
    fn copy_result(r: &KernSightCaptureResult) -> KernSightCaptureResult {
        KernSightCaptureResult {
            session_id: r.session_id,
            started_unix_ms: r.started_unix_ms,
            finished_unix_ms: r.finished_unix_ms,
            command_preview: r.command_preview.clone(),
            stdout: r.stdout.clone(),
            stderr: r.stderr.clone(),
            exit_code: r.exit_code,
            hide_debug: r.hide_debug,
        }
    }
    fn prepare() -> Group {
        let (mut g, r, result, n, m, source) = fixture();
        let p = proof(&g, &r, result.session_id.unwrap(), &result, &n, &m, &source).unwrap();
        g.budget
            .as_mut()
            .unwrap()
            .reserve(r.attempt_id.to_string(), "l1", now_millis())
            .unwrap();
        g.budget
            .as_mut()
            .unwrap()
            .settle(
                &r.attempt_id.to_string(),
                &json!({"admitted_write_bytes":1000,"partial":true}),
            )
            .unwrap();
        g.finish(
            &r,
            result.session_id,
            None,
            Some("remote_collection_partial".into()),
        )
        .unwrap();
        g.stages[1].attempts[0].remote_lifecycle = Some(n);
        g.stages[1].attempts[0].coverage_continuation = authorize_phase(Some(p), true);
        g
    }
    #[test]
    fn sealed_loss_only_can_snapshot_without_upgrading_coverage() {
        let mut g = prepare();
        assert!(g.continue_after_partial("l1"));
        let r = g.start("dump", epoch()).unwrap();
        g.finish(&r, None, Some("actual-owned-dump".into()), None)
            .unwrap();
        let r = g.start("linker", epoch()).unwrap();
        g.finish(&r, Some(Uuid::new_v4()), None, None).unwrap();
        assert_eq!(g.state, "partial");
        assert_eq!(g.stages[1].attempts[0].state, "partial");
    }
    #[test]
    fn only_explicit_absent_before_start_can_skip_dump_and_cold_start_linker() {
        let mut g = prepare();
        let r = g.start("dump", epoch()).unwrap();
        g.budget
            .as_mut()
            .unwrap()
            .reserve(r.attempt_id.to_string(), "dump", now_millis())
            .unwrap();
        g.budget
            .as_mut()
            .unwrap()
            .release_stage_granted_before_capture(&r.attempt_id.to_string())
            .unwrap();
        g.finish(&r, None, None, Some(ABSENT.into())).unwrap();
        let a = &mut g.stages[2].attempts[0];
        a.state = "unavailable".into();
        a.source_disposition = Some(ABSENT.into());
        g.refresh();
        assert!(g.continue_after_partial("dump"));
        assert!(g.start("linker", epoch()).is_ok());
        let mut bad = g.clone();
        bad.stages[2].attempts[0].source_disposition = None;
        assert!(bad.check_predecessors(3).is_err());
        assert_eq!(g.stages[1].attempts[0].state, "partial");
        assert_eq!(g.stages[2].attempts[0].state, "unavailable");
    }
    #[test]
    fn sealed_unread_tail_allows_independent_snapshot_but_preserves_partial() {
        let (g, r, mut result, n, m, source) = fixture();
        let mut rows: Vec<Value> = result
            .stderr
            .lines()
            .filter_map(|l| serde_json::from_str(l).ok())
            .collect();
        rows[0]["queues_observed_empty"] = json!(false);
        rows[0]["unknown_tail"] = json!(true);
        rows[1]["unread_tail_possible"] = json!(true);
        result.stderr = rows
            .iter()
            .map(Value::to_string)
            .collect::<Vec<_>>()
            .join("\n");
        let p = proof(&g, &r, result.session_id.unwrap(), &result, &n, &m, &source).unwrap();
        assert_eq!(p["coverage"], "incomplete_tail");
        assert_eq!(p["drain"]["unknown_tail"], true);
        rows[0]["producers_stopped"] = json!(false);
        result.stderr = rows
            .iter()
            .map(Value::to_string)
            .collect::<Vec<_>>()
            .join("\n");
        assert!(proof(&g, &r, result.session_id.unwrap(), &result, &n, &m, &source).is_none());
        rows[0]["producers_stopped"] = json!(true);
        rows[0].as_object_mut().unwrap().remove("unknown_tail");
        result.stderr = rows
            .iter()
            .map(Value::to_string)
            .collect::<Vec<_>>()
            .join("\n");
        assert!(proof(&g, &r, result.session_id.unwrap(), &result, &n, &m, &source).is_none());
    }
    #[test]
    fn missing_conflicting_or_unsafe_counter_and_identity_facts_fail_closed() {
        let (g, r, result, n, m, source) = fixture();
        let session = result.session_id.unwrap();
        for field in ["scope_failures", "perf_read_failures"] {
            let mut bad = copy_result(&result);
            let mut rows: Vec<Value> = bad
                .stderr
                .lines()
                .filter_map(|l| serde_json::from_str(l).ok())
                .collect();
            rows[1][field] = if field == "unread_tail_possible" {
                json!(true)
            } else {
                json!(1)
            };
            bad.stderr = rows
                .iter()
                .map(Value::to_string)
                .collect::<Vec<_>>()
                .join("\n");
            assert!(proof(&g, &r, session, &bad, &n, &m, &source).is_none());
        }
        let mut bad = copy_result(&result);
        bad.stderr.clear();
        assert!(proof(&g, &r, session, &bad, &n, &m, &source).is_none());
        let mut bad = copy_result(&result);
        bad.stderr = format!("{}\n{}", bad.stderr, bad.stderr);
        assert!(proof(&g, &r, session, &bad, &n, &m, &source).is_none());
        let mut bad = m.clone();
        bad["writer"]["committed_events"] = json!(9693);
        assert!(proof(&g, &r, session, &result, &n, &bad, &source).is_none());
        let mut bad = n.clone();
        bad["qualification"]["token"] = json!(Uuid::new_v4());
        assert!(proof(&g, &r, session, &result, &bad, &m, &source).is_none());
        for cause in [
            "parent_cancelled",
            "parent_deadline_exhausted",
            "output_budget_exhausted",
            "output_io_failed",
        ] {
            let mut bad = n.clone();
            bad["stop_reason"] = json!(cause);
            assert!(proof(&g, &r, session, &result, &bad, &m, &source).is_none());
        }
        let mut bad = g.clone();
        bad.unified = true;
        assert!(proof(&bad, &r, session, &result, &n, &m, &source).is_none());
        let mut bad = g.clone();
        bad.cancel_requested = true;
        assert!(proof(&bad, &r, session, &result, &n, &m, &source).is_none());
        assert!(authorize_phase(Some(serde_json::json!({})), false).is_none());
        let mut late = prepare();
        late.stages[1].attempts[0]
            .coverage_continuation
            .as_mut()
            .unwrap()["hostPhaseSafe"] = json!(false);
        assert!(!late.continue_after_partial("l1"));
        let mut missing_startup = n.clone();
        missing_startup["startup"] = Value::Null;
        assert!(proof(&g, &r, session, &result, &missing_startup, &m, &source).is_none());
        let mut bad = prepare();
        bad.stages[1].attempts[0].coverage_continuation = None;
        assert!(!bad.continue_after_partial("l1"));
        assert!(bad.start("dump", epoch()).is_err());
    }
}
