use super::*;
#[test]
#[ignore = "explicit single authorized provenance-pinned USB parent 300s/600s4GiB; preserves original sources"]
fn approved_usb_pinned_single_parent_4g() {
    // This monolithic debug acceptance future needs a bounded test-only stack.
    // Production UI invokes separate commands and does not use this runner.
    std::thread::Builder::new()
        .name("usb-pinned-explicit-acceptance".into())
        .stack_size(64 * 1024 * 1024)
        .spawn(|| {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(usb79_single_parent_body())
        })
        .unwrap()
        .join()
        .unwrap();
}
async fn usb79_single_parent_body() {
    let max_seconds =
        approved_usb_parent_seconds(std::env::var("ME_APPROVED_USB_79").as_deref()).unwrap();
    let out = PathBuf::from(std::env::var_os("ME_USB_79_OUTPUT").unwrap());
    assert!(out.is_absolute() && !out.exists());
    std::fs::create_dir_all(&out).unwrap();
    let serial = "35251JEGR12568".to_owned();
    let paths: runtime_paths::RuntimePaths = serde_json::from_str(
        &std::fs::read_to_string(std::env::var("ME_USB_79_RUNTIME").unwrap()).unwrap(),
    )
    .unwrap();
    paths.validate().unwrap();
    let provenance = validate_acceptance_provenance(&paths).unwrap();
    let offline =
        std::env::var("ME_USB_79_OFFLINE_LAYOUT").as_deref() == Ok("never-poll-device-future");
    if !offline {
        require_runtime_paths(&serial, Some(&paths)).await.unwrap();
        require_parent_lifecycle_capability(&serial, Some(&paths))
            .await
            .unwrap();
        require_code_scope_capability(&serial, Some(&paths))
            .await
            .unwrap();
        let identity = run_device_root_script(
            &serial,
            &paths
                .route("/data/local/tmp/ksight/ksightd code-capabilities")
                .unwrap(),
        )
        .await
        .unwrap();
        let note: serde_json::Value = serde_json::from_str(&identity.stdout).unwrap();
        assert_eq!(note["agent_git_commit"], provenance["agentCommit"]);
        assert_eq!(note["agent_build_version"], provenance["agentBuildVersion"]);
        assert_eq!(note["agent_git_dirty"], false);
        assert_eq!(note["agent_sha256"], paths.expected_sha256);
        assert_eq!(note["runtime_root"], paths.root);

        let lock = run_device_root_script(&serial, "dumpsys window policy")
            .await
            .unwrap();
        assert!(
            lock.stdout.contains("showing=false")
                && lock.stdout.contains("screenState=SCREEN_STATE_ON")
        );
    }
    let req:KernSightCaptureRequest=serde_json::from_value(serde_json::json!({"serial":serial,"package":"com.dlxx.mam.Internal","durationSeconds":15,"runtimePaths":paths,"sessionBudget":{"totalBytes":4294967296u64,"maxSeconds":max_seconds},"files":true,"network":true,"memory":true,"binder":true,"inspectMaxBytes":512,"inspectMaxHits":256})).unwrap();
    let groups = out.join("groups");
    std::fs::create_dir_all(&groups).unwrap();
    let mut manager_roots = vec![groups.clone()];
    for name in [
        "capture-group.json",
        "capture-group-after-import.json",
        "transfer-running-receipt.json",
        "transfer-final-receipt.json",
        "acceptance-blocker.txt",
        "manager-receipt.json",
        "pending-preservation.json",
        "acceptance-provenance.json",
    ] {
        manager_roots.push(out.join(name));
    }
    for key in ["l0", "l1", "dump", "linker"] {
        for suffix in ["-result.json", ".stdout.txt", ".stderr.txt"] {
            manager_roots.push(out.join(format!("{key}{suffix}")));
        }
    }
    let manager_guard = session_budget::Guard::install(
        manager_roots,
        2 * 1024 * 1024 - TERMINAL_RESERVED_BYTES,
        max_seconds * 1000,
    )
    .unwrap();
    let mut group =
        capture_groups::begin_group_at(groups.clone(), req, vec![15, 90, 15], true).unwrap();
    let deadline = group.budget.as_ref().unwrap().deadline().unwrap();
    let mut terminal = TerminalCleanup::new(&out, &groups, group.id);
    session_budget::write(
        out.join("acceptance-provenance.json"),
        serde_json::to_vec_pretty(&provenance).unwrap(),
    )
    .unwrap();
    let archive = out.join("received-evidence.mee");
    let (transfer, archive_cap, import_cap, ms) =
        capture_groups::reserve_export_at(&groups, &mut group, &archive)
            .unwrap()
            .unwrap();
    let checkpoint = out.join("raw-checkpoints");
    let staging = out.join("received");
    std::fs::create_dir_all(&checkpoint).unwrap();
    std::fs::create_dir_all(&staging).unwrap();
    let guard = session_budget::Guard::install(
        vec![checkpoint.clone(), staging.clone()],
        transfer - 65536,
        ms,
    )
    .unwrap();
    let mut seen = BTreeSet::new();
    let mut bundle_root = None;
    let work_future = async {
        for key in ["l0", "l1", "dump", "linker"] {
            println!("physical_stage_start={key} parent={} budget=4GiB", group.id);
            let value = stage_result_with_preservation(
                capture_groups::run_group_stage_at(groups.clone(), group.id, key.into()),
                async {
                    let pending = group.session_ids().difference(&seen).copied().collect();
                    preserve_usb_sources(&serial, &paths, &group, &pending, &checkpoint).await?;
                    Ok(())
                },
            )
            .await?;
            group = value.group.clone();
            group.validate()?;
            session_budget::write(
                out.join(format!("{key}-result.json")),
                serde_json::to_vec_pretty(&value).unwrap(),
            )
            .map_err(|e| e.to_string())?;
            session_budget::write(
                out.join("capture-group.json"),
                serde_json::to_vec_pretty(&group).unwrap(),
            )
            .map_err(|e| e.to_string())?;
            if let Some(r) = value.result.as_ref() {
                session_budget::write(out.join(format!("{key}.stdout.txt")), &r.stdout)
                    .map_err(|e| e.to_string())?;
                session_budget::write(out.join(format!("{key}.stderr.txt")), &r.stderr)
                    .map_err(|e| e.to_string())?;
            }
            println!(
                "physical_stage_finished={key} parent_state={} error={:?}",
                group.state, value.error
            );
            // Every genuine referenced session is preserved before the next producer starts.
            let next = group
                .stages
                .iter()
                .position(|s| s.key == key)
                .and_then(|i| group.stages.get(i + 1))
                .map(|s| s.key.as_str());
            let succeeded = value.error.is_none()
                && group
                    .stages
                    .iter()
                    .find(|stage| stage.key == key)
                    .and_then(|stage| stage.attempts.last())
                    .is_some_and(|attempt| attempt.state == "succeeded");
            let defer_checkpoint =
                defer_checkpoint_until_dependency(key, next, succeeded, group.cancel_requested);
            let pending: Vec<_> = group.session_ids().difference(&seen).copied().collect();
            session_budget::write(out.join("pending-preservation.json"),serde_json::to_vec_pretty(&serde_json::json!({"parentId":group.id,"sessions":pending,"status":if pending.is_empty(){"none"}else{"pending; not yet preserved"},"deadlineUnchanged":true,"failurePolicy":"if stage runner returns error while original deadline remains, attempt bounded preservation; expired/cancelled deadline leaves this pending record unconfirmed"})).unwrap()).map_err(|e|e.to_string())?;
            if !defer_checkpoint {
                let pending = group.session_ids().difference(&seen).copied().collect();
                seen.extend(
                    preserve_usb_sources(&serial, &paths, &group, &pending, &checkpoint).await?,
                );
            }
            if let Some(r) = value.result.as_ref() {
                for line in r
                    .stdout
                    .lines()
                    .filter(|l| l.contains("spool complete: directory="))
                {
                    let path = line
                        .split("directory=")
                        .nth(1)
                        .and_then(|x| x.split_whitespace().next())
                        .ok_or("invalid spool completion path")?;
                    let id = Uuid::parse_str(path.rsplit('/').next().unwrap_or(""))
                        .map_err(|e| e.to_string())?;
                    if !group.session_ids().contains(&id) {
                        return Err("producer reported unreferenced rollover spool; no next stage, raw stdout preserved for explicit intake".into());
                    }
                }
            }
            // Keep Dump -> Linker adjacent. Pull bulk Dump evidence only after
            // Linker returns, or when Dump itself blocks further producers.
            if key == "linker"
                || (key == "dump" && value.error.is_some() && !value.continue_after_partial)
            {
                let phase_ms =
                    capture_groups::begin_export_time_at(&groups, &mut group, "transfer")?;
                guard.constrain_time(phase_ms).map_err(|e| e.to_string())?;
                let spent = guard.receipt().admitted_write_bytes;
                let cap = planned_transfer_payload_limit(
                    transfer.saturating_sub(spent),
                    archive_cap,
                    import_cap,
                );
                println!(
                    "production_dump_pull_start parent={} payload_cap={cap}",
                    group.id
                );
                let b = pull_kernsight_package_evidence_with_plan(
                    serial.clone(),
                    group.package.clone(),
                    staging.to_string_lossy().into_owned(),
                    Some(capture_groups::export_root(&group)?),
                    Some(&paths),
                    BTreeMap::new(),
                    Some(cap),
                    false,
                )
                .await?;
                bundle_root = Some(PathBuf::from(&b.root));
                println!(
                    "production_dump_pull_finished parent={} root={}",
                    group.id, b.root
                );
            }
            session_budget::write(
                out.join("transfer-running-receipt.json"),
                serde_json::to_vec_pretty(&guard.receipt()).unwrap(),
            )
            .map_err(|e| e.to_string())?;
            if value.error.is_some() && !value.continue_after_partial {
                return Err(format!("stage {key} stopped: {:?}", value.error));
            }
        }
        let root = bundle_root.as_ref().ok_or("dump source was not received")?;
        append_device_sessions_to_package_evidence(&serial, &group.package, root, Some(&group))
            .await?;
        check_acceptance_time_phase(&group, "transfer")?;
        let limits = serde_json::json!({"schema":"mobilee.archive-output-limits/v1","archive_bytes":archive_cap,"import_bytes":import_cap,"max_ms":deadline.remaining_ms()?,"deadline_unix_ms":group.budget.as_ref().unwrap().deadline_unix_ms,"parent_id":group.id});
        session_budget::write(
            root.join("archive-output-limits.json"),
            serde_json::to_vec(&limits).unwrap(),
        )
        .map_err(|e| e.to_string())?;
        Ok(())
    };
    println!(
        "acceptance_composite_future_bytes={} offline_layout={offline}",
        std::mem::size_of_val(&work_future)
    );
    if offline {
        drop(work_future);
        println!("offline_composite_future_constructed_and_dropped_no_device_poll=true");
        return;
    }
    let work = deadline.run(work_future).await;
    let mut transfer_note = serde_json::to_value(guard.receipt()).unwrap();
    if work.is_err() {
        transfer_note["partial"] = serde_json::json!(true);
    }
    terminal.begin_phase();
    let mut cleanup_errors = vec![];
    record_cleanup(
        &mut cleanup_errors,
        terminal.write(
            "transfer-final-receipt.json",
            &serde_json::to_vec_pretty(&transfer_note).unwrap(),
        ),
    );
    record_cleanup(
        &mut cleanup_errors,
        terminal.settle(
            &groups,
            &mut group,
            &archive,
            "transfer",
            &transfer_note,
            work.is_err(),
        ),
    );
    drop(guard);
    if work.is_err() || !cleanup_errors.is_empty() {
        let reason = work
            .err()
            .unwrap_or_else(|| "transfer metadata settlement failed".into());
        terminal.finish(
            &group,
            &manager_guard.receipt(),
            Some(&reason),
            &mut cleanup_errors,
        );
        panic!("physical acceptance blocked; retained evidence; {reason}; cleanup errors={cleanup_errors:?}");
    }
    let root = bundle_root.unwrap();
    let mut final_import_guard = None;
    let final_work=deadline.run(async {
  let archive_ms=capture_groups::begin_export_time_at(&groups,&mut group,"archive")?;
  session_budget::write_json(root.join("archive-output-limits.json"),&serde_json::json!({"schema":"mobilee.archive-output-limits/v1","archive_bytes":archive_cap,"import_bytes":import_cap,"max_ms":archive_ms,"deadline_unix_ms":group.budget.as_ref().unwrap().deadline_unix_ms,"parent_id":group.id})).map_err(|e|e.to_string())?;
  let share_guard=session_budget::Guard::install(vec![root.clone()],archive_cap.saturating_sub(65536),archive_ms).map_err(|e|e.to_string())?;
  println!("production_archive_start parent={}",group.id);
  write_kernsight_evidence_archive(&root,&archive)?;
  archive_objects::share_fresh_pull(&root,&archive)?;
  session_budget::remaining_ms(&root,u64::MAX).map_err(|e|e.to_string())?;
  check_acceptance_time_phase(&group,"archive")?;
  drop(share_guard);
  let note:Value=serde_json::from_str(&std::fs::read_to_string(format!("{}.budget.json",archive.display())).map_err(|e|e.to_string())?).map_err(|e|e.to_string())?;
  let _archive_note=note; // Real archive receipt is settled in independent bounded metadata cleanup.
  let import_ms=capture_groups::begin_export_time_at(&groups,&mut group,"import")?;
  final_import_guard=Some(session_budget::Guard::install(vec![root.clone(),out.join("production-import-result.json")],import_cap.saturating_sub(65536),import_ms).map_err(|e|e.to_string())?);
  let bundle=import_kernsight_evidence_directory(root.to_string_lossy().into_owned()).await?;
  let report=bundle.session_report.as_ref().ok_or("actual parent report absent")?;if report["mobilee_capture_group"]["id"]!=group.id.to_string(){return Err("parent report mismatch".into());}
  let execution_complete=report["execution_complete"]==true;
  let mut children=vec![];for id in group.session_ids(){let child=capture_groups::get_local_kernsight_child_report(bundle.root.clone(),group.id,id)?;children.push(serde_json::json!({"sessionId":id,"totalEvents":child.report["total_events"],"sourceStatus":child.report["mobilee_child_source_status"]}));}
  let verified_runtime=verified_runtime_preview_path(&root)?;
  let code=bundle.files.iter().find(|f|f.relative_path.starts_with("readable-dex/")).or_else(||bundle.files.iter().find(|f|f.relative_path.starts_with("code-objects/"))).or_else(||bundle.files.iter().find(|f|Some(f.relative_path.as_str())==verified_runtime.as_deref()));
  let preview=if let Some(f)=code{Some(read_local_kernsight_evidence_file(bundle.root.clone(),group.package.clone(),f.relative_path.clone(),512).await?)}else{None};
  let code_preview_present=preview.is_some();
  let child_events_present=children.len()==3 && children.iter().all(|c|c["totalEvents"].as_u64().unwrap_or(0)>0);
  session_budget::write_json(out.join("production-import-result.json"),&serde_json::json!({"bundle":bundle,"children":children,"codePreview":preview,"parentCaptureState":group.state,"rawSessionsPreserved":seen,"archiveBytes":std::fs::metadata(&archive).map_err(|e|e.to_string())?.len(),"newParentBudgetBytes":4294967296u64,"captureMaxSeconds":max_seconds,"oldParentUnchanged":true,"ackSent":false,"sourceDeleted":false})).map_err(|e|e.to_string())?;
  deadline.check()?;
  session_budget::remaining_ms(&root,u64::MAX).map_err(|e|e.to_string())?;
  check_acceptance_time_phase(&group,"import")?;
  println!("production_import_finished parent={} children={}",group.id,children.len());
  if group.state!="succeeded"||!execution_complete||!code_preview_present||!child_events_present{return Err(format!("full acceptance not passed: parent={}, execution_complete={execution_complete}, code_preview={code_preview_present}, three_real_child_events={child_events_present}; retained partial preserved",group.state));}
  Ok(())
 }).await;
    terminal.begin_phase();
    let mut cleanup_errors = vec![];
    let archive_receipt = PathBuf::from(format!("{}.budget.json", archive.display()));
    if archive_receipt.is_file() {
        let result = (|| {
            let mut note: Value =
                serde_json::from_str(&read_bounded_text(&archive_receipt, 65536)?)
                    .map_err(|e| e.to_string())?;
            if final_work.is_err() {
                note["partial"] = serde_json::json!(true);
            }
            terminal.settle(
                &groups,
                &mut group,
                &archive,
                "archive",
                &note,
                final_import_guard.is_none(),
            )
        })();
        record_cleanup(&mut cleanup_errors, result);
    }
    if final_import_guard.is_none() {
        // Import has not entered its guard. Unknown archive usage remains unknown.
        record_cleanup(
            &mut cleanup_errors,
            terminal.settle(
                &groups,
                &mut group,
                &archive,
                "not_started",
                &Value::Null,
                true,
            ),
        );
    }
    if let Some(import_guard) = final_import_guard.as_ref() {
        let mut note = serde_json::to_value(import_guard.receipt()).unwrap();
        if final_work.is_err() {
            note["partial"] = serde_json::json!(true);
        }
        record_cleanup(
            &mut cleanup_errors,
            terminal.settle(&groups, &mut group, &archive, "import", &note, false),
        );
    }
    let reason = final_work.err().or_else(|| {
        (!cleanup_errors.is_empty()).then(|| "final metadata settlement failed".into())
    });
    terminal.finish(
        &group,
        &manager_guard.receipt(),
        reason.as_deref(),
        &mut cleanup_errors,
    );
    if reason.is_some() || !cleanup_errors.is_empty() {
        panic!("physical acceptance blocked; evidence retained; reason={reason:?}; cleanup errors={cleanup_errors:?}");
    }
    println!(
        "physical_acceptance_finished parent={} state={}",
        group.id, group.state
    );
}
#[test]
fn offline_usb79_future_layout_no_device() {
    let d = session_deadline::Deadline::new(Duration::from_secs(1));
    let stage = run_group_stage_at(
        PathBuf::from("/tmp/never-polled-usb79"),
        Uuid::nil(),
        "l0".into(),
    );
    println!(
        "production_stage_future_bytes={}",
        std::mem::size_of_val(&stage)
    );
    let wrapped = d.run(stage);
    println!(
        "deadline_wrapped_stage_future_bytes={}",
        std::mem::size_of_val(&wrapped)
    );
    drop(wrapped);
    for bytes in [2147483648u64, 4294967296u64] {
        let limits = session_budget::Limits {
            total_bytes: bytes,
            max_seconds: 300,
        };
        let contract = session_budget::Contract::new_planned(limits, now_millis(), true).unwrap();
        println!(
            "budget={bytes} contract_stack_bytes={} reservations={} no_payload_allocation=true",
            std::mem::size_of_val(&contract),
            contract.reservations.len()
        );
    }
    println!(
        "offline_precheck_complete no_device_commands=true no_parent_registered_for_capture=true"
    );
}

/// Bulk preservation may follow a dependent snapshot, but must precede another
/// spool producer. Failed/cancelled stages preserve immediately and do not advance.
fn defer_checkpoint_until_dependency(
    key: &str,
    next: Option<&str>,
    succeeded: bool,
    cancelled: bool,
) -> bool {
    key == "l1" && next == Some("dump") && succeeded && !cancelled
}
#[test]
fn offline_checkpoint_dependency_order_and_fail_closed_counterexamples() {
    assert!(defer_checkpoint_until_dependency(
        "l1",
        Some("dump"),
        true,
        false
    ));
    for (key, next, ok, cancel) in [
        ("l0", Some("l1"), true, false),
        ("dump", Some("linker"), true, false),
        ("l1", Some("linker"), true, false),
        ("l1", None, true, false),
        ("l1", Some("dump"), false, false),
        ("l1", Some("dump"), true, true),
    ] {
        assert!(!defer_checkpoint_until_dependency(key, next, ok, cancel));
    }
    // The producer's original identity remains the only candidate. A later PID is
    // neither installed into the request nor permitted by the existing handoff gate.
    let mut note = serde_json::json!({"relation":{"attempt_id":"old"},"token":"original","qualification":{"schema":"kernsight.qualified-source/v1","relation":{"attempt_id":"old"},"token":"original","source":"MetadataObserver physical pidfd lease","sources":[{"package":"p","pid":17114,"uid":10285,"birth_ns":9,"exec_id":4,"boot_id":"boot"}]}});
    assert_eq!(
        qualified_dump_sources(Some(&note), "p").unwrap()[0]["pid"],
        17114
    );
    note["qualification"]["token"] = serde_json::json!("new-physical-source");
    assert!(qualified_dump_sources(Some(&note), "p").is_err());
}

async fn preserve_usb_sources(
    serial: &str,
    paths: &runtime_paths::RuntimePaths,
    group: &capture_groups::Group,
    pending: &BTreeSet<Uuid>,
    checkpoint: &Path,
) -> Result<BTreeSet<Uuid>, String> {
    let mut saved = BTreeSet::new();
    for id in pending.iter().copied() {
        let remote = format!("{}/spool/{id}", paths.root);
        let relation = run_device_root_script(
            &serial,
            &format!(
                "head -c 32769 {}",
                crate::shell_quote(&format!("{remote}/capture-relation.json"))
            ),
        )
        .await?;
        if relation.code != Some(0) || relation.stdout.len() > 32768 {
            return Err("checkpoint original relation missing/bounded input exceeded".into());
        }
        let n: Value = serde_json::from_str(&relation.stdout).map_err(|e| e.to_string())?;
        capture_groups::verify_session_relation(&group, id, &n)?;
        let manifest = run_device_root_script(
            &serial,
            &format!(
                "head -c 1048577 {}",
                crate::shell_quote(&format!("{remote}/session.json"))
            ),
        )
        .await?;
        if manifest.code != Some(0) || manifest.stdout.len() > 1048576 {
            return Err("checkpoint sealed session manifest missing/too large".into());
        }
        let m: Value = serde_json::from_str(&manifest.stdout).map_err(|e| e.to_string())?;
        if m["session_id"] != id.to_string()
            || !matches!(
                m["state"].as_str(),
                Some("completed" | "interrupted" | "rotated" | "storage_limited")
            )
        {
            return Err("checkpoint session not sealed".into());
        }
        let inventory = run_device_root_script(
            &serial,
            &format!(
                "cd {} && find . -maxdepth 1 -type f -exec sha256sum '{{}}' ';'",
                crate::shell_quote(&remote)
            ),
        )
        .await?;
        if inventory.code != Some(0)
            || inventory.stdout.is_empty()
            || inventory.stdout.len() > 1048576
        {
            return Err("checkpoint source hashes unavailable".into());
        }
        let local = checkpoint.join(id.to_string());
        std::fs::create_dir_all(&local).map_err(|e| e.to_string())?;
        session_budget::write(local.join("capture-relation.json"), relation.stdout)
            .map_err(|e| e.to_string())?;
        session_budget::write(local.join("session.json"), manifest.stdout)
            .map_err(|e| e.to_string())?;
        session_budget::write(local.join("source-sha256.txt"), inventory.stdout)
            .map_err(|e| e.to_string())?;
        let dst = local.join("original-spool.tar");
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&dst)
            .map_err(|e| e.to_string())?;
        let script = format!("cd {} && tar -cf - .", crate::shell_quote(&remote));
        let mut child = tokio::process::Command::new("/opt/homebrew/bin/adb")
            .args([
                "-s",
                &serial,
                "exec-out",
                &format!("su -c {}", crate::shell_quote(&script)),
            ])
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .map_err(|e| e.to_string())?;
        let mut stdout = child.stdout.take().unwrap();
        let mut buf = [0u8; 65536];
        let mut count = 0u64;
        let mut h = Sha256::new();
        loop {
            let n = stdout.read(&mut buf).await.map_err(|e| e.to_string())?;
            if n == 0 {
                break;
            }
            count += n as u64;
            if count > 128 * 1024 * 1024 {
                return Err(
                    "checkpoint raw spool exceeded finite 128MiB cap; prefix retained".into(),
                );
            }
            session_budget::charge(&dst, n as u64).map_err(|e| e.to_string())?;
            use std::io::Write;
            f.write_all(&buf[..n]).map_err(|e| e.to_string())?;
            h.update(&buf[..n]);
        }
        if !child.wait().await.map_err(|e| e.to_string())?.success() {
            return Err("checkpoint raw spool command failed".into());
        }
        f.sync_all().map_err(|e| e.to_string())?;
        session_budget::write_json(local.join("receipt.json"),&serde_json::json!({"sessionId":id,"source":remote,"tarBytes":count,"tarSha256":format!("{:x}",h.finalize()),"ackSent":false,"sourceDeleted":false})).map_err(|e|e.to_string())?;
        let validation = r#"import sys,tarfile,hashlib,pathlib,json
r=pathlib.Path(sys.argv[1]); expected={}
for line in (r/'source-sha256.txt').read_text().splitlines():
 h,n=line.split(None,1); n=n.strip(); n=n[2:] if n.startswith('./') else n; expected[n]=h
actual={}
with tarfile.open(r/'original-spool.tar') as t:
 for m in t:
  if m.isdir():continue
  n=m.name[2:] if m.name.startswith('./') else m.name
  assert m.isfile() and '/' not in n and n not in actual and n in expected
  h=hashlib.sha256(); f=t.extractfile(m)
  for b in iter(lambda:f.read(65536),b''):h.update(b)
  actual[n]=h.hexdigest()
assert actual==expected,(len(actual),len(expected))
m=json.loads((r/'session.json').read_text()); assert len([n for n in actual if n.startswith('batch-')])==m['batch_count']
print('raw_spool_full_hash_and_manifest_verified',len(actual))
"#;
        let v = tokio::process::Command::new("python3")
            .arg("-c")
            .arg(validation)
            .arg(&local)
            .kill_on_drop(true)
            .output()
            .await
            .map_err(|e| e.to_string())?;
        session_budget::write(local.join("verification.txt"), &v.stdout)
            .map_err(|e| e.to_string())?;
        if !v.status.success() {
            return Err(format!(
                "raw spool hash verification failed: {}",
                String::from_utf8_lossy(&v.stderr)
            ));
        }
        saved.insert(id);
        println!("physical_checkpoint_saved session={id} raw_bytes={count}");
    }

    Ok(saved)
}
async fn stage_result_with_preservation<T>(
    run: impl std::future::Future<Output = Result<T, String>>,
    preserve: impl std::future::Future<Output = Result<(), String>>,
) -> Result<T, String> {
    match run.await {
        Ok(value) => Ok(value),
        Err(error) => {
            let preserved = preserve.await;
            Err(format!(
                "{error}; deferred checkpoint: {}",
                match preserved {
                    Ok(()) => "preserved with original limits".into(),
                    Err(e) => format!("unconfirmed: {e}"),
                }
            ))
        }
    }
}

#[tokio::test]
async fn offline_deferred_checkpoint_runs_on_stage_error_without_restarting_stage() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let stages = AtomicUsize::new(0);
    let copies = AtomicUsize::new(0);
    let e = stage_result_with_preservation(
        async {
            stages.fetch_add(1, Ordering::SeqCst);
            Err::<(), _>("original pidfd ESRCH".into())
        },
        async {
            copies.fetch_add(1, Ordering::SeqCst);
            Ok(())
        },
    )
    .await
    .unwrap_err();
    assert_eq!(stages.load(Ordering::SeqCst), 1);
    assert_eq!(copies.load(Ordering::SeqCst), 1);
    assert!(e.contains("ESRCH") && e.contains("preserved with original limits"));
    let e = stage_result_with_preservation(
        async { Err::<(), _>("original stage validation refusal".into()) },
        async { Err("original deadline exhausted; pending preservation unconfirmed".into()) },
    )
    .await
    .unwrap_err();
    assert!(e.contains("validation refusal") && e.contains("unconfirmed"));
    let cancelled = session_deadline::Deadline::new(Duration::from_secs(1));
    cancelled.cancel();
    let result = cancelled
        .run(stage_result_with_preservation(
            async { Err::<(), _>("cancelled".into()) },
            async { panic!("expired scope must not create a new preservation deadline") },
        ))
        .await;
    assert!(result.unwrap_err().contains("parent_cancelled"));
}

// Pure preparation: does not instantiate a capture group or poll any device future.
#[test]
#[ignore = "explicit local artifact/path preflight; no device or parent construction"]
fn approved_usb_pinned_preflight_no_parent() {
    let paths: runtime_paths::RuntimePaths = serde_json::from_str(
        &std::fs::read_to_string(std::env::var("ME_USB_79_RUNTIME").unwrap()).unwrap(),
    )
    .unwrap();
    paths.validate().unwrap();
    let _provenance = validate_acceptance_provenance(&paths).unwrap();
    assert_eq!(paths.agent_path, format!("{}/ksightd", paths.root));
    let routed = paths.route("/data/local/tmp/ksight/ksightd capture --object /data/local/tmp/ksight/code_metadata_v1.bpf.o --spool-dir /data/local/tmp/ksight/spool").unwrap();
    assert!(!routed.contains("/data/local/tmp/ksight/"));
    assert!(routed.contains(&format!(
        "--expected-agent-sha256 {}",
        paths.expected_sha256
    )));
    assert!(routed.contains(&format!("--spool-dir {}/spool", paths.root)));
    println!("local_pinned_preflight_passed=true device_calls=0 parent_created=false physical_stage_started=false");
}

// A preview of retained qualified bytes is not complete DEX/code coverage.
fn verified_runtime_preview_path(root: &Path) -> Result<Option<String>, String> {
    use sha2::Digest as _;
    use std::io::Read as _;
    let runtime = root.join("runtime");
    if !runtime.is_dir() {
        return Ok(None);
    }
    let mut count = 0;
    for entry in std::fs::read_dir(runtime).map_err(|e| e.to_string())? {
        session_deadline::check()?;
        let entry = entry.map_err(|e| e.to_string())?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if !name.starts_with("bound-source-") || !name.ends_with(".json") {
            continue;
        }
        count += 1;
        if count > 16 {
            return Err("runtime preview note count limit".into());
        }
        let mut body = Vec::new();
        std::fs::File::open(entry.path())
            .map_err(|e| e.to_string())?
            .take(256 * 1024 + 1)
            .read_to_end(&mut body)
            .map_err(|e| e.to_string())?;
        if body.len() > 256 * 1024 {
            return Err("runtime preview note size limit".into());
        }
        let note: Value = serde_json::from_slice(&body).map_err(|e| e.to_string())?;
        if note["schema"] != "kernsight.bound-code-copy/v1" {
            continue;
        }
        for row in note["records"].as_array().into_iter().flatten() {
            let read = &row["read"];
            if row["admitted"] != true
                || read["admission"] != "qualified_live_copy"
                || read["read_status"] != "complete"
                || read["write_status"] != "complete"
            {
                continue;
            }
            let Some(bytes) = read["actual_length"]
                .as_u64()
                .filter(|n| (1..=65536).contains(n))
            else {
                continue;
            };
            let Some(name) = row["raw_evidence"]
                .as_str()
                .filter(|n| n.ends_with(".code") && !n.contains('/') && *n != "..")
            else {
                continue;
            };
            let path = root.join("runtime").join(name);
            if !path.is_file()
                || path.is_symlink()
                || path.metadata().map_err(|e| e.to_string())?.len() != bytes
            {
                continue;
            }
            let mut data = Vec::new();
            std::fs::File::open(&path)
                .map_err(|e| e.to_string())?
                .take(65537)
                .read_to_end(&mut data)
                .map_err(|e| e.to_string())?;
            if data.len() as u64 == bytes
                && read["sha256"].as_str()
                    == Some(format!("{:x}", sha2::Sha256::digest(&data)).as_str())
            {
                return Ok(Some(format!("runtime/{name}")));
            }
        }
    }
    Ok(None)
}

// Test-only host cleanup. No device, payload root, archive or parent clock capability.
const TERMINAL_RESERVED_BYTES: u64 = 256 * 1024;
struct TerminalCleanup {
    out: PathBuf,
    group_path: PathBuf,
    temp_path: PathBuf,
    charged: u64,
    deadline: std::time::Instant,
}
impl TerminalCleanup {
    fn new(out: &Path, groups: &Path, id: Uuid) -> Self {
        let out = out.canonicalize().expect("existing terminal output root");
        let groups = groups.canonicalize().expect("existing terminal group root");
        Self {
            out,
            group_path: groups.join(format!("{id}.json")),
            temp_path: groups.join(format!(".{id}.terminal.tmp")),
            charged: 0,
            deadline: std::time::Instant::now() + Duration::from_secs(5),
        }
    }
    fn finish(
        &mut self,
        group: &Group,
        manager: &session_budget::Receipt,
        reason: Option<&str>,
        errors: &mut Vec<String>,
    ) {
        record_cleanup(
            errors,
            self.write(
                "capture-group-after-import.json",
                &serde_json::to_vec_pretty(group).unwrap(),
            ),
        );
        if reason.is_some() || !errors.is_empty() {
            let text = format!(
                "{}; terminal cleanup errors={errors:?}",
                &reason
                    .unwrap_or("terminal metadata unconfirmed")
                    .chars()
                    .take(4096)
                    .collect::<String>()
            );
            record_cleanup(
                errors,
                self.write("acceptance-blocker.txt", text.as_bytes()),
            );
        }
        let receipt = serde_json::json!({"payloadMetadata":manager,"terminalReservedBytes":TERMINAL_RESERVED_BYTES,"terminalChargedBeforeReceipt":self.charged,"cleanupErrors":errors,"cleanupScope":"independent host metadata only; 5s per phase; original parent clock unchanged","missingReceiptMeans":"unknown, never zero"});
        record_cleanup(
            errors,
            self.write(
                "manager-receipt.json",
                &serde_json::to_vec_pretty(&receipt).unwrap(),
            ),
        );
    }
    fn begin_phase(&mut self) {
        self.deadline = std::time::Instant::now() + Duration::from_secs(5);
    }
    fn write(&mut self, name: &str, bytes: &[u8]) -> Result<(), String> {
        if !matches!(
            name,
            "transfer-final-receipt.json"
                | "acceptance-blocker.txt"
                | "capture-group-after-import.json"
                | "manager-receipt.json"
        ) {
            return Err("terminal cleanup path not allowed".into());
        }
        self.write_exact(&self.out.join(name), bytes)
    }
    fn write_exact(&mut self, path: &Path, bytes: &[u8]) -> Result<(), String> {
        if std::time::Instant::now() >= self.deadline {
            return Err("terminal cleanup deadline exhausted".into());
        }
        let diagnostic = path == self.out.join("manager-receipt.json")
            || path == self.out.join("acceptance-blocker.txt");
        let cap = if diagnostic {
            TERMINAL_RESERVED_BYTES
        } else {
            TERMINAL_RESERVED_BYTES - 16384
        };
        if bytes.len() as u64 > cap.saturating_sub(self.charged) {
            return Err("terminal cleanup reserved bytes exhausted".into());
        }
        if path
            .ancestors()
            .any(|p| std::fs::symlink_metadata(p).is_ok_and(|m| m.file_type().is_symlink()))
        {
            return Err("terminal cleanup symlink refused".into());
        }
        self.charged += bytes.len() as u64;
        let mut options = std::fs::OpenOptions::new();
        options.write(true);
        if path == self.temp_path {
            options.create_new(true);
        } else {
            options.create(true).truncate(true);
        }
        let mut file = options.open(path).map_err(|e| e.to_string())?;
        file.write_all(bytes).map_err(|e| e.to_string())?;
        file.sync_all().map_err(|e| e.to_string())?;
        if std::time::Instant::now() >= self.deadline {
            return Err(
                "terminal cleanup completed IO beyond cleanup deadline; not confirmed".into(),
            );
        }
        Ok(())
    }
    fn settle(
        &mut self,
        groups: &Path,
        group: &mut Group,
        output: &Path,
        kind: &str,
        note: &Value,
        release_following: bool,
    ) -> Result<(), String> {
        let _lock = IO_LOCK.lock().map_err(|e| e.to_string())?;
        let body = read_bounded_text(&self.group_path, 1024 * 1024)?;
        let mut retained: Group = serde_json::from_str(&body).map_err(|e| e.to_string())?;
        if retained.id != group.id
            || path(&groups.canonicalize().map_err(|e| e.to_string())?, group.id) != self.group_path
        {
            return Err("terminal parent mismatch".into());
        }
        let token = retained.budget.as_ref().and_then(|b| b.deadline_token);
        if let Some(b) = retained.budget.as_mut() {
            if kind != "not_started" {
                b.settle(&format!("export:{}:{kind}", output.display()), note)?;
            }
            if release_following {
                for next in ["archive", "import"] {
                    if next != kind && (kind != "not_started" || next == "import") {
                        b.release_unstarted(&format!("export:{}:{next}", output.display()))?;
                    }
                }
            }
        }
        retained.refresh();
        retained.validate()?;
        assert_eq!(
            retained.budget.as_ref().and_then(|b| b.deadline_token),
            token
        );
        let encoded = serde_json::to_vec_pretty(&retained).map_err(|e| e.to_string())?;
        self.write_exact(&self.temp_path.clone(), &encoded)?;
        std::fs::rename(&self.temp_path, &self.group_path).map_err(|e| e.to_string())?;
        File::open(groups)
            .and_then(|f| f.sync_all())
            .map_err(|e| e.to_string())?;
        *group = retained;
        Ok(())
    }
}
fn validate_acceptance_provenance(paths: &runtime_paths::RuntimePaths) -> Result<Value, String> {
    let p = std::env::var("ME_USB_ACCEPTANCE_PROVENANCE")
        .map_err(|_| "missing explicit acceptance provenance")?;
    let note: Value = serde_json::from_str(&read_bounded_text(Path::new(&p), 65536)?)
        .map_err(|e| e.to_string())?;
    if note["meBaseCommit"] != "6501a89aa09d1916b0117da28ffbe365705dcc54"
        || note["kernBaseCommit"] != "c6545f1db538e1e749b32110ead2760bd96c4678"
        || note["agentGitDirty"] != false
    {
        return Err("acceptance base provenance mismatch/dirty".into());
    }
    for field in ["agentCommit", "agentSha256", "testBinarySha256"] {
        let n = note[field].as_str().ok_or("missing final provenance pin")?;
        let len = if field == "agentCommit" { 40 } else { 64 };
        if n.len() != len
            || !n.bytes().all(|c| c.is_ascii_hexdigit())
            || n.bytes().all(|c| c == b'0')
        {
            return Err("invalid final provenance pin".into());
        }
    }
    if note["agentBuildVersion"]
        .as_str()
        .is_none_or(|s| s.is_empty())
        || note["agentSha256"] != paths.expected_sha256
    {
        return Err("agent artifact provenance mismatch".into());
    }
    let report_path = note["buildReportPath"]
        .as_str()
        .ok_or("missing build report")?;
    let report: Value = serde_json::from_str(&read_bounded_text(Path::new(report_path), 1048576)?)
        .map_err(|e| e.to_string())?;
    if report["base_fix_commit"] != note["kernBaseCommit"]
        || report["source_commit"] != note["agentCommit"]
        || report["git_dirty"] != false
        || report["build_version"] != note["agentBuildVersion"]
        || report["assets"]["ksightd"]["sha256"] != note["agentSha256"]
    {
        return Err("build report provenance mismatch".into());
    }
    let agent = Path::new(
        note["agentPath"]
            .as_str()
            .ok_or("missing actual agent path")?,
    );
    if sha256_file_bounded(agent)? != note["agentSha256"] {
        return Err("actual local agent SHA mismatch".into());
    }
    let binary = std::env::current_exe().map_err(|e| e.to_string())?;
    let actual = sha256_file_bounded(&binary)?;
    if note["testBinarySha256"] != actual {
        return Err("test binary provenance mismatch".into());
    }
    Ok(note)
}
fn sha256_file_bounded(path: &Path) -> Result<String, String> {
    use std::io::Read;
    let mut f = File::open(path).map_err(|e| e.to_string())?;
    let mut h = Sha256::new();
    let mut buf = [0; 65536];
    let mut total = 0u64;
    loop {
        let n = f.read(&mut buf).map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        }
        total += n as u64;
        if total > 2 * 1024 * 1024 * 1024 {
            return Err("provenance artifact exceeds 2GiB".into());
        }
        h.update(&buf[..n]);
    }
    Ok(format!("{:x}", h.finalize()))
}
#[test]
fn offline_terminal_metadata_survives_expired_parent_without_payload_restart() {
    let root = std::env::temp_dir().join(format!("me-terminal-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&root).unwrap();
    let mut group = tests::group();
    group.budget = Some(
        session_budget::Contract::new(
            session_budget::Limits {
                total_bytes: 67108864,
                max_seconds: 60,
            },
            now_millis(),
        )
        .unwrap(),
    );
    save(&root, &group).unwrap();
    let output = root.join("fixture.mee");
    reserve_export_at(&root, &mut group, &output).unwrap();
    let token = group.budget.as_ref().unwrap().deadline_token;
    let parent = group.budget.as_ref().unwrap().deadline().unwrap();
    parent.cancel();
    let old = session_budget::Guard::install(vec![root.clone()], 1, 1).unwrap();
    std::thread::sleep(Duration::from_millis(2));
    assert!(session_budget::write(
        root.join("transfer-final-receipt.json"),
        b"old guard must reject"
    )
    .is_err());
    let mut cleanup = TerminalCleanup::new(&root, &root, group.id);
    cleanup
        .write("transfer-final-receipt.json", b"retained")
        .unwrap();
    cleanup
        .settle(
            &root,
            &mut group,
            &output,
            "transfer",
            &serde_json::json!({"admitted_write_bytes":99,"partial":true}),
            true,
        )
        .unwrap();
    assert_eq!(group.budget.as_ref().unwrap().deadline_token, token);
    assert!(parent.check().is_err());
    assert_eq!(old.receipt().admitted_write_bytes, 0);
    assert!(cleanup.write("payload.code", b"denied").is_err());
    assert!(!root.join("payload.code").exists());
    cleanup.charged = TERMINAL_RESERVED_BYTES;
    assert!(cleanup.write("acceptance-blocker.txt", b"x").is_err());
    cleanup.charged = 0;
    cleanup.deadline = std::time::Instant::now();
    assert!(cleanup.write("acceptance-blocker.txt", b"x").is_err());
    drop(old);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn offline_terminal_archive_import_receipts_and_symlink_fail_closed() {
    let root = std::env::temp_dir().join(format!("me-terminal-receipts-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&root).unwrap();
    let mut group = tests::group();
    group.budget = Some(
        session_budget::Contract::new(
            session_budget::Limits {
                total_bytes: 67108864,
                max_seconds: 60,
            },
            now_millis(),
        )
        .unwrap(),
    );
    save(&root, &group).unwrap();
    let output = root.join("fixture.mee");
    reserve_export_at(&root, &mut group, &output).unwrap();
    let token = group.budget.as_ref().unwrap().deadline_token;
    group.budget.as_ref().unwrap().deadline().unwrap().cancel();
    let mut cleanup = TerminalCleanup::new(&root, &root, group.id);
    cleanup
        .settle(
            &root,
            &mut group,
            &output,
            "archive",
            &serde_json::json!({"admitted_write_bytes":113497,"partial":true}),
            false,
        )
        .unwrap();
    cleanup
        .settle(
            &root,
            &mut group,
            &output,
            "import",
            &serde_json::json!({"admitted_write_bytes":250,"partial":true}),
            false,
        )
        .unwrap();
    let b = group.budget.as_ref().unwrap();
    assert_eq!(b.deadline_token, token);
    assert!(b.deadline().unwrap().check().is_err());
    for (kind, actual) in [("archive", 113497), ("import", 250)] {
        let q = b.reservations.iter().find(|q| q.kind == kind).unwrap();
        assert_eq!(q.charged_bytes, Some(actual + 65536));
        assert_eq!(q.status, "partial");
    }
    let payload = root.join("original.code");
    std::fs::write(&payload, b"original").unwrap();
    std::os::unix::fs::symlink(&payload, root.join("acceptance-blocker.txt")).unwrap();
    assert!(cleanup.write("acceptance-blocker.txt", b"refused").is_err());
    assert_eq!(std::fs::read(&payload).unwrap(), b"original");
    std::fs::remove_dir_all(root).unwrap();
}

fn record_cleanup(errors: &mut Vec<String>, result: Result<(), String>) {
    if let Err(e) = result {
        eprintln!("terminal_cleanup_unconfirmed={e}");
        errors.push(e.chars().take(1024).collect());
    }
}

#[test]
fn offline_terminal_finalizer_retains_blocker_and_manager_after_snapshot_error() {
    let root = std::env::temp_dir().join(format!("me-terminal-finalizer-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&root).unwrap();
    let group = tests::group();
    let mut cleanup = TerminalCleanup::new(&root, &root, group.id);
    // Force the first finalizer write to fail, then verify independent diagnostics.
    std::fs::create_dir(root.join("capture-group-after-import.json")).unwrap();
    let mut errors = vec![];
    let guard = session_budget::Guard::install(vec![root.join("unrelated")], 1, 1000).unwrap();
    cleanup.finish(
        &group,
        &guard.receipt(),
        Some("original parent deadline exhausted"),
        &mut errors,
    );
    assert!(!errors.is_empty());
    assert!(root.join("acceptance-blocker.txt").is_file());
    assert!(root.join("manager-receipt.json").is_file());
    let note: Value =
        serde_json::from_str(&std::fs::read_to_string(root.join("manager-receipt.json")).unwrap())
            .unwrap();
    assert!(!note["cleanupErrors"].as_array().unwrap().is_empty());
    assert!(cleanup.charged <= TERMINAL_RESERVED_BYTES);
    drop(guard);
    std::fs::remove_dir_all(root).unwrap();
}

fn approved_usb_parent_seconds(value: Result<&str, &std::env::VarError>) -> Result<u64, String> {
    match value {
        Ok("single-parent-300s4GiB") => Ok(300),
        Ok("single-parent-600s4GiB") => Ok(600),
        _ => Err("missing exact authorized USB parent duration".into()),
    }
}
fn check_acceptance_time_phase(group: &capture_groups::Group, phase: &str) -> Result<(), String> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .as_millis() as u64;
    group
        .budget
        .as_ref()
        .ok_or("parent budget missing")?
        .check_time_phase(phase, now)
}
#[test]
fn offline_authorized_usb_duration_gate_is_exact() {
    assert_eq!(
        approved_usb_parent_seconds(Ok("single-parent-300s4GiB")).unwrap(),
        300
    );
    assert_eq!(
        approved_usb_parent_seconds(Ok("single-parent-600s4GiB")).unwrap(),
        600
    );
    assert!(approved_usb_parent_seconds(Ok("single-parent-601s4GiB")).is_err());
    assert!(approved_usb_parent_seconds(Err(&std::env::VarError::NotPresent)).is_err());
}
