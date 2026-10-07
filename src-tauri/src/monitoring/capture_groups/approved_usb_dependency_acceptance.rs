use super::*;
#[test]
#[ignore = "explicit single authorized 79e2dfd USB parent 300s4GiB; preserves original sources"]
fn approved_usb_79_single_parent_4g() {
    // This monolithic debug acceptance future needs a bounded test-only stack.
    // Production UI invokes separate commands and does not use this runner.
    std::thread::Builder::new()
        .name("usb79-explicit-acceptance".into())
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
    assert_eq!(
        std::env::var("ME_APPROVED_USB_79").as_deref(),
        Ok("single-parent-300s4GiB")
    );
    let out = PathBuf::from(std::env::var_os("ME_USB_79_OUTPUT").unwrap());
    assert!(out.is_absolute() && !out.exists());
    std::fs::create_dir_all(&out).unwrap();
    let serial = "35251JEGR12568".to_owned();
    let paths: runtime_paths::RuntimePaths = serde_json::from_str(
        &std::fs::read_to_string(std::env::var("ME_USB_79_RUNTIME").unwrap()).unwrap(),
    )
    .unwrap();
    paths.validate().unwrap();
    assert_eq!(
        paths.expected_sha256,
        "201fc87900273bd98fc15f0057092879b8759fcf9c0f7c94ee56daf70742bcd4"
    );
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
        let lock = run_device_root_script(&serial, "dumpsys window policy")
            .await
            .unwrap();
        assert!(
            lock.stdout.contains("showing=false")
                && lock.stdout.contains("screenState=SCREEN_STATE_ON")
        );
    }
    let req:KernSightCaptureRequest=serde_json::from_value(serde_json::json!({"serial":serial,"package":"com.dlxx.mam.Internal","durationSeconds":15,"runtimePaths":paths,"sessionBudget":{"totalBytes":4294967296u64,"maxSeconds":300},"files":true,"network":true,"memory":true,"binder":true,"inspectMaxBytes":512,"inspectMaxHits":256})).unwrap();
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
    ] {
        manager_roots.push(out.join(name));
    }
    for key in ["l0", "l1", "dump", "linker"] {
        for suffix in ["-result.json", ".stdout.txt", ".stderr.txt"] {
            manager_roots.push(out.join(format!("{key}{suffix}")));
        }
    }
    let manager_guard =
        session_budget::Guard::install(manager_roots, 2 * 1024 * 1024, 300000).unwrap();
    let mut group =
        capture_groups::begin_group_at(groups.clone(), req, vec![15, 90, 15], true).unwrap();
    let deadline = group.budget.as_ref().unwrap().deadline().unwrap();
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
            if key == "dump" {
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
    session_budget::write(
        out.join("transfer-final-receipt.json"),
        serde_json::to_vec_pretty(&transfer_note).unwrap(),
    )
    .unwrap();
    capture_groups::settle_export_at(&groups, &mut group, &archive, "transfer", &transfer_note)
        .unwrap();
    drop(guard);
    if let Err(e) = work {
        session_budget::write(out.join("acceptance-blocker.txt"), &e).unwrap();
        println!(
            "physical_acceptance_stopped parent={} error={e}; no retry",
            group.id
        );
        panic!("physical acceptance blocked; evidence preserved: {e}");
    }
    let root = bundle_root.unwrap();
    let final_work=deadline.run(async {
  println!("production_archive_start parent={}",group.id);write_kernsight_evidence_archive(&root,&archive)?;
  let note:Value=serde_json::from_str(&std::fs::read_to_string(format!("{}.budget.json",archive.display())).map_err(|e|e.to_string())?).map_err(|e|e.to_string())?;
  capture_groups::settle_export_at(&groups,&mut group,&archive,"archive",&note)?;
  let import_guard=session_budget::Guard::install(vec![root.clone(),out.join("production-import-result.json")],import_cap-65536,deadline.remaining_ms()?).map_err(|e|e.to_string())?;
  let bundle=import_kernsight_evidence_directory(root.to_string_lossy().into_owned()).await?;
  let report=bundle.session_report.as_ref().ok_or("actual parent report absent")?;if report["mobilee_capture_group"]["id"]!=group.id.to_string(){return Err("parent report mismatch".into());}
  let execution_complete=report["execution_complete"]==true;
  let mut children=vec![];for id in group.session_ids(){let child=capture_groups::get_local_kernsight_child_report(bundle.root.clone(),group.id,id)?;children.push(serde_json::json!({"sessionId":id,"totalEvents":child.report["total_events"],"sourceStatus":child.report["mobilee_child_source_status"]}));}
  let code=bundle.files.iter().find(|f|f.relative_path.starts_with("readable-dex/")).or_else(||bundle.files.iter().find(|f|f.relative_path.starts_with("code-objects/")));
  let preview=if let Some(f)=code{Some(read_local_kernsight_evidence_file(bundle.root.clone(),group.package.clone(),f.relative_path.clone(),512).await?)}else{None};
  let code_preview_present=preview.is_some();
  let child_events_present=children.len()==3 && children.iter().all(|c|c["totalEvents"].as_u64().unwrap_or(0)>0);
  session_budget::write_json(out.join("production-import-result.json"),&serde_json::json!({"bundle":bundle,"children":children,"codePreview":preview,"parentCaptureState":group.state,"rawSessionsPreserved":seen,"archiveBytes":std::fs::metadata(&archive).map_err(|e|e.to_string())?.len(),"newParentBudgetBytes":4294967296u64,"captureMaxSeconds":300,"oldParentUnchanged":true,"ackSent":false,"sourceDeleted":false})).map_err(|e|e.to_string())?;
  let receipt=serde_json::to_value(import_guard.receipt()).unwrap();capture_groups::settle_export_at(&groups,&mut group,&archive,"import",&receipt)?;
  println!("production_import_finished parent={} children={}",group.id,children.len());
  if group.state!="succeeded"||!execution_complete||!code_preview_present||!child_events_present{return Err(format!("full acceptance not passed: parent={}, execution_complete={execution_complete}, code_preview={code_preview_present}, three_real_child_events={child_events_present}; retained partial preserved",group.state));}
  Ok(())
 }).await;
    session_budget::write(
        out.join("capture-group-after-import.json"),
        serde_json::to_vec_pretty(&group).unwrap(),
    )
    .unwrap();
    session_budget::write(
        out.join("manager-receipt.json"),
        serde_json::to_vec_pretty(&manager_guard.receipt()).unwrap(),
    )
    .unwrap();
    if let Err(e) = final_work {
        session_budget::write(out.join("acceptance-blocker.txt"), &e).unwrap();
        println!(
            "physical_acceptance_stopped parent={} error={e}; no retry",
            group.id
        );
        panic!("physical acceptance blocked; evidence preserved: {e}");
    } else {
        println!(
            "physical_acceptance_finished parent={} state={}",
            group.id, group.state
        );
    }
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
