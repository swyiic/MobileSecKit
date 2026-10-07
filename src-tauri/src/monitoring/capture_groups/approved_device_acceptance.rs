//! Explicit opt-in physical acceptance. Never part of the default test run.
use super::*;
#[tokio::test]
#[ignore = "requires explicit current-thread device authorization and matched candidate configuration"]
async fn approved_calculator_parent_60s_64mib() {
    assert_eq!(
        std::env::var("KSIGHT_APPROVED_CALCULATOR_RUN").as_deref(),
        Ok("60s64MiB")
    );
    let out = PathBuf::from(std::env::var_os("KSIGHT_ACCEPTANCE_OUTPUT").expect("explicit output"));
    assert!(out.is_absolute());
    std::fs::create_dir_all(&out).unwrap();
    let serial = std::env::var("KSIGHT_ACCEPTANCE_SERIAL").expect("explicit serial");
    let paths: runtime_paths::RuntimePaths = serde_json::from_str(
        &std::env::var("KSIGHT_ACCEPTANCE_RUNTIME").expect("explicit matched runtime"),
    )
    .unwrap();
    paths.validate().unwrap();
    require_runtime_paths(&serial, Some(&paths)).await.unwrap();
    require_code_scope_capability(&serial, Some(&paths))
        .await
        .unwrap();
    let request:KernSightCaptureRequest=serde_json::from_value(serde_json::json!({
        "serial":serial,"package":"com.google.android.calculator","durationSeconds":5,
        "codeOnly":true,"runtimePaths":paths,"sessionBudget":{"totalBytes":67108864,"maxSeconds":60},
        "files":true,"network":true,"memory":true,"binder":true,
        "inspectMaxBytes":512,"inspectMaxHits":256
    })).unwrap();
    let groups = out.join("groups");
    std::fs::create_dir_all(&groups).unwrap();
    let g = begin_group_at(groups.clone(), request, vec![5, 10, 5], true).unwrap();
    let mut stage_results = Vec::new();
    for key in ["l0", "l1", "dump", "linker"] {
        let result = run_group_stage_at(groups.clone(), g.id, key.into()).await;
        match result {
            Ok(value) => {
                println!(
                    "physical_stage={key} group_state={} error={:?}",
                    value.group.state, value.error
                );
                let stop = value.error.is_some() && !value.continue_after_partial;
                stage_results.push(serde_json::to_value(&value).unwrap());
                std::fs::write(
                    out.join("actual-stage-results.json"),
                    serde_json::to_vec_pretty(&stage_results).unwrap(),
                )
                .unwrap();
                std::fs::write(
                    out.join("capture-group.json"),
                    serde_json::to_vec_pretty(&value.group).unwrap(),
                )
                .unwrap();
                if stop {
                    break;
                }
            }
            Err(error) => {
                stage_results.push(serde_json::json!({"stage":key,"error":error}));
                std::fs::write(
                    out.join("actual-stage-results.json"),
                    serde_json::to_vec_pretty(&stage_results).unwrap(),
                )
                .unwrap();
                break;
            }
        }
    }
    let actual = load(&groups, g.id).unwrap();
    actual.validate().unwrap();
    assert_eq!(
        actual.stages.last().unwrap().attempts.last().unwrap().state,
        "succeeded",
        "Linker must actually finish; no retry"
    );
    assert_eq!(actual.session_ids().len(), 3);
    assert!(matches!(actual.state.as_str(), "partial" | "succeeded"));
    let export = pull_kernsight_package_archive_at(
        Some(groups.clone()),
        Some(g.id),
        serial.clone(),
        g.package.clone(),
        out.join("calculator.mee").to_string_lossy().into_owned(),
    )
    .await;
    let summary = match export {
        Ok(bundle) => {
            serde_json::json!({"status":"exported_and_imported","root":bundle.root,"parent":bundle.session_report.as_ref().map(|r|r["mobilee_capture_group"].clone()),"accounting":bundle.dump_report["local_storage_accounting"]})
        }
        Err(error) => serde_json::json!({"status":"failed_or_partial","error":error}),
    };
    std::fs::write(
        out.join("actual-export-result.json"),
        serde_json::to_vec_pretty(&summary).unwrap(),
    )
    .unwrap();
    let final_group = load(&groups, g.id).unwrap();
    final_group.validate().unwrap();
    std::fs::write(
        out.join("capture-group-after-export.json"),
        serde_json::to_vec_pretty(&final_group).unwrap(),
    )
    .unwrap();
    if actual.state == "partial" {
        assert_eq!(final_group.state, "partial");
    }
}

#[tokio::test]
#[ignore = "explicit retained failed Calculator parent only; read-only scoped replay, no App or collection"]
async fn approved_calculator_partial_readback() {
    assert_eq!(
        std::env::var("KSIGHT_APPROVED_CALCULATOR_READBACK").as_deref(),
        Ok("retained-parent-only")
    );
    let out =
        PathBuf::from(std::env::var_os("KSIGHT_ACCEPTANCE_OUTPUT").expect("exact retained output"));
    let g = read_import(&out).unwrap().unwrap();
    assert_eq!(g.package, "com.google.android.calculator");
    assert!(matches!(g.state.as_str(), "failed" | "partial"));
    assert_eq!(g.session_ids().len(), 1);
    let paths = runtime_paths_from_group(Some(&g)).unwrap().unwrap();
    require_runtime_paths(&g.serial, Some(&paths))
        .await
        .unwrap();
    let child = *g.session_ids().iter().next().unwrap();
    let report =
        get_kernsight_session_report_scoped(g.serial.clone(), child.to_string(), Some(&paths))
            .await
            .unwrap();
    let remote = runtime_paths::route(
        Some(&paths),
        &format!("{KSIGHT_SPOOL}/{child}/capture-relation.json"),
    )
    .unwrap();
    let source = run_device_root_script(
        &g.serial,
        &format!("head -c 32769 {}", crate::shell_quote(&remote)),
    )
    .await
    .unwrap();
    assert_eq!(source.code, Some(0));
    assert!(source.stdout.len() <= 32768);
    let note: Value = serde_json::from_str(&source.stdout).unwrap();
    verify_session_relation(&g, child, &note).unwrap();
    assert!(verify_session_relation(&g, Uuid::new_v4(), &note).is_err());
    let dir = out.join("sessions").join(child.to_string());
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("session-report.json"),
        serde_json::to_vec_pretty(&report.report).unwrap(),
    )
    .unwrap();
    std::fs::write(dir.join("capture-relation.json"), source.stdout).unwrap();
    let imported =
        get_local_kernsight_child_report(out.to_string_lossy().into_owned(), g.id, child).unwrap();
    assert_eq!(imported.report["mobilee_capture_group"]["state"], g.state);
    assert_eq!(
        imported.report["mobilee_child_source_status"],
        "agent_relation_matched"
    );
    assert_eq!(
        g.stages[0].attempts[0].remote_lifecycle.as_ref().unwrap()["collection_status"],
        "partial"
    );
    assert!(get_local_kernsight_child_report(
        out.to_string_lossy().into_owned(),
        Uuid::new_v4(),
        child
    )
    .is_err());
    let (_, _, files) = local_tree_stats(&out, 50_000).unwrap();
    let accounting = storage_evidence::account(
        &out,
        &files
            .iter()
            .map(|f| (f.relative_path.clone(), f.bytes))
            .collect::<Vec<_>>(),
    );
    assert_eq!(accounting["verified_code_logical_bytes"], 0);
    assert_eq!(accounting["verified_code_unique_bytes"], 0);
    std::fs::write(out.join("Me-partial-readback.json"),serde_json::to_vec_pretty(&serde_json::json!({"parentId":g.id,"childId":child,"groupState":g.state,"sourceStatus":imported.report["mobilee_child_source_status"],"collectionStatus":"partial","readbackOnly":true,"newAppOperations":0,"actualMemoryRanges":"not_exercised_no_dump","accounting":accounting})).unwrap()).unwrap();
    println!("physical_partial_readback parent={} child={} state={} source=agent_relation_matched no_code_ranges=true",g.id,child,g.state);
}

#[tokio::test]
#[ignore = "explicit retained current-parent-only readback; no new capture"]
async fn approved_calculator_current_group_import() {
    assert_eq!(
        std::env::var("KSIGHT_APPROVED_CALCULATOR_READBACK").as_deref(),
        Ok("retained-current-parent-only")
    );
    let out = PathBuf::from(std::env::var_os("KSIGHT_ACCEPTANCE_OUTPUT").unwrap());
    let state: Value =
        serde_json::from_str(&std::fs::read_to_string(out.join("IMPORT_STATE.json")).unwrap())
            .unwrap();
    let root = PathBuf::from(state["root"].as_str().unwrap());
    let g = read_import(&out).unwrap().unwrap();
    assert_eq!(g.package, "com.google.android.calculator");
    g.validate().unwrap();
    let guard =
        session_budget::Guard::install(vec![root.clone()], 12 * 1024 * 1024, 30000).unwrap();
    append_device_sessions_to_package_evidence(&g.serial, &g.package, &root, Some(&g))
        .await
        .unwrap();
    let bundle = import_kernsight_evidence_directory(root.to_string_lossy().into_owned())
        .await
        .unwrap();
    let report = bundle.session_report.as_ref().unwrap();
    assert_eq!(report["mobilee_capture_group"]["state"], g.state);
    assert_eq!(
        report["mobilee_included_sessions"]
            .as_array()
            .unwrap()
            .len(),
        g.session_ids().len()
    );
    if g.state != "succeeded" {
        assert_eq!(report["execution_complete"], false);
    }
    for child in g.session_ids() {
        let imported =
            get_local_kernsight_child_report(root.to_string_lossy().into_owned(), g.id, child)
                .unwrap();
        assert_eq!(
            imported.report["mobilee_child_source_status"],
            "agent_relation_matched"
        );
        assert!(get_local_kernsight_child_report(
            root.to_string_lossy().into_owned(),
            Uuid::new_v4(),
            child
        )
        .is_err());
    }
    let receipt = guard.receipt();
    assert!(!receipt.partial);
    std::fs::write(out.join("Me-current-parent-import.json"),serde_json::to_vec_pretty(&serde_json::json!({"parentId":g.id,"parentState":g.state,"childIds":g.session_ids(),"executionComplete":report["execution_complete"],"sourceSessions":report["mobilee_source_sessions"],"accounting":bundle.dump_report["local_storage_accounting"],"readbackOnly":true,"newAppOperations":0,"metadataWriteReceipt":receipt})).unwrap()).unwrap();
    println!(
        "current_parent_import parent={} state={} children={} readback_only=true",
        g.id,
        g.state,
        g.session_ids().len()
    );
}

#[tokio::test]
#[ignore = "explicit current local transfer partial only; no device access"]
async fn approved_calculator_current_transfer_partial_import() {
    let root =
        std::env::var("KSIGHT_CURRENT_TRANSFER_PARTIAL").expect("explicit retained partial root");
    let bundle = import_kernsight_evidence_directory(root).await.unwrap();
    assert_eq!(
        bundle.dump_report["mobilee_transport_status"]["complete"],
        false
    );
    assert_eq!(
        bundle.session_report.as_ref().unwrap()["mobilee_capture_group"]["id"],
        "866dcdc7-9c7a-4b74-91f6-15f8a2cfd778"
    );
    assert_eq!(
        bundle.session_report.as_ref().unwrap()["mobilee_capture_group"]["state"],
        "partial"
    );
    assert!(bundle
        .files
        .iter()
        .any(|f| f.relative_path.contains(".partial-")));
    if let Ok(output) = std::env::var("KSIGHT_CURRENT_TRANSFER_IMPORT_REPORT") {
        std::fs::write(output,serde_json::to_vec_pretty(&serde_json::json!({"parent":bundle.session_report.as_ref().unwrap()["mobilee_capture_group"]["id"],"parent_state":"partial","transport_status":bundle.dump_report["mobilee_transport_status"],"accounting":bundle.dump_report["local_storage_accounting"],"partial_files":bundle.files.iter().filter(|f|f.relative_path.contains(".partial-")).map(|f|serde_json::json!({"path":f.relative_path,"bytes":f.bytes})).collect::<Vec<_>>()})).unwrap()).unwrap();
    }
}

#[tokio::test]
#[ignore = "explicit retained local partial export; no device or new collection"]
async fn approved_current_partial_archive_round_trip_inside_remaining_bytes() {
    let source = PathBuf::from(
        std::env::var_os("KSIGHT_CURRENT_PARTIAL_ARCHIVE_SOURCE")
            .expect("explicit received source"),
    );
    let output = PathBuf::from(
        std::env::var_os("KSIGHT_CURRENT_PARTIAL_ARCHIVE_OUTPUT").expect("explicit new archive"),
    );
    let evidence = source.parent().unwrap().parent().unwrap();
    let group: Group = serde_json::from_slice(
        &std::fs::read(evidence.join("capture-group-after-export.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(group.id.to_string(), "866dcdc7-9c7a-4b74-91f6-15f8a2cfd778");
    let budget = group.budget.as_ref().unwrap();
    let archive_reserved = budget
        .reservations
        .iter()
        .find(|r| r.kind == "archive")
        .unwrap()
        .reserved_bytes;
    let import_reserved = budget
        .reservations
        .iter()
        .find(|r| r.kind == "import")
        .unwrap()
        .reserved_bytes;
    let before = collect_archive_files(&source).unwrap();
    let hashes = before
        .iter()
        .map(|(p, r, n)| (r.clone(), (*n, storage_evidence::hash_file(p, *n).unwrap())))
        .collect::<BTreeMap<_, _>>();
    let archive_guard = session_budget::Guard::install(
        vec![
            output.clone(),
            PathBuf::from(format!("{}.part", output.display())),
        ],
        archive_reserved - 65536,
        30000,
    )
    .unwrap();
    let import_guard =
        session_budget::Guard::install(vec![std::env::temp_dir()], import_reserved - 65536, 30000)
            .unwrap();
    export_kernsight_evidence_archive(
        source.to_string_lossy().into_owned(),
        output.to_string_lossy().into_owned(),
    )
    .unwrap();
    let bundle = import_kernsight_evidence_archive(output.to_string_lossy().into_owned())
        .await
        .unwrap();
    assert_eq!(
        bundle.dump_report["mobilee_archive_coverage"]["status"],
        "partial"
    );
    assert_eq!(
        bundle.session_report.as_ref().unwrap()["mobilee_capture_group"]["state"],
        "partial"
    );
    for (relative, (bytes, hash)) in &hashes {
        assert_eq!(
            storage_evidence::hash_file(&Path::new(&bundle.root).join(relative), *bytes).as_ref(),
            Some(hash)
        );
        assert_eq!(
            storage_evidence::hash_file(&source.join(relative), *bytes).as_ref(),
            Some(hash)
        );
    }
    let archive_receipt = archive_guard.receipt();
    let import_receipt = import_guard.receipt();
    let earlier = budget.manager_reserve_bytes
        + budget
            .reservations
            .iter()
            .filter_map(|r| r.charged_bytes)
            .sum::<u64>();
    let cumulative = earlier
        + archive_receipt.admitted_write_bytes
        + import_receipt.admitted_write_bytes
        + 2 * 65536;
    assert!(cumulative <= budget.limits.total_bytes);
    let mut zip = ZipArchive::new(File::open(&output).unwrap()).unwrap();
    let mut manifest = String::new();
    zip.by_name("manifest.json")
        .unwrap()
        .read_to_string(&mut manifest)
        .unwrap();
    let manifest: Value = serde_json::from_str(&manifest).unwrap();
    let summary = serde_json::json!({"scope":"explicit offline recovery of retained bytes; original 60-second capture deadline not resumed","source":source,"archive":output,"restored_root":bundle.root,"archive_bytes":std::fs::metadata(&output).unwrap().len(),"archive_sha256":storage_evidence::hash_file(&output,std::fs::metadata(&output).unwrap().len()),"logical_retained_bytes":manifest["uncompressedBytes"],"unique_content_bytes":manifest["objectBytes"],"original_paths_hash_verified":hashes.len(),"coverage":manifest["coverage"],"archive_write_receipt":archive_receipt,"import_write_receipt":import_receipt,"cumulative_writes_plus_terminal_reserves_and_manager":cumulative,"original_total_limit_bytes":budget.limits.total_bytes,"parent_state":"partial","source_hashes_unchanged":true,"new_device_transferred_bytes":0});
    std::fs::write(
        evidence.join("ACTUAL_PARTIAL_ARCHIVE_RECOVERY.json"),
        serde_json::to_vec_pretty(&summary).unwrap(),
    )
    .unwrap();
}

#[tokio::test]
#[ignore = "explicit already captured Calculator snapshot readback only; no launch or collection"]
async fn approved_existing_calculator_snapshot_cached_export_round_trip() {
    let evidence = PathBuf::from(
        std::env::var_os("KSIGHT_EXISTING_SNAPSHOT_OUTPUT").expect("explicit existing run output"),
    );
    let group: Group = serde_json::from_slice(
        &std::fs::read(evidence.join("capture-group-after-export.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(group.id.to_string(), "866dcdc7-9c7a-4b74-91f6-15f8a2cfd778");
    let budget = group.budget.as_ref().unwrap();
    let prior: Value = serde_json::from_slice(
        &std::fs::read(evidence.join("ACTUAL_PARTIAL_ARCHIVE_RECOVERY.json")).unwrap(),
    )
    .unwrap();
    let earlier = prior["cumulative_writes_plus_terminal_reserves_and_manager"]
        .as_u64()
        .unwrap()
        + std::fs::metadata(evidence.join("EXISTING_DEVICE_INVENTORY.json"))
            .unwrap()
            .len();
    let remaining = budget.limits.total_bytes - earlier;
    let plan: Value = serde_json::from_slice(
        &std::fs::read(evidence.join("EXPLICIT_EXISTING_OBJECT_REUSE_PLAN.json")).unwrap(),
    )
    .unwrap();
    let known = plan["known_objects"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| {
            (
                (
                    r["sha256"].as_str().unwrap().to_owned(),
                    r["bytes"].as_u64().unwrap(),
                ),
                PathBuf::from(r["source"].as_str().unwrap()),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let target = evidence.join("retained-complete-device-tree");
    assert!(!target.exists());
    let output = evidence.join("calculator-retained-snapshot-partial.mee");
    assert!(!output.exists());
    let guard = session_budget::Guard::install(
        vec![
            target.clone(),
            output.clone(),
            PathBuf::from(format!("{}.part", output.display())),
            std::env::temp_dir(),
        ],
        remaining - 3 * 65536,
        30000,
    )
    .unwrap();
    let runtime = runtime_paths_from_group(Some(&group)).unwrap().unwrap();
    let source = export_root(&group).unwrap();
    let bundle = pull_kernsight_package_evidence_with_objects(
        group.serial.clone(),
        group.package.clone(),
        target.to_string_lossy().into_owned(),
        Some(source.clone()),
        Some(&runtime),
        known,
    )
    .await
    .unwrap();
    let root = PathBuf::from(&bundle.root);
    let inventory: Value = serde_json::from_slice(
        &std::fs::read(evidence.join("EXISTING_DEVICE_INVENTORY.json")).unwrap(),
    )
    .unwrap();
    for r in inventory["files"].as_array().unwrap() {
        assert_eq!(
            storage_evidence::hash_file(
                &root.join(r["path"].as_str().unwrap()),
                r["bytes"].as_u64().unwrap()
            )
            .as_deref(),
            r["sha256"].as_str()
        );
    }
    session_budget::write(
        root.join("capture-group.json"),
        serde_json::to_vec(&group).unwrap(),
    )
    .unwrap();
    session_budget::write(root.join("received-snapshot-provenance.json"),serde_json::to_vec(&serde_json::json!({"schema":"mobilee.received-snapshot/v1","parent":group.id,"remote_root":source,"inventory_file_count":35,"inventory_hash":storage_evidence::hash_file(&evidence.join("EXISTING_DEVICE_INVENTORY.json"),std::fs::metadata(evidence.join("EXISTING_DEVICE_INVENTORY.json")).unwrap().len()),"retained_paths":"every original inventory path hash verified","collection_status":"partial","session_spool_status":"not downloaded in this recovery; original references preserved","reuse_plan":plan})).unwrap()).unwrap();
    export_kernsight_evidence_archive(
        root.to_string_lossy().into_owned(),
        output.to_string_lossy().into_owned(),
    )
    .unwrap();
    let restored = import_kernsight_evidence_archive(output.to_string_lossy().into_owned())
        .await
        .unwrap();
    for r in inventory["files"].as_array().unwrap() {
        assert_eq!(
            storage_evidence::hash_file(
                &Path::new(&restored.root).join(r["path"].as_str().unwrap()),
                r["bytes"].as_u64().unwrap()
            )
            .as_deref(),
            r["sha256"].as_str()
        );
    }
    assert_eq!(
        restored.dump_report["mobilee_archive_coverage"]["status"],
        "partial"
    );
    assert_eq!(
        restored.session_report.as_ref().unwrap()["mobilee_capture_group"]["state"],
        "partial"
    );
    assert_eq!(
        restored.dump_report["local_storage_accounting"]["verified_code_unique_bytes"],
        19983868
    );
    let receipt = guard.receipt();
    assert!(!receipt.partial);
    let cumulative = earlier + receipt.admitted_write_bytes + 3 * 65536;
    assert!(cumulative <= budget.limits.total_bytes);
    let summary = serde_json::json!({"scope":"bounded read-only recovery of already retained snapshot; no new collection or capture deadline restart","source_root":root,"archive":output,"restored_root":restored.root,"inventory_paths_hash_verified":35,"device_missing_unique_bytes":plan["device_missing_unique_bytes"],"archive_bytes":std::fs::metadata(&output).unwrap().len(),"archive_sha256":storage_evidence::hash_file(&output,std::fs::metadata(&output).unwrap().len()),"output_receipt":receipt,"cumulative_writes_and_reserves":cumulative,"original_total_limit":budget.limits.total_bytes,"parent_state":"partial","runtime_observations":restored.dump_report["local_storage_accounting"]["runtime_observations"],"accounting":restored.dump_report["local_storage_accounting"],"unresolved":"unselected/unread/uncommitted ranges and three original child spools not fully transported"});
    std::fs::write(
        evidence.join("ACTUAL_CACHED_SNAPSHOT_ARCHIVE.json"),
        serde_json::to_vec_pretty(&summary).unwrap(),
    )
    .unwrap();
}

#[tokio::test]
#[ignore = "explicit authorized read-only default installation verification; no collection"]
async fn approved_default_installation_hash_and_capability() {
    let serial = std::env::var("KSIGHT_DEFAULT_VERIFY_SERIAL").expect("explicit device serial");
    let expected = std::env::var("KSIGHT_DEFAULT_VERIFY_SHA256").expect("explicit candidate hash");
    assert_eq!(expected.len(), 64);
    assert!(expected.bytes().all(|b| b.is_ascii_hexdigit()));
    let script = runtime_paths::route(None, &format!("{KSIGHT_AGENT} code-capabilities")).unwrap();
    assert_eq!(script, format!("{KSIGHT_AGENT} code-capabilities"));
    let out = run_device_root_script(&serial, &script).await.unwrap();
    validate_parent_lifecycle_capability(out.code, &out.stdout).unwrap();
    validate_code_scope_capability(out.code, &out.stdout).unwrap();
    let note: Value = serde_json::from_str(&out.stdout).unwrap();
    assert_eq!(note["agent_path"], KSIGHT_AGENT);
    assert_eq!(note["runtime_root"], "/data/local/tmp/ksight");
    assert_eq!(note["agent_sha256"], expected);
    require_parent_lifecycle_capability(&serial, None)
        .await
        .unwrap();
    require_code_scope_capability(&serial, None).await.unwrap();
}

#[tokio::test]
#[ignore = "explicit new Reqable ordinary-homepage device authorization; 60s128MiB; no VPN or login"]
async fn approved_reqable_homepage_60s_128mib() {
    assert_eq!(
        std::env::var("KSIGHT_APPROVED_REQABLE_RUN").as_deref(),
        Ok("60s128MiB")
    );
    let out = PathBuf::from(std::env::var_os("KSIGHT_ACCEPTANCE_OUTPUT").unwrap());
    std::fs::create_dir_all(&out).unwrap();
    let serial = std::env::var("KSIGHT_ACCEPTANCE_SERIAL").unwrap();
    let paths: runtime_paths::RuntimePaths =
        serde_json::from_str(&std::env::var("KSIGHT_ACCEPTANCE_RUNTIME").unwrap()).unwrap();
    require_runtime_paths(&serial, Some(&paths)).await.unwrap();
    require_code_scope_capability(&serial, Some(&paths))
        .await
        .unwrap();
    let request: KernSightCaptureRequest = serde_json::from_value(serde_json::json!({"serial":serial,"package":"com.reqable.android","durationSeconds":5,"codeOnly":true,"runtimePaths":paths,"sessionBudget":{"totalBytes":134217728,"maxSeconds":60},"files":true,"network":false,"memory":true,"binder":true,"inspectMaxBytes":512,"inspectMaxHits":256})).unwrap();
    let groups = out.join("groups");
    let g = begin_group_at(groups.clone(), request, vec![5, 10, 5], true).unwrap();
    let mut results = Vec::new();
    for key in ["l0", "l1", "dump"] {
        let result = run_group_stage_at(groups.clone(), g.id, key.into()).await;
        match result {
            Ok(value) => {
                let stop = value.error.is_some() && !value.continue_after_partial;
                results.push(serde_json::to_value(&value).unwrap());
                std::fs::write(
                    out.join("actual-stage-results.json"),
                    serde_json::to_vec_pretty(&results).unwrap(),
                )
                .unwrap();
                if stop {
                    break;
                }
            }
            Err(error) => {
                results.push(serde_json::json!({"stage":key,"error":error}));
                break;
            }
        }
    }
    let actual = load(&groups, g.id).unwrap();
    std::fs::write(
        out.join("capture-group.json"),
        serde_json::to_vec_pretty(&actual).unwrap(),
    )
    .unwrap();
    std::fs::write(
        out.join("actual-stage-results.json"),
        serde_json::to_vec_pretty(&results).unwrap(),
    )
    .unwrap();
    let dump = actual
        .stages
        .iter()
        .find(|stage| stage.key == "dump")
        .unwrap();
    assert_eq!(
        dump.attempts.len(),
        1,
        "dump must actually execute, not merely appear in the planned stages"
    );
    assert!(matches!(
        dump.attempts[0].state.as_str(),
        "partial" | "succeeded"
    ));
    assert!(dump.attempts[0].remote_artifact_root.is_some());
    assert_eq!(
        actual.session_ids().len(),
        2,
        "L0 and L1 must actually return sessions"
    );
}

#[test]
#[ignore = "explicit retained Reqable file analysis; no device, no new capture"]
fn approved_retained_reqable_ranges_me_analysis() {
    let root = PathBuf::from(
        std::env::var_os("KSIGHT_RETAINED_REQABLE_ROOT").expect("exact retained evidence root"),
    );
    let output = PathBuf::from(
        std::env::var_os("KSIGHT_RETAINED_REQABLE_ANALYSIS").expect("bounded result path"),
    );
    let (_, _, files) = local_tree_stats(&root, 50_000).unwrap();
    let ledger = storage_evidence::account(
        &root,
        &files
            .iter()
            .map(|f| (f.relative_path.clone(), f.bytes))
            .collect::<Vec<_>>(),
    );
    let rows = ledger["runtime_observations"].as_array().unwrap();
    assert_eq!(rows.len(), 24);
    assert_eq!(ledger["verified_code_unique_bytes"], 65465087u64);
    assert!(rows
        .iter()
        .all(|r| r["local_content_status"] == "complete_range_hash_verified"));
    let modules = ledger["elf_module_observations"].as_array().unwrap();
    assert_eq!(modules.len(), 7);
    assert!(modules
        .iter()
        .all(|v| v["all_load_file_bytes_covered"] == true
            && v["complete_file_reconstructed"] == false));
    assert_eq!(
        modules
            .iter()
            .filter(|v| v["all_load_memory_bytes_covered"] == true)
            .count(),
        1
    );
    let summary = serde_json::json!({"schema":"mobilee.retained-reqable-analysis/v1","verified_code_unique_bytes":ledger["verified_code_unique_bytes"],"hash_budget_remaining":ledger["hash_budget_remaining"],"elf_module_observations":modules,"rows":rows.iter().map(|v|serde_json::json!({"path":v["mapping"]["path"],"relative_path":v["relative_path"],"source_report":v["source_report"],"source":v["source"],"read":v["read"],"mapping_complete":v["mapping_complete"],"object_inspection":v["object_inspection"]})).collect::<Vec<_>>()});
    let bytes = serde_json::to_vec(&summary).unwrap();
    assert!(bytes.len() < 128 * 1024);
    std::fs::write(output, bytes).unwrap();
}

#[tokio::test]
#[ignore = "explicit offline retained Reqable archive round trip; no device or capture"]
async fn approved_retained_reqable_archive_round_trip() {
    let root = PathBuf::from(std::env::var_os("KSIGHT_RETAINED_REQABLE_ROOT").unwrap());
    let output = PathBuf::from(std::env::var_os("KSIGHT_RETAINED_REQABLE_ARCHIVE").unwrap());
    let result = PathBuf::from(std::env::var_os("KSIGHT_RETAINED_REQABLE_ARCHIVE_RESULT").unwrap());
    let source = collect_archive_files(&root).unwrap();
    let hashes = source
        .iter()
        .map(|(path, rel, n)| {
            (
                rel.clone(),
                *n,
                storage_evidence::hash_file(path, *n).unwrap(),
            )
        })
        .collect::<Vec<_>>();
    export_kernsight_evidence_archive(
        root.to_string_lossy().into_owned(),
        output.to_string_lossy().into_owned(),
    )
    .unwrap();
    let bundle = import_kernsight_evidence_archive(output.to_string_lossy().into_owned())
        .await
        .unwrap();
    for (rel, n, hash) in &hashes {
        assert_eq!(
            storage_evidence::hash_file(&PathBuf::from(&bundle.root).join(rel), *n).as_ref(),
            Some(hash),
            "{rel}"
        );
    }
    let ledger = &bundle.dump_report["local_storage_accounting"];
    assert_eq!(ledger["runtime_observations"].as_array().unwrap().len(), 24);
    assert_eq!(
        ledger["elf_module_observations"].as_array().unwrap().len(),
        7
    );
    assert_eq!(ledger["verified_code_unique_bytes"], 65465087u64);
    assert_eq!(
        bundle.session_report.as_ref().unwrap()["mobilee_capture_group"]["state"],
        "partial"
    );
    assert!(bundle.dump_report["mobilee_archive_coverage"]["complete_collection"] != true);
    let summary = serde_json::json!({"scope":"independent bounded offline archive/import; original 60s128MiB parent not resumed","archive":output,"archive_bytes":std::fs::metadata(&output).unwrap().len(),"archive_sha256":storage_evidence::hash_file(&output,std::fs::metadata(&output).unwrap().len()),"all_source_paths_full_hash_verified":hashes.len(),"root":bundle.root,"parent_state":"partial","verified_code_unique_bytes":ledger["verified_code_unique_bytes"],"runtime_observations":24,"elf_modules":7,"archive_coverage":bundle.dump_report["mobilee_archive_coverage"],"originals_unchanged":hashes.iter().all(|(rel,n,h)|storage_evidence::hash_file(&root.join(rel),*n).as_ref()==Some(h))});
    std::fs::write(result, serde_json::to_vec_pretty(&summary).unwrap()).unwrap();
}

#[tokio::test]
#[ignore = "explicit existing retained archive import; no export, device or capture"]
async fn approved_retained_reqable_existing_archive_diagnostics() {
    let archive = std::env::var("KSIGHT_RETAINED_REQABLE_ARCHIVE").unwrap();
    let bundle = import_kernsight_evidence_archive(archive).await.unwrap();
    let ledger = &bundle.dump_report["local_storage_accounting"];
    assert_eq!(ledger["runtime_observations"].as_array().unwrap().len(), 24);
    assert_eq!(
        ledger["elf_module_observations"].as_array().unwrap().len(),
        7
    );
    let diagnostics = ledger["runtime_source_diagnostics"].as_array().unwrap();
    assert_eq!(diagnostics.len(), 3);
    assert!(diagnostics.iter().all(|v| v["status"] == "accepted"));
    assert_eq!(
        diagnostics
            .iter()
            .filter_map(|v| v["records_seen"].as_u64())
            .sum::<u64>(),
        24
    );
    assert_eq!(
        ledger["elf_module_observations"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|v| v["verified_range_count"].as_u64())
            .sum::<u64>(),
        22
    );
    let vdex = ledger["runtime_observations"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| {
            v["mapping"]["path"]
                .as_str()
                .is_some_and(|p| p.ends_with("base.vdex"))
        })
        .unwrap();
    let rejected = &vdex["object_inspection"]["rejected_candidates"][0];
    assert_eq!(rejected["source_offset"], 64);
    assert_eq!(rejected["declared_length"], 5979524);
    assert_eq!(rejected["missing_declared_bytes"], 3949253);
    assert_eq!(
        rejected["reason"],
        "declared_dex_extends_beyond_retained_range"
    );
    assert_eq!(
        vdex["object_inspection"]["derived_objects"]
            .as_array()
            .unwrap()
            .len(),
        0
    );
    if let Some(output) = std::env::var_os("KSIGHT_RETAINED_REQABLE_ANALYSIS") {
        let bytes = serde_json::to_vec(ledger).unwrap();
        assert!(bytes.len() < 128 * 1024);
        std::fs::write(output, bytes).unwrap();
    }
    assert!(bundle
        .session_report
        .as_ref()
        .unwrap()
        .get("mobilee_capture_accounting")
        .is_some());
}

#[tokio::test]
#[ignore = "explicit fresh Reqable retained DEX archive verification; no new device operation"]
async fn approved_fresh_reqable_complete_runtime_dex_archive() {
    let root = PathBuf::from(std::env::var_os("KSIGHT_RETAINED_REQABLE_ROOT").unwrap());
    let output = std::env::var("KSIGHT_RETAINED_REQABLE_ARCHIVE").unwrap();
    let result = std::env::var_os("KSIGHT_RETAINED_REQABLE_ANALYSIS").unwrap();
    let sources = collect_archive_files(&root).unwrap();
    let hashes = sources
        .iter()
        .map(|(p, r, n)| (r.clone(), *n, storage_evidence::hash_file(p, *n).unwrap()))
        .collect::<Vec<_>>();
    let original = import_kernsight_evidence_directory(root.to_string_lossy().into_owned())
        .await
        .unwrap();
    export_kernsight_evidence_archive(root.to_string_lossy().into_owned(), output.clone()).unwrap();
    let restored = import_kernsight_evidence_archive(output.clone())
        .await
        .unwrap();
    for bundle in [&original, &restored] {
        let ledger = &bundle.dump_report["local_storage_accounting"];
        let rows = ledger["runtime_observations"].as_array().unwrap();
        assert_eq!(rows.len(), 24);
        assert_eq!(
            rows.iter()
                .filter(|r| r["mapping"]["path"]
                    .as_str()
                    .is_some_and(|p| p.ends_with(".so")))
                .count(),
            22
        );
        let vdex = rows
            .iter()
            .find(|r| {
                r["mapping"]["path"]
                    .as_str()
                    .is_some_and(|p| p.ends_with("base.vdex"))
            })
            .unwrap();
        assert_eq!(vdex["source"]["pid"], 13685);
        let dex = &vdex["object_inspection"]["derived_objects"][0];
        assert_eq!(dex["length"], 5979524);
        assert_eq!(dex["semantic"]["class_defs"], 8201);
        assert_eq!(dex["sha1_signature_verified"], true);
        assert_eq!(dex["adler32_checksum_verified"], true);
        assert_eq!(
            dex["sha256"],
            "9ca2c83abbeb9379a20effb57a607397b646062a87734c9f74fd2ca627d9c884"
        );
        let modules = ledger["elf_module_observations"].as_array().unwrap();
        assert_eq!(modules.len(), 7);
        assert!(modules
            .iter()
            .all(|m| m["all_load_file_bytes_covered"] == true
                && m["complete_file_reconstructed"] == false));
    }
    for (rel, n, hash) in &hashes {
        assert_eq!(
            storage_evidence::hash_file(&PathBuf::from(&restored.root).join(rel), *n).as_ref(),
            Some(hash)
        );
        assert_eq!(
            storage_evidence::hash_file(&root.join(rel), *n).as_ref(),
            Some(hash)
        );
    }
    let summary = serde_json::json!({"archive":output,"archive_bytes":std::fs::metadata(&output).unwrap().len(),"source_paths_verified":hashes.len(),"originals_unchanged":true,"parent_state":restored.session_report.as_ref().unwrap()["mobilee_capture_group"]["state"],"archive_coverage":restored.dump_report["mobilee_archive_coverage"],"accounting":restored.dump_report["local_storage_accounting"]});
    let bytes = serde_json::to_vec(&summary).unwrap();
    assert!(bytes.len() < 2 * 1024 * 1024);
    std::fs::write(result, bytes).unwrap();
}

#[tokio::test]
#[ignore = "explicit existing runtime DEX class-index archive replay; no device or export"]
async fn approved_retained_complete_dex_class_index_reimport() {
    let archive = std::env::var("KSIGHT_RETAINED_REQABLE_ARCHIVE").unwrap();
    let bundle = import_kernsight_evidence_archive(archive).await.unwrap();
    let index = &bundle.dump_report["content_dex_class_index"];
    assert_eq!(index["objects"].as_array().unwrap().len(), 1);
    let object = &index["objects"][0];
    assert_eq!(object["class_index_status"], "complete_class_def_index");
    assert_eq!(object["declared_classes"], 8201);
    assert_eq!(object["indexed_classes"], 8201);
    assert_eq!(object["sources"].as_array().unwrap().len(), 2);
    assert_eq!(object["sources"][0]["source"]["pid"], 13685);
    assert_eq!(
        object["sources"][0]["parent_id"],
        bundle.session_report.as_ref().unwrap()["mobilee_capture_group"]["id"]
    );
    assert_eq!(object["sources"][1]["kind"], "static_comparison_reference");
    assert_eq!(object["ownership"], "mixed_or_unknown");
    let rows = bundle.dump_report["local_storage_accounting"]["runtime_observations"]
        .as_array()
        .unwrap();
    let classes = &rows[object["sources"][0]["row_index"].as_u64().unwrap() as usize]
        ["object_inspection"]["derived_objects"][0]["class_index"];
    assert_eq!(classes["classes"].as_array().unwrap().len(), 8201);
    assert_eq!(classes["omitted_classes"], 0);
    assert!(classes["classes"]
        .as_array()
        .unwrap()
        .iter()
        .any(|c| c.as_str().is_some_and(|s| s.starts_with("Lcom/reqable/"))));
    let summary = serde_json::json!({"content_index":index,"runtime_class_index":classes,"accounting":bundle.dump_report["local_storage_accounting"],"class_descriptor_budget_remaining":bundle.dump_report["local_storage_accounting"]["class_index_descriptor_budget_remaining"],"parent":bundle.session_report.as_ref().unwrap()["mobilee_capture_group"]["id"],"parent_state":bundle.session_report.as_ref().unwrap()["mobilee_capture_group"]["state"],"source_root":bundle.root});
    let bytes = serde_json::to_vec(&summary).unwrap();
    assert!(bytes.len() < 2 * 1024 * 1024);
    std::fs::write(
        std::env::var_os("KSIGHT_RETAINED_REQABLE_ANALYSIS").unwrap(),
        bytes,
    )
    .unwrap();
}

#[tokio::test]
#[ignore = "explicit independent local UI fixture and archive re-export; no device"]
async fn approved_existing_reqable_ui_fixture_and_reexport() {
    let input = std::env::var("KSIGHT_RETAINED_REQABLE_ARCHIVE").unwrap();
    let output = std::env::var("KSIGHT_UI_REEXPORT").unwrap();
    let original = import_kernsight_evidence_archive(input).await.unwrap();
    let saved = export_kernsight_evidence_archive(original.root.clone(), output.clone()).unwrap();
    let restored = import_kernsight_evidence_archive(saved.clone())
        .await
        .unwrap();
    assert_eq!(
        original.session_report.as_ref().unwrap()["mobilee_capture_group"]["id"],
        restored.session_report.as_ref().unwrap()["mobilee_capture_group"]["id"]
    );
    assert_eq!(
        restored.dump_report["content_dex_class_index"]["objects"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        restored.dump_report["content_dex_class_index"]["objects"][0]["indexed_classes"],
        8201
    );
    assert_eq!(
        restored.dump_report["local_storage_accounting"]["elf_module_observations"]
            .as_array()
            .unwrap()
            .len(),
        7
    );
    assert_eq!(
        restored.dump_report["mobilee_archive_coverage"]["status"],
        "partial"
    );
    let fixture =
        serde_json::json!({"original":original,"reimported":restored,"reexport_path":saved});
    let bytes = serde_json::to_vec(&fixture).unwrap();
    assert!(bytes.len() < 4 * 1024 * 1024);
    std::fs::write(std::env::var_os("KSIGHT_UI_FIXTURE_JSON").unwrap(), bytes).unwrap();
}

#[tokio::test]
#[ignore = "explicit new cn.i4.mobile ordinary-launch authorization; 60s128MiB; no login/location/permission actions"]
async fn approved_i4_ordinary_launch_60s_128mib() {
    assert_eq!(
        std::env::var("KSIGHT_APPROVED_I4_RUN").as_deref(),
        Ok("60s128MiB")
    );
    let out = PathBuf::from(std::env::var_os("KSIGHT_ACCEPTANCE_OUTPUT").unwrap());
    std::fs::create_dir_all(&out).unwrap();
    let serial = std::env::var("KSIGHT_ACCEPTANCE_SERIAL").unwrap();
    let paths: runtime_paths::RuntimePaths =
        serde_json::from_str(&std::env::var("KSIGHT_ACCEPTANCE_RUNTIME").unwrap()).unwrap();
    require_runtime_paths(&serial, Some(&paths)).await.unwrap();
    require_code_scope_capability(&serial, Some(&paths))
        .await
        .unwrap();
    let request: KernSightCaptureRequest = serde_json::from_value(serde_json::json!({"serial":serial,"package":"cn.i4.mobile","durationSeconds":5,"codeOnly":true,"runtimePaths":paths,"sessionBudget":{"totalBytes":134217728,"maxSeconds":60},"files":false,"network":false,"memory":true,"binder":false,"inspectMaxBytes":512,"inspectMaxHits":256})).unwrap();
    let groups = out.join("groups");
    let g = begin_group_at(groups.clone(), request, vec![5, 10, 5], true).unwrap();
    let mut results = Vec::new();
    for key in ["l0", "l1", "dump"] {
        let result = run_group_stage_at(groups.clone(), g.id, key.into()).await;
        match result {
            Ok(value) => {
                let stop = value.error.is_some() && !value.continue_after_partial;
                results.push(serde_json::to_value(&value).unwrap());
                std::fs::write(
                    out.join("actual-stage-results.json"),
                    serde_json::to_vec_pretty(&results).unwrap(),
                )
                .unwrap();
                if stop {
                    break;
                }
            }
            Err(error) => {
                results.push(serde_json::json!({"stage":key,"error":error}));
                break;
            }
        }
    }
    let actual = load(&groups, g.id).unwrap();
    std::fs::write(
        out.join("capture-group.json"),
        serde_json::to_vec_pretty(&actual).unwrap(),
    )
    .unwrap();
    std::fs::write(
        out.join("actual-stage-results.json"),
        serde_json::to_vec_pretty(&results).unwrap(),
    )
    .unwrap();
    let dump = actual
        .stages
        .iter()
        .find(|stage| stage.key == "dump")
        .unwrap();
    assert_eq!(
        dump.attempts.len(),
        1,
        "dump must actually execute, not merely appear in the planned stages"
    );
    assert!(matches!(
        dump.attempts[0].state.as_str(),
        "partial" | "succeeded"
    ));
    assert!(dump.attempts[0].remote_artifact_root.is_some());
    assert_eq!(
        actual.session_ids().len(),
        2,
        "L0 and L1 must actually return sessions"
    );
}

#[tokio::test]
#[ignore = "explicit retained i4 loader evidence roundtrip; no device operation"]
async fn approved_i4_checksum_failed_loader_archive_roundtrip() {
    let root = PathBuf::from(std::env::var_os("KSIGHT_I4_ROOT").unwrap());
    let output = std::env::var("KSIGHT_I4_ARCHIVE").unwrap();
    let hashes = collect_archive_files(&root)
        .unwrap()
        .into_iter()
        .map(|(p, r, n)| (r, n, storage_evidence::hash_file(&p, n).unwrap()))
        .collect::<Vec<_>>();
    let original = import_kernsight_evidence_directory(root.to_string_lossy().into_owned())
        .await
        .unwrap();
    export_kernsight_evidence_archive(root.to_string_lossy().into_owned(), output.clone()).unwrap();
    let restored = import_kernsight_evidence_archive(output.clone())
        .await
        .unwrap();
    for bundle in [&original, &restored] {
        let index = &bundle.dump_report["content_dex_class_index"];
        assert_eq!(index["objects"].as_array().unwrap().len(), 1);
        let object = &index["objects"][0];
        assert_eq!(object["indexed_classes"], 4);
        assert_eq!(
            object["sha256"],
            "462148d258913b25c1c5a8944406c009f299aef68cf8a686581d4ab96e9e808f"
        );
        assert_eq!(object["sha1_signature_verified"], false);
        assert_eq!(object["adler32_checksum_verified"], true);
        assert!(object["validation_status"]
            .as_str()
            .unwrap()
            .starts_with("checksum_failed"));
        assert_eq!(object["ownership"], "unknown");
        assert_eq!(object["sources"].as_array().unwrap().len(), 4);
        assert_eq!(
            object["sources"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|s| s["kind"] == "runtime")
                .count(),
            3
        );
        assert_eq!(
            object["sources"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|s| s["kind"] == "static_comparison_reference")
                .count(),
            1
        );
        let rows = bundle.dump_report["local_storage_accounting"]["runtime_observations"]
            .as_array()
            .unwrap();
        assert_eq!(rows.len(), 12);
        let modules = bundle.dump_report["local_storage_accounting"]["elf_module_observations"]
            .as_array()
            .unwrap();
        assert_eq!(modules.len(), 1);
        assert_eq!(modules[0]["complete_file_reconstructed"], false);
        assert_eq!(
            bundle.session_report.as_ref().unwrap()["mobilee_capture_group"]["id"],
            "1379eff3-0f36-411c-8e7e-a2d9a129fa06"
        );
    }
    assert_eq!(
        restored.dump_report["mobilee_archive_coverage"]["status"],
        "partial"
    );
    for (rel, n, h) in &hashes {
        assert_eq!(
            storage_evidence::hash_file(&root.join(rel), *n).as_ref(),
            Some(h)
        );
        assert_eq!(
            storage_evidence::hash_file(&PathBuf::from(&restored.root).join(rel), *n).as_ref(),
            Some(h)
        );
    }
    let summary = serde_json::json!({"archive":output,"archive_bytes":std::fs::metadata(&output).unwrap().len(),"source_paths_verified":hashes.len(),"originals_unchanged":true,"content_index":restored.dump_report["content_dex_class_index"],"accounting":restored.dump_report["local_storage_accounting"],"coverage":restored.dump_report["mobilee_archive_coverage"],"parent":restored.session_report.as_ref().unwrap()["mobilee_capture_group"],"restored_root":restored.root});
    let bytes = serde_json::to_vec(&summary).unwrap();
    assert!(bytes.len() < 2 * 1024 * 1024);
    std::fs::write(std::env::var_os("KSIGHT_I4_RESULT").unwrap(), bytes).unwrap();
}

#[tokio::test]
#[ignore = "explicit retained i4 UI fixture; no device or export"]
async fn approved_i4_existing_archive_ui_fixture() {
    let archive = std::env::var("KSIGHT_I4_ARCHIVE").unwrap();
    let bundle = import_kernsight_evidence_archive(archive.clone())
        .await
        .unwrap();
    assert_eq!(
        bundle.dump_report["content_dex_class_index"]["objects"][0]["sha1_signature_verified"],
        false
    );
    let fixture =
        serde_json::json!({"original":bundle,"reimported":bundle,"reexport_path":archive});
    let bytes = serde_json::to_vec(&fixture).unwrap();
    assert!(bytes.len() < 2 * 1024 * 1024);
    std::fs::write(std::env::var_os("KSIGHT_I4_UI_FIXTURE").unwrap(), bytes).unwrap();
}
