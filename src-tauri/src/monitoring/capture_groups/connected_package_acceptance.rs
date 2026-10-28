//! Explicit physical acceptance of reported or deliberately selected installed packages.
use super::*;

#[test]
#[ignore = "explicit saved capture metadata verification on connected phone; never launches or recollects"]
fn connected_saved_selected_capture_verification() {
    crate::advanced::initialize_host_environment(None).unwrap();
    assert_eq!(
        std::env::var("ME_CONNECTED_ACCEPTANCE").as_deref(),
        Ok("saved-selected-capture")
    );
    let file = PathBuf::from(std::env::var_os("ME_SAVED_CAPTURE_GROUP").unwrap());
    let out = PathBuf::from(std::env::var_os("ME_CONNECTED_OUTPUT").unwrap());
    assert!(file.is_absolute() && out.is_absolute() && !out.exists());
    let group: Group = serde_json::from_slice(&std::fs::read(file).unwrap()).unwrap();
    assert_eq!(
        group.package,
        std::env::var("ME_CONNECTED_PACKAGE").unwrap()
    );
    assert_eq!(group.serial, std::env::var("ME_CONNECTED_SERIAL").unwrap());
    group.validate().unwrap();
    std::fs::create_dir(&out).unwrap();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let result = runtime.block_on(capture_only_initial_candidates(&group, &out));
    let summary = match &result {
        Ok(value) => value.clone(),
        Err(error) => serde_json::json!({"status":"verification_failed","error":error}),
    };
    std::fs::write(
        out.join("capture-only-result.json"),
        serde_json::to_vec_pretty(&summary).unwrap(),
    )
    .unwrap();
    result.expect("saved capture verification failed; capture unchanged");
}

#[test]
#[ignore = "requires a connected authorized phone and explicit output; launches the selected package"]
fn connected_reported_package_roundtrip() {
    crate::advanced::initialize_host_environment(None).expect("ME host environment");
    assert_eq!(
        std::env::var("ME_CONNECTED_ACCEPTANCE").as_deref(),
        Ok("reported-packages")
    );
    std::thread::Builder::new()
        .name("connected-package-roundtrip".into())
        .stack_size(64 * 1024 * 1024)
        .spawn(|| {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(run())
        })
        .unwrap()
        .join()
        .unwrap();
}

#[test]
#[ignore = "requires explicit selected installed packages, connected phone and fresh output; cold launches only"]
fn connected_selected_installed_package_capture() {
    // Match the GUI startup, including macOS libusb on an ADB server restart.
    crate::advanced::initialize_host_environment(None).expect("ME host environment");
    assert_eq!(
        std::env::var("ME_CONNECTED_ACCEPTANCE").as_deref(),
        Ok("selected-installed-packages")
    );
    assert_eq!(
        std::env::var("ME_CAPTURE_ACCEPTANCE_ONLY").as_deref(),
        Ok("1")
    );
    std::thread::Builder::new()
        .name("connected-selected-package".into())
        .stack_size(64 * 1024 * 1024)
        .spawn(|| {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(run())
        })
        .unwrap()
        .join()
        .unwrap();
}

async fn run() {
    let serial = std::env::var("ME_CONNECTED_SERIAL").unwrap();
    let package = std::env::var("ME_CONNECTED_PACKAGE").unwrap();
    if std::env::var("ME_CONNECTED_ACCEPTANCE").as_deref() == Ok("selected-installed-packages") {
        let selected: Vec<String> =
            serde_json::from_str(&std::env::var("ME_CONNECTED_SELECTED_PACKAGES_JSON").unwrap())
                .unwrap();
        assert!(!selected.is_empty() && selected.len() <= 8);
        assert!(selected.iter().any(|candidate| candidate == &package));
        assert!(
            package.contains('.')
                && package
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'_')
        );
    } else {
        assert!(matches!(
            package.as_str(),
            "uni.UNICA432ED" | "com.example.jmap_cc.hwt"
        ));
    }
    let out = PathBuf::from(std::env::var_os("ME_CONNECTED_OUTPUT").unwrap());
    assert!(out.is_absolute() && !out.exists());
    std::fs::create_dir_all(&out).unwrap();
    let budget_mib = std::env::var("ME_CONNECTED_BUDGET_MIB")
        .ok()
        .map(|value| value.parse::<u64>().expect("invalid explicit test budget"))
        .unwrap_or(8192);
    assert!((4..=16384).contains(&budget_mib));
    // Read the exact UI preset exported by the production TypeScript module.
    // Existing regressions retain their original timing unless explicitly set.
    let timing: Value = std::env::var("ME_CONNECTED_TIMING_JSON")
        .map(|raw| serde_json::from_str(&raw).expect("invalid explicit UI timing preset"))
        .unwrap_or_else(|_| {
            serde_json::json!({"autoL0Seconds":25,"autoL1Seconds":30,"autoLinkerSeconds":20,
            "captureMaxSeconds":600,"l2MaxSeconds":180,"transferMaxSeconds":600,
            "archiveMaxSeconds":180,"importMaxSeconds":180,"maxSessionSeconds":1565})
        });
    let durations: Vec<u64> = ["autoL0Seconds", "autoL1Seconds", "autoLinkerSeconds"]
        .iter()
        .map(|key| timing[key].as_u64().expect("missing observation duration"))
        .collect();
    let request: KernSightCaptureRequest = serde_json::from_value(serde_json::json!({
        "serial":serial,"package":package,"durationSeconds":25,
        "codeOnly":false,"sessionBudget":{"totalBytes":budget_mib * 1048576,"maxSeconds":timing["maxSessionSeconds"]},
        "captureTime":{"maxSeconds":timing["captureMaxSeconds"],"l2MaxSeconds":timing["l2MaxSeconds"]},
        "saveTime":{"transferMaxSeconds":timing["transferMaxSeconds"],"archiveMaxSeconds":timing["archiveMaxSeconds"],"importMaxSeconds":timing["importMaxSeconds"]},
        "files":true,"network":true,"memory":true,"binder":true,
        "inspectMaxBytes":65536,"inspectMaxHits":0
    }))
    .unwrap();
    require_timed_configuration(&request).unwrap();
    let groups = out.join("groups");
    std::fs::create_dir_all(&groups).unwrap();
    let g = begin_group_at(groups.clone(), request, durations, true).unwrap();
    let mut results = Vec::new();
    for key in ["l0", "l1", "dump", "linker"] {
        println!(
            "physical_stage_start package={package} stage={key} parent={}",
            g.id
        );
        let result = run_group_stage_at(groups.clone(), g.id, key.into()).await;
        match result {
            Ok(value) => {
                let stage = value.group.stages.iter().find(|s| s.key == key).unwrap();
                let state = stage.attempts.last().unwrap().state.clone();
                let next = value
                    .group
                    .stages
                    .iter()
                    .skip_while(|s| s.key != key)
                    .nth(1);
                let allowed_partial = matches!(state.as_str(), "partial" | "unavailable")
                    && value.continue_after_partial
                    && next.is_some_and(|next| {
                        (next.key == "dump"
                            && value.continuation_policy.as_deref()
                                == Some("sealed_partial_snapshot"))
                            || (next.launch_after_attach
                                && (state != "unavailable"
                                    || value.continuation_policy.as_deref()
                                        == Some("source_absent_independent_start")))
                    });
                println!("physical_stage_end package={package} stage={key} state={state} error_present={} allowed_partial={allowed_partial}", value.error.is_some());
                results.push(serde_json::to_value(&value).unwrap());
                std::fs::write(
                    out.join("actual-stage-results.json"),
                    serde_json::to_vec_pretty(&results).unwrap(),
                )
                .unwrap();
                std::fs::write(
                    out.join("capture-group.json"),
                    serde_json::to_vec_pretty(&value.group).unwrap(),
                )
                .unwrap();
                if state != "succeeded" && !allowed_partial {
                    break;
                }
            }
            Err(error) => {
                println!("physical_stage_end package={package} stage={key} invocation_failed=true");
                results.push(serde_json::json!({"stage":key,"error":error}));
                std::fs::write(
                    out.join("actual-stage-results.json"),
                    serde_json::to_vec_pretty(&results).unwrap(),
                )
                .unwrap();
                break;
            }
        }
    }
    if std::env::var("ME_REQUIRE_INITIAL_COVERAGE").as_deref() == Ok("complete") {
        let actual = load(&groups, g.id).unwrap();
        assert!(
            actual.stages.iter().all(|stage| stage
                .attempts
                .last()
                .is_some_and(|attempt| attempt.state == "succeeded")),
            "capture completeness not accepted; original stage results and phone evidence retained"
        );
    }
    if std::env::var("ME_CAPTURE_ACCEPTANCE_ONLY").as_deref() == Ok("1") {
        let actual = load(&groups, g.id).unwrap();
        let result = capture_only_initial_candidates(&actual, &out).await;
        let summary = match &result {
            Ok(summary) => summary.clone(),
            Err(error) => {
                serde_json::json!({"status":"capture_only_failed","parentId":actual.id,"package":actual.package,"error":error,"payloadDownloaded":false,"fullImportPerformed":false})
            }
        };
        std::fs::write(
            out.join("capture-only-result.json"),
            serde_json::to_vec_pretty(&summary).unwrap(),
        )
        .unwrap();
        result.expect("capture-only acceptance failed; metadata and exact error retained");
        if std::env::var("ME_REQUIRE_OBSERVATION_CLOCK").as_deref() == Ok("1") {
            let mut clocks = Vec::new();
            for stage in &results {
                for line in stage["result"]["stderr"]
                    .as_str()
                    .unwrap_or_default()
                    .lines()
                {
                    if let Ok(record) = serde_json::from_str::<Value>(line) {
                        if record["schema"] == "kernsight.observation-window/v1" {
                            clocks.push(record);
                        }
                    }
                }
            }
            std::fs::write(
                out.join("observation-clock-verification.json"),
                serde_json::to_vec_pretty(&clocks).unwrap(),
            )
            .unwrap();
            assert_eq!(clocks.len(), 3, "missing effective observation clocks");
            for clock in &clocks {
                let requested = clock["requested_ms"].as_u64().unwrap();
                let actual = clock["elapsed_ms"].as_u64().unwrap();
                assert!(
                    actual >= requested && actual - requested <= 500,
                    "observation clock exceeds 500ms acceptance tolerance: {clock}"
                );
                assert_eq!(clock["shortened"], false);
            }
        }
        return;
    }
    roundtrip(groups, g, out, true).await;
}

/// Independent metadata-only readback after capture. Payload bytes stay on the
/// phone; the agent's inventory hashes are compared with original copy receipts.
async fn capture_only_initial_candidates(g: &Group, out: &Path) -> Result<Value, String> {
    g.validate()?;
    if g.cancel_requested
        || !g.stages.iter().all(|stage| {
            stage
                .attempts
                .last()
                .is_some_and(|attempt| attempt.state == "succeeded")
        })
    {
        return Err(
            "capture-only requires all four stages to succeed; no payload was pulled".into(),
        );
    }
    let dump = g
        .stages
        .iter()
        .find(|stage| stage.key == "dump")
        .ok_or("Dump stage missing")?;
    let attempt = dump.attempts.last().ok_or("Dump attempt missing")?;
    let remote = attempt
        .remote_artifact_root
        .as_ref()
        .ok_or("exact Dump root missing")?;
    let expected = dump_artifact_reference(g, &attempt.relation, true, false)?
        .ok_or("exact Dump root unconfirmed")?;
    if remote != &expected {
        return Err("Dump root does not match the exact parent/stage/attempt".into());
    }
    let lifecycle = attempt
        .remote_lifecycle
        .as_ref()
        .ok_or("Dump lifecycle missing")?;
    validate_remote_lifecycle(lifecycle, &attempt.relation)?;
    if !remote_terminal_confirmed(lifecycle) {
        return Err("Dump producer termination and cleanup unconfirmed".into());
    }
    let paths = runtime_paths_from_group(Some(g))?;
    let script = runtime_paths::route(
        paths.as_ref(),
        &format!(
            "{KSIGHT_AGENT} evidence-inventory --root {}",
            crate::shell_quote(remote)
        ),
    )?;
    let output = run_evidence_inventory(&g.serial, &script).await?;
    if output.code != Some(0) {
        return Err(format!(
            "exact Dump evidence inventory failed: {:?}",
            output.code
        ));
    }
    if output.stdout.len() > 32 * 1024 * 1024 {
        return Err("inventory exceeds metadata envelope".into());
    }
    let inventory: Value = serde_json::from_str(&output.stdout).map_err(|e| e.to_string())?;
    if inventory["schema"] != "kernsight.evidence-inventory/v1" {
        return Err("inventory schema unconfirmed".into());
    }
    let mut files = BTreeMap::<String, Value>::new();
    let mut logical_bytes = 0_u64;
    for row in inventory["files"]
        .as_array()
        .ok_or("inventory files missing")?
    {
        let relative = row["path"].as_str().ok_or("inventory path missing")?;
        validate_evidence_relative_path(relative)?;
        let bytes = row["bytes"].as_u64().ok_or("inventory length missing")?;
        let hash = row["sha256"].as_str().ok_or("inventory hash missing")?;
        if hash.len() != 64
            || !hash
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        {
            return Err("inventory SHA256 invalid".into());
        }
        logical_bytes = logical_bytes
            .checked_add(bytes)
            .ok_or("inventory byte overflow")?;
        if logical_bytes > MAX_EVIDENCE_ARCHIVE_BYTES
            || files.len() >= 100_000
            || files.insert(relative.to_owned(), row.clone()).is_some()
        {
            return Err("inventory duplicate or size limit".into());
        }
    }
    if inventory["logical_bytes"].as_u64() != Some(logical_bytes) {
        return Err("inventory logical byte count mismatch".into());
    }
    std::fs::write(out.join("device-evidence-inventory.json"), output.stdout)
        .map_err(|e| e.to_string())?;
    let metadata_root = out.join("capture-only-metadata");
    std::fs::create_dir(&metadata_root).map_err(|e| e.to_string())?;
    let _guard =
        session_budget::Guard::install(vec![metadata_root.clone()], 32 * 1024 * 1024, 120_000)
            .map_err(|e| e.to_string())?;
    let sources = files
        .values()
        .filter(|row| {
            row["path"].as_str().is_some_and(|path| {
                path.starts_with("runtime/bound-source-")
                    && path.ends_with(".json")
                    && Path::new(path).components().count() == 2
            })
        })
        .cloned()
        .collect::<Vec<_>>();
    if sources.is_empty()
        || sources.len() > 128
        || sources
            .iter()
            .any(|row| row["bytes"].as_u64().unwrap() > 2 * 1024 * 1024)
    {
        return Err("source metadata missing or exceeds bounded protocol".into());
    }
    batch_transfer::transfer(&g.serial, remote, &metadata_root, &sources, BTreeMap::new()).await?;
    std::fs::rename(
        metadata_root.join("batch-transfer-receipt.json"),
        metadata_root.join("source-metadata-transfer-receipt.json"),
    )
    .map_err(|e| e.to_string())?;
    let mut manifests = BTreeMap::<String, Vec<(String, Value)>>::new();
    for row in &sources {
        let relative = row["path"].as_str().unwrap();
        let note: Value = serde_json::from_slice(
            &std::fs::read(metadata_root.join(relative)).map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?;
        if note["schema"] != "kernsight.bound-code-copy/v1"
            || note["source"]["package"] != g.package
        {
            return Err("source metadata schema or package mismatch".into());
        }
        let pid = note["source"]["pid"].as_u64().ok_or("source PID missing")?;
        let manifest = note["candidate_manifest"]
            .as_str()
            .ok_or("source candidate manifest missing")?;
        let prefix = format!("bound-candidates-{pid}-");
        let id = manifest
            .strip_prefix(&prefix)
            .ok_or("foreign candidate manifest")?;
        if Uuid::parse_str(id).is_err() {
            return Err("candidate manifest UUID invalid".into());
        }
        manifests
            .entry(manifest.to_owned())
            .or_default()
            .push((relative.to_owned(), note));
    }
    let candidates = files
        .values()
        .filter(|row| {
            row["path"].as_str().is_some_and(|path| {
                path.ends_with(".json")
                    && Path::new(path).components().count() == 2
                    && manifests
                        .keys()
                        .any(|manifest| path.starts_with(&format!("runtime/{manifest}-")))
            })
        })
        .cloned()
        .collect::<Vec<_>>();
    if candidates.is_empty()
        || candidates.len() > 1024
        || candidates
            .iter()
            .any(|row| row["bytes"].as_u64().unwrap() > 256 * 1024)
    {
        return Err("named candidate metadata missing or exceeds bounded protocol".into());
    }
    batch_transfer::transfer(
        &g.serial,
        remote,
        &metadata_root,
        &candidates,
        BTreeMap::new(),
    )
    .await?;
    let mut summaries = Vec::new();
    let mut verified_ranges = 0_u64;
    let mut verified_bytes = 0_u64;
    for (manifest, notes) in manifests {
        let page =
            bound_source_page::read_page(&metadata_root, &g.package, &notes[0].0, 0, 1, None)?;
        let coverage = &page["candidateCoverage"];
        if coverage["status"] != "available"
            || coverage["candidateManifest"] != manifest
            || coverage["eligibleRanges"].as_u64().unwrap_or(0) == 0
            || coverage["remainingBytes"] != 0
            || coverage["unattemptedRanges"] != 0
            || coverage["excludedRanges"] != 0
            || coverage["rejectedRanges"] != 0
            || coverage["sourceShardCount"].as_u64() != Some(notes.len() as u64)
        {
            return Err(format!(
                "initial candidate coverage not complete: {coverage}"
            ));
        }
        let mut ranges = 0_u64;
        let mut bytes = 0_u64;
        for (_, note) in &notes {
            if note["partial"] != false || note["candidate_result"]["unattempted_state"] != "none" {
                return Err("source report remains partial or unattempted".into());
            }
            for record in note["records"].as_array().ok_or("source records missing")? {
                let raw = record["raw_evidence"]
                    .as_str()
                    .ok_or("raw range name missing")?;
                if raw.contains(['/', '\\'])
                    || !raw.ends_with(".code")
                    || record["source"] != note["source"]
                {
                    return Err("raw range path or source identity mismatch".into());
                }
                let file = files
                    .get(&format!("runtime/{raw}"))
                    .ok_or("raw range absent from remote inventory")?;
                if record["admitted"] != true
                    || record["read"]["read_status"] != "complete"
                    || record["read"]["write_status"] != "complete"
                    || file["bytes"] != record["read"]["actual_length"]
                    || file["sha256"] != record["read"]["sha256"]
                {
                    return Err(
                        "remote actual range hash/length differs from admitted copy receipt".into(),
                    );
                }
                ranges += 1;
                bytes = bytes
                    .checked_add(file["bytes"].as_u64().unwrap())
                    .ok_or("range bytes overflow")?;
            }
        }
        if coverage["admittedRanges"].as_u64() != Some(ranges)
            || coverage["admittedBytes"].as_u64() != Some(bytes)
        {
            return Err("coverage totals differ from remotely verified range receipts".into());
        }
        verified_ranges += ranges;
        verified_bytes = verified_bytes
            .checked_add(bytes)
            .ok_or("verified bytes overflow")?;
        summaries.push(coverage.clone());
    }
    Ok(
        serde_json::json!({"status":"capture_only_initial_candidates_verified","parentId":g.id,"package":g.package,
        "groupState":g.state,"dumpRelation":attempt.relation,"remoteDumpRoot":remote,"metadataRoot":metadata_root,
        "remoteInventoryFiles":files.len(),"remoteInventoryLogicalBytes":logical_bytes,"remoteVerifiedRanges":verified_ranges,
        "remoteVerifiedBytes":verified_bytes,"candidateCoverage":summaries,"payloadDownloaded":false,"fullImportPerformed":false,
        "verification":"source/candidate metadata transferred with exact SHA256 and length; admitted .code receipts matched to fresh remote agent inventory SHA256 and length; payload not independently read back on host",
        "scope":"all initial qualified main-process candidate mappings only; not all App data, complete DEX/SO reconstruction or globally consistent memory"}),
    )
}

#[test]
#[ignore = "explicit phone readback for either reported package; does not launch or recollect"]
fn connected_saved_report_roundtrip() {
    assert_eq!(
        std::env::var("ME_CONNECTED_ACCEPTANCE").as_deref(),
        Ok("saved-reports")
    );
    std::thread::Builder::new()
        .stack_size(64 * 1024 * 1024)
        .spawn(|| {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async {
                    let id =
                        Uuid::parse_str(&std::env::var("ME_CONNECTED_PARENT").unwrap()).unwrap();
                    let groups = PathBuf::from(std::env::var_os("ME_CONNECTED_GROUPS").unwrap());
                    let g = load(&groups, id).unwrap();
                    assert!(matches!(
                        g.package.as_str(),
                        "uni.UNICA432ED" | "com.example.jmap_cc.hwt"
                    ));
                    let out = PathBuf::from(std::env::var_os("ME_CONNECTED_OUTPUT").unwrap());
                    assert!(out.is_absolute() && !out.exists());
                    std::fs::create_dir_all(&out).unwrap();
                    roundtrip(groups, g, out, false).await;
                });
        })
        .unwrap()
        .join()
        .unwrap();
}

async fn roundtrip(groups: PathBuf, g: Group, out: PathBuf, charge_parent: bool) {
    let serial = g.serial.clone();
    let package = g.package.clone();
    let archive = out.join(format!("{package}.mee"));
    println!("physical_transfer_start package={package}");
    let local_intake = std::env::var_os("ME_CONNECTED_COMPLETE_INTAKE").map(PathBuf::from);
    let exported = if let Some(root) = local_intake.as_ref() {
        assert!(!charge_parent && root.is_absolute());
        let receipt: Value = serde_json::from_slice(
            &std::fs::read(root.join("batch-transfer-receipt.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(
            receipt["complete"], true,
            "requires a verified complete phone intake"
        );
        println!("physical_intake_mode=previously_completed_phone_transfer package={package}");
        archive_objects::write_local_retained(root, &archive)
            .and_then(|_| received_evidence_bundle(root, &package))
    } else {
        pull_kernsight_package_archive_at(
            Some(groups.clone()),
            Some(g.id),
            serial,
            package.clone(),
            archive.to_string_lossy().into_owned(),
            charge_parent,
        )
        .await
    };
    let bundle = match exported {
        Ok(bundle) => bundle,
        Err(error) => {
            std::fs::write(
                out.join("roundtrip-result.json"),
                serde_json::to_vec_pretty(
                    &serde_json::json!({"status":"transfer_failed","error":error}),
                )
                .unwrap(),
            )
            .unwrap();
            panic!("physical transfer failed; exact error retained in roundtrip-result.json");
        }
    };
    println!(
        "physical_transfer_end package={package} archive_bytes={}",
        std::fs::metadata(&archive).unwrap().len()
    );
    std::fs::write(
        out.join("imported-dump-report.json"),
        serde_json::to_vec_pretty(&bundle.dump_report).unwrap(),
    )
    .unwrap();
    println!("physical_reopen_start package={package}");
    let reopened = import_kernsight_evidence_archive(archive.to_string_lossy().into_owned())
        .await
        .unwrap();
    let analysis = out.join("external-analysis");
    export_kernsight_analysis_directory(
        reopened.root.clone(),
        analysis.to_string_lossy().into_owned(),
    )
    .await
    .unwrap();
    let mut inventory = Vec::new();
    let mut pending = vec![analysis.clone()];
    while let Some(dir) = pending.pop() {
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                pending.push(path);
                continue;
            }
            let relative = path
                .strip_prefix(&analysis)
                .unwrap()
                .to_string_lossy()
                .into_owned();
            let bytes = std::fs::metadata(&path).unwrap().len();
            let mut file = File::open(&path).unwrap();
            let mut magic = [0u8; 8];
            let n = std::io::Read::read(&mut file, &mut magic).unwrap();
            let kind = if magic[..n].starts_with(b"dex\n") {
                "dex"
            } else if magic[..n].starts_with(b"\x7fELF") {
                "elf"
            } else {
                "other"
            };
            inventory.push(serde_json::json!({"path":relative,"bytes":bytes,"magicType":kind}));
        }
    }
    let dex = inventory.iter().filter(|f| f["magicType"] == "dex").count();
    let elf = inventory.iter().filter(|f| f["magicType"] == "elf").count();
    let final_group = load(&groups, g.id).unwrap();
    std::fs::write(
        out.join("capture-group-after-export.json"),
        serde_json::to_vec_pretty(&final_group).unwrap(),
    )
    .unwrap();
    std::fs::write(
        out.join("external-file-inventory.json"),
        serde_json::to_vec_pretty(&inventory).unwrap(),
    )
    .unwrap();
    std::fs::write(out.join("roundtrip-result.json"), serde_json::to_vec_pretty(&serde_json::json!({
        "status":"transferred_reopened_exported","package":package,"parentId":g.id,
        "groupState":final_group.state,"archive":archive,"analysisDirectory":analysis,
        "fileCount":inventory.len(),"dexMagicFiles":dex,"elfMagicFiles":elf,
        "intakeMode":if local_intake.is_some() {"previously_completed_phone_transfer"} else {"fresh_phone_transfer"},
        "note":"transport success is not complete runtime coverage; inspect original stage and bound-source reports"
    })).unwrap()).unwrap();
    println!(
        "physical_roundtrip_end package={package} group={} files={} dex={dex} elf={elf}",
        final_group.state,
        inventory.len()
    );
    assert!(
        dex > 0 && elf > 0,
        "external tool readable DEX/ELF required"
    );
    if std::env::var("ME_REQUIRE_INITIAL_COVERAGE").as_deref() == Ok("complete") {
        require_complete_initial_candidates(&analysis, &out);
    }
}

fn require_complete_initial_candidates(root: &Path, out: &Path) {
    let runtime = root.join("runtime");
    let mut groups = BTreeMap::<String, Vec<Value>>::new();
    for entry in std::fs::read_dir(&runtime).unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_name().unwrap().to_string_lossy();
        if name.starts_with("bound-source-") && name.ends_with(".json") {
            let note: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
            let manifest = note["candidate_manifest"].as_str().unwrap().to_owned();
            groups.entry(manifest).or_default().push(note);
        }
    }
    assert!(!groups.is_empty(), "source notes must actually exist");
    let mut summaries = Vec::new();
    for (manifest, mut notes) in groups {
        notes.sort_by_key(|n| n["shard_index"].as_u64().unwrap_or(0));
        let first = &notes[0];
        assert_eq!(
            first["shard_count"].as_u64().unwrap_or(1) as usize,
            notes.len()
        );
        let mut candidates = BTreeSet::new();
        let mut eligible = None;
        let mut shards = std::fs::read_dir(&runtime)
            .unwrap()
            .map(|e| e.unwrap().path())
            .filter(|p| {
                p.file_name()
                    .unwrap()
                    .to_string_lossy()
                    .starts_with(&format!("{manifest}-"))
            })
            .collect::<Vec<_>>();
        shards.sort();
        for (index, path) in shards.iter().enumerate() {
            let shard: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
            assert_eq!(shard["shard_index"].as_u64(), Some(index as u64));
            let count = shard["eligible_count"].as_u64().unwrap();
            assert!(eligible.is_none_or(|prior| prior == count));
            eligible = Some(count);
            for row in shard["candidates"].as_array().unwrap() {
                assert_eq!(row["rank"].as_u64(), Some(candidates.len() as u64));
                assert!(candidates
                    .insert((row["start"].as_u64().unwrap(), row["end"].as_u64().unwrap())));
            }
        }
        assert_eq!(eligible, Some(candidates.len() as u64));
        let mut actual = BTreeSet::new();
        let mut bytes = 0u64;
        for (index, note) in notes.iter().enumerate() {
            assert_eq!(note["source"], first["source"]);
            assert_eq!(note["shard_index"].as_u64().unwrap_or(0), index as u64);
            assert_eq!(note["partial"], false);
            assert_eq!(note["candidate_result"]["unattempted_state"], "none");
            for row in note["records"].as_array().unwrap() {
                assert_eq!(row["admitted"], true);
                assert_eq!(row["read"]["read_status"], "complete");
                assert_eq!(row["read"]["write_status"], "complete");
                let start = row["mapping"]["start"].as_u64().unwrap();
                let end = row["mapping"]["end"].as_u64().unwrap();
                assert!(actual.insert((start, end)));
                assert_eq!(row["read"]["actual_length"].as_u64(), Some(end - start));
                assert_eq!(
                    std::fs::metadata(runtime.join(row["raw_evidence"].as_str().unwrap()))
                        .unwrap()
                        .len(),
                    end - start
                );
                bytes += end - start;
            }
        }
        assert_eq!(
            actual, candidates,
            "every initial candidate must be copied exactly once"
        );
        summaries.push(serde_json::json!({"candidateManifest":manifest,"source":first["source"],"candidateRanges":candidates.len(),"copiedRanges":actual.len(),"copiedBytes":bytes,"unattemptedRanges":0,"rejectedRanges":0,"scope":"initial qualified main-process candidate mappings only; not all App data"}));
    }
    std::fs::write(
        out.join("coverage-acceptance.json"),
        serde_json::to_vec_pretty(&summaries).unwrap(),
    )
    .unwrap();
    println!(
        "physical_initial_candidate_coverage=complete sources={}",
        summaries.len()
    );
}
