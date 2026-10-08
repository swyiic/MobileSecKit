use super::*;

#[tokio::test]
#[ignore = "explicit retained sealed Linker evidence only; no device or capture"]
async fn retained_linker_records_through_production_directory_import() {
    let source = PathBuf::from(std::env::var_os("ME_LINKER_INTAKE_SOURCE").unwrap());
    let out = PathBuf::from(std::env::var_os("ME_LINKER_INTAKE_OUTPUT").unwrap());
    assert!(source.is_absolute() && out.is_absolute() && !out.exists());
    assert!(!out.starts_with(&source));
    std::fs::create_dir_all(&out).unwrap();
    let guard = session_budget::Guard::install(vec![out.clone()], 16 * 1024 * 1024, 30000).unwrap();
    let launch: Value = serde_json::from_str(
        &read_bounded_text(&source.join("physical-launch.json"), 65536).unwrap(),
    )
    .unwrap();
    let ids: Vec<String> = serde_json::from_str(
        &read_bounded_text(&source.join("first-session-ids.json"), 4096).unwrap(),
    )
    .unwrap();
    assert_eq!(ids.len(), 1);
    let id = &ids[0];
    let relation_path = source
        .join("first-source/spool")
        .join(id)
        .join("capture-relation.json");
    let relation_text = read_bounded_text(&relation_path, 32768).unwrap();
    let envelope: Value = serde_json::from_str(&relation_text).unwrap();
    assert_eq!(envelope["session_id"], *id);
    assert_eq!(envelope["package"], "com.dlxx.mam.Internal");
    let relation = envelope["relation"].clone();
    assert_eq!(relation["parent_id"], launch["relation"]["parent"]);
    assert_eq!(relation["attempt_id"], launch["relation"]["attempt"]);
    assert_eq!(relation["stage_key"], "linker");
    let original_tar = std::fs::read(source.join("first-source.tar")).unwrap();
    let original_sha = format!("{:x}", Sha256::digest(&original_tar));
    let mut paths: Vec<_> = std::fs::read_dir(source.join("first-decoded").join(id))
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| {
            p.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("batch-")
        })
        .collect();
    paths.sort();
    assert!(paths.len() <= 32);
    let mut events = Vec::new();
    let mut builder = SessionReportBuilder::default();
    let mut linker = LinkerObservations::default();
    for path in paths {
        let batch: Message =
            serde_json::from_str(&read_bounded_text(&path, 1024 * 1024).unwrap()).unwrap();
        let Message::EventBatch(batch) = batch else {
            panic!("retained batch type mismatch")
        };
        assert_eq!(batch.session_id.to_string(), *id);
        for event in batch.events {
            assert_eq!(event.header.session_id.to_string(), *id);
            builder.record(&event);
            linker.record(&event);
            events.push(event);
        }
    }
    assert!(events.len() <= 4096);
    let mut report = serde_json::to_value(builder.finish()).unwrap();
    linker.augment(&mut report);
    assert_eq!(report["linker_observations_observed"], 8);
    report["session_id"] = serde_json::json!(id);
    report["mobilee_agent_capture_relation"] = relation.clone();
    report["mobilee_included_sessions"] = serde_json::json!([id]);
    report["mobilee_session_scope"] = serde_json::json!("one sealed independently qualified Linker child; source parent reference retained; no managed four-stage Me parent fabricated");
    let child = out.join("sessions").join(id);
    std::fs::create_dir_all(&child).unwrap();
    session_budget::write_json(child.join("events.json"), &events).unwrap();
    session_budget::write_json(child.join("session-report.json"), &report).unwrap();
    session_budget::write(child.join("capture-relation.json"), relation_text).unwrap();
    session_budget::write_json(out.join("session-report.json"), &report).unwrap();
    session_budget::write_json(out.join("session-index.json"), &serde_json::json!({"scope":"explicit-agent-parent-reference-single-child","parentId":relation["parent_id"],"includedSessions":[id]})).unwrap();
    // Explicit local adapter envelope, not a fabricated agent Dump report.
    session_budget::write_json(out.join("dump-report.json"), &serde_json::json!({"schema_version":"mobilee.local-session-envelope/v1","package":"com.dlxx.mam.Internal","collection_status":"not_collected","artifacts":[],"warnings":["Only original sealed Linker session imported; no Dump or four-stage completion is asserted."]})).unwrap();
    session_budget::write(
        out.join("original-sealed-session-source.tar"),
        &original_tar,
    )
    .unwrap();
    let bundle = import_kernsight_evidence_directory(out.to_string_lossy().into_owned())
        .await
        .unwrap();
    let imported = bundle.session_report.as_ref().unwrap();
    assert_eq!(
        imported["linker_observations"],
        report["linker_observations"]
    );
    assert_eq!(imported["session_id"], *id);
    assert_eq!(imported["mobilee_agent_capture_relation"], relation);
    assert_eq!(bundle.dump_report["collection_status"], "not_collected");
    let managed_parent_boundary = capture_groups::get_local_kernsight_child_report(
        out.to_string_lossy().into_owned(),
        Uuid::parse_str(relation["parent_id"].as_str().unwrap()).unwrap(),
        Uuid::parse_str(id).unwrap(),
    )
    .unwrap_err();
    session_budget::write_json(out.join("production-import-verification.json"), &serde_json::json!({"bundle":bundle,"rawEvents":events.len(),"standaloneChildSessionId":id,"originalParentReference":relation["parent_id"],"managedFourStageParentNotFabricated":true,"managedParentLookupBoundary":managed_parent_boundary,"guiActuallyDisplayed":false,"originalTarSha256":original_sha,"receiptBeforeFinalRecord":guard.receipt()})).unwrap();
    assert_eq!(
        format!(
            "{:x}",
            Sha256::digest(std::fs::read(source.join("first-source.tar")).unwrap())
        ),
        original_sha
    );
    println!("real_linker_production_import_pass events={} hits=8 source_unchanged=true GUI_unverified=true charged={}", events.len(), guard.receipt().admitted_write_bytes);
}
