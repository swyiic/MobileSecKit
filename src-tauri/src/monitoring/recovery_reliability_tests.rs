use super::*;
#[tokio::test]
async fn invalid_metadata_import_preserves_preexisting_verified_archive_cache() {
    let root = std::env::temp_dir().join(format!("recovery-owned-{}", Uuid::new_v4()));
    std::fs::create_dir(&root).unwrap();
    std::fs::write(
        root.join("dump-report.json"),
        b"{\"package\":\"org.example.fixture\"}",
    )
    .unwrap();
    std::fs::write(root.join("capture-group.json"), b"{\"schema\":\"broken\"}").unwrap();
    std::fs::write(root.join("raw.bin"), vec![7u8; 4096]).unwrap();
    let archive = root.with_extension("mee");
    archive_objects::write(&root, &archive).unwrap();
    let restored = archive_objects::restore(&archive).unwrap();
    let before = std::fs::read(restored.join("raw.bin")).unwrap();
    assert!(
        import_kernsight_evidence_archive(archive.to_string_lossy().into_owned())
            .await
            .is_err()
    );
    assert_eq!(
        std::fs::read(restored.join("raw.bin"))
            .expect("semantic import failure must not remove previously verified cache"),
        before
    );
}

fn owned_metadata_view(source: &Path, runtime: bool) -> PathBuf {
    let root = std::env::temp_dir().join(format!("recovery-view-{}", Uuid::new_v4()));
    for (path, rel, _) in collect_archive_files(source).unwrap() {
        if !runtime && rel.starts_with("runtime/") {
            continue;
        }
        let target = root.join(&rel);
        std::fs::create_dir_all(target.parent().unwrap()).unwrap();
        if rel.ends_with(".code") {
            std::fs::hard_link(path, target).unwrap();
        } else {
            std::fs::copy(path, target).unwrap();
        }
    }
    root
}
#[tokio::test]
#[ignore = "explicit read-only retained Reqable/i4 archives; isolated cache; no device"]
async fn real_archives_failure_recovery_is_consistent() {
    let config: Value =
        serde_json::from_str(&std::env::var("ME_RECOVERY_FIXTURES").unwrap()).unwrap();
    let mut summaries = Vec::new();
    for item in config.as_array().unwrap() {
        let archive = PathBuf::from(item["archive"].as_str().unwrap());
        let source = PathBuf::from(item["source"].as_str().unwrap());
        let archive_bytes = std::fs::metadata(&archive).unwrap().len();
        let archive_hash = storage_evidence::hash_file(&archive, archive_bytes).unwrap();
        let restored = archive_objects::restore_from_export_source(&archive, &source).unwrap();
        let first = import_kernsight_evidence_archive(archive.to_string_lossy().into_owned())
            .await
            .unwrap();
        let second = import_kernsight_evidence_archive(archive.to_string_lossy().into_owned())
            .await
            .unwrap();
        assert_eq!(first.root, second.root);
        assert_eq!(first.file_count, second.file_count);
        assert_eq!(first.total_bytes, second.total_bytes);
        assert_eq!(
            first.dump_report["local_storage_accounting"],
            second.dump_report["local_storage_accounting"]
        );
        assert_eq!(
            first.dump_report["content_dex_class_index"],
            second.dump_report["content_dex_class_index"]
        );
        assert_eq!(first.session_report, second.session_report);
        let original = first.dump_report["local_storage_accounting"]["verified_code_unique_bytes"]
            .as_u64()
            .unwrap();
        assert!(original > 0);
        let missing = owned_metadata_view(&restored, false);
        let absent = import_kernsight_evidence_directory(missing.to_string_lossy().into_owned())
            .await
            .unwrap();
        assert_eq!(
            absent.dump_report["local_storage_accounting"]["verified_code_unique_bytes"],
            0
        );
        assert_eq!(
            absent.session_report.as_ref().unwrap()["mobilee_capture_group"]["state"],
            "partial"
        );
        let damaged = owned_metadata_view(&restored, true);
        let note = collect_archive_files(&damaged)
            .unwrap()
            .into_iter()
            .find(|(path, rel, _)| {
                rel.contains("bound-source-")
                    && serde_json::from_slice::<Value>(&std::fs::read(path).unwrap()).unwrap()
                        ["records"]
                        .as_array()
                        .is_some_and(|r| !r.is_empty())
            })
            .unwrap()
            .0;
        let mut value: Value = serde_json::from_slice(&std::fs::read(&note).unwrap()).unwrap();
        value["records"][0]["read"]["sha256"] = serde_json::json!("0".repeat(64));
        value["records"]
            .as_array_mut()
            .unwrap()
            .push(serde_json::json!(42));
        std::fs::write(note, serde_json::to_vec(&value).unwrap()).unwrap();
        let partial = import_kernsight_evidence_directory(damaged.to_string_lossy().into_owned())
            .await
            .unwrap();
        let ledger = &partial.dump_report["local_storage_accounting"];
        assert!(ledger["unverified_observations"].as_u64().unwrap() > 0);
        assert!(ledger["verified_code_unique_bytes"].as_u64().unwrap() > 0);
        assert!(ledger["verified_code_unique_bytes"].as_u64().unwrap() < original);
        assert_eq!(
            partial.session_report.as_ref().unwrap()["mobilee_capture_group"]["state"],
            "partial"
        );
        let foreign = owned_metadata_view(&restored, false);
        let path = foreign.join("capture-group.json");
        let mut group: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        group["id"] = serde_json::json!(Uuid::new_v4());
        std::fs::write(path, serde_json::to_vec(&group).unwrap()).unwrap();
        assert!(
            import_kernsight_evidence_directory(foreign.to_string_lossy().into_owned())
                .await
                .is_err()
        );
        assert_eq!(
            storage_evidence::hash_file(&archive, archive_bytes).unwrap(),
            archive_hash
        );
        summaries.push(serde_json::json!({"archive":archive,"archive_sha256":archive_hash,"restored":restored,"repeated_import_same_root_counts_index_parent":true,"missing_runtime_verified_bytes":0,"original_verified_bytes":original,"bad_record_verified_bytes":ledger["verified_code_unique_bytes"],"bad_record_unverified":ledger["unverified_observations"],"foreign_parent_refused":true,"parent_state":"partial","original_archive_unchanged":true}));
    }
    std::fs::write(
        std::env::var("ME_RECOVERY_RESULT").unwrap(),
        serde_json::to_vec_pretty(&summaries).unwrap(),
    )
    .unwrap();
}

#[test]
fn corrupt_object_is_refused_without_an_unreferenced_partial_cache() {
    let root = std::env::temp_dir().join(format!("recovery-corrupt-{}", Uuid::new_v4()));
    std::fs::create_dir(&root).unwrap();
    std::fs::write(
        root.join("dump-report.json"),
        b"{\"package\":\"org.example.fixture\"}",
    )
    .unwrap();
    std::fs::write(root.join("raw.bin"), vec![7u8; 4096]).unwrap();
    let archive = root.with_extension("mee");
    archive_objects::write(&root, &archive).unwrap();
    let damaged = root.with_extension("damaged.mee");
    let mut input = ZipArchive::new(File::open(&archive).unwrap()).unwrap();
    let mut output = ZipWriter::new(File::create(&damaged).unwrap());
    for i in 0..input.len() {
        let mut entry = input.by_index(i).unwrap();
        let name = entry.name().to_owned();
        let mut bytes = Vec::new();
        entry.read_to_end(&mut bytes).unwrap();
        if bytes.len() == 4096 {
            bytes[0] ^= 1;
        }
        output
            .start_file(name, SimpleFileOptions::default())
            .unwrap();
        output.write_all(&bytes).unwrap();
    }
    output.finish().unwrap();
    let hash =
        storage_evidence::hash_file(&damaged, std::fs::metadata(&damaged).unwrap().len()).unwrap();
    let staging = std::env::temp_dir().join(format!("mobilee-objects-{hash}"));
    assert!(archive_objects::restore(&damaged)
        .unwrap_err()
        .contains("hash"));
    assert!(!staging.exists());
    assert_eq!(
        std::fs::read(root.join("raw.bin")).unwrap(),
        vec![7u8; 4096]
    );
}

#[test]
fn fresh_restore_insufficient_import_budget_is_failure_without_partial_cache() {
    let root = std::env::temp_dir().join(format!("recovery-budget-{}", Uuid::new_v4()));
    std::fs::create_dir(&root).unwrap();
    std::fs::write(
        root.join("dump-report.json"),
        b"{\"package\":\"org.example.fixture\"}",
    )
    .unwrap();
    std::fs::write(root.join("raw.bin"), vec![9u8; 4096]).unwrap();
    std::fs::write(
        root.join("archive-output-limits.json"),
        b"{\"archive_bytes\":1048576,\"import_bytes\":65792,\"max_ms\":30000}",
    )
    .unwrap();
    let archive = root.with_extension("mee");
    archive_objects::write(&root, &archive).unwrap();
    let hash =
        storage_evidence::hash_file(&archive, std::fs::metadata(&archive).unwrap().len()).unwrap();
    let staging = std::env::temp_dir().join(format!("mobilee-objects-{hash}"));
    assert!(archive_objects::restore(&archive).is_err());
    assert!(!staging.exists());
    assert!(root.join("raw.bin").is_file());
}
