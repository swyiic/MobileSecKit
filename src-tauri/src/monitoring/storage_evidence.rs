//! Read-only local evidence accounting; old schema does not imply verified contents.
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::Read,
    path::Path,
};

pub(super) fn account(root: &Path, files: &[(String, u64)]) -> Value {
    let mut logical = 0_u64;
    let mut inode_bytes = 0_u64;
    let mut allocated = 0_u64;
    let mut unknown_metadata = 0_u64;
    #[cfg(unix)]
    let mut inodes = BTreeSet::<(u64, u64)>::new();
    let mut categories = BTreeMap::<String, u64>::new();
    for (path, _) in files {
        match fs::symlink_metadata(root.join(path)) {
            Ok(m) if m.is_file() => {
                logical += m.len();
                *categories
                    .entry(path.split('/').next().unwrap_or("report").to_owned())
                    .or_default() += m.len();
                #[cfg(unix)]
                {
                    use std::os::unix::fs::MetadataExt;
                    if inodes.insert((m.dev(), m.ino())) {
                        inode_bytes += m.len();
                        allocated += m.blocks() * 512;
                    }
                }
                #[cfg(not(unix))]
                {
                    inode_bytes += m.len();
                    allocated += m.len();
                }
            }
            _ => unknown_metadata += 1,
        }
    }
    let known = files
        .iter()
        .map(|(p, n)| (p.as_str(), *n))
        .collect::<BTreeMap<_, _>>();
    let mut observations = Vec::new();
    let mut omitted = 0;
    let mut hash_budget = 64 * 1024 * 1024_u64;
    let mut verified_paths = BTreeMap::<String, (String, u64)>::new();
    let mut failures = 0;
    for (path, len) in files
        .iter()
        .filter(|(p, _)| p.starts_with("code-evidence/") && p.ends_with(".json"))
    {
        if observations.len() >= 256 || *len > 32768 {
            omitted += 1;
            continue;
        }
        let value = fs::read(root.join(path))
            .ok()
            .and_then(|b| serde_json::from_slice::<Value>(&b).ok());
        let Some(mut note) = value else {
            failures += 1;
            continue;
        };
        if note["schema"] != "kernsight.apk-member-evidence/v1" {
            failures += 1;
            continue;
        }
        let relative = note["relative_path"].as_str().unwrap_or("").to_owned();
        let expected = note["sha256"].as_str().unwrap_or("").to_owned();
        let bytes = note["bytes"].as_u64().unwrap_or(u64::MAX);
        let code_path = ["apk-dex/", "readable-dex/", "lib/", "apk-assets/"]
            .iter()
            .any(|prefix| relative.starts_with(prefix))
            || (!relative.contains('/')
                && ["dex", "so"]
                    .iter()
                    .any(|ext| Path::new(&relative).extension().is_some_and(|e| e == *ext)));
        let valid = code_path
            && known.get(relative.as_str()) == Some(&bytes)
            && expected.len() == 64
            && note["source_complete"] == true
            && matches!(
                note["write_status"].as_str(),
                Some("hard_link" | "existing_verified")
            );
        let verified = if valid && verified_paths.get(&relative) == Some(&(expected.clone(), bytes))
        {
            true
        } else if valid && bytes <= hash_budget {
            hash_budget -= bytes;
            hash_file(&root.join(&relative), bytes).is_some_and(|s| s == expected)
        } else {
            false
        };
        if verified {
            verified_paths.insert(relative.clone(), (expected, bytes));
        } else {
            failures += 1;
        }
        note["local_content_status"] = json!(if verified {
            "complete_file_hash_verified"
        } else {
            "unknown_or_failed"
        });
        // A ZIP source is a producer assertion; local verification above covers retained file bytes only.
        note["apk_member_rechecked_locally"] = json!(false);
        observations.push(note);
    }
    let mut runtime = Vec::new();
    let mut source_diagnostics = Vec::new();
    let mut source_count = 0_usize;
    let mut source_omitted = 0_usize;
    let mut inspections = BTreeMap::<String, Value>::new();
    let mut inspection_budget = 64 * 1024 * 1024_u64;
    let mut class_index_budget = 1024 * 1024_usize;
    for (path, len) in files.iter().filter(|(p, _)| {
        Path::new(p)
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.starts_with("bound-source-") && n.ends_with(".json"))
    }) {
        if source_count >= 256 {
            source_omitted += 1;
            omitted += 1;
            continue;
        }
        source_count += 1;
        let mut diagnostic = json!({"source_report":path,"status":"accepted","records_seen":0,"invalid_records":0,"omitted_records":0,"byte_limit":65536});
        let result = (|| -> Result<Value, &'static str> {
            if *len > 65536 {
                return Err("source_byte_limit");
            }
            if !safe_local_file(root, path) {
                return Err("unsafe_or_missing_source");
            }
            let file = fs::File::open(root.join(path)).map_err(|_| "source_read_failed")?;
            let mut bytes = Vec::new();
            file.take(65537)
                .read_to_end(&mut bytes)
                .map_err(|_| "source_read_failed")?;
            if bytes.len() > 65536 {
                return Err("source_byte_limit");
            }
            let note: Value =
                serde_json::from_slice(&bytes).map_err(|_| "invalid_or_truncated_json")?;
            if note["schema"] != "kernsight.bound-code-copy/v1" {
                return Err("unknown_source_schema");
            }
            if !note["records"].is_array() {
                return Err("missing_or_invalid_records");
            }
            Ok(note)
        })();
        let note = match result {
            Ok(note) => note,
            Err(reason) => {
                diagnostic["status"] = json!(reason);
                failures += 1;
                source_diagnostics.push(diagnostic);
                continue;
            }
        };
        let records = note["records"].as_array().unwrap();
        diagnostic["records_seen"] = json!(records.len());
        let mut invalid_records = 0_usize;
        let mut omitted_records = 0_usize;
        for record in records {
            if runtime.len() >= 256 {
                omitted += 1;
                omitted_records += 1;
                continue;
            }
            if !record.is_object() {
                failures += 1;
                invalid_records += 1;
                continue;
            }
            let raw = record["raw_evidence"].as_str().unwrap_or("");
            let relative = Path::new(path)
                .parent()
                .unwrap_or(Path::new(""))
                .join(raw)
                .to_string_lossy()
                .into_owned();
            let read = &record["read"];
            let bytes = read["actual_length"].as_u64();
            let expected = read["sha256"].as_str().unwrap_or("");
            let source = &record["source"];
            let identity_known = source == &note["source"]
                && source["package"].as_str().is_some_and(|v| !v.is_empty())
                && source["pid"].as_u64().is_some_and(|v| v > 0)
                && source["birth_ns"].as_u64().is_some_and(|v| v > 0)
                && source["uid"].as_u64().is_some()
                && source["exec_id"].as_u64().is_some()
                && source["boot_id"].as_str().is_some_and(|v| !v.is_empty());
            let range_known = (|| {
                let start = record["mapping"]["start"].as_u64()?;
                let end = record["mapping"]["end"].as_u64()?;
                let request = read["requested_length"].as_u64()?;
                let actual = bytes?;
                let request_start = read["requested_start"].as_u64()?;
                let actual_start = read["actual_start"].as_u64()?;
                Some(
                    end > start
                        && request > 0
                        && actual == request
                        && request_start >= start
                        && actual_start == request_start
                        && request_start.checked_add(request)? <= end,
                )
            })()
            .unwrap_or(false);
            let parent = Path::new(path).parent().unwrap_or(Path::new(""));
            let code_scope = parent.as_os_str().is_empty() || parent == Path::new("runtime");
            let safe_raw = code_scope
                && !raw.is_empty()
                && !raw.contains('/')
                && !raw.contains('\\')
                && raw.starts_with("bound-")
                && raw.ends_with(".code")
                && safe_local_file(root, &relative);
            let valid = identity_known
                && range_known
                && safe_raw
                && record["admitted"] == true
                && read["admission"] == "qualified_live_copy"
                && read["read_status"] == "complete"
                && read["write_status"] == "complete"
                && read.get("read_error").is_some_and(Value::is_null)
                && read.get("write_error").is_some_and(Value::is_null)
                && read["torn"].as_bool().is_some()
                && read["paused"].as_bool().is_some()
                && expected.len() == 64
                && expected.bytes().all(|b| b.is_ascii_hexdigit())
                && bytes.is_some_and(|n| known.get(relative.as_str()) == Some(&n));
            let verified = if valid
                && bytes.is_some_and(|n| {
                    verified_paths.get(&relative) == Some(&(expected.to_owned(), n))
                }) {
                true
            } else if valid && bytes.is_some_and(|n| n <= hash_budget) {
                let n = bytes.unwrap();
                hash_budget -= n;
                hash_file(&root.join(&relative), n).is_some_and(|h| h == expected)
            } else {
                false
            };
            if verified {
                verified_paths.insert(relative.clone(), (expected.to_owned(), bytes.unwrap()));
            } else {
                failures += 1;
            }
            let mut observation = record.clone();
            observation["schema"] = json!("mobilee.bound-runtime-range/v1");
            observation["source_report"] = json!(path);
            observation["relative_path"] = json!(relative);
            observation["source_identity_status"] = json!(if identity_known {
                "producer_identity_recorded"
            } else {
                "unknown_or_conflicting"
            });
            observation["local_content_status"] = json!(if verified {
                "complete_range_hash_verified"
            } else {
                "unknown_or_failed"
            });
            observation["retained_file_bytes"] = json!(known.get(relative.as_str()));
            observation["mapping_complete"] = json!(if verified {
                Some(
                    read["requested_start"] == record["mapping"]["start"]
                        && read["actual_length"].as_u64()
                            == record["mapping"]["end"]
                                .as_u64()
                                .zip(record["mapping"]["start"].as_u64())
                                .map(|(e, s)| e - s),
                )
            } else {
                None
            });
            // Hashing a live range cannot attest atomic memory, a reconstructed DEX/SO,
            // semantic parsing or ownership. Preserve producer derivations without inventing links.
            observation["parse_status"] = json!("unknown_not_attested_by_range_copy");
            observation["ownership"] = json!("unknown");
            if verified && bytes.unwrap() <= 16 * 1024 * 1024 {
                let key = format!("{expected}:{}", bytes.unwrap());
                if !inspections.contains_key(&key) && bytes.unwrap() <= inspection_budget {
                    inspection_budget -= bytes.unwrap();
                    let analysis = fs::read(root.join(&relative))
                        .ok()
                        .filter(|b| {
                            b.len() as u64 == bytes.unwrap()
                                && format!("{:x}", Sha256::digest(b)) == expected
                        })
                        .map(|b| {
                            inspect_runtime_bytes_with_class_budget(&b, &mut class_index_budget)
                        })
                        .unwrap_or_else(
                            || json!({"status":"unknown_changed_or_unreadable_after_hash"}),
                        );
                    inspections.insert(key.clone(), analysis);
                }
                observation["object_inspection"] = inspections
                    .get(&key)
                    .cloned()
                    .unwrap_or_else(|| json!({"status":"unknown_inspection_budget_exhausted"}));
            } else {
                observation["object_inspection"] =
                    json!({"status":"unknown_unverified_or_oversized_range"});
            }

            if let Some(objects) =
                observation["object_inspection"]["derived_objects"].as_array_mut()
            {
                for object in objects {
                    object["source_artifact"] = json!(relative);
                    object["source_artifact_sha256"] = json!(expected);
                    object["source_instance"] = source.clone();
                    object["source_absolute_start"] = json!(read["actual_start"]
                        .as_u64()
                        .zip(object["source_offset"].as_u64())
                        .and_then(|(a, b)| a.checked_add(b)));
                    object["source_torn"] = read["torn"].clone();
                }
            }
            if !verified {
                invalid_records += 1;
            }
            runtime.push(observation);
        }
        diagnostic["invalid_records"] = json!(invalid_records);
        diagnostic["omitted_records"] = json!(omitted_records);
        if invalid_records > 0 || omitted_records > 0 {
            diagnostic["status"] = json!("partial_records");
        }
        source_diagnostics.push(diagnostic);
    }
    let code_logical = verified_paths.values().map(|(_, n)| *n).sum::<u64>();
    let unique = verified_paths
        .values()
        .cloned()
        .collect::<BTreeSet<_>>()
        .iter()
        .map(|(_, n)| *n)
        .sum::<u64>();
    let elf_modules = super::elf_runtime::module_views(&runtime);
    json!({"schema":"mobilee.local-storage-evidence/v1","logical_file_bytes":logical,"unique_inode_bytes":if cfg!(unix){Some(inode_bytes)}else{None},"allocated_bytes":if cfg!(unix){Some(allocated)}else{None},
        "shared_inode_logical_bytes":if cfg!(unix){Some(logical.saturating_sub(inode_bytes))}else{None},"allocation_basis":if cfg!(unix){"unique_inode_st_blocks_512"}else{"unavailable"},"unknown_metadata_files":unknown_metadata,"category_logical_bytes":categories,
        "verified_code_logical_bytes":code_logical,"verified_code_unique_bytes":unique,"verified_code_duplicate_bytes":code_logical.saturating_sub(unique),
        "unverified_observations":failures,"omitted_observations":omitted,"hash_budget_bytes":64*1024*1024,"hash_budget_remaining":hash_budget,"observations":observations,"runtime_observations":runtime,"elf_module_observations":elf_modules,"runtime_source_diagnostics":source_diagnostics,"runtime_source_limit":256,"runtime_sources_omitted":source_omitted,"class_index_descriptor_budget_bytes":1048576,"class_index_descriptor_budget_remaining":class_index_budget,
        "warnings":["Content redundancy is an accounting opportunity, not physical disk savings","APK members and producer transformations are provenance assertions; local verification hashes retained files only","This bounded code ledger does not hash private data or old memory windows"]})
}
/// Reuse the existing bounded DEX splitter/semantic parser. Slice references
/// identify original bytes; no repaired or standalone file is fabricated.
#[cfg(test)]
fn inspect_runtime_bytes(bytes: &[u8]) -> Value {
    inspect_runtime_bytes_with_class_budget(bytes, &mut 1048576)
}
fn dex_layout_diagnostics(bytes: &[u8]) -> Value {
    let word = |at: usize| {
        bytes
            .get(at..at + 4)
            .and_then(|b| b.try_into().ok())
            .map(u32::from_le_bytes)
            .map(u64::from)
    };
    if bytes.len() < 112 || !matches!(&bytes[4..7], b"035" | b"037" | b"038" | b"039" | b"040") {
        return json!({"status":"unknown_unsupported_header_version","full_dex_verifier":false});
    }
    let declared = word(32).unwrap();
    let data_off = word(108).unwrap();
    let data_size = word(104).unwrap();
    let link_off = word(48).unwrap();
    let link_size = word(44).unwrap();
    let data_end = data_off + data_size;
    let link_end = link_off + link_size;
    let end = 112_u64.max(data_end).max(link_end);
    let bounds = data_end <= declared && link_end <= declared && declared == bytes.len() as u64;
    json!({"status":if !bounds {"declared_spans_out_of_bounds"} else if end<declared {"declared_spans_leave_unaccounted_tail"}else{"declared_spans_cover_file"},"actual_bytes":bytes.len(),"declared_file_bytes":declared,"declared_data_start":data_off,"declared_data_bytes":data_size,"declared_data_end":data_end,"declared_link_start":link_off,"declared_link_bytes":link_size,"trailing_unaccounted_bytes":declared.saturating_sub(end),"full_dex_verifier":false,"scope":"header-declared data/link spans only; map entries and instruction code items not fully validated; trailing bytes remain uninterpreted"})
}
fn inspect_runtime_bytes_with_class_budget(bytes: &[u8], class_budget: &mut usize) -> Value {
    let dex_offsets = bytes
        .windows(4)
        .enumerate()
        .filter_map(|(i, b)| (b == b"dex\n").then_some(i))
        .take(257)
        .collect::<Vec<_>>();
    let elf_magic = bytes.windows(4).filter(|b| *b == b"\x7fELF").count();
    if dex_offsets.len() > 256 {
        return json!({"status":"unknown_candidate_limit","candidate_limit":256,"elf_magic_count":elf_magic});
    }
    let slices = ksight_core::split_concatenated_dex(bytes);
    let mut objects = Vec::new();
    let mut rejected = Vec::new();
    for offset in dex_offsets {
        match slices.iter().find(|s| s.offset==offset as u64) {
            Some(slice) => match ksight_core::parse_dex_semantics(&slice.bytes) {
                Some(semantic)=>objects.push(json!({"kind":"dex","source_offset":offset,"length":slice.bytes.len(),"sha256":format!("{:x}",Sha256::digest(&slice.bytes)),"semantic":semantic,"layout_diagnostics":dex_layout_diagnostics(&slice.bytes),"class_index":super::dex_class_index::classes(&slice.bytes, class_budget),"sha1_signature_verified":sha1::Sha1::digest(&slice.bytes[32..]).as_slice()==&slice.bytes[12..32],"adler32_checksum_verified":dex_adler32(&slice.bytes[12..])==u32::from_le_bytes(slice.bytes[8..12].try_into().unwrap()),"validation_level":"bounded_semantic_tables_and_checksum_results; instruction_code_items_not_fully_validated","retained_as_separate_file":false,"ownership":"unknown","relationship":"exact_slice_of_original_runtime_range"})),
                None=>rejected.push(json!({"source_offset":offset,"reason":"semantic_tables_invalid_or_unsupported"})),
            },
            None=>{
                let candidate = &bytes[offset..];
                let read_u32 = |at: usize| candidate.get(at..at+4).and_then(|b| b.try_into().ok()).map(u32::from_le_bytes);
                let declared = read_u32(32);
                // These are header assertions, not full DEX validation or authority to read more memory.
                let plausible = candidate.get(..8).is_some_and(|b| b.starts_with(b"dex\n") && b[4..7].iter().all(u8::is_ascii_digit) && b[7]==0)
                    && read_u32(36)==Some(112) && read_u32(40)==Some(0x12345678)
                    && declared.is_some_and(|n|n>=112);
                rejected.push(json!({"source_offset":offset,"reason":if plausible && declared.is_some_and(|n|n as usize>candidate.len()) {"declared_dex_extends_beyond_retained_range"} else {"truncated_or_invalid_dex_header_and_declared_bounds"},"header_claim_only":true,"declared_length":if plausible {declared}else{None},"available_range_bytes":candidate.len(),"missing_declared_bytes":if plausible {declared.map(|n|(n as u64).saturating_sub(candidate.len() as u64))}else{None},"complete_dex_validated":false}));
            },
        }
    }
    json!({"status":if objects.is_empty() && rejected.is_empty() && elf_magic==0 {"no_dex_or_elf_header_in_retained_range"} else {"bounded_candidate_inspection"},"scanned_bytes":bytes.len(),"dex_magic_count":objects.len()+rejected.len(),"elf_magic_count":elf_magic,"elf_header":super::elf_runtime::header(bytes),"derived_objects":objects,"rejected_candidates":rejected,"elf_status":if elf_magic==0 {"no_elf_header"} else {"unknown_no_linked_elf_reconstruction_parser"},"boundary":"this retained range only; headerless JIT, unselected pages and unread bytes remain unknown"})
}

fn dex_adler32(bytes: &[u8]) -> u32 {
    let (mut a, mut b) = (1_u32, 0_u32);
    for chunk in bytes.chunks(5552) {
        for byte in chunk {
            a += u32::from(*byte);
            b += a;
        }
        a %= 65521;
        b %= 65521;
    }
    (b << 16) | a
}

fn safe_local_file(root: &Path, relative: &str) -> bool {
    let mut path = root.to_path_buf();
    for part in Path::new(relative).components() {
        let std::path::Component::Normal(name) = part else {
            return false;
        };
        path.push(name);
        if fs::symlink_metadata(&path).map_or(true, |m| m.file_type().is_symlink()) {
            return false;
        }
    }
    fs::metadata(path).is_ok_and(|m| m.is_file())
}

pub(super) fn hash_file(path: &Path, expected: u64) -> Option<String> {
    let mut file = fs::File::open(path).ok()?;
    let mut hash = Sha256::new();
    let mut n = 0;
    let mut buffer = [0; 65536];
    loop {
        let count = file.read(&mut buffer).ok()?;
        if count == 0 {
            break;
        }
        n += count as u64;
        if n > expected {
            return None;
        }
        hash.update(&buffer[..count]);
    }
    (n == expected).then(|| format!("{:x}", hash.finalize()))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn runtime_inspection_reuses_dex_parser_and_rejects_fake_truncated_headers() {
        let mut dex = vec![0_u8; 112];
        dex[..8].copy_from_slice(b"dex\n035\0");
        dex[32..36].copy_from_slice(&112_u32.to_le_bytes());
        dex[36..40].copy_from_slice(&112_u32.to_le_bytes());
        dex[40..44].copy_from_slice(&0x12345678_u32.to_le_bytes());
        let mut bytes = vec![9_u8; 17];
        bytes.extend(&dex);
        let valid = inspect_runtime_bytes(&bytes);
        assert_eq!(valid["derived_objects"][0]["source_offset"], 17);
        assert_eq!(valid["derived_objects"][0]["length"], 112);
        assert_eq!(valid["derived_objects"][0]["semantic"]["class_defs"], 0);
        assert_eq!(
            valid["derived_objects"][0]["retained_as_separate_file"],
            false
        );
        assert_eq!(valid["derived_objects"][0]["ownership"], "unknown");
        for bad in [&bytes[..bytes.len() - 1], b"dex\nnot-a-dex".as_slice()] {
            let result = inspect_runtime_bytes(bad);
            assert!(result["derived_objects"].as_array().unwrap().is_empty());
            assert_eq!(result["rejected_candidates"].as_array().unwrap().len(), 1);
        }
        assert_eq!(
            inspect_runtime_bytes(b"\x7fELFfake")["elf_status"],
            "unknown_no_linked_elf_reconstruction_parser"
        );
    }
    fn runtime_fixture() -> (std::path::PathBuf, Vec<(String, u64)>, Value) {
        let root = std::env::temp_dir().join(format!("me-runtime-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(root.join("runtime")).unwrap();
        let bytes = [7; 256];
        fs::write(root.join("runtime/bound-fixture.code"), bytes).unwrap();
        let source = json!({"package":"org.example.fixture","pid":42,"uid":10001,"birth_ns":77,"exec_id":4,"boot_id":"fixture-boot"});
        let note = json!({"schema":"kernsight.bound-code-copy/v1","source":source,"partial":true,"torn":true,"records":[{
            "source":source,"mapping":{"start":4096,"end":8192,"path":"/memfd:fixture","perms":"r-x"},"raw_evidence":"bound-fixture.code","admitted":true,"derived":[],
            "read":{"requested_start":4096,"requested_length":256,"actual_start":4096,"actual_length":256,"read_status":"complete","write_status":"complete","read_error":null,"write_error":null,"admission":"qualified_live_copy","sha256":format!("{:x}",Sha256::digest(bytes)),"torn":true,"paused":false}}]});
        (
            root,
            vec![
                ("runtime/bound-fixture.code".into(), 256),
                ("runtime/bound-source-fixture.json".into(), 0),
            ],
            note,
        )
    }
    #[test]
    fn runtime_complete_range_is_not_complete_mapping_or_parsed_dex() {
        let (root, files, note) = runtime_fixture();
        fs::write(
            root.join("runtime/bound-source-fixture.json"),
            serde_json::to_vec(&note).unwrap(),
        )
        .unwrap();
        let result = account(&root, &files);
        assert_eq!(result["verified_code_unique_bytes"], 256);
        let row = &result["runtime_observations"][0];
        assert_eq!(row["local_content_status"], "complete_range_hash_verified");
        assert_eq!(row["mapping_complete"], false);
        assert_eq!(row["read"]["torn"], true);
        assert_eq!(row["parse_status"], "unknown_not_attested_by_range_copy");
        assert_eq!(row["source"], note["source"]);
        assert_eq!(
            row["object_inspection"]["status"],
            "no_dex_or_elf_header_in_retained_range"
        );
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn runtime_partial_missing_identity_forged_hash_and_private_paths_are_not_verified() {
        for (field, value) in [
            ("read_status", json!("short_read")),
            ("write_status", json!("write_failed")),
            ("actual_length", json!(128)),
            ("sha256", json!("0".repeat(64))),
            ("torn", Value::Null),
            ("requested_start", json!(0)),
        ] {
            let (root, files, mut note) = runtime_fixture();
            note["records"][0]["read"][field] = value;
            fs::write(
                root.join("runtime/bound-source-fixture.json"),
                serde_json::to_vec(&note).unwrap(),
            )
            .unwrap();
            assert_eq!(
                account(&root, &files)["verified_code_unique_bytes"],
                0,
                "{field}"
            );
            fs::remove_dir_all(root).unwrap();
        }
        for (field, value) in [
            ("source", Value::Null),
            ("raw_evidence", json!("../data-private/log.txt")),
            ("admitted", Value::Null),
        ] {
            let (root, files, mut note) = runtime_fixture();
            note["records"][0][field] = value;
            fs::write(
                root.join("runtime/bound-source-fixture.json"),
                serde_json::to_vec(&note).unwrap(),
            )
            .unwrap();
            let result = account(&root, &files);
            assert_eq!(result["verified_code_unique_bytes"], 0, "{field}");
            assert_eq!(
                result["hash_budget_remaining"],
                64 * 1024 * 1024_u64,
                "{field}"
            );
            fs::remove_dir_all(root).unwrap();
        }
    }
    #[test]
    fn actual_checksum_results_do_not_upgrade_corrupted_retained_dex() {
        let mut dex = vec![0_u8; 112];
        dex[..8].copy_from_slice(b"dex\n035\0");
        dex[32..36].copy_from_slice(&112_u32.to_le_bytes());
        dex[36..40].copy_from_slice(&112_u32.to_le_bytes());
        dex[40..44].copy_from_slice(&0x12345678_u32.to_le_bytes());
        let signature = sha1::Sha1::digest(&dex[32..]);
        dex[12..32].copy_from_slice(&signature);
        let checksum = dex_adler32(&dex[12..]);
        dex[8..12].copy_from_slice(&checksum.to_le_bytes());
        let result = inspect_runtime_bytes(&dex);
        assert_eq!(
            result["derived_objects"][0]["sha1_signature_verified"],
            true
        );
        assert_eq!(
            result["derived_objects"][0]["adler32_checksum_verified"],
            true
        );
        dex[8] ^= 1;
        let corrupt = inspect_runtime_bytes(&dex);
        assert_eq!(
            corrupt["derived_objects"][0]["adler32_checksum_verified"],
            false
        );
        assert_eq!(corrupt["derived_objects"][0]["ownership"], "unknown");
    }
    #[test]
    fn declared_full_bytes_and_valid_checksums_do_not_hide_unaccounted_tail() {
        let mut dex = vec![0_u8; 128];
        dex[..8].copy_from_slice(b"dex\n035\0");
        dex[32..36].copy_from_slice(&128_u32.to_le_bytes());
        dex[36..40].copy_from_slice(&112_u32.to_le_bytes());
        dex[40..44].copy_from_slice(&0x12345678_u32.to_le_bytes());
        let signature = sha1::Sha1::digest(&dex[32..]);
        dex[12..32].copy_from_slice(&signature);
        let checksum = dex_adler32(&dex[12..]);
        dex[8..12].copy_from_slice(&checksum.to_le_bytes());
        let result = inspect_runtime_bytes(&dex);
        let object = &result["derived_objects"][0];
        assert_eq!(object["sha1_signature_verified"], true);
        assert_eq!(object["adler32_checksum_verified"], true);
        assert_eq!(
            object["layout_diagnostics"]["trailing_unaccounted_bytes"],
            16
        );
        assert_eq!(
            object["layout_diagnostics"]["status"],
            "declared_spans_leave_unaccounted_tail"
        );
        assert_eq!(object["layout_diagnostics"]["full_dex_verifier"], false);
    }
    #[test]
    fn partial_dex_header_reports_exact_gap_without_fabricating_object() {
        let mut bytes = vec![0_u8; 176];
        bytes[64..72].copy_from_slice(b"dex\n035\0");
        bytes[96..100].copy_from_slice(&1000_u32.to_le_bytes());
        bytes[100..104].copy_from_slice(&112_u32.to_le_bytes());
        bytes[104..108].copy_from_slice(&0x12345678_u32.to_le_bytes());
        let result = inspect_runtime_bytes(&bytes);
        assert_eq!(result["derived_objects"].as_array().unwrap().len(), 0);
        assert_eq!(
            result["rejected_candidates"][0]["reason"],
            "declared_dex_extends_beyond_retained_range"
        );
        assert_eq!(
            result["rejected_candidates"][0]["missing_declared_bytes"],
            888
        );
        assert_eq!(
            result["rejected_candidates"][0]["complete_dex_validated"],
            false
        );
        bytes[104] = 0;
        assert!(
            inspect_runtime_bytes(&bytes)["rejected_candidates"][0]["declared_length"].is_null()
        );
    }
    #[test]
    fn source_errors_and_invalid_item_preserve_valid_sibling_with_bounded_diagnostics() {
        let (root, mut files, mut note) = runtime_fixture();
        note["records"]
            .as_array_mut()
            .unwrap()
            .insert(0, Value::Null);
        fs::write(
            root.join("runtime/bound-source-fixture.json"),
            serde_json::to_vec(&note).unwrap(),
        )
        .unwrap();
        fs::write(
            root.join("runtime/bound-source-truncated.json"),
            b"{\"schema\":",
        )
        .unwrap();
        files.push(("runtime/bound-source-truncated.json".into(), 10));
        let result = account(&root, &files);
        assert_eq!(result["verified_code_unique_bytes"], 256);
        assert_eq!(result["runtime_observations"].as_array().unwrap().len(), 1);
        let diagnostics = result["runtime_source_diagnostics"].as_array().unwrap();
        assert_eq!(diagnostics[0]["invalid_records"], 1);
        assert_eq!(diagnostics[1]["status"], "invalid_or_truncated_json");
        note.as_object_mut().unwrap().remove("records");
        fs::write(
            root.join("runtime/bound-source-fixture.json"),
            serde_json::to_vec(&note).unwrap(),
        )
        .unwrap();
        assert_eq!(
            account(&root, &files)["runtime_source_diagnostics"][0]["status"],
            "missing_or_invalid_records"
        );
        for _ in 0..300 {
            files.push(("runtime/bound-source-truncated.json".into(), 10));
        }
        let bounded = account(&root, &files);
        assert_eq!(
            bounded["runtime_source_diagnostics"]
                .as_array()
                .unwrap()
                .len(),
            256
        );
        assert!(bounded["runtime_sources_omitted"].as_u64().unwrap() > 0);
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn legitimate_bound_source_over_32k_is_analyzed_but_64k_limit_still_applies() {
        let (root, mut files, mut note) = runtime_fixture();
        note["bounded_extra_metadata"] = json!("x".repeat(33000));
        let bytes = serde_json::to_vec(&note).unwrap();
        assert!(bytes.len() > 32768 && bytes.len() < 65536);
        fs::write(root.join("runtime/bound-source-fixture.json"), &bytes).unwrap();
        files
            .iter_mut()
            .find(|(p, _)| p == "runtime/bound-source-fixture.json")
            .unwrap()
            .1 = bytes.len() as u64;
        let result = account(&root, &files);
        assert_eq!(result["verified_code_unique_bytes"], 256);
        assert_eq!(result["runtime_observations"].as_array().unwrap().len(), 1);
        note["bounded_extra_metadata"] = json!("x".repeat(66000));
        let bytes = serde_json::to_vec(&note).unwrap();
        fs::write(root.join("runtime/bound-source-fixture.json"), &bytes).unwrap();
        files
            .iter_mut()
            .find(|(p, _)| p == "runtime/bound-source-fixture.json")
            .unwrap()
            .1 = bytes.len() as u64;
        assert_eq!(account(&root, &files)["verified_code_unique_bytes"], 0);
    }
    #[test]
    fn runtime_duplicate_sources_preserve_rows_without_double_counting_and_symlinks_fail() {
        let (root, mut files, note) = runtime_fixture();
        for name in [
            "runtime/bound-source-fixture.json",
            "runtime/bound-source-second.json",
        ] {
            fs::write(root.join(name), serde_json::to_vec(&note).unwrap()).unwrap();
        }
        files.push(("runtime/bound-source-second.json".into(), 0));
        let result = account(&root, &files);
        assert_eq!(result["runtime_observations"].as_array().unwrap().len(), 2);
        assert_eq!(result["verified_code_logical_bytes"], 256);
        assert_eq!(result["hash_budget_remaining"], 64 * 1024 * 1024_u64 - 256);
        #[cfg(unix)]
        {
            fs::rename(
                root.join("runtime/bound-fixture.code"),
                root.join("original.code"),
            )
            .unwrap();
            std::os::unix::fs::symlink(
                root.join("original.code"),
                root.join("runtime/bound-fixture.code"),
            )
            .unwrap();
            assert_eq!(account(&root, &files)["verified_code_unique_bytes"], 0);
        }
        fs::remove_dir_all(root).unwrap();
    }
    #[tokio::test]
    #[ignore = "requires explicit retained local dump directory; no device access"]
    async fn retained_runtime_directory_import_keeps_file_sources_and_partial_parent() {
        let root = std::env::var("KSIGHT_RETAINED_DUMP_DIRECTORY")
            .expect("explicit retained dump directory");
        let imported = super::super::import_kernsight_evidence_directory(root)
            .await
            .unwrap();
        let ledger = &imported.dump_report["local_storage_accounting"];
        assert_eq!(ledger["verified_code_unique_bytes"], 19983868);
        assert_eq!(ledger["verified_code_logical_bytes"], 29603824);
        let file = imported
            .files
            .iter()
            .find(|f| {
                f.relative_path
                    .ends_with("0477ba96-b4db-4845-bcf4-19b62f67150a.code")
            })
            .unwrap();
        assert_eq!(file.code_evidence.len(), 1);
        assert_eq!(
            file.code_evidence[0]["local_content_status"],
            "complete_range_hash_verified"
        );
        assert_eq!(
            file.code_evidence[0]["source"]["birth_ns"],
            354039788906422_u64
        );
        let parent = &imported.session_report.as_ref().unwrap()["mobilee_capture_group"];
        assert_eq!(parent["state"], "partial");
        assert_eq!(parent["id"], "015a1673-f7f7-416c-96c2-30b17c469e26");
        if let Ok(output) = std::env::var("KSIGHT_RETAINED_LEDGER_REPORT") {
            fs::write(output,serde_json::to_vec_pretty(&json!({"verified_code_unique_bytes":ledger["verified_code_unique_bytes"],"verified_code_logical_bytes":ledger["verified_code_logical_bytes"],"runtime_observations":ledger["runtime_observations"],"parent_state":parent["state"],"parent_id":parent["id"]})).unwrap()).unwrap();
        }
    }
    #[test]
    #[ignore = "requires explicit retained local runtime sample; no device access"]
    fn retained_runtime_sample_uses_production_ledger() {
        let root = std::path::PathBuf::from(
            std::env::var_os("KSIGHT_RETAINED_RUNTIME_SAMPLE")
                .expect("explicit retained sample path"),
        );
        let files = fs::read_dir(&root)
            .unwrap()
            .map(|e| {
                let e = e.unwrap();
                (
                    e.file_name().to_string_lossy().into_owned(),
                    e.metadata().unwrap().len(),
                )
            })
            .collect::<Vec<_>>();
        let result = account(&root, &files);
        assert_eq!(result["verified_code_unique_bytes"], 16777216);
        assert_eq!(result["runtime_observations"].as_array().unwrap().len(), 2);
        assert_eq!(result["runtime_observations"][0]["mapping_complete"], false);
        assert_eq!(
            result["runtime_observations"][0]["object_inspection"]["status"],
            "no_dex_or_elf_header_in_retained_range"
        );
        assert_eq!(
            result["runtime_observations"][0]["object_inspection"]["scanned_bytes"],
            16777216
        );
        assert_eq!(
            result["runtime_observations"][1]["read"]["actual_length"],
            6946816
        );
        assert_eq!(
            result["runtime_observations"][1]["local_content_status"],
            "unknown_or_failed"
        );
    }
    #[test]
    #[cfg(unix)]
    fn legacy_zero_is_not_content_verification() {
        let root = std::env::temp_dir().join(format!("me-volume-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&root).unwrap();
        fs::write(root.join("a.dex"), [9; 17]).unwrap();
        fs::hard_link(root.join("a.dex"), root.join("b.dex")).unwrap();
        fs::write(root.join("c.dex"), [9; 17]).unwrap();
        let result = account(
            &root,
            &[
                ("a.dex".into(), 17),
                ("b.dex".into(), 17),
                ("c.dex".into(), 17),
            ],
        );
        assert_eq!(result["logical_file_bytes"], 51);
        assert_eq!(result["unique_inode_bytes"], 34);
        assert_eq!(result["shared_inode_logical_bytes"], 17);
        assert_eq!(result["verified_code_logical_bytes"], 0);
        assert_eq!(result["observations"], json!([]));
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn forged_member_hash_not_promoted_and_equal_files_are_only_accounted_redundancy() {
        let root = std::env::temp_dir().join(format!("me-members-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(root.join("code-evidence")).unwrap();
        let bytes = [7; 256];
        let hash = format!("{:x}", Sha256::digest(bytes));
        let mut files = Vec::new();
        for name in ["a.dex", "b.dex", "bad.dex"] {
            fs::write(root.join(name), bytes).unwrap();
            files.push((name.into(), 256));
            let note = json!({"schema":"kernsight.apk-member-evidence/v1","relative_path":name,"bytes":256,"sha256":if name=="bad.dex"{"0".repeat(64)}else{hash.clone()},"source_complete":true,"write_status":"hard_link"});
            let path = format!("code-evidence/{name}.json");
            fs::write(root.join(&path), serde_json::to_vec(&note).unwrap()).unwrap();
            files.push((path, 0));
        }
        let result = account(&root, &files);
        assert_eq!(result["verified_code_unique_bytes"], 256);
        assert_eq!(result["verified_code_logical_bytes"], 512);
        assert_eq!(result["verified_code_duplicate_bytes"], 256);
        #[cfg(unix)]
        assert_eq!(result["shared_inode_logical_bytes"], 0);
        assert_eq!(result["unverified_observations"], 1);
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn forged_member_note_cannot_hash_private_evidence() {
        let root = std::env::temp_dir().join(format!("me-private-scope-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(root.join("data-private")).unwrap();
        fs::create_dir(root.join("code-evidence")).unwrap();
        let bytes = b"synthetic placeholder";
        fs::write(root.join("data-private/log.txt"), bytes).unwrap();
        let note = json!({"schema":"kernsight.apk-member-evidence/v1","relative_path":"data-private/log.txt","bytes":bytes.len(),"sha256":format!("{:x}",Sha256::digest(bytes)),"source_complete":true,"write_status":"hard_link"});
        fs::write(
            root.join("code-evidence/forged.json"),
            serde_json::to_vec(&note).unwrap(),
        )
        .unwrap();
        let result = account(
            &root,
            &[
                ("data-private/log.txt".into(), bytes.len() as u64),
                ("code-evidence/forged.json".into(), 0),
            ],
        );
        assert_eq!(result["verified_code_logical_bytes"], 0);
        assert_eq!(result["unverified_observations"], 1);
        assert_eq!(result["hash_budget_remaining"], 64 * 1024 * 1024_u64);
        fs::remove_dir_all(root).unwrap();
    }
}
