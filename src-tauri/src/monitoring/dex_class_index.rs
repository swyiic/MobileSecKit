//! Bounded complete class index and content grouping. Namespace matches remain hints.
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};

pub(super) fn classes(bytes: &[u8], budget: &mut usize) -> Value {
    let u = |o: usize| {
        bytes
            .get(o..o.checked_add(4)?)
            .and_then(|b| b.try_into().ok())
            .map(u32::from_le_bytes)
    };
    let Some(count) = u(96) else {
        return json!({"status":"invalid_header"});
    };
    let (Some(co), Some(tc), Some(to), Some(sc), Some(so)) = (u(100), u(64), u(68), u(56), u(60))
    else {
        return json!({"status":"invalid_tables"});
    };
    let mut names = BTreeSet::new();
    let mut invalid = 0;
    let mut processed = 0;
    let mut total_bytes = 0_usize;
    let class_limit = 16384_u32;
    let descriptor_byte_limit = 4 * 1024 * 1024_usize;
    for i in 0..count.min(class_limit) {
        let name = (|| -> Option<String> {
            let tid = u((co as usize).checked_add((i as usize).checked_mul(32)?)?)?;
            if tid >= tc {
                return None;
            }
            let sid = u((to as usize).checked_add((tid as usize).checked_mul(4)?)?)?;
            if sid >= sc {
                return None;
            }
            let mut pos = u((so as usize).checked_add((sid as usize).checked_mul(4)?)?)? as usize;
            let mut ended = false;
            for _ in 0..5 {
                let b = *bytes.get(pos)?;
                pos = pos.checked_add(1)?;
                if b < 128 {
                    ended = true;
                    break;
                }
            }
            if !ended {
                return None;
            }
            let slice = bytes.get(pos..bytes.len().min(pos.checked_add(4097)?))?;
            let len = slice.iter().position(|b| *b == 0)?;
            let s = std::str::from_utf8(&slice[..len]).ok()?;
            if !s.starts_with('L') || !s.ends_with(';') {
                return None;
            }
            Some(s.to_owned())
        })();
        if let Some(name) = name {
            if total_bytes.saturating_add(name.len()) > descriptor_byte_limit
                || name.len() > *budget
            {
                break;
            }
            *budget -= name.len();
            total_bytes += name.len();
            names.insert(name);
        } else {
            invalid += 1
        }
        processed += 1;
    }
    json!({"status":if processed==count && invalid==0 && names.len()==count as usize {"complete_class_def_index"}else{"partial_class_def_index"},"declared_classes":count,"processed_classes":processed,"indexed_unique_classes":names.len(),"invalid_classes":invalid,"duplicate_class_definitions":processed as usize-invalid as usize-names.len(),"omitted_classes":count-processed,"class_limit":class_limit,"descriptor_byte_limit":descriptor_byte_limit,"classes":names})
}

pub(super) fn objects(
    runtime: &[Value],
    static_sets: &Value,
    package: &str,
    components: &Value,
    parent: &Value,
) -> Value {
    let mut objects = BTreeMap::<String, Value>::new();
    let mut add = |hash: &str, length: u64, source: Value, index: Option<&Value>| {
        if hash.len() != 64 || !hash.bytes().all(|b| b.is_ascii_hexdigit()) {
            return;
        }
        let key = format!("{hash}:{length}");
        let object=objects.entry(key).or_insert_with(||json!({"sha256":hash,"bytes":length,"sources":[],"class_index_status":"unknown","declared_classes":null,"indexed_classes":null,"ownership":"unknown","classification_basis":"class names and manifest components are hints, not authorship/content signatures","validation_status":"unknown","sha1_signature_verified":null,"adler32_checksum_verified":null}));
        if source["kind"] == "runtime" {
            object["layout_diagnostics"] = source["layout_diagnostics"].clone();
            object["sha1_signature_verified"] = source["sha1_signature_verified"].clone();
            object["adler32_checksum_verified"] = source["adler32_checksum_verified"].clone();
            object["validation_status"] = json!(if source["sha1_signature_verified"] == true
                && source["adler32_checksum_verified"] == true
                && source["layout_diagnostics"]["status"] == "declared_spans_cover_file"
            {
                "checksum_and_bounded_structure_verified"
            } else if source["sha1_signature_verified"] == false
                || source["adler32_checksum_verified"] == false
            {
                "checksum_failed; structure_index_only_not_complete_business_recovery"
            } else if source["sha1_signature_verified"] == true
                && source["adler32_checksum_verified"] == true
            {
                "layout_unverified; checksum_passed_structure_index_only"
            } else {
                "checksum_unknown; structure_index_only"
            });
        }
        object["sources"]
            .as_array_mut()
            .unwrap()
            .push(source.clone());
        if let Some(declared) = source["declared_file_bytes"].as_u64() {
            object["declared_file_bytes"] = json!(declared);
            object["length_matches_declared"] = json!(source["length_matches_declared"] == true);
        }
        if let Some(index) = index {
            let incoming_partial = index["status"] == "partial_class_def_index"
                || index["omitted_classes"].as_u64().is_some_and(|n| n > 0);
            let keep_complete =
                object["class_index_status"] == "complete_class_def_index" && incoming_partial;
            if !keep_complete {
                object["class_index_status"] = index["status"].clone();
                object["declared_classes"] = index["declared_classes"].clone();
                object["indexed_classes"] = index["indexed_unique_classes"].clone();
                object["omitted_classes"] = index["omitted_classes"].clone();
                object["classes"] = index["classes"].clone();
                let root = format!("L{}/", package.replace('.', "/"));
                let mut own = 0;
                let mut sdk = 0;
                let mut manifest = 0;
                let mut unknown = 0;
                let mut packer = 0;
                for class in index["classes"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(Value::as_str)
                {
                    let dotted = class
                        .trim_start_matches('L')
                        .trim_end_matches(';')
                        .replace('/', ".");
                    if class.starts_with("Lcom/secneo/apkwrapper/") {
                        packer += 1
                    } else if components
                        .as_array()
                        .into_iter()
                        .flatten()
                        .any(|c| c.as_str() == Some(&dotted))
                    {
                        manifest += 1
                    } else if class.starts_with(&root) {
                        own += 1
                    } else if super::is_mobilee_sdk_namespace(
                        class.trim_start_matches('L').trim_end_matches(';'),
                    ) {
                        sdk += 1
                    } else {
                        unknown += 1
                    }
                }
                object["class_hints"] = json!({"manifest_component_candidates":manifest,"package_namespace_candidates":own,"known_library_namespace_candidates":sdk,"unknown":unknown});
                let indexed = index["classes"]
                    .as_array()
                    .map(|items| items.len())
                    .unwrap_or(0);
                let partial = index["status"] == "partial_class_def_index"
                    || index["omitted_classes"].as_u64().unwrap_or(0) > 0;
                let shell_mixed = packer > 0 && packer < indexed;
                if partial || shell_mixed {
                    object["classification_basis"] = json!(
                        "candidate only; a shell mixed with other classes, or a partial index, is not a pure ownership judgment"
                    );
                }
                object["ownership"] = json!(if partial || shell_mixed {
                    "mixed_or_unknown"
                } else if indexed > 0 && packer == indexed {
                    "packer_shell"
                } else if own + manifest > 0 && sdk + unknown > 0 {
                    "mixed_or_unknown"
                } else if own + manifest > 0 {
                    "business"
                } else if sdk > 0 && unknown == 0 {
                    "third_party_sdk"
                } else {
                    "unknown"
                });
            }
        }
    };
    for (row_index, row) in runtime.iter().enumerate() {
        if row["local_content_status"] != "complete_range_hash_verified"
            || row["source"]["package"] != package
        {
            continue;
        }
        for dex in row["object_inspection"]["derived_objects"]
            .as_array()
            .into_iter()
            .flatten()
        {
            if dex["kind"] != "dex" {
                continue;
            }
            let (Some(hash), Some(length)) = (dex["sha256"].as_str(), dex["length"].as_u64())
            else {
                continue;
            };
            add(
                hash,
                length,
                json!({"kind":"runtime","layout_diagnostics":dex["layout_diagnostics"],"sha1_signature_verified":dex["sha1_signature_verified"],"adler32_checksum_verified":dex["adler32_checksum_verified"],"declared_file_bytes":dex["declared_file_bytes"],"length_matches_declared":dex["length_matches_declared"],"parent_id":parent,"source_report":row["source_report"],"source":row["source"],"relative_path":row["relative_path"],"range_sha256":row["read"]["sha256"],"source_offset":dex["source_offset"],"row_index":row_index,"storage_scope":if row["mapping"]["path"].as_str().is_some_and(|p|p.ends_with(".apk")){"mapped_apk_slice; not decrypted runtime business recovery"}else{"observed_runtime_code_slice"},"verification":if dex["sha1_signature_verified"]==true && dex["adler32_checksum_verified"]==true && dex["layout_diagnostics"]["status"]=="declared_spans_cover_file" {"complete_runtime_slice_checksum_and_bounded_declared_spans"}else{"bounded_structure_only; checksum_failed_or_unknown"}}),
                Some(&dex["class_index"]),
            );
        }
    }
    for set in static_sets.as_array().into_iter().flatten() {
        if let (Some(hash), Some(length)) = (set["sha256"].as_str(), set["bytes"].as_u64()) {
            let path = set["canonical_relative_path"].as_str().unwrap_or("");
            let unpacked = path
                .rsplit('/')
                .next()
                .is_some_and(|name| name.starts_with("anon-"));
            let semantic = set.get("semantic");
            let class_index = semantic.map(|semantic| {
                let declared = semantic["class_defs"].as_u64().unwrap_or(0);
                let indexed = semantic["class_descriptors"]
                    .as_array()
                    .map(|items| items.len() as u64)
                    .unwrap_or(0);
                let truncated =
                    semantic["class_descriptors_truncated"] == true || declared > indexed;
                json!({
                    "status": if truncated {
                        "partial_class_def_index"
                    } else {
                        "complete_class_def_index"
                    },
                    "declared_classes": semantic["class_defs"],
                    "indexed_unique_classes": indexed,
                    "omitted_classes": declared.saturating_sub(indexed),
                    "classes": semantic["class_descriptors"],
                })
            });
            let declared = semantic.and_then(|item| item["declared_file_size"].as_u64());
            add(
                hash,
                length,
                json!({"kind": if unpacked { "anonymous_unpacked_dex" } else { "producer_dex_set" },"relative_path":set["canonical_relative_path"],"observations":set["observations"],"declared_file_bytes":declared,"length_matches_declared":declared.is_some_and(|n| n == length),"verification": if unpacked { "anonymous memory image copied by the agent; class names come from the producer class index" } else { "producer_record_only_not_reverified_here" }}),
                class_index.as_ref(),
            );
        }
    }
    json!({"schema":"mobilee.content-dex-class-index/v1","scope":"this imported tree; fullhash+length content grouping, every source retained","objects":objects.into_values().collect::<Vec<_>>()})
}

const INVENTORY_PROJECTION_BYTE_LIMIT: usize = 8 * 1024 * 1024;

#[derive(Default)]
struct InventoryProjection {
    inventory_rows: usize,
    valid_rows: usize,
    skipped_unverified_rows: usize,
    skipped_uninspected_rows: usize,
    skipped_no_dex_rows: usize,
    invalid_rows: usize,
    invalid_derived_links: usize,
    invalid_index_objects: usize,
    projected_links: usize,
    upgraded_links: usize,
    appended_links: usize,
    omitted_links: usize,
    unmatched_dex_links: usize,
    admitted_metadata_bytes: usize,
    metadata_limit_reached: bool,
}

impl InventoryProjection {
    fn report(&self, byte_limit: usize, stop: Option<&str>) -> Value {
        let mut reasons = Vec::new();
        if self.invalid_rows > 0 {
            reasons.push("invalid_verified_inventory_reference");
        }
        if self.invalid_derived_links > 0 {
            reasons.push("invalid_derived_dex_reference");
        }
        if self.invalid_index_objects > 0 || self.unmatched_dex_links > 0 {
            reasons.push("missing_or_ambiguous_indexed_dex_content");
        }
        if self.omitted_links > 0 {
            reasons.push("alias_metadata_byte_limit");
        }
        if stop.is_some() {
            reasons.push("projection_stopped");
        }
        json!({
            "schema":"mobilee.runtime-dex-alias-projection/v1",
            "scope":"verified retained range refs with shared canonical content inspection; not full capture or full code recovery",
            "complete":reasons.is_empty(),
            "inventory_rows":self.inventory_rows,
            "valid_rows":self.valid_rows,
            "skipped_unverified_rows":self.skipped_unverified_rows,
            "skipped_uninspected_rows":self.skipped_uninspected_rows,
            "skipped_no_dex_rows":self.skipped_no_dex_rows,
            "invalid_rows":self.invalid_rows,
            "invalid_derived_links":self.invalid_derived_links,
            "invalid_index_objects":self.invalid_index_objects,
            "projected_links":self.projected_links,
            "upgraded_links":self.upgraded_links,
            "appended_links":self.appended_links,
            "omitted_links":self.omitted_links,
            "unmatched_dex_links":self.unmatched_dex_links,
            "metadata_byte_limit":byte_limit,
            "admitted_metadata_bytes":self.admitted_metadata_bytes,
            "partial_reasons":reasons,
            "stop_reason":stop,
        })
    }
}

fn projection_checkpoint(root: &std::path::Path) -> Result<(), String> {
    super::session_deadline::check()?;
    super::session_budget::charge(root, 0).map_err(|e| e.to_string())
}

fn projection_hash(value: &Value) -> Option<&str> {
    value
        .as_str()
        .filter(|hash| hash.len() == 64 && hash.bytes().all(|b| b.is_ascii_hexdigit()))
}

fn projection_relative_path(value: &Value) -> bool {
    value.as_str().is_some_and(|s| {
        !s.is_empty()
            && !s.contains('\\')
            && std::path::Path::new(s)
                .components()
                .all(|part| matches!(part, std::path::Component::Normal(_)))
    })
}

fn projection_identity(source: &Value, package: &str) -> bool {
    source["package"] == package
        && !package.is_empty()
        && source["pid"].as_u64().is_some_and(|v| v > 0)
        && source["birth_ns"].as_u64().is_some_and(|v| v > 0)
        && source["uid"].as_u64().is_some()
        && source["exec_id"].as_u64().is_some()
        && source["boot_id"].as_str().is_some_and(|v| !v.is_empty())
}

fn projection_range(row: &Value) -> Option<(u64, u64)> {
    let read = &row["read"];
    let start = row["mapping"]["start"].as_u64()?;
    let end = row["mapping"]["end"].as_u64()?;
    let requested_start = read["requested_start"].as_u64()?;
    let requested_length = read["requested_length"].as_u64()?;
    let actual_start = read["actual_start"].as_u64()?;
    let actual_length = read["actual_length"].as_u64()?;
    (end > start
        && requested_length > 0
        && actual_start == requested_start
        && actual_length == requested_length
        && actual_start >= start
        && actual_start.checked_add(actual_length)? <= end
        && row["admitted"] == true
        && read["admission"] == "qualified_live_copy"
        && read["read_status"] == "complete"
        && read["write_status"] == "complete"
        && read.get("read_error").is_some_and(Value::is_null)
        && read.get("write_error").is_some_and(Value::is_null)
        && read["torn"].as_bool().is_some()
        && read["paused"].as_bool().is_some())
    .then_some((actual_start, actual_length))
}

/// Share an inspected *content* result across independently verified retained
/// ranges. This adds provenance only: classes, validation and ownership remain
/// exactly those already present in `objects`.
pub(super) fn attach_inventory_sources(
    root: &std::path::Path,
    index: &mut Value,
    runtime: &[Value],
    inventory: &[Value],
    package: &str,
    parent: &Value,
) -> Result<(), String> {
    attach_inventory_sources_with_limit(
        root,
        index,
        runtime,
        inventory,
        package,
        parent,
        INVENTORY_PROJECTION_BYTE_LIMIT,
    )
}

fn attach_inventory_sources_with_limit(
    root: &std::path::Path,
    index: &mut Value,
    runtime: &[Value],
    inventory: &[Value],
    package: &str,
    parent: &Value,
    byte_limit: usize,
) -> Result<(), String> {
    if !index.is_object() {
        return Err("runtime_inventory_projection_invalid_index".into());
    }
    let mut accounting = InventoryProjection {
        inventory_rows: inventory.len(),
        ..Default::default()
    };
    // A cancelled/expired projection must never leave a success receipt.
    index["runtime_inventory_projection"] =
        accounting.report(byte_limit, Some("projection_in_progress"));
    let outcome = project_inventory_sources(
        root,
        index,
        runtime,
        inventory,
        package,
        parent,
        byte_limit,
        &mut accounting,
    )
    .and_then(|()| projection_checkpoint(root));
    index["runtime_inventory_projection"] =
        accounting.report(byte_limit, outcome.as_ref().err().map(String::as_str));
    // Include the final accounting operation in the same fixed deadline.
    if let Err(reason) = projection_checkpoint(root) {
        index["runtime_inventory_projection"] = accounting.report(byte_limit, Some(&reason));
        return Err(reason);
    }
    outcome
}

#[allow(clippy::too_many_arguments)]
fn project_inventory_sources(
    root: &std::path::Path,
    index: &mut Value,
    runtime: &[Value],
    inventory: &[Value],
    package: &str,
    parent: &Value,
    byte_limit: usize,
    accounting: &mut InventoryProjection,
) -> Result<(), String> {
    projection_checkpoint(root)?;
    let mut object_indices = BTreeMap::<String, Option<usize>>::new();
    let mut canonical_sources = BTreeMap::<(usize, usize, u64), Option<usize>>::new();
    let mut alias_sources = BTreeMap::<(usize, usize, u64), Option<usize>>::new();
    let objects = index["objects"]
        .as_array()
        .ok_or("runtime_inventory_projection_missing_objects")?;
    for (object_index, object) in objects.iter().enumerate() {
        projection_checkpoint(root)?;
        let (Some(hash), Some(length)) = (
            projection_hash(&object["sha256"]),
            object["bytes"].as_u64().filter(|n| *n > 0),
        ) else {
            accounting.invalid_index_objects += 1;
            continue;
        };
        let key = format!("{hash}:{length}");
        object_indices
            .entry(key)
            .and_modify(|slot| *slot = None)
            .or_insert(Some(object_index));
        let Some(sources) = object["sources"].as_array() else {
            accounting.invalid_index_objects += 1;
            continue;
        };
        for (source_index, source) in sources.iter().enumerate() {
            projection_checkpoint(root)?;
            let Some(offset) = source["source_offset"].as_u64() else {
                continue;
            };
            let slots = if source["kind"] == "runtime" {
                (&mut canonical_sources, source["row_index"].as_u64())
            } else if source["kind"] == "runtime_range_inventory" {
                (&mut alias_sources, source["inventory_row_index"].as_u64())
            } else {
                continue;
            };
            if let Some(row_index) = slots.1.and_then(|v| usize::try_from(v).ok()) {
                slots
                    .0
                    .entry((object_index, row_index, offset))
                    .and_modify(|slot| *slot = None)
                    .or_insert(Some(source_index));
            }
        }
    }
    for (inventory_row_index, row) in inventory.iter().enumerate() {
        projection_checkpoint(root)?;
        if row["local_content_status"] != "complete_range_hash_verified" {
            accounting.skipped_unverified_rows += 1;
            continue;
        }
        if row.get("inspection_ref").is_none_or(Value::is_null) {
            accounting.skipped_uninspected_rows += 1;
            continue;
        }
        let Some((inspection_ref, canonical, start, length, range_hash, key)) = (|| {
            let inspection_ref = usize::try_from(row["inspection_ref"].as_u64()?).ok()?;
            let canonical = runtime.get(inspection_ref)?;
            let (start, length) = projection_range(row)?;
            let range_hash = projection_hash(&row["read"]["sha256"])?;
            let (_, canonical_length) = projection_range(canonical)?;
            let canonical_hash = projection_hash(&canonical["read"]["sha256"])?;
            let key = format!("{range_hash}:{length}");
            (row["source_identity_status"] == "producer_identity_recorded"
                && projection_identity(&row["source"], package)
                && row["source_record_index"].as_u64().is_some()
                && projection_hash(&row["source_report_sha256"]).is_some()
                && projection_relative_path(&row["source_report"])
                && projection_relative_path(&row["relative_path"])
                && canonical["local_content_status"] == "complete_range_hash_verified"
                && canonical["source_identity_status"] == "producer_identity_recorded"
                && projection_identity(&canonical["source"], package)
                && (row["source_report"] != canonical["source_report"]
                    || (row["source_report_sha256"] == canonical["source_report_sha256"]
                        && row["source"] == canonical["source"]))
                && range_hash == canonical_hash
                && length == canonical_length
                && row["inspection_content_key"] == key)
                .then_some((inspection_ref, canonical, start, length, range_hash, key))
        })() else {
            accounting.invalid_rows += 1;
            continue;
        };
        accounting.valid_rows += 1;
        let canonical_instance = canonical["source_report"] == row["source_report"]
            && canonical["source_report_sha256"] == row["source_report_sha256"]
            && canonical["source_record_index"] == row["source_record_index"]
            && canonical["relative_path"] == row["relative_path"]
            && canonical["source"] == row["source"];
        let mut dex_seen = false;
        for dex in canonical["object_inspection"]["derived_objects"]
            .as_array()
            .into_iter()
            .flatten()
        {
            projection_checkpoint(root)?;
            if dex["kind"] != "dex" {
                continue;
            }
            dex_seen = true;
            let Some((hash, bytes, offset, absolute_start)) = (|| {
                let hash = projection_hash(&dex["sha256"])?;
                let bytes = dex["length"].as_u64().filter(|n| *n > 0)?;
                let offset = dex["source_offset"].as_u64()?;
                (offset.checked_add(bytes)? <= length).then_some((
                    hash,
                    bytes,
                    offset,
                    start.checked_add(offset)?,
                ))
            })() else {
                accounting.invalid_derived_links += 1;
                continue;
            };
            let Some(Some(object_index)) = object_indices.get(&format!("{hash}:{bytes}")) else {
                accounting.unmatched_dex_links += 1;
                continue;
            };
            projection_checkpoint(root)?;
            let projected = json!({
                "kind":"runtime_range_inventory",
                "inventory_row_index":inventory_row_index,
                "source_record_index":row["source_record_index"],
                "source_report":row["source_report"],
                "source_report_sha256":row["source_report_sha256"],
                "source":row["source"],
                "relative_path":row["relative_path"],
                "range_sha256":range_hash,
                "source_offset":offset,
                "source_absolute_start":absolute_start,
                "source_torn":row["read"]["torn"],
                "inspection_ref":inspection_ref,
                "inspection_content_key":key,
                "parent_id":parent,
                "storage_scope":if row["mapping"]["path"].as_str().is_some_and(|p| p.ends_with(".apk")) {
                    "mapped_apk_slice; not decrypted runtime business recovery"
                } else {
                    "observed_runtime_code_slice"
                },
                "verification":"current_verified_range_and_shared_content_inspection",
            });
            let metadata_bytes = serde_json::to_vec(&projected)
                .map_err(|e| format!("runtime_inventory_projection_serialization: {e}"))?
                .len();
            projection_checkpoint(root)?;
            if accounting.metadata_limit_reached
                || metadata_bytes > byte_limit.saturating_sub(accounting.admitted_metadata_bytes)
            {
                accounting.metadata_limit_reached = true;
                accounting.omitted_links += 1;
                continue;
            }
            let Some(sources) = index["objects"][*object_index]["sources"].as_array_mut() else {
                accounting.unmatched_dex_links += 1;
                continue;
            };
            let canonical_slot = canonical_sources
                .get(&(*object_index, inspection_ref, offset))
                .copied()
                .flatten()
                .filter(|source_index| {
                    let source = &sources[*source_index];
                    canonical_instance
                        && source["kind"] == "runtime"
                        && source["parent_id"] == *parent
                        && source["row_index"].as_u64() == Some(inspection_ref as u64)
                        && source["source_report"] == canonical["source_report"]
                        && source["relative_path"] == canonical["relative_path"]
                        && source["source"] == canonical["source"]
                        && source["range_sha256"] == canonical["read"]["sha256"]
                        && source["source_offset"] == dex["source_offset"]
                        && (source.get("inventory_row_index").is_none()
                            || source["inventory_row_index"].as_u64()
                                == Some(inventory_row_index as u64))
                });
            let alias_key = (*object_index, inventory_row_index, offset);
            let existing_alias = alias_sources
                .get(&alias_key)
                .copied()
                .flatten()
                .is_some_and(|source_index| sources[source_index] == projected);
            if let Some(source_index) = canonical_slot {
                for (field, value) in projected.as_object().unwrap() {
                    if field != "kind" && field != "verification" && field != "storage_scope" {
                        sources[source_index][field] = value.clone();
                    }
                }
                sources[source_index]["source_projection_verification"] =
                    json!("current_verified_range_and_shared_content_inspection");
                accounting.upgraded_links += 1;
            } else if !existing_alias {
                alias_sources.insert(alias_key, Some(sources.len()));
                sources.push(projected);
                accounting.appended_links += 1;
            }
            accounting.admitted_metadata_bytes += metadata_bytes;
            accounting.projected_links += 1;
        }
        if !dex_seen {
            accounting.skipped_no_dex_rows += 1;
        }
    }
    projection_checkpoint(root)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn identical_static_runtime_groups_content_without_losing_instance_or_claiming_sdk() {
        let hash = "a".repeat(64);
        let row = json!({"local_content_status":"complete_range_hash_verified","source":{"pid":1,"package":"com.pkg"},"object_inspection":{"derived_objects":[{"kind":"dex","sha256":hash,"length":100,"sha1_signature_verified":true,"adler32_checksum_verified":true,"class_index":{"status":"complete_class_def_index","declared_classes":2,"indexed_unique_classes":2,"classes":["Lcom/pkg/A;","Lx/y/Z;"]}}]}});
        let sets = json!([{"sha256":hash,"bytes":100,"canonical_relative_path":"apk/classes.dex"}]);
        let result = objects(&[row], &sets, "com.pkg", &json!([]), &json!("parent-one"));
        let obj = &result["objects"][0];
        assert_eq!(result["objects"].as_array().unwrap().len(), 1);
        assert_eq!(obj["sources"].as_array().unwrap().len(), 2);
        assert_eq!(obj["sources"][0]["source"]["pid"], 1);
        assert_eq!(obj["sources"][0]["parent_id"], "parent-one");
        assert_eq!(obj["class_hints"]["unknown"], 1);
        assert_eq!(obj["ownership"], "mixed_or_unknown");
    }
    #[test]
    fn anonymous_unpacked_dex_keeps_its_class_index_and_a_secneo_shell_stays_separate() {
        let unpacked = "a".repeat(64);
        let shell = "b".repeat(64);
        let sets = json!([
            {
                "sha256": unpacked,
                "bytes": 12415448,
                "canonical_relative_path": "apk-dex/anon-15404-73dc0ba000.dex",
                "semantic": {
                    "class_defs": 3,
                    "class_descriptors_truncated": false,
                    "class_descriptors": ["Lcn/gov/tax/its/MainActivity;", "Lcom/alipay/mobile/A;", "Lcom/secneo/apkwrapper/H;"]
                }
            },
            {
                "sha256": shell,
                "bytes": 18802080,
                "canonical_relative_path": "runtime/base.vdex",
                "semantic": {
                    "class_defs": 2,
                    "class_descriptors_truncated": false,
                    "class_descriptors": ["Lcom/secneo/apkwrapper/AP;", "Lcom/secneo/apkwrapper/H;"]
                }
            }
        ]);
        let result = objects(&[], &sets, "cn.gov.tax.its", &json!([]), &json!(null));
        let objects = result["objects"].as_array().unwrap();
        assert_eq!(objects.len(), 2);
        let unpacked_row = objects
            .iter()
            .find(|row| row["sha256"] == unpacked)
            .unwrap();
        assert_eq!(unpacked_row["sources"][0]["kind"], "anonymous_unpacked_dex");
        assert_eq!(unpacked_row["declared_classes"], 3);
        assert_eq!(
            unpacked_row["class_hints"]["package_namespace_candidates"],
            1
        );
        assert_eq!(
            unpacked_row["class_hints"]["known_library_namespace_candidates"],
            1
        );
        assert_eq!(unpacked_row["ownership"], "mixed_or_unknown");
        let shell_row = objects.iter().find(|row| row["sha256"] == shell).unwrap();
        assert_eq!(shell_row["ownership"], "packer_shell");
    }
    #[test]
    fn shell_mixed_with_business_and_a_partial_index_stay_candidates() {
        let mixed = "d".repeat(64);
        let partial = "e".repeat(64);
        let sets = json!([
            {
                "sha256": mixed,
                "bytes": 100,
                "canonical_relative_path": "runtime/mixed.dex",
                "semantic": {
                    "class_defs": 2,
                    "class_descriptors_truncated": false,
                    "class_descriptors": ["Lcom/pkg/Main;", "Lcom/secneo/apkwrapper/H;"]
                }
            },
            {
                "sha256": partial,
                "bytes": 100,
                "canonical_relative_path": "runtime/partial.dex",
                "semantic": {
                    "class_defs": 6,
                    "class_descriptors_truncated": true,
                    "class_descriptors": ["Lcom/pkg/OnlySeen;"]
                }
            }
        ]);
        let result = objects(&[], &sets, "com.pkg", &json!([]), &json!(null));
        let objects = result["objects"].as_array().unwrap();
        let mixed_row = objects.iter().find(|row| row["sha256"] == mixed).unwrap();
        assert_eq!(mixed_row["ownership"], "mixed_or_unknown");
        assert!(mixed_row["classification_basis"]
            .as_str()
            .unwrap()
            .contains("candidate"));
        let partial_row = objects.iter().find(|row| row["sha256"] == partial).unwrap();
        assert_eq!(partial_row["class_index_status"], "partial_class_def_index");
        assert_eq!(partial_row["ownership"], "mixed_or_unknown");
        assert!(partial_row["classification_basis"]
            .as_str()
            .unwrap()
            .contains("candidate"));
    }
    #[test]
    fn complete_runtime_index_is_not_replaced_by_a_truncated_producer_list() {
        let hash = "c".repeat(64);
        let row = json!({"local_content_status":"complete_range_hash_verified","source":{"package":"com.pkg","pid":1},"object_inspection":{"derived_objects":[{"kind":"dex","sha256":hash,"length":100,"declared_file_bytes":100,"length_matches_declared":true,"class_index":{"status":"complete_class_def_index","declared_classes":2,"indexed_unique_classes":2,"omitted_classes":0,"classes":["Lcom/pkg/A;","Lcom/pkg/B;"]}}]}});
        let sets = json!([{
            "sha256": hash,
            "bytes": 100,
            "canonical_relative_path": "runtime/bound-1.code",
            "semantic": {
                "declared_file_size": 100,
                "class_defs": 2,
                "class_descriptors_truncated": true,
                "class_descriptors": ["Lcom/pkg/A;"]
            }
        }]);
        let result = objects(&[row], &sets, "com.pkg", &json!([]), &json!(null));
        let object = &result["objects"][0];
        assert_eq!(object["class_index_status"], "complete_class_def_index");
        assert_eq!(object["indexed_classes"], 2);
        assert_eq!(object["classes"].as_array().unwrap().len(), 2);
        assert_eq!(object["declared_file_bytes"], 100);
        assert_eq!(object["length_matches_declared"], true);
        assert_eq!(object["sources"].as_array().unwrap().len(), 2);
    }
    #[test]
    fn checksum_failed_structural_classes_are_visible_but_never_verified_recovery() {
        let hash = "a".repeat(64);
        let row = json!({"local_content_status":"complete_range_hash_verified","mapping":{"path":"base.apk"},"source":{"package":"com.example.application","pid":1},"object_inspection":{"derived_objects":[{"kind":"dex","sha256":hash,"length":100,"sha1_signature_verified":false,"adler32_checksum_verified":true,"class_index":{"status":"complete_class_def_index","declared_classes":4,"indexed_unique_classes":4,"classes":["Lcom/stub/StubApp;","Lcom/example/loader/Configuration;","Lcom/example/loader/DtcLoader;","Lcom/example/loader/A;"]}}]}});
        let result = objects(
            &[row],
            &json!([]),
            "com.example.application",
            &json!([]),
            &json!("parent"),
        );
        assert_eq!(result["objects"].as_array().unwrap().len(), 1);
        assert_eq!(result["objects"][0]["indexed_classes"], 4);
        assert_eq!(result["objects"][0]["sha1_signature_verified"], false);
        assert!(result["objects"][0]["validation_status"]
            .as_str()
            .unwrap()
            .starts_with("checksum_failed"));
        assert_eq!(result["objects"][0]["ownership"], "unknown");
        assert!(result["objects"][0]["sources"][0]["storage_scope"]
            .as_str()
            .unwrap()
            .contains("not decrypted"));
    }
    #[test]
    fn legacy_missing_checksums_remains_unknown() {
        let row = json!({"local_content_status":"complete_range_hash_verified","source":{"package":"com.pkg"},"object_inspection":{"derived_objects":[{"kind":"dex","sha256":"a".repeat(64),"length":100,"class_index":{"status":"complete_class_def_index","declared_classes":1,"indexed_unique_classes":1,"classes":["Lcom/pkg/A;"]}}]}});
        let index = objects(&[row], &json!([]), "com.pkg", &json!([]), &Value::Null);
        let object = &index["objects"][0];
        assert!(object["sha1_signature_verified"].is_null());
        assert!(object["adler32_checksum_verified"].is_null());
        assert_eq!(
            object["validation_status"],
            "checksum_unknown; structure_index_only"
        );
        assert_eq!(
            object["sources"][0]["verification"],
            "bounded_structure_only; checksum_failed_or_unknown"
        );
    }
    #[test]
    fn foreign_package_does_not_enter_this_parent_index() {
        let row = json!({"local_content_status":"complete_range_hash_verified","source":{"package":"other.pkg"},"object_inspection":{"derived_objects":[{"kind":"dex","sha256":"a".repeat(64),"length":100,"sha1_signature_verified":true,"adler32_checksum_verified":true}]}});
        assert_eq!(
            objects(&[row], &json!([]), "com.pkg", &json!([]), &json!("parent"))["objects"]
                .as_array()
                .unwrap()
                .len(),
            0
        );
    }
    #[test]
    fn malformed_and_over_limit_index_is_explicit_partial() {
        let mut bytes = vec![0; 112];
        bytes[96..100].copy_from_slice(&20000_u32.to_le_bytes());
        let result = classes(&bytes, &mut 1048576);
        assert_eq!(result["processed_classes"], 16384);
        assert_eq!(result["omitted_classes"], 3616);
        assert_eq!(result["status"], "partial_class_def_index");
    }
}

#[cfg(test)]
mod inventory_projection_tests {
    use super::*;
    use std::{path::PathBuf, time::Duration};

    fn root() -> PathBuf {
        std::env::temp_dir().join(format!(
            "me-dex-inventory-projection-{}",
            uuid::Uuid::new_v4()
        ))
    }

    fn canonical() -> Value {
        json!({
            "local_content_status":"complete_range_hash_verified",
            "source_identity_status":"producer_identity_recorded",
            "source_report":"runtime/bound-source-one.json",
            "source_report_sha256":"c".repeat(64),
            "source_record_index":3,
            "relative_path":"runtime/bound-one.code",
            "source":{"package":"com.pkg","pid":1,"birth_ns":11,"uid":1000,"exec_id":2,"boot_id":"boot"},
            "mapping":{"start":4096,"end":8192,"path":"/base.apk"},
            "admitted":true,
            "read":{"requested_start":4096,"requested_length":512,"actual_start":4096,"actual_length":512,"sha256":"a".repeat(64),"admission":"qualified_live_copy","read_status":"complete","write_status":"complete","read_error":null,"write_error":null,"torn":true,"paused":false},
            "object_inspection":{"derived_objects":[{
                "kind":"dex","sha256":"b".repeat(64),"length":100,"source_offset":16,
                "sha1_signature_verified":true,"adler32_checksum_verified":true,
                "layout_diagnostics":{"status":"declared_spans_cover_file"},
                "class_index":{"status":"complete_class_def_index","declared_classes":1,"indexed_unique_classes":1,"classes":["Lcom/pkg/A;"]}
            }]},
            "inspection_ref":0,"inspection_content_key":format!("{}:512", "a".repeat(64)),
        })
    }

    fn alias() -> Value {
        let mut row = canonical();
        row.as_object_mut().unwrap().remove("object_inspection");
        row["source_report"] = json!("runtime/bound-source-two.json");
        row["source_report_sha256"] = json!("d".repeat(64));
        row["source_record_index"] = json!(7);
        row["relative_path"] = json!("runtime/bound-two.code");
        row["source"]["pid"] = json!(2);
        row["source"]["birth_ns"] = json!(22);
        row["source"]["exec_id"] = json!(3);
        row["mapping"]["start"] = json!(8192);
        row["mapping"]["end"] = json!(12288);
        row["mapping"]["path"] = json!("/memfd:alias");
        row["read"]["requested_start"] = json!(8192);
        row["read"]["actual_start"] = json!(8192);
        row["read"]["torn"] = json!(false);
        row
    }

    fn index(runtime: &[Value]) -> Value {
        objects(runtime, &json!([]), "com.pkg", &json!([]), &json!("parent"))
    }

    fn content_without_sources(index: &Value) -> Value {
        let mut object = index["objects"][0].clone();
        object.as_object_mut().unwrap().remove("sources");
        object
    }

    #[test]
    fn aliases_preserve_independent_identity_address_report_and_torn_state() {
        let canonical = canonical();
        let runtime = [canonical.clone()];
        let mut index = index(&runtime);
        let content = content_without_sources(&index);
        let original_verification = index["objects"][0]["sources"][0]["verification"].clone();
        attach_inventory_sources(
            &root(),
            &mut index,
            &runtime,
            &[canonical, alias()],
            "com.pkg",
            &json!("parent"),
        )
        .unwrap();
        assert_eq!(content_without_sources(&index), content);
        let sources = index["objects"][0]["sources"].as_array().unwrap();
        assert_eq!(sources.len(), 2);
        assert_eq!(sources[0]["kind"], "runtime");
        assert_eq!(sources[0]["verification"], original_verification);
        assert_eq!(sources[0]["source"]["pid"], 1);
        assert_eq!(sources[0]["source_record_index"], 3);
        assert_eq!(sources[0]["source_absolute_start"], 4112);
        assert_eq!(sources[0]["source_torn"], true);
        assert_eq!(sources[1]["kind"], "runtime_range_inventory");
        assert_eq!(sources[1]["source"]["pid"], 2);
        assert_eq!(sources[1]["source"]["birth_ns"], 22);
        assert_eq!(sources[1]["source"]["exec_id"], 3);
        assert_eq!(sources[1]["source_report"], "runtime/bound-source-two.json");
        assert_eq!(sources[1]["source_report_sha256"], "d".repeat(64));
        assert_eq!(sources[1]["source_record_index"], 7);
        assert_eq!(sources[1]["inventory_row_index"], 1);
        assert_eq!(sources[1]["source_absolute_start"], 8208);
        assert_eq!(sources[1]["source_torn"], false);
        assert_eq!(sources[1]["storage_scope"], "observed_runtime_code_slice");
        assert_eq!(sources[1]["parent_id"], "parent");
        assert_eq!(index["runtime_inventory_projection"]["complete"], true);
        assert_eq!(index["runtime_inventory_projection"]["projected_links"], 2);
        assert_eq!(index["runtime_inventory_projection"]["upgraded_links"], 1);
        assert_eq!(index["runtime_inventory_projection"]["appended_links"], 1);
    }

    #[test]
    fn bad_keys_refs_report_hashes_identity_and_ranges_never_attach() {
        let runtime = [canonical()];
        let mut index = index(&runtime);
        let sources_before = index["objects"][0]["sources"].clone();
        let mut bad_key = alias();
        bad_key["inspection_content_key"] = json!(format!("{}:512", "f".repeat(64)));
        let mut bad_ref = alias();
        bad_ref["inspection_ref"] = json!(5);
        let mut bad_report = alias();
        bad_report["source_report_sha256"] = json!("not-a-sha");
        let mut bad_identity = alias();
        bad_identity["source"]["uid"] = Value::Null;
        let mut bad_range = alias();
        bad_range["read"]["actual_length"] = json!(1000);
        let mut bad_content = alias();
        bad_content["read"]["sha256"] = json!("e".repeat(64));
        bad_content["inspection_content_key"] = json!(format!("{}:512", "e".repeat(64)));
        let mut foreign = alias();
        foreign["source"]["package"] = json!("other.pkg");
        let mut bad_status = alias();
        bad_status["source_identity_status"] = json!("unknown_or_conflicting");
        let mut unsafe_path = alias();
        unsafe_path["relative_path"] = json!("../bound-two.code");
        let mut conflicting_report_hash = canonical();
        conflicting_report_hash["source_report_sha256"] = json!("f".repeat(64));
        let mut conflicting_report_identity = canonical();
        conflicting_report_identity["source"]["pid"] = json!(9);
        attach_inventory_sources(
            &root(),
            &mut index,
            &runtime,
            &[
                bad_key,
                bad_ref,
                bad_report,
                bad_identity,
                bad_range,
                bad_content,
                foreign,
                bad_status,
                unsafe_path,
                conflicting_report_hash,
                conflicting_report_identity,
            ],
            "com.pkg",
            &json!("parent"),
        )
        .unwrap();
        assert_eq!(index["objects"][0]["sources"], sources_before);
        assert_eq!(index["runtime_inventory_projection"]["invalid_rows"], 11);
        assert_eq!(index["runtime_inventory_projection"]["complete"], false);
    }

    #[test]
    fn repeated_projection_uses_source_slots_without_duplicating_aliases() {
        let canonical = canonical();
        let runtime = [canonical.clone()];
        let inventory = [canonical, alias()];
        let mut index = index(&runtime);
        attach_inventory_sources(
            &root(),
            &mut index,
            &runtime,
            &inventory,
            "com.pkg",
            &json!("parent"),
        )
        .unwrap();
        let before = index["objects"].clone();
        attach_inventory_sources(
            &root(),
            &mut index,
            &runtime,
            &inventory,
            "com.pkg",
            &json!("parent"),
        )
        .unwrap();
        assert_eq!(index["objects"], before);
        assert_eq!(index["runtime_inventory_projection"]["projected_links"], 2);
        assert_eq!(index["runtime_inventory_projection"]["appended_links"], 0);
        assert_eq!(index["runtime_inventory_projection"]["complete"], true);
    }

    #[test]
    fn out_of_range_derived_offset_and_ambiguous_content_never_attach() {
        let canonical = canonical();
        let mut index = index(std::slice::from_ref(&canonical));
        let before = index["objects"][0]["sources"].clone();
        let mut bad_offset = canonical.clone();
        bad_offset["object_inspection"]["derived_objects"][0]["source_offset"] = json!(500);
        attach_inventory_sources(
            &root(),
            &mut index,
            &[bad_offset],
            &[alias()],
            "com.pkg",
            &json!("parent"),
        )
        .unwrap();
        assert_eq!(index["objects"][0]["sources"], before);
        assert_eq!(
            index["runtime_inventory_projection"]["invalid_derived_links"],
            1
        );
        let duplicate = index["objects"][0].clone();
        index["objects"].as_array_mut().unwrap().push(duplicate);
        attach_inventory_sources(
            &root(),
            &mut index,
            &[canonical],
            &[alias()],
            "com.pkg",
            &json!("parent"),
        )
        .unwrap();
        assert_eq!(index["objects"][0]["sources"], before);
        assert_eq!(index["objects"][1]["sources"], before);
        assert_eq!(
            index["runtime_inventory_projection"]["unmatched_dex_links"],
            1
        );
        assert_eq!(index["runtime_inventory_projection"]["complete"], false);
    }

    #[test]
    fn metadata_limit_retains_admitted_prefix_without_touching_classes_or_old_sources() {
        let canonical = canonical();
        let runtime = [canonical.clone()];
        let mut measured = index(&runtime);
        attach_inventory_sources(
            &root(),
            &mut measured,
            &runtime,
            std::slice::from_ref(&canonical),
            "com.pkg",
            &json!("parent"),
        )
        .unwrap();
        let first_bytes = measured["runtime_inventory_projection"]["admitted_metadata_bytes"]
            .as_u64()
            .unwrap() as usize;
        let mut bounded = index(&runtime);
        let content = content_without_sources(&bounded);
        attach_inventory_sources_with_limit(
            &root(),
            &mut bounded,
            &runtime,
            &[canonical.clone(), alias()],
            "com.pkg",
            &json!("parent"),
            first_bytes,
        )
        .unwrap();
        assert_eq!(content_without_sources(&bounded), content);
        assert_eq!(
            bounded["objects"][0]["sources"].as_array().unwrap().len(),
            1
        );
        assert_eq!(
            bounded["objects"][0]["sources"][0]["inventory_row_index"],
            0
        );
        assert_eq!(
            bounded["runtime_inventory_projection"]["projected_links"],
            1
        );
        assert_eq!(bounded["runtime_inventory_projection"]["omitted_links"], 1);
        assert_eq!(
            bounded["runtime_inventory_projection"]["admitted_metadata_bytes"],
            first_bytes
        );
        assert_eq!(bounded["runtime_inventory_projection"]["complete"], false);
        let mut zero = index(&runtime);
        let original_sources = zero["objects"][0]["sources"].clone();
        attach_inventory_sources_with_limit(
            &root(),
            &mut zero,
            &runtime,
            &[canonical, alias()],
            "com.pkg",
            &json!("parent"),
            0,
        )
        .unwrap();
        assert_eq!(zero["objects"][0]["sources"], original_sources);
        assert_eq!(zero["runtime_inventory_projection"]["omitted_links"], 2);
        assert_eq!(zero["runtime_inventory_projection"]["complete"], false);
    }

    #[test]
    fn unverified_uninspected_and_no_dex_rows_are_scope_skips_not_invalid_references() {
        let mut no_dex = canonical();
        no_dex["object_inspection"]["derived_objects"] = json!([]);
        let runtime = [no_dex.clone()];
        let mut unverified = alias();
        unverified["local_content_status"] = json!("unknown_or_failed");
        let mut uninspected = alias();
        uninspected["inspection_ref"] = Value::Null;
        let mut index = index(&runtime);
        attach_inventory_sources(
            &root(),
            &mut index,
            &runtime,
            &[no_dex, unverified, uninspected],
            "com.pkg",
            &json!("parent"),
        )
        .unwrap();
        let report = &index["runtime_inventory_projection"];
        assert_eq!(report["complete"], true);
        assert_eq!(report["invalid_rows"], 0);
        assert_eq!(report["valid_rows"], 1);
        assert_eq!(report["skipped_unverified_rows"], 1);
        assert_eq!(report["skipped_uninspected_rows"], 1);
        assert_eq!(report["skipped_no_dex_rows"], 1);
    }

    #[test]
    fn expired_output_scope_propagates_and_never_claims_complete_projection() {
        let root = root();
        let _guard =
            super::super::session_budget::Guard::install(vec![root.clone()], 0, 1).unwrap();
        std::thread::sleep(Duration::from_millis(3));
        let runtime = [canonical()];
        let mut index = index(&runtime);
        let before = index["objects"][0]["sources"].clone();
        let error = attach_inventory_sources(
            &root,
            &mut index,
            &runtime,
            &[alias()],
            "com.pkg",
            &json!("parent"),
        )
        .unwrap_err();
        assert!(error.contains("time_budget_exhausted"));
        assert_eq!(index["objects"][0]["sources"], before);
        assert_eq!(index["runtime_inventory_projection"]["complete"], false);
        assert!(index["runtime_inventory_projection"]["stop_reason"]
            .as_str()
            .unwrap()
            .contains("time_budget_exhausted"));
    }

    #[tokio::test]
    async fn current_parent_cancellation_is_propagated_without_new_deadline() {
        let runtime = [canonical()];
        let mut index = index(&runtime);
        let deadline = super::super::session_deadline::Deadline::new(Duration::from_secs(1));
        let result = deadline
            .run(async {
                super::super::session_deadline::current().unwrap().cancel();
                let result = attach_inventory_sources(
                    &root(),
                    &mut index,
                    &runtime,
                    &[alias()],
                    "com.pkg",
                    &json!("parent"),
                );
                assert_eq!(index["runtime_inventory_projection"]["complete"], false);
                result
            })
            .await;
        assert!(result.unwrap_err().contains("parent_cancelled"));
    }
}
