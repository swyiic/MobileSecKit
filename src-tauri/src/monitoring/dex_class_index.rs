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
                object["ownership"] = json!(if indexed > 0 && packer == indexed {
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
