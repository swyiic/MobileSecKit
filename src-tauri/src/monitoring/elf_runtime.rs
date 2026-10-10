//! Bounded ELF64 PT_LOAD views over verified ranges; never fills holes or reconstructs a file.
use serde_json::{json, Value};
use std::{collections::BTreeMap, path::Path};

fn u16(b: &[u8], n: usize) -> Option<u16> {
    Some(u16::from_le_bytes(
        b.get(n..n.checked_add(2)?)?.try_into().ok()?,
    ))
}
fn u32(b: &[u8], n: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        b.get(n..n.checked_add(4)?)?.try_into().ok()?,
    ))
}
fn u64(b: &[u8], n: usize) -> Option<u64> {
    Some(u64::from_le_bytes(
        b.get(n..n.checked_add(8)?)?.try_into().ok()?,
    ))
}

// Same ELF64 little-endian header/program-header layout used by KernSight elf.rs.
// This header-only view makes no claims about dynamic symbols or relocation semantics.
pub(super) fn header(b: &[u8]) -> Option<Value> {
    if b.get(..7)? != b"\x7fELF\x02\x01\x01"
        || u16(b, 52)? != 64
        || u32(b, 20)? != 1
        || !matches!(u16(b, 16)?, 2 | 3)
    {
        return None;
    }
    let off = usize::try_from(u64(b, 32)?).ok()?;
    let count = u16(b, 56)? as usize;
    if off < 64 || u16(b, 54)? != 56 || count == 0 || count > 128 {
        return None;
    }
    let end = off.checked_add(count.checked_mul(56)?)?;
    if end > b.len() {
        return None;
    }
    let mut loads = Vec::new();
    for i in 0..count {
        let o = off + i * 56;
        if u32(b, o)? != 1 {
            continue;
        }
        let f = u64(b, o + 8)?;
        let va = u64(b, o + 16)?;
        let fs = u64(b, o + 32)?;
        let ms = u64(b, o + 40)?;
        let align = u64(b, o + 48)?;
        f.checked_add(fs)?;
        va.checked_add(ms)?;
        if fs > ms || (align > 1 && (!align.is_power_of_two() || f % align != va % align)) {
            return None;
        }
        loads.push(json!({"file_offset":f,"virtual_address":va,"file_bytes":fs,"memory_bytes":ms,"flags":u32(b,o+4)?}));
    }
    if loads.is_empty() {
        return None;
    }
    let shoff = u64(b, 40)?;
    let shbytes = (u16(b, 58)? as u64).checked_mul(u16(b, 60)? as u64)?;
    shoff.checked_add(shbytes)?;
    Some(
        json!({"status":"bounded_elf64_header_and_program_table","machine":u16(b,18)?,"header_bytes":end,"loads":loads,"section_table_offset":shoff,"section_table_bytes":shbytes,"complete_file_parsed":false}),
    )
}
// The input has already been sorted once per module, rather than once per load.
fn gaps(
    start: u64,
    end: u64,
    ranges: &[(u64, u64)],
    checkpoint: &mut impl FnMut() -> Result<(), String>,
) -> Result<Vec<(u64, u64)>, String> {
    let mut p = start;
    let mut out = Vec::new();
    for &(a, b) in ranges {
        checkpoint()?;
        if b <= p || a >= end {
            continue;
        }
        if a > p {
            out.push((p, a.min(end)));
        }
        p = p.max(b.min(end));
    }
    if p < end {
        out.push((p, end));
    }
    Ok(out)
}
pub(super) fn module_views(rows: &[Value]) -> Value {
    module_views_inner(rows, &mut || Ok(())).expect("unscoped ELF analysis has no scope failure")
}

pub(super) fn module_views_scoped(root: &Path, rows: &[Value]) -> Result<Value, String> {
    module_views_inner(rows, &mut || {
        super::session_deadline::check()?;
        super::session_budget::charge(root, 0).map_err(|error| error.to_string())
    })
}

fn module_views_inner(
    rows: &[Value],
    checkpoint: &mut impl FnMut() -> Result<(), String>,
) -> Result<Value, String> {
    checkpoint()?;
    let mut groups = BTreeMap::<String, Vec<&Value>>::new();
    for r in rows {
        checkpoint()?;
        let Some(path) = r["mapping"]["path"].as_str() else {
            continue;
        };
        if !path.ends_with(".so") || r["local_content_status"] != "complete_range_hash_verified" {
            continue;
        }
        // Do not combine separate producer copy windows, inode generations or task identities.
        let key = json!([r["source_report"], r["source"], r["mapping"]["inode"], path]).to_string();
        groups.entry(key).or_default().push(r);
    }
    let mut modules = Vec::new();
    for rows in groups.values() {
        checkpoint()?;
        // Exact repeated observations do not conflict. Keep every original row
        // for source attribution, but sort and sweep the unique interval keys.
        let mut unique = BTreeMap::new();
        let mut invalid_range = false;
        for row in rows {
            checkpoint()?;
            let (Some(start), Some(len), Some(hash)) = (
                row["read"]["actual_start"].as_u64(),
                row["read"]["actual_length"].as_u64(),
                row["read"]["sha256"]
                    .as_str()
                    .filter(|hash| !hash.is_empty()),
            ) else {
                invalid_range = true;
                continue;
            };
            let Some(end) = start.checked_add(len).filter(|_| len > 0) else {
                invalid_range = true;
                continue;
            };
            unique.insert((start, len, hash), end);
        }
        let mut prior_end = None::<u64>;
        let mut conflicting_overlap = false;
        let mut intervals = Vec::with_capacity(unique.len());
        for ((start, _, _), end) in unique {
            checkpoint()?;
            if prior_end.is_some_and(|prior| start < prior) {
                conflicting_overlap = true;
            }
            prior_end = Some(prior_end.map_or(end, |prior| prior.max(end)));
            intervals.push((start, end));
        }
        if invalid_range || conflicting_overlap {
            modules.push(json!({"schema":"mobilee.verified-elf-load-view/v1","path":rows[0]["mapping"]["path"],"source":rows[0]["source"],"source_report":rows[0]["source_report"],"all_load_file_bytes_covered":null,"all_load_memory_bytes_covered":null,"complete_file_reconstructed":false,"association":if invalid_range {"unknown_missing_or_overflowing_range"} else {"unknown_conflicting_overlapping_ranges"},"segments":[],"torn":true,"ownership":"unknown"}));
            continue;
        }
        let mut first = None;
        for row in rows {
            checkpoint()?;
            if row["object_inspection"]["elf_header"]["status"]
                == "bounded_elf64_header_and_program_table"
            {
                first = Some(*row);
                break;
            }
        }
        let Some(first) = first else {
            continue;
        };
        let h = &first["object_inspection"]["elf_header"];
        let Some(loads) = h["loads"].as_array() else {
            continue;
        };
        let mut anchors = Vec::new();
        for l in loads {
            checkpoint()?;
            if l["file_offset"] == 0
                && l["file_bytes"]
                    .as_u64()
                    .is_some_and(|n| n >= h["header_bytes"].as_u64().unwrap_or(u64::MAX))
            {
                anchors.push(l);
            }
        }
        if anchors.len() != 1 {
            continue;
        }
        let Some(bias) = first["read"]["actual_start"]
            .as_u64()
            .and_then(|s| s.checked_sub(anchors[0]["virtual_address"].as_u64()?))
        else {
            continue;
        };
        let mut segments = Vec::new();
        let mut file_ranges = Vec::new();
        for l in loads {
            checkpoint()?;
            let (Some(off), Some(va), Some(fs), Some(ms)) = (
                l["file_offset"].as_u64(),
                l["virtual_address"].as_u64(),
                l["file_bytes"].as_u64(),
                l["memory_bytes"].as_u64(),
            ) else {
                continue;
            };
            let (Some(start), Some(end), Some(memend), Some(fileend)) = (
                bias.checked_add(va),
                bias.checked_add(va).and_then(|a| a.checked_add(fs)),
                bias.checked_add(va).and_then(|a| a.checked_add(ms)),
                off.checked_add(fs),
            ) else {
                continue;
            };
            let mut sources = Vec::new();
            for r in rows {
                checkpoint()?;
                let (Some(a), Some(n)) = (
                    r["read"]["actual_start"].as_u64(),
                    r["read"]["actual_length"].as_u64(),
                ) else {
                    continue;
                };
                let Some(b) = a.checked_add(n) else {
                    continue;
                };
                let s = a.max(start);
                let e = b.min(end);
                if s < e {
                    sources.push(json!({"relative_path":r["relative_path"],"sha256":r["read"]["sha256"],"source_offset":s-a,"length":e-s,"file_offset":off+(s-start),"virtual_start":s}));
                }
            }
            segments.push(json!({"file_offset":off,"virtual_start":start,"file_bytes":fs,"memory_bytes":ms,"file_backed_gaps":gaps(start,end,&intervals,checkpoint)?,"memory_gaps":gaps(start,memend,&intervals,checkpoint)?,"source_slices":sources,"derived_bytes_sha256":null,"derived_hash_status":"source_full_hashes_verified; no_new_slice_hash_budget"}));
            file_ranges.push((off, fileend));
        }
        if segments.len() != loads.len() {
            continue;
        }
        let file_complete = segments
            .iter()
            .all(|s| s["file_backed_gaps"].as_array().is_some_and(Vec::is_empty));
        let mem_complete = segments
            .iter()
            .all(|s| s["memory_gaps"].as_array().is_some_and(Vec::is_empty));
        let shoff = h["section_table_offset"].as_u64().unwrap_or(0);
        let shbytes = h["section_table_bytes"].as_u64().unwrap_or(0);
        checkpoint()?;
        file_ranges.sort_unstable();
        checkpoint()?;
        let shgaps = gaps(
            shoff,
            shoff.saturating_add(shbytes),
            &file_ranges,
            checkpoint,
        )?;
        let mut torn = false;
        let mut limits = Vec::new();
        let mut verified_bytes = Some(0_u64);
        for row in rows {
            checkpoint()?;
            torn |= row["read"]["torn"] == true;
            if let Some(reason) = row["selection_limit_reason"].as_str() {
                limits.push(reason);
            }
            verified_bytes = verified_bytes
                .zip(row["read"]["actual_length"].as_u64())
                .and_then(|(total, length)| total.checked_add(length));
        }
        let mapping_copy = if limits.is_empty() {
            "unknown"
        } else if limits
            .iter()
            .all(|reason| *reason == "full_mapping_selected")
        {
            "full_mapping_selected"
        } else if limits.iter().any(|reason| {
            *reason == "per_range_cap" || *reason == "runtime_payload_budget_metadata_reserve"
        }) {
            "truncated_by_cap_or_budget"
        } else {
            "mixed_or_other"
        };
        let symbol_analysis = if mapping_copy == "truncated_by_cap_or_budget" {
            "not_performed_on_budget_or_per_range_truncated_copy"
        } else if file_complete && shgaps.is_empty() {
            "file_backed_load_and_section_bytes_covered; process was not paused; symbols not parsed in this import"
        } else if file_complete {
            "file_backed_load_bytes_covered; section table still has gaps; dynsym is catalogued separately when those bytes sit in the retained mapping"
        } else {
            "not_performed_on_incomplete_memory_file"
        };
        modules.push(json!({"schema":"mobilee.verified-elf-load-view/v1","path":first["mapping"]["path"],"source":first["source"],"source_report":first["source_report"],"load_bias":bias,"verified_range_count":rows.len(),"verified_range_bytes":verified_bytes,"association":"inferred_from_unique_offset_zero_PT_LOAD_and_retained_header; kernel_file_offsets_not_recorded","torn":torn,"all_load_file_bytes_covered":file_complete,"all_load_memory_bytes_covered":mem_complete,"section_table_gaps":shgaps,"segments":segments,"complete_file_reconstructed":file_complete && shgaps.is_empty() && !torn,"mapping_copy":mapping_copy,"symbol_analysis":symbol_analysis,"ownership":"unknown","scope":"this producer window and listed verified ranges only"}));
    }
    checkpoint()?;
    Ok(json!(modules))
}
#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> Vec<u8> {
        let mut b = vec![0u8; 192];
        b[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
        b[16..18].copy_from_slice(&3u16.to_le_bytes());
        b[18..20].copy_from_slice(&183u16.to_le_bytes());
        b[20..24].copy_from_slice(&1u32.to_le_bytes());
        b[32..40].copy_from_slice(&64u64.to_le_bytes());
        b[40..48].copy_from_slice(&192u64.to_le_bytes());
        b[52..54].copy_from_slice(&64u16.to_le_bytes());
        b[54..56].copy_from_slice(&56u16.to_le_bytes());
        b[56..58].copy_from_slice(&1u16.to_le_bytes());
        b[58..60].copy_from_slice(&64u16.to_le_bytes());
        b[60..62].copy_from_slice(&1u16.to_le_bytes());
        b[64..68].copy_from_slice(&1u32.to_le_bytes());
        b[96..104].copy_from_slice(&192u64.to_le_bytes());
        b[104..112].copy_from_slice(&256u64.to_le_bytes());
        b
    }
    #[test]
    fn file_backed_complete_is_not_bss_or_whole_file_complete() {
        let h = header(&fixture()).unwrap();
        let r = json!({"mapping":{"path":"/data/app/id/lib.so","inode":1},"source":{"pid":1},"source_report":"one-window","read":{"actual_start":4096,"actual_length":192,"sha256":"verified-source"},"relative_path":"runtime/bound.code","local_content_status":"complete_range_hash_verified","object_inspection":{"elf_header":h}});
        let v = module_views(&[r]);
        assert_eq!(v[0]["all_load_file_bytes_covered"], true);
        assert_eq!(v[0]["all_load_memory_bytes_covered"], false);
        assert_eq!(v[0]["complete_file_reconstructed"], false);
        assert_eq!(v[0]["section_table_gaps"], json!([[192, 256]]));
        assert_eq!(
            v[0]["symbol_analysis"],
            "file_backed_load_bytes_covered; section table still has gaps; dynsym is catalogued separately when those bytes sit in the retained mapping"
        );
        assert_eq!(v[0]["mapping_copy"], "unknown");
    }
    #[test]
    fn budget_truncated_elf_is_not_described_as_a_covered_load() {
        let h = header(&fixture()).unwrap();
        let r = json!({"mapping":{"path":"/data/app/id/lib.so","inode":1},"source":{"pid":1},"source_report":"one-window","selection_limit_reason":"per_range_cap","read":{"actual_start":4096,"actual_length":64,"sha256":"verified-source","torn":true},"relative_path":"runtime/bound.code","local_content_status":"complete_range_hash_verified","object_inspection":{"elf_header":h}});
        let v = module_views(&[r]);
        assert_eq!(v[0]["mapping_copy"], "truncated_by_cap_or_budget");
        assert_eq!(
            v[0]["symbol_analysis"],
            "not_performed_on_budget_or_per_range_truncated_copy"
        );
        assert_eq!(v[0]["complete_file_reconstructed"], false);
    }
    #[test]
    fn full_mapping_torn_read_keeps_load_coverage_separate_from_reconstruction() {
        let h = header(&fixture()).unwrap();
        let r = json!({"mapping":{"path":"/data/app/id/lib.so","inode":1},"source":{"pid":1},"source_report":"one-window","selection_limit_reason":"full_mapping_selected","read":{"actual_start":4096,"actual_length":192,"sha256":"verified-source","torn":true},"relative_path":"runtime/bound.code","local_content_status":"complete_range_hash_verified","object_inspection":{"elf_header":h}});
        let v = module_views(&[r]);
        assert_eq!(v[0]["mapping_copy"], "full_mapping_selected");
        assert_eq!(v[0]["all_load_file_bytes_covered"], true);
        assert_eq!(v[0]["complete_file_reconstructed"], false);
        assert_eq!(
            v[0]["symbol_analysis"],
            "file_backed_load_bytes_covered; section table still has gaps; dynsym is catalogued separately when those bytes sit in the retained mapping"
        );
    }
    #[test]
    fn fake_truncated_and_overflow_program_tables_stay_unknown() {
        assert!(header(b"\x7fELFfake").is_none());
        assert!(header(&fixture()[..100]).is_none());
        let mut b = fixture();
        b[32..40].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(header(&b).is_none());
    }
    #[test]
    fn different_source_window_cannot_fill_missing_bss() {
        let mut a = json!({"mapping":{"path":"lib.so","inode":1},"source":{"pid":1},"source_report":"first","read":{"actual_start":4096,"actual_length":192},"local_content_status":"complete_range_hash_verified","object_inspection":{"elf_header":header(&fixture()).unwrap()}});
        let mut b = a.clone();
        b["source_report"] = json!("second");
        b["read"]["actual_start"] = json!(4288);
        b["read"]["actual_length"] = json!(64);
        b["object_inspection"] = json!({});
        a["read"]["sha256"] = json!("first-hash");
        assert_eq!(
            module_views(&[a, b])[0]["all_load_memory_bytes_covered"],
            false
        );
    }
    #[test]
    fn conflicting_overlap_never_becomes_complete_coverage() {
        let a = json!({"mapping":{"path":"lib.so","inode":1},"source":{"pid":1},"source_report":"one","read":{"actual_start":4096,"actual_length":192,"sha256":"a"},"local_content_status":"complete_range_hash_verified","object_inspection":{"elf_header":header(&fixture()).unwrap()}});
        let mut b = a.clone();
        b["read"]["sha256"] = json!("b");
        let views = module_views(&[a, b]);
        assert!(views[0]["all_load_file_bytes_covered"].is_null());
        assert_eq!(
            views[0]["association"],
            "unknown_conflicting_overlapping_ranges"
        );
    }

    fn verified_row() -> Value {
        json!({"mapping":{"path":"lib.so","inode":1},"source":{"pid":1,"birth_ns":10},"source_report":"one","read":{"actual_start":4096,"actual_length":192,"sha256":"a","torn":false},"relative_path":"runtime/a.code","local_content_status":"complete_range_hash_verified","object_inspection":{"elf_header":header(&fixture()).unwrap()}})
    }

    #[test]
    fn exact_duplicate_ranges_preserve_sources_without_conflicting() {
        let a = verified_row();
        let mut b = a.clone();
        b["relative_path"] = json!("runtime/alias.code");
        let views = module_views(&[a, b]);
        assert_eq!(views[0]["all_load_file_bytes_covered"], true);
        assert_eq!(views[0]["verified_range_count"], 2);
        assert_eq!(
            views[0]["segments"][0]["source_slices"]
                .as_array()
                .unwrap()
                .len(),
            2
        );
    }

    #[test]
    fn contained_intervals_conflict_even_when_the_hash_matches() {
        let a = verified_row();
        let mut b = a.clone();
        b["read"]["actual_start"] = json!(4128);
        b["read"]["actual_length"] = json!(32);
        let views = module_views(&[a, b]);
        assert_eq!(
            views[0]["association"],
            "unknown_conflicting_overlapping_ranges"
        );
        assert!(views[0]["all_load_memory_bytes_covered"].is_null());
    }

    #[test]
    fn adjacent_ranges_fill_bss_without_becoming_overlapping() {
        let a = verified_row();
        let mut b = a.clone();
        b["read"]["actual_start"] = json!(4288);
        b["read"]["actual_length"] = json!(64);
        b["read"]["sha256"] = json!("b");
        b["object_inspection"] = json!({});
        let views = module_views(&[a, b]);
        assert_eq!(views[0]["all_load_memory_bytes_covered"], true);
        assert_ne!(
            views[0]["association"],
            "unknown_conflicting_overlapping_ranges"
        );
        assert_eq!(views[0]["section_table_gaps"], json!([[192, 256]]));
    }

    #[test]
    fn missing_zero_and_overflowing_intervals_remain_unknown() {
        for invalid in [
            json!({"actual_start":4096,"sha256":"a"}),
            json!({"actual_start":4096,"actual_length":0,"sha256":"a"}),
            json!({"actual_start":u64::MAX,"actual_length":1,"sha256":"a"}),
            json!({"actual_start":4096,"actual_length":192}),
        ] {
            let mut row = verified_row();
            row["read"] = invalid;
            let views = module_views(&[row]);
            assert_eq!(
                views[0]["association"],
                "unknown_missing_or_overflowing_range"
            );
            assert!(views[0]["all_load_file_bytes_covered"].is_null());
            assert_eq!(views[0]["complete_file_reconstructed"], false);
        }
    }

    #[test]
    fn inode_and_full_source_identity_do_not_merge_windows() {
        let a = verified_row();
        for field in ["inode", "birth_ns"] {
            let mut b = a.clone();
            b["read"]["actual_start"] = json!(4288);
            b["read"]["actual_length"] = json!(64);
            b["read"]["sha256"] = json!("b");
            b["object_inspection"] = json!({});
            if field == "inode" {
                b["mapping"]["inode"] = json!(2);
            } else {
                b["source"]["birth_ns"] = json!(11);
            }
            assert_eq!(
                module_views(&[a.clone(), b])[0]["all_load_memory_bytes_covered"],
                false
            );
        }
    }

    #[test]
    fn large_inventory_uses_a_bounded_number_of_sweep_steps() {
        let mut rows = vec![verified_row()];
        for index in 0..8192 {
            let mut row = verified_row();
            row["read"]["actual_start"] = json!(4288 + index);
            row["read"]["actual_length"] = json!(1);
            row["object_inspection"] = json!({});
            rows.push(row);
        }
        let mut checkpoints = 0_usize;
        let views = module_views_inner(&rows, &mut || {
            checkpoints += 1;
            Ok(())
        })
        .unwrap();
        assert_eq!(views[0]["all_load_memory_bytes_covered"], true);
        assert_eq!(views[0]["verified_range_count"], rows.len());
        assert!(checkpoints <= rows.len() * 12 + 128, "{checkpoints}");
    }

    #[test]
    fn a_scope_stop_during_group_processing_never_returns_partial_success() {
        let rows = vec![verified_row(); 64];
        let mut checkpoints = 0_usize;
        let result = module_views_inner(&rows, &mut || {
            checkpoints += 1;
            if checkpoints == 100 {
                Err("parent_cancelled".into())
            } else {
                Ok(())
            }
        });
        assert_eq!(result.unwrap_err(), "parent_cancelled");
    }

    #[test]
    fn independently_expired_guard_returns_failure_instead_of_empty_views() {
        let root = std::env::temp_dir().join(format!("elf-guard-{}", uuid::Uuid::new_v4()));
        let guard = super::super::session_budget::Guard::install(vec![root.clone()], 0, 1).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(5));
        assert!(super::super::session_deadline::current().is_none());
        assert_eq!(
            module_views_scoped(&root, &[]).unwrap_err(),
            "time_budget_exhausted"
        );
        assert_eq!(
            guard.receipt().reason.as_deref(),
            Some("time_budget_exhausted")
        );
    }

    #[tokio::test]
    async fn cancellation_of_original_parent_is_fail_closed() {
        let root = std::env::temp_dir().join(format!("elf-cancel-{}", uuid::Uuid::new_v4()));
        let deadline =
            super::super::session_deadline::Deadline::new(std::time::Duration::from_secs(1));
        let result = deadline
            .run(async {
                deadline.cancel();
                let error = module_views_scoped(&root, &[verified_row()]).unwrap_err();
                assert_eq!(error, "parent_cancelled");
                Err::<(), String>(error)
            })
            .await;
        assert!(result.unwrap_err().contains("parent_cancelled"));
    }

    #[tokio::test]
    async fn original_parent_expiry_is_fail_closed() {
        let root = std::env::temp_dir().join(format!("elf-expiry-{}", uuid::Uuid::new_v4()));
        let deadline =
            super::super::session_deadline::Deadline::new(std::time::Duration::from_millis(20));
        let result = deadline
            .run(async {
                std::thread::sleep(std::time::Duration::from_millis(25));
                let error = module_views_scoped(&root, &[verified_row()]).unwrap_err();
                assert_eq!(error, "parent_deadline_exhausted");
                Err::<(), String>(error)
            })
            .await;
        assert!(result.unwrap_err().contains("parent_deadline_exhausted"));
    }
}
