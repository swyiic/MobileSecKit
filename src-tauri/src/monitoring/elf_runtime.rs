//! Bounded ELF64 PT_LOAD views over verified ranges; never fills holes or reconstructs a file.
use serde_json::{json, Value};
use std::collections::BTreeMap;

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
fn gaps(start: u64, end: u64, mut ranges: Vec<(u64, u64)>) -> Vec<(u64, u64)> {
    ranges.sort_unstable();
    let mut p = start;
    let mut out = Vec::new();
    for (a, b) in ranges {
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
    out
}
pub(super) fn module_views(rows: &[Value]) -> Value {
    let mut groups = BTreeMap::<String, Vec<&Value>>::new();
    for r in rows {
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
        let mut ambiguous = false;
        for (i, a) in rows.iter().enumerate() {
            for b in rows.iter().skip(i + 1) {
                let (Some(sa), Some(na), Some(sb), Some(nb)) = (
                    a["read"]["actual_start"].as_u64(),
                    a["read"]["actual_length"].as_u64(),
                    b["read"]["actual_start"].as_u64(),
                    b["read"]["actual_length"].as_u64(),
                ) else {
                    ambiguous = true;
                    continue;
                };
                if sa < sb.saturating_add(nb)
                    && sb < sa.saturating_add(na)
                    && (sa != sb || na != nb || a["read"]["sha256"] != b["read"]["sha256"])
                {
                    ambiguous = true;
                }
            }
        }
        if ambiguous {
            modules.push(json!({"schema":"mobilee.verified-elf-load-view/v1","path":rows[0]["mapping"]["path"],"source":rows[0]["source"],"source_report":rows[0]["source_report"],"all_load_file_bytes_covered":null,"all_load_memory_bytes_covered":null,"complete_file_reconstructed":false,"association":"unknown_conflicting_overlapping_ranges","segments":[],"torn":true,"ownership":"unknown"}));
            continue;
        }
        let Some(first) = rows.iter().find(|r| {
            r["object_inspection"]["elf_header"]["status"]
                == "bounded_elf64_header_and_program_table"
        }) else {
            continue;
        };
        let h = &first["object_inspection"]["elf_header"];
        let Some(loads) = h["loads"].as_array() else {
            continue;
        };
        let anchors: Vec<_> = loads
            .iter()
            .filter(|l| {
                l["file_offset"] == 0
                    && l["file_bytes"]
                        .as_u64()
                        .is_some_and(|n| n >= h["header_bytes"].as_u64().unwrap_or(u64::MAX))
            })
            .collect();
        if anchors.len() != 1 {
            continue;
        }
        let Some(bias) = first["read"]["actual_start"]
            .as_u64()
            .and_then(|s| s.checked_sub(anchors[0]["virtual_address"].as_u64()?))
        else {
            continue;
        };
        let intervals: Vec<_> = rows
            .iter()
            .filter_map(|r| {
                Some((
                    r["read"]["actual_start"].as_u64()?,
                    r["read"]["actual_start"]
                        .as_u64()?
                        .checked_add(r["read"]["actual_length"].as_u64()?)?,
                ))
            })
            .collect();
        let mut segments = Vec::new();
        let mut file_ranges = Vec::new();
        for l in loads {
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
            segments.push(json!({"file_offset":off,"virtual_start":start,"file_bytes":fs,"memory_bytes":ms,"file_backed_gaps":gaps(start,end,intervals.clone()),"memory_gaps":gaps(start,memend,intervals.clone()),"source_slices":sources,"derived_bytes_sha256":null,"derived_hash_status":"source_full_hashes_verified; no_new_slice_hash_budget"}));
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
        let shgaps = gaps(shoff, shoff.saturating_add(shbytes), file_ranges);
        modules.push(json!({"schema":"mobilee.verified-elf-load-view/v1","path":first["mapping"]["path"],"source":first["source"],"source_report":first["source_report"],"load_bias":bias,"verified_range_count":rows.len(),"verified_range_bytes":rows.iter().filter_map(|r|r["read"]["actual_length"].as_u64()).sum::<u64>(),"association":"inferred_from_unique_offset_zero_PT_LOAD_and_retained_header; kernel_file_offsets_not_recorded","torn":true,"all_load_file_bytes_covered":file_complete,"all_load_memory_bytes_covered":mem_complete,"section_table_gaps":shgaps,"segments":segments,"complete_file_reconstructed":false,"symbol_analysis":"not_performed_on_incomplete_memory_file","ownership":"unknown","scope":"this producer window and listed verified ranges only"}));
    }
    json!(modules)
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
}
