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
    let code_logical = verified_paths.values().map(|(_, n)| *n).sum::<u64>();
    let unique = verified_paths
        .values()
        .cloned()
        .collect::<BTreeSet<_>>()
        .iter()
        .map(|(_, n)| *n)
        .sum::<u64>();
    json!({"schema":"mobilee.local-storage-evidence/v1","logical_file_bytes":logical,"unique_inode_bytes":if cfg!(unix){Some(inode_bytes)}else{None},"allocated_bytes":if cfg!(unix){Some(allocated)}else{None},
        "shared_inode_logical_bytes":if cfg!(unix){Some(logical.saturating_sub(inode_bytes))}else{None},"allocation_basis":if cfg!(unix){"unique_inode_st_blocks_512"}else{"unavailable"},"unknown_metadata_files":unknown_metadata,"category_logical_bytes":categories,
        "verified_code_logical_bytes":code_logical,"verified_code_unique_bytes":unique,"verified_code_duplicate_bytes":code_logical.saturating_sub(unique),
        "unverified_observations":failures,"omitted_observations":omitted,"hash_budget_bytes":64*1024*1024,"hash_budget_remaining":hash_budget,"observations":observations,
        "warnings":["Content redundancy is an accounting opportunity, not physical disk savings","APK members and producer transformations are provenance assertions; local verification hashes retained files only","This bounded code ledger does not hash private data or old memory windows"]})
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
