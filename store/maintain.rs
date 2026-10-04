//! SPDX-License-Identifier: GPL-2.0-only
//! buildutil — store maintenance: verify output hashes, evict corrupt entries,
//! and hardlink identical files across store entries.

use super::Store;
use crate::source;
use std::collections::{BTreeMap, BTreeSet};

impl Store {
    /// Recompute output hashes against the meta records.
    pub fn verify(&self) -> Result<Vec<String>, String> {
        let mut corrupt = Vec::new();
        for name in self.list()? {
            let Ok(meta) = self.read_meta(&name) else {
                corrupt.push(format!("{} (no meta)", name));
                continue;
            };
            for (rel, expected) in &meta.outs {
                match source::filehash::hash_file(&self.root.join(&name).join(rel)) {
                    Ok(actual) if actual == *expected => {}
                    _ => corrupt.push(format!("{}/{}", name, rel)),
                }
            }
            for (rel, expected) in &meta.outdirs {
                match source::filehash::hash_tree(&self.root.join(&name).join(rel)) {
                    Ok(actual) if actual == *expected => {}
                    _ => corrupt.push(format!("{}/{}/", name, rel)),
                }
            }
        }
        Ok(corrupt)
    }

    /// Verify, evicting each corrupt entry (dir + meta + realization record)
    /// so the next build or substitution reproduces it. Returns the evicted
    /// entry names.
    pub fn verify_repair_with_lease(
        &self,
        _lease: &crate::state::StoreExclusiveLease,
    ) -> Result<Vec<String>, String> {
        let corrupt = self.verify()?;
        let mut names: BTreeSet<String> = BTreeSet::new();
        for c in &corrupt {
            let name = c.split(['/', ' ']).next().unwrap_or("").to_string();
            if !name.is_empty() {
                names.insert(name);
            }
        }
        let mut evicted = Vec::new();
        for name in names {
            let _ = std::fs::remove_dir_all(self.root.join(&name));
            let _ = std::fs::remove_file(self.meta_path(&name));
            let _ = std::fs::remove_file(self.state.join("drv").join(format!("{}.drv", name)));
            if let Some(hash32) = name.split('-').next() {
                if hash32.len() == 32 {
                    let _ = std::fs::remove_file(self.realization_path(hash32));
                }
            }
            evicted.push(name);
        }
        Ok(evicted)
    }

    /// Hardlink files with identical content across store entries (skipping
    /// files < 4096 bytes); idempotent. Returns (links made, bytes saved).
    pub fn optimise_with_lease(
        &self,
        _lease: &crate::state::StoreExclusiveLease,
    ) -> Result<(usize, u64), String> {
        let mut canon: BTreeMap<String, std::path::PathBuf> = BTreeMap::new();
        let mut links = 0usize;
        let mut saved = 0u64;
        for name in self.list()? {
            let mut stack = vec![self.root.join(&name)];
            while let Some(dir) = stack.pop() {
                let Ok(rd) = std::fs::read_dir(&dir) else {
                    continue;
                };
                let mut files: Vec<std::path::PathBuf> = rd.flatten().map(|e| e.path()).collect();
                files.sort();
                for path in files {
                    let Ok(md) = std::fs::symlink_metadata(&path) else {
                        continue;
                    };
                    if md.is_dir() {
                        stack.push(path);
                        continue;
                    }
                    if !md.is_file() || md.len() < 4096 {
                        continue;
                    }
                    let Ok(h) = source::filehash::hash_file(&path) else {
                        continue;
                    };
                    match canon.get(&h) {
                        None => {
                            canon.insert(h, path);
                        }
                        Some(c) => {
                            if super::gc::same_inode(c, &path) {
                                continue;
                            }
                            let tmp = path.with_extension("optmp");
                            let _ = std::fs::remove_file(&tmp);
                            if std::fs::hard_link(c, &tmp).is_ok()
                                && std::fs::rename(&tmp, &path).is_ok()
                            {
                                links += 1;
                                saved += md.len();
                            } else {
                                let _ = std::fs::remove_file(&tmp);
                            }
                        }
                    }
                }
            }
        }
        Ok((links, saved))
    }
}
