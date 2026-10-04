//! SPDX-License-Identifier: GPL-2.0-only
//! buildutil — store registration: move `out_dir` into the store, write the meta
//! file and the realization record, and return the realization digest. A lost
//! registration race keeps the winner and discards ours. `extra_meta` carries
//! builder-specific lines (a port's runtime dependencies and
//! package identity, an output's scan-recorded `reference:` edges).

use super::Store;
use super::derivation::Derivation;
use crate::source;
use std::path::Path;

impl Store {
    /// Move `out_dir` into the store, write the meta file and the realization
    /// record, and return the **realization digest**. A lost registration
    /// race keeps the winner and discards ours. `extra_meta` carries
    /// builder-specific lines (a port's runtime dependencies and
    /// package identity, an output's scan-recorded `reference:` edges).
    pub fn register(
        &self,
        drv: &Derivation,
        out_dir: &Path,
        sandbox: &str,
        extra_meta: &[String],
    ) -> Result<String, String> {
        let dest = self.out_path(drv);
        match std::fs::rename(out_dir, &dest) {
            Ok(()) => {}
            Err(_) if dest.is_dir() => {
                let _ = std::fs::remove_dir_all(out_dir);
            }
            Err(e) => {
                return Err(format!(
                    "cannot register {} -> {}: {}",
                    out_dir.display(),
                    dest.display(),
                    e
                ));
            }
        }
        let mut meta = format!("drv: {}\n", drv.hash());
        for dep in &drv.deps {
            meta.push_str(&format!("ref: {}\n", dep.store_name));
        }
        let mut outs: Vec<(String, String)> = Vec::new();
        let mut outdirs: Vec<(String, String)> = Vec::new();
        for output in &drv.outputs {
            if let Some(dir) = output.strip_suffix('/') {
                let h = source::filehash::hash_tree(&dest.join(dir))?;
                meta.push_str(&format!("outdir: {} {}\n", h, dir));
                outdirs.push((dir.to_string(), h));
            } else {
                let h = source::filehash::hash_file(&dest.join(output))?;
                meta.push_str(&format!("out: {} {}\n", h, output));
                outs.push((output.clone(), h));
            }
        }
        meta.push_str(&format!("sandbox: {}\n", sandbox));
        for line in extra_meta {
            meta.push_str(line);
            meta.push('\n');
        }
        let meta_path = self.meta_path(&drv.store_name());
        let tmp = meta_path.with_extension("tmp");
        std::fs::write(&tmp, &meta).map_err(|e| format!("cannot write meta: {}", e))?;
        std::fs::rename(&tmp, &meta_path).map_err(|e| format!("cannot commit meta: {}", e))?;

        let digest = super::realization_digest(&outs, &outdirs);
        self.write_realization(
            &drv.hash(),
            &digest,
            &outs,
            &outdirs,
            sandbox,
            &drv.store_name(),
        )?;
        Ok(digest)
    }
}
