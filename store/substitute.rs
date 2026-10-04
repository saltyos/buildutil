//! SPDX-License-Identifier: GPL-2.0-only
//! buildutil — signed store substitution (protocol v2)
//!
//! Substitution is keyed on the *realization record*, not the drv-named
//! archive. A cache serves two objects per entry:
//!
//!   GET <base>/<drv-hash>.realization   the signed record
//!   GET <base>/<digest>.out             the canonical archive by content digest
//!
//! A client with the signer's key in `tools/buildutil/trusted-keys.txt` fetches
//! the record, verifies a trusted signature over its preimage, fetches the
//! archive by the record's digest, unpacks it, and recomputes the realization
//! digest — which must equal the record's claim before install. The meta is
//! written locally (drv line from the record, `ref:` lines from the local
//! graph, outputs/sandbox from the record). The mechanism ships OFF: with no
//! substituters configured nothing is fetched, and an unsigned / unknown-key
//! / digest-mismatched offer falls back to a local build.
//!
//! Signature preimage: SHA-512 over "buildutil-realization\0" ‖ the record text
//! up to (excluding) the first `sig:` line, with `provider:` lines removed —
//! so the signature binds the input identity, the output digest, and the
//! recorded outputs together, while surviving a local provider rewrite.
//!
//! Sandbox-grade gate: `buildutil store sign` refuses `sandbox: audit` entries
//! and self-tool entries. Only the self-tool class runs at audit grade, and
//! it is built from an ambient compiler, so neither is ever substitutable.
//!
//! Substitution runs where realization runs, on the Linux build host, with
//! the store curl the node's stage declares; the engine never calls a host
//! curl.

use super::Store;
use crate::crypto::ed25519;
use crate::crypto::sha512;
use crate::source;
use std::collections::BTreeMap;
use std::path::{Component, Path, PathBuf};

#[derive(Clone)]
struct ArchiveEntry {
    expected_hash: String,
    kind: char,
    mode: u32,
    rel: String,
    path: PathBuf,
}

fn safe_relative_path(rel: &str) -> Result<PathBuf, String> {
    if rel.is_empty() || rel.contains('\0') || rel.contains('\\') {
        return Err(format!("archive path is not canonical: {rel}"));
    }
    let path = Path::new(rel);
    if path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
        || rel.split('/').any(|component| component.is_empty())
    {
        return Err(format!("archive path escapes: {rel}"));
    }
    Ok(path.to_path_buf())
}

fn parse_archive_manifest(manifest: &str) -> Result<Vec<ArchiveEntry>, String> {
    let mut entries = Vec::new();
    let mut kinds = BTreeMap::new();
    for line in manifest.lines() {
        let mut fields = line.splitn(4, ' ');
        let expected_hash = fields.next().ok_or("malformed manifest line")?;
        if expected_hash.len() != 64 || !expected_hash.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return Err("malformed manifest hash".to_string());
        }
        let kind_text = fields.next().ok_or("malformed manifest line")?;
        let kind = match kind_text {
            "f" => 'f',
            "l" => 'l',
            "d" => 'd',
            other => return Err(format!("unknown manifest kind `{other}`")),
        };
        let mode = u32::from_str_radix(fields.next().ok_or("malformed manifest line")?, 8)
            .map_err(|_| "malformed mode".to_string())?;
        if mode & !0o7777 != 0 {
            return Err(format!("archive mode is out of range: {mode:o}"));
        }
        let rel = fields.next().ok_or("malformed manifest line")?.to_string();
        let path = safe_relative_path(&rel)?;
        if kinds.insert(path.clone(), kind).is_some() {
            return Err(format!("duplicate archive path: {rel}"));
        }
        entries.push(ArchiveEntry {
            expected_hash: expected_hash.to_string(),
            kind,
            mode,
            rel,
            path,
        });
    }
    for entry in &entries {
        let mut ancestor = entry.path.parent();
        while let Some(path) = ancestor.filter(|path| !path.as_os_str().is_empty()) {
            if kinds.get(path).is_some_and(|kind| *kind != 'd') {
                return Err(format!(
                    "archive path descends through a non-directory: {}",
                    entry.rel
                ));
            }
            ancestor = path.parent();
        }
    }
    Ok(entries)
}

fn archive_entries_match_outputs(
    entries: &[ArchiveEntry],
    outs: &[(String, String)],
    outdirs: &[(String, String)],
) -> Result<(), String> {
    let out_paths = outs
        .iter()
        .map(|(rel, _)| safe_relative_path(rel))
        .collect::<Result<Vec<_>, _>>()?;
    let outdir_paths = outdirs
        .iter()
        .map(|(rel, _)| safe_relative_path(rel))
        .collect::<Result<Vec<_>, _>>()?;
    for entry in entries {
        let declared_file = entry.kind != 'd' && out_paths.iter().any(|path| path == &entry.path);
        let declared_tree = outdir_paths
            .iter()
            .any(|path| entry.path == *path || entry.path.starts_with(path));
        if !declared_file && !declared_tree {
            return Err(format!(
                "archive contains undeclared output path: {}",
                entry.rel
            ));
        }
    }
    Ok(())
}

/// Canonical archive of a store entry: the tree manifest, then each
/// entry's payload in manifest order — file bytes for `f` lines, the
/// symlink target string for `l` lines. Empty dirs are fully described
/// by the manifest itself.
///
///   buildutil-archive\n
///   <manifest-len u64 LE> <manifest bytes>
///   per manifest `f`/`l` line: <len u64 LE> <payload bytes>
pub fn pack(entry_dir: &Path) -> Result<Vec<u8>, String> {
    let manifest = source::filehash::tree_manifest(entry_dir)?;
    let mut out = Vec::new();
    out.extend_from_slice(b"buildutil-archive\n");
    out.extend_from_slice(&(manifest.len() as u64).to_le_bytes());
    out.extend_from_slice(manifest.as_bytes());
    for line in manifest.lines() {
        let mut fields = line.splitn(4, ' ');
        let _hash = fields.next();
        let kind = fields.next().ok_or("malformed manifest line")?;
        let _mode = fields.next();
        let rel = fields.next().ok_or("malformed manifest line")?;
        let payload = match kind {
            "f" => std::fs::read(entry_dir.join(rel))
                .map_err(|e| format!("cannot read {}: {}", rel, e))?,
            "l" => {
                let target = std::fs::read_link(entry_dir.join(rel))
                    .map_err(|e| format!("cannot readlink {}: {}", rel, e))?;
                target
                    .to_str()
                    .ok_or_else(|| format!("non-UTF-8 symlink target at {}", rel))?
                    .as_bytes()
                    .to_vec()
            }
            _ => continue,
        };
        out.extend_from_slice(&(payload.len() as u64).to_le_bytes());
        out.extend_from_slice(&payload);
    }
    Ok(out)
}

/// Unpack a canonical archive into a fresh directory.
#[cfg(test)]
pub fn unpack(archive: &[u8], dest: &Path) -> Result<(), String> {
    unpack_with_outputs(archive, dest, None)
}

fn unpack_with_outputs(
    archive: &[u8],
    dest: &Path,
    outputs: Option<(&[(String, String)], &[(String, String)])>,
) -> Result<(), String> {
    let mut cur = archive;
    let mut take = |n: usize| -> Result<&[u8], String> {
        if cur.len() < n {
            return Err("truncated archive".to_string());
        }
        let (head, tail) = cur.split_at(n);
        cur = tail;
        Ok(head)
    };
    if take(b"buildutil-archive\n".len())? != b"buildutil-archive\n" {
        return Err("not a buildutil archive".to_string());
    }
    let mlen = u64::from_le_bytes(take(8)?.try_into().expect("8 bytes")) as usize;
    let manifest = String::from_utf8(take(mlen)?.to_vec())
        .map_err(|_| "archive manifest is not UTF-8".to_string())?;
    let entries = parse_archive_manifest(&manifest)?;
    if let Some((outs, outdirs)) = outputs {
        archive_entries_match_outputs(&entries, outs, outdirs)?;
    }
    match std::fs::symlink_metadata(dest) {
        Ok(metadata) if metadata.is_dir() => {
            if std::fs::read_dir(dest)
                .map_err(|e| format!("cannot inspect archive destination {}: {e}", dest.display()))?
                .next()
                .is_some()
            {
                return Err(format!(
                    "archive destination is not empty: {}",
                    dest.display()
                ));
            }
        }
        Ok(_) => {
            return Err(format!(
                "archive destination is not a directory: {}",
                dest.display()
            ));
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            std::fs::create_dir_all(dest).map_err(|e| {
                format!("cannot create archive destination {}: {e}", dest.display())
            })?;
        }
        Err(error) => {
            return Err(format!(
                "cannot inspect archive destination {}: {error}",
                dest.display()
            ));
        }
    }
    for entry in entries {
        let path = dest.join(&entry.path);
        match entry.kind {
            'f' => {
                let len = u64::from_le_bytes(take(8)?.try_into().expect("8 bytes")) as usize;
                let data = take(len)?;
                if crate::crypto::sha256::hash_bytes(data) != entry.expected_hash {
                    return Err(format!("archive content mismatch at {}", entry.rel));
                }
                if let Some(parent) = path.parent() {
                    std::fs::create_dir_all(parent)
                        .map_err(|e| format!("cannot create {}: {}", parent.display(), e))?;
                }
                std::fs::write(&path, data)
                    .map_err(|e| format!("cannot write {}: {}", path.display(), e))?;
                crate::platform::set_mode(&path, entry.mode)
                    .map_err(|e| format!("cannot chmod {}: {}", path.display(), e))?;
            }
            'l' => {
                let len = u64::from_le_bytes(take(8)?.try_into().expect("8 bytes")) as usize;
                let target = String::from_utf8(take(len)?.to_vec())
                    .map_err(|_| "non-UTF-8 symlink target".to_string())?;
                if crate::crypto::sha256::hash_bytes(target.as_bytes()) != entry.expected_hash {
                    return Err(format!("archive symlink mismatch at {}", entry.rel));
                }
                if let Some(parent) = path.parent() {
                    std::fs::create_dir_all(parent)
                        .map_err(|e| format!("cannot create {}: {}", parent.display(), e))?;
                }
                crate::platform::create_symlink_auto(Path::new(&target), &path)
                    .map_err(|e| format!("cannot symlink {}: {}", path.display(), e))?;
            }
            'd' => {
                if entry.expected_hash != crate::crypto::sha256::hash_bytes(b"") {
                    return Err(format!(
                        "archive empty-directory hash mismatch at {}",
                        entry.rel
                    ));
                }
                std::fs::create_dir_all(&path)
                    .map_err(|e| format!("cannot create {}: {}", path.display(), e))?;
                crate::platform::set_mode(&path, entry.mode)
                    .map_err(|e| format!("cannot chmod {}: {}", path.display(), e))?;
            }
            _ => unreachable!("archive manifest kind validated before extraction"),
        }
    }
    if !cur.is_empty() {
        return Err("archive has trailing payload bytes".to_string());
    }
    Ok(())
}

/// The signature domain of a realization record. Records signed under an
/// earlier domain do not verify; `buildutil store resign` signs them again.
const SIGNATURE_DOMAIN: &[u8] = b"buildutil-realization\0";

/// Signature preimage over a realization record (substitution protocol v2):
/// SHA-512 over `"buildutil-realization\0"` ‖ the record text up to (excluding)
/// the first `sig:` line, with `provider:` lines removed (they are local
/// state). A substituted record thus keeps a valid signature after its
/// provider line is rewritten locally.
fn record_sig_preimage(record: &str) -> [u8; 64] {
    let mut body = String::new();
    for line in record.lines() {
        if line.starts_with("sig: ") {
            break;
        }
        if line.starts_with("provider: ") {
            continue;
        }
        body.push_str(line);
        body.push('\n');
    }
    let mut h = sha512::Sha512::new();
    h.update(SIGNATURE_DOMAIN);
    h.update(body.as_bytes());
    h.finalize()
}

struct RecordParsed {
    drv: String,
    digest: String,
    sandbox: String,
    outs: Vec<(String, String)>,
    outdirs: Vec<(String, String)>,
}

fn parse_record(text: &str) -> Option<RecordParsed> {
    let mut r = RecordParsed {
        drv: String::new(),
        digest: String::new(),
        sandbox: String::new(),
        outs: Vec::new(),
        outdirs: Vec::new(),
    };
    for line in text.lines() {
        if let Some(v) = line.strip_prefix("drv: ") {
            r.drv = v.to_string();
        } else if let Some(v) = line.strip_prefix("digest: ") {
            r.digest = v.to_string();
        } else if let Some(v) = line.strip_prefix("sandbox: ") {
            r.sandbox = v.to_string();
        } else if let Some(v) = line.strip_prefix("out: ") {
            if let Some((h, rel)) = v.split_once(' ') {
                r.outs.push((rel.to_string(), h.to_string()));
            }
        } else if let Some(v) = line.strip_prefix("outdir: ") {
            if let Some((h, rel)) = v.split_once(' ') {
                r.outdirs.push((rel.to_string(), h.to_string()));
            }
        }
    }
    let valid_hash =
        |hash: &str| hash.len() == 64 && hash.bytes().all(|byte| byte.is_ascii_hexdigit());
    if r.drv.is_empty()
        || !valid_hash(&r.digest)
        || r.sandbox.is_empty()
        || r.outs
            .iter()
            .any(|(rel, hash)| safe_relative_path(rel).is_err() || !valid_hash(hash))
        || r.outdirs
            .iter()
            .any(|(rel, hash)| safe_relative_path(rel).is_err() || !valid_hash(hash))
    {
        return None;
    }
    Some(r)
}

/// Sign a realized entry's realization record in place (substitution v2).
/// Audit-grade and self-tool entries refuse signing.
pub fn sign_realization(store: &Store, store_name: &str, seed: &[u8; 32]) -> Result<(), String> {
    let meta = store.read_meta(store_name)?;
    if meta.sandbox == "audit" || meta.self_tool {
        return Err(format!(
            "refusing to sign `{}`: a self-tool realization (only enforcing-sandbox \
             store realizations are substitutable)",
            store_name
        ));
    }
    let path = store.realization_path(store_name);
    let record = std::fs::read_to_string(&path)
        .map_err(|e| format!("no realization record for {}: {}", store_name, e))?;
    let sig = ed25519::sign(seed, &record_sig_preimage(&record));
    let mut updated = record;
    if !updated.ends_with('\n') {
        updated.push('\n');
    }
    updated.push_str(&format!("sig: {}\n", ed25519::hex(&sig)));
    std::fs::write(&path, updated).map_err(|e| format!("cannot write record: {}", e))?;
    Ok(())
}

/// Sign every record that carries a signature again under the current
/// domain with `seed`, replacing its earlier signatures, which no longer
/// verify. Returns the number of records rewritten.
pub fn resign_realizations(store: &Store, seed: &[u8; 32]) -> Result<usize, String> {
    let dir = store.state_dir().join("realizations");
    let mut entries: Vec<std::path::PathBuf> = match std::fs::read_dir(&dir) {
        Ok(entries) => entries.flatten().map(|entry| entry.path()).collect(),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(e) => return Err(format!("cannot read {}: {e}", dir.display())),
    };
    entries.sort();
    let mut rewritten = 0;
    for path in entries {
        let Ok(record) = std::fs::read_to_string(&path) else {
            continue;
        };
        if !record.lines().any(|line| line.starts_with("sig: ")) {
            continue;
        }
        let mut body = String::new();
        for line in record.lines().filter(|line| !line.starts_with("sig: ")) {
            body.push_str(line);
            body.push('\n');
        }
        let sig = ed25519::sign(seed, &record_sig_preimage(&body));
        body.push_str(&format!("sig: {}\n", ed25519::hex(&sig)));
        let tmp = path.with_extension(format!("resign-{}", std::process::id()));
        std::fs::write(&tmp, &body).map_err(|e| format!("cannot write {}: {e}", tmp.display()))?;
        std::fs::rename(&tmp, &path)
            .map_err(|e| format!("cannot replace {}: {e}", path.display()))?;
        rewritten += 1;
    }
    Ok(rewritten)
}

/// Export every realized entry for a substituter cache: the signed
/// realization record (`<drv-hash>.realization`) and the content-addressed
/// output archive (`<digest>.out`). Returns the number of entries written.
pub fn export_store(store: &Store, out_dir: &Path) -> Result<usize, String> {
    std::fs::create_dir_all(out_dir)
        .map_err(|e| format!("cannot create {}: {}", out_dir.display(), e))?;
    let mut n = 0;
    for name in store.list()? {
        let Ok(record) = std::fs::read_to_string(store.realization_path(&name)) else {
            continue;
        };
        let Some(parsed) = parse_record(&record) else {
            continue;
        };
        std::fs::write(out_dir.join(format!("{}.realization", parsed.drv)), &record)
            .map_err(|e| format!("cannot write record: {}", e))?;
        let archive = pack(&store.root.join(&name))?;
        std::fs::write(out_dir.join(format!("{}.out", parsed.digest)), &archive)
            .map_err(|e| format!("cannot write archive: {}", e))?;
        n += 1;
    }
    Ok(n)
}

pub fn load_trusted_keys(repo_root: &Path) -> Vec<[u8; 32]> {
    let path = repo_root.join(crate::paths::TRUSTED_KEYS);
    let Ok(text) = std::fs::read_to_string(&path) else {
        return Vec::new();
    };
    let mut keys = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Ok(bytes) = ed25519::from_hex(line) {
            if bytes.len() == 32 {
                let mut key = [0u8; 32];
                key.copy_from_slice(&bytes);
                keys.push(key);
            }
        }
    }
    keys
}

/// Attempt substitution of one derivation from the configured
/// substituters. Returns Ok(true) when the entry was installed; any
/// verification failure is a silent fallback to the local build.
/// Verify a fetched/pulled realization record + output archive and install
/// it locally. Trust is a signature over the record preimage against
/// `keys`, then the recomputed realization digest against the record's
/// claim. Returns `Ok(true)` on install, `Ok(false)` on any verification
/// failure (untrusted signature, wrong drv, digest mismatch, bad archive) —
/// the caller falls back to another source or a local build. Shared by
/// substitution and remote-execution pull.
#[allow(clippy::too_many_arguments)]
pub fn install_verified(
    store: &Store,
    drv_hash: &str,
    store_name: &str,
    refs: &[String],
    record: &str,
    archive: &[u8],
    keys: &[[u8; 32]],
) -> Result<bool, String> {
    let msg = record_sig_preimage(record);
    let signed = record
        .lines()
        .filter_map(|l| l.strip_prefix("sig: "))
        .filter_map(|h| ed25519::from_hex(h.trim()).ok())
        .filter(|b| b.len() == 64)
        .any(|b| {
            let mut sig = [0u8; 64];
            sig.copy_from_slice(&b);
            keys.iter().any(|k| ed25519::verify(k, &msg, &sig))
        });
    if !signed {
        return Ok(false);
    }
    let Some(parsed) = parse_record(record) else {
        return Ok(false);
    };
    if parsed.drv != drv_hash {
        return Ok(false);
    }
    let staging = store.tmp_build_dir(store_name).with_extension("subst");
    let _ = std::fs::remove_dir_all(&staging);
    std::fs::create_dir_all(&staging).map_err(|e| format!("cannot stage: {}", e))?;
    if unpack_with_outputs(archive, &staging, Some((&parsed.outs, &parsed.outdirs))).is_err() {
        let _ = std::fs::remove_dir_all(&staging);
        return Ok(false);
    }
    // Recompute the realization digest from the unpacked tree; it must match
    // the record's claim before anything is installed.
    let outs: Vec<(String, String)> = parsed
        .outs
        .iter()
        .map(|(rel, _)| {
            (
                rel.clone(),
                source::filehash::hash_file(&staging.join(rel)).unwrap_or_default(),
            )
        })
        .collect();
    let outdirs: Vec<(String, String)> = parsed
        .outdirs
        .iter()
        .map(|(rel, _)| {
            (
                rel.clone(),
                source::filehash::hash_tree(&staging.join(rel)).unwrap_or_default(),
            )
        })
        .collect();
    if super::realization_digest(&outs, &outdirs) != parsed.digest {
        let _ = std::fs::remove_dir_all(&staging);
        return Ok(false);
    }
    let mut meta = format!("drv: {}\n", parsed.drv);
    for r in refs {
        meta.push_str(&format!("ref: {}\n", r));
    }
    for (rel, h) in &parsed.outs {
        meta.push_str(&format!("out: {} {}\n", h, rel));
    }
    for (rel, h) in &parsed.outdirs {
        meta.push_str(&format!("outdir: {} {}\n", h, rel));
    }
    meta.push_str(&format!("sandbox: {}\n", parsed.sandbox));
    store.install_substituted(store_name, &staging, &meta)?;
    store.write_realization(
        &parsed.drv,
        &parsed.digest,
        &parsed.outs,
        &parsed.outdirs,
        &parsed.sandbox,
        store_name,
    )?;
    Ok(true)
}

/// Fetch and install a signed realization for `drv_hash` from the
/// configured substituters, with `curl` — a store tool the node's stage
/// declares. `Ok(false)` falls back to a local build.
pub fn try_substitute(
    store: &Store,
    repo_root: &Path,
    curl: &Path,
    substituters: &[String],
    drv_hash: &str,
    store_name: &str,
    refs: &[String],
) -> Result<bool, String> {
    if substituters.is_empty() {
        return Ok(false);
    }
    let keys = load_trusted_keys(repo_root);
    if keys.is_empty() {
        return Ok(false);
    }
    for base in substituters {
        let base = base.trim_end_matches('/');
        let fetch = |url: String| -> Option<Vec<u8>> {
            let out = crate::invocation::isolated(curl)
                .args(["-fsSL", "--max-time", "120", &url])
                .output()
                .ok()?;
            out.status.success().then_some(out.stdout)
        };
        // Fetch the signed record, then the output archive by its content
        // digest, and hand both to the shared verify-and-install path.
        let Some(rec_raw) = fetch(format!("{}/{}.realization", base, drv_hash)) else {
            continue;
        };
        let Ok(record) = String::from_utf8(rec_raw) else {
            continue;
        };
        let Some(parsed) = parse_record(&record) else {
            continue;
        };
        let Some(archive) = fetch(format!("{}/{}.out", base, parsed.digest)) else {
            continue;
        };
        match install_verified(store, drv_hash, store_name, refs, &record, &archive, &keys)? {
            true => {
                crate::log::info(
                    "substitute",
                    &format!("substituted {} from {}", store_name, base),
                );
                return Ok(true);
            }
            false => {
                crate::log::warn(
                    "substitute",
                    &format!(
                        "Substituter {} offered an unverifiable record for {}",
                        base, store_name
                    ),
                );
                continue;
            }
        }
    }
    Ok(false)
}

pub fn cmd_keygen(out_path: &Path) -> Result<(), String> {
    // Key generation is the one legitimately random operation; read the
    // OS entropy pool directly.
    let mut seed = [0u8; 32];
    crate::platform::fill_random(&mut seed).map_err(|e| format!("cannot read OS entropy: {e}"))?;
    let public = ed25519::public_key(&seed);
    std::fs::write(out_path, format!("{}\n", ed25519::hex(&seed)))
        .map_err(|e| format!("cannot write {}: {}", out_path.display(), e))?;
    let _ = crate::platform::set_mode(out_path, 0o600);
    out!("secret key: {}", out_path.display());
    out!(
        "public key (add to {}): {}",
        crate::paths::TRUSTED_KEYS,
        ed25519::hex(&public)
    );
    Ok(())
}

pub fn read_seed(path: &Path) -> Result<[u8; 32], String> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read {}: {}", path.display(), e))?;
    let bytes = ed25519::from_hex(text.trim())?;
    if bytes.len() != 32 {
        return Err("secret key must be 32 hex-encoded bytes".to_string());
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&bytes);
    Ok(seed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn archive_with(entries: &[(&str, char, u32, &[u8])]) -> Vec<u8> {
        let mut manifest = String::new();
        for (rel, kind, mode, payload) in entries {
            manifest.push_str(&format!(
                "{} {} {:04o} {}\n",
                crate::crypto::sha256::hash_bytes(payload),
                kind,
                mode,
                rel
            ));
        }
        let mut archive = b"buildutil-archive\n".to_vec();
        archive.extend_from_slice(&(manifest.len() as u64).to_le_bytes());
        archive.extend_from_slice(manifest.as_bytes());
        for (_, kind, _, payload) in entries {
            if matches!(*kind, 'f' | 'l') {
                archive.extend_from_slice(&(payload.len() as u64).to_le_bytes());
                archive.extend_from_slice(payload);
            }
        }
        archive
    }

    #[test]
    fn required_signatures_use_the_buildutil_realization_domain_only() {
        let seed = [9u8; 32];
        let public = ed25519::public_key(&seed);
        let record = format!(
            "buildutil-realization\nformat: 1\ndrv: {}\ndigest: {}\nsandbox: namespace\nprovider: x\n",
            "a".repeat(64),
            "b".repeat(64)
        );
        let mut old = sha512::Sha512::new();
        old.update(b"salty-realization\0");
        old.update(
            record
                .lines()
                .filter(|line| !line.starts_with("provider: "))
                .map(|line| format!("{line}\n"))
                .collect::<String>()
                .as_bytes(),
        );
        let old_sig = ed25519::sign(&seed, &old.finalize());
        assert!(!ed25519::verify(&public, &record_sig_preimage(&record), &old_sig));

        let base =
            std::env::temp_dir().join(format!("buildutil-resign-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let store = Store::open(&base).unwrap();
        let path = base.join("realizations").join("a".repeat(32));
        std::fs::write(&path, format!("{record}sig: {}\n", ed25519::hex(&old_sig))).unwrap();
        std::fs::write(base.join("realizations").join("b".repeat(32)), &record).unwrap();
        assert_eq!(resign_realizations(&store, &seed).unwrap(), 1);
        let resigned = std::fs::read_to_string(&path).unwrap();
        let sigs: Vec<&str> = resigned
            .lines()
            .filter_map(|line| line.strip_prefix("sig: "))
            .collect();
        assert_eq!(sigs.len(), 1);
        assert_ne!(sigs[0], ed25519::hex(&old_sig));
        let fresh = ed25519::sign(&seed, &record_sig_preimage(&resigned));
        assert_eq!(sigs[0], ed25519::hex(&fresh));
        // A record that was never signed stays unsigned.
        assert!(
            !std::fs::read_to_string(base.join("realizations").join("b".repeat(32)))
                .unwrap()
                .contains("sig: ")
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn archive_roundtrip_and_signature() {
        let base =
            std::env::temp_dir().join(format!("buildutil-subst-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let entry = base.join("entry");
        std::fs::create_dir_all(entry.join("stage/usr/bin")).unwrap();
        std::fs::write(entry.join("stage/usr/bin/tool"), b"payload").unwrap();
        crate::platform::set_mode(&entry.join("stage/usr/bin/tool"), 0o755).unwrap();

        let archive = pack(&entry).unwrap();
        let out = base.join("unpacked");
        unpack(&archive, &out).unwrap();
        assert_eq!(
            std::fs::read(out.join("stage/usr/bin/tool")).unwrap(),
            b"payload"
        );
        assert_eq!(
            crate::platform::file_mode(&std::fs::metadata(out.join("stage/usr/bin/tool")).unwrap())
                & 0o7777,
            0o755
        );
        assert_eq!(
            source::filehash::tree_manifest(&entry).unwrap(),
            source::filehash::tree_manifest(&out).unwrap()
        );

        // v2: the signature covers the realization-record preimage, which
        // excludes the (local) provider: line — so a substituted provider
        // rewrite keeps the signature valid — and detects digest tampering.
        let seed = [7u8; 32];
        let public = ed25519::public_key(&seed);
        let record = "buildutil-realization\nformat: 1\ndrv: cafe\ndigest: d00d\n\
                      out: h result\nsandbox: namespace\nbuildutil: x\nprovider: aa-x-x86_64\n";
        let sig = ed25519::sign(&seed, &record_sig_preimage(record));
        assert!(ed25519::verify(&public, &record_sig_preimage(record), &sig));
        let reprovided = record.replace("provider: aa-x-x86_64", "provider: bb-y-x86_64");
        assert!(
            ed25519::verify(&public, &record_sig_preimage(&reprovided), &sig),
            "a new provider line must not invalidate the record signature"
        );
        let tampered = record.replace("digest: d00d", "digest: beef");
        assert!(!ed25519::verify(
            &public,
            &record_sig_preimage(&tampered),
            &sig
        ));
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn archive_rejects_absolute_duplicate_and_symlink_ancestor_paths() {
        let base =
            std::env::temp_dir().join(format!(
                "buildutil-subst-confinement-{}",
                std::process::id()
            ));
        let _ = std::fs::remove_dir_all(&base);
        let escaped = base.join("escaped");
        let absolute = archive_with(&[(escaped.to_str().unwrap(), 'f', 0o644, b"outside")]);
        assert!(unpack(&absolute, &base.join("absolute-out")).is_err());
        assert!(!escaped.exists());

        let duplicate = archive_with(&[
            ("result", 'f', 0o644, b"first"),
            ("result", 'f', 0o644, b"second"),
        ]);
        assert!(unpack(&duplicate, &base.join("duplicate-out")).is_err());

        let target = base.join("outside");
        let target = target.to_string_lossy();
        let symlink_ancestor = archive_with(&[
            ("link", 'l', 0o777, target.as_bytes()),
            ("link/payload", 'f', 0o644, b"outside"),
        ]);
        assert!(unpack(&symlink_ancestor, &base.join("symlink-out")).is_err());
        assert!(!base.join("outside/payload").exists());
        let _ = std::fs::remove_dir_all(base);
    }

    #[test]
    fn signed_archive_coverage_rejects_undeclared_entries() {
        let manifest = [
            format!(
                "{} f 0644 result",
                crate::crypto::sha256::hash_bytes(b"declared")
            ),
            format!(
                "{} f 0644 extra",
                crate::crypto::sha256::hash_bytes(b"undeclared")
            ),
        ]
        .join("\n");
        let entries = parse_archive_manifest(&(manifest + "\n")).unwrap();
        let outs = vec![(
            "result".to_string(),
            crate::crypto::sha256::hash_bytes(b"declared"),
        )];
        assert!(archive_entries_match_outputs(&entries, &outs, &[]).is_err());
    }

    #[test]
    fn substitution_v2_end_to_end_via_file_url() {
        use crate::store::derivation::{Derivation, DrvParts};
        // The seed's curl drives the fetch, as it does for the bootstrap
        // stage; the test derivation supplies the seed.
        let Some(seed) = std::env::var_os("BUILDUTIL_CONTRACT_SEED") else {
            say!("skipping substitution_v2 test: no seed curl");
            return;
        };
        let curl = std::path::PathBuf::from(seed).join("bin/curl");
        if !curl.is_file() {
            say!("skipping substitution_v2 test: no seed curl");
            return;
        }
        let base = std::env::temp_dir().join(format!("buildutil-subst-v2-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);

        // Source store: one namespace-grade entry with a realization record.
        let src = Store::open(&base.join("src")).unwrap();
        let d = Derivation::seal(DrvParts {
            name: "widget".into(),
            arch: "x86_64".into(),
            builder: "test".into(),
            tools: vec![],
            env: vec![],
            srcs: vec![],
            srcdirs: vec![],
            source_roots: vec![],
            source_overlays: vec![],
            copy: vec![],
            stage_deps: vec![],
            allowed_refs: crate::spec::RefPolicy::None,
            deps: vec![],
            config: vec![],
            module_config: None,
            argv: vec!["true".into()],
            plan: vec![],
            outputs: vec!["result".into()],
        });
        let out = src.tmp_build_dir(&d.store_name()).join("out");
        std::fs::create_dir_all(&out).unwrap();
        std::fs::write(out.join("result"), b"widget-bytes").unwrap();
        src.write_drv(&d).unwrap();
        src.register(&d, &out, "namespace", &[]).unwrap();

        // Sign the record; then export a substituter cache and point a
        // file:// URL at it.
        let seed = [9u8; 32];
        let pubkey = ed25519::public_key(&seed);
        sign_realization(&src, &d.store_name(), &seed).unwrap();
        let cache = base.join("cache");
        assert_eq!(export_store(&src, &cache).unwrap(), 1);
        let sub = format!("file://{}", cache.display());

        // A repo view that trusts the signer.
        let repo = base.join("repo");
        std::fs::create_dir_all(repo.join(crate::paths::BUILDUTIL)).unwrap();
        std::fs::write(
            repo.join(crate::paths::TRUSTED_KEYS),
            format!("{}\n", ed25519::hex(&pubkey)),
        )
        .unwrap();

        // Fresh destination store: substitution installs the entry.
        let dst = Store::open(&base.join("dst")).unwrap();
        let entry = dst.root.join(d.store_name());
        assert!(!entry.exists());
        let ok =
            try_substitute(&dst, &repo, &curl, &[sub.clone()], &d.hash(), &d.store_name(), &[])
                .unwrap();
        assert!(ok, "substitution should install from {}", sub);
        assert_eq!(
            std::fs::read(entry.join("result")).unwrap(),
            b"widget-bytes"
        );

        // Without a trusted key the same offer is refused (falls back to build).
        let repo2 = base.join("repo2");
        std::fs::create_dir_all(repo2.join(crate::paths::BUILDUTIL)).unwrap();
        let dst2 = Store::open(&base.join("dst2")).unwrap();
        assert!(
            !try_substitute(&dst2, &repo2, &curl, &[sub], &d.hash(), &d.store_name(), &[])
                .unwrap(),
            "an untrusted signer must not be accepted"
        );

        let _ = std::fs::remove_dir_all(&base);
    }
}
