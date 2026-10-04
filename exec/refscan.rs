//! SPDX-License-Identifier: GPL-2.0-only
//! buildutil — output reference scanner
//!
//! A realized output tree may carry embedded paths: a wrapper naming its
//! interpreter's `/lib/.../ld.so`, a CMake cache pointing at `/usr/lib/...`,
//! an autoconf cache that recorded its build prefix. The runtime closure of
//! a hosted output is exactly the union of those paths (so the GC knows
//! what to keep alive), and a path outside the declared closure is the
//! real leak — the build reached an undeclared input. This module
//! classifies each occurrence and reports violations plus the reference
//! set downstream code persists as `reference:` meta lines.

use crate::spec::RefPolicy;
use crate::store::Store;
use crate::store::derivation::Derivation;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// A store entry name is `<hash32>-<name>-<arch>`, so its bytes are the store
/// filename alphabet. A store reference ends at the first byte outside it.
fn is_store_name_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'.' || b == b'-' || b == b'_'
}

/// True when the byte one past a matched needle is a path boundary — a
/// separator, terminator, quote, or the end of the buffer. So a `/build`
/// needle matches `HOME=/build`, `/build/stage`, and a NUL-terminated
/// `/build`, but never `/buildroot`.
fn at_path_boundary(bytes: &[u8], end: usize) -> bool {
    match bytes.get(end) {
        None => true,
        Some(b) => matches!(
            b,
            b'/' | 0 | b'"' | b'\'' | b':' | b' ' | b'\t' | b'\n' | b'\r'
        ),
    }
}

/// True when `needle` occurs in `hay` as a path token — a match whose trailing
/// byte is a path boundary. Used for build-private needles (the per-run build
/// dir and the sandbox's constant `/build`), where a bare substring match
/// would false-positive on an unrelated longer path.
pub(super) fn contains_path_token(hay: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || needle.len() > hay.len() {
        return false;
    }
    let mut i = 0;
    while i + needle.len() <= hay.len() {
        if &hay[i..i + needle.len()] == needle && at_path_boundary(hay, i + needle.len()) {
            return true;
        }
        i += 1;
    }
    false
}

/// Classify every store-root occurrence in a byte buffer. A store reference is
/// `<store_root>/<name>...`; `name` is the path component that follows. For a
/// `hosted` output a reference whose name
/// is in `legal` (the transitive dependency closure) is allowed — a host
/// binary legitimately carries the store paths of its interpreter / `RPATH`;
/// a name outside `legal` is an undeclared reference (the real leak). A
/// freestanding output must carry no store reference at all. A store-root
/// occurrence with no resolvable entry is always a violation. Returns the
/// distinct violation details plus the allowed references that were hit —
/// the entry names GC must keep alive for these bytes to stay runnable.
fn store_ref_violations(
    bytes: &[u8],
    store_root: &[u8],
    legal: &BTreeSet<String>,
    allow_store_refs: bool,
) -> (Vec<String>, BTreeSet<String>) {
    let mut out = Vec::new();
    let mut hits = BTreeSet::new();
    if store_root.is_empty() || store_root.len() >= bytes.len() {
        return (out, hits);
    }
    let mut i = 0;
    while i + store_root.len() <= bytes.len() {
        if &bytes[i..i + store_root.len()] != store_root {
            i += 1;
            continue;
        }
        let after = i + store_root.len();
        if bytes.get(after) != Some(&b'/') {
            out.push("references the store root with no resolvable entry".to_string());
            i = after;
            continue;
        }
        let name_start = after + 1;
        let mut j = name_start;
        while j < bytes.len() && is_store_name_byte(bytes[j]) {
            j += 1;
        }
        let name = String::from_utf8_lossy(&bytes[name_start..j]).into_owned();
        if name.is_empty() {
            out.push("references the store root with no resolvable entry".to_string());
        } else if !allow_store_refs {
            out.push(format!(
                "references store entry `{}` (a freestanding output must carry no store reference)",
                name
            ));
        } else if !legal.contains(&name) {
            out.push(format!("references undeclared store entry `{}`", name));
        } else {
            hits.insert(name);
        }
        i = j.max(after + 1);
    }
    (out, hits)
}

/// The derivation name a store entry realizes, parsed from its
/// `<hash32>-<name>-<arch>` store name. The hash prefix is fixed-width, but
/// build-host-qualified arch suffixes contain `-` themselves
/// (`host-aarch64-unknown-linux-musl`), so parse by known suffix rather than
/// by the final dash. Used by the enforcing sandbox's closure lookups and by
/// the transitive dep-view staging on every platform.
pub(super) fn store_entry_drv_name(store_name: &str) -> Option<&str> {
    let rest = store_name.get(33..)?;
    if store_name.as_bytes().get(32) != Some(&b'-') {
        return None;
    }
    for arch in [
        "host-aarch64-unknown-linux-musl",
        "host-x86_64-unknown-linux-musl",
        "aarch64",
        "x86_64",
        "any",
    ] {
        let suffix = format!("-{arch}");
        if let Some(name) = rest.strip_suffix(&suffix) {
            if !name.is_empty() {
                return Some(name);
            }
        }
    }
    rest.rfind('-').map(|cut| &rest[..cut])
}

/// The transitive store-name closure of a derivation's declared dependencies
/// (which include store-tool providers — the eval pass folds each into
/// `deps`). This is the legal reference set for a hosted output and the
/// enforcing sandbox's read set. Dependencies are realized before they are
/// consumed, so an unreadable dependency meta is a hard error, not a silent
/// gap.
pub(super) fn dep_closure(store: &Store, drv: &Derivation) -> Result<BTreeSet<String>, String> {
    let mut closure = BTreeSet::new();
    let mut queue: Vec<String> = drv.deps.iter().map(|d| d.store_name.clone()).collect();
    while let Some(name) = queue.pop() {
        if !closure.insert(name.clone()) {
            continue;
        }
        let meta = store.read_meta(&name).map_err(|e| {
            format!(
                "reference scan: dependency `{}` meta is unreadable: {}",
                name, e
            )
        })?;
        queue.extend(meta.refs);
    }
    Ok(closure)
}

pub(super) fn allowed_store_refs(
    policy: &RefPolicy,
    closure: &BTreeSet<String>,
) -> BTreeSet<String> {
    match policy {
        RefPolicy::None => BTreeSet::new(),
        RefPolicy::Closure => closure.clone(),
        RefPolicy::List(names) => closure
            .iter()
            .filter(|store_name| {
                store_entry_drv_name(store_name)
                    .is_some_and(|drv_name| names.iter().any(|name| name == drv_name))
            })
            .cloned()
            .collect(),
    }
}

/// Reference-scan a realized output tree: classify every embedded absolute
/// path against the derivation's
/// output class and dependency closure:
///
/// - A **build-private path** — the per-run, hash-named host build dir — is
///   always a violation: it does not exist after the build, so an output
///   embedding it is broken and non-reproducible. The sandbox-constant
///   `/build` is deliberately NOT a needle: it is the reproducible remap
///   target, byte-identical across runs and machines, so a build tool that
///   only ever executes inside a sandbox (a compiler wrapper naming its
///   staged `/build/stage/dep/…` sysroot, say) may embed it.
/// - A **store reference** is classified by `store_ref_violations`: legal for
///   a hosted output when it resolves into the declared closure, else a
///   violation; any store reference is a violation for a freestanding output.
///
/// Both file contents and symlink targets are scanned; every occurrence is
/// classified, and identical details for one path are collapsed. Returns
/// sorted `"<relpath>: <detail>"` violations plus the distinct legal store
/// references the tree carries (its recorded runtime reference set).
pub(super) fn scan_references(
    out_dir: &Path,
    store_root: &Path,
    build_needles: &[PathBuf],
    legal: &BTreeSet<String>,
    allow_store_refs: bool,
) -> (Vec<String>, BTreeSet<String>) {
    let store_root_bytes = crate::platform::os_str_bytes(store_root.as_os_str());
    let needle_bytes: Vec<Vec<u8>> = build_needles
        .iter()
        .map(|p| crate::platform::os_str_bytes(p.as_os_str()).to_vec())
        .filter(|b| !b.is_empty())
        .collect();
    let mut references: BTreeSet<String> = BTreeSet::new();
    let mut classify = |bytes: &[u8]| -> Vec<String> {
        let mut v = Vec::new();
        for n in &needle_bytes {
            if contains_path_token(bytes, n) {
                v.push(format!(
                    "embeds build-private path `{}`",
                    String::from_utf8_lossy(n)
                ));
            }
        }
        let (violations, hits) =
            store_ref_violations(bytes, store_root_bytes, legal, allow_store_refs);
        v.extend(violations);
        references.extend(hits);
        v.sort();
        v.dedup();
        v
    };
    let mut hits = Vec::new();
    let mut stack = vec![out_dir.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in rd.flatten() {
            let path = entry.path();
            let Ok(ft) = entry.file_type() else {
                continue;
            };
            let rel = path
                .strip_prefix(out_dir)
                .unwrap_or(&path)
                .display()
                .to_string();
            if ft.is_symlink() {
                if let Ok(target) = std::fs::read_link(&path) {
                    for detail in classify(crate::platform::os_str_bytes(target.as_os_str())) {
                        hits.push(format!("{} -> {}: {}", rel, target.display(), detail));
                    }
                }
            } else if ft.is_dir() {
                stack.push(path);
            } else if ft.is_file() {
                if let Ok(bytes) = std::fs::read(&path) {
                    for detail in classify(&bytes) {
                        hits.push(format!("{}: {}", rel, detail));
                    }
                }
            }
        }
    }
    hits.sort();
    hits.dedup();
    (hits, references)
}
