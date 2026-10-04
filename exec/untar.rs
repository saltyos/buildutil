//! SPDX-License-Identifier: GPL-2.0-only
//! buildutil — tar extractor (`buildutil untar <archive> <out-dir>`)
//!
//! The bootstrap seed is a pinned binary archive, and unpacking it
//! cannot use `tar`/`sh`/`cp` — those live *inside* the seed, so relying on
//! them to extract the seed is circular (the same bootstrap problem Nix breaks
//! with a static busybox). `buildutil` is the one tool always present, so it does
//! the extraction itself. Supports the ustar subset plus GNU long-name (`L`)
//! entries, which deep toolchain paths need. Gzip framing is decoded by inflate.

#[path = "inflate.rs"]
mod inflate;

use std::collections::{BTreeMap, BTreeSet};
use std::io::{BufRead, BufReader, Read};
use std::path::{Component, Path, PathBuf};

fn octal(field: &[u8]) -> Result<u64, String> {
    if field.first().is_some_and(|byte| byte & 0x80 != 0) {
        return Err("untar: base-256 numeric field is unsupported".into());
    }
    let trimmed = field.strip_suffix(&[0]).unwrap_or(field);
    let trimmed = trimmed.strip_suffix(&[b' ']).unwrap_or(trimmed);
    let trimmed = trimmed
        .iter()
        .copied()
        .skip_while(|byte| *byte == b' ')
        .collect::<Vec<_>>();
    let end = trimmed
        .iter()
        .position(|byte| *byte == 0 || *byte == b' ')
        .unwrap_or(trimmed.len());
    if end == 0
        || trimmed[end..]
            .iter()
            .any(|byte| *byte != 0 && *byte != b' ')
    {
        return Err("untar: malformed octal field".into());
    }
    let mut value = 0u64;
    for &byte in &trimmed[..end] {
        if !(b'0'..=b'7').contains(&byte) {
            return Err("untar: malformed octal field".into());
        }
        value = value
            .checked_mul(8)
            .and_then(|v| v.checked_add((byte - b'0') as u64))
            .ok_or("untar: octal field overflows u64")?;
    }
    Ok(value)
}

fn cstr(field: &[u8]) -> String {
    let end = field.iter().position(|&b| b == 0).unwrap_or(field.len());
    String::from_utf8_lossy(&field[..end]).into_owned()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum NodeKind {
    Directory,
    Regular,
    Symlink,
    Hardlink,
}

impl NodeKind {
    fn description(self) -> &'static str {
        match self {
            NodeKind::Directory => "a directory",
            NodeKind::Regular => "a regular file",
            NodeKind::Symlink => "a symlink",
            NodeKind::Hardlink => "a hardlink",
        }
    }
}

#[derive(Debug)]
enum EntryKind {
    Directory,
    Regular(Vec<u8>),
    Symlink(String),
    Hardlink(String),
}

#[derive(Debug)]
struct Entry {
    name: String,
    rel: String,
    mode: u32,
    kind: EntryKind,
}

impl Entry {
    fn node_kind(&self) -> NodeKind {
        match self.kind {
            EntryKind::Directory => NodeKind::Directory,
            EntryKind::Regular(_) => NodeKind::Regular,
            EntryKind::Symlink(_) => NodeKind::Symlink,
            EntryKind::Hardlink(_) => NodeKind::Hardlink,
        }
    }
}

fn normalized_rel(name: &str) -> &str {
    let mut rel = name;
    while let Some(rest) = rel.strip_prefix("./") {
        rel = rest;
    }
    rel.trim_end_matches('/')
}

fn validate_header_checksum(block: &[u8]) -> Result<(), String> {
    let declared = octal(&block[148..156])?;
    let actual: u64 = block
        .iter()
        .enumerate()
        .map(|(idx, byte)| {
            if (148..156).contains(&idx) {
                b' ' as u64
            } else {
                *byte as u64
            }
        })
        .sum();
    if declared != actual {
        return Err(format!(
            "untar: header checksum mismatch (declared {declared:o}, actual {actual:o})"
        ));
    }
    Ok(())
}

/// One tar entry after pax and GNU long-name records are applied.
pub(crate) struct ArchiveEntry {
    /// The entry name as recorded in the archive.
    pub(crate) name: String,
    /// `name` without leading `./` and trailing `/`.
    pub(crate) rel: String,
    /// Permission bits from the header.
    pub(crate) mode: u32,
    /// The tar typeflag byte.
    pub(crate) typeflag: u8,
    /// Link target for symlink and hardlink entries.
    pub(crate) link: String,
    /// Regular-file contents, present only when the selector kept them.
    pub(crate) body: Option<Vec<u8>>,
}

struct TarReader<R> {
    input: R,
    offset: u64,
    global: BTreeMap<String, String>,
    local: BTreeMap<String, String>,
    long_name: Option<String>,
    long_link: Option<String>,
}

impl<R: Read> TarReader<R> {
    fn new(input: R) -> Self {
        Self {
            input,
            offset: 0,
            global: BTreeMap::new(),
            local: BTreeMap::new(),
            long_name: None,
            long_link: None,
        }
    }

    fn read_exact(&mut self, bytes: &mut [u8]) -> Result<(), String> {
        let mut done = 0;
        while done < bytes.len() {
            let count = self
                .input
                .read(&mut bytes[done..])
                .map_err(|e| format!("untar: offset {}: {e}", self.offset))?;
            if count == 0 {
                return Err(format!(
                    "untar: truncated archive at offset {}",
                    self.offset
                ));
            }
            done += count;
            self.offset += count as u64;
        }
        Ok(())
    }

    fn skip(&mut self, mut remaining: u64) -> Result<(), String> {
        let mut buffer = [0u8; 8192];
        while remaining != 0 {
            let count = remaining.min(buffer.len() as u64) as usize;
            self.read_exact(&mut buffer[..count])?;
            remaining -= count as u64;
        }
        Ok(())
    }

    fn payload(&mut self, size: u64, keep: bool) -> Result<Option<Vec<u8>>, String> {
        let body = if keep {
            let len = usize::try_from(size)
                .map_err(|_| format!("untar: entry too large at offset {}", self.offset))?;
            let mut bytes = Vec::new();
            bytes.try_reserve_exact(len).map_err(|e| {
                format!(
                    "untar: cannot allocate entry at offset {}: {e}",
                    self.offset
                )
            })?;
            bytes.resize(len, 0);
            self.read_exact(&mut bytes)?;
            Some(bytes)
        } else {
            self.skip(size)?;
            None
        };
        self.skip((512 - size % 512) % 512)?;
        Ok(body)
    }

    fn next(
        &mut self,
        select: &mut impl FnMut(&str, u8) -> bool,
    ) -> Result<Option<ArchiveEntry>, String> {
        loop {
            let mut block = [0u8; 512];
            let first = self
                .input
                .read(&mut block[..1])
                .map_err(|e| format!("untar: offset {}: {e}", self.offset))?;
            if first == 0 {
                return Ok(None);
            }
            self.offset += 1;
            self.read_exact(&mut block[1..])?;
            if block.iter().all(|byte| *byte == 0) {
                let mut rest = [0u8; 8192];
                loop {
                    let count = self
                        .input
                        .read(&mut rest)
                        .map_err(|e| format!("untar: offset {}: {e}", self.offset))?;
                    if count == 0 {
                        return Ok(None);
                    }
                    if rest[..count].iter().any(|byte| *byte != 0) {
                        return Err(format!(
                            "untar: non-zero data after end marker at offset {}",
                            self.offset
                        ));
                    }
                    self.offset += count as u64;
                }
            }
            validate_header_checksum(&block)
                .map_err(|e| format!("{e} at offset {}", self.offset - 512))?;
            let header_size = octal(&block[124..136])
                .map_err(|e| format!("{e} at offset {}", self.offset - 512))?;
            let typeflag = block[156];
            if matches!(typeflag, b'g' | b'x' | b'L' | b'K') {
                if header_size > 16 * 1024 * 1024 {
                    return Err(format!(
                        "untar: metadata too large at offset {}",
                        self.offset
                    ));
                }
                let data = self
                    .payload(header_size, true)?
                    .ok_or("untar: missing metadata")?;
                match typeflag {
                    b'g' => self.global.extend(parse_pax(&data)?),
                    b'x' => self.local.extend(parse_pax(&data)?),
                    b'L' => self.long_name = Some(cstr(&data)),
                    b'K' => self.long_link = Some(cstr(&data)),
                    _ => {}
                }
                continue;
            }
            let prefix = cstr(&block[345..500]);
            let header_name = cstr(&block[0..100]);
            let header_name = if prefix.is_empty() {
                header_name
            } else {
                format!("{prefix}/{header_name}")
            };
            let pax_path = self
                .local
                .get("path")
                .or_else(|| self.global.get("path"))
                .cloned();
            let pax_link = self
                .local
                .get("linkpath")
                .or_else(|| self.global.get("linkpath"))
                .cloned();
            let pax_size = self
                .local
                .get("size")
                .or_else(|| self.global.get("size"))
                .cloned();
            let name = pax_path
                .or_else(|| self.long_name.take())
                .unwrap_or(header_name);
            let link = pax_link
                .or_else(|| self.long_link.take())
                .unwrap_or_else(|| cstr(&block[157..257]));
            let size = match pax_size {
                Some(value) => {
                    decimal(&value).map_err(|e| format!("{e} at offset {}", self.offset - 512))?
                }
                None => header_size,
            };
            self.local.clear();
            self.long_name = None;
            self.long_link = None;
            let rel = normalized_rel(&name).to_string();
            if rel.is_empty() || rel == "." {
                self.payload(size, false)?;
                continue;
            }
            if path_escapes(&rel) {
                return Err(format!("untar: entry `{name}` escapes the output dir"));
            }
            let mode = u32::try_from(octal(&block[100..108])?)
                .map_err(|_| format!("untar: mode overflows at offset {}", self.offset - 512))?;
            if typeflag == b'1'
                && (normalized_rel(&link).is_empty() || path_escapes(normalized_rel(&link)))
            {
                return Err(format!(
                    "untar: hardlink `{name}` has escaping target `{link}`"
                ));
            }
            if !matches!(typeflag, b'5' | b'2' | b'1' | b'0' | 0 | b'7') {
                return Err(format!(
                    "untar: unsupported entry type 0x{typeflag:02x} at `{name}`"
                ));
            }
            let keep = matches!(typeflag, b'0' | 0 | b'7') && select(&rel, typeflag);
            let body = self.payload(size, keep)?;
            return Ok(Some(ArchiveEntry {
                name,
                rel,
                mode,
                typeflag,
                link,
                body,
            }));
        }
    }
}

fn decimal(value: &str) -> Result<u64, String> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err("untar: malformed PAX size".into());
    }
    value
        .parse()
        .map_err(|_| "untar: PAX size overflows u64".into())
}

fn parse_pax(data: &[u8]) -> Result<BTreeMap<String, String>, String> {
    let mut records = BTreeMap::new();
    let mut pos = 0usize;
    while pos < data.len() {
        let space = data[pos..]
            .iter()
            .position(|byte| *byte == b' ')
            .ok_or("untar: malformed PAX length")?
            + pos;
        let len =
            std::str::from_utf8(&data[pos..space]).map_err(|_| "untar: malformed PAX length")?;
        if len.is_empty() || !len.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err("untar: malformed PAX length".into());
        }
        let len: usize = len
            .parse()
            .map_err(|_| "untar: PAX length overflows address space")?;
        let end = pos
            .checked_add(len)
            .ok_or("untar: PAX length overflows address space")?;
        if end > data.len() || end <= space + 2 || data[end - 1] != b'\n' {
            return Err("untar: malformed PAX record framing".into());
        }
        let record = &data[space + 1..end - 1];
        let equal = record
            .iter()
            .position(|byte| *byte == b'=')
            .ok_or("untar: malformed PAX key")?;
        if equal == 0 {
            return Err("untar: empty PAX key".into());
        }
        let key = std::str::from_utf8(&record[..equal]).map_err(|_| "untar: non-UTF-8 PAX key")?;
        let value =
            std::str::from_utf8(&record[equal + 1..]).map_err(|_| "untar: non-UTF-8 PAX value")?;
        if matches!(key, "path" | "linkpath" | "size") {
            records.insert(key.to_string(), value.to_string());
        }
        pos = end;
    }
    Ok(records)
}

fn open_archive(archive: &Path) -> Result<Box<dyn Read>, String> {
    let file = std::fs::File::open(archive)
        .map_err(|e| format!("untar: cannot open {}: {e}", archive.display()))?;
    let mut reader = BufReader::new(file);
    let gzip = reader
        .fill_buf()
        .map_err(|e| format!("untar: cannot read {}: {e}", archive.display()))?
        .starts_with(&[0x1f, 0x8b]);
    if gzip {
        Ok(Box::new(inflate::Gzip::new(reader)))
    } else {
        Ok(Box::new(reader))
    }
}

/// Visit every tar entry in order. `select(rel, typeflag)` decides whether a
/// regular file's body is read into memory; unselected bodies are skipped.
pub(crate) fn scan_archive(
    archive: &Path,
    mut select: impl FnMut(&str, u8) -> bool,
    mut visit: impl FnMut(ArchiveEntry) -> Result<(), String>,
) -> Result<(), String> {
    let mut reader = TarReader::new(open_archive(archive)?);
    while let Some(entry) = reader
        .next(&mut select)
        .map_err(|e| format!("{}: {e}", archive.display()))?
    {
        visit(entry)?;
    }
    Ok(())
}

fn parse_archive(archive: &Path) -> Result<Vec<Entry>, String> {
    let mut entries = Vec::new();
    scan_archive(
        archive,
        |_, _| true,
        |entry| {
            let kind = match entry.typeflag {
                b'5' => EntryKind::Directory,
                b'2' => EntryKind::Symlink(entry.link),
                b'1' => EntryKind::Hardlink(normalized_rel(&entry.link).to_string()),
                _ => EntryKind::Regular(entry.body.ok_or("untar: missing file content")?),
            };
            entries.push(Entry {
                name: entry.name,
                rel: entry.rel,
                mode: entry.mode,
                kind,
            });
            Ok(())
        },
    )?;
    Ok(entries)
}

fn rel_ancestors(rel: &str) -> impl Iterator<Item = &str> {
    rel.match_indices('/').map(|(idx, _)| &rel[..idx])
}

fn validate_plan(entries: &[Entry]) -> Result<BTreeMap<String, NodeKind>, String> {
    let mut nodes: BTreeMap<String, NodeKind> = BTreeMap::new();
    for entry in entries {
        for ancestor in rel_ancestors(&entry.rel) {
            if let Some(kind) = nodes.get(ancestor) {
                if *kind != NodeKind::Directory {
                    return Err(format!(
                        "untar: entry `{}` write-through: ancestor `{ancestor}` is {}",
                        entry.name,
                        kind.description()
                    ));
                }
            }
        }
        let kind = entry.node_kind();
        if kind != NodeKind::Directory {
            let prefix = format!("{}/", entry.rel);
            if let Some((descendant, _)) = nodes.range(prefix.clone()..).next() {
                if descendant.starts_with(&prefix) {
                    return Err(format!(
                        "untar: entry `{}` replaces an ancestor of `{descendant}`",
                        entry.name
                    ));
                }
            }
        }
        if let Some(old) = nodes.get(&entry.rel) {
            if (*old == NodeKind::Directory) != (kind == NodeKind::Directory) {
                return Err(format!(
                    "untar: entry `{}` changes `{}` from {old:?} to {kind:?}",
                    entry.name, entry.rel
                ));
            }
        }
        nodes.insert(entry.rel.clone(), kind);
    }

    fn resolves_regular(
        rel: &str,
        entries: &[Entry],
        seen: &mut BTreeSet<String>,
    ) -> Result<(), String> {
        if !seen.insert(rel.to_string()) {
            return Err(format!("untar: hardlink cycle through `{rel}`"));
        }
        let entry = entries
            .iter()
            .rev()
            .find(|entry| entry.rel == rel)
            .ok_or_else(|| format!("untar: hardlink target `{rel}` does not exist"))?;
        match &entry.kind {
            EntryKind::Regular(_) => Ok(()),
            EntryKind::Hardlink(next) => resolves_regular(next, entries, seen),
            _ => Err(format!(
                "untar: hardlink target `{rel}` is not a regular file"
            )),
        }
    }
    for entry in entries {
        if let EntryKind::Hardlink(target) = &entry.kind {
            resolves_regular(target, entries, &mut BTreeSet::new())?;
        }
    }
    Ok(nodes)
}

fn ensure_empty_output(out: &Path) -> Result<(), String> {
    if out.is_dir() {
        let mut entries =
            std::fs::read_dir(out).map_err(|e| format!("untar: read {}: {e}", out.display()))?;
        if entries.next().is_some() {
            return Err(format!(
                "untar: output directory is not empty: {}",
                out.display()
            ));
        }
    } else if std::fs::symlink_metadata(out).is_ok() {
        return Err(format!(
            "untar: output is not a directory: {}",
            out.display()
        ));
    }
    Ok(())
}

fn ensure_parents(out: &Path, target: &Path, name: &str) -> Result<(), String> {
    if let Some(bad) = ancestor_is_symlink(out, target) {
        return Err(format!(
            "untar: entry `{name}` write-through: ancestor `{}` is a symlink",
            bad.display()
        ));
    }
    if let Some(parent) = target.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("untar: mkdir {}: {e}", parent.display()))?;
    }
    Ok(())
}

fn remove_leaf(path: &Path) -> Result<(), String> {
    let Ok(meta) = std::fs::symlink_metadata(path) else {
        return Ok(());
    };
    if meta.is_dir() && !meta.file_type().is_symlink() {
        std::fs::remove_dir(path)
    } else {
        std::fs::remove_file(path)
    }
    .map_err(|e| format!("untar: cannot replace {}: {e}", path.display()))
}

/// Structural, no-follow check: does `rel` (an entry's own path, already
/// trimmed of a leading `./`) escape the output dir? Lexical `starts_with`
/// on a joined path is unsound (`out.join("../x")` still `starts_with(out)`
/// component-wise is false, but the historical bug compared the joined
/// PathBuf's string form) — check path components directly instead.
fn path_escapes(rel: &str) -> bool {
    let p = Path::new(rel);
    p.is_absolute() || p.components().any(|c| matches!(c, Component::ParentDir))
}

/// Write-through defense: before creating a directory, symlink, or file at
/// `target`, verify no EXISTING ancestor between `out` and `target`'s parent
/// is a symlink. `create_dir_all`/`fs::write`/`os::unix::fs::symlink`'s own
/// parent-dir creation all silently FOLLOW a symlinked ancestor and mutate
/// whatever it points at — the actual hazard (a `foo -> /etc` entry followed
/// by a `foo/passwd`, or even a `foo/evil-link`, entry). Applied uniformly to
/// all three create/write branches (dir, symlink, file) in `extract` — the
/// hazard shape is identical regardless of what's finally created at
/// `target`. No-follow throughout: each check is `symlink_metadata` (lstat),
/// never `metadata` (stat). Returns the first symlinked ancestor found, or
/// `None` if the walk is clear. Stops at the first path component that
/// doesn't exist yet — nothing beneath a not-yet-created path can be a
/// preexisting symlink.
fn ancestor_is_symlink(out: &Path, target: &Path) -> Option<PathBuf> {
    let rel = target.strip_prefix(out).ok()?;
    let mut cur = out.to_path_buf();
    let mut components = rel.components().peekable();
    while let Some(comp) = components.next() {
        if components.peek().is_none() {
            break; // final component is `target` itself — not an ancestor
        }
        cur.push(comp);
        match std::fs::symlink_metadata(&cur) {
            Ok(meta) if meta.file_type().is_symlink() => return Some(cur),
            Ok(_) => {}
            Err(_) => break, // doesn't exist yet — nothing to walk through
        }
    }
    None
}

/// Extract `archive` (an uncompressed tar) into `out`, recreating files (with
/// their mode), directories, and symlinks. Paths are taken relative to `out`;
/// an entry whose OWN path escapes `out` via `..` or an absolute path is
/// rejected (`path_escapes`). A symlink's target is created verbatim,
/// absolute or not — creating a symlink AT `target` writes nothing outside
/// `out` by itself — but any entry (dir, symlink, or file) that would create
/// or write THROUGH an existing symlinked ancestor of `target` is rejected
/// (`ancestor_is_symlink`): that traversal is where a write actually lands
/// outside `out`. A file-content entry additionally removes any preexisting
/// symlink AT `target` itself before writing, so the write lands on a fresh
/// real file rather than following a stale link left by an earlier entry.
pub fn extract(archive: &Path, out: &Path) -> Result<(), String> {
    let entries = parse_archive(archive)?;
    let _nodes = validate_plan(&entries)?;
    ensure_empty_output(out)?;
    std::fs::create_dir_all(out).map_err(|e| format!("untar: mkdir {}: {e}", out.display()))?;

    let mut directory_modes = Vec::new();
    for entry in &entries {
        let target = out.join(&entry.rel);
        ensure_parents(out, &target, &entry.name)?;
        match &entry.kind {
            EntryKind::Directory => {
                std::fs::create_dir_all(&target)
                    .map_err(|e| format!("untar: mkdir {}: {e}", target.display()))?;
                directory_modes.push((target, entry.mode));
            }
            EntryKind::Regular(content) => {
                remove_leaf(&target)?;
                std::fs::write(&target, content)
                    .map_err(|e| format!("untar: write {}: {e}", target.display()))?;
                crate::platform::set_mode(&target, entry.mode | 0o600)
                    .map_err(|e| format!("untar: chmod {}: {e}", target.display()))?;
            }
            EntryKind::Symlink(link) => {
                remove_leaf(&target)?;
                crate::platform::create_symlink_auto(Path::new(link), &target)
                    .map_err(|e| format!("untar: symlink {}: {e}", target.display()))?;
            }
            EntryKind::Hardlink(_) => {}
        }
    }
    for entry in &entries {
        let EntryKind::Hardlink(link) = &entry.kind else {
            continue;
        };
        let target = out.join(&entry.rel);
        ensure_parents(out, &target, &entry.name)?;
        remove_leaf(&target)?;
        let mut resolved = link.as_str();
        loop {
            let source_entry = entries
                .iter()
                .rev()
                .find(|candidate| candidate.rel == resolved)
                .ok_or_else(|| format!("untar: missing hardlink target `{resolved}`"))?;
            match &source_entry.kind {
                EntryKind::Regular(_) => break,
                EntryKind::Hardlink(next) => resolved = next,
                _ => return Err(format!("untar: invalid hardlink target `{resolved}`")),
            }
        }
        std::fs::hard_link(out.join(resolved), &target).map_err(|e| {
            format!(
                "untar: hardlink {} -> {}: {e}",
                target.display(),
                out.join(resolved).display()
            )
        })?;
    }
    directory_modes.sort_by_key(|(path, _)| std::cmp::Reverse(path.components().count()));
    for (path, mode) in directory_modes {
        crate::platform::set_mode(&path, mode | 0o700)
            .map_err(|e| format!("untar: chmod {}: {e}", path.display()))?;
    }
    Ok(())
}

pub fn run(args: &[String]) -> Result<i32, String> {
    if args.len() != 2 {
        return Err("usage: buildutil untar <archive> <out-dir>".to_string());
    }
    let out = PathBuf::from(&args[1]);
    extract(&PathBuf::from(&args[0]), &out)?;
    // The dir-mode-inclusive tree hash is the exact value UntarBuilder
    // verifies against BUILDUTIL_FIXED_TREE_SHA256 — printing it here is the
    // canonical way to capture/record a seed import's pin.
    let tree_hash = crate::source::filehash::hash_tree_with_dir_modes(&out)?;
    out!("tree-sha256: {}", tree_hash);
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pax_record(key: &str, value: &str) -> Vec<u8> {
        let mut len = key.len() + value.len() + 4;
        loop {
            let record = format!("{len} {key}={value}\n");
            if record.len() == len {
                return record.into_bytes();
            }
            len = record.len();
        }
    }

    #[test]
    fn accepts_global_pax_and_local_long_path() {
        let dir = scratch_dir("pax");
        let mut data = Vec::new();
        push_entry(
            &mut data,
            "pax-global",
            b'g',
            0o644,
            &pax_record("comment", "revision"),
            "",
        );
        push_entry(&mut data, "plain.txt", b'0', 0o644, b"plain", "");
        let long_path = format!("nested/{}/file.txt", "segment".repeat(20));
        push_entry(
            &mut data,
            "pax-local",
            b'x',
            0o644,
            &pax_record("path", &long_path),
            "",
        );
        push_entry(&mut data, "short.txt", b'0', 0o644, b"long", "");
        let gnu_path = format!("gnu/{}/file.txt", "part".repeat(30));
        let mut gnu_name = gnu_path.as_bytes().to_vec();
        gnu_name.push(0);
        push_entry(&mut data, "gnu-long", b'L', 0o644, &gnu_name, "");
        push_entry(&mut data, "short-gnu", b'0', 0o644, b"gnu", "");
        push_entry(
            &mut data,
            "pax-link",
            b'x',
            0o644,
            &pax_record("linkpath", "plain.txt"),
            "",
        );
        push_entry(&mut data, "alias", b'1', 0o644, b"", "ignored");
        push_entry(
            &mut data,
            "pax-size",
            b'x',
            0o644,
            &pax_record("size", "3"),
            "",
        );
        data.extend_from_slice(&header_block("sized", b'0', 0o644, 0, ""));
        data.extend_from_slice(b"abc");
        data.resize(data.len().div_ceil(512) * 512, 0);
        data.extend_from_slice(&[0; 1024]);
        let archive = write_archive(&dir, &data);
        let out = dir.join("out");
        extract(&archive, &out).unwrap();
        assert_eq!(std::fs::read(out.join("plain.txt")).unwrap(), b"plain");
        let long_target = long_path
            .split('/')
            .fold(out.clone(), |path, part| path.join(part));
        assert_eq!(std::fs::read(long_target).unwrap(), b"long");
        let gnu_target = gnu_path
            .split('/')
            .fold(out.clone(), |path, part| path.join(part));
        assert_eq!(std::fs::read(gnu_target).unwrap(), b"gnu");
        assert_eq!(std::fs::read(out.join("sized")).unwrap(), b"abc");
        assert_eq!(std::fs::read(out.join("alias")).unwrap(), b"plain");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn rejects_bad_pax_and_numeric_fields() {
        let dir = scratch_dir("bad-fields");
        let mut data = Vec::new();
        push_entry(&mut data, "pax-local", b'x', 0o644, b"8 path=x\n", "");
        push_entry(&mut data, "next", b'0', 0o644, b"x", "");
        let archive = write_archive(&dir, &data);
        assert!(extract(&archive, &dir.join("out")).is_err());
        assert!(octal(&[0x80, 0, 0]).is_err());
        assert!(octal(b"not-octal").is_err());
        let _ = std::fs::remove_dir_all(dir);
    }

    const SMALL_TAR_GZ: &[u8] = &[
        31, 139, 8, 0, 0, 0, 0, 0, 2, 19, 237, 205, 177, 9, 2, 81, 16, 4, 208, 141, 173, 194, 10,
        244, 127, 56, 175, 7, 3, 51, 27, 80, 206, 88, 208, 21, 206, 238, 93, 140, 196, 92, 65, 124,
        47, 153, 97, 146, 201, 211, 156, 235, 221, 118, 191, 202, 57, 227, 67, 90, 25, 135, 225,
        153, 229, 61, 203, 230, 165, 215, 222, 91, 239, 99, 44, 91, 124, 193, 237, 154, 135, 75,
        221, 199, 127, 58, 158, 167, 251, 34, 0, 0, 0, 0, 0, 0, 0, 0, 0, 248, 53, 15, 26, 126, 193,
        193, 0, 40, 0, 0,
    ];

    #[test]
    fn extracts_gzip_tar() {
        let dir = scratch_dir("gzip-tar");
        let archive = dir.join("fixture.tar.gz");
        std::fs::write(&archive, SMALL_TAR_GZ).unwrap();
        let out = dir.join("out");
        extract(&archive, &out).unwrap();
        assert_eq!(
            std::fs::read(out.join("text").join("MIT.txt")).unwrap(),
            b"body\n"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    /// Build a 512-byte ustar header. Only the fields `extract` reads.
    fn header_block(name: &str, typeflag: u8, mode: u32, size: usize, linkname: &str) -> [u8; 512] {
        let mut block = [0u8; 512];
        let nb = name.as_bytes();
        let n = nb.len().min(100);
        block[0..n].copy_from_slice(&nb[..n]);
        let mode_str = format!("{:07o}\0", mode);
        let mb = mode_str.as_bytes();
        let ml = mb.len().min(8);
        block[100..100 + ml].copy_from_slice(&mb[..ml]);
        let size_str = format!("{:011o}\0", size);
        let sb = size_str.as_bytes();
        let sl = sb.len().min(12);
        block[124..124 + sl].copy_from_slice(&sb[..sl]);
        block[156] = typeflag;
        let lb = linkname.as_bytes();
        let ll = lb.len().min(100);
        block[157..157 + ll].copy_from_slice(&lb[..ll]);
        block[148..156].fill(b' ');
        let checksum: u64 = block.iter().map(|byte| *byte as u64).sum();
        let checksum = format!("{:06o}\0 ", checksum);
        block[148..156].copy_from_slice(checksum.as_bytes());
        block
    }

    fn push_entry(
        data: &mut Vec<u8>,
        name: &str,
        typeflag: u8,
        mode: u32,
        content: &[u8],
        linkname: &str,
    ) {
        data.extend_from_slice(&header_block(name, typeflag, mode, content.len(), linkname));
        data.extend_from_slice(content);
        let pad = (512 - (content.len() % 512)) % 512;
        data.extend(std::iter::repeat(0u8).take(pad));
    }

    fn scratch_dir(tag: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!(
                "buildutil-untar-test-{}-{}",
                std::process::id(),
                tag
            ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn write_archive(dir: &Path, data: &[u8]) -> PathBuf {
        let archive = dir.join("test.tar");
        std::fs::write(&archive, data).unwrap();
        archive
    }

    #[test]
    fn rejects_parent_dir_escape() {
        let dir = scratch_dir("parent-escape");
        let mut data = Vec::new();
        push_entry(&mut data, "../escape", b'0', 0o644, b"x", "");
        let archive = write_archive(&dir, &data);
        let err = extract(&archive, &dir.join("out")).unwrap_err();
        assert!(err.contains("escapes"), "{}", err);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn rejects_absolute_path() {
        let dir = scratch_dir("absolute-path");
        let mut data = Vec::new();
        push_entry(&mut data, "/etc/passwd", b'0', 0o644, b"x", "");
        let archive = write_archive(&dir, &data);
        let err = extract(&archive, &dir.join("out")).unwrap_err();
        assert!(err.contains("escapes"), "{}", err);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn creates_absolute_and_escaping_symlink_targets_verbatim() {
        // A symlink's own entry path still can't escape (path_escapes), but
        // its TARGET may be anything, including absolute or `..`-climbing —
        // creating the link itself writes nothing outside `out`. This is the
        // real seed's shape: e.g. `lib/python3.12/sitecustomize.py ->
        // /etc/python3.12/sitecustomize.py` (a standard, dangling Debian
        // python3-minimal artifact) must extract cleanly.
        let dir = scratch_dir("verbatim-symlink-target");
        let mut data = Vec::new();
        push_entry(&mut data, "abs-link", b'2', 0o777, b"", "/etc/passwd");
        push_entry(&mut data, "climbing-link", b'2', 0o777, b"", "../../etc");
        let archive = write_archive(&dir, &data);
        let out = dir.join("out");
        extract(&archive, &out).unwrap();
        assert_eq!(
            std::fs::read_link(out.join("abs-link")).unwrap(),
            Path::new("/etc/passwd")
        );
        assert_eq!(
            std::fs::read_link(out.join("climbing-link")).unwrap(),
            Path::new("../../etc")
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn rejects_write_through_a_symlinked_ancestor() {
        // `d` is a symlink (target need not exist or resolve anywhere real —
        // the check only cares that `d` IS a symlink, not where it points).
        // A later entry nested under `d` must not be allowed to create/write
        // through it.
        let dir = scratch_dir("write-through-ancestor");
        let mut data = Vec::new();
        push_entry(&mut data, "d", b'2', 0o777, b"", "/nonexistent-target");
        push_entry(&mut data, "d/x", b'0', 0o644, b"payload", "");
        let archive = write_archive(&dir, &data);
        let err = extract(&archive, &dir.join("out")).unwrap_err();
        assert!(err.contains("write-through"), "{}", err);
        assert!(err.contains("symlink"), "{}", err);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn rejects_a_symlink_entry_nested_under_a_symlinked_ancestor() {
        // Same hazard as `rejects_write_through_a_symlinked_ancestor`, but
        // the nested entry is itself a SYMLINK (typeflag b'2'), not a file —
        // the ancestor check must fire for all three create/write branches,
        // not just the file-write one.
        let dir = scratch_dir("write-through-ancestor-symlink");
        let mut data = Vec::new();
        push_entry(&mut data, "d", b'2', 0o777, b"", "/nonexistent-target");
        push_entry(&mut data, "d/evil", b'2', 0o777, b"", "somewhere");
        let archive = write_archive(&dir, &data);
        let err = extract(&archive, &dir.join("out")).unwrap_err();
        assert!(err.contains("write-through"), "{}", err);
        assert!(err.contains("symlink"), "{}", err);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn file_write_removes_a_preexisting_symlink_at_the_exact_target() {
        // `x` is first a symlink pointing OUTSIDE `out` (at `../marker`,
        // i.e. a sibling of `out`, fully within our own scratch dir so the
        // test can assert on it without touching anything ambient). A later
        // FILE entry at the same path `x` must remove the stale symlink and
        // write a real file in its place — not follow it out to `marker`.
        let dir = scratch_dir("leaf-symlink-removed");
        let mut data = Vec::new();
        push_entry(&mut data, "x", b'2', 0o777, b"", "../marker");
        push_entry(&mut data, "x", b'0', 0o644, b"real-content", "");
        let archive = write_archive(&dir, &data);
        let out = dir.join("out");
        extract(&archive, &out).unwrap();
        let meta = std::fs::symlink_metadata(out.join("x")).unwrap();
        assert!(
            !meta.file_type().is_symlink(),
            "x should be a real file now"
        );
        assert_eq!(
            std::fs::read_to_string(out.join("x")).unwrap(),
            "real-content"
        );
        assert!(
            !dir.join("marker").exists(),
            "the write must not have followed the old symlink out to `marker`"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn extracts_normal_tree_cleanly() {
        let dir = scratch_dir("normal-tree");
        let mut data = Vec::new();
        push_entry(&mut data, "sub", b'5', 0o755, b"", "");
        push_entry(&mut data, "sub/file.txt", b'0', 0o644, b"hi", "");
        push_entry(&mut data, "sub/alias", b'2', 0o777, b"", "file.txt");
        let archive = write_archive(&dir, &data);
        let out = dir.join("out");
        extract(&archive, &out).unwrap();
        assert_eq!(
            std::fs::read_to_string(out.join("sub/file.txt")).unwrap(),
            "hi"
        );
        assert_eq!(
            std::fs::read_link(out.join("sub/alias")).unwrap(),
            Path::new("file.txt")
        );
        assert!(out.join("sub").is_dir());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn extracts_hardlinks_as_shared_files() {
        let dir = scratch_dir("hardlink");
        let mut data = Vec::new();
        push_entry(&mut data, "bin/tool", b'0', 0o755, b"payload", "");
        push_entry(&mut data, "bin/tool-copy", b'1', 0o755, b"", "bin/tool");
        let archive = write_archive(&dir, &data);
        let out = dir.join("out");
        extract(&archive, &out).unwrap();
        assert_eq!(
            std::fs::read(out.join("bin/tool-copy")).unwrap(),
            b"payload"
        );
        let a = std::fs::metadata(out.join("bin/tool")).unwrap();
        let b = std::fs::metadata(out.join("bin/tool-copy")).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            assert_eq!(a.ino(), b.ino());
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn unsupported_type_is_rejected_before_output_is_created() {
        let dir = scratch_dir("unsupported-preflight");
        let mut data = Vec::new();
        push_entry(&mut data, "first", b'0', 0o644, b"would-be-partial", "");
        push_entry(&mut data, "fifo", b'6', 0o644, b"", "");
        let archive = write_archive(&dir, &data);
        let out = dir.join("out");
        let err = extract(&archive, &out).unwrap_err();
        assert!(err.contains("unsupported entry type"), "{err}");
        assert!(!out.exists(), "preflight failure must not create output");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
