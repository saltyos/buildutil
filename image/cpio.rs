//! SPDX-License-Identifier: GPL-2.0-only
//! buildutil — CPIO newc writer for initrd images
//!
//! Deterministic by construction: inode numbers are sequential, mtime is
//! zero, and entry order is the manifest order. Every entry name is the
//! canonical absolute path of its destination, and no two entries share
//! one. An entry is a regular file or a symbolic link, whose body is its
//! target; the archive carries no directory entries. The format aligns data
//! to four bytes. A consumer that maps file data in place declares a larger
//! alignment and the entries it applies to (`Align`); the writer then
//! places `.pad/NNNN` filler entries so each selected entry's data starts
//! on that boundary. Padding names are the one exception to absolute names;
//! a reader skips them.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

const HEADER_SIZE: usize = 110;

/// The file type bits of a regular file and of a symbolic link.
const MODE_REGULAR: u32 = 0o100000;
const MODE_SYMLINK: u32 = 0o120000;

/// The manifest source prefix that declares a symbolic link, the syntax the
/// rootfs manifest shares.
const SYMLINK_SOURCE: &str = "@symlink:";

/// The name prefix of the alignment filler entries.
const PAD_PREFIX: &str = ".pad/";

/// The largest data alignment a declaration may ask for.
const MAX_ALIGN: usize = 65536;

/// Which entries get their data aligned beyond the format's four bytes, and
/// to what. The archive's consumer declares it; the writer knows no default.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Align {
    /// The data alignment in bytes; zero aligns nothing.
    pub bytes: usize,
    /// Align ELF and PE images, recognized by their magic.
    pub executables: bool,
    /// Align every entry under these archive directories.
    pub under: Vec<String>,
}

impl Align {
    /// Take the alignment option at `args[*i]`, with its value; `Ok(false)`
    /// when the word is none of them.
    pub fn take(&mut self, args: &[String], i: &mut usize) -> Result<bool, String> {
        match args[*i].as_str() {
            "--align" => {
                *i += 1;
                let text = args.get(*i).ok_or("--align needs a byte count")?;
                let bytes: usize =
                    text.parse().map_err(|_| format!("--align `{text}` is not a byte count"))?;
                if !(4..=MAX_ALIGN).contains(&bytes) || !bytes.is_power_of_two() {
                    return Err(format!(
                        "--align {bytes} is not a power of two from 4 to {MAX_ALIGN}"
                    ));
                }
                self.bytes = bytes;
            }
            "--align-executables" => self.executables = true,
            "--align-under" => {
                *i += 1;
                let dir = args
                    .get(*i)
                    .map(|dir| dir.trim_matches('/'))
                    .filter(|dir| !dir.is_empty())
                    .ok_or("--align-under needs an archive directory")?;
                self.under.push(dir.to_string());
            }
            _ => return Ok(false),
        }
        Ok(true)
    }

    /// Refuse an alignment that selects no entry and a selection without
    /// an alignment.
    pub fn validate(&self) -> Result<(), String> {
        let selects = self.executables || !self.under.is_empty();
        match (self.bytes != 0, selects) {
            (true, false) => Err(
                "--align selects no entry; name --align-executables or --align-under".to_string(),
            ),
            (false, true) => {
                Err("--align-executables and --align-under need --align <bytes>".to_string())
            }
            _ => Ok(()),
        }
    }

    /// Whether the data of entry `name`, holding `data`, is aligned.
    pub fn selects(&self, name: &str, data: &[u8]) -> bool {
        if self.bytes == 0 {
            return false;
        }
        if self.executables && (data.starts_with(b"\x7fELF") || data.starts_with(b"MZ")) {
            return true;
        }
        let path = name.trim_start_matches('/');
        self.under
            .iter()
            .any(|dir| path.strip_prefix(dir.as_str()).is_some_and(|rest| rest.starts_with('/')))
    }
}

fn align4(n: usize) -> usize {
    (n + 3) & !3
}

fn header(ino: u32, mode: u32, filesize: usize, namesize: usize, uid: u32, gid: u32) -> String {
    format!(
        "070701{ino:08X}{mode:08X}{uid:08X}{gid:08X}{nlink:08X}{mtime:08X}{filesize:08X}\
         {devmajor:08X}{devminor:08X}{rdevmajor:08X}{rdevminor:08X}{namesize:08X}{check:08X}",
        nlink = 1,
        mtime = 0,
        devmajor = 0,
        devminor = 0,
        rdevmajor = 0,
        rdevminor = 0,
        check = 0,
    )
}

fn append_entry(
    archive: &mut Vec<u8>,
    ino: u32,
    name: &str,
    data: &[u8],
    mode: u32,
    uid: u32,
    gid: u32,
) {
    let namesize = name.len() + 1;
    archive.extend_from_slice(header(ino, mode, data.len(), namesize, uid, gid).as_bytes());
    archive.extend_from_slice(name.as_bytes());
    archive.push(0);
    let header_plus_name = HEADER_SIZE + namesize;
    archive.resize(
        archive.len() + (align4(header_plus_name) - header_plus_name),
        0,
    );
    archive.extend_from_slice(data);
    archive.resize(archive.len() + (align4(data.len()) - data.len()), 0);
}

fn next_data_start(archive_len: usize, name: &str) -> usize {
    align4(archive_len + HEADER_SIZE + name.len() + 1)
}

/// The smallest pad-entry payload that lands the next entry's data start
/// on an `alignment` boundary.
fn pad_payload_size(
    archive_len: usize,
    next_name: &str,
    pad_name: &str,
    alignment: usize,
) -> Option<usize> {
    (0..alignment).find(|&payload| {
        let pad_data_start = align4(archive_len + HEADER_SIZE + pad_name.len() + 1);
        let after_pad = align4(pad_data_start + payload);
        next_data_start(after_pad, next_name) % alignment == 0
    })
}

pub type Permissions = BTreeMap<String, (u32, u32, u32)>;

/// What one archive entry holds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Source {
    /// A regular file whose bytes are read from this path.
    File(PathBuf),
    /// A symbolic link to this target, stored as written.
    Symlink(String),
}

/// One archive entry: its canonical name and what it holds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub name: String,
    pub source: Source,
}

/// The canonical archive name of a destination: absolute, with empty and
/// `.` components dropped and each `..` taking back the component before
/// it, a `..` at the root staying there. A destination that is empty or
/// reduces to `/` names no entry and is refused.
pub fn canonical_name(destination: &str) -> Result<String, String> {
    let mut components: Vec<&str> = Vec::new();
    for component in destination.split('/') {
        match component {
            "" | "." => {}
            ".." => {
                components.pop();
            }
            component => components.push(component),
        }
    }
    if components.is_empty() {
        return Err(format!("destination `{destination}` names no entry"));
    }
    Ok(format!("/{}", components.join("/")))
}

/// The entry for a source that is itself a symbolic link: the link's own
/// target, never what it points to.
fn link_source(path: &Path) -> Result<Source, String> {
    let target = std::fs::read_link(path)
        .map_err(|e| format!("cannot read link {}: {}", path.display(), e))?;
    let target = target
        .to_str()
        .ok_or_else(|| format!("link {} has a target that is not UTF-8", path.display()))?;
    if target.is_empty() {
        return Err(format!("link {} has an empty target", path.display()));
    }
    Ok(Source::Symlink(target.to_string()))
}

/// Every regular file and symbolic link under `root`, each directory's
/// entries in byte order of their names, descended depth-first (so `sub/…`
/// precedes `sub.txt`). A link is not followed, whatever it points to; other
/// node types are not archive content.
fn walk_manifest_directory(root: &Path) -> Result<Vec<PathBuf>, String> {
    fn walk(dir: &Path, out: &mut Vec<PathBuf>) -> Result<(), String> {
        let read_dir = std::fs::read_dir(dir)
            .map_err(|e| format!("cannot read directory {}: {}", dir.display(), e))?;
        let mut children = Vec::new();
        for child in read_dir {
            let child = child
                .map_err(|e| format!("cannot read directory entry in {}: {}", dir.display(), e))?;
            children.push(child);
        }
        children.sort_by_key(|child| child.file_name());

        for child in children {
            let path = child.path();
            let metadata = std::fs::symlink_metadata(&path)
                .map_err(|e| format!("cannot inspect {}: {}", path.display(), e))?;
            let file_type = metadata.file_type();
            if file_type.is_dir() {
                walk(&path, out)?;
            } else if file_type.is_symlink() || file_type.is_file() {
                out.push(path);
            }
        }
        Ok(())
    }

    let mut files = Vec::new();
    walk(root, &mut files)?;
    files.sort();
    Ok(files)
}

/// Parse a permissions file: `/path MODE UID GID` per line, octal mode.
pub fn load_permissions(path: &Path) -> Result<Permissions, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read {}: {}", path.display(), e))?;
    let mut perms = Permissions::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() != 4 {
            continue;
        }
        let mode = u32::from_str_radix(parts[1], 8)
            .map_err(|e| format!("{}: bad mode `{}`: {}", path.display(), parts[1], e))?;
        let uid = parts[2].parse().map_err(|e| format!("bad uid: {}", e))?;
        let gid = parts[3].parse().map_err(|e| format!("bad gid: {}", e))?;
        perms.insert(parts[0].to_string(), (mode, uid, gid));
    }
    Ok(perms)
}

/// The entries one `destination=source` line declares. `source` is
/// `@symlink:<target>` for a link, else a path `resolve` finds: a regular
/// file, a symbolic link (stored as a link to its own target) or a
/// directory, which expands inline to every file and link under it in
/// `walk_manifest_directory`'s order.
fn line_entries(
    destination: &str,
    source: &str,
    resolve: impl Fn(&str) -> Option<PathBuf>,
) -> Result<Vec<Entry>, String> {
    let name = canonical_name(destination)?;
    if let Some(target) = source.strip_prefix(SYMLINK_SOURCE) {
        if target.is_empty() {
            return Err(format!("`{destination}` declares a link with an empty target"));
        }
        return Ok(vec![Entry { name, source: Source::Symlink(target.to_string()) }]);
    }
    let path = resolve(source).ok_or_else(|| format!("file not found: {source}"))?;
    let metadata = std::fs::symlink_metadata(&path)
        .map_err(|e| format!("cannot inspect {}: {}", path.display(), e))?;
    if metadata.file_type().is_symlink() {
        return Ok(vec![Entry { name, source: link_source(&path)? }]);
    }
    if !metadata.file_type().is_dir() {
        return Ok(vec![Entry { name, source: Source::File(path) }]);
    }
    let mut entries = Vec::new();
    for child in walk_manifest_directory(&path)? {
        let relative = child
            .strip_prefix(&path)
            .map_err(|_| format!("directory walk escaped {}", path.display()))?;
        let relative = relative
            .to_str()
            .ok_or_else(|| format!("{} has a name that is not UTF-8", child.display()))?;
        let name = canonical_name(&format!("{name}/{relative}"))?;
        let child_type = std::fs::symlink_metadata(&child)
            .map_err(|e| format!("cannot inspect {}: {}", child.display(), e))?
            .file_type();
        let source =
            if child_type.is_symlink() { link_source(&child)? } else { Source::File(child) };
        entries.push(Entry { name, source });
    }
    Ok(entries)
}

/// Parse a manifest, one `destination=source` line each, `#` lines and
/// blank lines aside. A destination is canonicalized to an absolute name
/// (`canonical_name`). A source is `@symlink:<target>` or a path resolved
/// against the manifest's directory, then `port_dir` (see `line_entries`).
pub fn load_manifest(manifest: &Path, port_dir: Option<&Path>) -> Result<Vec<Entry>, String> {
    let text = std::fs::read_to_string(manifest)
        .map_err(|e| format!("cannot read {}: {}", manifest.display(), e))?;
    let base = manifest.parent().unwrap_or(Path::new("."));
    let resolve = |source: &str| {
        let mut candidates = vec![base.join(source)];
        if let Some(pd) = port_dir {
            candidates.push(pd.join(source));
        }
        // A dangling link is a link and still a source.
        candidates.into_iter().find(|path| std::fs::symlink_metadata(path).is_ok())
    };
    let mut entries = Vec::new();
    for (index, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let at = |error: String| format!("{}:{}: {}", manifest.display(), index + 1, error);
        let (destination, source) = line
            .split_once('=')
            .ok_or_else(|| at(format!("expected destination=source, got `{line}`")))?;
        entries.extend(line_entries(destination.trim(), source.trim(), &resolve).map_err(at)?);
    }
    Ok(entries)
}

/// Refuse an archive that names one path twice.
fn check_unique(entries: &[Entry]) -> Result<(), String> {
    let mut names = BTreeSet::new();
    for entry in entries {
        if !names.insert(entry.name.as_str()) {
            return Err(format!("`{}` is named twice in the archive", entry.name));
        }
    }
    Ok(())
}

/// Build the archive bytes from ordered entries, the entries `align`
/// selects starting their data on its boundary. Names must be canonical and
/// unique across the archive. A permissions line gives an entry its
/// permission bits and owner; the entry's kind gives the file type.
pub fn build(entries: &[Entry], perms: &Permissions, align: &Align) -> Result<Vec<u8>, String> {
    for entry in entries {
        if canonical_name(&entry.name)? != entry.name {
            return Err(format!("`{}` is not a canonical archive name", entry.name));
        }
    }
    check_unique(entries)?;
    let mut archive = Vec::new();
    let mut ino: u32 = 1;
    let mut pad_idx = 0;

    for entry in entries {
        let name = &entry.name;
        let (kind, data) = match &entry.source {
            Source::File(path) => (
                MODE_REGULAR,
                std::fs::read(path).map_err(|e| format!("cannot read {}: {}", path.display(), e))?,
            ),
            Source::Symlink(target) => (MODE_SYMLINK, target.as_bytes().to_vec()),
        };
        if align.selects(name, &data) && next_data_start(archive.len(), name) % align.bytes != 0 {
            let pad_name = format!("{PAD_PREFIX}{:04}", pad_idx);
            let payload = pad_payload_size(archive.len(), name, &pad_name, align.bytes)
                .ok_or_else(|| format!("failed to align CPIO entry: {}", name))?;
            append_entry(
                &mut archive,
                ino,
                &pad_name,
                &vec![0u8; payload],
                MODE_REGULAR | 0o644,
                0,
                0,
            );
            ino += 1;
            pad_idx += 1;
        }
        let default_bits = if kind == MODE_SYMLINK { 0o777 } else { 0o644 };
        let (bits, uid, gid) = match perms.get(name) {
            // A link's permission bits are not consulted; its owner is.
            Some(&(_, uid, gid)) if kind == MODE_SYMLINK => (0o777, uid, gid),
            Some(&(mode, uid, gid)) => (mode & 0o7777, uid, gid),
            None => (default_bits, 0, 0),
        };
        append_entry(&mut archive, ino, name, &data, kind | bits, uid, gid);
        ino += 1;
    }

    // Trailer.
    let trailer = "TRAILER!!!";
    let namesize = trailer.len() + 1;
    archive.extend_from_slice(header(0, 0, 0, namesize, 0, 0).as_bytes());
    archive.extend_from_slice(trailer.as_bytes());
    archive.push(0);
    let header_plus_name = HEADER_SIZE + namesize;
    archive.resize(
        archive.len() + (align4(header_plus_name) - header_plus_name),
        0,
    );
    Ok(archive)
}

/// `buildutil cpio --output <file> [--manifest <file>]... [--port-dir <dir>]
/// [--permissions <file>] [--align <bytes> [--align-executables]
/// [--align-under <dir>]...] [<destination>=<source>]...`. A positional
/// entry takes a manifest line's form, its path resolved against the
/// working directory; positional entries and every manifest form one
/// archive, in which no path may be named twice.
pub fn run(args: &[String]) -> Result<i32, String> {
    let mut output: Option<PathBuf> = None;
    let mut manifests: Vec<PathBuf> = Vec::new();
    let mut port_dir: Option<PathBuf> = None;
    let mut perms_path: Option<PathBuf> = None;
    let mut align = Align::default();
    let mut positional: Vec<String> = Vec::new();
    let mut i = 0;
    while i < args.len() {
        if align.take(args, &mut i)? {
            i += 1;
            continue;
        }
        match args[i].as_str() {
            "--output" | "-o" => {
                i += 1;
                output = Some(PathBuf::from(args.get(i).ok_or("--output needs a path")?));
            }
            "--manifest" => {
                i += 1;
                manifests.push(PathBuf::from(args.get(i).ok_or("--manifest needs a path")?));
            }
            "--port-dir" => {
                i += 1;
                port_dir = Some(PathBuf::from(args.get(i).ok_or("--port-dir needs a dir")?));
            }
            "--permissions" => {
                i += 1;
                perms_path = Some(PathBuf::from(
                    args.get(i).ok_or("--permissions needs a path")?,
                ));
            }
            other => positional.push(other.to_string()),
        }
        i += 1;
    }
    let output = output.ok_or("cpio: --output is required")?;
    align.validate().map_err(|e| format!("cpio: {e}"))?;

    let resolve = |source: &str| {
        let path = PathBuf::from(source);
        std::fs::symlink_metadata(&path).is_ok().then_some(path)
    };
    let mut entries: Vec<Entry> = Vec::new();
    for entry in &positional {
        let (destination, source) = entry
            .split_once('=')
            .ok_or_else(|| format!("cpio: entries are destination=source, got `{}`", entry))?;
        let declared =
            line_entries(destination, source, &resolve).map_err(|e| format!("cpio: {e}"))?;
        entries.extend(declared);
    }
    for manifest in &manifests {
        entries.extend(load_manifest(manifest, port_dir.as_deref())?);
    }
    if entries.is_empty() {
        return Err("cpio: no entries to archive".to_string());
    }
    let perms = match &perms_path {
        Some(p) if p.exists() => load_permissions(p)?,
        _ => Permissions::new(),
    };
    let archive = build(&entries, &perms, &align)?;
    if let Some(parent) = output.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("cannot create {}: {}", parent.display(), e))?;
    }
    std::fs::write(&output, &archive)
        .map_err(|e| format!("cannot write {}: {}", output.display(), e))?;
    crate::log::success(
        "cpio",
        &format!(
            "wrote {} ({} bytes, {} entries)",
            output.display(),
            archive.len(),
            entries.len()
        ),
    );
    Ok(0)
}

pub struct ParsedEntry {
    pub name: String,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub size: u32,
    pub data_offset: usize,
    pub sha256: String,
}

/// Decode a newc archive (used by the parity dumper).
pub fn parse(archive: &[u8]) -> Result<Vec<ParsedEntry>, String> {
    let mut entries = Vec::new();
    let mut off = 0usize;
    loop {
        if off + HEADER_SIZE > archive.len() {
            return Err("cpio: truncated header".to_string());
        }
        let hdr = &archive[off..off + HEADER_SIZE];
        if &hdr[..6] != b"070701" {
            return Err(format!("cpio: bad magic at offset {}", off));
        }
        let field = |i: usize| -> Result<u32, String> {
            let s = std::str::from_utf8(&hdr[6 + i * 8..6 + (i + 1) * 8])
                .map_err(|_| format!("cpio: non-ASCII header field at offset {}", off))?;
            u32::from_str_radix(s, 16)
                .map_err(|_| format!("cpio: bad hex field `{}` at offset {}", s, off))
        };
        let mode = field(1)?;
        let uid = field(2)?;
        let gid = field(3)?;
        let size = field(6)?;
        let namesize = field(11)? as usize;
        let name_start = off + HEADER_SIZE;
        if namesize == 0 || name_start + namesize > archive.len() {
            return Err("cpio: truncated name".to_string());
        }
        let name =
            String::from_utf8_lossy(&archive[name_start..name_start + namesize - 1]).to_string();
        let data_offset = align4(name_start + namesize);
        if name == "TRAILER!!!" {
            break;
        }
        if data_offset + size as usize > archive.len() {
            return Err(format!("cpio: truncated data for `{}`", name));
        }
        let data = &archive[data_offset..data_offset + size as usize];
        entries.push(ParsedEntry {
            name,
            mode,
            uid,
            gid,
            size,
            data_offset,
            sha256: crate::crypto::sha256::hash_bytes(data),
        });
        off = align4(data_offset + size as usize);
    }
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The data start of the entry named `name` in `archive`.
    fn data_start(archive: &[u8], name: &[u8]) -> usize {
        let pos = archive.windows(name.len()).position(|w| w == name).unwrap();
        align4(pos + name.len() + 1)
    }

    #[test]
    fn newc_layout_and_declared_alignment() {
        let dir = std::env::temp_dir().join(format!("buildutil-cpio-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let elf = dir.join("prog");
        std::fs::write(&elf, [b"\x7fELF".as_ref(), &[0u8; 100]].concat()).unwrap();
        let script = dir.join("tool");
        std::fs::write(&script, b"#!/bin/sh\n").unwrap();
        let cfg = dir.join("a.conf");
        std::fs::write(&cfg, b"x=1\n").unwrap();

        let file = |name: &str, path: &PathBuf| Entry {
            name: name.to_string(),
            source: Source::File(path.clone()),
        };
        let entries = vec![
            file("/etc/a.conf", &cfg),
            file("/lib/prog", &elf),
            file("/etc/b.conf", &cfg),
            file("/sbin/tool", &script),
        ];
        let align = Align {
            bytes: 4096,
            executables: true,
            under: vec!["sbin".to_string()],
        };
        let archive = build(&entries, &Permissions::new(), &align).unwrap();

        // The executable and the entry under the declared directory start
        // their data on the declared boundary.
        let start = data_start(&archive, b"lib/prog");
        assert_eq!(start % 4096, 0);
        assert_eq!(&archive[start..start + 4], b"\x7fELF");
        assert_eq!(data_start(&archive, b"sbin/tool") % 4096, 0);

        // The filler entries are named under `.pad/`, the one name that is
        // not absolute.
        let parsed = parse(&archive).unwrap();
        assert!(parsed.iter().any(|entry| entry.name.starts_with(PAD_PREFIX)));
        assert!(
            parsed
                .iter()
                .all(|entry| entry.name.starts_with('/') || entry.name.starts_with(PAD_PREFIX))
        );

        // Without a declaration only the format's four bytes apply.
        let plain = build(&entries, &Permissions::new(), &Align::default()).unwrap();
        assert!(!plain.windows(5).any(|w| w == b".pad/"));

        // Deterministic: same inputs, same bytes.
        assert_eq!(archive, build(&entries, &Permissions::new(), &align).unwrap());
        assert!(archive.windows(10).any(|w| w == b"TRAILER!!!"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn destinations_are_canonical_absolute_names() {
        assert_eq!(canonical_name("etc/fstab").unwrap(), "/etc/fstab");
        assert_eq!(canonical_name("/etc/fstab").unwrap(), "/etc/fstab");
        assert_eq!(canonical_name("//lib/./fluxd//system/").unwrap(), "/lib/fluxd/system");
        assert_eq!(canonical_name("/../sbin/x/../init").unwrap(), "/sbin/init");
        assert!(canonical_name("").is_err());
        assert!(canonical_name("/").is_err());
        assert!(canonical_name("a/..").is_err());
    }

    #[test]
    fn links_are_link_entries_and_names_are_unique() {
        let dir =
            std::env::temp_dir().join(format!("buildutil-cpio-link-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("tree")).unwrap();
        let program = dir.join("program");
        std::fs::write(&program, [b"\x7fELF".as_ref(), &[0u8; 60]].concat()).unwrap();
        std::fs::write(dir.join("tree/a.txt"), b"a").unwrap();
        // A source that is itself a link, and a link inside a directory
        // source: each is archived as a link to its own target.
        crate::platform::create_symlink_auto(Path::new("program"), &dir.join("alias")).unwrap();
        crate::platform::create_symlink_auto(Path::new("a.txt"), &dir.join("tree/b.txt")).unwrap();
        let manifest = dir.join("initramfs.manifest");
        std::fs::write(
            &manifest,
            "/sbin/fluxd=program\n\
             /sbin/init=@symlink:fluxd\n\
             /bin/sh=@symlink:/usr/bin/bash\n\
             etc/alias=alias\n\
             /tree=tree\n",
        )
        .unwrap();
        let entries = load_manifest(&manifest, None).unwrap();
        let names: Vec<&str> = entries.iter().map(|entry| entry.name.as_str()).collect();
        assert_eq!(
            names,
            ["/sbin/fluxd", "/sbin/init", "/bin/sh", "/etc/alias", "/tree/a.txt", "/tree/b.txt"]
        );
        assert_eq!(entries[1].source, Source::Symlink("fluxd".to_string()));
        assert_eq!(entries[3].source, Source::Symlink("program".to_string()));
        assert_eq!(entries[5].source, Source::Symlink("a.txt".to_string()));

        let align = Align { bytes: 4096, executables: true, under: Vec::new() };
        let archive = build(&entries, &Permissions::new(), &align).unwrap();
        let parsed = parse(&archive).unwrap();
        let init = parsed.iter().find(|entry| entry.name == "/sbin/init").unwrap();
        assert_eq!(init.mode, MODE_SYMLINK | 0o777);
        assert_eq!(&archive[init.data_offset..init.data_offset + init.size as usize], b"fluxd");
        let fluxd = parsed.iter().find(|entry| entry.name == "/sbin/fluxd").unwrap();
        assert_eq!(fluxd.mode, MODE_REGULAR | 0o644);
        assert_eq!(fluxd.data_offset % 4096, 0);

        // The same path twice, however it is spelled, is refused across
        // every source of the archive.
        let mut doubled = entries.clone();
        doubled.extend(line_entries("sbin//init", "@symlink:other", |_| None).unwrap());
        assert!(build(&doubled, &Permissions::new(), &Align::default()).is_err());
        std::fs::write(dir.join("dup.manifest"), "/etc/x=program\netc/x=program\n").unwrap();
        let dup = load_manifest(&dir.join("dup.manifest"), None).unwrap();
        assert!(build(&dup, &Permissions::new(), &Align::default()).is_err());

        // An empty link target, an empty or root destination and a line
        // without a source are refused.
        assert!(line_entries("/sbin/init", "@symlink:", |_| None).is_err());
        assert!(line_entries("/", "@symlink:fluxd", |_| None).is_err());
        assert!(line_entries("", "@symlink:fluxd", |_| None).is_err());
        std::fs::write(dir.join("bad.manifest"), "/etc/x\n").unwrap();
        assert!(load_manifest(&dir.join("bad.manifest"), None).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_alignment_and_its_selection_are_declared_together() {
        let words = |text: &str| text.split_whitespace().map(str::to_string).collect::<Vec<_>>();
        let parse = |text: &str| -> Result<Align, String> {
            let args = words(text);
            let mut align = Align::default();
            let mut i = 0;
            while i < args.len() {
                if !align.take(&args, &mut i)? {
                    return Err(format!("not an alignment option: {}", args[i]));
                }
                i += 1;
            }
            align.validate()?;
            Ok(align)
        };
        let align = parse("--align 4096 --align-executables --align-under /bin/").unwrap();
        assert_eq!(align.under, ["bin"]);
        assert!(align.selects("/bin/sh", b"#!"));
        assert!(!align.selects("/binary", b"#!"));
        assert!(parse("--align 4096").is_err());
        assert!(parse("--align-executables").is_err());
        assert!(parse("--align 3000 --align-executables").is_err());
        assert!(parse("").is_ok());
    }

    #[test]
    fn manifest_directory_sources_expand_in_sorted_order() {
        let dir =
            std::env::temp_dir().join(format!(
                "buildutil-cpio-manifest-test-{}",
                std::process::id()
            ));
        let _ = std::fs::remove_dir_all(&dir);
        let services = dir.join("services");
        std::fs::create_dir_all(services.join("sub")).unwrap();
        std::fs::write(services.join("b.txt"), b"b").unwrap();
        std::fs::write(services.join("a.txt"), b"a").unwrap();
        std::fs::write(services.join("sub/c.txt"), b"c").unwrap();
        let after = dir.join("after.txt");
        std::fs::write(&after, b"after").unwrap();
        let manifest = dir.join("initramfs.manifest");
        std::fs::write(
            &manifest,
            format!("/svc={}\n/after={}\n", services.display(), after.display()),
        )
        .unwrap();

        let entries = load_manifest(&manifest, None).unwrap();
        assert_eq!(
            entries
                .iter()
                .map(|entry| entry.name.as_str())
                .collect::<Vec<_>>(),
            vec!["/svc/a.txt", "/svc/b.txt", "/svc/sub/c.txt", "/after"]
        );
        assert_eq!(entries[3].source, Source::File(after.clone()));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn manifest_directory_order_is_per_directory_depth_first() {
        let dir = std::env::temp_dir().join(format!(
            "buildutil-cpio-manifest-order-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let tree = dir.join("tree");
        std::fs::create_dir_all(tree.join("sub")).unwrap();
        std::fs::write(tree.join("sub/c.txt"), b"c").unwrap();
        std::fs::write(tree.join("sub.txt"), b"s").unwrap();
        let manifest = dir.join("initramfs.manifest");
        std::fs::write(&manifest, format!("/svc={}\n", tree.display())).unwrap();

        let entries = load_manifest(&manifest, None).unwrap();
        assert_eq!(
            entries
                .iter()
                .map(|entry| entry.name.as_str())
                .collect::<Vec<_>>(),
            vec!["/svc/sub/c.txt", "/svc/sub.txt"]
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
