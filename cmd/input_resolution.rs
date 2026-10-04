// SPDX-License-Identifier: GPL-2.0-only
//! Repository input resolution, development state, and atomic release locks.

use crate::inputs::{codec, content};
use codec::{Declaration, Entry, Lock};
use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static TEMP_SEQ: AtomicU64 = AtomicU64::new(0);

/// Acquisition uses declared fixed-output tools; an update captures the archive pin
/// before its content is verified and any lock is published.
pub(crate) trait Acquisition {
    fn archive(&mut self, url: &str, sha256: Option<&str>) -> Result<(PathBuf, String), String>;
}

/// An input's captured execution tree and checkout provenance.
#[derive(Clone, Debug)]
pub(crate) struct Resolved {
    pub(crate) path: String,
    pub(crate) root: PathBuf,
    pub(crate) content: String,
    pub(crate) rev: String,
    pub(crate) dirty: bool,
    pub(crate) ahead: bool,
    pub(crate) declaration: Declaration,
    pub(crate) entry: Option<Entry>,
    pub(crate) inputs: BTreeMap<String, String>,
    excluded: Vec<String>,
    checkout: bool,
}

/// Captured nodes keyed by descriptive input paths, with shared root nodes reused.
#[derive(Clone, Debug, Default)]
pub(crate) struct Resolution {
    pub(crate) inputs: BTreeMap<String, String>,
    pub(crate) nodes: BTreeMap<String, Resolved>,
    root: PathBuf,
    declarations: BTreeMap<String, Declaration>,
}

impl Resolution {
    pub(crate) fn report(&self) -> Vec<String> {
        self.nodes
            .iter()
            .map(|(name, input)| {
                format!(
                    "{name}: {}{}",
                    if input.dirty {
                        "dirty".to_string()
                    } else {
                        format!("clean@{}", input.rev)
                    },
                    if input.ahead { ", ahead of lock" } else { "" }
                )
            })
            .collect()
    }

    /// Fresh reads catch checkout or selection changes, including untracked paths.
    pub(crate) fn revalidate(&self, updating: bool) -> Result<(), String> {
        if codec::declarations(&crate::input_toml::parse_file(
            &self.root.join("buildutil.toml"),
        )?)? != self.declarations
        {
            return Err("root input declarations changed during capture".into());
        }
        for (name, input) in &self.nodes {
            let content = format!(
                "tree:{}",
                content::capture(&input.root, &input.excluded)?.hash()
            );
            if content != input.content {
                return Err(format!("input `{name}` changed after capture"));
            }
            if input.checkout {
                let (rev, dirty) = checkout_state(&input.root)?;
                if rev != input.rev || dirty != input.dirty || (updating && dirty) {
                    return Err(format!(
                        "input `{name}` changed its checkout state during capture"
                    ));
                }
            }
        }
        Ok(())
    }

    fn lock(&self) -> Result<Lock, String> {
        let mut lock = Lock {
            inputs: self.inputs.clone(),
            entries: BTreeMap::new(),
        };
        for (name, input) in &self.nodes {
            let mut entry = input
                .entry
                .clone()
                .ok_or_else(|| format!("lock: input `{name}` has no verified archive"))?;
            entry.inputs = input.inputs.clone();
            lock.entries.insert(name.clone(), entry);
        }
        lock.validate()?;
        Ok(lock)
    }
}

fn checkout_state(root: &Path) -> Result<(String, bool), String> {
    let run = |args: &[&str]| -> Result<String, String> {
        let output = crate::invocation::command("git")
            .arg("-C")
            .arg(root)
            .args(args)
            .output()
            .map_err(|e| format!("cannot inspect input checkout {}: {e}", root.display()))?;
        if !output.status.success() {
            return Err(format!(
                "cannot inspect input checkout {}: {}",
                root.display(),
                String::from_utf8_lossy(&output.stderr).trim()
            ));
        }
        String::from_utf8(output.stdout)
            .map(|s| s.trim().to_string())
            .map_err(|e| format!("invalid checkout state: {e}"))
    };
    let rev = run(&["rev-parse", "--verify", "HEAD"])?;
    if !(codec::hex(&rev, 40) || codec::hex(&rev, 64)) {
        return Err(format!(
            "input at {} has no full committed revision",
            root.display()
        ));
    }
    let dirty = !run(&["status", "--porcelain", "--untracked-files=all"])?.is_empty();
    Ok((rev, dirty))
}

fn declared_at(root: &Path, source: bool) -> Result<BTreeMap<String, Declaration>, String> {
    if source {
        return Ok(BTreeMap::new());
    }
    codec::declarations(&crate::input_toml::parse_file(
        &root.join("buildutil.toml"),
    )?)
}

fn selected(
    root: &Path,
    declarations: &BTreeMap<String, Declaration>,
) -> Result<(String, Vec<String>), String> {
    let excluded = declarations
        .values()
        .filter_map(|input| input.path.clone())
        .collect::<Vec<_>>();
    let hash = crate::source::ingest_repository(root, &excluded)?;
    let content = format!("tree:{hash}");
    Ok((content, excluded))
}

fn validate_captured_declarations(
    root: &Path,
    content: &str,
    source: bool,
    declarations: &BTreeMap<String, Declaration>,
) -> Result<(), String> {
    if !source {
        let bytes = crate::source::input_file(content, "buildutil.toml")?;
        let text = String::from_utf8(bytes)
            .map_err(|e| format!("captured input specification is not UTF-8: {e}"))?;
        let captured = codec::declarations(&crate::input_toml::parse(
            &root.join("buildutil.toml"),
            &text,
        )?)?;
        if captured != *declarations {
            return Err(format!(
                "input specification {} changed during capture",
                root.display()
            ));
        }
    }
    Ok(())
}

struct Resolver<'a, A> {
    root: &'a Path,
    state_root: &'a Path,
    declarations: BTreeMap<String, Declaration>,
    lock: Option<Lock>,
    overrides: BTreeMap<String, PathBuf>,
    used_overrides: BTreeSet<String>,
    visiting: BTreeSet<String>,
    result: Resolution,
    acquisition: &'a mut A,
    locked: bool,
    updating: bool,
}

impl<A: Acquisition> Resolver<'_, A> {
    fn resolve(
        &mut self,
        owner: &Path,
        path: &str,
        declaration: &Declaration,
        locked_name: Option<&str>,
    ) -> Result<String, String> {
        if let Some((root_name, root_declaration)) = self
            .declarations
            .iter()
            .find(|(_, input)| input.url == declaration.url)
        {
            let root_name = root_name.clone();
            let root_declaration = root_declaration.clone();
            if root_name != path {
                codec::minimum(&root_declaration, declaration, path)?;
                if self.overrides.contains_key(path) {
                    return Err(format!(
                        "--override-input `{path}` is a shared edge; override root input `{root_name}` instead"
                    ));
                }
                let locked_root = self
                    .lock
                    .as_ref()
                    .and_then(|lock| lock.inputs.get(&root_name))
                    .cloned();
                if self.locked && locked_name != locked_root.as_deref() {
                    return Err(format!(
                        "--locked: shared input `{path}` must name root input `{root_name}`'s buildutil.lock entry"
                    ));
                }
                return self.resolve(
                    self.root,
                    &root_name,
                    &root_declaration,
                    locked_root.as_deref(),
                );
            }
        }
        if let Some(existing) = self.result.nodes.get(&lock_name(path)) {
            if existing.path != path {
                return Err(format!("ambiguous input entry name `{}`", lock_name(path)));
            }
            return Ok(lock_name(path));
        }
        if !self.visiting.insert(path.to_string()) {
            return Err(format!("repository input cycle through `{path}`"));
        }
        let old = locked_name
            .and_then(|name| self.lock.as_ref().and_then(|lock| lock.entries.get(name)))
            .cloned();
        if self.overrides.contains_key(path) {
            self.used_overrides.insert(path.to_string());
        }
        let checkout = self.checkout(owner, path, declaration)?;
        let (root, rev, dirty, is_checkout) = match checkout {
            Some(root) => {
                let (rev, dirty) = checkout_state(&root)?;
                (root, rev, dirty, true)
            }
            None => {
                let entry = old.as_ref().ok_or_else(|| {
                    format!("input `{path}` has neither a checkout nor an entry in buildutil.lock")
                })?;
                let root = self.fetch(path, entry)?;
                (root, entry.rev.clone(), false, false)
            }
        };
        if self.updating && dirty {
            return Err(format!(
                "lock: refusing dirty input `{path}`; buildutil.lock was not changed"
            ));
        }
        let nested = declared_at(&root, declaration.source)?;
        let (content, excluded) = selected(&root, &nested)?;
        validate_captured_declarations(&root, &content, declaration.source, &nested)?;
        if !is_checkout && old.as_ref().is_some_and(|entry| entry.content != content) {
            return Err(format!(
                "buildutil.lock [input.{}]: fetched content differs from content pin",
                locked_name.unwrap_or(path)
            ));
        }
        let ahead = old.as_ref().is_none_or(|entry| entry.content != content);
        if self.locked && ahead {
            return Err(format!(
                "--locked: input `{path}` differs from or has no buildutil.lock [input.{}] entry (selected {content})",
                locked_name.unwrap_or(path)
            ));
        }
        let mut entry = old.clone();
        if self.updating && is_checkout {
            let url = if declaration.url.contains("{rev}") {
                declaration.url.replace("{rev}", &rev)
            } else if let Some(old) = old.as_ref().filter(|old| old.rev == rev) {
                old.url.clone()
            } else {
                declaration.url.clone()
            };
            let subdir = declaration
                .subdir
                .as_ref()
                .map(|value| value.replace("{rev}", &rev));
            let pin = old
                .as_ref()
                .filter(|old| old.rev == rev && old.url == url)
                .map(|old| old.sha256.as_str());
            let (archive, sha256) = self.acquisition.archive(&url, pin)?;
            let candidate = Entry {
                url,
                rev: rev.clone(),
                sha256,
                subdir,
                content: content.clone(),
                inputs: BTreeMap::new(),
            };
            let fetched_root = self.unpack(path, &archive, &candidate)?;
            let fetched_declarations = declared_at(&fetched_root, declaration.source)?;
            let (fetched_content, _) = selected(&fetched_root, &fetched_declarations)?;
            validate_captured_declarations(
                &fetched_root,
                &fetched_content,
                declaration.source,
                &fetched_declarations,
            )?;
            if fetched_content != content {
                return Err(format!(
                    "lock: input `{path}` archive content differs from checkout; buildutil.lock was not changed"
                ));
            }
            entry = Some(candidate);
        }
        let mut edges = BTreeMap::new();
        for (local, nested_declaration) in &nested {
            let nested_path = format!("{path}/{local}");
            let nested_lock = old.as_ref().and_then(|entry| entry.inputs.get(local));
            let target = self.resolve(
                &root,
                &nested_path,
                nested_declaration,
                nested_lock.map(String::as_str),
            )?;
            edges.insert(local.clone(), target);
        }
        let key = lock_name(path);
        if self.result.nodes.contains_key(&key) {
            return Err(format!("ambiguous resolved input name `{key}`"));
        }
        self.result.nodes.insert(
            key.clone(),
            Resolved {
                path: path.to_string(),
                root,
                content,
                rev,
                dirty,
                ahead,
                declaration: declaration.clone(),
                entry,
                inputs: edges,
                excluded,
                checkout: is_checkout,
            },
        );
        self.visiting.remove(path);
        Ok(key)
    }

    fn checkout(
        &self,
        owner: &Path,
        path: &str,
        declaration: &Declaration,
    ) -> Result<Option<PathBuf>, String> {
        let override_path = self.overrides.get(path).cloned();
        let checkout = match override_path {
            Some(pathbuf) => Some(pathbuf.canonicalize().map_err(|e| {
                format!(
                    "--override-input {path}: cannot open {}: {e}",
                    pathbuf.display()
                )
            })?),
            None => match &declaration.path {
                Some(relative) => {
                    let candidate = owner.join(relative);
                    match std::fs::symlink_metadata(&candidate) {
                        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
                        Err(e) => return Err(format!("input `{path}` is unreadable: {e}")),
                        Ok(meta)
                            if meta.is_dir()
                                && !candidate.join(".git").exists()
                                && std::fs::read_dir(&candidate)
                                    .map_err(|e| format!("input `{path}` is unreadable: {e}"))?
                                    .next()
                                    .is_none() =>
                        {
                            None
                        }
                        Ok(_) => {
                            let canonical = candidate
                                .canonicalize()
                                .map_err(|e| format!("input `{path}` is unreadable: {e}"))?;
                            let owner = owner
                                .canonicalize()
                                .map_err(|e| format!("input owner is unreadable: {e}"))?;
                            if !canonical.starts_with(owner) {
                                return Err(format!(
                                    "input `{path}` checkout path escapes its declaring repository; use --override-input"
                                ));
                            }
                            Some(canonical)
                        }
                    }
                }
                None => None,
            },
        };
        if let Some(checkout) = &checkout {
            if !checkout.is_dir() || std::fs::symlink_metadata(checkout.join(".git")).is_err() {
                return Err(format!(
                    "input `{path}` is present but is not a readable repository checkout: {}",
                    checkout.display()
                ));
            }
        }
        Ok(checkout)
    }

    fn preflight(
        &self,
        owner: &Path,
        path: &str,
        declaration: &Declaration,
        locked_name: Option<&str>,
        active: &mut BTreeSet<String>,
        done: &mut BTreeSet<String>,
    ) -> Result<(), String> {
        if let Some((root_name, root_declaration)) = self
            .declarations
            .iter()
            .find(|(_, input)| input.url == declaration.url)
        {
            if root_name != path {
                codec::minimum(root_declaration, declaration, path)?;
                if self.overrides.contains_key(path) {
                    return Err(format!(
                        "--override-input `{path}` is a shared edge; override root input `{root_name}` instead"
                    ));
                }
                let root_entry = self
                    .lock
                    .as_ref()
                    .and_then(|lock| lock.inputs.get(root_name));
                if self.locked && locked_name != root_entry.map(String::as_str) {
                    return Err(format!(
                        "--locked: shared input `{path}` must name root input `{root_name}`'s buildutil.lock entry"
                    ));
                }
                return self.preflight(
                    self.root,
                    root_name,
                    root_declaration,
                    root_entry.map(String::as_str),
                    active,
                    done,
                );
            }
        }
        if done.contains(path) {
            return Ok(());
        }
        if !active.insert(path.to_string()) {
            return Err(format!("repository input cycle through `{path}`"));
        }
        let old =
            locked_name.and_then(|name| self.lock.as_ref().and_then(|lock| lock.entries.get(name)));
        if let Some(root) = self.checkout(owner, path, declaration)? {
            let (_, dirty) = checkout_state(&root)?;
            if self.updating && dirty {
                return Err(format!(
                    "lock: refusing dirty input `{path}`; buildutil.lock was not changed"
                ));
            }
            let nested = declared_at(&root, declaration.source)?;
            let (content, _) = selected(&root, &nested)?;
            validate_captured_declarations(&root, &content, declaration.source, &nested)?;
            if self.locked && old.is_none_or(|entry| entry.content != content) {
                return Err(format!(
                    "--locked: input `{path}` differs from or has no buildutil.lock [input.{}] entry",
                    locked_name.unwrap_or(path)
                ));
            }
            for (local, child) in &nested {
                self.preflight(
                    &root,
                    &format!("{path}/{local}"),
                    child,
                    old.and_then(|entry| entry.inputs.get(local))
                        .map(String::as_str),
                    active,
                    done,
                )?;
            }
        } else if old.is_none() {
            return Err(format!(
                "input `{path}` has neither a checkout nor an entry in buildutil.lock"
            ));
        }
        active.remove(path);
        done.insert(path.to_string());
        Ok(())
    }

    fn fetch(&mut self, name: &str, entry: &Entry) -> Result<PathBuf, String> {
        let (archive, pin) = self.acquisition.archive(&entry.url, Some(&entry.sha256))?;
        if pin != entry.sha256 {
            return Err(format!(
                "buildutil.lock [input.{name}]: archive checksum differs"
            ));
        }
        self.unpack(name, &archive, entry)
    }

    fn unpack(&self, name: &str, archive: &Path, entry: &Entry) -> Result<PathBuf, String> {
        let actual = content::file(archive)?.0;
        if actual != entry.sha256 {
            return Err(format!(
                "buildutil.lock [input.{name}]: archive sha256 mismatch"
            ));
        }
        let seq = TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
        let unpack = self.state_root.join("sources/input-unpack").join(format!(
            "{}-{}-{seq}",
            entry.sha256,
            std::process::id()
        ));
        // Extract into a new private directory; a warm, mutable extraction is
        // never taken as evidence of an archive pin.
        crate::exec::untar::extract(archive, &unpack)?;
        if content::file(archive)?.0 != entry.sha256 {
            return Err(format!(
                "buildutil.lock [input.{name}]: archive changed during extraction"
            ));
        }
        let selected = match &entry.subdir {
            Some(path) => {
                codec::clean_path(path)?;
                unpack.join(path)
            }
            None => unpack.clone(),
        };
        let canonical = selected
            .canonicalize()
            .map_err(|e| format!("input `{name}` archive root is unreadable: {e}"))?;
        if !canonical.starts_with(unpack.canonicalize().map_err(|e| e.to_string())?) {
            return Err(format!(
                "input `{name}` archive subdir escapes its extraction"
            ));
        }
        Ok(canonical)
    }
}

fn lock_name(path: &str) -> String {
    path.replace('/', "--")
}

/// Resolve every declared edge before a consumer or generator can execute.
pub(crate) fn resolve<A: Acquisition>(
    root: &Path,
    state_root: &Path,
    overrides: &[(String, PathBuf)],
    locked: bool,
    updating: bool,
    acquisition: &mut A,
) -> Result<Resolution, String> {
    let declarations = codec::declarations(&crate::input_toml::parse_file(
        &root.join("buildutil.toml"),
    )?)?;
    let lock = Lock::read(&root.join("buildutil.lock"))?;
    let mut override_map = BTreeMap::new();
    for (path, checkout) in overrides {
        for part in path.split('/') {
            codec::name(part)?;
        }
        if override_map
            .insert(path.clone(), checkout.clone())
            .is_some()
        {
            return Err(format!("duplicate --override-input `{path}`"));
        }
    }
    let mut resolver = Resolver {
        root,
        state_root,
        declarations: declarations.clone(),
        lock,
        overrides: override_map,
        used_overrides: BTreeSet::new(),
        visiting: BTreeSet::new(),
        result: Resolution {
            root: root.to_path_buf(),
            declarations: declarations.clone(),
            ..Resolution::default()
        },
        acquisition,
        locked,
        updating,
    };
    let mut active = BTreeSet::new();
    let mut done = BTreeSet::new();
    for (name, declaration) in &declarations {
        let locked_name = resolver
            .lock
            .as_ref()
            .and_then(|lock| lock.inputs.get(name));
        if locked && locked_name.is_none() {
            return Err(format!(
                "--locked: no buildutil.lock entry for root input `{name}`"
            ));
        }
        resolver.preflight(
            root,
            name,
            declaration,
            locked_name.map(String::as_str),
            &mut active,
            &mut done,
        )?;
    }
    for (name, declaration) in &declarations {
        let locked_name = resolver
            .lock
            .as_ref()
            .and_then(|lock| lock.inputs.get(name))
            .cloned();
        let target = resolver.resolve(root, name, declaration, locked_name.as_deref())?;
        resolver.result.inputs.insert(name.clone(), target);
    }
    if let Some(unknown) = resolver
        .overrides
        .keys()
        .find(|name| !resolver.used_overrides.contains(*name))
    {
        return Err(format!("--override-input names unknown input `{unknown}`"));
    }
    resolver.result.revalidate(updating)?;
    Ok(resolver.result)
}

/// Replace the complete lock only after graph, archive, and checkout validation.
pub(crate) fn update(root: &Path, resolution: &Resolution) -> Result<(), String> {
    let text = resolution.lock()?.render()?;
    resolution.revalidate(true)?;
    let path = root.join("buildutil.lock");
    let seq = TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
    let temp = root.join(format!(".buildutil.lock.tmp-{}-{seq}", std::process::id()));
    let mut created = false;
    let result = (|| {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp)
            .map_err(|e| format!("cannot create lock replacement: {e}"))?;
        created = true;
        file.write_all(text.as_bytes())
            .and_then(|_| file.sync_all())
            .map_err(|e| format!("cannot write lock replacement: {e}"))?;
        resolution.revalidate(true)?;
        drop(file);
        std::fs::rename(&temp, &path)
            .map_err(|e| format!("cannot atomically replace {}: {e}", path.display()))
    })();
    if result.is_err() && created {
        let _ = std::fs::remove_file(temp);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Archive {
        file: PathBuf,
        calls: usize,
    }

    impl Acquisition for Archive {
        fn archive(&mut self, _url: &str, pin: Option<&str>) -> Result<(PathBuf, String), String> {
            self.calls += 1;
            let sha = content::file(&self.file)?.0;
            if pin.is_some_and(|pin| pin != sha) {
                return Err("archive pin mismatch".into());
            }
            Ok((self.file.clone(), sha))
        }
    }

    fn git(root: &Path, args: &[&str]) -> bool {
        std::process::Command::new("git")
            .arg("-C")
            .arg(root)
            .args(args)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .is_ok_and(|status| status.success())
    }

    fn fixture(tag: &str) -> Option<(PathBuf, PathBuf, Archive)> {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "buildutil-lock-{tag}-{}-{stamp}",
            std::process::id()
        ));
        let input = root.join("checkout");
        let state = root.join("state");
        std::fs::create_dir_all(&input).unwrap();
        std::fs::write(root.join("buildutil.toml"), "[input.library]\nkind = \"source\"\nurl = \"https://example.org/library/{rev}.tar.gz\"\npath = \"checkout\"\n").unwrap();
        if !git(&input, &["init"]) {
            std::fs::remove_dir_all(root).unwrap();
            return None;
        }
        assert!(git(&input, &["config", "user.name", "buildutil test"]));
        assert!(git(
            &input,
            &["config", "user.email", "buildutil-test@example.invalid"]
        ));
        for (file, bytes) in [
            ("lib.rs", "pub fn value() {}\n"),
            (".buildutilignore", "scratch\n"),
            ("scratch", "old\n"),
        ] {
            std::fs::write(input.join(file), bytes).unwrap();
        }
        assert!(git(&input, &["add", "-A"]));
        assert!(git(&input, &["commit", "--no-gpg-sign", "-m", "input"]));
        let mut tar = Vec::new();
        for file in ["lib.rs", ".buildutilignore", "scratch"] {
            let bytes = std::fs::read(input.join(file)).unwrap();
            let mut header = [0u8; 512];
            header[..file.len()].copy_from_slice(file.as_bytes());
            header[100..108].copy_from_slice(b"0000644\0");
            header[108..116].copy_from_slice(b"0000000\0");
            header[116..124].copy_from_slice(b"0000000\0");
            header[124..136].copy_from_slice(format!("{:011o}\0", bytes.len()).as_bytes());
            header[136..148].copy_from_slice(b"00000000000\0");
            header[148..156].fill(b' ');
            header[156] = b'0';
            header[257..263].copy_from_slice(b"ustar\0");
            header[263..265].copy_from_slice(b"00");
            let sum: u32 = header.iter().map(|byte| u32::from(*byte)).sum();
            header[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
            tar.extend_from_slice(&header);
            tar.extend_from_slice(&bytes);
            tar.resize(tar.len().div_ceil(512) * 512, 0);
        }
        tar.resize(tar.len() + 1024, 0);
        let archive = root.join("archive.tar");
        std::fs::write(&archive, &tar).unwrap();
        crate::source::activate(&state).unwrap();
        let tree = format!(
            "tree:{}",
            crate::source::ingest_repository(&input, &[]).unwrap()
        );
        let rev = checkout_state(&input).unwrap().0;
        let entry = Entry {
            url: format!("https://example.org/library/{rev}.tar.gz"),
            rev,
            sha256: content::file(&archive).unwrap().0,
            subdir: None,
            content: tree,
            inputs: BTreeMap::new(),
        };
        let lock = Lock {
            inputs: BTreeMap::from([("library".into(), "library-pin".into())]),
            entries: BTreeMap::from([("library-pin".into(), entry)]),
        };
        std::fs::write(root.join("buildutil.lock"), lock.render().unwrap()).unwrap();
        Some((
            root,
            state,
            Archive {
                file: archive,
                calls: 0,
            },
        ))
    }

    #[test]
    fn dirty_lock_equal_selected_content_passes_but_lock_updates_refuse_it() {
        let _guard = crate::source::cas_test_guard();
        let Some((root, state, mut acquisition)) = fixture("dirty") else {
            return;
        };
        let before = std::fs::read(root.join("buildutil.lock")).unwrap();
        std::fs::write(root.join("checkout/scratch"), "unselected changes\n").unwrap();
        let resolved = resolve(&root, &state, &[], true, false, &mut acquisition).unwrap();
        assert!(resolved.nodes["library"].dirty);
        assert!(!resolved.nodes["library"].ahead);
        assert_eq!(resolved.report(), ["library: dirty"]);
        assert!(
            resolve(&root, &state, &[], false, true, &mut acquisition)
                .unwrap_err()
                .contains("refusing dirty input")
        );
        assert_eq!(acquisition.calls, 0);
        assert_eq!(std::fs::read(root.join("buildutil.lock")).unwrap(), before);
        std::fs::write(root.join("checkout/lib.rs"), "pub fn changed() {}\n").unwrap();
        assert!(
            resolve(&root, &state, &[], true, false, &mut acquisition)
                .unwrap_err()
                .contains("[input.library-pin]")
        );
        assert_eq!(
            std::fs::read_to_string(root.join("checkout/lib.rs")).unwrap(),
            "pub fn changed() {}\n"
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn absent_checkout_and_external_override_share_the_verified_content_pin() {
        let _guard = crate::source::cas_test_guard();
        let Some((root, state, mut acquisition)) = fixture("routes") else {
            return;
        };
        let pin = Lock::read(&root.join("buildutil.lock"))
            .unwrap()
            .unwrap()
            .entries["library-pin"]
            .content
            .clone();
        let external = root.join("external");
        std::fs::rename(root.join("checkout"), &external).unwrap();
        let fetched = resolve(&root, &state, &[], true, false, &mut acquisition).unwrap();
        assert_eq!(fetched.nodes["library"].content, pin);
        assert!(!fetched.nodes["library"].dirty);
        let overridden = resolve(
            &root,
            &state,
            &[("library".into(), external.clone())],
            true,
            false,
            &mut acquisition,
        )
        .unwrap();
        assert_eq!(overridden.nodes["library"].content, pin);
        let updating = resolve(&root, &state, &[], false, true, &mut acquisition).unwrap();
        update(&root, &updating).unwrap();
        assert_eq!(
            Lock::read(&root.join("buildutil.lock"))
                .unwrap()
                .unwrap()
                .entries["library"]
                .content,
            pin
        );
        assert!(
            !std::fs::read_to_string(root.join("buildutil.lock"))
                .unwrap()
                .contains(&external.to_string_lossy().to_string())
        );
        std::fs::remove_dir_all(root).unwrap();
    }
}
