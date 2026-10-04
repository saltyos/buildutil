//! SPDX-License-Identifier: GPL-2.0-only
//! buildutil — source content-addressed storage: git helpers

use std::collections::{BTreeMap, BTreeSet};
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

static REPO_PROBES: Mutex<Option<BTreeMap<PathBuf, RepoProbe>>> = Mutex::new(None);
static PREWARMED_ROUTES: Mutex<Option<BTreeMap<PathBuf, Option<CheckedGitTree>>>> =
    Mutex::new(None);

/// Nanoseconds spent building `RepoProbe`s (cache misses only) during the
/// current eval — the git-probe phase timer. Reset per eval via
/// `reset_probe_ns`; read by the eval loop and `--timings`.
static PROBE_NS: AtomicU64 = AtomicU64::new(0);
/// Wall-clock nanoseconds on the evaluation's critical path: one duration for
/// the whole parallel prewarm plus serial route revalidations. Unlike
/// `PROBE_NS`, concurrent workers are never added to this counter separately.
static PROBE_WALL_NS: AtomicU64 = AtomicU64::new(0);

/// Repository-local `git cat-file --batch --filters` probe results. Git may
/// fail a probe in one checkout without ruling out another checkout's route.
static FILTERS_SUPPORTED: Mutex<BTreeMap<PathBuf, Arc<OnceLock<bool>>>> =
    Mutex::new(BTreeMap::new());

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ProbeState {
    Safe,
    Unsafe,
    Unknown,
}

impl ProbeState {
    pub(crate) fn is_safe(self) -> bool {
        self == ProbeState::Safe
    }
}

#[derive(Clone)]
pub(crate) struct RepoProbe {
    pub toplevel: PathBuf,
    pub head_commit: Option<String>,
    pub head_tree: Option<String>,
    // Additional guards the toplevel object-db route evaluates precisely once
    // per repository. All are required to be true — any one false routes to the
    // filesystem walk. Gitlinks are checked independently at recursion sites.
    pub filemode_true: ProbeState,
    pub sparse_off: ProbeState,
    pub no_index_specials: ProbeState,
    pub no_custom_filter_attr: ProbeState,
    pub conversion_identity: ProbeState,
    pub conversion_state: Option<String>,
}

/// A git toplevel tree whose filesystem equivalence has been proven by the
/// shared guard set.
#[derive(Clone)]
pub(crate) struct CheckedGitTree {
    pub toplevel: PathBuf,
    pub tree_id: String,
    pub head_tree: String,
    pub repo_prefix: String,
    pub conversion_state: String,
}

/// A filesystem-equivalent Git tree plus the repo-relative paths whose
/// checked-out representation must replace the corresponding HEAD entries.
/// The baseline is content-addressed; only `changed` paths are read from the
/// worktree.
#[derive(Clone)]
pub(crate) struct CheckedHybridTree {
    pub checked: CheckedGitTree,
    pub changed: Vec<String>,
}

/// Returns `true` iff `git cat-file --batch --filters` accepts input
/// of the form `<oid> <repo-relative-path>` and emits filtered bytes. Cached
/// by repository toplevel; any failed probe disables this repository's route.
pub(crate) fn filtered_blob_reading_available(toplevel: &Path) -> bool {
    let result = FILTERS_SUPPORTED
        .lock()
        .expect("filters probe lock")
        .entry(toplevel.to_path_buf())
        .or_insert_with(|| Arc::new(OnceLock::new()))
        .clone();
    *result.get_or_init(|| {
        crate::invocation::command("git")
            .arg("-C")
            .arg(toplevel)
            .args(["cat-file", "--batch", "--filters"])
            .stdin(crate::invocation::Io::Null)
            .stdout(crate::invocation::Io::Null)
            .stderr(crate::invocation::Io::Null)
            .status()
            .map(|status| status.success())
            .unwrap_or(false)
    })
}

pub(crate) fn git_output(dir: &Path, args: &[&str]) -> Option<String> {
    let output = crate::invocation::command("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    Some(
        String::from_utf8(output.stdout)
            .ok()?
            .trim_end_matches(['\r', '\n'])
            .to_string(),
    )
}

/// Resolve every effective attribute for every tracked path and hash that
/// semantic result together with the Git configuration that affects built-in
/// worktree conversion. This incorporates attributes from the full hierarchy,
/// `.git/info/attributes`, and global/system attribute files because
/// `check-attr` performs Git's normal resolution. Any command or parse failure
/// is `Unknown`, which is never object-db-safe.
fn probe_conversion_state(toplevel: &Path) -> (ProbeState, ProbeState, Option<String>) {
    let mut ls_command = crate::invocation::command("git");
    ls_command.arg("-C").arg(toplevel).args(["ls-files", "-z"]);
    let Ok(ls) = ls_command.stderr(crate::invocation::Io::Null).output() else {
        return (ProbeState::Unknown, ProbeState::Unknown, None);
    };
    if !ls.status.success() {
        return (ProbeState::Unknown, ProbeState::Unknown, None);
    }
    if !ls.stdout.is_empty() && ls.stdout.last() != Some(&0) {
        return (ProbeState::Unknown, ProbeState::Unknown, None);
    }
    let Ok(mut child) = crate::invocation::command("git")
        .arg("-C")
        .arg(toplevel)
        .args(["check-attr", "-z", "--stdin", "--all"])
        .stdin(crate::invocation::Io::Piped)
        .stdout(crate::invocation::Io::Piped)
        .stderr(crate::invocation::Io::Null)
        .spawn()
    else {
        return (ProbeState::Unknown, ProbeState::Unknown, None);
    };
    let Some(mut stdin) = child.stdin.take() else {
        return (ProbeState::Unknown, ProbeState::Unknown, None);
    };
    // Feed the (potentially multi-MB) path list on a separate thread so a full
    // stdin pipe cannot deadlock against our stdout read.
    let paths = ls.stdout;
    let paths_for_writer = paths.clone();
    let writer = std::thread::spawn(move || stdin.write_all(&paths_for_writer));
    let output = child.wait_with_output();
    let wrote = writer.join();
    let Ok(output) = output else {
        return (ProbeState::Unknown, ProbeState::Unknown, None);
    };
    if !matches!(wrote, Ok(Ok(()))) || !output.status.success() {
        return (ProbeState::Unknown, ProbeState::Unknown, None);
    }
    if !output.stdout.is_empty() && output.stdout.last() != Some(&0) {
        return (ProbeState::Unknown, ProbeState::Unknown, None);
    }

    let mut raw_fields: Vec<&[u8]> = output.stdout.split(|&b| b == 0).collect();
    if raw_fields.last() == Some(&&b""[..]) {
        raw_fields.pop();
    }
    if raw_fields.len() % 3 != 0 {
        return (ProbeState::Unknown, ProbeState::Unknown, None);
    }
    let mut attrs: Vec<(Vec<u8>, Vec<u8>, Vec<u8>)> = Vec::new();
    let mut custom_filter = false;
    let mut byte_transform = false;
    for fields in raw_fields.chunks_exact(3) {
        let (path, attr, value) = (fields[0], fields[1], fields[2]);
        if path.is_empty() || attr.is_empty() || value.is_empty() {
            return (ProbeState::Unknown, ProbeState::Unknown, None);
        }
        if attr == b"filter" && value != b"unspecified" && value != b"unset" {
            custom_filter = true;
        }
        if matches!(
            attr,
            b"text" | b"crlf" | b"eol" | b"ident" | b"working-tree-encoding"
        ) && value != b"unspecified"
            && value != b"unset"
        {
            byte_transform = true;
        }
        attrs.push((path.to_vec(), attr.to_vec(), value.to_vec()));
    }
    attrs.sort();

    let mut tracked: Vec<Vec<u8>> = paths
        .split(|&b| b == 0)
        .filter(|field| !field.is_empty())
        .map(|field| field.to_vec())
        .collect();
    tracked.sort();

    let autocrlf = match git_config_value(toplevel, "core.autocrlf") {
        Ok(None) => b"false".to_vec(),
        Ok(Some(value)) if matches!(value.as_slice(), b"true" | b"false" | b"input") => value,
        _ => return (ProbeState::Unknown, ProbeState::Unknown, None),
    };
    let eol = match git_config_value(toplevel, "core.eol") {
        Ok(None) => b"native".to_vec(),
        Ok(Some(value)) if matches!(value.as_slice(), b"lf" | b"crlf" | b"native") => value,
        _ => return (ProbeState::Unknown, ProbeState::Unknown, None),
    };

    let mut h = crate::crypto::sha256::Sha256::new();
    h.update(b"buildutil-git-conversion-state-v1\0");
    hash_field(&mut h, &autocrlf);
    hash_field(&mut h, &eol);
    for path in tracked {
        hash_field(&mut h, &path);
    }
    h.update(b"\0attributes\0");
    for (path, attr, value) in attrs {
        hash_field(&mut h, &path);
        hash_field(&mut h, &attr);
        hash_field(&mut h, &value);
    }
    let custom_filter_state = if custom_filter {
        ProbeState::Unsafe
    } else {
        ProbeState::Safe
    };
    let conversion_identity = if autocrlf == b"false" && !byte_transform && !custom_filter {
        ProbeState::Safe
    } else {
        ProbeState::Unsafe
    };
    (
        custom_filter_state,
        conversion_identity,
        Some(h.finalize_hex()),
    )
}

fn hash_field(h: &mut crate::crypto::sha256::Sha256, bytes: &[u8]) {
    h.update(&(bytes.len() as u64).to_le_bytes());
    h.update(bytes);
}

/// `Ok(None)` is a normal missing key (git-config exit 1); every other
/// non-success and non-UTF-8 value is unknown rather than a default.
fn git_config_value(dir: &Path, key: &str) -> Result<Option<Vec<u8>>, ()> {
    let output = crate::invocation::command("git")
        .arg("-C")
        .arg(dir)
        .args(["config", "--get", key])
        .output()
        .map_err(|_| ())?;
    if output.status.success() {
        let mut value = output.stdout.as_slice();
        while matches!(value.last(), Some(b'\r' | b'\n')) {
            value = &value[..value.len() - 1];
        }
        let value = std::str::from_utf8(value)
            .map_err(|_| ())?
            .trim()
            .to_ascii_lowercase()
            .into_bytes();
        return if value.is_empty() {
            Err(())
        } else {
            Ok(Some(value))
        };
    }
    if output.status.code() == Some(1) {
        Ok(None)
    } else {
        Err(())
    }
}

fn git_success(dir: &Path, args: &[&str]) -> bool {
    crate::invocation::command("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .stdout(crate::invocation::Io::Null)
        .stderr(crate::invocation::Io::Null)
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

/// Host-verified bootstrap input content and its exact projection identity.
pub(crate) const CONTAINER_INPUT_CONTENT_ENV: &str = "BUILDUTIL_CONTAINER_INPUT_CONTENT";
pub(crate) const CONTAINER_BOOTSTRAP_HASH_ENV: &str = "BUILDUTIL_CONTAINER_BOOTSTRAP_HASH";

fn is_lower_hex(byte: u8) -> bool {
    matches!(byte, b'0'..=b'9' | b'a'..=b'f')
}

/// Validate the envelope of a repository-free bootstrap attestation.
/// The selected content is independently checked against the projected lock.
pub(crate) fn attested_bootstrap_content_from(
    pin: Option<&str>,
    hash: Option<&str>,
    repo_root: &Path,
) -> Result<Option<String>, String> {
    let (pin, hash) = match (pin, hash) {
        (None, None) => return Ok(None),
        (Some(_), None) | (None, Some(_)) => {
            return Err("buildutil: incomplete container input content attestation".to_string());
        }
        (Some(pin), Some(hash)) => (pin, hash),
    };
    if pin.len() != 64 || !pin.bytes().all(is_lower_hex) {
        return Err("buildutil: invalid container input content attestation".to_string());
    }
    if hash.len() != 32 || !hash.bytes().all(is_lower_hex) {
        return Err("buildutil: invalid container bootstrap hash attestation".to_string());
    }
    // A checkout establishes its own provenance; only an exact repository-free
    // projection may use the host's content attestation.
    if has_own_git_dir(repo_root) {
        return Err(
            "buildutil: container input content attestation present on a git checkout".to_string(),
        );
    }
    if repo_root.file_name().and_then(|name| name.to_str()) != Some(hash) {
        return Err(
            "buildutil: container input content attestation does not match projection identity"
                .to_string(),
        );
    }
    if !repo_root.join("buildutil.lock").is_file() || !repo_root.join("buildutil.toml").is_file() {
        return Err(
            "buildutil: attested container projection lacks buildutil.lock or its declarations"
                .to_string(),
        );
    }
    Ok(Some(pin.to_string()))
}

fn container_attested_bootstrap_content(repo_root: &Path) -> Result<Option<String>, String> {
    let pin = std::env::var(CONTAINER_INPUT_CONTENT_ENV).ok();
    let hash = std::env::var(CONTAINER_BOOTSTRAP_HASH_ENV).ok();
    attested_bootstrap_content_from(pin.as_deref(), hash.as_deref(), repo_root)
}

/// Env var carrying the host's repository identity into an evaluation of a
/// `.git`-less view of the same tree, where git cannot read it: `<rev>
/// <dirty>`, the `git-rev` and `git-dirty` the host's own plan records.
pub(crate) const CONTAINER_GIT_IDENTITY_ENV: &str = "BUILDUTIL_CONTAINER_GIT_IDENTITY";

/// Decide whether an evaluation may take the repository identity from an
/// attestation. Pure over its inputs, like `attested_bootstrap_content_from`, whose
/// conditions it shares: the identity is honored only where the projection
/// attestation holds.
///
/// - `Ok(None)` — no identity attestation; git reads the identity.
/// - `Ok(Some((rev, dirty)))` — a well-formed identity for an attested
///   projection.
/// - `Err(_)` — an identity without a holding projection attestation (a real
///   checkout among them), or a malformed one.
pub(crate) fn attested_identity_from(
    identity: Option<&str>,
    pin: Option<&str>,
    hash: Option<&str>,
    repo_root: &Path,
) -> Result<Option<(String, bool)>, String> {
    let Some(identity) = identity else {
        return Ok(None);
    };
    if attested_bootstrap_content_from(pin, hash, repo_root)?.is_none() {
        return Err(
            "buildutil: container git identity attestation without a projection attestation"
                .to_string(),
        );
    }
    let mut fields = identity.split(' ');
    let (Some(rev), Some(dirty), None) = (fields.next(), fields.next(), fields.next()) else {
        return Err("buildutil: invalid container git identity attestation".to_string());
    };
    if rev.is_empty() || !rev.bytes().all(|byte| byte.is_ascii_alphanumeric()) {
        return Err("buildutil: invalid container git identity attestation".to_string());
    }
    let dirty = match dirty {
        "true" => true,
        "false" => false,
        _ => return Err("buildutil: invalid container git identity attestation".to_string()),
    };
    Ok(Some((rev.to_string(), dirty)))
}

fn container_attested_identity(repo_root: &Path) -> Result<Option<(String, bool)>, String> {
    let identity = std::env::var(CONTAINER_GIT_IDENTITY_ENV).ok();
    let pin = std::env::var(CONTAINER_INPUT_CONTENT_ENV).ok();
    let hash = std::env::var(CONTAINER_BOOTSTRAP_HASH_ENV).ok();
    attested_identity_from(
        identity.as_deref(),
        pin.as_deref(),
        hash.as_deref(),
        repo_root,
    )
}

/// Compare selected bootstrap content with the lock, including inside projections.
pub(crate) fn verified_bootstrap_content(repo_root: &Path) -> Result<String, String> {
    let actual = crate::inputs::verify_bootstrap(repo_root)?;
    if let Some(pin) = container_attested_bootstrap_content(repo_root)? {
        if actual != pin {
            return Err(
                "buildutil: container input attestation differs from buildutil.lock content"
                    .to_string(),
            );
        }
    }
    Ok(actual)
}

fn build_repo_probe(toplevel: &Path) -> RepoProbe {
    let head_commit = git_output(toplevel, &["rev-parse", "HEAD"]);
    let head_tree = git_output(toplevel, &["rev-parse", "HEAD^{tree}"]);
    // Guard (c): `core.filemode=false` silently flips `100755`↔`100644`
    // bits in the working tree but `git status` stays quiet, which would
    // make `git_ls_tree`'s mode differ from what's on disk — unsafe for the
    // object-db fast path. Default is `true`; probe failure is conservatively
    // treated as not-true.
    let filemode_true = match git_config_value(toplevel, "core.filemode") {
        Ok(None) => ProbeState::Safe,
        Ok(Some(value)) if value == b"true" => ProbeState::Safe,
        Ok(Some(value)) if value == b"false" => ProbeState::Unsafe,
        _ => ProbeState::Unknown,
    };
    // Guard (b): sparse-checkout ON changes the bits present in the working
    // tree but not in the object db — the reverse of what we need. Detect it
    // via `core.sparseCheckout` (there is no `rev-parse --is-sparse-checkout`
    // flag; git would echo the unknown option back and mis-read as "on") plus
    // the presence of the sparse-checkout patterns file.
    let sparse_config_off = match git_config_value(toplevel, "core.sparsecheckout") {
        Ok(None) => ProbeState::Safe,
        Ok(Some(value)) if value == b"false" => ProbeState::Safe,
        Ok(Some(value)) if value == b"true" => ProbeState::Unsafe,
        _ => ProbeState::Unknown,
    };
    let sparse_file_off = match git_output(
        toplevel,
        &["rev-parse", "--git-path", "info/sparse-checkout"],
    ) {
        Some(path) => {
            let path = PathBuf::from(path);
            let path = if path.is_absolute() {
                path
            } else {
                toplevel.join(path)
            };
            if path.exists() {
                ProbeState::Unsafe
            } else {
                ProbeState::Safe
            }
        }
        None => ProbeState::Unknown,
    };
    let sparse_off = if sparse_config_off.is_safe() && sparse_file_off.is_safe() {
        ProbeState::Safe
    } else if sparse_config_off == ProbeState::Unsafe || sparse_file_off == ProbeState::Unsafe {
        ProbeState::Unsafe
    } else {
        ProbeState::Unknown
    };
    // Guard (d): `git ls-files -v` tags assume-unchanged (lowercase letter)
    // and skip-worktree (`S`) files. Both make the working tree diverge from
    // the object db without `git status` complaining. `true` here = "no
    // such paths", which lets the fast path run.
    let no_index_specials = match crate::invocation::command("git")
        .arg("-C")
        .arg(toplevel)
        .args(["ls-files", "-v", "-z"])
        .stderr(crate::invocation::Io::Null)
        .output()
    {
        Ok(output) if output.status.success() => {
            let mut state = ProbeState::Safe;
            if !output.stdout.is_empty() && output.stdout.last() != Some(&0) {
                state = ProbeState::Unknown;
            }
            for record in output.stdout.split(|&b| b == 0).filter(|r| !r.is_empty()) {
                if record.len() < 3 || record[1] != b' ' {
                    state = ProbeState::Unknown;
                    break;
                }
                let leading = record[0];
                if leading == b'S' || leading.is_ascii_lowercase() {
                    state = ProbeState::Unsafe;
                    break;
                }
                if !matches!(leading, b'H' | b'M' | b'R' | b'C' | b'K' | b'?') {
                    state = ProbeState::Unknown;
                    break;
                }
            }
            state
        }
        _ => ProbeState::Unknown,
    };
    let (no_custom_filter_attr, conversion_identity, conversion_state) =
        probe_conversion_state(toplevel);
    RepoProbe {
        toplevel: toplevel.to_path_buf(),
        head_commit,
        head_tree,
        filemode_true,
        sparse_off,
        no_index_specials,
        no_custom_filter_attr,
        conversion_identity,
        conversion_state,
    }
}

/// Resolve the enclosing git toplevel of `path` (canonical), or `None` when the
/// path is not under git. Cheap — a single `rev-parse --show-toplevel`.
pub(crate) fn toplevel_of(path: &Path) -> Option<PathBuf> {
    let path = path.canonicalize().ok()?;
    let toplevel = git_output(&path, &["rev-parse", "--show-toplevel"])?;
    PathBuf::from(toplevel).canonicalize().ok()
}

/// Warm exact repository roots plus subtrees of clean, pinned submodules.
/// Ordinary worktree subtrees remain filesystem-authoritative.
pub(crate) fn prewarm_probes(dirs: &[PathBuf]) {
    let wall = std::time::Instant::now();
    let mut routes: BTreeSet<PathBuf> = BTreeSet::new();
    let mut toplevels: BTreeSet<PathBuf> = BTreeSet::new();
    for dir in dirs {
        let Some(route) = dir.canonicalize().ok() else {
            continue;
        };
        if let Some(top) = toplevel_of(&route) {
            if !has_own_git_dir(&top) || (route != top && pinned_submodule_commit(&top).is_none()) {
                continue;
            }
            routes.insert(route);
            toplevels.insert(top);
        }
    }
    let toplevels: Vec<PathBuf> = toplevels.into_iter().collect();
    if !toplevels.is_empty() {
        let workers = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4)
            .min(toplevels.len());
        let next = AtomicUsize::new(0);
        std::thread::scope(|s| {
            for _ in 0..workers {
                s.spawn(|| {
                    loop {
                        let i = next.fetch_add(1, Ordering::Relaxed);
                        let Some(top) = toplevels.get(i) else {
                            break;
                        };
                        let _ = probe_for_mode(top, false);
                    }
                });
            }
        });
    }

    let route_results = Mutex::new(BTreeMap::new());
    let routes: Vec<PathBuf> = routes.into_iter().collect();
    if !routes.is_empty() {
        let workers = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4)
            .min(routes.len());
        let next = AtomicUsize::new(0);
        std::thread::scope(|s| {
            for _ in 0..workers {
                s.spawn(|| {
                    loop {
                        let i = next.fetch_add(1, Ordering::Relaxed);
                        let Some(route) = routes.get(i) else {
                            break;
                        };
                        let checked = checked_git_tree_candidate(route);
                        route_results
                            .lock()
                            .expect("prewarmed route lock")
                            .insert(route.clone(), checked);
                    }
                });
            }
        });
    }
    if let Some(cache) = PREWARMED_ROUTES
        .lock()
        .expect("prewarmed route lock")
        .as_mut()
    {
        cache.extend(route_results.into_inner().expect("prewarmed route lock"));
    }
    PROBE_WALL_NS.fetch_add(wall.elapsed().as_nanos() as u64, Ordering::Relaxed);
}

pub(crate) fn begin_repo_probe_eval() {
    *REPO_PROBES.lock().expect("repo probe lock") = Some(BTreeMap::new());
    *PREWARMED_ROUTES.lock().expect("prewarmed route lock") = Some(BTreeMap::new());
}

pub(crate) fn end_repo_probe_eval() {
    *REPO_PROBES.lock().expect("repo probe lock") = None;
    *PREWARMED_ROUTES.lock().expect("prewarmed route lock") = None;
}

pub(crate) fn probe_for(path: &Path) -> Option<RepoProbe> {
    probe_for_mode(path, true)
}

/// Repository identity used by `{git-rev}` / `{git-dirty}`. This intentionally
/// does not build a source-ingestion proof: the dirty token has always meant
/// tracked worktree/index changes only. `diff-index HEAD` is the single-command
/// equivalent of the previous worktree-vs-index plus index-vs-HEAD checks and
/// does not scan untracked or ignored source candidates. An attested
/// `.git`-less view of the tree carries the host's identity instead, which git
/// cannot read there; an identity attestation that does not hold is not
/// honored.
pub(crate) fn identity_for(path: &Path) -> Option<(String, bool)> {
    if let Ok(Some(identity)) = container_attested_identity(path) {
        return Some(identity);
    }
    let toplevel = toplevel_of(path)?;
    let rev = git_output(&toplevel, &["rev-parse", "--short=12", "HEAD"])
        .unwrap_or_else(|| "unknown".to_string());
    let dirty = !git_success(&toplevel, &["diff-index", "--quiet", "HEAD", "--"]);
    Some((rev, dirty))
}

fn probe_for_mode(path: &Path, count_wall: bool) -> Option<RepoProbe> {
    let toplevel = toplevel_of(path)?;
    {
        let mut probes = REPO_PROBES.lock().expect("repo probe lock");
        let probes = probes.get_or_insert_with(BTreeMap::new);
        if let Some(probe) = probes.get(&toplevel) {
            return Some(probe.clone());
        }
    }
    let t = std::time::Instant::now();
    let probe = build_repo_probe(&toplevel);
    let elapsed = t.elapsed().as_nanos() as u64;
    PROBE_NS.fetch_add(elapsed, Ordering::Relaxed);
    if count_wall {
        PROBE_WALL_NS.fetch_add(elapsed, Ordering::Relaxed);
    }
    let mut probes = REPO_PROBES.lock().expect("repo probe lock");
    let probes = probes.get_or_insert_with(BTreeMap::new);
    Some(probes.entry(toplevel).or_insert(probe).clone())
}

/// Git-probe phase time (ms) for the current eval — see `PROBE_NS`.
pub fn probe_ms() -> u128 {
    (PROBE_NS.load(Ordering::Relaxed) / 1_000_000) as u128
}

/// Git-probe critical-path wall time (parallel prewarm counted once).
pub fn probe_wall_ms() -> u128 {
    (PROBE_WALL_NS.load(Ordering::Relaxed) / 1_000_000) as u128
}

/// Zero the git-probe phase timer at the start of each eval.
pub(crate) fn reset_probe_ns() {
    PROBE_NS.store(0, Ordering::Relaxed);
    PROBE_WALL_NS.store(0, Ordering::Relaxed);
}

pub(crate) fn has_own_git_dir(path: &Path) -> bool {
    path.join(".git").exists()
}

#[cfg(test)]
pub(crate) fn clean_checkout_tree_id(path: &Path) -> Option<String> {
    let checked = checked_git_tree(path)?;
    checked.repo_prefix.is_empty().then_some(checked.tree_id)
}

/// Resolve the object-db tree for `path` only after the complete, shared guard
/// set proves that Git's filtered bytes and modes equal a filesystem walk.
/// Exact repository roots are eligible, as are subtrees of a checkout whose
/// HEAD exactly matches its superproject gitlink. An unsafe or unknown
/// observation is represented by `None` and must fall back to pure filesystem
/// ingestion.
#[cfg(test)]
pub(crate) fn checked_git_tree(path: &Path) -> Option<CheckedGitTree> {
    let filter = super::SourceFilter::load_for_walk(path).ok()?;
    let candidate = checked_git_tree_candidate(path)?;
    revalidate_checked_git_tree(path, &candidate, &filter, "")
}

fn checked_git_tree_candidate(path: &Path) -> Option<CheckedGitTree> {
    let path = path.canonicalize().ok()?;
    let probe = probe_for(&path)?;
    if !filtered_blob_reading_available(&probe.toplevel) {
        return None;
    }
    if !has_own_git_dir(&probe.toplevel) {
        return None;
    }
    if !probe.filemode_true.is_safe()
        || !probe.sparse_off.is_safe()
        || !probe.no_index_specials.is_safe()
        || !probe.no_custom_filter_attr.is_safe()
        || !probe.conversion_identity.is_safe()
    {
        return None;
    }
    let head_tree = probe.head_tree.clone()?;
    let repo_prefix = path
        .strip_prefix(&probe.toplevel)
        .ok()?
        .to_string_lossy()
        .replace('\\', "/");
    let tree_id = if repo_prefix.is_empty() {
        head_tree.clone()
    } else {
        // A normal source subtree remains worktree-authoritative. Only a
        // checkout whose HEAD is the superproject's exact gitlink target may
        // derive subtree identity from the object database.
        pinned_submodule_commit(&probe.toplevel)?;
        git_output(
            &probe.toplevel,
            &["rev-parse", &format!("HEAD:{repo_prefix}")],
        )?
    };
    Some(CheckedGitTree {
        toplevel: probe.toplevel,
        tree_id,
        head_tree,
        repo_prefix,
        conversion_state: probe.conversion_state?,
    })
}

/// Return a route proof for immediate object-db consumption. A prewarmed proof
/// is only a candidate: HEAD, route dirtiness, index flags, conversion state,
/// and nested checkout state are freshly checked here. Any changed or unknown
/// observation fails closed to the filesystem walk.
pub(crate) fn checked_git_tree_for_ingest(
    path: &Path,
    filter: &super::SourceFilter,
    entry_prefix: &str,
) -> Option<CheckedGitTree> {
    let canonical = path.canonicalize().ok()?;
    let warmed = PREWARMED_ROUTES
        .lock()
        .expect("prewarmed route lock")
        .as_ref()
        .and_then(|routes| routes.get(&canonical).cloned());
    let candidate = match warmed {
        Some(candidate) => candidate?,
        None => checked_git_tree_candidate(&canonical)?,
    };
    revalidate_checked_git_tree(&canonical, &candidate, filter, entry_prefix)
}

/// Resolve a dirty checkout as HEAD plus a file-level worktree overlay.  This
/// uses the same byte/mode guards as the clean object-db route; any ambiguity
/// declines to the existing full filesystem walk.
pub(crate) fn checked_hybrid_git_tree_for_ingest(
    path: &Path,
    filter: &super::SourceFilter,
    entry_prefix: &str,
) -> Option<CheckedHybridTree> {
    let path = path.canonicalize().ok()?;
    let toplevel = toplevel_of(&path)?;
    if !has_own_git_dir(&toplevel) || !filtered_blob_reading_available(&toplevel) {
        return None;
    }
    let probe = probe_for(&toplevel)?;
    if !probe.filemode_true.is_safe()
        || !probe.sparse_off.is_safe()
        || !probe.no_index_specials.is_safe()
        || !probe.no_custom_filter_attr.is_safe()
        || !probe.conversion_identity.is_safe()
    {
        return None;
    }
    let head_tree = git_output(&toplevel, &["rev-parse", "HEAD^{tree}"])?;
    let repo_prefix = path
        .strip_prefix(&toplevel)
        .ok()?
        .to_string_lossy()
        .replace('\\', "/");
    let tree_id = if repo_prefix.is_empty() {
        head_tree.clone()
    } else {
        git_output(&toplevel, &["rev-parse", &format!("HEAD:{repo_prefix}")])?
    };
    let conversion_state = probe.conversion_state?;
    let checked = CheckedGitTree {
        toplevel: toplevel.clone(),
        tree_id,
        head_tree,
        repo_prefix: repo_prefix.clone(),
        conversion_state,
    };
    let changed = hybrid_changed_paths(&toplevel, &repo_prefix, filter, entry_prefix)?;
    if changed.is_empty() {
        return None;
    }
    Some(CheckedHybridTree { checked, changed })
}

fn git_z_output(dir: &Path, args: &[&str], repo_prefix: &str) -> Option<Vec<Vec<u8>>> {
    let pathspec = if repo_prefix.is_empty() {
        ":(top)".to_string()
    } else {
        format!(":(top,literal){repo_prefix}")
    };
    let output = crate::invocation::command("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .args(["--", &pathspec])
        .stderr(crate::invocation::Io::Null)
        .output()
        .ok()?;
    if !output.status.success() || (!output.stdout.is_empty() && output.stdout.last() != Some(&0)) {
        return None;
    }
    Some(
        output
            .stdout
            .split(|&b| b == 0)
            .filter(|field| !field.is_empty())
            .map(ToOwned::to_owned)
            .collect(),
    )
}

pub(super) fn hybrid_changed_paths(
    toplevel: &Path,
    repo_prefix: &str,
    filter: &super::SourceFilter,
    entry_prefix: &str,
) -> Option<Vec<String>> {
    let mut repo_paths = BTreeSet::<Vec<u8>>::new();
    for args in [
        &[
            "diff",
            "--name-only",
            "-z",
            "--no-renames",
            "--ignore-submodules=none",
            "HEAD",
        ][..],
        &["ls-files", "--others", "--exclude-standard", "-z"][..],
        &[
            "ls-files",
            "--others",
            "--ignored",
            "--directory",
            "--exclude-standard",
            "-z",
        ][..],
    ] {
        repo_paths.extend(git_z_output(toplevel, args, repo_prefix)?);
    }

    let mut changed = BTreeSet::new();
    for raw in repo_paths {
        // Ignored directories arrive as a single path so excluded build state
        // is never enumerated file-by-file. Included directories are overlaid
        // through the filtered filesystem walk, preserving every source byte.
        let path = std::str::from_utf8(&raw).ok()?.trim_end_matches('/');
        let source_path = if repo_prefix.is_empty() {
            path
        } else if path == repo_prefix {
            ""
        } else if let Some(path) = path.strip_prefix(&format!("{repo_prefix}/")) {
            path
        } else {
            continue;
        };
        if source_path.is_empty() {
            // Git collapsed the selected root itself; the caller must walk
            // that root instead of accepting a partial HEAD overlay.
            return None;
        }
        let source_rel = super::tree::join_rel(entry_prefix, source_path);
        let fs_path = toplevel.join(path);
        let is_dir = std::fs::symlink_metadata(&fs_path)
            .map(|m| m.is_dir())
            .unwrap_or(false);
        if !filter.excludes_path_or_parent(&source_rel, is_dir) {
            changed.insert(source_path.to_string());
        }
    }

    // Keep only minimal overlay roots. Git reports both a dirty gitlink and,
    // in some layouts, descendants; replacing the parent once is sufficient.
    let mut minimal = Vec::new();
    for path in changed {
        if minimal
            .iter()
            .any(|parent: &String| path == *parent || path.starts_with(&format!("{parent}/")))
        {
            continue;
        }
        minimal.push(path);
    }
    Some(minimal)
}

fn revalidate_checked_git_tree(
    path: &Path,
    expected: &CheckedGitTree,
    filter: &super::SourceFilter,
    entry_prefix: &str,
) -> Option<CheckedGitTree> {
    let timer = std::time::Instant::now();
    let result = (|| {
        if !filtered_blob_reading_available(&expected.toplevel)
            || toplevel_of(path)? != expected.toplevel
        {
            return None;
        }
        if git_output(&expected.toplevel, &["rev-parse", "HEAD^{tree}"]).as_deref()
            != Some(expected.head_tree.as_str())
        {
            return None;
        }
        if expected.repo_prefix.is_empty() {
            if expected.tree_id != expected.head_tree {
                return None;
            }
        } else {
            pinned_submodule_commit(&expected.toplevel)?;
            if git_output(
                &expected.toplevel,
                &["rev-parse", &format!("HEAD:{}", expected.repo_prefix)],
            )
            .as_deref()
                != Some(expected.tree_id.as_str())
            {
                return None;
            }
        }
        if !route_status_clean(
            &expected.toplevel,
            &expected.repo_prefix,
            filter,
            entry_prefix,
        )
        .is_safe()
            || !route_index_specials_clear(&expected.toplevel).is_safe()
            || !route_submodules_clean(&expected.toplevel).is_safe()
            || !route_config_safe(&expected.toplevel).is_safe()
        {
            return None;
        }
        let (no_custom_filter, conversion_identity, conversion_state) =
            probe_conversion_state(&expected.toplevel);
        if !no_custom_filter.is_safe() || !conversion_identity.is_safe() {
            return None;
        }
        Some(CheckedGitTree {
            toplevel: expected.toplevel.clone(),
            tree_id: expected.tree_id.clone(),
            head_tree: expected.head_tree.clone(),
            repo_prefix: expected.repo_prefix.clone(),
            conversion_state: conversion_state?,
        })
    })();
    let elapsed = timer.elapsed().as_nanos() as u64;
    PROBE_NS.fetch_add(elapsed, Ordering::Relaxed);
    PROBE_WALL_NS.fetch_add(elapsed, Ordering::Relaxed);
    result
}

fn route_status_clean(
    toplevel: &Path,
    repo_prefix: &str,
    filter: &super::SourceFilter,
    entry_prefix: &str,
) -> ProbeState {
    let mut command = crate::invocation::command("git");
    command.arg("-C").arg(toplevel).args([
        "status",
        "--porcelain=v1",
        "-z",
        "--untracked-files=all",
        "--ignored=matching",
        "--ignore-submodules=none",
    ]);
    let Ok(output) = command.stderr(crate::invocation::Io::Null).output() else {
        return ProbeState::Unknown;
    };
    if !output.status.success() {
        return ProbeState::Unknown;
    }
    for record in output.stdout.split(|&b| b == 0).filter(|r| !r.is_empty()) {
        // Tracked and untracked changes are source bytes and always invalidate
        // HEAD. An ignored path is harmless only when the active source filter
        // excludes it, because then both the object-db and filesystem routes
        // omit it from the tree identity.
        let Some(path) = record.strip_prefix(b"!! ") else {
            return ProbeState::Unsafe;
        };
        let Ok(path) = std::str::from_utf8(path) else {
            return ProbeState::Unknown;
        };
        let is_dir = path.ends_with('/');
        let path = path.trim_end_matches('/');
        let source_path = if repo_prefix.is_empty() {
            path
        } else if path == repo_prefix {
            ""
        } else if let Some(path) = path.strip_prefix(&format!("{repo_prefix}/")) {
            path
        } else {
            // An ignored path outside the selected subtree cannot enter this
            // source tree. Tracked/untracked changes were rejected above.
            continue;
        };
        let source_rel = super::tree::join_rel(entry_prefix, source_path);
        if !filter.excludes_path_or_parent(&source_rel, is_dir) {
            return ProbeState::Unsafe;
        }
    }
    ProbeState::Safe
}

/// Return HEAD only when this repository is a registered submodule checkout
/// whose full commit exactly matches the superproject index gitlink.
fn pinned_submodule_commit(toplevel: &Path) -> Option<String> {
    let superproject = git_output(toplevel, &["rev-parse", "--show-superproject-working-tree"])?;
    if superproject.is_empty() {
        return None;
    }
    let superproject = PathBuf::from(superproject).canonicalize().ok()?;
    let rel = super::tree::rel_path_string(&superproject, toplevel).ok()?;
    let line = git_output(&superproject, &["ls-files", "-s", "--", &rel])?;
    let mut fields = line.split_whitespace();
    if fields.next()? != "160000" {
        return None;
    }
    let pinned = fields.next()?;
    if pinned.len() != 40 || !pinned.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let head = git_output(toplevel, &["rev-parse", "HEAD"])?;
    (head == pinned).then_some(head)
}

fn route_index_specials_clear(toplevel: &Path) -> ProbeState {
    let mut command = crate::invocation::command("git");
    command
        .arg("-C")
        .arg(toplevel)
        .args(["ls-files", "-v", "-z"]);
    match command.stderr(crate::invocation::Io::Null).output() {
        Ok(output) if output.status.success() => {
            if !output.stdout.is_empty() && output.stdout.last() != Some(&0) {
                return ProbeState::Unknown;
            }
            for record in output.stdout.split(|&b| b == 0).filter(|r| !r.is_empty()) {
                if record.len() < 3 || record[1] != b' ' {
                    return ProbeState::Unknown;
                }
                let leading = record[0];
                if leading == b'S' || leading.is_ascii_lowercase() {
                    return ProbeState::Unsafe;
                }
                if !matches!(leading, b'H' | b'M' | b'R' | b'C' | b'K' | b'?') {
                    return ProbeState::Unknown;
                }
            }
            ProbeState::Safe
        }
        _ => ProbeState::Unknown,
    }
}

fn route_submodules_clean(toplevel: &Path) -> ProbeState {
    if !toplevel.join(".gitmodules").exists() {
        return ProbeState::Safe;
    }
    let mut command = crate::invocation::command("git");
    command
        .arg("-C")
        .arg(toplevel)
        .args(["submodule", "status", "--recursive"]);
    match command.stderr(crate::invocation::Io::Null).output() {
        Ok(output) if output.status.success() => {
            if output
                .stdout
                .split(|&b| b == b'\n')
                .filter(|line| !line.is_empty())
                .all(|line| line.first().copied() == Some(b' '))
            {
                ProbeState::Safe
            } else {
                ProbeState::Unsafe
            }
        }
        _ => ProbeState::Unknown,
    }
}

fn route_config_safe(toplevel: &Path) -> ProbeState {
    let filemode = match git_config_value(toplevel, "core.filemode") {
        Ok(None) => true,
        Ok(Some(value)) => value == b"true",
        Err(()) => false,
    };
    let autocrlf = match git_config_value(toplevel, "core.autocrlf") {
        Ok(None) => true,
        Ok(Some(value)) => value == b"false",
        Err(()) => false,
    };
    let sparse = match git_config_value(toplevel, "core.sparsecheckout") {
        Ok(None) => true,
        Ok(Some(value)) => value == b"false",
        Err(()) => false,
    };
    let sparse_file_absent = git_output(
        toplevel,
        &["rev-parse", "--git-path", "info/sparse-checkout"],
    )
    .map(|path| {
        let path = PathBuf::from(path);
        let path = if path.is_absolute() {
            path
        } else {
            toplevel.join(path)
        };
        !path.exists()
    })
    .unwrap_or(false);
    if filemode && autocrlf && sparse && sparse_file_absent {
        ProbeState::Safe
    } else {
        ProbeState::Unsafe
    }
}

/// A gitlink is safe only if the nested checkout independently passes the
/// complete toplevel guard set and its full HEAD object id exactly matches the
/// superproject's recorded commit. Short-prefix comparisons are insufficient.
pub(crate) fn checked_gitlink_tree(
    subrepo: &Path,
    recorded_commit: &str,
    filter: &super::SourceFilter,
    entry_prefix: &str,
) -> Option<CheckedGitTree> {
    if !has_own_git_dir(subrepo) {
        return None;
    }
    let probe = probe_for(subrepo)?;
    if probe.head_commit.as_deref() != Some(recorded_commit) {
        return None;
    }
    if git_output(subrepo, &["rev-parse", "HEAD"]).as_deref() != Some(recorded_commit) {
        return None;
    }
    let checked = checked_git_tree_for_ingest(subrepo, filter, entry_prefix)?;
    checked.repo_prefix.is_empty().then_some(checked)
}

#[cfg(target_os = "macos")]
pub(crate) fn reflink_file(src: &Path, dst: &Path) -> Result<(), ()> {
    use std::ffi::CString;
    use std::os::raw::{c_char, c_int};
    use std::os::unix::ffi::OsStrExt;

    unsafe extern "C" {
        fn clonefile(src: *const c_char, dst: *const c_char, flags: u32) -> c_int;
    }

    let src = CString::new(src.as_os_str().as_bytes()).map_err(|_| ())?;
    let dst = CString::new(dst.as_os_str().as_bytes()).map_err(|_| ())?;
    let rc = unsafe { clonefile(src.as_ptr(), dst.as_ptr(), 0) };
    if rc == 0 { Ok(()) } else { Err(()) }
}

#[cfg(target_os = "linux")]
pub(crate) fn reflink_file(src: &Path, dst: &Path) -> Result<(), ()> {
    use std::fs::{File, OpenOptions};
    use std::os::fd::AsRawFd;
    use std::os::raw::{c_int, c_ulong};

    const FICLONE: c_ulong = 0x4004_9409;

    unsafe extern "C" {
        fn ioctl(fd: c_int, request: c_ulong, ...) -> c_int;
    }

    let src_file = File::open(src).map_err(|_| ())?;
    let dst_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(dst)
        .map_err(|_| ())?;
    let rc = unsafe { ioctl(dst_file.as_raw_fd(), FICLONE, src_file.as_raw_fd()) };
    if rc == 0 {
        Ok(())
    } else {
        drop(dst_file);
        let _ = std::fs::remove_file(dst);
        Err(())
    }
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub(crate) fn reflink_file(_src: &Path, _dst: &Path) -> Result<(), ()> {
    Err(())
}

pub(super) fn git_ls_tree(repo: &Path, treeid: &str) -> Result<Vec<super::GitTreeEntry>, String> {
    let output = crate::invocation::command("git")
        .arg("-C")
        .arg(repo)
        .args(["ls-tree", "-rz", "-r", "--full-tree", treeid])
        .output()
        .map_err(|e| format!("cannot run git ls-tree in {}: {}", repo.display(), e))?;
    if !output.status.success() {
        return Err(format!(
            "git ls-tree failed in {} for {}",
            repo.display(),
            treeid
        ));
    }
    if !output.stdout.is_empty() && output.stdout.last() != Some(&0) {
        return Err(format!(
            "git ls-tree returned an unterminated record in {} for {}",
            repo.display(),
            treeid
        ));
    }
    let mut out = Vec::new();
    for record in output.stdout.split(|b| *b == 0).filter(|r| !r.is_empty()) {
        let text = std::str::from_utf8(record)
            .map_err(|_| "non-UTF-8 path in git tree cannot enter source CAS".to_string())?;
        let (meta, path) = text
            .split_once('\t')
            .ok_or_else(|| format!("invalid git ls-tree record `{text}`"))?;
        let mut fields = meta.split_whitespace();
        let mode = fields
            .next()
            .ok_or_else(|| format!("invalid git ls-tree record `{text}`"))?;
        let kind = fields
            .next()
            .ok_or_else(|| format!("invalid git ls-tree record `{text}`"))?;
        let object = fields
            .next()
            .ok_or_else(|| format!("invalid git ls-tree record `{text}`"))?;
        out.push(super::GitTreeEntry {
            mode: mode.to_string(),
            kind: kind.to_string(),
            object: object.to_string(),
            path: path.to_string(),
        });
    }
    Ok(out)
}

impl super::GitBlobBatch {
    /// Open `git cat-file --batch --filters` against `repo`, which
    /// MUST be the git toplevel (the .gitattributes resolution depends on
    /// the working tree rooted at the toplevel). The batched reader takes
    /// one request per line in `<oid> <repo-relative-path>` form and
    /// returns the filtered blob bytes followed by a trailing newline;
    /// without `--filters` a single OID can yield different bytes at
    /// different paths, which is unsound for any memo that omits the path and
    /// for every build whose tree contains an attributed file.
    ///
    /// Do NOT add `--buffer`: `blob()` is a synchronous write-one/read-one
    /// loop over a still-open stdin, and `--buffer` suppresses git's
    /// per-object stdout flush (it flushes only at input EOF) — git would
    /// hold each response while we block reading it, a permanent pipe
    /// deadlock. The default per-object flush is exactly the interactive
    /// behavior this reader needs.
    ///
    /// `filtered_blob_reading_available(repo)` MUST be checked by the caller
    /// first — this constructor always passes `--filters` and fails fast
    /// when the flag is unsupported.
    pub(super) fn open(repo: &Path) -> Result<Self, String> {
        let mut child = crate::invocation::command("git")
            .arg("-C")
            .arg(repo)
            .args(["cat-file", "--batch", "--filters"])
            .stdin(crate::invocation::Io::Piped)
            .stdout(crate::invocation::Io::Piped)
            .stderr(crate::invocation::Io::Null)
            .spawn()
            .map_err(|e| {
                format!(
                    "cannot run git cat-file --batch --filters in {}: {}",
                    repo.display(),
                    e
                )
            })?;
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| format!("cannot open git cat-file stdin in {}", repo.display()))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| format!("cannot open git cat-file stdout in {}", repo.display()))?;
        Ok(super::GitBlobBatch {
            repo: repo.to_path_buf(),
            child: Some(child),
            stdin: Some(stdin),
            stdout: BufReader::new(stdout),
        })
    }

    pub(super) fn blob(&mut self, oid: &str, rel: &str) -> Result<Vec<u8>, String> {
        let stdin = self
            .stdin
            .as_mut()
            .ok_or_else(|| format!("git cat-file stdin is closed in {}", self.repo.display()))?;
        writeln!(stdin, "{oid} {rel}")
            .and_then(|_| stdin.flush())
            .map_err(|e| {
                format!(
                    "cannot request git filtered blob {} for {} in {}: {}",
                    oid,
                    rel,
                    self.repo.display(),
                    e
                )
            })?;
        let mut header = String::new();
        self.stdout.read_line(&mut header).map_err(|e| {
            format!(
                "cannot read git blob header {} for {} in {}: {}",
                oid,
                rel,
                self.repo.display(),
                e
            )
        })?;
        let header = header.trim_end_matches('\n');
        let mut fields = header.split_whitespace();
        let got_oid = fields.next().unwrap_or("");
        let kind = fields.next().unwrap_or("");
        if kind == "missing" {
            return Err(format!(
                "git cat-file returned `{}` for {} at {}",
                header, oid, rel
            ));
        }
        let size = fields
            .next()
            .ok_or_else(|| format!("invalid git blob header `{header}` for {rel}"))?
            .parse::<usize>()
            .map_err(|_| format!("invalid git blob size in `{header}` for {rel}"))?;
        if got_oid != oid || kind != "blob" {
            return Err(format!(
                "git cat-file returned `{header}` for blob {} at {}",
                oid, rel
            ));
        }
        let mut data = vec![0u8; size];
        self.stdout.read_exact(&mut data).map_err(|e| {
            format!(
                "cannot read git blob {} for {} in {}: {}",
                oid,
                rel,
                self.repo.display(),
                e
            )
        })?;
        let mut lf = [0u8; 1];
        self.stdout.read_exact(&mut lf).map_err(|e| {
            format!(
                "cannot read git blob trailer {} for {} in {}: {}",
                oid,
                rel,
                self.repo.display(),
                e
            )
        })?;
        if lf[0] != b'\n' {
            return Err(format!("invalid git blob trailer for {} at {}", oid, rel));
        }
        Ok(data)
    }

    pub(super) fn finish(mut self) -> Result<(), String> {
        drop(self.stdin.take());
        let status = self
            .child
            .take()
            .ok_or_else(|| format!("git cat-file child is gone in {}", self.repo.display()))?
            .wait()
            .map_err(|e| format!("cannot reap git cat-file in {}: {}", self.repo.display(), e))?;
        if status.success() {
            Ok(())
        } else {
            Err(format!(
                "git cat-file --batch --filters failed in {}",
                self.repo.display()
            ))
        }
    }
}

impl Drop for super::GitBlobBatch {
    fn drop(&mut self) {
        let _ = self.stdin.take();
        if let Some(mut child) = self.child.take() {
            match child.try_wait() {
                Ok(Some(_)) => {}
                Ok(None) => {
                    let _ = child.kill();
                    let _ = child.wait();
                }
                Err(_) => {
                    let _ = child.kill();
                    let _ = child.wait();
                }
            }
        }
    }
}
