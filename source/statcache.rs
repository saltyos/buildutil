//! SPDX-License-Identifier: GPL-2.0-only
//! buildutil — source content-addressed storage: persistent stat/blob caches
//!
//! The Git blob memo has an evaluation-local exact key plus a persistent
//! `(ingestion schema, object id) -> sha256` content-key map. Object-db routes
//! are admitted only when conversion is byte-identical, so an OID denotes the
//! same bytes independent of checkout path, inode, host, or container.
//!
//! The file cache (`StatCache`) replaces a composite-keyed whole-file text
//! cache whose entries accreted forever and were rewritten after every
//! ingested directory. The new design is a git-index-style accelerator:
//!
//! * Keys are raw repo-relative path bytes (no `to_string_lossy` collisions).
//! * A persisted entry is a HIT only when the full stat snapshot
//!   `(size, mtime_s, mtime_ns, ctime_s, ctime_ns, ino, dev)` ALL still
//!   matches, AND the file is not racy (file.mtime ≥ cache.write_nanos ⇒
//!   re-hash, git's rule). The racy check is lookup-only.
//! * Record admission is stat-snapshot equality only (the
//!   pre-read vs. post-read double-stat that the source CAS already did
//!   inline, moved into this layer now that the key no longer embeds
//!   mtime). Applying the racy check on record would forever block fresh
//!   writes from caching.
//! * Generation is read from disk and incremented exactly once at load
//!   (NOT per lookup). Eviction runs at the rare flush cadence.
//! * Bounded: drop entries with `last_used_gen < generation-64` and
//!   hard-cap at 4M (keep most-recent generations).
//! * The on-disk cache file carries a sha256 trailer over the header and
//!   the entry payload; magic / version / namespace mismatch ⇒ cold start
//!   (file unlinked) rather than an error.

use std::collections::hash_map::DefaultHasher;
use std::collections::{BTreeMap, HashMap};
use std::fmt::Write as _;
use std::fs::OpenOptions;
use std::hash::{Hash, Hasher};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use crate::crypto::sha256::Sha256;

const MAGIC: &[u8; 8] = b"BLDSTAT1";
const VERSION: u32 = 1;
const SHARDS: usize = 16;
const RETIRE_GEN_DROP: u64 = 64;
const HARD_CAP_ENTRIES: usize = 4_000_000;
/// Default persisted stat-cache byte ceiling (1 GiB). Only bounds eviction at
/// flush — it never changes a returned hash, so it is a pure accelerator knob
/// and stays out of every derivation preimage. Sized high so the whole working
/// set stays cached as the OS grows; the file is only ever as large as the live
/// tracked-file set, never preallocated. Override per run with the
/// `BUILDUTIL_STATCACHE_MAX_BYTES` env var (see `configured_statcache_max_bytes`).
const DEFAULT_STATCACHE_MAX_BYTES: usize = 1024 * 1024 * 1024;

/// Effective byte cap for this run: `BUILDUTIL_STATCACHE_MAX_BYTES` when set and
/// parseable, else [`DEFAULT_STATCACHE_MAX_BYTES`]. Parsing is intentionally
/// lenient — a cache knob must never fail a build — so an unset or malformed
/// value silently uses the default. Accepts a plain byte count or an optional
/// trailing `K`/`M`/`G` (base-1024, case-insensitive), e.g. `2G` or `512M`.
fn configured_statcache_max_bytes() -> usize {
    let Some(raw) = crate::invocation::ambient_var_os("BUILDUTIL_STATCACHE_MAX_BYTES") else {
        return DEFAULT_STATCACHE_MAX_BYTES;
    };
    let Some(s) = raw.to_str() else {
        return DEFAULT_STATCACHE_MAX_BYTES;
    };
    let s = s.trim();
    let (digits, mult) = match s.as_bytes().last() {
        Some(b'k' | b'K') => (&s[..s.len() - 1], 1024usize),
        Some(b'm' | b'M') => (&s[..s.len() - 1], 1024 * 1024),
        Some(b'g' | b'G') => (&s[..s.len() - 1], 1024 * 1024 * 1024),
        _ => (s, 1),
    };
    match digits.trim().parse::<usize>() {
        Ok(n) => n.saturating_mul(mult),
        Err(_) => DEFAULT_STATCACHE_MAX_BYTES,
    }
}

// The outer mutex protects only handle replacement during startup/tests. Each
// operation clones the Arc while holding it, then drops the outer lock before
// touching a shard. The Arc keeps that cache generation alive, and each shard
// mutex is therefore the sole protector of its entries; unrelated shards can
// proceed concurrently without an outer-lock/shard-lock nesting bottleneck.
static FILE_HASH_CACHE: Mutex<Option<Arc<StatCache>>> = Mutex::new(None);
static GIT_BLOB_MEMO: Mutex<Option<GitBlobMemo>> = Mutex::new(None);
static GIT_BLOB_MEMO_PATH: Mutex<Option<PathBuf>> = Mutex::new(None);

static STAT_HITS: AtomicU64 = AtomicU64::new(0);
static STAT_MISSES: AtomicU64 = AtomicU64::new(0);
static STATCACHE_LOAD_MS: AtomicU64 = AtomicU64::new(0);

pub fn statcache_hits() -> u64 {
    STAT_HITS.load(Ordering::Relaxed)
}
pub fn statcache_misses() -> u64 {
    STAT_MISSES.load(Ordering::Relaxed)
}

/// Wall-clock duration of the most recent stat-cache load. This is an
/// accelerator-only observation and never contributes to a derivation input.
pub fn statcache_load_ms() -> u128 {
    STATCACHE_LOAD_MS.load(Ordering::Relaxed) as u128
}

fn elapsed_ms(started: Instant) -> u64 {
    started.elapsed().as_millis().min(u64::MAX as u128) as u64
}

struct FlushTimer {
    started: Instant,
}

impl FlushTimer {
    fn from_start(started: Instant) -> Self {
        Self { started }
    }
}

impl Drop for FlushTimer {
    fn drop(&mut self) {
        say!(
            "  {:<20} : {}",
            "stat cache flush (exit)",
            crate::events::fmt_ms(elapsed_ms(self.started) as u128)
        );
    }
}

/// Opaque file state carried from directory enumeration through hashing. The
/// post-read re-stat checks every identity-relevant field before the digest is
/// admitted, so a concurrent mutation cannot poison the cache or tree mode.
#[derive(Clone)]
pub(crate) struct FileSnapshot {
    size: u64,
    mtime_s: i64,
    mtime_ns: i64,
    ctime_s: i64,
    ctime_ns: i64,
    ino: u64,
    dev: u64,
    mode: u32,
}

#[derive(Clone)]
pub(crate) struct FileCacheToken {
    cache: Arc<StatCache>,
    abs_path: PathBuf,
    rel_path: Vec<u8>,
    snapshot: FileSnapshot,
}

struct StatCache {
    state_root: PathBuf,
    repo_root: PathBuf,
    dev: u64,
    write_nanos: i64,
    generation: u64,
    shards: [Mutex<Shard>; SHARDS],
    content_dirty: AtomicBool,
    lru_dirty: AtomicBool,
}

struct Shard {
    entries: HashMap<Vec<u8>, ShardEntry>,
}

#[derive(Clone)]
struct ShardEntry {
    size: u64,
    mtime_s: i64,
    mtime_ns: i64,
    ctime_s: i64,
    ctime_ns: i64,
    ino: u64,
    dev: u64,
    sha256: [u8; 32],
    last_used_gen: u64,
}

/// Evaluation-local filtered-blob memo. `PathBuf` preserves the repository's
/// native path identity without a lossy string conversion.
struct GitBlobMemo {
    map: BTreeMap<(PathBuf, u32, String, String, String), String>,
    content: BTreeMap<(u32, String, String), String>,
    dirty: bool,
}

// --- helpers ---

#[inline]
fn shard_for(rel: &[u8]) -> usize {
    let mut h = DefaultHasher::new();
    rel.hash(&mut h);
    (h.finish() as usize) % SHARDS
}

fn canonicalize_quiet(path: &Path) -> PathBuf {
    std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
}

fn dev_id_of(path: &Path) -> Option<u64> {
    crate::platform::device_id(path)
}

pub(crate) fn file_snapshot(m: &std::fs::Metadata) -> Option<FileSnapshot> {
    if !m.is_file() {
        return None;
    }
    let fields = crate::platform::stat_fields(m);
    Some(FileSnapshot {
        size: m.len(),
        mtime_s: fields.mtime_s,
        mtime_ns: fields.mtime_ns,
        ctime_s: fields.ctime_s,
        ctime_ns: fields.ctime_ns,
        ino: fields.ino,
        dev: fields.dev,
        mode: fields.mode,
    })
}

impl FileSnapshot {
    pub(crate) fn kind(&self) -> char {
        if self.mode & 0o111 != 0 { 'x' } else { 'f' }
    }

    fn cache_fields(&self) -> (u64, i64, i64, i64, i64, u64, u64) {
        (
            self.size,
            self.mtime_s,
            self.mtime_ns,
            self.ctime_s,
            self.ctime_ns,
            self.ino,
            self.dev,
        )
    }
}

/// Repo-relative path bytes — `<never to_string_lossy>`. `None` means the
/// path is not cacheable: not under `repo_root`, or under `state_root`.
fn compute_rel(path: &Path, repo_root: &Path, state_root: &Path) -> Option<Vec<u8>> {
    let cp: Vec<_> = path.components().collect();
    let cr: Vec<_> = repo_root.components().collect();
    let cs: Vec<_> = state_root.components().collect();
    if cp.starts_with(&cs) {
        return None;
    }
    if !cp.starts_with(&cr) {
        return None;
    }
    let mut rel = Vec::new();
    let mut first = true;
    for c in cp.iter().skip(cr.len()) {
        let std::path::Component::Normal(os) = c else {
            return None;
        };
        if !first {
            rel.push(b'/');
        }
        first = false;
        rel.extend_from_slice(os.as_encoded_bytes());
    }
    Some(rel)
}

fn hex_encode(b: &[u8]) -> String {
    let mut out = String::with_capacity(b.len() * 2);
    for byte in b {
        out.push_str(&format!("{:02x}", byte));
    }
    out
}

fn hex_decode(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let bytes = s.as_bytes();
    let mut out = [0u8; 32];
    fn hex_val(b: u8) -> Option<u8> {
        match b {
            b'0'..=b'9' => Some(b - b'0'),
            b'a'..=b'f' => Some(b - b'a' + 10),
            _ => None,
        }
    }
    for i in 0..32 {
        let hi = hex_val(bytes[i * 2])?;
        let lo = hex_val(bytes[i * 2 + 1])?;
        out[i] = (hi << 4) | lo;
    }
    Some(out)
}

fn empty_cache(state_root: PathBuf, repo_root: PathBuf, dev: u64) -> StatCache {
    StatCache {
        state_root,
        repo_root,
        dev,
        // Cold-start sentinel: the racy rule compares a file's mtime_s
        // against this. With i64::MAX no file mtime is "racy", since we
        // never persisted a cache to invalidate against.
        write_nanos: i64::MAX,
        generation: 0,
        shards: std::array::from_fn(|_| {
            Mutex::new(Shard {
                entries: HashMap::new(),
            })
        }),
        content_dirty: AtomicBool::new(false),
        lru_dirty: AtomicBool::new(false),
    }
}

// --- public file-cache API ---

/// Activate the file cache. `state_root` is where `cache/stat-cache.v1`
/// lives; `repo_root` is the canonical prefix that bounds cacheable paths
/// (anything outside it or inside `state_root` is uncached). Replaces any
/// previously-loaded cache (the tests' CAS_TEST_LOCK serializes that).
pub fn load_file_cache(state_root: &Path, repo_root: &Path) {
    let started = Instant::now();
    let state_root_c = canonicalize_quiet(state_root);
    let repo_root_c = canonicalize_quiet(repo_root);
    let dev = dev_id_of(&repo_root_c).unwrap_or(0);
    let mut cache = empty_cache(state_root_c, repo_root_c, dev);

    let path = crate::state::stat_cache_path(&cache.state_root);
    if let Ok(mut fd) = OpenOptions::new().read(true).open(&path) {
        // write_nanos is derived from fstat of the OPEN fd, never a stored
        // header field — that's how we keep the racy check honest across
        // load/flush without trusting persisted data.
        let write_nanos = fd
            .metadata()
            .map(|metadata| crate::platform::stat_fields(&metadata).mtime_s)
            .unwrap_or(-1);
        let mut data = Vec::new();
        if fd.read_to_end(&mut data).is_ok() {
            match parse_cache_file(&data, &cache.repo_root, cache.dev) {
                Some((generation, entries)) => {
                    insert_cache_entries(&cache.shards, entries);
                    cache.write_nanos = write_nanos;
                    cache.generation = generation.saturating_add(1);
                }
                None => {
                    let _ = std::fs::remove_file(&path);
                }
            }
        }
    }
    *FILE_HASH_CACHE.lock().expect("stat cache lock") = Some(Arc::new(cache));
    *GIT_BLOB_MEMO_PATH.lock().expect("git blob memo path lock") =
        Some(crate::state::git_blob_memo(state_root));
    STATCACHE_LOAD_MS.store(elapsed_ms(started), Ordering::Relaxed);
}

/// Persist the cache if it gained content entries. Called ONLY from `main()`
/// after the command completes (see the join-comment below).
///
/// ## Join assumption
///
/// This is an exit-only flush. All worker threads today (scoped worktree
/// parallelism in `source::worktree::parallel_worktree_files`) join before
/// `main()` returns. Any future parallel evaluator MUST preserve that join —
/// `flush_file_cache` reads from the same per-shard mutexes that any worker
/// would have been using, and missing a join would race the serialization
/// below.
pub fn flush_file_cache() {
    let cache = match FILE_HASH_CACHE.lock().expect("stat cache lock").clone() {
        Some(c) => c,
        None => return,
    };
    if !cache.content_dirty.load(Ordering::Acquire) {
        return;
    }
    let _timer = FlushTimer::from_start(Instant::now());

    let lock_path = crate::state::stat_cache_lock_path(&cache.state_root);
    if let Some(parent) = lock_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let lock_file = match OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(&lock_path)
    {
        Ok(f) => f,
        Err(_) => return,
    };
    if !matches!(crate::platform::lock_exclusive(&lock_file, false), Ok(true)) {
        return;
    }

    let final_path = crate::state::stat_cache_path(&cache.state_root);
    // Another one-shot process can have flushed while this process was
    // evaluating. Read after taking the flock, then retain the newest record
    // for every path so this stale in-memory snapshot cannot erase it.
    let (disk_generation, mut merged) = std::fs::read(&final_path)
        .ok()
        .and_then(|data| parse_cache_file(&data, &cache.repo_root, cache.dev))
        .unwrap_or_default();
    for (path, local) in snapshot_cache_entries(&cache.shards) {
        if merged
            .get(&path)
            .map(|disk| disk.last_used_gen < local.last_used_gen)
            .unwrap_or(true)
        {
            merged.insert(path, local);
        }
    }

    let saved_generation = cache.generation.max(disk_generation.saturating_add(1));
    // Apply retire, then entry cap, then size cap — in that order so the byte
    // cap (the user-visible bound) is what actually fires when a single eval
    // run produces far more entries than the cap allows.
    let mut all_entries = merged.into_iter().collect::<Vec<_>>();
    let retire_gen = saved_generation.saturating_sub(RETIRE_GEN_DROP);
    all_entries.retain(|(_, e)| e.last_used_gen >= retire_gen);
    if all_entries.len() > HARD_CAP_ENTRIES {
        all_entries.sort_by(|a, b| b.1.last_used_gen.cmp(&a.1.last_used_gen));
        all_entries.truncate(HARD_CAP_ENTRIES);
    }
    // Byte cap. Each entry's on-disk cost is 98 fixed bytes plus the
    // repo-relative path length (path bytes are already raw in
    // `all_entries`). Trim by walking the most-recent-first sort and
    // accumulating the cost of survivors until the next entry would
    // exceed the configured cap. The survivors are the freshest
    // `last_used_gen`s in path order.
    let cap = configured_statcache_max_bytes();
    let entry_cost = |k: &[u8]| 98 + k.len();
    let total_bytes: usize = all_entries.iter().map(|(k, _)| entry_cost(k)).sum();
    if total_bytes > cap {
        all_entries.sort_by(|a, b| {
            b.1.last_used_gen
                .cmp(&a.1.last_used_gen)
                .then_with(|| a.0.cmp(&b.0))
        });
        let mut keep: usize = 0;
        let mut kept: usize = 0;
        for (k, _) in all_entries.iter() {
            let cost = entry_cost(k);
            if kept + cost > cap {
                break;
            }
            kept += cost;
            keep += 1;
        }
        all_entries.truncate(keep);
    }
    // Stable payload order: shard id, then key — keeps the trailer sha256
    // deterministic across runs that don't actually mutate entries.
    all_entries.sort_by(|a, b| {
        let sa = shard_for(&a.0);
        let sb = shard_for(&b.0);
        sa.cmp(&sb).then_with(|| a.0.cmp(&b.0))
    });

    if let Some(parent) = final_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }

    let mut payload: Vec<u8> = Vec::new();
    payload.extend_from_slice(MAGIC);
    payload.extend_from_slice(&VERSION.to_le_bytes());
    payload.extend_from_slice(&saved_generation.to_le_bytes());
    payload.extend_from_slice(&(all_entries.len() as u64).to_le_bytes());
    let repo_bytes = cache.repo_root.as_os_str().as_encoded_bytes();
    payload.extend_from_slice(&(repo_bytes.len() as u32).to_le_bytes());
    payload.extend_from_slice(repo_bytes);
    payload.extend_from_slice(&cache.dev.to_le_bytes());
    for (k, e) in &all_entries {
        payload.extend_from_slice(&e.size.to_le_bytes());
        payload.extend_from_slice(&e.mtime_s.to_le_bytes());
        payload.extend_from_slice(&e.mtime_ns.to_le_bytes());
        payload.extend_from_slice(&e.ctime_s.to_le_bytes());
        payload.extend_from_slice(&e.ctime_ns.to_le_bytes());
        payload.extend_from_slice(&e.ino.to_le_bytes());
        payload.extend_from_slice(&e.dev.to_le_bytes());
        payload.extend_from_slice(&e.sha256);
        payload.extend_from_slice(&e.last_used_gen.to_le_bytes());
        payload.extend_from_slice(&(k.len() as u16).to_le_bytes());
        payload.extend_from_slice(k);
    }
    // Trailer: sha256 over header AND entry payload (not just entries).
    let mut h = Sha256::new();
    h.update(&payload);
    let trailer = h.finalize();
    payload.extend_from_slice(trailer.as_slice());

    let tmp_path = final_path.with_extension("tmp");
    let write_result = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&tmp_path)
        .and_then(|mut f| {
            f.write_all(&payload)?;
            f.sync_all()?;
            Ok(())
        })
        .and_then(|()| std::fs::rename(&tmp_path, &final_path));

    if write_result.is_ok() {
        cache.content_dirty.store(false, Ordering::Release);
        cache.lru_dirty.store(false, Ordering::Release);
    }
}

fn parse_cache_file(
    data: &[u8],
    repo_root: &Path,
    expected_dev: u64,
) -> Option<(u64, BTreeMap<Vec<u8>, ShardEntry>)> {
    if data.len() < 40 || &data[0..8] != MAGIC {
        return None;
    }
    let version = u32::from_le_bytes(data[8..12].try_into().ok()?);
    if version != VERSION {
        return None;
    }
    let generation = u64::from_le_bytes(data[12..20].try_into().ok()?);
    let _entry_count = u64::from_le_bytes(data[20..28].try_into().ok()?) as usize;
    let repo_root_len = u32::from_le_bytes(data[28..32].try_into().ok()?) as usize;
    let header_end = 32 + repo_root_len + 8;
    if data.len() < header_end + 32 {
        return None;
    }
    let repo_bytes_in = &data[32..32 + repo_root_len];
    let repo_bytes_cur = repo_root.as_os_str().as_encoded_bytes();
    if repo_bytes_in != repo_bytes_cur {
        return None;
    }
    let dev_in = u64::from_le_bytes(data[32 + repo_root_len..header_end].try_into().ok()?);
    if dev_in != expected_dev {
        return None;
    }
    let trailer_offset = data.len() - 32;
    let entries_payload = &data[header_end..trailer_offset];
    let trailer = &data[trailer_offset..];
    let mut h = Sha256::new();
    h.update(&data[..trailer_offset]);
    let computed = h.finalize();
    if computed.as_slice() != trailer {
        return None;
    }

    let mut entries = BTreeMap::new();
    let mut pos = 0;
    while pos < entries_payload.len() {
        if pos + 98 > entries_payload.len() {
            return None;
        }
        let size = u64::from_le_bytes(entries_payload[pos..pos + 8].try_into().ok()?);
        let mtime_s = i64::from_le_bytes(entries_payload[pos + 8..pos + 16].try_into().ok()?);
        let mtime_ns = i64::from_le_bytes(entries_payload[pos + 16..pos + 24].try_into().ok()?);
        let ctime_s = i64::from_le_bytes(entries_payload[pos + 24..pos + 32].try_into().ok()?);
        let ctime_ns = i64::from_le_bytes(entries_payload[pos + 32..pos + 40].try_into().ok()?);
        let ino = u64::from_le_bytes(entries_payload[pos + 40..pos + 48].try_into().ok()?);
        let dev_in_e = u64::from_le_bytes(entries_payload[pos + 48..pos + 56].try_into().ok()?);
        let mut sha = [0u8; 32];
        sha.copy_from_slice(&entries_payload[pos + 56..pos + 88]);
        let last_used_gen =
            u64::from_le_bytes(entries_payload[pos + 88..pos + 96].try_into().ok()?);
        let path_len =
            u16::from_le_bytes(entries_payload[pos + 96..pos + 98].try_into().ok()?) as usize;
        pos += 98;
        if pos + path_len > entries_payload.len() {
            return None;
        }
        let rel_path = entries_payload[pos..pos + path_len].to_vec();
        pos += path_len;
        if dev_in_e != expected_dev {
            // Entry from a foreign mount crossed into this file; drop.
            continue;
        }
        entries.insert(
            rel_path,
            ShardEntry {
                size,
                mtime_s,
                mtime_ns,
                ctime_s,
                ctime_ns,
                ino,
                dev: dev_in_e,
                sha256: sha,
                last_used_gen,
            },
        );
    }
    Some((generation, entries))
}

fn insert_cache_entries(shards: &[Mutex<Shard>; SHARDS], entries: BTreeMap<Vec<u8>, ShardEntry>) {
    for (path, entry) in entries {
        shards[shard_for(&path)]
            .lock()
            .expect("shard lock")
            .entries
            .insert(path, entry);
    }
}

fn snapshot_cache_entries(shards: &[Mutex<Shard>; SHARDS]) -> BTreeMap<Vec<u8>, ShardEntry> {
    let mut entries = BTreeMap::new();
    for shard in shards {
        entries.extend(
            shard
                .lock()
                .expect("shard lock")
                .entries
                .iter()
                .map(|(path, entry)| (path.clone(), entry.clone())),
        );
    }
    entries
}

fn file_cache_handle() -> Option<Arc<StatCache>> {
    FILE_HASH_CACHE.lock().expect("stat cache lock").clone()
}

/// Build a cache token for a path already known to be canonical. Worktree
/// ingestion canonicalizes its root once, so every descendant can use this
/// syscall-free path-key construction with the metadata obtained from
/// `DirEntry::metadata`.
pub(crate) fn file_cache_key_for_canonical(
    path: &Path,
    snapshot: &FileSnapshot,
) -> Option<FileCacheToken> {
    let cache = file_cache_handle()?;
    let rel = compute_rel(path, &cache.repo_root, &cache.state_root)?;
    Some(FileCacheToken {
        cache,
        abs_path: path.to_path_buf(),
        rel_path: rel,
        snapshot: snapshot.clone(),
    })
}

pub(crate) fn cached_file_hash_for_key(token: &FileCacheToken) -> Option<String> {
    let cache = &token.cache;
    let fields = token.snapshot.cache_fields();
    let shard_idx = shard_for(&token.rel_path);
    let mut shard = cache.shards[shard_idx].lock().expect("shard lock");
    let entry_snap = match shard.entries.get(&token.rel_path) {
        Some(e) => (
            e.size,
            e.mtime_s,
            e.mtime_ns,
            e.ctime_s,
            e.ctime_ns,
            e.ino,
            e.dev,
            e.sha256,
            e.last_used_gen,
        ),
        None => {
            drop(shard);
            STAT_MISSES.fetch_add(1, Ordering::Relaxed);
            return None;
        }
    };
    if entry_snap.0 != fields.0
        || entry_snap.1 != fields.1
        || entry_snap.2 != fields.2
        || entry_snap.3 != fields.3
        || entry_snap.4 != fields.4
        || entry_snap.5 != fields.5
        || entry_snap.6 != fields.6
    {
        drop(shard);
        STAT_MISSES.fetch_add(1, Ordering::Relaxed);
        return None;
    }
    // RACY RULE — applied on lookup only.
    if token.snapshot.mtime_s >= cache.write_nanos {
        drop(shard);
        STAT_MISSES.fetch_add(1, Ordering::Relaxed);
        return None;
    }
    let sha = entry_snap.7;
    let needs_gen_touch = entry_snap.8 != cache.generation;
    if needs_gen_touch {
        if let Some(e_mut) = shard.entries.get_mut(&token.rel_path) {
            e_mut.last_used_gen = cache.generation;
            cache.lru_dirty.store(true, Ordering::Release);
        }
    }
    drop(shard);
    STAT_HITS.fetch_add(1, Ordering::Relaxed);
    Some(hex_encode(&sha))
}

pub(crate) fn snapshot_still_matches(path: &Path, snapshot: &FileSnapshot) -> bool {
    std::fs::metadata(path)
        .ok()
        .and_then(|m| file_snapshot(&m))
        .is_some_and(|current| {
            current.cache_fields() == snapshot.cache_fields() && current.mode == snapshot.mode
        })
}

pub(crate) fn cache_token_still_matches(token: &FileCacheToken) -> bool {
    snapshot_still_matches(&token.abs_path, &token.snapshot)
}

/// Validate the post-read snapshot and admit the digest. `false` means the
/// file changed while it was being read; callers must reject that ingestion.
pub(crate) fn record_file_hash_for_key(token: FileCacheToken, digest: &str) -> bool {
    let cache = &token.cache;
    if !cache_token_still_matches(&token) {
        // The file moved (size/mtime/ctime/ino/dev) between the read and
        // the record — do not poison the cache with a wrong hash.
        return false;
    }
    let sha = match hex_decode(digest) {
        Some(s) => s,
        None => return false,
    };
    let shard_idx = shard_for(&token.rel_path);
    let mut shard = cache.shards[shard_idx].lock().expect("shard lock");
    shard.entries.insert(
        token.rel_path,
        ShardEntry {
            size: token.snapshot.size,
            mtime_s: token.snapshot.mtime_s,
            mtime_ns: token.snapshot.mtime_ns,
            ctime_s: token.snapshot.ctime_s,
            ctime_ns: token.snapshot.ctime_ns,
            ino: token.snapshot.ino,
            dev: token.snapshot.dev,
            sha256: sha,
            last_used_gen: cache.generation,
        },
    );
    cache.content_dirty.store(true, Ordering::Release);
    true
}

// --- evaluation-scoped git-blob memo ---

pub(crate) fn begin_git_blob_memo_eval() {
    let content = GIT_BLOB_MEMO_PATH
        .lock()
        .expect("git blob memo path lock")
        .as_ref()
        .map(|path| load_git_blob_content_map(path))
        .unwrap_or_default();
    *GIT_BLOB_MEMO.lock().expect("git blob memo lock") = Some(GitBlobMemo {
        map: BTreeMap::new(),
        content,
        dirty: false,
    });
}

pub(crate) fn end_git_blob_memo_eval() {
    let memo = GIT_BLOB_MEMO.lock().expect("git blob memo lock").take();
    let path = GIT_BLOB_MEMO_PATH
        .lock()
        .expect("git blob memo path lock")
        .clone();
    if let (Some(memo), Some(path)) = (memo, path) {
        if memo.dirty {
            persist_git_blob_content_map(&path, &memo.content);
        }
    }
}

pub fn cached_git_blob_hash(
    repo: &Path,
    schema: u32,
    conversion_state: &str,
    oid: &str,
    rel: &str,
) -> Option<String> {
    let guard = GIT_BLOB_MEMO.lock().expect("git blob memo lock");
    let memo = guard.as_ref()?;
    memo.map
        .get(&(
            repo.to_path_buf(),
            schema,
            conversion_state.to_string(),
            oid.to_string(),
            rel.to_string(),
        ))
        .cloned()
        .or_else(|| {
            memo.content
                .get(&(schema, conversion_state.to_string(), oid.to_string()))
                .cloned()
        })
}

pub fn record_git_blob_hash(
    repo: &Path,
    schema: u32,
    conversion_state: &str,
    oid: &str,
    rel: &str,
    digest: &str,
) {
    let mut guard = GIT_BLOB_MEMO.lock().expect("git blob memo lock");
    let Some(memo) = guard.as_mut() else {
        return;
    };
    memo.map.insert(
        (
            repo.to_path_buf(),
            schema,
            conversion_state.to_string(),
            oid.to_string(),
            rel.to_string(),
        ),
        digest.to_string(),
    );
    if memo
        .content
        .insert(
            (schema, conversion_state.to_string(), oid.to_string()),
            digest.to_string(),
        )
        .as_deref()
        != Some(digest)
    {
        memo.dirty = true;
    }
}

const GIT_BLOB_MAP_HEADER: &str = "BLDGIT1";

fn load_git_blob_content_map(path: &Path) -> BTreeMap<(u32, String, String), String> {
    let Ok(text) = std::fs::read_to_string(path) else {
        return BTreeMap::new();
    };
    let mut lines = text.lines();
    if lines.next() != Some(GIT_BLOB_MAP_HEADER) {
        return BTreeMap::new();
    }
    let mut out = BTreeMap::new();
    for line in lines {
        let mut fields = line.split(' ');
        let (Some(schema), Some(conversion), Some(oid), Some(digest), None) = (
            fields.next(),
            fields.next(),
            fields.next(),
            fields.next(),
            fields.next(),
        ) else {
            return BTreeMap::new();
        };
        let Ok(schema) = schema.parse::<u32>() else {
            return BTreeMap::new();
        };
        if conversion.len() != 64
            || !conversion.bytes().all(|b| b.is_ascii_hexdigit())
            || !oid.bytes().all(|b| b.is_ascii_hexdigit())
            || digest.len() != 64
            || !digest.bytes().all(|b| b.is_ascii_hexdigit())
        {
            return BTreeMap::new();
        }
        out.insert(
            (schema, conversion.to_string(), oid.to_string()),
            digest.to_string(),
        );
    }
    out
}

fn persist_git_blob_content_map(path: &Path, additions: &BTreeMap<(u32, String, String), String>) {
    let Some(parent) = path.parent() else { return };
    if std::fs::create_dir_all(parent).is_err() {
        return;
    }
    let lock_path = path.with_extension("lock");
    let Ok(lock) = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open(lock_path)
    else {
        return;
    };
    if !matches!(crate::platform::lock_exclusive(&lock, false), Ok(true)) {
        return;
    }
    let mut merged = load_git_blob_content_map(path);
    merged.extend(additions.iter().map(|(k, v)| (k.clone(), v.clone())));
    let mut text = String::from(GIT_BLOB_MAP_HEADER);
    text.push('\n');
    for ((schema, conversion, oid), digest) in merged {
        let _ = writeln!(text, "{schema} {conversion} {oid} {digest}");
    }
    let tmp = path.with_extension(format!("tmp-{}", std::process::id()));
    if std::fs::write(&tmp, text).is_ok() {
        let _ = std::fs::rename(&tmp, path);
    }
    let _ = std::fs::remove_file(tmp);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_path(name: &str) -> PathBuf {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "buildutil-statcache-{name}-{}-{nonce}",
            std::process::id()
        ))
    }

    fn entry(last_used_gen: u64, marker: u8) -> ShardEntry {
        ShardEntry {
            size: 1,
            mtime_s: 1,
            mtime_ns: 0,
            ctime_s: 1,
            ctime_ns: 0,
            ino: marker as u64,
            dev: 7,
            sha256: [marker; 32],
            last_used_gen,
        }
    }

    fn insert(cache: &Arc<StatCache>, path: &[u8], entry: ShardEntry) {
        cache.shards[shard_for(path)]
            .lock()
            .expect("shard lock")
            .entries
            .insert(path.to_vec(), entry);
    }

    fn install(cache: Arc<StatCache>) {
        *FILE_HASH_CACHE.lock().expect("stat cache lock") = Some(cache);
    }

    fn clear_cache() {
        *FILE_HASH_CACHE.lock().expect("stat cache lock") = None;
    }

    #[test]
    fn lru_only_touches_do_not_rewrite_the_stat_cache() {
        let _guard = crate::source::cas_test_guard();
        let root = temp_path("lru-only");
        let state = root.join("state");
        let repo = root.join("repo");
        std::fs::create_dir_all(&repo).unwrap();
        let cache = Arc::new(empty_cache(state.clone(), repo.clone(), 7));
        insert(&cache, b"tracked", entry(0, 1));
        cache.content_dirty.store(true, Ordering::Release);
        install(cache.clone());
        flush_file_cache();

        let cache_path = crate::state::stat_cache_path(&state);
        let first = std::fs::read(&cache_path).unwrap();
        cache.shards[shard_for(b"tracked")]
            .lock()
            .expect("shard lock")
            .entries
            .get_mut(&b"tracked".to_vec())
            .unwrap()
            .last_used_gen = 1;
        cache.lru_dirty.store(true, Ordering::Release);
        flush_file_cache();

        assert_eq!(std::fs::read(&cache_path).unwrap(), first);
        assert!(cache.lru_dirty.load(Ordering::Acquire));
        clear_cache();
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn flush_merges_newer_on_disk_entries_after_locking() {
        let _guard = crate::source::cas_test_guard();
        let root = temp_path("merge");
        let state = root.join("state");
        let repo = root.join("repo");
        std::fs::create_dir_all(&repo).unwrap();

        let disk_cache = Arc::new(empty_cache(state.clone(), repo.clone(), 7));
        insert(&disk_cache, b"fresh", entry(8, 2));
        insert(&disk_cache, b"shared", entry(9, 3));
        disk_cache.content_dirty.store(true, Ordering::Release);
        install(disk_cache);
        flush_file_cache();

        let stale_cache = Arc::new(empty_cache(state.clone(), repo.clone(), 7));
        insert(&stale_cache, b"stale", entry(1, 4));
        insert(&stale_cache, b"shared", entry(2, 5));
        stale_cache.content_dirty.store(true, Ordering::Release);
        install(stale_cache);
        flush_file_cache();

        let cache_path = crate::state::stat_cache_path(&state);
        let (_, entries) = parse_cache_file(&std::fs::read(cache_path).unwrap(), &repo, 7).unwrap();
        assert_eq!(entries.get(&b"fresh".to_vec()).unwrap().sha256, [2; 32]);
        assert_eq!(entries.get(&b"shared".to_vec()).unwrap().sha256, [3; 32]);
        assert_eq!(entries.get(&b"stale".to_vec()).unwrap().sha256, [4; 32]);
        clear_cache();
        let _ = std::fs::remove_dir_all(root);
    }
}
