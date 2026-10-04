//! SPDX-License-Identifier: GPL-2.0-only
//! Snapshot, pin and log conformance over the production writer, codec and
//! reader. The fixture publishes a second version of subvolume 1 that pins
//! the writer's version as a snapshot, either as a clean checkpoint or as a
//! certified atom left in the ring; only fault injection edits raw bytes.

use super::build::{NodeMeta, build_internal, build_leaf};
use super::*;
use std::path::{Path, PathBuf};

fn leaf_items(block: &[u8]) -> Vec<(Key, Vec<u8>)> {
    assert_eq!(&block[..4], NODE_MAGIC);
    assert_eq!(get16(block, 0x20), 0);
    let count = get32(block, 0x04) as usize;
    (0..count)
        .map(|index| {
            let at = NODE_HEADER_SIZE + index * LEAF_ENTRY_SIZE;
            let start = get32(block, at + KEY_SIZE) as usize;
            let size = get32(block, at + KEY_SIZE + 4) as usize;
            (Key::unpack(&block[at..at + KEY_SIZE]), block[start..start + size].to_vec())
        })
        .collect()
}

/// A plain volume's pointer: the image is in the clear and xxh3 tags it.
fn pointer_to(address: u64, birth: u64, block: &[u8]) -> Pointer { Pointer { address, birth, tag: xxh3::hash128(block) } }

/// One deadlog leaf: `(sequence, address, length, birth)` entries keyed by
/// the dropping atom's sequence and the run's address.
fn deadlog_leaf(incarnation: u64, address: u64, entries: &[(u64, u64, u32, u64)]) -> Vec<u8> {
    let mut items: Vec<(Key, Vec<u8>)> = entries
        .iter()
        .map(|(sequence, run, length, birth)| {
            let mut payload = vec![0u8; DEADLOG_ENTRY_BYTES];
            put32(&mut payload, 0, *length);
            put64(&mut payload, 8, *birth);
            (Key::new(DEFAULT_SUBVOL, *sequence, ITEM_DEADLOG_ENTRY, *run), payload)
        })
        .collect();
    items.sort_by_key(|(key, _)| *key);
    let meta = NodeMeta { owner: DEFAULT_SUBVOL, birth: SEQ, tree: TREE_DEADLOG, incarnation };
    build_leaf(meta, address, &items).unwrap()
}

fn hole(logical: u64, birth: u64) -> Vec<u8> {
    let mut out = vec![0u8; EXTENT_HEADER_SIZE];
    put64(&mut out, 0x00, birth);
    put64(&mut out, 0x08, logical);
    out[0x20] = EXTENT_HOLE;
    out
}

const SEQ: u64 = 2;

struct Fixture {
    directory: PathBuf,
    image: PathBuf,
    raw: Vec<u8>,
    /// The writer's checkpoint.
    sb: Superblock,
    old_row: SubvolRow,
    /// The key-tree and store rows, carried unchanged into every table.
    other_rows: Vec<(Key, Vec<u8>)>,
    old_table: u64,
    old_data: u64,
    new_data: u64,
    item_new: u64,
    table_new: u64,
    registry: u64,
    deadlog: u64,
    /// First block above the fixture's own allocations.
    spare: u64,
    row: SubvolRow,
    registry_items: Vec<(Key, Vec<u8>)>,
    bitmap: Vec<u8>,
    table_root: Pointer,
    registry_root: Pointer,
}

impl Drop for Fixture {
    fn drop(&mut self) { let _ = std::fs::remove_dir_all(&self.directory); }
}

fn image_spec() -> FsSpec {
    FsSpec { size_bytes: 256 * BLOCK_SIZE as u64, label: "snapshot-fixture".into(), epoch_secs: 1, clock_valid: true, casefold_root: false, extra_incompat: 0, compat_ro_flags: 0, casefold_version: 0 }
}

fn image_contents() -> Contents {
    Contents { files: vec![("file".into(), FileSource::Bytes(vec![b'A'; BLOCK_SIZE]))], empty_dirs: vec![], symlinks: vec![], directory_links: vec![], permissions: cpio::Permissions::new() }
}

fn errors(path: &Path) -> String {
    match read::verify(path) { Ok(errors) => errors.join("; "), Err(error) => error }
}

/// The blocks of the writer's image the fixture's second version keeps:
/// subvolume 1's index leaf, the store's two leaves, and the new blocks.
const STORE_BLOCKS: u64 = 2;

impl Fixture {
    fn new(tag: &str, live_size: u64) -> Fixture {
        let nonce = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
        let directory = std::env::temp_dir().join(format!("saltyfs-snap-{tag}-{}-{nonce}", std::process::id()));
        std::fs::create_dir_all(&directory).unwrap();
        let image = directory.join("image");
        build::build_to_file(&image, &image_spec(), &image_contents()).unwrap();
        let raw = std::fs::read(&image).unwrap();
        let sb = Superblock::parse(&raw[..BLOCK_SIZE]).unwrap();
        let block = |nr: u64| raw[nr as usize * BLOCK_SIZE..(nr as usize + 1) * BLOCK_SIZE].to_vec();
        let old_table = sb.table_root.address;
        let table_items = leaf_items(&block(old_table));
        assert_eq!(table_items.len(), 3, "the default, key-tree and store rows");
        let old_row = SubvolRow::unpack(&table_items[0].1).unwrap();
        let other_rows = table_items[1..].to_vec();
        let old_items = leaf_items(&block(old_row.item_root.address));
        let (file_key, _) = old_items.iter().find(|(key, _)| key.ty == ITEM_INODE && key.objectid != ROOT_INO).unwrap();
        let file = (file_key.locality, file_key.objectid);
        let old_data = old_items.iter().find(|(key, _)| key.ty == ITEM_EXTENT_DATA).map(|(_, ext)| get64(ext, 0x10)).unwrap();
        let mut bitmap = block(sb.bitmap_start);
        let set = |bitmap: &[u8], b: u64| bitmap[(b / 8) as usize] & (1 << (b % 8)) != 0;
        let first = (sb.first_data_block()..sb.total_blocks).find(|b| !set(&bitmap, *b)).unwrap();
        let (new_data, item_new, tag_new, table_new, registry, deadlog) = (first, first + 1, first + 2, first + 3, first + 4, first + 5);
        let spare = first + 6;

        let node = |owner, tree| NodeMeta { owner, birth: SEQ, tree, incarnation: sb.volume_incarnation };
        let mut raw = raw;
        let mut write = |nr: u64, data: &[u8]| raw[nr as usize * BLOCK_SIZE..(nr as usize + 1) * BLOCK_SIZE].copy_from_slice(data);

        // The live version: the file rewritten at a new address.
        let data = vec![b'N'; BLOCK_SIZE];
        write(new_data, &data);
        let mut live_items = old_items.clone();
        for (key, item) in &mut live_items {
            if (key.locality, key.objectid) != file { continue; }
            if key.ty == ITEM_INODE {
                put64(item, 0x08, live_size);
                put64(item, 0x10, 1);
                put64(item, 0x50, SEQ);
            }
            if key.ty == ITEM_EXTENT_DATA {
                *item = pack_extent_regular(live_size.min(BLOCK_SIZE as u64), new_data, BLOCK_SIZE as u64, SEQ, COMPRESSION_NONE);
            }
        }
        if live_size > BLOCK_SIZE as u64 {
            live_items.push((Key::new(file.0, file.1, ITEM_EXTENT_DATA, BLOCK_SIZE as u64), hole(live_size - BLOCK_SIZE as u64, SEQ)));
        }
        live_items.sort_by_key(|(key, _)| *key);
        let item_leaf = build_leaf(node(DEFAULT_SUBVOL, TREE_ITEM), item_new, &live_items).unwrap();
        write(item_new, &item_leaf);
        let tag_leaf = build_leaf(node(DEFAULT_SUBVOL, TREE_DATA_TAG), tag_new, &[(Key::new(0, new_data, ITEM_DATA_TAG, SEQ), pack_data_tags(&[xxh3::hash128(&data)]))]).unwrap();
        write(tag_new, &tag_leaf);

        // The snapshot retains the writer's version and its dropped blocks.
        let dropped = [old_row.item_root.address, old_row.tag_root.address, old_data];
        let deadlog_bytes = deadlog_leaf(sb.volume_incarnation, deadlog, &dropped.map(|b| (SEQ, b, 1, INITIAL_SEQ)));
        write(deadlog, &deadlog_bytes);
        let snap = SnapRow {
            snapshot_id: 1, item_root: old_row.item_root, index_root: old_row.index_root, tag_root: old_row.tag_root, objectid_hwm: old_row.objectid_hwm,
            incarnation_hwm: old_row.incarnation_hwm, creation_time: 1, deadlog_root: pointer_to(deadlog, SEQ, &deadlog_bytes), deadlog_cursor: 0, owner: (0, 0),
            state: SNAP_STATE_PINNED, holds: 0, flags: 0, seal_time: 0, commit_name: [0; 32],
        };
        let registry_items = vec![(Key::new(DEFAULT_SUBVOL, INITIAL_SEQ, ITEM_SNAP, 0), snap.pack())];
        // Live: the new item and tag leaves, the shared index leaf, the new
        // data block. Retained: the old item and tag leaves and the old data.
        let row = SubvolRow {
            item_root: pointer_to(item_new, SEQ, &item_leaf), tag_root: pointer_to(tag_new, SEQ, &tag_leaf), publish_seq: SEQ, referenced: 4, owned: 4, retained_charge: 3,
            catalog_id_hwm: 2, ..SubvolRow::unpack(&table_items[0].1).unwrap()
        };

        let clear = |bitmap: &mut [u8], b: u64| bitmap[(b / 8) as usize] &= !(1 << (b % 8));
        let mark = |bitmap: &mut [u8], b: u64| bitmap[(b / 8) as usize] |= 1 << (b % 8);
        clear(&mut bitmap, old_table);
        for b in first..spare { mark(&mut bitmap, b); }

        let mut fixture = Fixture {
            directory, image, raw, sb, old_row, other_rows, old_table, old_data, new_data, item_new, table_new, registry, deadlog, spare, row, registry_items, bitmap,
            table_root: Pointer::NULL, registry_root: Pointer::NULL,
        };
        fixture.rebuild_roots();
        fixture
    }

    fn write(&mut self, nr: u64, data: &[u8]) { self.raw[nr as usize * BLOCK_SIZE..(nr as usize + 1) * BLOCK_SIZE].copy_from_slice(data); }

    fn block(&self, nr: u64) -> Vec<u8> { self.raw[nr as usize * BLOCK_SIZE..(nr as usize + 1) * BLOCK_SIZE].to_vec() }

    fn persist(&self) { std::fs::write(&self.image, &self.raw).unwrap(); }

    fn mark(&mut self, b: u64, present: bool) {
        if present { self.bitmap[(b / 8) as usize] |= 1 << (b % 8); } else { self.bitmap[(b / 8) as usize] &= !(1 << (b % 8)); }
    }

    /// Rebuild the table and registry leaves from the fixture's rows.
    fn rebuild_roots(&mut self) {
        let incarnation = self.sb.volume_incarnation;
        let node = move |tree| NodeMeta { owner: 0, birth: SEQ, tree, incarnation };
        let mut rows = vec![(Key::new(0, DEFAULT_SUBVOL, ITEM_SUBVOL, 0), self.row.pack())];
        rows.extend(self.other_rows.iter().cloned());
        rows.sort_by_key(|(key, _)| *key);
        let table = build_leaf(node(TREE_SUBVOL_TABLE), self.table_new, &rows).unwrap();
        self.table_root = pointer_to(self.table_new, SEQ, &table);
        self.write(self.table_new, &table);
        let mut items = self.registry_items.clone();
        items.sort_by_key(|(key, _)| *key);
        let registry = build_leaf(node(TREE_PIN_REGISTRY), self.registry, &items).unwrap();
        self.registry_root = pointer_to(self.registry, SEQ, &registry);
        self.write(self.registry, &registry);
    }

    fn snapshot_row(&self) -> SnapRow { SnapRow::unpack(&self.registry_items.iter().find(|(key, _)| key.ty == ITEM_SNAP).unwrap().1).unwrap() }

    fn set_snapshot_row(&mut self, row: SnapRow) {
        let slot = self.registry_items.iter_mut().find(|(key, _)| key.ty == ITEM_SNAP).unwrap();
        slot.1 = row.pack();
    }

    /// Land the second version as a clean checkpoint with an empty ring.
    fn checkpoint(&mut self) {
        let sb = Superblock {
            table_root: self.table_root, registry_root: self.registry_root, checkpoint_seq: SEQ, commit_seq: SEQ, replay_floor: SEQ, reserved_seq_hwm: SEQ + RESERVATION_WINDOW,
            last_write_time: 2, ..self.sb.clone()
        };
        let bytes = sb.pack();
        self.write(0, &bytes);
        self.write(1, &bytes);
        self.write(self.sb.total_blocks - 1, &bytes);
        let bitmap = self.bitmap.clone();
        self.write(self.sb.bitmap_start, &bitmap);
        self.persist();
    }

    /// Leave the second version in the ring as one certified atom above the
    /// writer's checkpoint: the bitmap page travels as a journaled image and
    /// the on-disk page stays the old one.
    fn dirty_log(&mut self, predecessor: [u8; 16]) -> u64 {
        let head = log::Head { kind: log::KIND_ATOM, incarnation: self.sb.volume_incarnation, cycle: self.sb.log_cycle, lsn: 0, seq: SEQ, fragment_index: 0, fragment_count: 1, predecessor };
        let image_tag = xxh3::hash128(&self.bitmap);
        let fragment = log::Fragment {
            images: vec![log::ImageEntry { address: self.sb.bitmap_start, birth: SEQ, tag: image_tag }],
            allocs: vec![
                log::AllocEntry { first: self.new_data, count: (self.spare - self.new_data) as u32, op: log::ALLOC_OP_ALLOCATE },
                log::AllocEntry { first: self.old_table, count: 1, op: log::ALLOC_OP_FREE },
            ],
            roots: vec![
                log::RootEntry { subvol: DEFAULT_SUBVOL, kind: log::ROOT_KIND_ITEM, pointer: self.row.item_root, identity: Some((self.row.objectid_hwm, self.row.incarnation_hwm, SEQ)) },
                log::RootEntry { subvol: DEFAULT_SUBVOL, kind: log::ROOT_KIND_TAG, pointer: self.row.tag_root, identity: None },
            ],
            charges: vec![log::ChargeEntry { subvol: DEFAULT_SUBVOL, referenced_delta: 0, owned_delta: 0, retained_delta: 3 }],
        };
        let record = log::encode_fragment(&head, &fragment).unwrap();
        let cert = log::Certificate {
            reserved_seq_hwm: self.sb.reserved_seq_hwm, fragment_count: 1, image_blocks: 1, first_lsn: 0, record_blocks: 3,
            digest: log::atom_digest(&[(record.clone(), vec![image_tag])]), table_root: self.table_root, registry_root: self.registry_root, commit_time: 2,
        };
        let cert_block = log::encode_certificate(&log::Head { lsn: 2, ..head }, &cert);
        let start = self.sb.log_start;
        self.write(start, &record);
        let bitmap = self.bitmap.clone();
        self.write(start + 1, &bitmap);
        self.write(start + 2, &cert_block);
        let sb = Superblock { state: STATE_DIRTY, log_head: 3, ..self.sb.clone() };
        let bytes = sb.pack();
        self.write(0, &bytes);
        self.write(1, &bytes);
        self.write(self.sb.total_blocks - 1, &bytes);
        self.persist();
        start + 2
    }
}

#[test]
fn required_saltyfs_snapshot_retains_roots_and_accounting_is_from_the_model() {
    let mut fixture = Fixture::new("roots", 8192);
    fixture.checkpoint();
    assert_eq!(errors(&fixture.image), "");
    let usage = read::accounting(&fixture.image, None).unwrap();
    assert_eq!((usage.live, usage.snapshots, usage.registry, usage.combined), (4 + STORE_BLOCKS, 4, 3, 4 + STORE_BLOCKS + 3 + 3));
    assert_eq!(usage.reserved, 2 + 1 + 32 + 1);
    assert_eq!(usage.expected_used, usage.combined + usage.reserved);
    assert_eq!(usage.capacity + usage.reserved + CLEANUP_BLOCKS, 256);
    let dump = read::dump_text(&fixture.image).unwrap();
    let mut current = vec![b'N'; BLOCK_SIZE];
    current.resize(8192, 0);
    assert!(dump.contains(&format!(
        "file /file mode=100644 uid=0 gid=0 nlink=1 size=8192 sha256={}",
        sha256::hash_bytes(&current)
    )), "{dump}");
    assert!(dump.contains("state=clean copies=identical replayed=0"));
    assert!(dump.contains("subvolume 1 incarnation="));
    assert!(dump.contains("publish-seq=2 origin=0:0 owner=0:0 limits=[0, 0, 0, 0] referenced=4 owned=4 retained=3"), "{dump}");
    assert!(dump.contains("snapshot subvol=1 epoch=1 id=1 owner=0:0 deleting=false sealed=false"));
    assert!(dump.contains(&format!(
        "  file /file mode=100644 size=4096 sha256={} target=",
        sha256::hash_bytes(&vec![b'A'; BLOCK_SIZE])
    )));
    assert!(!dump.contains("ERROR"), "{dump}");
}

#[test]
fn required_saltyfs_verification_does_not_materialize_sparse_contents() {
    let mut fixture = Fixture::new("sparse", 16 * 1024 * 1024 * 1024);
    fixture.checkpoint();
    assert_eq!(errors(&fixture.image), "");
    assert_eq!(read::accounting(&fixture.image, None).unwrap().combined, 4 + STORE_BLOCKS + 3 + 3);
}

#[test]
fn required_saltyfs_retained_bitmap_bit_cannot_be_treated_as_free() {
    let mut fixture = Fixture::new("bitmap", 8192);
    fixture.checkpoint();
    let bit = fixture.old_data as usize;
    fixture.raw[fixture.sb.bitmap_start as usize * BLOCK_SIZE + bit / 8] &= !(1 << (bit % 8));
    fixture.persist();
    let before = fixture.raw.clone();
    assert!(errors(&fixture.image).contains("bitmap misses 1 reachable"));
    assert!(read::accounting(&fixture.image, None).is_err());
    assert_eq!(std::fs::read(&fixture.image).unwrap(), before, "verification cannot repair away a retained obligation");
}

#[test]
fn required_saltyfs_deadlog_and_retirement_entries_are_allocated_off_every_root() {
    let mut fixture = Fixture::new("deadlog", 8192);
    let extra = fixture.spare;
    let retire_log = fixture.spare + 1;
    let retired = fixture.spare + 2;
    // A block only a snapshot's deadlog names.
    let mut snap = fixture.snapshot_row();
    let incarnation = fixture.sb.volume_incarnation;
    let leaf = deadlog_leaf(incarnation, fixture.deadlog, &[(SEQ, fixture.old_data, 1, INITIAL_SEQ), (SEQ, extra, 1, INITIAL_SEQ)]);
    fixture.write(fixture.deadlog, &leaf);
    snap.deadlog_root = pointer_to(fixture.deadlog, SEQ, &leaf);
    fixture.set_snapshot_row(snap);
    // A block only the subvolume's retirement log names.
    let retire_leaf = deadlog_leaf(incarnation, retire_log, &[(SEQ, retired, 1, SEQ)]);
    fixture.write(retire_log, &retire_leaf);
    let mut retire = pointer_to(retire_log, SEQ, &retire_leaf).pack().to_vec();
    retire.extend_from_slice(&0u64.to_le_bytes());
    retire.extend_from_slice(&1u64.to_le_bytes());
    fixture.registry_items.push((Key::new(DEFAULT_SUBVOL, 0, ITEM_RETIRE, 0), retire));
    fixture.row.retained_charge = 5;
    for b in [extra, retire_log, retired] { fixture.mark(b, true); }
    fixture.rebuild_roots();
    fixture.checkpoint();
    assert_eq!(errors(&fixture.image), "");
    let usage = read::accounting(&fixture.image, None).unwrap();
    assert_eq!((usage.snapshots, usage.registry, usage.combined), (6, 4, 4 + STORE_BLOCKS + 5 + 4));
    assert!(read::dump_text(&fixture.image).unwrap().contains("retirement subvol=1 pending=1"));

    fixture.mark(extra, false);
    fixture.mark(retired, false);
    fixture.checkpoint();
    assert!(errors(&fixture.image).contains("bitmap misses 2 reachable"));

    // The retirement row's pending count is bound to its chain.
    fixture.mark(extra, true);
    fixture.mark(retired, true);
    let slot = fixture.registry_items.iter_mut().find(|(key, _)| key.ty == ITEM_RETIRE).unwrap();
    put64(&mut slot.1, POINTER_SIZE + 8, 2);
    fixture.rebuild_roots();
    fixture.checkpoint();
    assert!(errors(&fixture.image).contains("pending count disagrees"));
}

#[test]
fn required_saltyfs_replay_applies_the_journaled_bitmap_and_the_certified_roots() {
    let mut fixture = Fixture::new("replay", 8192);
    let sb = fixture.sb.clone();
    fixture.dirty_log(sb.last_certificate);
    // The home copy has not happened: the on-disk page still misses the new blocks.
    let page = fixture.block(sb.bitmap_start);
    assert_eq!(page[(fixture.item_new / 8) as usize] & (1 << (fixture.item_new % 8)), 0);
    assert_eq!(read::verify(&fixture.image).unwrap(), vec!["log dirty: 1 certified atoms above the checkpoint".to_string()]);
    assert_eq!(read::uncheckpointed_atoms(&fixture.image).unwrap(), 1);
    let dump = read::dump_text(&fixture.image).unwrap();
    assert!(dump.contains("state=dirty copies=identical replayed=1"));
    assert!(dump.contains("snapshot subvol=1 epoch=1 id=1"));
    assert!(dump.contains("publish-seq=2"));
    assert!(!dump.contains("ERROR"), "{dump}");
}

#[test]
fn required_saltyfs_torn_certificate_leaves_the_checkpoint_state() {
    let mut fixture = Fixture::new("torn", 8192);
    let sb = fixture.sb.clone();
    let cert = fixture.dirty_log(sb.last_certificate);
    fixture.write(cert, &vec![0u8; BLOCK_SIZE]);
    fixture.persist();
    assert_eq!(read::uncheckpointed_atoms(&fixture.image).unwrap(), 0);
    assert_eq!(read::verify(&fixture.image).unwrap(), vec!["log dirty: 0 certified atoms above the checkpoint".to_string()]);
    let dump = read::dump_text(&fixture.image).unwrap();
    assert!(dump.contains("replayed=0"));
    assert!(!dump.contains("snapshot subvol="));
    assert!(dump.contains("publish-seq=1"));
}

#[test]
fn required_saltyfs_image_tag_mismatch_discards_the_whole_set() {
    let mut fixture = Fixture::new("image-tag", 8192);
    let sb = fixture.sb.clone();
    fixture.dirty_log(sb.last_certificate);
    fixture.raw[(sb.log_start as usize + 1) * BLOCK_SIZE + 9] ^= 0x80;
    fixture.persist();
    assert_eq!(read::uncheckpointed_atoms(&fixture.image).unwrap(), 0);
    let errors = read::verify(&fixture.image).unwrap();
    assert_eq!(errors, vec!["log dirty: 0 certified atoms above the checkpoint".to_string()], "an incomplete set is ignored, not reported");
}

#[test]
fn required_saltyfs_certified_atom_off_the_chain_is_reported_not_applied() {
    let mut fixture = Fixture::new("chain", 8192);
    fixture.dirty_log([0x5A; 16]);
    assert_eq!(read::uncheckpointed_atoms(&fixture.image).unwrap(), 0);
    let errors = errors(&fixture.image);
    assert!(errors.contains("certified atom 2 is not reachable from the checkpoint chain"), "{errors}");
}

#[test]
fn required_saltyfs_birth_above_publish_sequence_is_refused() {
    let mut fixture = Fixture::new("birth", 8192);
    fixture.row.publish_seq = INITIAL_SEQ;
    fixture.rebuild_roots();
    fixture.checkpoint();
    let error = errors(&fixture.image);
    assert!(error.contains("birth 2 above its parent's 1"), "{error}");

    let mut fixture = Fixture::new("epoch", 8192);
    let mut snap = fixture.snapshot_row();
    snap.item_root = fixture.row.item_root;
    fixture.set_snapshot_row(snap);
    fixture.rebuild_roots();
    fixture.checkpoint();
    let error = errors(&fixture.image);
    assert!(error.contains("birth 2 above its parent's 1"), "{error}");
}

#[test]
fn required_saltyfs_snapshot_identity_marks_fail_closed() {
    for (tag, edit) in [
        ("id-hwm", (|snap: &mut SnapRow| snap.snapshot_id = 2) as fn(&mut SnapRow)),
        ("state", |snap| snap.state = SNAP_STATE_SEALING),
        ("objectid-hwm", |snap| snap.objectid_hwm = 1),
        ("owner-half", |snap| snap.owner = (7, 0)),
        ("cursor", |snap| snap.deadlog_cursor = 4),
        ("commit-without-seal", |snap| snap.commit_name = [1; 32]),
    ] {
        let mut fixture = Fixture::new(tag, 8192);
        let mut snap = fixture.snapshot_row();
        edit(&mut snap);
        fixture.registry_items[0].1 = snap.pack();
        fixture.rebuild_roots();
        fixture.checkpoint();
        assert!(!errors(&fixture.image).is_empty(), "{tag}");
    }
}

#[test]
fn required_saltyfs_duplicate_or_misordered_keys_are_refused() {
    let mut fixture = Fixture::new("dup", 8192);
    let node = NodeMeta { owner: 0, birth: SEQ, tree: TREE_PIN_REGISTRY, incarnation: fixture.sb.volume_incarnation };
    let item = fixture.registry_items[0].clone();
    let leaf = build_leaf(node, fixture.registry, &[item.clone(), item]).unwrap();
    fixture.write(fixture.registry, &leaf);
    fixture.registry_root = pointer_to(fixture.registry, SEQ, &leaf);
    fixture.checkpoint();
    let error = errors(&fixture.image);
    assert!(error.contains("invalid key order"), "{error}");
}

#[test]
fn required_saltyfs_leaf_payload_geometry_is_validated_before_decoding() {
    for malformed_count in [false, true] {
        let mut fixture = Fixture::new(if malformed_count { "count" } else { "overlap" }, 8192);
        let mut leaf = fixture.block(fixture.old_row.item_root.address);
        if malformed_count {
            put32(&mut leaf, 0x04, u32::MAX);
        } else {
            let first = get32(&leaf, NODE_HEADER_SIZE + KEY_SIZE);
            put32(&mut leaf, NODE_HEADER_SIZE + LEAF_ENTRY_SIZE + KEY_SIZE, first);
        }
        fixture.write(fixture.old_row.item_root.address, &leaf);
        let mut snap = fixture.snapshot_row();
        snap.item_root = pointer_to(fixture.old_row.item_root.address, INITIAL_SEQ, &leaf);
        fixture.set_snapshot_row(snap);
        fixture.rebuild_roots();
        fixture.checkpoint();
        let error = errors(&fixture.image);
        assert!(error.contains(if malformed_count { "invalid entry count" } else { "overlapping leaf payload" }), "{error}");
    }
}

#[test]
fn required_saltyfs_rejects_cycles_and_shared_children_within_a_root() {
    let mut fixture = Fixture::new("shared-child", 8192);
    let parent = fixture.spare;
    let node = NodeMeta { owner: 0, birth: SEQ, tree: TREE_PIN_REGISTRY, incarnation: fixture.sb.volume_incarnation };
    let leaf_key = fixture.registry_items[0].0;
    let internal = build_internal(node, parent, 1, &[
        (leaf_key, fixture.registry_root),
        (Key::new(leaf_key.locality, leaf_key.objectid + 1, leaf_key.ty, 0), fixture.registry_root),
    ]).unwrap();
    fixture.write(parent, &internal);
    fixture.registry_root = pointer_to(parent, SEQ, &internal);
    fixture.mark(parent, true);
    fixture.checkpoint();
    let error = errors(&fixture.image);
    assert!(error.contains("cycle or shared child"), "{error}");

    let cycle = build_internal(node, parent, 1, &[(leaf_key, Pointer { address: parent, birth: SEQ, tag: [0; 16] })]).unwrap();
    fixture.write(parent, &cycle);
    fixture.registry_root = pointer_to(parent, SEQ, &cycle);
    fixture.checkpoint();
    let error = errors(&fixture.image);
    assert!(error.contains("cycle or shared child") || error.contains("tag mismatch"), "{error}");
}

#[test]
fn required_saltyfs_newest_checkpoint_wins_and_divergence_is_reported() {
    let mut fixture = Fixture::new("copies", 8192);
    let original = fixture.block(0);
    fixture.checkpoint();
    fixture.write(0, &original);
    fixture.persist();
    let dump = read::dump_text(&fixture.image).unwrap();
    assert!(dump.contains("snapshot subvol=1 epoch=1"), "the newer checkpoint is the authority");
    assert!(dump.contains("copies=DIVERGED"));
    assert!(errors(&fixture.image).contains("superblock copies diverge"));
}

#[test]
fn required_saltyfs_builder_refuses_to_overwrite_pins_or_a_dirty_log() {
    let mut fixture = Fixture::new("overwrite", 8192);
    fixture.checkpoint();
    let pinned = fixture.raw.clone();
    assert!(build::build_to_file(&fixture.image, &image_spec(), &image_contents()).is_err());
    assert_eq!(std::fs::read(&fixture.image).unwrap(), pinned);
    // An invalid copy never hides a valid one that carries pins.
    fixture.raw[SB_LABEL] ^= 1;
    fixture.persist();
    let damaged = fixture.raw.clone();
    assert!(build::build_to_file(&fixture.image, &image_spec(), &image_contents()).is_err());
    assert_eq!(std::fs::read(&fixture.image).unwrap(), damaged);

    let mut fixture = Fixture::new("overwrite-dirty", 8192);
    let sb = fixture.sb.clone();
    fixture.dirty_log(sb.last_certificate);
    let dirty = fixture.raw.clone();
    assert!(build::build_to_file(&fixture.image, &image_spec(), &image_contents()).is_err());
    assert_eq!(std::fs::read(&fixture.image).unwrap(), dirty);

    // A clean volume without pins is replaced, byte for byte reproducibly.
    let fresh = fixture.directory.join("fresh");
    build::build_to_file(&fresh, &image_spec(), &image_contents()).unwrap();
    let before = std::fs::read(&fresh).unwrap();
    build::build_to_file(&fresh, &image_spec(), &image_contents()).unwrap();
    assert_eq!(std::fs::read(&fresh).unwrap(), before);
    assert_eq!(errors(&fresh), "");
}

#[test]
fn required_saltyfs_charges_and_limits_are_checked_per_subvolume() {
    let mut fixture = Fixture::new("charges", 8192);
    fixture.row.referenced = 9;
    fixture.rebuild_roots();
    fixture.checkpoint();
    assert!(errors(&fixture.image).contains("referenced 9 disagrees with reachable 4"));

    let mut fixture = Fixture::new("retained", 8192);
    fixture.row.retained_charge = 2;
    fixture.rebuild_roots();
    fixture.checkpoint();
    assert!(errors(&fixture.image).contains("retained charge 2 disagrees with retained 3"));

    let mut fixture = Fixture::new("quota", 8192);
    fixture.row.owner = (5, 1);
    fixture.row.limits = [6, 4, 0, 0];
    fixture.rebuild_roots();
    fixture.checkpoint();
    assert!(errors(&fixture.image).contains("quota, refquota, reservation or refreservation violated"));
    fixture.row.limits = [7, 4, 0, 0];
    fixture.rebuild_roots();
    fixture.checkpoint();
    assert_eq!(errors(&fixture.image), "");
}
