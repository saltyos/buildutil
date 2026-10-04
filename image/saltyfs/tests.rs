//! SPDX-License-Identifier: GPL-2.0-only
//! flake — SaltyFS format 2 conformance tests over the writer, the codecs,
//! the cryptographic primitives, the sealer and the reader.

use super::cpio::Permissions;
use super::primitives::{aes, argon2, blake3, chacha, from_hex, hex, siphash24, Suite};
use super::*;
use std::path::PathBuf;

fn tmp(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("flake-saltyfs-{}-{}", tag, std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn spec(size: u64) -> FsSpec {
    FsSpec { size_bytes: size, label: "rootfs".to_string(), epoch_secs: 1, clock_valid: true, casefold_root: false, extra_incompat: 0, compat_ro_flags: 0, casefold_version: 0 }
}

fn big_pattern() -> Vec<u8> { (0..20_000u32).map(|i| (i % 251) as u8).collect() }

fn contents() -> Contents {
    let mut permissions = Permissions::new();
    permissions.insert("/bin/init".to_string(), (S_IFREG | 0o755, 0, 0));
    Contents {
        files: vec![
            ("etc/hostname".to_string(), FileSource::Bytes(b"salty\n".to_vec())),
            ("bin/init".to_string(), FileSource::Bytes(big_pattern())),
            ("usr/lib/libc.so".to_string(), FileSource::Bytes(vec![0x7F, b'E', b'L', b'F'])),
        ],
        empty_dirs: vec!["/dev".to_string(), "/var/log".to_string()],
        symlinks: vec![("bin/sh".to_string(), b"/bin/init".to_vec())],
        directory_links: vec![],
        permissions,
    }
}

fn passphrase() -> Unlock { Unlock::Passphrase { passphrase: b"correct horse".to_vec(), memory_kib: 256, iterations: 2, lanes: 1 } }

/// The suites this host runs, with the name the dump prints: the AES suite
/// only on a host with its instructions, where any other host refuses it.
fn host_suites() -> Vec<(Suite, &'static str)> {
    match Suite::xaes() {
        Ok(xaes) => vec![(Suite::XChaCha20Poly1305, "xchacha20-poly1305"), (xaes, "xaes-256-gcm")],
        Err(_) => {
            assert!(Suite::from_word(2).is_err(), "a host without the instructions refuses the AES suite");
            vec![(Suite::XChaCha20Poly1305, "xchacha20-poly1305")]
        }
    }
}

fn plain_keys() -> Keys { Keys::plain([7; 16], &[9; 32]) }

fn h(text: &str) -> Vec<u8> { from_hex(text).unwrap() }

fn key32(text: &str) -> [u8; 32] { h(text).try_into().unwrap() }

// ---------------------------------------------------------------------------
// Images
// ---------------------------------------------------------------------------

#[test]
fn build_verify_dump_roundtrip() {
    let dir = tmp("roundtrip");
    let img = dir.join("rootfs.img");
    let stats = build::build_to_file(&img, &spec(8 * 1024 * 1024), &contents()).unwrap();
    assert!(stats.used_blocks <= stats.total_blocks);

    let raw = std::fs::read(&img).unwrap();
    assert_eq!(&raw[..8], MAGIC);
    assert_eq!(get32(&raw, SB_LAYOUT), LAYOUT);
    assert_eq!(get32(&raw, SB_STATE), STATE_CLEAN);
    assert_eq!(get32(&raw, SB_SUITE), SUITE_PLAIN);
    assert_eq!(get64(&raw, SB_CHECKPOINT_SEQ), 1);
    assert_eq!(get64(&raw, SB_COMMIT_SEQ), get64(&raw, SB_REPLAY_FLOOR));
    assert_eq!(get64(&raw, SB_RESERVED_SEQ_HWM), 1 + RESERVATION_WINDOW);
    let sb = Superblock::parse(&raw[..BLOCK_SIZE]).unwrap();
    assert_eq!(sb.total_blocks, 2048);
    assert_eq!((sb.keyslot_start, sb.keyslot_blocks, sb.bitmap_start, sb.bitmap_blocks, sb.log_start, sb.log_blocks), (0, 0, 2, 1, 3, 256));
    assert_eq!(sb.registry_root, Pointer::NULL);
    assert_eq!(sb.table_root.birth, INITIAL_SEQ);
    assert_eq!(sb.store_public_key, [0; 32]);
    assert!(sb.chunker.valid());
    assert_eq!(&raw[BLOCK_SIZE..2 * BLOCK_SIZE], &raw[..BLOCK_SIZE]);
    assert_eq!(&raw[raw.len() - BLOCK_SIZE..], &raw[..BLOCK_SIZE]);
    // The ring is zero: a clean checkpoint with nothing to replay.
    let ring = &raw[sb.log_start as usize * BLOCK_SIZE..(sb.log_start + sb.log_blocks) as usize * BLOCK_SIZE];
    assert!(ring.iter().all(|b| *b == 0));
    // A plain volume's tree nodes are in the clear.
    assert_eq!(&raw[sb.table_root.address as usize * BLOCK_SIZE..][..4], NODE_MAGIC);

    assert_eq!(read::verify(&img).unwrap(), Vec::<String>::new());
    assert_eq!(read::uncheckpointed_atoms(&img).unwrap(), 0);

    let dump = read::dump_text(&img).unwrap();
    assert!(dump.starts_with("saltyfs layout=2 label=rootfs block-size=4096"), "{dump}");
    assert!(dump.contains("suite=plain state=clean copies=identical replayed=0"));
    assert!(dump.contains("dir /bin mode=40755"));
    assert!(dump.contains("dir /var/log mode=40755"));
    assert!(dump.contains("file /bin/init mode=100755 uid=0 gid=0 nlink=1 size=20000"));
    assert!(dump.contains(&format!(
        "file /etc/hostname mode=100644 uid=0 gid=0 nlink=1 size=6 sha256={}",
        sha256::hash_bytes(b"salty\n")
    )));
    assert!(dump.contains("symlink /bin/sh -> /bin/init mode=120777"));
    // Root nlink: "." + ".." + {bin, dev, etc, usr, var}.
    assert!(dump.contains("dir / mode=40755 uid=0 gid=0 nlink=7"));
    assert!(dump.contains("subvolume 1 incarnation="));
    assert!(dump.contains("publish-seq=1 origin=0:0 owner=0:0 limits=[0, 0, 0, 0] referenced="));
    assert!(dump.contains("label=key-tree"));
    assert!(dump.contains("label=store"));
    assert!(!dump.contains("ERROR"), "{dump}");

    let accounting = read::accounting(&img, None).unwrap();
    assert_eq!(accounting.snapshots, 0);
    assert_eq!(accounting.registry, 1, "the table leaf is volume overhead");
    assert_eq!(accounting.live + accounting.registry, accounting.combined);
    assert_eq!(accounting.reserved, 2 + 1 + 256 + 1);
    assert_eq!(accounting.expected_used, stats.used_blocks + 1);
    assert_eq!(accounting.capacity, 2048 - accounting.reserved - CLEANUP_BLOCKS);
    assert_eq!(accounting.store_data, 0);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn encrypted_image_roundtrip_under_both_suites() {
    let dir = tmp("encrypted");
    for (suite, name) in host_suites() {
        let img = dir.join(format!("{name}.img"));
        let options = Options { suite: Some(suite), unlock: Some(passphrase()), compression: COMPRESSION_NONE, seal: false };
        build::build_to_file_with(&img, &spec(8 * 1024 * 1024), &contents(), &options).unwrap();
        let raw = std::fs::read(&img).unwrap();
        let sb = Superblock::parse(&raw[..BLOCK_SIZE]).unwrap();
        assert_eq!(sb.suite, suite.word());
        assert_eq!((sb.keyslot_start, sb.keyslot_blocks, sb.bitmap_start, sb.bitmap_blocks, sb.log_start, sb.log_blocks), (2, 8, 10, 1, 11, 256));
        // Slot 0 enrolls the passphrase; the others are empty; nodes are sealed.
        assert_eq!(get32(&raw, 2 * BLOCK_SIZE), KEYSLOT_KIND_PASSPHRASE);
        assert!(raw[3 * BLOCK_SIZE..10 * BLOCK_SIZE].iter().all(|b| *b == 0));
        assert_ne!(&raw[sb.table_root.address as usize * BLOCK_SIZE..][..4], NODE_MAGIC);
        assert!(!raw.windows(6).any(|w| w == b"salty\n"), "file content is not in the clear");

        let unlock = passphrase();
        assert_eq!(read::verify_with(&img, Some(&unlock)).unwrap(), Vec::<String>::new());
        let dump = read::dump_text_with(&img, Some(&unlock)).unwrap();
        assert!(dump.contains(&format!("suite={name} state=clean")), "{dump}");
        assert!(dump.contains(&format!(
            "file /etc/hostname mode=100644 uid=0 gid=0 nlink=1 size=6 sha256={}",
            sha256::hash_bytes(b"salty\n")
        )));
        assert!(dump.contains(&format!(
            "size=20000 sha256={}", sha256::hash_bytes(&big_pattern())
        )));
        assert!(!dump.contains("ERROR"), "{dump}");

        let error = read::verify(&img).unwrap_err();
        assert!(error.contains("encrypted"), "{error}");
        let wrong = Unlock::Passphrase { passphrase: b"incorrect horse".to_vec(), memory_kib: 256, iterations: 2, lanes: 1 };
        assert!(read::verify_with(&img, Some(&wrong)).unwrap_err().contains("opens no keyslot"));

        // A flipped byte in a sealed node fails authentication, not parsing.
        let mut damaged = raw.clone();
        damaged[sb.table_root.address as usize * BLOCK_SIZE + 0x200] ^= 1;
        std::fs::write(&img, &damaged).unwrap();
        assert!(read::verify_with(&img, Some(&unlock)).unwrap_err().contains("tag mismatch"));
    }
    // A raw volume key builds no keyslot and opens with the same key.
    let img = dir.join("volume-key.img");
    let key = [0x42u8; 32];
    let options = Options { suite: Some(Suite::XChaCha20Poly1305), unlock: Some(Unlock::VolumeKey(key)), compression: COMPRESSION_NONE, seal: false };
    build::build_to_file_with(&img, &spec(8 * 1024 * 1024), &contents(), &options).unwrap();
    let raw = std::fs::read(&img).unwrap();
    assert!(raw[2 * BLOCK_SIZE..10 * BLOCK_SIZE].iter().all(|b| *b == 0));
    assert_eq!(read::verify_with(&img, Some(&Unlock::VolumeKey(key))).unwrap(), Vec::<String>::new());
    assert!(read::verify_with(&img, Some(&Unlock::VolumeKey([1; 32]))).unwrap_err().contains("tag mismatch"));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn compressed_images_store_fewer_blocks_and_read_back_the_same_bytes() {
    let dir = tmp("compressed");
    let plain = dir.join("plain.img");
    let plain_stats = build::build_to_file(&plain, &spec(8 * 1024 * 1024), &contents()).unwrap();
    for (codec, name) in [(COMPRESSION_LZ4, "lz4"), (COMPRESSION_ZSTD, "zstd")] {
        let img = dir.join(format!("{name}.img"));
        let options = Options { suite: None, unlock: None, compression: codec, seal: false };
        let stats = build::build_to_file_with(&img, &spec(8 * 1024 * 1024), &contents(), &options).unwrap();
        assert!(stats.used_blocks < plain_stats.used_blocks, "{name}: {} < {}", stats.used_blocks, plain_stats.used_blocks);
        assert_eq!(read::verify(&img).unwrap(), Vec::<String>::new(), "{name}");
        let dump = read::dump_text(&img).unwrap();
        assert!(dump.contains(&format!(
            "file /bin/init mode=100755 uid=0 gid=0 nlink=1 size=20000 sha256={}",
            sha256::hash_bytes(&big_pattern())
        )), "{dump}");
        assert!(!dump.contains("ERROR"), "{dump}");
    }
    // Incompressible units stay plain even under a compression plugin.
    let keys = plain_keys();
    let noise: Vec<u8> = (0..BLOCK_SIZE as u32 * 3).map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8).collect();
    let files = Contents {
        files: vec![("noise".into(), FileSource::Bytes(noise)), ("zeros".into(), FileSource::Bytes(vec![0; 3 * BLOCK_SIZE]))],
        empty_dirs: vec![], symlinks: vec![], directory_links: vec![], permissions: Permissions::new(),
    };
    let meta = build::build_metadata(&build::SubvolInputs { subvol: DEFAULT_SUBVOL, contents: &files, root_case_axis: AXIS_SENSITIVE, compression: COMPRESSION_LZ4,
        time_ns: 1, keys: &keys, first_data_block: 100, birth: INITIAL_SEQ }).unwrap();
    let extents: Vec<&Vec<u8>> = meta.items.iter().filter(|(k, _)| k.ty == ITEM_EXTENT_DATA).map(|(_, v)| v).collect();
    assert_eq!(extents.len(), 2);
    let compressions: Vec<u8> = extents.iter().map(|e| e[0x21]).collect();
    assert!(compressions.contains(&COMPRESSION_NONE) && compressions.contains(&COMPRESSION_LZ4), "{compressions:?}");
    for extent in extents {
        if extent[0x21] == COMPRESSION_LZ4 { assert_eq!(get64(extent, 0x18), BLOCK_SIZE as u64); } else { assert_eq!(get64(extent, 0x18), 3 * BLOCK_SIZE as u64); }
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn sealed_image_carries_a_signed_commit_the_store_resolves() {
    let dir = tmp("sealed");
    let img = dir.join("sealed.img");
    let options = Options { suite: None, unlock: None, compression: COMPRESSION_NONE, seal: true };
    build::build_to_file_with(&img, &spec(16 * 1024 * 1024), &contents(), &options).unwrap();
    assert_eq!(read::verify(&img).unwrap(), Vec::<String>::new());
    let dump = read::dump_text(&img).unwrap();
    assert!(dump.contains("snapshot subvol=1 epoch=1 id=1 owner=1:1 deleting=false sealed=true"), "{dump}");
    assert!(dump.contains(&format!(
        "  file /bin/init mode=100755 size=20000 sha256={}",
        sha256::hash_bytes(&big_pattern())
    )));
    assert!(!dump.contains("sealed-head=0000000000000000000000000000000000000000000000000000000000000000 label=rootfs"), "{dump}");
    assert!(!dump.contains("ERROR"), "{dump}");
    let accounting = read::accounting(&img, None).unwrap();
    assert!(accounting.store_data > 0);
    assert_eq!(accounting.registry, 2, "table and registry leaves");
    let raw = std::fs::read(&img).unwrap();
    let sb = Superblock::parse(&raw[..BLOCK_SIZE]).unwrap();
    assert_ne!(sb.store_public_key, [0; 32]);
    assert!(sb.registry_root.address != 0);

    // A byte of the pack flips: the object no longer decodes to its name.
    let mut damaged = raw.clone();
    let pack_block = (0..sb.total_blocks as usize).find(|b| &damaged[b * BLOCK_SIZE..b * BLOCK_SIZE + 4] == seal::PACK_MAGIC).unwrap();
    damaged[pack_block * BLOCK_SIZE + seal::PACK_HEADER_SIZE + seal::PACK_ENTRY_HEADER_SIZE + 3] ^= 1;
    std::fs::write(&img, &damaged).unwrap();
    let outcome = read::verify(&img);
    assert!(outcome.is_err() || !outcome.unwrap().is_empty(), "a damaged store object is reported");

    // Encrypted, compressed and sealed together.
    let img = dir.join("all.img");
    let suite = host_suites().last().map(|(suite, _)| *suite);
    let options = Options { suite, unlock: Some(passphrase()), compression: COMPRESSION_ZSTD, seal: true };
    build::build_to_file_with(&img, &spec(16 * 1024 * 1024), &contents(), &options).unwrap();
    let unlock = passphrase();
    assert_eq!(read::verify_with(&img, Some(&unlock)).unwrap(), Vec::<String>::new());
    let dump = read::dump_text_with(&img, Some(&unlock)).unwrap();
    assert!(dump.contains("sealed=true"), "{dump}");
        assert!(dump.contains(&format!(
            "size=20000 sha256={}", sha256::hash_bytes(&big_pattern())
        )));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn inode_layout_is_exactly_128_bytes() {
    let incarnation = 0x0102_0304_0506_0708;
    let flags = INODE_CASEFOLD | (AXIS_INSENSITIVE as u32) << INODE_CASE_AXIS_SHIFT;
    let inode = pack_inode(
        &InodeFields { size: 7, blocks: 0, nlink: 1, owner: 0x0100_0000_0000_0005, group: 0x0200_0000_0000_0006, mode: S_IFDIR | 0o700, time_ns: 9, incarnation, flags,
            hidden_owner: 3, plugin: [DIR_HASH_SIPHASH, 0, COMPRESSION_ZSTD, 0], project_id: 77 },
        42,
    );
    assert_eq!(inode.len(), INODE_SIZE);
    assert_eq!(get64(&inode, 0x00), 42);
    assert_eq!(get64(&inode, 0x08), 7);
    assert_eq!(get64(&inode, 0x18), 0x0100_0000_0000_0005);
    assert_eq!(get64(&inode, 0x28), 9);
    assert_eq!(get64(&inode, 0x40), 9);
    assert_eq!(get64(&inode, 0x48), incarnation);
    assert_eq!(get64(&inode, 0x50), 42);
    assert_eq!(get64(&inode, 0x58), 42);
    assert_eq!(get64(&inode, 0x60), 3);
    assert_eq!(get32(&inode, 0x68), S_IFDIR | 0o700);
    assert_eq!(get32(&inode, 0x6C), 1);
    assert_eq!(get32(&inode, 0x70), flags);
    assert_eq!(&inode[0x74..0x78], &[DIR_HASH_SIPHASH, 0, COMPRESSION_ZSTD, 0]);
    assert_eq!(get32(&inode, 0x78), 77);
    assert!(inode[0x7C..0x80].iter().all(|byte| *byte == 0));
    let parsed = read::parse_inode(&inode).unwrap();
    assert_eq!((parsed.uid, parsed.gid, parsed.size, parsed.incarnation, parsed.project_id), (5, 6, 7, incarnation, 77));
    assert_eq!(parsed.plugin[PLUGIN_COMPRESSION], COMPRESSION_ZSTD);
    let mut bad = inode.clone();
    put32(&mut bad, 0x70, 1 << 20);
    assert!(read::parse_inode(&bad).unwrap_err().contains("undefined flag"));
    let mut bad = inode.clone();
    bad[0x76] = 9;
    assert!(read::parse_inode(&bad).unwrap_err().contains("unsupported plugin"));
}

#[test]
fn inode_axes_casefold_and_storage_flags_are_checked() {
    let inode = |mode: u32, flags: u32| {
        pack_inode(
            &InodeFields { size: 0, blocks: 0, nlink: 1, owner: 0x0100_0000_0000_0000, group: 0x0200_0000_0000_0000, mode, time_ns: 1, incarnation: 1, flags,
                hidden_owner: 0, plugin: [0; 4], project_id: 0 },
            1,
        )
    };
    let dir = S_IFDIR | 0o755;
    let file = S_IFREG | 0o644;
    let error = |mode: u32, flags: u32| read::parse_inode(&inode(mode, flags)).err().unwrap_or_default();

    // A directory may take any defined axis, CASEFOLD following the case axis.
    for case in [AXIS_SENSITIVE, AXIS_INSENSITIVE, AXIS_MIXED] {
        for norm in [AXIS_SENSITIVE, AXIS_INSENSITIVE, AXIS_MIXED] {
            assert!(read::parse_inode(&inode(dir, axis_flags(case, norm))).is_ok(), "axes {case}/{norm}");
        }
    }
    // Axis value 3 is undefined on either axis.
    assert!(error(dir, INODE_CASEFOLD | 3 << INODE_CASE_AXIS_SHIFT).contains("undefined case or normalization axis"));
    assert!(error(dir, 3 << INODE_NORM_AXIS_SHIFT).contains("undefined case or normalization axis"));
    // CASEFOLD is exactly the projection of a non-sensitive case axis.
    assert!(error(dir, INODE_CASEFOLD).contains("CASEFOLD"));
    assert!(error(dir, (AXIS_INSENSITIVE as u32) << INODE_CASE_AXIS_SHIFT).contains("CASEFOLD"));
    // A non-directory is sensitive on both axes.
    assert!(error(file, axis_flags(AXIS_INSENSITIVE, AXIS_SENSITIVE)).contains("not a directory"));
    assert!(error(S_IFLNK | 0o777, axis_flags(AXIS_SENSITIVE, AXIS_MIXED)).contains("not a directory"));
    assert!(read::parse_inode(&inode(file, 0)).is_ok());
    // HIDDEN and RETAINED never meet on one inode.
    assert!(read::parse_inode(&inode(file, INODE_HIDDEN)).is_ok());
    assert!(read::parse_inode(&inode(file, INODE_RETAINED)).is_ok());
    assert!(error(file, INODE_HIDDEN | INODE_RETAINED).contains("both hidden and retained"));
}

#[test]
fn deterministic_bytes() {
    let dir = tmp("det");
    let a = dir.join("a.img");
    let b = dir.join("b.img");
    build::build_to_file(&a, &spec(4 * 1024 * 1024), &contents()).unwrap();
    build::build_to_file(&b, &spec(4 * 1024 * 1024), &contents()).unwrap();
    assert_eq!(std::fs::read(&a).unwrap(), std::fs::read(&b).unwrap());
    let options = Options { suite: Some(Suite::XChaCha20Poly1305), unlock: Some(passphrase()), compression: COMPRESSION_LZ4, seal: true };
    build::build_to_file_with(&a, &spec(8 * 1024 * 1024), &contents(), &options).unwrap();
    build::build_to_file_with(&b, &spec(8 * 1024 * 1024), &contents(), &options).unwrap();
    assert_eq!(std::fs::read(&a).unwrap(), std::fs::read(&b).unwrap());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn corruption_detected() {
    let dir = tmp("corrupt");
    let img = dir.join("x.img");
    build::build_to_file(&img, &spec(4 * 1024 * 1024), &contents()).unwrap();
    let pristine = std::fs::read(&img).unwrap();

    // One byte inside the label of copy A: A fails its tag, B and C carry on.
    let mut raw = pristine.clone();
    raw[SB_LABEL + 1] ^= 0xFF;
    std::fs::write(&img, &raw).unwrap();
    let errors = read::verify(&img).unwrap();
    assert!(errors.iter().any(|e| e.contains("superblock A: superblock tag mismatch")), "{errors:?}");
    assert!(errors.iter().any(|e| e.contains("superblock copies diverge")));
    assert!(read::dump_text(&img).unwrap().contains("copies=DIVERGED"));

    // One byte inside a data block: the data-tag tree names it.
    let sb = Superblock::parse(&pristine[..BLOCK_SIZE]).unwrap();
    let mut raw = pristine.clone();
    let big_start = (0..sb.total_blocks as usize).rev()
        .find(|b| raw[b * BLOCK_SIZE..(b + 1) * BLOCK_SIZE].iter().any(|x| *x != 0) && *b < sb.total_blocks as usize - 1)
        .unwrap();
    raw[big_start * BLOCK_SIZE + 100] ^= 0x55;
    std::fs::write(&img, &raw).unwrap();
    let errors = read::verify(&img).unwrap();
    assert!(errors.iter().any(|e| e.contains(&format!("data block {big_start} tag mismatch"))), "{errors:?}");

    // One byte inside the table leaf: its pointer's tag refuses the tree.
    let mut raw = pristine.clone();
    raw[sb.table_root.address as usize * BLOCK_SIZE + NODE_HEADER_SIZE + 3] ^= 1;
    std::fs::write(&img, &raw).unwrap();
    let error = read::verify(&img).unwrap_err();
    assert!(error.contains("tag mismatch"), "{error}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn layout_1_is_rejected_not_decoded() {
    let dir = tmp("layout");
    let img = dir.join("x.img");
    build::build_to_file(&img, &spec(4 * 1024 * 1024), &contents()).unwrap();
    let mut raw = std::fs::read(&img).unwrap();
    let total = raw.len() / BLOCK_SIZE;
    for base in [0, 1, total - 1] {
        let sb = &mut raw[base * BLOCK_SIZE..(base + 1) * BLOCK_SIZE];
        put32(sb, SB_LAYOUT, 1);
        seal_block(sb);
    }
    std::fs::write(&img, &raw).unwrap();
    let error = read::verify(&img).unwrap_err();
    assert!(error.contains("layout 1 is not layout 2"), "{error}");
    assert!(error.contains("superblock C"), "every copy is reported: {error}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn dirty_state_requires_a_lagging_replay_floor_only() {
    let mut block = vec![0u8; BLOCK_SIZE];
    let dir = tmp("state");
    let img = dir.join("x.img");
    build::build_to_file(&img, &spec(4 * 1024 * 1024), &contents()).unwrap();
    let raw = std::fs::read(&img).unwrap();
    block.copy_from_slice(&raw[..BLOCK_SIZE]);
    put32(&mut block, SB_STATE, STATE_DIRTY);
    seal_block(&mut block);
    assert_eq!(Superblock::parse(&block).unwrap().state, STATE_DIRTY);
    put32(&mut block, SB_STATE, STATE_CLEAN);
    put64(&mut block, SB_REPLAY_FLOOR, 0);
    seal_block(&mut block);
    assert!(Superblock::parse(&block).unwrap_err().contains("CLEAN superblock whose replay floor lags"));
    put32(&mut block, SB_STATE, 3);
    seal_block(&mut block);
    assert!(Superblock::parse(&block).unwrap_err().contains("state 3"));
    put32(&mut block, SB_STATE, STATE_CLEAN);
    put64(&mut block, SB_REPLAY_FLOOR, 1);
    put32(&mut block, SB_SUITE, 7);
    seal_block(&mut block);
    assert!(Superblock::parse(&block).unwrap_err().contains("unknown suite 7"));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn casefold_and_fake_flags() {
    let dir = tmp("flags");
    let img = dir.join("cf.img");
    let mut s = spec(4 * 1024 * 1024);
    s.casefold_root = true;
    s.compat_ro_flags = 0x8;
    build::build_to_file(&img, &s, &contents()).unwrap();
    let dump = read::dump_text(&img).unwrap();
    assert!(dump.contains(&format!("incompat={:#x} compat-ro=0x8 casefold-version={}", INCOMPAT_CASEFOLD, CASEFOLD_VERSION_UNICODE_15_1)));
    assert_eq!(read::verify(&img).unwrap(), Vec::<String>::new());

    let mut s = spec(4 * 1024 * 1024);
    s.extra_incompat = 0x40;
    build::build_to_file(&img, &s, &contents()).unwrap();
    assert!(read::verify(&img).unwrap_err().contains("unknown incompat flags 0x40"));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn sealed_entries_carry_the_item_tree_axes() {
    // Under a case-insensitive root the commit carries the root's axes and
    // each directory entry the axes of its inode; the verifier compares
    // both with the sealed snapshot's inodes.
    let dir = tmp("sealed-casefold");
    let img = dir.join("sealed-cf.img");
    let mut s = spec(16 * 1024 * 1024);
    s.casefold_root = true;
    let options = Options { suite: None, unlock: None, compression: COMPRESSION_NONE, seal: true };
    build::build_to_file_with(&img, &s, &contents(), &options).unwrap();
    assert_eq!(read::verify(&img).unwrap(), Vec::<String>::new());
    let _ = std::fs::remove_dir_all(&dir);

    let contents = contents();
    let perm = |path: &str, default_mode: u32| build::lookup_perm(&contents.permissions, path, default_mode);
    for (casefold_root, root_case) in [(false, AXIS_SENSITIVE), (true, AXIS_INSENSITIVE)] {
        let inputs = seal::SealInputs {
            suite: None, name_key: [1; 32], key_material: [0; 32], store_identity: [3; 16], subvol_uuid: [4; 16], seal_time: 5, clock_valid: true,
            chunker: codec::fastcdc::Params::DEFAULT, casefold_root, time_ns: 6, contents: &contents, pack_identity: (2, 2), perm: &perm,
        };
        let commit = seal::seal(&inputs).unwrap().commit;
        assert_eq!(
            (commit.root_case_axis, commit.root_norm_axis), writer_directory_axes(root_case)
        );
    }
}

#[test]
fn casefold_root_keys_entries_by_folded_name() {
    let dir = tmp("casefold-keys");
    let img = dir.join("cf-keys.img");
    let mut s = spec(4 * 1024 * 1024);
    s.casefold_root = true;
    let mut c = contents();
    c.files.push(("README".to_string(), FileSource::Bytes(b"salt\n".to_vec())));
    c.files.push(("Ünïcode".to_string(), FileSource::Bytes(b"u\n".to_vec())));
    build::build_to_file(&img, &s, &c).unwrap();
    assert_eq!(read::verify(&img).unwrap(), Vec::<String>::new());
    let dump = read::dump_text(&img).unwrap();
    assert!(dump.contains("file /README"));
    assert!(dump.contains("file /Ünïcode"));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn directory_keys_follow_the_policy_and_the_keyed_hash() {
    let keys = plain_keys();
    let byte = Policy { case_axis: AXIS_SENSITIVE, norm_axis: AXIS_SENSITIVE, plugin: DIR_HASH_SIPHASH };
    let folded = Policy { case_axis: AXIS_INSENSITIVE, norm_axis: AXIS_SENSITIVE, plugin: DIR_HASH_SIPHASH };
    let fnv = Policy { case_axis: AXIS_SENSITIVE, norm_axis: AXIS_SENSITIVE, plugin: DIR_HASH_FNV1A };
    assert!(byte.is_byte() && !folded.is_byte());
    assert_eq!(folded.indexed_key(b"README").unwrap(), b"readme".to_vec());
    assert_eq!(folded.indexed_key("Δ".as_bytes()).unwrap(), "δ".as_bytes().to_vec());
    assert_eq!(byte.indexed_key(b"README").unwrap(), b"README".to_vec());
    assert_eq!(
        dir_item_offset(&keys, 1, ROOT_INO, byte, b"README").unwrap(),
        siphash24(&keys.dir_key(1, ROOT_INO), b"README")
    );
    assert_eq!(
        dir_item_offset(&keys, 1, ROOT_INO, folded, b"README").unwrap(),
        siphash24(&keys.dir_key(1, ROOT_INO), b"readme")
    );
    assert_eq!(dir_item_offset(&keys, 1, ROOT_INO, fnv, b"README").unwrap(), fnv1a(b"README"));
    assert_ne!(dir_item_offset(&keys, 1, ROOT_INO, byte, b"README"), dir_item_offset(&keys, 2, ROOT_INO, byte, b"README"), "the directory key is per subvolume");
    assert_ne!(dir_item_offset(&keys, 1, 5, byte, b"README"), dir_item_offset(&keys, 1, 6, byte, b"README"), "and per directory");
    assert_ne!(reference_offset(&keys, 1, (1, 1), byte, b"README"), reference_offset(&keys, 1, (1, 1), folded, b"README"), "the policy bytes enter the reference hash");
    // The encrypted-suite master differs from the plain one under the same salt.
    let unlocked = Keys::unlocked(Suite::XChaCha20Poly1305, [7; 16], [9; 32]);
    assert_ne!(unlocked.dir_key(1, ROOT_INO), keys.dir_key(1, ROOT_INO));
    // Policy round-trips through the inode flags.
    assert_eq!(Policy::of_flags(axis_flags(AXIS_INSENSITIVE, AXIS_SENSITIVE), DIR_HASH_SIPHASH), folded);
    assert!(axis_flags(AXIS_INSENSITIVE, AXIS_SENSITIVE) & INODE_CASEFOLD != 0);
    assert_eq!(axis_flags(AXIS_SENSITIVE, AXIS_SENSITIVE), 0);
}

#[test]
fn normalization_keys_use_the_pinned_canonical_relation() {
    let cases = [
        ("café", true, false, "cafe\u{301}"),
        ("\u{212B}", true, false, "A\u{30A}"),
        ("가", true, false, "\u{1100}\u{1161}"),
        ("A\u{315}\u{300}\u{301}", true, false, "A\u{300}\u{301}\u{315}"),
        ("İ", false, true, "İ"),
        ("İ", true, true, "i\u{307}"),
        ("\u{1E9B}\u{323}", true, true, "s\u{323}\u{307}"),
        ("Ⱥ", false, true, "ⱥ"),
    ];
    for (name, normalize, fold, expected) in cases {
        assert_eq!(casefold::key(name.as_bytes(), normalize, fold).unwrap(), expected.as_bytes());
    }
    assert!(casefold::key(&[0xFF], true, false).is_err());
    assert!(casefold::key(&[0xFF], false, true).is_err());
    assert_eq!(casefold::key(&[0xFF], false, false).unwrap(), [0xFF]);
    let policy = Policy {
        case_axis: AXIS_MIXED, norm_axis: AXIS_INSENSITIVE, plugin: DIR_HASH_SIPHASH,
    };
    assert_eq!(policy.indexed_key(b"A").unwrap(), policy.indexed_key(b"a").unwrap());
    assert_ne!(policy.unique_key(b"A").unwrap(), policy.unique_key(b"a").unwrap());
    assert_eq!(
        policy.unique_key("é".as_bytes()).unwrap(),
        policy.unique_key("e\u{301}".as_bytes()).unwrap()
    );
}

#[test]
fn writer_sha256_matches_the_published_digest_vectors() {
    assert_eq!(sha256::hash_bytes(b""),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    assert_eq!(sha256::hash_bytes(b"abc"),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    let input = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    let mut stream = sha256::Sha256::new();
    for piece in input.chunks(7) { stream.update(piece); }
    assert_eq!(primitives::hex(&stream.finalize()),
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
}

#[test]
fn normalizing_images_preserve_spelling_and_reject_equivalent_names() {
    let dir = tmp("normalization");
    let image = dir.join("rootfs.img");
    let mut input = contents();
    input.files.push(("usr/café".into(), FileSource::Bytes(b"name".to_vec())));
    let options = Options { seal: true, ..Options::default() };
    build::build_to_file_with(&image, &spec(16 * 1024 * 1024), &input, &options).unwrap();
    assert!(read::verify(&image).unwrap().is_empty());
    assert!(read::dump_text(&image).unwrap().contains("file /usr/café"));
    let raw = std::fs::read(&image).unwrap();
    let sb = Superblock::parse(&raw[..BLOCK_SIZE]).unwrap();
    assert_eq!(sb.casefold_version, CASEFOLD_VERSION_UNICODE_15_1);
    input.files.push(("usr/cafe\u{301}".into(), FileSource::Bytes(b"other".to_vec())));
    let refused = build::build_to_file(&dir.join("collision.img"), &spec(4 * 1024 * 1024), &input);
    assert!(refused.err().unwrap().contains("equivalent directory name"));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn fnv1a_matches_reference() {
    assert_eq!(fnv1a(b""), 0xcbf29ce484222325);
    assert_eq!(fnv1a(b"a"), 0xaf63dc4c8601ec8c);
}

#[test]
fn key_order_is_numeric_not_bytewise() {
    let low = Key::new(1, 0x0100, ITEM_DIR, 0);
    let high = Key::new(1, 0x00FF, ITEM_INODE, u64::MAX);
    assert!(high < low, "objectid 0xFF sorts before 0x100 although its first byte is larger");
    assert!(Key::new(0, 0, 0xFF, 0) < Key::new(1, 0, 0, 0));
    assert!(Key::new(2, 2, ITEM_DIR, 5) < Key::new(2, 2, ITEM_EXTENT_DATA, 0));
    let packed = low.pack();
    assert_eq!(packed.len(), KEY_SIZE);
    assert_eq!(Key::unpack(&packed), low);
    assert_eq!(packed[16], ITEM_DIR);
    let name = [0xABu8; 32];
    assert_eq!(skey_key(&name), Key::new(get64(&name, 0), get64(&name, 8), ITEM_SKEY, get64(&name, 16)));
}

#[test]
fn pointer_codec_is_32_bytes_and_refuses_vdevs() {
    let pointer = Pointer { address: 77, birth: 3, tag: [9; 16] };
    let mut packed = pointer.pack();
    assert_eq!(packed.len(), POINTER_SIZE);
    assert_eq!(POINTER_SIZE, 32);
    assert_eq!(Pointer::unpack(&packed).unwrap(), pointer);
    put64(&mut packed, 0, 77 | 1 << 48);
    assert!(Pointer::unpack(&packed).unwrap_err().contains("nonzero vdev"));
    let mut null = Pointer::NULL.pack();
    assert!(null.iter().all(|b| *b == 0));
    null[20] = 1;
    assert!(Pointer::unpack(&null).unwrap_err().contains("null pointer with nonzero bytes"));
}

#[test]
fn geometry_follows_the_prescription() {
    assert_eq!(Superblock::geometry(64, false).unwrap(), (0, 0, 2, 1, 3, 8));
    assert_eq!(Superblock::geometry(64, true).unwrap(), (2, 8, 10, 1, 11, 8));
    assert_eq!(Superblock::geometry(256, false).unwrap(), (0, 0, 2, 1, 3, 32));
    assert_eq!(Superblock::geometry(32768, false).unwrap(), (0, 0, 2, 1, 3, 4096));
    assert_eq!(Superblock::geometry(32769, true).unwrap(), (2, 8, 10, 2, 12, 4096));
    assert_eq!(Superblock::geometry(1 << 20, false).unwrap(), (0, 0, 2, 32, 34, 16384));
    assert!(Superblock::geometry(63, false).is_err());
    assert_eq!(LEAF_ENTRY_MAX, 122);
    assert_eq!(INTERNAL_ENTRY_MAX, 70);
    assert_eq!(DEADLOG_ENTRY_BYTES, 16);
    assert_eq!(SUBVOL_ROW_SIZE, PAYLOAD_MAX);
    assert_eq!(SNAP_ROW_SIZE, 240);
    assert_eq!(HOLD_ROW_WORDS, 17);
}

#[test]
fn subvolume_and_snapshot_rows_round_trip_and_fail_closed() {
    let row = SubvolRow {
        uuid: [1; 16], incarnation: 2, item_root: Pointer { address: 3, birth: 1, tag: [4; 16] }, index_root: Pointer::NULL, tag_root: Pointer::NULL, objectid_hwm: 5,
        incarnation_hwm: 6, publish_seq: 1, origin: (0, 0), owner: (7, 8), limits: [100, 90, 10, 5], referenced: 11, owned: 10, retained_charge: 1, catalog_id_hwm: 2,
        retain_pinned: 1, state: SUBVOL_STATE_LIVE, flags: SUBVOL_FLAG_BOOT_DEFAULT, label: [b'x'; 32], sealed_head: [9; 32],
    };
    let packed = row.pack();
    assert_eq!(packed.len(), SUBVOL_ROW_SIZE);
    assert_eq!(get64(&packed, 0x0D0), 11);
    assert_eq!(get64(&packed, 0x0D8), 10);
    assert_eq!(get64(&packed, 0x0E0), 1);
    assert_eq!(&packed[0x120..0x140], &[9; 32]);
    assert_eq!(SubvolRow::unpack(&packed).unwrap(), row);
    let mut bad = packed.clone();
    put32(&mut bad, 0x0F4, 9);
    assert!(SubvolRow::unpack(&bad).is_err(), "state 9");
    let mut bad = packed.clone();
    put64(&mut bad, 0x0B8, 200);
    assert!(SubvolRow::unpack(&bad).is_err(), "refquota above quota");
    let mut bad = packed.clone();
    put64(&mut bad, 0x0A8, 0);
    assert!(SubvolRow::unpack(&bad).is_err(), "half an owner");

    let snap = SnapRow {
        snapshot_id: 1, item_root: Pointer { address: 3, birth: 1, tag: [4; 16] }, index_root: Pointer::NULL, tag_root: Pointer::NULL, objectid_hwm: 5, incarnation_hwm: 6,
        creation_time: 7, deadlog_root: Pointer::NULL, deadlog_cursor: 0, owner: (1, 1), state: SNAP_STATE_SEALED, holds: 0, flags: 0, seal_time: 8, commit_name: [2; 32],
    };
    let packed = snap.pack();
    assert_eq!(packed.len(), SNAP_ROW_SIZE);
    assert_eq!(get64(&packed, 0xC8), 8);
    assert_eq!(&packed[0xD0..0xF0], &[2; 32]);
    assert_eq!(SnapRow::unpack(&packed).unwrap(), snap);
    let mut bad = packed.clone();
    put32(&mut bad, 0xB8, SNAP_STATE_PINNED);
    assert!(SnapRow::unpack(&bad).is_err(), "a pinned row carries no commit");

    // CLOCK_VALID belongs to sealing and sealed rows; other bits are undefined.
    let clocked = SnapRow { flags: SNAP_FLAG_CLOCK_VALID, ..snap.clone() };
    assert_eq!(SnapRow::unpack(&clocked.pack()).unwrap(), clocked);
    let sealing = SnapRow { state: SNAP_STATE_SEALING, commit_name: [0; 32], ..clocked.clone() };
    assert_eq!(SnapRow::unpack(&sealing.pack()).unwrap(), sealing);
    let pinned = SnapRow { state: SNAP_STATE_PINNED, seal_time: 0, commit_name: [0; 32], ..clocked.clone() };
    assert!(SnapRow::unpack(&pinned.pack()).is_err(), "a pinned row has no seal clock");
    let undefined = SnapRow { flags: 1 << 2, ..snap.clone() };
    assert!(SnapRow::unpack(&undefined.pack()).is_err(), "bit 2 is undefined");
}

#[test]
fn directory_links_and_seal_clocks_round_trip() {
    // The inode flag is legal on a symbolic link only.
    let fields = |mode| InodeFields {
        size: 1, blocks: 0, nlink: 1, owner: 0x0100_0000_0000_0000, group: 0x0200_0000_0000_0000, mode, time_ns: 1, incarnation: 1,
        flags: INODE_DIRECTORY_LINK, hidden_owner: 0, plugin: [0; 4], project_id: 0,
    };
    assert!(read::parse_inode(&pack_inode(&fields(S_IFLNK | 0o777), 1)).is_ok());
    assert!(read::parse_inode(&pack_inode(&fields(S_IFREG | 0o644), 1)).is_err());

    // The commit's clock byte is 0 or 1.
    let commit = seal::Commit {
        chunker: codec::fastcdc::Params::DEFAULT, subvol_uuid: [1; 16], epoch: 7, seal_time: 99, clock_valid: 0, parents: vec![], root: [5; 32],
        casefold_version: CASEFOLD_VERSION_UNICODE_15_1, key_algorithm: seal::KEY_ALGORITHM_SIPHASH, root_case_axis: AXIS_SENSITIVE, root_norm_axis: AXIS_SENSITIVE,
    };
    assert_eq!(seal::decode_commit(&seal::encode_commit(&commit).unwrap()).unwrap(), commit);
    let odd = seal::Commit { clock_valid: 2, ..commit };
    assert!(seal::decode_commit(&seal::encode_commit(&odd).unwrap()).is_err());

    // A sealed image with a directory link verifies: the inode and the seal
    // entry carry the flag, and the sealed row's clock matches its commit.
    let dir = tmp("directory-link");
    let img = dir.join("sealed.img");
    let mut with_link = contents();
    with_link.symlinks.push(("c".to_string(), b"/".to_vec()));
    with_link.directory_links.push("c".to_string());
    let options = Options { suite: None, unlock: None, compression: COMPRESSION_NONE, seal: true };
    build::build_to_file_with(&img, &spec(16 * 1024 * 1024), &with_link, &options).unwrap();
    assert_eq!(read::verify(&img).unwrap(), Vec::<String>::new());

    // Without a declared clock the row and the commit both leave it unset.
    let unclocked = dir.join("unclocked.img");
    let spec_unclocked = FsSpec { clock_valid: false, ..spec(16 * 1024 * 1024) };
    build::build_to_file_with(&unclocked, &spec_unclocked, &with_link, &options).unwrap();
    assert_eq!(read::verify(&unclocked).unwrap(), Vec::<String>::new());

    // Only a symbolic link can be marked a directory link.
    let mut stray = contents();
    stray.directory_links.push("etc/hostname".to_string());
    assert!(build::build_to_file_with(&dir.join("stray.img"), &spec(16 * 1024 * 1024), &stray, &options).is_err());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn keyslot_codec_round_trips_and_refuses_junk() {
    let slot = Keyslot::passphrase([1; NONCE_BYTES], [2; KEY_BYTES], [3; TAG_BYTES], 65536, 3, 4, [5; KEYSLOT_SALT_BYTES]);
    let block = slot.pack();
    assert_eq!(block.len(), BLOCK_SIZE);
    assert_eq!(get32(&block, 0), KEYSLOT_KIND_PASSPHRASE);
    assert_eq!(&block[KEYSLOT_OFF_NONCE..KEYSLOT_OFF_SEALED_KEY], &[1; NONCE_BYTES]);
    assert_eq!((get32(&block, KEYSLOT_OFF_PARAMS), get32(&block, KEYSLOT_OFF_PARAMS + 4), get32(&block, KEYSLOT_OFF_PARAMS + 8)), (65536, 3, 4));
    assert_eq!(&block[KEYSLOT_OFF_SALT..KEYSLOT_OFF_SALT + KEYSLOT_SALT_BYTES], &[5; KEYSLOT_SALT_BYTES]);
    assert_eq!(Keyslot::unpack(&block).unwrap().unwrap(), slot);
    assert_eq!(Keyslot::unpack(&vec![0u8; BLOCK_SIZE]).unwrap(), None);
    let mut junk = vec![0u8; BLOCK_SIZE];
    junk[0x200] = 1;
    assert!(Keyslot::unpack(&junk).is_err());
    let mut bad = block.clone();
    put32(&mut bad, KEYSLOT_OFF_PARAMS + 4, 0);
    assert!(Keyslot::unpack(&bad).is_err(), "zero iterations");
}

#[test]
fn log_record_codec_roundtrips() {
    let head = log::Head { kind: log::KIND_ATOM, incarnation: 5, cycle: 2, lsn: 17, seq: 9, fragment_index: 0, fragment_count: 1, predecessor: [3; 16] };
    let fragment = log::Fragment {
        images: vec![log::ImageEntry { address: 2, birth: 9, tag: [1; 16] }],
        allocs: vec![log::AllocEntry { first: 40, count: 6, op: log::ALLOC_OP_ALLOCATE }, log::AllocEntry { first: 38, count: 1, op: log::ALLOC_OP_FREE }],
        roots: vec![
            log::RootEntry { subvol: 1, kind: log::ROOT_KIND_ITEM, pointer: Pointer { address: 41, birth: 9, tag: [2; 16] }, identity: Some((10, 11, 9)) },
            log::RootEntry { subvol: 1, kind: log::ROOT_KIND_INDEX, pointer: Pointer { address: 36, birth: 1, tag: [6; 16] }, identity: None },
            log::RootEntry { subvol: 1, kind: log::ROOT_KIND_TAG, pointer: Pointer { address: 42, birth: 9, tag: [4; 16] }, identity: None },
        ],
        charges: vec![log::ChargeEntry { subvol: 1, referenced_delta: -1, owned_delta: -2, retained_delta: 3 }],
    };
    let block = log::encode_fragment(&head, &fragment).unwrap();
    assert_eq!(&block[..4], LOG_MAGIC);
    assert_eq!(get32(&block, 0x48), 4, "an identity entry occupies its own root slot");
    assert_eq!(get64(&block, 0xDD0), 1);
    assert_eq!(get64(&block, 0xDD8) as i64, -1);
    assert_eq!(get64(&block, 0xDE0) as i64, -2);
    assert_eq!(get64(&block, 0xDE8) as i64, 3);
    let parsed_head = log::parse_head(&block, 5).unwrap();
    assert_eq!(parsed_head, head);
    assert!(log::parse_head(&block, 6).is_none(), "a foreign incarnation is not a record");
    let parsed = log::parse_fragment(&block).unwrap();
    assert_eq!(parsed.images, fragment.images);
    assert_eq!(parsed.allocs, fragment.allocs);
    assert_eq!(parsed.roots, fragment.roots);
    assert_eq!(parsed.charges, fragment.charges);

    let cert = log::Certificate {
        reserved_seq_hwm: 300, fragment_count: 1, image_blocks: 1, first_lsn: 17, record_blocks: 3, digest: log::atom_digest(&[(block.clone(), vec![[1; 16]])]),
        table_root: Pointer { address: 43, birth: 9, tag: [5; 16] }, registry_root: Pointer::NULL, commit_time: 77,
    };
    let cert_block = log::encode_certificate(&log::Head { lsn: 19, ..head }, &cert);
    let cert_head = log::parse_head(&cert_block, 5).unwrap();
    assert_eq!((cert_head.kind, cert_head.lsn, cert_head.fragment_count), (log::KIND_CERT, 19, 0));
    assert_eq!(log::parse_certificate(&cert_block).unwrap(), cert);

    let reserve = log::encode_reserve(&log::Head { lsn: 20, ..head }, 600);
    assert_eq!(log::parse_head(&reserve, 5).unwrap().kind, log::KIND_RESERVE);
    assert_eq!(log::parse_reserve(&reserve).unwrap(), 600);

    let mut damaged = block.clone();
    damaged[0x100] ^= 1;
    assert!(log::parse_head(&damaged, 5).is_none(), "a record with a bad tag is not a record");
}

#[test]
fn xxh3_128_matches_the_reference_vectors() {
    let pattern = |n: usize, f: fn(usize) -> usize| -> Vec<u8> { (0..n).map(|i| (f(i) & 255) as u8).collect() };
    let cases: [(Vec<u8>, &str); 10] = [
        (Vec::new(), "99aa06d3014798d86001c324468d497f"),
        (b"a".to_vec(), "a96faf705af16834e6c632b61e964e1f"),
        (b"abc".to_vec(), "06b05ab6733a618578af5f94892f3950"),
        (b"salty".to_vec(), "5ac0f2ccc80048022c2c03a87794db89"),
        (b"SaltyFS format 2".to_vec(), "946e693a17e9f81465105c0c3f74fcc1"),
        (pattern(17, |i| 11 * i + 1), "e090e57c83adf8cdf73f93b0de8ab4ab"),
        (pattern(64, |i| 5 * i + 9), "e90eed23b2cfdbafc87b7c74870d931e"),
        (pattern(129, |i| 7 * i + 3), "293e4968c4619023bd91ce7ace4d385b"),
        (pattern(240, |i| 13 * i + 5), "393508c0c653b5b0f90cf0edcdfa17a2"),
        (pattern(4096, |i| i), "03916578969f7a66eb4b7c3707879151"),
    ];
    for (input, expected) in cases {
        assert_eq!(hex(&xxh3::hash128(&input)), expected, "input length {}", input.len());
    }
    let (lo, hi) = xxh3::hash128_words(b"abc");
    let mut canonical = hi.to_be_bytes().to_vec();
    canonical.extend_from_slice(&lo.to_be_bytes());
    assert_eq!(hex(&canonical), "06b05ab6733a618578af5f94892f3950");
}

#[test]
fn inode_data_blocks_follow_inline_and_regular_storage() {
    let lengths = [0, 1, INLINE_MAX, INLINE_MAX + 1, BLOCK_SIZE, BLOCK_SIZE + 1, 17 * BLOCK_SIZE, COMPRESSION_UNIT + 1];
    let contents = Contents {
        files: lengths.iter().enumerate().map(|(i, length)| (format!("file-{i}"), FileSource::Bytes(vec![0x53; *length]))).collect(),
        empty_dirs: Vec::new(), symlinks: Vec::new(), directory_links: Vec::new(), permissions: Permissions::new(),
    };
    let keys = plain_keys();
    let inputs = build::SubvolInputs { subvol: DEFAULT_SUBVOL, contents: &contents, root_case_axis: AXIS_SENSITIVE, compression: COMPRESSION_NONE, time_ns: 1, keys: &keys,
        first_data_block: 100, birth: INITIAL_SEQ };
    let metadata = build::build_metadata(&inputs).unwrap();
    let mut regular_files = 0;
    for (key, inode) in &metadata.items {
        if key.ty != ITEM_INODE || key.objectid == ROOT_INO { continue; }
        let size = get64(inode, 0x08);
        let blocks = get64(inode, 0x10);
        let extents: Vec<&Vec<u8>> = metadata.items.iter()
            .filter(|(k, _)| k.locality == key.locality && k.objectid == key.objectid && k.ty == ITEM_EXTENT_DATA).map(|(_, v)| v).collect();
        let extent = extents[0];
        regular_files += 1;
        assert_eq!(get64(extent, 0x00), INITIAL_SEQ);
        if size <= INLINE_MAX as u64 {
            assert_eq!(extents.len(), 1);
            assert_eq!(extent[0x20], EXTENT_INLINE);
            assert_eq!(extent.len(), EXTENT_HEADER_SIZE + size as usize);
            assert_eq!(blocks, 0, "inline payload owns no separate data blocks");
        } else {
            assert_eq!(extents.len(), 1, "an uncompressed file is one extent whatever its length");
            assert_eq!(extent[0x20], EXTENT_REGULAR);
            assert_eq!(extent[0x21], COMPRESSION_NONE);
            assert_eq!(extent.len(), EXTENT_HEADER_SIZE);
            let stored: u64 = extents.iter().map(|e| get64(e, 0x18)).sum();
            assert_eq!(blocks, stored / BLOCK_SIZE as u64);
            assert_eq!(blocks, size.div_ceil(BLOCK_SIZE as u64));
            let address = get64(extent, 0x10);
            let runs: Vec<&Vec<u8>> = metadata.tag_items.iter()
                .filter(|(k, _)| k.ty == ITEM_DATA_TAG && k.objectid >= address && k.objectid < address + blocks).map(|(_, tags)| tags).collect();
            assert_eq!(runs.iter().map(|r| r.len() / 16).sum::<usize>(), blocks as usize);
        }
        assert!(metadata.index_items.iter().any(|(k, v)| k == &Key::new(0, key.objectid, ITEM_OBJECT_INDEX, 0) && get64(v, 0) == key.locality));
    }
    assert_eq!(regular_files, lengths.len());
    assert_eq!(metadata.next_objectid, FIRST_INO + lengths.len() as u64);
}

// ---------------------------------------------------------------------------
// Primitives
// ---------------------------------------------------------------------------

/// The official BLAKE3 vectors: the input is the repeating byte sequence
/// 0, 1, ..., 250 and the outputs are the first 32 bytes of each mode.
#[test]
fn blake3_matches_the_official_vectors() {
    let key: [u8; 32] = b"whats the Elvish word for friend".as_slice().try_into().unwrap();
    let context = b"BLAKE3 2019-12-27 16:29:52 test vectors context";
    let cases: [(usize, &str, &str, &str); 3] = [
        (0, "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262", "92b2b75604ed3c761f9d6f62392c8a9227ad0ea3f09573e783f1498a4ed60d26",
            "2cc39783c223154fea8dfb7c1b1660f2ac2dcbd1c1de8277b0b0dd39b7e50d7d"),
        (1, "2d3adedff11b61f14c886e35afa036736dcd87a74d27b5c1510225d0f592e213", "6d7878dfff2f485635d39013278ae14f1454b8c0a3a2d34bc1ab38228a80c95b",
            "b3e2e340a117a499c6cf2398a19ee0d29cca2bb7404c73063382693bf66cb06c"),
        (1024, "42214739f095a406f3fc83deb889744ac00df831c10daa55189b5d121c855af7", "75c46f6f3d9eb4f55ecaaee480db732e6c2105546f1e675003687c31719c7ba4",
            "7356cd7720d5b66b6d0697eb3177d9f8d73a4a5c5e968896eb6a689684302706"),
    ];
    for (len, hash_hex, keyed_hex, derive_hex) in cases {
        let input: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
        assert_eq!(hex(&blake3::hash(&input)), hash_hex, "hash {len}");
        assert_eq!(hex(&blake3::keyed_hash(&key, &input)), keyed_hex, "keyed {len}");
        assert_eq!(hex(&blake3::derive_key(context, &input)), derive_hex, "derive {len}");
    }
    // Incremental hashing equals one-shot hashing across chunk boundaries.
    let input: Vec<u8> = (0..5000).map(|i| (i % 251) as u8).collect();
    let mut hasher = blake3::Hasher::new();
    for piece in input.chunks(333) { hasher.update(piece); }
    assert_eq!(hasher.finalize(), blake3::hash(&input));
    let mut long = [0u8; 64];
    hasher.finalize_into(&mut long);
    assert_eq!(&long[..32], &blake3::hash(&input));
}

#[test]
fn chacha20_poly1305_matches_rfc_8439_and_the_xchacha_draft() {
    let key = key32("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    // The ChaCha20 block-function reference vector with counter 1.
    let mut out = [0u8; 64];
    chacha::block(&key, 1, &h("000000090000004a00000000").try_into().unwrap(), &mut out);
    assert_eq!(hex(&out[..32]), "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4e");
    // The Poly1305 one-time authenticator reference vector.
    let poly_key = key32("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b");
    assert_eq!(hex(&chacha::poly1305(&poly_key, b"Cryptographic Forum Research Group")), "a8061dc1305136c6c22b8baf0c0127a9");
    // draft-irtf-cfrg-xchacha §2.2.1: HChaCha20.
    assert_eq!(hex(&chacha::hchacha20(&key, &h("000000090000004a0000000031415927").try_into().unwrap())),
        "82413b4227b27bfed30e42508a877d73a0f9e4d58a74a853c12ec41326d3ecdc");
    // draft-irtf-cfrg-xchacha A.3.1: the AEAD.
    let aead_key = key32("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
    let nonce: [u8; 24] = h("404142434445464748494a4b4c4d4e4f5051525354555657").try_into().unwrap();
    let ad = h("50515253c0c1c2c3c4c5c6c7");
    let plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
    let mut data = plaintext.to_vec();
    let tag = chacha::xchacha_seal(&aead_key, &nonce, &ad, &mut data);
    assert_eq!(hex(&tag), "c0875924c1c7987947deafd8780acf49");
    assert_eq!(hex(&data[..16]), "bd6d179d3e83d43b9576579493c0e939");
    assert!(chacha::xchacha_open(&aead_key, &nonce, &ad, &mut data, &tag).is_ok());
    assert_eq!(data, plaintext);
    let mut wrong_tag = tag;
    wrong_tag[0] ^= 1;
    assert!(chacha::xchacha_open(&aead_key, &nonce, &ad, &mut data, &wrong_tag).is_err());
    assert!(chacha::xchacha_open(&aead_key, &nonce, b"", &mut data, &tag).is_err(), "the associated data is authenticated");
}

#[test]
fn aes_256_gcm_and_xaes_match_the_published_vectors() {
    // A host with the instructions passes the known-answer test, so the
    // refusal below never hides a wrong implementation.
    assert_eq!(aes::available().is_some(), aes::host_has_instructions());
    let Some(instructions) = aes::available() else {
        assert!(Suite::xaes().is_err() && Suite::from_word(2).is_err(), "a host without the instructions refuses the AES suite");
        return;
    };
    // FIPS 197 C.3.
    let cipher = aes::Aes256::new(instructions, &key32("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"));
    let mut block: [u8; 16] = h("00112233445566778899aabbccddeeff").try_into().unwrap();
    cipher.encrypt_block(&mut block);
    assert_eq!(hex(&block), "8ea2b7ca516745bfeafc49904b496089");
    // NIST GCM test cases 13 and 14 (AES-256, zero key and IV).
    let zero = aes::Aes256::new(instructions, &[0; 32]);
    let mut empty: Vec<u8> = Vec::new();
    assert_eq!(hex(&aes::gcm_seal(&zero, &[0; 12], b"", &mut empty)), "530f8afbc74536b9a963b4f1c4cb738b");
    let mut data = vec![0u8; 16];
    let tag = aes::gcm_seal(&zero, &[0; 12], b"", &mut data);
    assert_eq!(hex(&data), "cea7403d4d606b6e074ec5d3baf39d18");
    assert_eq!(hex(&tag), "d0d1c8a799996bf0265b98b5d48ab919");
    assert!(aes::gcm_open(&zero, &[0; 12], b"", &mut data, &tag).is_ok());
    assert_eq!(data, vec![0u8; 16]);
    // C2SP XAES-256-GCM vectors.
    let nonce: [u8; 24] = *b"ABCDEFGHIJKLMNOPQRSTUVWX";
    let mut data = b"XAES-256-GCM".to_vec();
    let tag = aes::xaes_seal(instructions, &[1; 32], &nonce, b"", &mut data);
    let mut wire = data.clone();
    wire.extend_from_slice(&tag);
    assert_eq!(hex(&wire), "ce546ef63c9cc60765923609b33a9a1974e96e52daf2fcf7075e2271");
    assert!(aes::xaes_open(instructions, &[1; 32], &nonce, b"", &mut data, &tag).is_ok());
    assert_eq!(data, b"XAES-256-GCM");
    let mut data = b"XAES-256-GCM".to_vec();
    let tag = aes::xaes_seal(instructions, &[3; 32], &nonce, b"c2sp.org/XAES-256-GCM", &mut data);
    let mut wire = data.clone();
    wire.extend_from_slice(&tag);
    assert_eq!(hex(&wire), "986ec1832593df5443a179437fd083bf3fdb41abd740a21f71eb769d");
    // The suite dispatch reaches both AEADs.
    for suite in [Suite::XChaCha20Poly1305, Suite::Xaes256Gcm(instructions)] {
        let mut data = b"the same bytes under both suites".to_vec();
        let tag = suite.seal(&[5; 32], &[6; 24], b"ad", &mut data);
        assert_ne!(data, b"the same bytes under both suites");
        assert!(suite.open(&[5; 32], &[6; 24], b"ad", &mut data, &tag).is_ok());
        assert_eq!(data, b"the same bytes under both suites");
        assert_eq!(Suite::from_word(suite.word()).unwrap(), Some(suite));
    }
    assert_eq!(Suite::from_word(0).unwrap(), None);
    assert!(Suite::from_word(3).is_err());
}

#[test]
fn siphash_2_4_matches_the_reference_vectors() {
    let key: [u8; 16] = h("000102030405060708090a0b0c0d0e0f").try_into().unwrap();
    assert_eq!(siphash24(&key, b""), 0x726fdb47dd0e0e31);
    assert_eq!(siphash24(&key, &[0]), 0x74f839c593dc67fd);
    assert_eq!(siphash24(&key, &[0, 1]), 0x0d6c8009d9a94f5a);
    assert_ne!(siphash24(&[0; 16], b"README"), siphash24(&key, b"README"));
}

/// The Argon2 reference implementation's Argon2id vectors (version 0x13):
/// password `password`, salt `somesalt`, 32-byte tags.
#[test]
fn argon2id_matches_the_reference_vectors() {
    let cases: [(u32, u32, u32, &str); 4] = [
        (2, 256, 1, "9dfeb910e80bad0311fee20f9c0e2b12c17987b4cac90c2ef54d5b3021c68bfe"),
        (2, 256, 2, "6d093c501fd5999645e0ea3bf620d7b8be7fd2db59c20d9fff9539da2bf57037"),
        (2, 65536, 1, "09316115d5cf24ed5a15a31a3ba326e5cf32edc24702987c02b6566f61913cf7"),
        (1, 65536, 1, "f6a5adc1ba723dddef9b5ac1d464e180fcd9dffc9d1cbf76cca2fed795d9ca98"),
    ];
    for (t, m, p, expected) in cases {
        let mut out = [0u8; 32];
        argon2::argon2id(b"password", b"somesalt", t, m, p, &mut out).unwrap();
        assert_eq!(hex(&out), expected, "t={t} m={m} p={p}");
    }
    // BLAKE2b-512 reference digests of the empty message and of "abc".
    let mut digest = [0u8; 64];
    argon2::blake2b(&[b""], &mut digest);
    assert_eq!(hex(&digest[..16]), "786a02f742015903c6c6fd852552d272");
    argon2::blake2b(&[b"abc"], &mut digest);
    assert_eq!(hex(&digest), "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923");
    assert!(argon2::argon2id(b"x", b"somesalt", 1, 7, 1, &mut digest[..32]).is_err(), "memory below 8 blocks per lane is refused");
}

#[test]
fn padme_pads_to_the_published_lengths() {
    assert_eq!(padme(1), 1);
    assert_eq!(padme(2), 2);
    assert_eq!(padme(1000), 1024);
    assert_eq!(padme(1025), 1088);
    assert_eq!(padme(1_000_000), 1_015_808);
    for length in [1u64, 3, 100, 4097, 65_537, 1 << 20] {
        let padded = padme(length);
        assert!(padded >= length && padded - length <= length / 8 + 1, "{length} -> {padded}");
    }
}

// ---------------------------------------------------------------------------
// Codecs
// ---------------------------------------------------------------------------

#[test]
fn lz4_and_zstd_round_trip_and_decode_reference_frames() {
    let compressible: Vec<u8> = (0..COMPRESSION_UNIT).map(|i| b"saltyfs format two "[i % 19]).collect();
    let noise: Vec<u8> = (0..4096u32).map(|i| (i.wrapping_mul(2_654_435_761) >> 11) as u8).collect();
    for input in [compressible.clone(), noise.clone(), b"a".to_vec(), vec![0; 100_000]] {
        let frame = codec::lz4::compress(&input);
        let mut out = vec![0u8; input.len()];
        assert_eq!(codec::lz4::decompress(&frame, &mut out).unwrap(), input.len());
        assert_eq!(out, input);
        // Block padding is accepted when it is zero and refused otherwise.
        let mut padded = frame.clone();
        padded.resize(frame.len().div_ceil(BLOCK_SIZE) * BLOCK_SIZE + BLOCK_SIZE, 0);
        codec::lz4::decompress_padded(&padded, &mut out).unwrap();
        assert_eq!(out, input);
        *padded.last_mut().unwrap() = 1;
        assert!(codec::lz4::decompress_padded(&padded, &mut out).is_err());
        for single_segment in [false, true] {
            let frame = codec::zstd::compress(&input, single_segment);
            assert_eq!(&frame[..4], &[0x28, 0xB5, 0x2F, 0xFD]);
            let header = codec::zstd::frame_header(&frame).unwrap();
            assert_eq!(header.single_segment, single_segment);
            assert_eq!(codec::zstd::decompress(&frame).unwrap(), input);
        }
    }
    assert!(codec::lz4::compress(&compressible).len() < compressible.len() / 4);
    assert!(codec::zstd::compress(&compressible, false).len() < compressible.len() / 4);
    // The canonical empty frame: single segment, content size 0, one raw block.
    assert_eq!(codec::zstd::decompress(&[0x28, 0xB5, 0x2F, 0xFD, 0x20, 0x00, 0x01, 0x00, 0x00]).unwrap(), Vec::<u8>::new());
    // An RLE block frame: 0x20 (single segment, 1-byte FCS), FCS 3, block header RLE size 3 last, byte 0x41.
    assert_eq!(codec::zstd::decompress(&[0x28, 0xB5, 0x2F, 0xFD, 0x20, 0x03, 0x1B, 0x00, 0x00, 0x41]).unwrap(), b"AAA".to_vec());
    // xxh64 (the frame checksum hash) reference values.
    assert_eq!(codec::zstd::xxh64(b"", 0), 0xef46db3751d8e999);
    assert_eq!(codec::zstd::xxh64(b"a", 0), 0xd24ec4f1a98c6e5b);
    assert!(codec::zstd::decompress(&[0x28, 0xB5, 0x2F, 0xFD, 0x20, 0x03, 0x1B, 0x00]).is_err(), "a truncated frame is refused");
}

#[test]
fn fastcdc_cuts_within_bounds_and_deterministically() {
    let params = codec::fastcdc::Params::DEFAULT;
    assert!(params.valid());
    assert!(!codec::fastcdc::Params { min: 0, ..params }.valid());
    assert!(!codec::fastcdc::Params { max: params.target, ..params }.valid());
    let mut state = 0x9E37_79B9_7F4A_7C15u64;
    let data: Vec<u8> = (0..5 * 1024 * 1024).map(|_| { state ^= state << 13; state ^= state >> 7; state ^= state << 17; (state >> 24) as u8 }).collect();
    let chunks = codec::fastcdc::chunks(&data, &params);
    let total: usize = chunks.iter().sum();
    assert_eq!(total, data.len());
    assert!(chunks.len() > 1);
    for (i, &len) in chunks.iter().enumerate() {
        assert!(len <= params.max as usize, "chunk {i} above max");
        if i + 1 < chunks.len() { assert!(len >= params.min as usize, "chunk {i} below min"); }
    }
    assert_eq!(codec::fastcdc::chunks(&data, &params), chunks, "the same bytes cut the same way");
    // A shift in the data moves the boundaries with the content.
    let shifted: Vec<u8> = [&[0u8; 777][..], &data].concat();
    let shifted_chunks = codec::fastcdc::chunks(&shifted, &params);
    assert!(shifted_chunks.len() >= chunks.len() - 1);
    assert_eq!(codec::fastcdc::chunks(&data[..1000], &params), vec![1000], "input below the minimum is one chunk");
    assert_eq!(codec::fastcdc::cut(&data[..params.min as usize - 1], &params), params.min as usize - 1);
}

// ---------------------------------------------------------------------------
// Seal objects
// ---------------------------------------------------------------------------

#[test]
fn seal_encodings_are_canonical_and_bodies_open_under_every_suite() {
    let name_key = [4u8; 32];
    let commit = seal::Commit {
        chunker: codec::fastcdc::Params::DEFAULT, subvol_uuid: [1; 16], epoch: 7, seal_time: 99, clock_valid: 1, parents: vec![[2; 32], [3; 32]], root: [5; 32],
        casefold_version: CASEFOLD_VERSION_UNICODE_15_1, key_algorithm: seal::KEY_ALGORITHM_SIPHASH, root_case_axis: AXIS_INSENSITIVE, root_norm_axis: AXIS_SENSITIVE,
    };
    let encoding = seal::encode_commit(&commit).unwrap();
    assert_eq!(encoding[0], seal::KIND_COMMIT);
    assert_eq!(seal::decode_commit(&encoding).unwrap(), commit);
    let unsorted = seal::Commit { parents: vec![[3; 32], [2; 32]], ..commit.clone() };
    assert!(seal::encode_commit(&unsorted).is_err());
    let mut truncated = encoding.clone();
    truncated.pop();
    assert!(seal::decode_commit(&truncated).is_err());
    let name = seal::name_of(&name_key, &encoding);
    assert_ne!(name, seal::name_of(&[0; 32], &encoding), "names are keyed");

    let manifest = seal::encode_manifest(10_000, &[([7; 32], 6_000), ([8; 32], 4_000)]).unwrap();
    assert_eq!(manifest.len(), 13 + 2 * 36);
    assert!(seal::encode_manifest(10_000, &[([7; 32], 6_000)]).is_err(), "chunks must sum to the total");
    let chunk = seal::encode_chunk(b"bytes");
    assert_eq!(chunk, [&[seal::KIND_CHUNK][..], b"bytes"].concat());

    let entries = vec![
        seal::Entry { name: b"a".to_vec(), header: seal::EntryHeader { kind: 1, mode: 0o644, size: 3, ..Default::default() }, target: seal::Target::Inline(b"abc".to_vec()),
            xattrs: vec![(b"user.x".to_vec(), seal::Value::Inline(b"1".to_vec()))], access_control: None },
        seal::Entry { name: b"b".to_vec(), header: seal::EntryHeader { kind: 4, mode: 0o755, ..Default::default() }, target: seal::Target::Name([9; 32]), xattrs: vec![],
            access_control: Some(([0; seal::ACCESS_CONTROL_WORDS], seal::Value::Inline(Vec::new()))) },
    ];
    let tree = seal::encode_tree(&entries).unwrap();
    assert_eq!(tree[0], seal::KIND_TREE);
    assert_eq!(get32(&tree, 1), 2);
    assert!(seal::encode_tree(&[entries[1].clone(), entries[0].clone()]).is_err(), "entries sort by name");
    let mut wrong_size = entries[0].clone();
    wrong_size.header.size = 4;
    assert!(seal::encode_tree(&[wrong_size]).is_err(), "an inline target's length is its size");

    for suite in std::iter::once(None).chain(host_suites().into_iter().map(|(suite, _)| Some(suite))) {
        let key = [6u8; 32];
        for (kind, encoding) in [(seal::KIND_COMMIT, encoding.clone()), (seal::KIND_TREE, tree.clone()), (seal::KIND_CHUNK, seal::encode_chunk(&[0x41; 300_000]))] {
            let body = seal::build_body(&encoding, kind, suite, &key, &name);
            assert_eq!(body.len() as u64, padme((body.len() - suite.map_or(0, |_| 16)) as u64) + suite.map_or(0, |_| 16), "the body is Padmé-sized plus the tag");
            assert_eq!(seal::open_body(&body, kind, suite, &key, &name).unwrap(), encoding);
            if suite.is_some() {
                assert!(seal::open_body(&body, kind, suite, &[7; 32], &name).is_err(), "another key does not open it");
                assert!(seal::open_body(&body, kind, suite, &key, &[0; 32]).is_err(), "the name is associated data");
            }
            let mut damaged = body.clone();
            damaged[9] ^= 1;
            assert!(seal::open_body(&damaged, kind, suite, &key, &name).is_err());
        }
    }

    // Pack index and super-index read back what was written.
    let rows = vec![seal::IndexRow { name: [1; 32], offset: 0x18, stored_length: 40 }, seal::IndexRow { name: [200; 32], offset: 0x60, stored_length: 8 }];
    let index = seal::pack_index(&[3; 16], (2, 2), &rows).unwrap();
    let (pack, read_rows) = seal::read_pack_index(&index).unwrap();
    assert_eq!(pack, (2, 2));
    assert_eq!(read_rows.len(), 2);
    assert_eq!((read_rows[1].offset, read_rows[1].stored_length), (0x60, 8));
    let super_rows = vec![seal::SuperRow { name: [1; 32], pack: 0, offset: 0x18, stored_length: 40 }];
    let super_index = seal::super_index(&[3; 16], &[(2, 2)], &super_rows).unwrap();
    let (packs, read_super) = seal::read_super_index(&super_index).unwrap();
    assert_eq!(packs, vec![(2, 2)]);
    assert_eq!(read_super[0].name, [1; 32]);
    let mut damaged = super_index.clone();
    damaged[0x30] ^= 1;
    assert!(seal::read_super_index(&damaged).is_err(), "the fanout is checked");
    assert_eq!(seal::pack_file_name(2, false), "pack-0000000000000002.pack");
    assert_eq!(seal::pack_file_name(2, true), "pack-0000000000000002.idx");
}

#[test]
fn the_sealer_produces_a_store_the_verifier_resolves() {
    let contents = contents();
    let perm = |path: &str, default_mode: u32| build::lookup_perm(&contents.permissions, path, default_mode);
    let inputs = seal::SealInputs {
        suite: Some(Suite::XChaCha20Poly1305), name_key: [1; 32], key_material: [2; 32], store_identity: [3; 16], subvol_uuid: [4; 16], seal_time: 5, clock_valid: true,
        chunker: codec::fastcdc::Params::DEFAULT, casefold_root: false, time_ns: 6, contents: &contents, pack_identity: (2, 2), perm: &perm,
    };
    let sealed = seal::seal(&inputs).unwrap();
    assert_eq!(sealed.commit.subvol_uuid, [4; 16]);
    assert_eq!(sealed.commit.seal_time, 5);
    assert!(sealed.commit.parents.is_empty());
    assert_eq!(sealed.commit_name, seal::name_of(&[1; 32], &sealed.commit_encoding));
    assert_eq!(seal::decode_commit(&sealed.commit_encoding).unwrap(), sealed.commit);
    assert_eq!(&sealed.pack[..4], seal::PACK_MAGIC);
    // Root, bin, etc, usr, usr/lib, dev, var, var/log: eight trees, the
    // 20000-byte file as one manifest and one chunk, the commit.
    let (_, rows) = seal::read_pack_index(&sealed.index).unwrap();
    assert_eq!(rows.len(), sealed.objects.len());
    assert!(sealed.objects.iter().any(|o| o.name == sealed.commit_name));
    let mut names: Vec<[u8; 32]> = sealed.objects.iter().map(|o| o.name).collect();
    names.sort();
    names.dedup();
    assert_eq!(names.len(), sealed.objects.len(), "one object per name");
    for object in &sealed.objects {
        let row = rows.iter().find(|r| r.name == object.name).unwrap();
        let at = row.offset as usize;
        assert_eq!(&sealed.pack[at..at + 32], &object.name);
        assert_eq!(get64(&sealed.pack, at + 32), row.stored_length);
        assert_eq!(&sealed.pack[at + seal::PACK_ENTRY_HEADER_SIZE..at + seal::PACK_ENTRY_HEADER_SIZE + row.stored_length as usize], &object.body);
        let key = blake3::derive_key(b"SaltyFS image writer object key", &[&[2u8; 32][..], &object.name].concat());
        assert_eq!(object.key, key);
    }
    let (packs, super_rows) = seal::read_super_index(&sealed.super_index).unwrap();
    assert_eq!(packs, vec![(2, 2)]);
    assert_eq!(super_rows.len(), sealed.objects.len());
    let same = seal::seal(&inputs).unwrap();
    assert_eq!(same.pack, sealed.pack, "sealing is deterministic");
}
