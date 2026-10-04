//! SPDX-License-Identifier: GPL-2.0-only
//! buildutil — host: the container executor image, built from pinned inputs
//!
//! The executor image is `FROM scratch` with two layers: the pinned seed
//! archive as it is, and the stage-0 Rust distribution merged under the
//! declared prefix. buildutil writes the image itself as a docker-archive —
//! manifest, configuration and layers with fixed bytes — and loads it with
//! `docker load` or `nerdctl load`, so the image identity, the digest of its
//! configuration, is a function of its inputs and the same under either
//! runtime. The stage-0 archives are fetched once by the seed's own curl,
//! inside an image holding only the seed layer, and verified against their
//! pins here; the runtime carries the bytes and makes none.

use super::BuildHost;
use crate::spec::ExecutorImageSpec;
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

/// The executor image a container run uses: its local tag and its
/// content identity.
pub(crate) struct ExecutorImage {
    pub(crate) tag: String,
    /// `sha256:<digest of the image configuration>`.
    pub(crate) id: String,
}

/// Merges the distribution's component archives under the prefix and packs
/// the layer with fixed order, times and owners. Runs in the seed image with
/// the seed's shell, gzip, tar and cp; every byte of the layer follows from
/// the archives and this script.
const RUST_LAYER_SCRIPT: &str = r#"set -eu
umask 022
out=$1
work=$2
prefix=$3
shift 3
rm -rf "$work"
mkdir -p "$work/root/$prefix" "$work/root/tmp" "$work/unpack"
chmod 1777 "$work/root/tmp"
for archive in "$@"; do
  rm -rf "$work/unpack"
  mkdir -p "$work/unpack"
  gzip -dc "$archive" | tar -xf - -C "$work/unpack"
  set -- "$work/unpack"/*
  if [ "$#" -ne 1 ] || [ ! -f "$1/components" ]; then
    echo "executor image: $archive is not one distribution directory" >&2
    exit 1
  fi
  dist=$1
  while IFS= read -r component; do
    [ -n "$component" ] || continue
    cp -R "$dist/$component/." "$work/root/$prefix/"
  done < "$dist/components"
done
rm -f "$work/root/$prefix/manifest.in"
cd "$work/root"
tar --sort=name --mtime=@1 --owner=0 --group=0 --numeric-owner --format=gnu \
  -cf "$out.part" "${prefix%%/*}" tmp
mv "$out.part" "$out"
rm -rf "$work"
"#;

fn image_arch(build_host: &BuildHost) -> &'static str {
    match build_host.arch() {
        "aarch64" => "arm64",
        _ => "amd64",
    }
}

/// The image configuration: deterministic JSON (fixed key order, no
/// creation time), so its digest names the image.
fn config_json(arch: &str, env: &[String], diff_ids: &[String]) -> String {
    let quote = |s: &str| format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""));
    let env: Vec<String> = env.iter().map(|e| quote(e)).collect();
    let ids: Vec<String> = diff_ids
        .iter()
        .map(|d| quote(&format!("sha256:{d}")))
        .collect();
    format!(
        "{{\"architecture\":{},\"config\":{{\"Env\":[{}],\"WorkingDir\":\"/\"}},\"os\":\"linux\",\"rootfs\":{{\"diff_ids\":[{}],\"type\":\"layers\"}}}}",
        quote(arch),
        env.join(","),
        ids.join(",")
    )
}

/// One ustar header block for a regular file with fixed metadata.
fn ustar_header(name: &str, size: u64) -> Result<[u8; 512], String> {
    if name.len() > 100 {
        return Err(format!("image archive entry name too long: {name}"));
    }
    let mut h = [0u8; 512];
    h[..name.len()].copy_from_slice(name.as_bytes());
    let octal = |field: &mut [u8], value: u64| {
        let text = format!("{:0width$o}\0", value, width = field.len() - 1);
        field.copy_from_slice(text.as_bytes());
    };
    octal(&mut h[100..108], 0o644);
    octal(&mut h[108..116], 0);
    octal(&mut h[116..124], 0);
    octal(&mut h[124..136], size);
    octal(&mut h[136..148], 1);
    h[156] = b'0';
    h[257..263].copy_from_slice(b"ustar\0");
    h[263..265].copy_from_slice(b"00");
    h[148..156].copy_from_slice(b"        ");
    let sum: u32 = h.iter().map(|b| *b as u32).sum();
    let text = format!("{:06o}\0 ", sum);
    h[148..156].copy_from_slice(text.as_bytes());
    Ok(h)
}

fn write_entry(out: &mut File, name: &str, mut data: impl Read, size: u64) -> Result<(), String> {
    out.write_all(&ustar_header(name, size)?)
        .map_err(|e| format!("cannot write image archive: {e}"))?;
    let copied = std::io::copy(&mut data, out)
        .map_err(|e| format!("cannot write image archive: {e}"))?;
    if copied != size {
        return Err(format!("image archive entry {name} changed while it was written"));
    }
    let pad = (512 - (size % 512) as usize) % 512;
    out.write_all(&vec![0u8; pad])
        .map_err(|e| format!("cannot write image archive: {e}"))
}

/// Write a docker-archive holding one tagged image: the manifest, the
/// configuration and each layer under its uncompressed digest.
fn write_docker_archive(
    path: &Path,
    tag: &str,
    config: &str,
    config_digest: &str,
    layers: &[(String, PathBuf)],
) -> Result<(), String> {
    let layer_names: Vec<String> = layers
        .iter()
        .map(|(digest, _)| format!("\"{digest}/layer.tar\""))
        .collect();
    let manifest = format!(
        "[{{\"Config\":\"{config_digest}.json\",\"RepoTags\":[\"{tag}\"],\"Layers\":[{}]}}]",
        layer_names.join(",")
    );
    let part = path.with_extension("part");
    let mut out = File::create(&part)
        .map_err(|e| format!("cannot create {}: {e}", part.display()))?;
    write_entry(
        &mut out,
        "manifest.json",
        manifest.as_bytes(),
        manifest.len() as u64,
    )?;
    write_entry(
        &mut out,
        &format!("{config_digest}.json"),
        config.as_bytes(),
        config.len() as u64,
    )?;
    for (digest, layer) in layers {
        let file = File::open(layer).map_err(|e| format!("cannot open {}: {e}", layer.display()))?;
        let size = file
            .metadata()
            .map_err(|e| format!("cannot stat {}: {e}", layer.display()))?
            .len();
        write_entry(&mut out, &format!("{digest}/layer.tar"), file, size)?;
    }
    out.write_all(&[0u8; 1024])
        .map_err(|e| format!("cannot write image archive: {e}"))?;
    out.sync_all()
        .map_err(|e| format!("cannot sync {}: {e}", part.display()))?;
    std::fs::rename(&part, path).map_err(|e| format!("cannot publish {}: {e}", path.display()))
}

fn image_present(runtime: &str, tag: &str) -> bool {
    crate::invocation::command(runtime)
        .args(["image", "inspect", "--format", "{{.Id}}", tag])
        .stdout(crate::invocation::Io::Null)
        .stderr(crate::invocation::Io::Null)
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

/// Load the image `tag` from its archive unless the runtime already holds
/// it. The tag carries the configuration digest, so a present tag is the
/// same image.
fn ensure_loaded(
    runtime: &str,
    tmp: &Path,
    tag: &str,
    config: &str,
    config_digest: &str,
    layers: &[(String, PathBuf)],
) -> Result<(), String> {
    if image_present(runtime, tag) {
        return Ok(());
    }
    let archive = tmp.join(format!("{}.tar", tag.replace([':', '/'], "-")));
    write_docker_archive(&archive, tag, config, config_digest, layers)?;
    let output = crate::invocation::command(runtime)
        .args(["load", "-i"])
        .arg(&archive)
        .output()
        .map_err(|e| format!("cannot run {runtime} load: {e}"));
    let _ = std::fs::remove_file(&archive);
    let output = output?;
    if !output.status.success() {
        return Err(format!(
            "{runtime} load of {tag} failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    if !image_present(runtime, tag) {
        return Err(format!("{runtime} load did not provide {tag}"));
    }
    Ok(())
}

fn build_image(
    runtime: &str,
    tmp: &Path,
    name: &str,
    arch: &str,
    env: &[String],
    layers: &[(String, PathBuf)],
) -> Result<ExecutorImage, String> {
    let diff_ids: Vec<String> = layers.iter().map(|(digest, _)| digest.clone()).collect();
    let config = config_json(arch, env, &diff_ids);
    let digest = crate::crypto::sha256::hash_bytes(config.as_bytes());
    let tag = format!("{name}:{}", &digest[..32]);
    ensure_loaded(runtime, tmp, &tag, &config, &digest, layers)?;
    Ok(ExecutorImage {
        tag,
        id: format!("sha256:{digest}"),
    })
}

/// Run `argv` in the seed image with the state root mounted, for the
/// seed's own tools.
fn run_in_seed(
    runtime: &str,
    build_host: &BuildHost,
    seed: &ExecutorImage,
    state_root: &Path,
    argv: &[String],
) -> Result<(), String> {
    let output = crate::invocation::command(runtime)
        .args(["run", "--rm", "--platform", build_host.container_platform()])
        .arg("-v")
        .arg(format!(
            "{}:{}:rw",
            state_root.display(),
            super::container::CONTAINER_STATE_ROOT
        ))
        .arg(&seed.tag)
        .args(argv)
        .output()
        .map_err(|e| format!("cannot run {runtime}: {e}"))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(format!(
            "{} in the seed image failed: {}",
            argv.first().map(String::as_str).unwrap_or("command"),
            String::from_utf8_lossy(&output.stderr).trim()
        ))
    }
}

fn in_container(state_root: &Path, path: &Path) -> Result<String, String> {
    let rel = path
        .strip_prefix(state_root)
        .map_err(|_| format!("{} is outside the state root", path.display()))?;
    Ok(Path::new(super::container::CONTAINER_STATE_ROOT)
        .join(rel)
        .to_string_lossy()
        .into_owned())
}

/// Prepare the executor image for `build_host` from its declared inputs,
/// fetching and assembling what is missing, and load it into `runtime`.
pub(crate) fn prepare_executor_image(
    runtime: &str,
    state_root: &Path,
    build_host: &BuildHost,
    spec: &ExecutorImageSpec,
) -> Result<ExecutorImage, String> {
    let tmp = state_root.join("tmp").join("executor");
    std::fs::create_dir_all(&tmp).map_err(|e| format!("cannot create {}: {e}", tmp.display()))?;
    let arch = image_arch(build_host);

    let seed_path = state_root.join(&spec.seed);
    if !seed_path.is_file() {
        return Err(format!(
            "the pinned seed is missing at {} — place the output of its seed derivation or of \
             the first-seed recipe there",
            seed_path.display()
        ));
    }
    let seed_digest = crate::source::filehash::hash_file(&seed_path)?;
    if seed_digest != spec.seed_sha256 {
        return Err(format!(
            "seed {} does not match its pin\n  declared {}\n  actual   {}",
            seed_path.display(),
            spec.seed_sha256,
            seed_digest
        ));
    }
    let seed_layer = vec![(seed_digest.clone(), seed_path.clone())];
    let seed_image = build_image(
        runtime,
        &tmp,
        "buildutil-seed",
        arch,
        &["PATH=/bin".to_string()],
        &seed_layer,
    )?;

    // The stage-0 archives, fetched by the seed's curl and verified here.
    let archive_dir = seed_path
        .parent()
        .ok_or("seed path has no directory")?
        .join("stage0");
    std::fs::create_dir_all(&archive_dir)
        .map_err(|e| format!("cannot create {}: {e}", archive_dir.display()))?;
    let mut archives = Vec::new();
    for (url, sha) in &spec.rust_archives {
        let name = url.rsplit('/').next().unwrap_or(url);
        let path = archive_dir.join(name);
        let valid = path.is_file() && crate::source::filehash::hash_file(&path)? == *sha;
        if !valid {
            let part = archive_dir.join(format!("{name}.part"));
            let _ = std::fs::remove_file(&part);
            crate::log::announce("backend", &format!("Fetching {name} with the seed's curl"));
            run_in_seed(
                runtime,
                build_host,
                &seed_image,
                state_root,
                &[
                    "/bin/curl".to_string(),
                    "-fL".to_string(),
                    "--retry".to_string(),
                    "3".to_string(),
                    "-o".to_string(),
                    in_container(state_root, &part)?,
                    url.clone(),
                ],
            )?;
            let actual = crate::source::filehash::hash_file(&part)?;
            if actual != *sha {
                let _ = std::fs::remove_file(&part);
                return Err(format!(
                    "{url} does not match its pin\n  declared {sha}\n  actual   {actual}"
                ));
            }
            std::fs::rename(&part, &path)
                .map_err(|e| format!("cannot publish {}: {e}", path.display()))?;
        }
        archives.push(path);
    }

    // The distribution layer, keyed by everything that decides its bytes.
    let mut key = format!("{}\n{}\n", spec.rust_prefix, RUST_LAYER_SCRIPT);
    for (_, sha) in &spec.rust_archives {
        key.push_str(sha);
        key.push('\n');
    }
    let key = crate::crypto::sha256::hash_bytes(key.as_bytes());
    let layer = tmp.join(format!("rust-{}.tar", &key[..32]));
    if !layer.is_file() {
        crate::log::announce("backend", "Assembling the stage-0 Rust layer");
        let work = tmp.join(format!("rust-{}.work", &key[..32]));
        let mut argv = vec![
            "/bin/sh".to_string(),
            "-c".to_string(),
            RUST_LAYER_SCRIPT.to_string(),
            "rust-layer".to_string(),
            in_container(state_root, &layer)?,
            in_container(state_root, &work)?,
            spec.rust_prefix.clone(),
        ];
        for archive in &archives {
            argv.push(in_container(state_root, archive)?);
        }
        run_in_seed(runtime, build_host, &seed_image, state_root, &argv)?;
        if !layer.is_file() {
            return Err(format!(
                "the stage-0 Rust layer was not produced at {}",
                layer.display()
            ));
        }
    }
    let layer_digest = crate::source::filehash::hash_file(&layer)?;

    let prefix = format!("/{}", spec.rust_prefix);
    let env = vec![
        format!("PATH={prefix}/bin:/bin"),
        format!("BUILDUTIL_RUSTC={prefix}/bin/rustc"),
        "BUILDUTIL_LINKER=/bin/cc".to_string(),
    ];
    build_image(
        runtime,
        &tmp,
        "buildutil-executor",
        arch,
        &env,
        &[
            (seed_digest, seed_path),
            (layer_digest, layer),
        ],
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn configuration_is_deterministic_and_names_layers_in_order() {
        let env = vec!["PATH=/opt/rust/bin:/bin".to_string()];
        let ids = vec!["a".repeat(64), "b".repeat(64)];
        let one = config_json("amd64", &env, &ids);
        let two = config_json("amd64", &env, &ids);
        assert_eq!(one, two);
        assert!(one.find(&"a".repeat(64)).unwrap() < one.find(&"b".repeat(64)).unwrap());
        assert!(!one.contains("created"));
    }

    #[test]
    fn archive_bytes_follow_from_the_inputs_alone() {
        let dir = std::env::temp_dir().join(format!("buildutil-image-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let layer = dir.join("layer");
        std::fs::write(&layer, b"layer bytes").unwrap();
        let digest = crate::crypto::sha256::hash_bytes(b"layer bytes");
        let config = config_json("arm64", &[], std::slice::from_ref(&digest));
        let config_digest = crate::crypto::sha256::hash_bytes(config.as_bytes());
        let layers = vec![(digest, layer)];
        let a = dir.join("a.tar");
        let b = dir.join("b.tar");
        write_docker_archive(&a, "buildutil-executor:x", &config, &config_digest, &layers).unwrap();
        write_docker_archive(&b, "buildutil-executor:x", &config, &config_digest, &layers).unwrap();
        assert_eq!(std::fs::read(&a).unwrap(), std::fs::read(&b).unwrap());
        assert_eq!(std::fs::metadata(&a).unwrap().len() % 512, 0);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn ustar_headers_carry_a_valid_checksum() {
        let h = ustar_header("manifest.json", 10).unwrap();
        let stored = u32::from_str_radix(
            std::str::from_utf8(&h[148..154]).unwrap(),
            8,
        )
        .unwrap();
        let mut copy = h;
        copy[148..156].copy_from_slice(b"        ");
        let sum: u32 = copy.iter().map(|b| *b as u32).sum();
        assert_eq!(stored, sum);
        assert!(ustar_header(&"x".repeat(101), 0).is_err());
    }
}
