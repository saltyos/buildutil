//! SPDX-License-Identifier: GPL-2.0-only
//! buildutil — derivation identity
//!
//! A derivation is a pure function of its declared inputs. The canonical
//! serialization below IS the SHA-256 preimage (input-addressed): tool
//! identities, the declared static environment, source/source-tree content
//! hashes, dependency **realization digests**, the referenced configuration
//! projection, the resolved argv (with `{out}` / `{srcroot}` / `{dep:*}`
//! tokens left symbolic so store locations never enter the identity), and
//! the declared outputs. Line order inside each section is sorted; argv
//! keeps its own order. Values must not contain newlines (validated at spec
//! load). The build-directory paths themselves (out dir, stage root,
//! HOME/TMPDIR/PATH) are construction details, not inputs, and stay out of
//! the preimage.
//!
//! Format 5: the preimage carries a leading `format: 5` line,
//! copy/stage-dep execution declarations, the allowed reference policy, a
//! module builder's `module-config:` digest after its configuration lines,
//! and each `dep:` line references
//! the dependency's **realization digest** (content-addressed) rather than
//! its derivation hash — the early-cutoff mechanism. A dependency that
//! rebuilds to identical bytes leaves every dependent's preimage unchanged,
//! so the dependents' store lookups hit and the rebuild short-circuits.
//!
//! Identity-bearing fields (the SHA-256 hash and store-name) are computed
//! eagerly at `Derivation::seal` and cached immutably on the wrapper; the
//! public read view is via `Deref<Target = DrvParts>` so every existing
//! reader (`drv.name`, `drv.argv`, `drv.deps`, `drv.preimage()`, …) keeps
//! working byte-for-byte. No `DerefMut`: post-construction mutation is a
//! compile error, which is the whole point of the encapsulation.

use crate::spec::RefPolicy;

/// A finalized reference to a realized dependency. `digest` is the
/// dependency's realization digest (what enters this derivation's preimage);
/// `store_name` is the concrete provider directory that holds those bytes
/// (used for the meta `ref:` GC edge and the `stage/dep/<name>` staging
/// target). The two are deliberately separate: overloading one for the other
/// silently breaks either early cutoff or GC.
#[derive(Debug, Clone)]
pub struct DepRef {
    pub name: String,
    pub digest: String,
    pub store_name: String,
}

/// The mutable, preimage-bearing parts of a derivation. Identity inputs
/// live here — every field participates in `preimage()` exactly once.
/// Construct a `DrvParts` value, finalize it, then seal it into a
/// `Derivation` to lock its hash / store_name. `Derivation::Deref` reads
/// these fields transparently.
#[derive(Debug, Clone)]
pub struct DrvParts {
    pub name: String,
    pub arch: String,
    pub builder: String,
    /// (tool name, provider marker) — store:<derivation>:<output-relpath>.
    pub tools: Vec<(String, String)>,
    /// Static declared environment (the builder also gets private
    /// HOME/TMPDIR/PATH pointing into the build dir).
    pub env: Vec<(String, String)>,
    /// (repo-relative path, content sha256) for declared single files.
    pub srcs: Vec<(String, String)>,
    /// (repo-relative path, manifest sha256) for declared source subtrees.
    pub srcdirs: Vec<(String, String)>,
    /// Staged source roots: actual directories are created in the stage and
    /// their top-level entries are symlinked, allowing dependency overlays to
    /// replace selected entries without mutating the repository checkout.
    pub source_roots: Vec<(String, String)>,
    /// (source token, repo-relative destination) overlaid after source roots.
    pub source_overlays: Vec<(String, String)>,
    /// Output copy declarations, kept symbolic in identity.
    pub copy: Vec<(String, String)>,
    /// Dependency-file staging declarations, kept symbolic in identity.
    pub stage_deps: Vec<(String, String)>,
    /// Store-reference policy, kept symbolic in identity.
    pub allowed_refs: RefPolicy,
    /// Finalized dependency references (realization digest + provider).
    pub deps: Vec<DepRef>,
    /// Referenced configuration keys and their resolved values.
    pub config: Vec<(String, String)>,
    /// A module builder's effective module configuration, as the SHA-256 of
    /// its canonical text; `None` for every other builder.
    pub module_config: Option<String>,
    /// Fully resolved argv, one token per element; argv[0] is the declared
    /// tool name, resolved through its store provider at execution.
    pub argv: Vec<String>,
    /// Canonical lines describing a script-dag derivation's active inner
    /// plan (compile groups + steps); empty for plain builders.
    pub plan: Vec<String>,
    pub outputs: Vec<String>,
}

/// The preimage format version. A bump changes every hash; there is no
/// migration — old store entries never match again and GC sweeps them.
pub const PREIMAGE_FORMAT: u32 = 5;

/// Hexadecimal digits of the derivation hash that begin its store name.
const STORE_NAME_HASH_DIGITS: usize = 32;

/// A finalized, identity-locked derivation. Construction goes through
/// `Derivation::seal(DrvParts)`; the SHA-256 hash and store name are then
/// computed eagerly from `parts.preimage()` and stored in `id_hash` /
/// `id_store_name`. They cannot drift from the parts because both are
/// immutable after sealing, and every field that participates in the
/// preimage lives behind the `Deref` view as `DrvParts`.
#[derive(Debug, Clone)]
pub struct Derivation {
    parts: DrvParts,
    /// SHA-256 over `parts.preimage()` as hex (eagerly computed in `seal`).
    id_hash: String,
    /// `<hash32>-<name>-<arch>` (eagerly computed in `seal`).
    id_store_name: String,
}

impl Derivation {
    /// Construct a `Derivation` from finalized parts, eagerly computing its
    /// hash and store_name. The parts move in and are never observable
    /// mutably; treat every `Derivation` as an immutable identity.
    pub fn seal(parts: DrvParts) -> Derivation {
        let id_hash = crate::crypto::sha256::hash_bytes(parts.preimage().as_bytes());
        let id_store_name =
            format!("{}-{}-{}", &id_hash[..STORE_NAME_HASH_DIGITS], parts.name, parts.arch);
        Derivation {
            parts,
            id_hash,
            id_store_name,
        }
    }

    pub fn hash(&self) -> String {
        self.id_hash.clone()
    }

    /// Store directory name: first 32 hex of the drv hash + name + arch.
    pub fn store_name(&self) -> String {
        self.id_store_name.clone()
    }

    /// The hash digits that begin the store name, which `{self-hash}`
    /// expands to. The hash covers the arguments with that token symbolic,
    /// so its expansion never enters the identity it names.
    pub fn name_hash(&self) -> &str {
        &self.id_hash[..STORE_NAME_HASH_DIGITS]
    }

    /// Return one fixed-output contract value encoded in the canonical argv.
    /// Fixed-output argv is identity-bearing even though tools, environment,
    /// and sources deliberately are not; output pins therefore belong here.
    pub fn fixed_output_pin(&self, label: &str) -> Option<&str> {
        let prefix = format!("fixed-output:{label}:");
        self.argv.iter().find_map(|arg| arg.strip_prefix(&prefix))
    }

    /// Tests-only accessor for the parts view.
    #[cfg(test)]
    #[allow(dead_code)]
    pub fn parts(&self) -> &DrvParts {
        &self.parts
    }
}

impl std::ops::Deref for Derivation {
    type Target = DrvParts;
    fn deref(&self) -> &DrvParts {
        &self.parts
    }
}

impl DrvParts {
    pub fn preimage(&self) -> String {
        let mut out = String::from("buildutil-drv\n");
        out.push_str(&format!("format: {}\n", PREIMAGE_FORMAT));
        out.push_str(&format!("name: {}\n", self.name));
        out.push_str(&format!("arch: {}\n", self.arch));
        out.push_str(&format!("builder: {}\n", self.builder));
        // Fixed-output derivations commit to their complete declared output
        // contract in argv. Blob imports carry `fixed-output:sha256:<h>`;
        // untar additionally carries `fixed-output:tree-sha256:<h>`, so a
        // changed extraction contract cannot reuse the old store name.
        // In-process builders are deterministic
        // engine operations; their stable builder contract/version, declared
        // inputs, and dep digests matter, but the host binary executing the
        // operation does not.
        let fixed_output = crate::spec::builders::is_fixed_output(&self.builder);
        let in_process = crate::spec::builders::is_in_process(&self.builder);
        if !fixed_output {
            if !in_process {
                let mut tools = self.tools.clone();
                tools.sort();
                for (name, identity) in &tools {
                    out.push_str(&format!("tool: {}={}\n", name, identity));
                }
            }
            let mut env = self.env.clone();
            env.sort();
            for (k, v) in &env {
                out.push_str(&format!("env: {}={}\n", k, v));
            }
            let mut srcs = self.srcs.clone();
            srcs.sort();
            for (path, h) in &srcs {
                out.push_str(&format!("src: {}=sha256:{}\n", path, h));
            }
            let mut srcdirs = self.srcdirs.clone();
            srcdirs.sort();
            for (path, h) in &srcdirs {
                out.push_str(&format!("srcdir: {}=sha256:{}\n", path, h));
            }
            let mut source_roots = self.source_roots.clone();
            source_roots.sort();
            for (path, h) in &source_roots {
                out.push_str(&format!("source-root: {}=sha256:{}\n", path, h));
            }
            let mut source_overlays = self.source_overlays.clone();
            source_overlays.sort();
            for (src, dest) in &source_overlays {
                out.push_str(&format!("source-overlay: {}={}\n", src, dest));
            }
            let mut copy = self.copy.clone();
            copy.sort();
            for (src, dest) in &copy {
                out.push_str(&format!("copy: {}={}\n", src, dest));
            }
            let mut stage_deps = self.stage_deps.clone();
            stage_deps.sort();
            for (src, dest) in &stage_deps {
                out.push_str(&format!("stage-dep: {}={}\n", src, dest));
            }
            match &self.allowed_refs {
                RefPolicy::None => out.push_str("allowed-refs: none\n"),
                RefPolicy::Closure => out.push_str("allowed-refs: closure\n"),
                RefPolicy::List(items) => {
                    let mut items = items.clone();
                    items.sort();
                    for name in &items {
                        out.push_str(&format!("allowed-ref: {}\n", name));
                    }
                }
            }
            let mut deps: Vec<&DepRef> = self.deps.iter().collect();
            deps.sort_by(|a, b| a.name.cmp(&b.name));
            for dep in deps {
                out.push_str(&format!("dep: {}=sha256:{}\n", dep.name, dep.digest));
            }
            let mut config = self.config.clone();
            config.sort();
            for (k, v) in &config {
                out.push_str(&format!("config: {}={}\n", k, v));
            }
            if let Some(digest) = &self.module_config {
                out.push_str(&format!("module-config: sha256:{}\n", digest));
            }
        }
        for arg in &self.argv {
            out.push_str(&format!("argv: {}\n", arg));
        }
        for line in &self.plan {
            out.push_str(&format!("plan: {}\n", line));
        }
        for o in &self.outputs {
            out.push_str(&format!("out: {}\n", o));
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_parts() -> DrvParts {
        DrvParts {
            name: "uapi-src".into(),
            arch: "x86_64".into(),
            builder: "bindgen".into(),
            tools: vec![("bindgen".into(), "sha256:aa;bindgen 0.72.0".into())],
            env: vec![
                ("SOURCE_DATE_EPOCH".into(), "1".into()),
                ("LC_ALL".into(), "C".into()),
            ],
            srcs: vec![("kernite/include/uapi/bindgen.h".into(), "bb".into())],
            srcdirs: vec![],
            source_roots: vec![],
            source_overlays: vec![],
            copy: vec![],
            stage_deps: vec![],
            allowed_refs: RefPolicy::None,
            deps: vec![],
            config: vec![],
            module_config: None,
            argv: vec![
                "bindgen".into(),
                "--use-core".into(),
                "--output".into(),
                "{out}/uapi.rs".into(),
            ],
            plan: vec![],
            outputs: vec!["uapi.rs".into()],
        }
    }

    fn sample() -> Derivation {
        Derivation::seal(sample_parts())
    }

    #[test]
    fn identity_is_stable_and_input_sensitive() {
        let a = sample();
        let b = sample();
        assert_eq!(a.hash(), b.hash());
        assert!(a.store_name().starts_with(&a.hash()[..32]));
        assert!(a.store_name().ends_with("-uapi-src-x86_64"));

        let mut c_parts = sample_parts();
        c_parts.srcs[0].1 = "cc".into();
        let c = Derivation::seal(c_parts);
        assert_ne!(a.hash(), c.hash());

        let mut d_parts = sample_parts();
        d_parts.env.push(("EXTRA".into(), "1".into()));
        let d = Derivation::seal(d_parts);
        assert_ne!(a.hash(), d.hash());
    }

    #[test]
    fn preimage_is_format_4() {
        let a = sample();
        assert!(a.preimage().starts_with("buildutil-drv\nformat: 5\n"));
    }

    #[test]
    fn allowed_refs_policy_enters_identity() {
        let a = sample();
        let mut b_parts = sample_parts();
        b_parts.allowed_refs = RefPolicy::Closure;
        let b = Derivation::seal(b_parts);
        assert_ne!(a.hash(), b.hash());
        assert!(a.preimage().contains("allowed-refs: none\n"));
        assert!(b.preimage().contains("allowed-refs: closure\n"));
    }

    #[test]
    fn copy_stage_deps_and_allowed_refs_enter_format_4_identity_in_order() {
        let original_hash = sample().hash();
        let mut parts = sample_parts();
        parts.copy = vec![
            ("{srcroot}/z".into(), "out/z".into()),
            ("{dep:lib}/a".into(), "out/a".into()),
        ];
        parts.stage_deps = vec![
            ("{dep:lib}/include/z.h".into(), "include/z.h".into()),
            ("{dep:lib}/include/a.h".into(), "include/a.h".into()),
        ];
        parts.allowed_refs = RefPolicy::List(vec!["zeta".into(), "alpha".into()]);
        let a = Derivation::seal(parts);
        let pre = a.preimage();
        let copy_a = pre.find("copy: {dep:lib}/a=out/a").unwrap();
        let copy_z = pre.find("copy: {srcroot}/z=out/z").unwrap();
        let stage_a = pre
            .find("stage-dep: {dep:lib}/include/a.h=include/a.h")
            .unwrap();
        let stage_z = pre
            .find("stage-dep: {dep:lib}/include/z.h=include/z.h")
            .unwrap();
        let allowed_a = pre.find("allowed-ref: alpha").unwrap();
        let allowed_z = pre.find("allowed-ref: zeta").unwrap();
        let dep_pos = pre.find("\ndep:").unwrap_or(pre.len());
        assert!(copy_a < copy_z);
        assert!(copy_z < stage_a);
        assert!(stage_a < stage_z);
        assert!(stage_z < allowed_a);
        assert!(allowed_a < allowed_z);
        assert!(allowed_z < dep_pos);
        assert_ne!(original_hash, a.hash());
    }

    #[test]
    fn dep_lines_use_realization_digests_sorted_by_name() {
        let mut parts = sample_parts();
        parts.deps = vec![
            DepRef {
                name: "zeta".into(),
                digest: "zdigest".into(),
                store_name: "zz-zeta-x86_64".into(),
            },
            DepRef {
                name: "alpha".into(),
                digest: "adigest".into(),
                store_name: "aa-alpha-x86_64".into(),
            },
        ];
        let a = Derivation::seal(parts);
        let pre = a.preimage();
        let alpha = pre.find("dep: alpha=sha256:adigest").unwrap();
        let zeta = pre.find("dep: zeta=sha256:zdigest").unwrap();
        assert!(alpha < zeta, "dep lines must be sorted by name");
        // The provider store_name is NOT part of identity.
        assert!(!pre.contains("aa-alpha-x86_64"));
    }

    #[test]
    fn fetch_identity_excludes_runtime_provisioning() {
        // A fixed-output fetch's identity is the declared hash alone: the
        // store-tool markers and provider dep edges it carries for staging
        // must not move the preimage, and the preimage stays byte-identical
        // to one with no provisioning at all.
        let bare_parts = DrvParts {
            name: "stage0-rustc".into(),
            arch: "any".into(),
            builder: "fetch".into(),
            tools: vec![],
            env: vec![],
            srcs: vec![],
            srcdirs: vec![],
            source_roots: vec![],
            source_overlays: vec![],
            copy: vec![],
            stage_deps: vec![],
            allowed_refs: RefPolicy::None,
            deps: vec![],
            config: vec![],
            module_config: None,
            argv: vec!["fixed-output:sha256:aabb".into()],
            plan: vec![],
            outputs: vec!["source.tar".into()],
        };
        let bare = Derivation::seal(bare_parts.clone());
        let mut provisioned_parts = bare_parts;
        provisioned_parts.tools = vec![
            ("sh".into(), "store:bootstrap-seed:bin/sh".into()),
            ("curl".into(), "store:bootstrap-seed:bin/curl".into()),
        ];
        provisioned_parts.deps = vec![DepRef {
            name: "bootstrap-seed".into(),
            digest: "seeddigest".into(),
            store_name: "ss-bootstrap-seed-aarch64".into(),
        }];
        let provisioned = Derivation::seal(provisioned_parts);
        assert_eq!(bare.preimage(), provisioned.preimage());
        assert!(!provisioned.preimage().contains("bootstrap-seed"));
    }

    #[test]
    fn untar_tree_pin_is_identity_bearing() {
        let mut a = sample_parts();
        a.builder = "untar".into();
        a.argv = vec![
            "fixed-output:sha256:same-archive".into(),
            "fixed-output:tree-sha256:tree-a".into(),
        ];
        let mut b = a.clone();
        b.argv[1] = "fixed-output:tree-sha256:tree-b".into();
        let a = Derivation::seal(a);
        let b = Derivation::seal(b);
        assert_ne!(a.hash(), b.hash());
        assert_eq!(a.fixed_output_pin("tree-sha256"), Some("tree-a"));
    }

    #[test]
    fn section_order_is_canonical() {
        let mut parts_reversed = sample_parts();
        parts_reversed.env.reverse();
        parts_reversed.tools.reverse();
        let a = Derivation::seal(parts_reversed);
        let b = sample();
        // Sorting inside preimage makes declaration order irrelevant…
        assert_eq!(a.hash(), b.hash());
        // …but argv order is meaningful.
        let mut parts_swap = sample_parts();
        parts_swap.argv.swap(1, 2);
        let c = Derivation::seal(parts_swap);
        assert_ne!(c.hash(), b.hash());
    }

    #[test]
    fn clone_of_sealed_drv_has_same_identity() {
        let a = sample();
        let b = a.clone();
        assert_eq!(a.hash(), b.hash());
        assert_eq!(a.store_name(), b.store_name());
    }
}
