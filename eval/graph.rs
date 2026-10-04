//! SPDX-License-Identifier: GPL-2.0-only
//! buildutil — target resolution, dependency graph, and the hash pass
//!
//! Targets are addresses a command resolved through its kind table
//! (`spec::kinds`): derivation or variant names, the readable configured form
//! and node keys. The graph is a graph of configured nodes: a derivation
//! evaluated under the overrides that reach it and change what it reads,
//! keyed `<name>` or `<name>@<hash>` (`spec::address`). The hash pass
//! produces a `Recipe` per node — source hashes, tool provider markers,
//! config projections, argv/plan, and dependency KEYS — but not a finalized
//! derivation hash: under staged resolution a dependent's identity embeds its
//! dependencies' realization digests, known only once they are realized. The
//! scheduler finalizes each recipe into a `Derivation` as its dependencies
//! resolve (`Recipe::finalize`); the preimage names every node and dependency
//! by its base name.

use super::ninja_emit;
use crate::source;
use crate::spec::address::{self, Overrides};
use crate::spec::configres::Config;
use crate::spec::{ActivePlan, DrvSpec, RefPolicy, Spec};
use crate::store::Store;
use crate::store::derivation::{DepRef, Derivation, DrvParts};
use crate::tools::{ToolLocator, ToolProvider, Toolchain};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, mpsc};

#[derive(Clone)]
pub(crate) struct CancellationToken(Arc<AtomicBool>);

impl CancellationToken {
    pub(crate) fn never() -> Self {
        Self::from_flag(Arc::new(AtomicBool::new(false)))
    }

    pub(crate) fn from_flag(flag: Arc<AtomicBool>) -> Self {
        Self(flag)
    }

    pub(crate) fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }

    fn check(&self) -> Result<(), String> {
        if self.is_cancelled() {
            Err("evaluation cancelled".to_string())
        } else {
            Ok(())
        }
    }
}

/// Everything needed to build a derivation EXCEPT its finalized dependency
/// references. Under staged resolution a dependent's preimage embeds each
/// dependency's realization digest, which is unknown until that dependency is
/// realized — so the hash pass produces recipes, and the scheduler finalizes
/// each into a `Derivation` once its dependencies' digests and providers are
/// known (`Recipe::finalize`).
#[derive(Debug, Clone)]
pub struct Recipe {
    pub name: String,
    pub arch: String,
    pub builder: String,
    pub tools: Vec<(String, String)>,
    pub env: Vec<(String, String)>,
    /// Regular-file sources with the executable-bit kind captured by the
    /// ingest pass.  Keeping the kind here lets plan emission assert CAS
    /// presence without re-statting the worktree.
    pub srcs: Vec<(char, String, String)>,
    pub srcdirs: Vec<(String, String)>,
    pub source_roots: Vec<(String, String)>,
    pub source_overlays: Vec<(String, String)>,
    pub copy: Vec<(String, String)>,
    pub stage_deps: Vec<(String, String)>,
    pub allowed_refs: RefPolicy,
    /// Dependency node keys, in declaration order.
    pub dep_names: Vec<String>,
    pub config: Vec<(String, String)>,
    /// A module builder's module-configuration digest.
    pub module_config: Option<String>,
    pub argv: Vec<String>,
    pub plan: Vec<String>,
    pub outputs: Vec<String>,
}

impl Recipe {
    /// Finalize into a `Derivation` once every dependency reference (its
    /// realization digest + provider store name) is known. A reference may
    /// carry a dependency's node key; the preimage names it by its base name.
    pub fn finalize(&self, deps: Vec<DepRef>) -> Derivation {
        let deps = deps
            .into_iter()
            .map(|dep| DepRef {
                name: address::base_name(&dep.name).to_string(),
                ..dep
            })
            .collect();
        Derivation::seal(DrvParts {
            name: self.name.clone(),
            arch: self.arch.clone(),
            builder: self.builder.clone(),
            tools: self.tools.clone(),
            env: self.env.clone(),
            srcs: self
                .srcs
                .iter()
                .map(|(_, rel, hash)| (rel.clone(), hash.clone()))
                .collect(),
            srcdirs: self.srcdirs.clone(),
            source_roots: self.source_roots.clone(),
            source_overlays: self.source_overlays.clone(),
            copy: self.copy.clone(),
            stage_deps: self.stage_deps.clone(),
            allowed_refs: self.allowed_refs.clone(),
            deps,
            config: self.config.clone(),
            module_config: self.module_config.clone(),
            argv: self.argv.clone(),
            plan: self.plan.clone(),
            outputs: self.outputs.clone(),
        })
    }
}

#[derive(Clone)]
pub struct Evaluated {
    /// Node keys of the requested closure, topologically ordered
    /// (dependencies first). Config-disabled (`when = …`) derivations reached
    /// through a group are filtered out.
    pub order: Vec<String>,
    /// Recipes by node key.
    pub recipes: BTreeMap<String, Recipe>,
    /// Active inner plans of script-dag derivations, by node key.
    pub plans: BTreeMap<String, ActivePlan>,
    /// The requested roots that are live, as (requested name, node key).
    pub roots: Vec<(String, String)>,
    /// The relevant override set of every configured (non-default) node.
    pub configured: BTreeMap<String, Overrides>,
    /// Digest of every configured node's resolved configuration values.
    pub config_digests: BTreeMap<String, String>,
    /// Stage-1 source results.  This is execution metadata only and never
    /// enters a derivation preimage except through the existing hashes.
    pub(crate) resolved_sources: ResolvedSources,
    pub(crate) git_state: (String, String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EvalProgress {
    pub current: usize,
    pub total: usize,
    pub phase: EvalPhase,
    pub detail: String,
    /// The item named by `detail` (a source, a derivation) starting or
    /// finishing; reported as the same job events a build's derivations use.
    pub item: Option<EvalItem>,
    /// The readable form of a configured node `detail` names, sent with its
    /// first report so screens never show a bare key.
    pub label: Option<String>,
}

/// One evaluation item's step, with the counts of finished items.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EvalItem {
    Started,
    /// Finished, with a short content hash when the item has one.
    Finished(String),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EvalPhase {
    ResolvingSources,
    Instantiating,
    Evaluated,
}

impl EvalPhase {
    pub fn as_str(self) -> &'static str {
        match self {
            EvalPhase::ResolvingSources => "resolving_sources",
            EvalPhase::Instantiating => "instantiating",
            EvalPhase::Evaluated => "evaluated",
        }
    }

    pub fn from_str(value: &str) -> Option<Self> {
        match value {
            "resolving_sources" => Some(EvalPhase::ResolvingSources),
            "instantiating" => Some(EvalPhase::Instantiating),
            "evaluated" => Some(EvalPhase::Evaluated),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Default)]
pub(crate) struct ResolvedSources {
    pub(crate) blobs: BTreeMap<String, (String, char)>,
    pub(crate) trees: BTreeMap<String, String>,
}

impl ResolvedSources {
    pub(crate) fn blob(&self, rel: &str) -> Result<(String, char), String> {
        self.blobs
            .get(rel)
            .cloned()
            .ok_or_else(|| format!("stage-1 omitted source `{rel}`"))
    }

    pub(crate) fn tree(&self, rel: &str) -> Result<String, String> {
        self.trees
            .get(rel)
            .cloned()
            .ok_or_else(|| format!("stage-1 omitted source tree `{rel}`"))
    }

    #[allow(dead_code)] // Used by full buildutil's eval cache, absent in minibuildutil.
    pub(crate) fn mappings(&self) -> impl Iterator<Item = (&str, String)> {
        self.blobs
            .iter()
            .map(|(path, (hash, kind))| (path.as_str(), format!("blob:{kind}:sha256:{hash}")))
            .chain(
                self.trees
                    .iter()
                    .map(|(path, hash)| (path.as_str(), format!("tree:{hash}"))),
            )
    }

    #[allow(dead_code)]
    pub(crate) fn contains_blob(&self, hash: &str, kind: char) -> bool {
        self.blobs
            .values()
            .any(|(candidate, candidate_kind)| candidate == hash && *candidate_kind == kind)
    }

    #[allow(dead_code)]
    pub(crate) fn contains_tree(&self, hash: &str) -> bool {
        self.trees.values().any(|candidate| candidate == hash)
    }
}

#[derive(Clone, Copy)]
enum WorkKind {
    Blob,
    Tree,
}

struct SourceWork {
    rel: String,
    key: String,
    kind: WorkKind,
    bootstrap: bool,
    owner: Option<crate::spec::Repository>,
}

pub(crate) struct PreparedEval {
    pub(crate) graph: ConfiguredGraph,
    pub(crate) resolved_sources: ResolvedSources,
    pub(crate) git_state: (String, String),
}

/// A finalized derivation paired with its dry-resolved realized signal.
/// `drv` is always present (the predecessor in the closure has been
/// resolved); `digest` is `Some` only when the store has a complete
/// realization record for the node (output dir exists and meta parses —
/// see `Store::has_named`), and the store_name + digest travel together
/// along the dep edge.
#[derive(Debug)]
pub struct ResolvedDrv {
    pub drv: Derivation,
    pub store_name: String,
    pub digest: Option<String>,
}

impl Evaluated {
    #[allow(dead_code)] // Used by full buildutil's eval cache, absent in minibuildutil.
    pub(crate) fn from_cached_plan(
        graph: &ConfiguredGraph,
        plan: &super::plan::ExecPlan,
        resolved_sources: ResolvedSources,
    ) -> Self {
        let order = plan.nodes.iter().map(|node| node.name.clone()).collect();
        let recipes = plan.recipes();
        let plans = plan
            .nodes
            .iter()
            .map(|node| (node.name.clone(), node.active_plan.clone()))
            .collect();
        Evaluated {
            order,
            recipes,
            plans,
            roots: graph.roots.clone(),
            configured: graph.configured(),
            config_digests: graph.config_digests(),
            resolved_sources,
            git_state: (plan.git_rev.clone(), plan.git_dirty.clone()),
        }
    }

    /// How a screen names a node: its readable form, the base name alone for
    /// the default configuration.
    pub fn readable(&self, key: &str) -> String {
        match self.configured.get(key) {
            Some(overrides) => address::readable(address::base_name(key), overrides),
            None => key.to_string(),
        }
    }

    /// Read-only staged resolution against the store: finalize the derivation
    /// for every node whose dependency closure is already realized (dep
    /// digests read from the store). Returns a map of finalized derivations
    /// paired with their realized signal (store_name + optional realization
    /// digest). A node whose dependencies are not yet realized is absent —
    /// its identity is not yet determined. Used by `buildutil eval`,
    /// `buildutil build`'s cache-candidate scan and `buildutil explain`,
    /// all of which observe identities without building.
    pub fn dry_resolve(&self, store: &Store) -> BTreeMap<String, ResolvedDrv> {
        dry_resolve_recipes(&self.order, &self.recipes, store)
    }
}

pub(crate) fn dry_resolve_recipes(
    order: &[String],
    recipes: &BTreeMap<String, Recipe>,
    store: &Store,
) -> BTreeMap<String, ResolvedDrv> {
    let in_closure: BTreeSet<&str> = order.iter().map(|s| s.as_str()).collect();
    // name → (realization digest, provider store name), for realized nodes.
    let mut realized: BTreeMap<String, (String, String)> = BTreeMap::new();
    let mut drvs: BTreeMap<String, ResolvedDrv> = BTreeMap::new();
    for name in order {
        let recipe = &recipes[name];
        let mut deps = Vec::new();
        let mut resolvable = true;
        for dep_name in &recipe.dep_names {
            if !in_closure.contains(dep_name.as_str()) {
                continue;
            }
            match realized.get(dep_name) {
                Some((digest, store_name)) => deps.push(DepRef {
                    name: dep_name.clone(),
                    digest: digest.clone(),
                    store_name: store_name.clone(),
                }),
                None => {
                    // A fetch's deps are runtime tool provisioning only —
                    // its identity is the declared output hash, so it
                    // stays observable on a cold store (an unrealized
                    // provider defers the *build*, not the identity).
                    if recipe.builder == "fetch" {
                        continue;
                    }
                    resolvable = false;
                    break;
                }
            }
        }
        if !resolvable {
            continue;
        }
        let drv = recipe.finalize(deps);
        let store_name = drv.store_name();
        // Record as realized (so dependents resolve) only if it is built:
        // a directory + parseable meta is the realized-signal contract
        // (Store::has_named). digest_of is read only after that check
        // passes — it is meta-only and would otherwise mis-report a
        // half-registered meta with no out dir as realized.
        let digest = if store.has_named(&store_name) {
            store.digest_of(&store_name).ok()
        } else {
            None
        };
        if let Some(d) = &digest {
            realized.insert(name.clone(), (d.clone(), store_name.clone()));
        }
        drvs.insert(
            name.clone(),
            ResolvedDrv {
                drv,
                store_name,
                digest,
            },
        );
    }
    drvs
}

/// The store-tool provider derivations a derivation's declared tools resolve
/// to — dependency edges in their own right. The registry maps each tool to
/// the derivation that provides it (bootstrap-aware); the graph must walk
/// those edges like declared `deps`, or a provider that no spec file names
/// explicitly is never ordered, instantiated, or realized. A registered
/// provider missing from the loaded spec is a hard eval error.
fn tool_provider_edges(spec: &Spec, dspec: &DrvSpec) -> Result<Vec<String>, String> {
    if crate::spec::builders::is_in_process(&dspec.builder) {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    for tool in std::iter::once(&dspec.tool).chain(dspec.extra_tools.iter()) {
        let Some(provider) = spec.tool_provider(dspec, tool) else {
            return Err(format!(
                "`{}` declares tool `{}`, which stage `{}` provides no derivation for",
                dspec.name,
                tool,
                crate::spec::stages::stage_name(dspec)
            ));
        };
        let ToolProvider::Store { drv: provider, .. } = provider else {
            continue;
        };
        if !spec.drvs.contains_key(&provider) {
            return Err(format!(
                "`{}` declares tool `{}`, whose provider derivation `{}` is not defined by any loaded buildutil.toml",
                dspec.name, tool, provider
            ));
        }
        if provider != dspec.name && !out.contains(&provider) {
            out.push(provider);
        }
    }
    Ok(out)
}

/// The static closure of derivation names: declared deps (a variant edge
/// reaches its base) plus store-tool provider edges, dependencies first. It
/// ignores configuration; queries that draw the declared graph use it.
pub fn closure(spec: &Spec, targets: &[String]) -> Result<Vec<String>, String> {
    let mut order: Vec<String> = Vec::new();
    let mut done: BTreeSet<String> = BTreeSet::new();
    let mut in_progress: BTreeSet<String> = BTreeSet::new();

    fn visit(
        name: &str,
        spec: &Spec,
        order: &mut Vec<String>,
        done: &mut BTreeSet<String>,
        in_progress: &mut BTreeSet<String>,
    ) -> Result<(), String> {
        let name = crate::spec::variant_base(&spec.variants, name);
        if done.contains(name) {
            return Ok(());
        }
        let dspec = spec
            .drvs
            .get(name)
            .ok_or_else(|| format!("unknown derivation `{name}`"))?;
        if !in_progress.insert(name.to_string()) {
            return Err(format!("dependency cycle through `{}`", name));
        }
        for dep in &dspec.deps {
            visit(dep, spec, order, done, in_progress)?;
        }
        for provider in tool_provider_edges(spec, dspec)? {
            visit(&provider, spec, order, done, in_progress)?;
        }
        in_progress.remove(name);
        done.insert(name.to_string());
        order.push(name.to_string());
        Ok(())
    }

    for target in targets {
        let target = target.trim_start_matches(crate::spec::kinds::OPTIONAL_PREFIX);
        let name = address::parse(target)?.name().to_string();
        visit(&name, spec, &mut order, &mut done, &mut in_progress)?;
    }
    Ok(order)
}

/// One node of the configured closure.
#[derive(Clone)]
pub(crate) struct ConfiguredNode {
    /// The derivation's own name, the one its preimage carries.
    pub(crate) name: String,
    /// The relevant override set; empty for the default configuration.
    pub(crate) overrides: Overrides,
    /// The configuration the node is evaluated under.
    pub(crate) config: Arc<Config>,
    /// (edge as declared — a dependency, variant or tool-provider name —,
    /// dependency key), declared dependencies first.
    pub(crate) deps: Vec<(String, String)>,
}

/// The configured closure of a request: nodes in dependency order and the
/// live requested roots.
#[derive(Clone, Default)]
pub(crate) struct ConfiguredGraph {
    pub(crate) order: Vec<String>,
    pub(crate) nodes: BTreeMap<String, ConfiguredNode>,
    /// (requested name, node key) of every live root, in request order.
    pub(crate) roots: Vec<(String, String)>,
}

impl ConfiguredGraph {
    /// The relevant override sets of the non-default nodes.
    pub(crate) fn configured(&self) -> BTreeMap<String, Overrides> {
        self.nodes
            .iter()
            .filter(|(_, node)| !node.overrides.is_empty())
            .map(|(key, node)| (key.clone(), node.overrides.clone()))
            .collect()
    }

    /// The digest of every configured node's resolved values.
    pub(crate) fn config_digests(&self) -> BTreeMap<String, String> {
        self.nodes
            .iter()
            .filter(|(_, node)| !node.overrides.is_empty())
            .map(|(key, node)| {
                let mut text = String::new();
                for (name, value) in &node.config.values {
                    text.push_str(name);
                    text.push('=');
                    text.push_str(value);
                    text.push('\n');
                }
                (
                    key.clone(),
                    crate::crypto::sha256::hash_bytes(text.as_bytes()),
                )
            })
            .collect()
    }
}

#[derive(Clone)]
enum Visit {
    Node(String),
    Disabled,
}

struct ClosureBuilder<'a> {
    spec: &'a Spec,
    base: Arc<Config>,
    cancel: &'a CancellationToken,
    visits: BTreeMap<(String, Overrides), Visit>,
    active: BTreeSet<(String, Overrides)>,
    graph: ConfiguredGraph,
}

impl<'a> ClosureBuilder<'a> {
    fn new(spec: &'a Spec, config: &Config, cancel: &'a CancellationToken) -> Self {
        Self {
            spec,
            base: Arc::new(config.clone()),
            cancel,
            visits: BTreeMap::new(),
            active: BTreeSet::new(),
            graph: ConfiguredGraph::default(),
        }
    }

    fn layered(&self, overrides: &Overrides) -> Result<Arc<Config>, String> {
        if overrides.is_empty() {
            Ok(Arc::clone(&self.base))
        } else {
            self.base.with_layered(overrides)
        }
    }

    /// Compose `extra` over `current`: a key a `-D` override sets to another
    /// value fails, as does a key the enclosing variants set to another
    /// value; an equal value passes.
    fn compose(
        &self,
        current: &Overrides,
        extra: &Overrides,
        through: &str,
    ) -> Result<Overrides, String> {
        let mut composed = current.clone();
        for (key, value) in extra {
            if let Some(cli) = self.base.cli_overrides.get(key)
                && cli != value
            {
                return Err(format!(
                    "-D{key}={cli} contradicts `{through}`, which sets {key}={value}"
                ));
            }
            match composed.get(key) {
                Some(existing) if existing != value => {
                    return Err(format!(
                        "`{through}` sets {key}={value} inside a configuration that sets {key}={existing}"
                    ));
                }
                _ => {
                    composed.insert(key.clone(), value.clone());
                }
            }
        }
        Ok(composed)
    }

    /// The overrides a variant name carries along its `variant-of` chain,
    /// and the derivation it finally configures.
    fn variant_chain(&self, name: &str) -> (String, Overrides) {
        let mut overrides = Overrides::new();
        let mut current = name;
        while let Some(variant) = self.spec.variants.get(current) {
            for (key, value) in &variant.overrides {
                overrides
                    .entry(key.clone())
                    .or_insert_with(|| value.clone());
            }
            current = &variant.base;
        }
        (current.to_string(), overrides)
    }

    /// The node an edge named `edge` reaches under `current`.
    fn edge(&self, current: &Overrides, edge: &str) -> Result<(String, Overrides), String> {
        if self.spec.variants.contains_key(edge) {
            let (base, overrides) = self.variant_chain(edge);
            Ok((base, self.compose(current, &overrides, edge)?))
        } else {
            Ok((edge.to_string(), current.clone()))
        }
    }

    fn visit(&mut self, name: &str, overrides: &Overrides) -> Result<Visit, String> {
        self.cancel.check()?;
        let memo = (name.to_string(), overrides.clone());
        if let Some(visit) = self.visits.get(&memo) {
            return Ok(visit.clone());
        }
        if !self.active.insert(memo.clone()) {
            return Err(format!("dependency cycle through `{name}`"));
        }
        let result = self.visit_uncached(name, overrides);
        self.active.remove(&memo);
        let visit = result?;
        self.visits.insert(memo, visit.clone());
        Ok(visit)
    }

    fn visit_uncached(&mut self, name: &str, overrides: &Overrides) -> Result<Visit, String> {
        let spec = self.spec;
        let dspec = spec
            .drvs
            .get(name)
            .ok_or_else(|| format!("unknown derivation `{name}`"))?;
        let config = self.layered(overrides)?;
        if !config.view().eval_when(&dspec.when)? {
            return Ok(Visit::Disabled);
        }
        let mut edges: Vec<String> = dspec.deps.clone();
        for provider in tool_provider_edges(spec, dspec)? {
            if !edges.contains(&provider) {
                edges.push(provider);
            }
        }
        let mut deps = Vec::with_capacity(edges.len());
        let mut reached: BTreeMap<String, String> = BTreeMap::new();
        // Overrides arriving from above that a dependency's node carries.
        let mut relevant = Overrides::new();
        for edge in edges {
            let (child, child_overrides) = self.edge(overrides, &edge)?;
            let key = match self.visit(&child, &child_overrides)? {
                Visit::Node(key) => key,
                Visit::Disabled => {
                    return Err(format!(
                        "`{name}` depends on `{edge}`, which is disabled by configuration"
                    ));
                }
            };
            if let Some(other) = reached.insert(child.clone(), key.clone())
                && other != key
            {
                return Err(format!(
                    "`{name}` reaches two configurations of `{child}` ({other} and {key})"
                ));
            }
            for (k, v) in &self.graph.nodes[&key].overrides {
                if overrides.get(k) == Some(v) {
                    relevant.insert(k.clone(), v.clone());
                }
            }
            deps.push((edge, key));
        }
        if !overrides.is_empty() {
            // An override is relevant to this node when removing it changes
            // a value the node reads (derived options included) or when a
            // dependency's node carries it.
            let reads = probe_reads(spec, dspec, &config)?;
            for (key, value) in overrides {
                if relevant.contains_key(key) {
                    continue;
                }
                let mut without = overrides.clone();
                without.remove(key);
                let other = self.layered(&without)?;
                if reads
                    .iter()
                    .any(|read| config.values.get(read) != other.values.get(read))
                {
                    relevant.insert(key.clone(), value.clone());
                }
            }
            if relevant != *overrides {
                // Keys that matter only together keep the whole set, so a
                // key never names a node whose reads it does not reproduce.
                let reduced = self.layered(&relevant)?;
                if !reads
                    .iter()
                    .all(|read| config.values.get(read) == reduced.values.get(read))
                {
                    relevant = overrides.clone();
                }
            }
            if relevant != *overrides {
                // The node is its derivation under the relevant set alone,
                // however the request reached it.
                return self.visit(name, &relevant);
            }
        }
        let key = address::node_key(name, overrides);
        if !self.graph.nodes.contains_key(&key) {
            self.graph.nodes.insert(
                key.clone(),
                ConfiguredNode {
                    name: name.to_string(),
                    overrides: overrides.clone(),
                    config,
                    deps,
                },
            );
            self.graph.order.push(key.clone());
        }
        Ok(Visit::Node(key))
    }

    /// The node a requested address names, as (name, overrides).
    fn request(
        &self,
        text: &str,
        universe: &Option<ConfiguredGraph>,
    ) -> Result<(String, Overrides), String> {
        match address::parse(text)? {
            address::Address::Plain(name) => {
                if self.spec.variants.contains_key(&name) {
                    self.edge(&Overrides::new(), &name)
                } else if self.spec.drvs.contains_key(&name) {
                    Ok((name, Overrides::new()))
                } else {
                    Err(format!("unknown target `{name}`"))
                }
            }
            address::Address::Configured(name, extra) => {
                let (base, carried) = self.edge(&Overrides::new(), &name)?;
                if !self.spec.drvs.contains_key(&base) {
                    return Err(format!("unknown target `{name}`"));
                }
                Ok((base, self.compose(&carried, &extra, text)?))
            }
            address::Address::Hash(name, hash) => {
                let key = format!("{name}@{hash}");
                let node = universe
                    .as_ref()
                    .and_then(|graph| graph.nodes.get(&key))
                    .ok_or_else(|| {
                        format!("`{key}` names no configured node of the current evaluation")
                    })?;
                Ok((node.name.clone(), node.overrides.clone()))
            }
        }
    }
}

/// Every configuration key a derivation reads under `config`: its `when`
/// predicate, its argument expansion and a script DAG's plan.
fn probe_reads(spec: &Spec, dspec: &DrvSpec, config: &Config) -> Result<BTreeSet<String>, String> {
    let mut view = config.view();
    view.eval_when(&dspec.when)?;
    if !crate::spec::builders::is_fixed_output(&dspec.builder) {
        spec.eval_argv(dspec, &mut view)?;
        if dspec.builder == "script-dag" {
            spec.eval_plan(dspec, &mut view)?;
        }
    }
    Ok(view.referenced)
}

/// The names a hash address may select: every name exposed in `[packages]`
/// or `[checks]`, each dropping out when disabled.
fn universe_targets(spec: &Spec) -> Vec<String> {
    spec.kinds
        .packages
        .expose
        .keys()
        .chain(spec.kinds.checks.expose.keys())
        .map(|name| format!("{}{name}", crate::spec::kinds::OPTIONAL_PREFIX))
        .collect()
}

/// Build the configured closure of `targets`. A target marked optional
/// (a group member) drops out when configuration disables it; any other
/// disabled target, and a live node depending on a disabled one, fails.
pub(crate) fn configured_closure(
    spec: &Spec,
    config: &Config,
    targets: &[String],
    cancel: &CancellationToken,
) -> Result<ConfiguredGraph, String> {
    let needs_universe = targets.iter().any(|target| {
        matches!(
            address::parse(target.trim_start_matches(crate::spec::kinds::OPTIONAL_PREFIX)),
            Ok(address::Address::Hash(..))
        )
    });
    let universe = if needs_universe {
        Some(configured_closure(
            spec,
            config,
            &universe_targets(spec),
            cancel,
        )?)
    } else {
        None
    };
    let mut builder = ClosureBuilder::new(spec, config, cancel);
    for target in targets {
        let optional = target.starts_with(crate::spec::kinds::OPTIONAL_PREFIX);
        let text = target.trim_start_matches(crate::spec::kinds::OPTIONAL_PREFIX);
        let (name, overrides) = builder.request(text, &universe)?;
        match builder.visit(&name, &overrides)? {
            Visit::Node(key) => {
                if !builder
                    .graph
                    .roots
                    .iter()
                    .any(|(request, _)| request == text)
                {
                    builder.graph.roots.push((text.to_string(), key));
                }
            }
            Visit::Disabled if optional => {}
            Visit::Disabled => {
                return Err(format!(
                    "target `{}` is disabled by configuration (when = \"{}\")",
                    text, spec.drvs[&name].when
                ));
            }
        }
    }
    Ok(builder.graph)
}

/// The hash pass: build `Derivation`s for the closure in topo order.
pub fn evaluate(
    spec: &Spec,
    config: &Config,
    toolchain: &mut Toolchain,
    targets: &[String],
    git_state: &(String, String),
) -> Result<Evaluated, String> {
    evaluate_with_progress(spec, config, toolchain, targets, git_state, |_| {})
}

/// The hash pass with a progress sink. Stage 1 reports source-resolution work
/// from its bounded worker pool; stage 2 reports derivation instantiation.
pub fn evaluate_with_progress(
    spec: &Spec,
    config: &Config,
    toolchain: &mut Toolchain,
    targets: &[String],
    git_state: &(String, String),
    mut progress: impl FnMut(EvalProgress) + Send,
) -> Result<Evaluated, String> {
    let _memo_scope = source::EvaluationMemoScope::new();
    let cancel = CancellationToken::never();
    let prepared = prepare_with_progress(
        spec,
        config,
        targets,
        git_state.clone(),
        &cancel,
        &mut progress,
    )?;
    instantiate_prepared(spec, config, toolchain, prepared, &mut progress)
}

/// Stage 1: compute the live closure and resolve every source in a bounded
/// outer worker pool. The caller owns the request-local source memo scope so
/// it can keep the observations live through an optional snapshot check.
pub(crate) fn prepare_with_progress(
    spec: &Spec,
    config: &Config,
    targets: &[String],
    git_state: (String, String),
    cancel: &CancellationToken,
    progress: &mut (impl FnMut(EvalProgress) + Send),
) -> Result<PreparedEval, String> {
    prepare_with_progress_reusing(
        spec,
        config,
        targets,
        git_state,
        None,
        &BTreeSet::new(),
        cancel,
        progress,
    )
}

/// Stage 1 with an optional verified source baseline. `reusable` is accepted
/// only by the daemon watcher path after it has drained a healthy watcher;
/// every dirty path is re-ingested through the ordinary source APIs.
pub(crate) fn prepare_with_progress_reusing(
    spec: &Spec,
    config: &Config,
    targets: &[String],
    git_state: (String, String),
    reusable: Option<&ResolvedSources>,
    dirty: &BTreeSet<String>,
    cancel: &CancellationToken,
    progress: &mut (impl FnMut(EvalProgress) + Send),
) -> Result<PreparedEval, String> {
    cancel.check()?;
    source::reset_eval_phase_timers();
    let t_closure = std::time::Instant::now();
    // The configured closure: every node reachable from the enabled roots
    // under the configuration that reaches it. Disabling a subsystem (e.g.
    // BUILD_KERNEL) drops its gated artifacts and their now-orphaned
    // dependencies (the Nix-lazy / Bazel-closure / Kbuild inclusion model);
    // a live node depending on a disabled one is a real conflict and errors.
    let graph = configured_closure(spec, config, targets, cancel)?;
    source::set_closure_ns(t_closure.elapsed().as_nanos() as u64);

    let mut work = Vec::new();
    let mut overlay_roots = BTreeSet::new();
    let mut seen: BTreeSet<(u8, String)> = BTreeSet::new();
    let mut push =
        |rel: &str, kind: WorkKind, bootstrap: bool, owner: Option<&crate::spec::Repository>| {
            let tag = match kind {
                WorkKind::Blob => 0,
                WorkKind::Tree => 1,
            };
            let key = owner
                .map(|owner| owner.source_key(rel))
                .unwrap_or_else(|| rel.to_string());
            if seen.insert((tag, key.clone())) {
                work.push(SourceWork {
                    rel: rel.to_string(),
                    key,
                    kind,
                    bootstrap,
                    owner: owner.cloned(),
                });
            }
        };
    let mut names: Vec<&str> = graph
        .nodes
        .values()
        .map(|node| node.name.as_str())
        .collect();
    names.sort_unstable();
    names.dedup();
    for name in names {
        cancel.check()?;
        let dspec = &spec.drvs[name];
        if !crate::spec::builders::is_fixed_output(&dspec.builder) {
            for rel in &dspec.sources {
                push(rel, WorkKind::Blob, false, dspec.repository.as_ref());
            }
        }
        // Fixed-output declarations omit these hashes from their derivation
        // identity, but plan execution still consumes the directories.
        for rel in &dspec.src_dirs {
            push(rel, WorkKind::Tree, false, dspec.repository.as_ref());
        }
        for rel in &dspec.source_roots {
            if dspec.overlay_root(rel) {
                crate::inputs::codec::clean_path(rel)?;
                overlay_roots.insert(dspec.source_root_key(rel));
            } else {
                push(rel, WorkKind::Tree, false, dspec.repository.as_ref());
            }
        }
    }
    for rel in super::plan::bootstrap::bootstrap_paths(&spec.repo_root)? {
        push(&rel, WorkKind::Blob, true, None);
    }

    let mut resolved_sources = ResolvedSources::default();
    for root in overlay_roots {
        resolved_sources.trees.insert(root, source::empty_tree()?);
    }
    let mut unresolved = Vec::new();
    for item in work {
        cancel.check()?;
        let cached = reusable.and_then(|sources| match item.kind {
            WorkKind::Blob => sources
                .blobs
                .get(&item.key)
                .cloned()
                .map(|(hash, kind)| (hash, kind)),
            WorkKind::Tree => sources
                .trees
                .get(&item.key)
                .cloned()
                .map(|hash| (hash, 't')),
        });
        if dirty.contains(&item.key) || cached.is_none() {
            unresolved.push(item);
            continue;
        }
        let (hash, kind) = cached.expect("cached source checked above");
        match item.kind {
            WorkKind::Blob => {
                resolved_sources.blobs.insert(item.key, (hash, kind));
            }
            WorkKind::Tree => {
                resolved_sources.trees.insert(item.key, hash);
            }
        }
    }

    let dirs = unresolved
        .iter()
        .filter(|item| matches!(item.kind, WorkKind::Tree))
        .filter(|item| item.owner.is_none())
        .map(|item| spec.repo_root.join(&item.rel))
        .collect::<Vec<_>>();
    source::prewarm_probes(&dirs);
    cancel.check()?;

    let work = Arc::new(unresolved);
    let next = AtomicUsize::new(0);
    let completed = AtomicUsize::new(0);
    let total = work.len();
    let results = Mutex::new(
        std::iter::repeat_with(|| None)
            .take(work.len())
            .collect::<Vec<Option<Result<(String, WorkKind, String, char), String>>>>(),
    );
    let workers = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
        .min(4)
        .max(1);
    let t_source = std::time::Instant::now();
    std::thread::scope(|scope| {
        let (progress_tx, progress_rx) = mpsc::channel::<EvalProgress>();
        scope.spawn(move || {
            while let Ok(event) = progress_rx.recv() {
                progress(event);
            }
        });
        for _ in 0..workers {
            let work = Arc::clone(&work);
            let next = &next;
            let completed = &completed;
            let results = &results;
            let repo_root = &spec.repo_root;
            let progress_tx = progress_tx.clone();
            let cancel = cancel.clone();
            scope.spawn(move || {
                loop {
                    if cancel.is_cancelled() {
                        break;
                    }
                    let idx = next.fetch_add(1, Ordering::Relaxed);
                    let Some(item) = work.get(idx) else {
                        break;
                    };
                    let _ = progress_tx.send(EvalProgress {
                        current: completed.load(Ordering::Relaxed),
                        total,
                        phase: EvalPhase::ResolvingSources,
                        detail: item.rel.clone(),
                        item: Some(EvalItem::Started),
                        label: None,
                    });
                    let resolved = match item.kind {
                        WorkKind::Blob => (if item.bootstrap {
                            super::plan::bootstrap::ingest_blob(repo_root, &item.rel)
                        } else {
                            let owner_root = item
                                .owner
                                .as_ref()
                                .map(|owner| &owner.root)
                                .unwrap_or(repo_root);
                            crate::inputs::validate_source(owner_root, &item.rel).and_then(|_| {
                                source::hash_and_ingest_file(&owner_root.join(&item.rel))
                            })
                        })
                        .map(|(hash, kind)| (item.key.clone(), item.kind, hash, kind)),
                        WorkKind::Tree => (if let Some(owner) = &item.owner {
                            crate::inputs::validate_source(&owner.root, &item.rel)
                                .and_then(|_| source::input_subtree(&owner.content, &item.rel))
                        } else {
                            crate::inputs::validate_source(repo_root, &item.rel).and_then(|holes| {
                                if holes.is_empty() {
                                    source::hash_and_ingest_dir(&repo_root.join(&item.rel))
                                } else {
                                    source::ingest_owned_subtree(&repo_root.join(&item.rel), &holes)
                                }
                            })
                        })
                        .map(|hash| (item.key.clone(), item.kind, hash, 't')),
                    };
                    // A failed item is not finished: the evaluation error
                    // reports it.
                    let finished = resolved
                        .as_ref()
                        .ok()
                        .map(|(_, _, hash, _)| hash.chars().take(12).collect::<String>());
                    results.lock().expect("stage-1 result lock")[idx] = Some(resolved);
                    let current = completed.fetch_add(1, Ordering::Relaxed) + 1;
                    let _ = progress_tx.send(EvalProgress {
                        current,
                        total,
                        phase: EvalPhase::ResolvingSources,
                        detail: item.rel.clone(),
                        item: finished.map(EvalItem::Finished),
                        label: None,
                    });
                }
            });
        }
        drop(progress_tx);
    });
    cancel.check()?;
    for result in results.into_inner().expect("stage-1 result lock") {
        let (rel, kind, hash, file_kind) = result.expect("stage-1 worker result")?;
        match kind {
            WorkKind::Blob => {
                resolved_sources.blobs.insert(rel, (hash, file_kind));
            }
            WorkKind::Tree => {
                resolved_sources.trees.insert(rel, hash);
            }
        }
    }
    // The per-directory timers above sum worker work.  User-facing source_ms
    // is the Stage-1 critical path, so overwrite it with bounded-pool wall
    // time after every worker has joined.
    source::set_source_ingest_ns(t_source.elapsed().as_nanos() as u64);
    Ok(PreparedEval {
        graph,
        resolved_sources,
        git_state,
    })
}

/// Stage 2: instantiate recipes in the original topological order.  All
/// source identities come from stage 1, so interleaving cannot affect the
/// preimage or plan ordering.
pub(crate) fn instantiate_prepared(
    spec: &Spec,
    config: &Config,
    toolchain: &mut Toolchain,
    prepared: PreparedEval,
    progress: &mut impl FnMut(EvalProgress),
) -> Result<Evaluated, String> {
    let PreparedEval {
        graph,
        resolved_sources,
        git_state,
    } = prepared;
    let mut recipes: BTreeMap<String, Recipe> = BTreeMap::new();
    let mut plans: BTreeMap<String, ActivePlan> = BTreeMap::new();

    let total = graph.order.len();
    let t_loop = std::time::Instant::now();
    for (idx, key) in graph.order.iter().enumerate() {
        let node = &graph.nodes[key];
        progress(EvalProgress {
            current: idx,
            total,
            phase: EvalPhase::Instantiating,
            detail: key.clone(),
            item: Some(EvalItem::Started),
            label: (!node.overrides.is_empty())
                .then(|| address::readable(&node.name, &node.overrides)),
        });
        let dspec = &spec.drvs[&node.name];
        let (mut recipe, plan) = instantiate(
            spec,
            &node.config,
            toolchain,
            dspec,
            &git_state,
            &resolved_sources,
        )?;
        // The recipe names its edges as declared; the graph gives each the
        // key of the configured node it reaches.
        let edge_keys: BTreeMap<&str, &str> = node
            .deps
            .iter()
            .map(|(edge, key)| (edge.as_str(), key.as_str()))
            .collect();
        recipe.dep_names = recipe
            .dep_names
            .iter()
            .map(|edge| {
                edge_keys
                    .get(edge.as_str())
                    .map(|key| key.to_string())
                    .ok_or_else(|| format!("`{key}` has an edge `{edge}` outside its closure"))
            })
            .collect::<Result<_, _>>()?;
        // Resolve from the SPEC's declaration, not the recipe — a fixed-
        // output fetch keeps its tools out of the identity but still runs
        // them. Store tools are resolved at realize from their provider
        // derivations; there is no host-resolved build tool.
        if !crate::spec::builders::is_in_process(&dspec.builder) {
            for tool in std::iter::once(&dspec.tool).chain(dspec.extra_tools.iter()) {
                if let ToolLocator::Unknown = spec.tool_locator(toolchain, dspec, tool) {
                    return Err(format!(
                        "`{}` declares unavailable tool `{}` in stage `{}`",
                        dspec.name,
                        tool,
                        crate::spec::stages::stage_name(dspec)
                    ));
                }
            }
        }
        if let Some(plan) = plan {
            plans.insert(key.clone(), plan);
        }
        recipes.insert(key.clone(), recipe);
        progress(EvalProgress {
            current: idx + 1,
            total,
            phase: EvalPhase::Instantiating,
            detail: key.clone(),
            item: Some(EvalItem::Finished(String::new())),
            label: None,
        });
    }
    source::set_instantiate_ns(t_loop.elapsed().as_nanos() as u64);
    progress(EvalProgress {
        current: total,
        total,
        phase: EvalPhase::Evaluated,
        detail: String::new(),
        item: None,
        label: None,
    });
    Ok(Evaluated {
        order: graph.order.clone(),
        recipes,
        plans,
        roots: graph.roots.clone(),
        configured: graph.configured(),
        config_digests: graph.config_digests(),
        resolved_sources,
        git_state,
    })
}

#[cfg(test)]
mod cancellation_tests {
    use super::*;
    use crate::spec::ToolProviderSpec;
    use std::path::PathBuf;

    fn project_tool_drv(name: &str, tool: &str, bootstrap: bool) -> DrvSpec {
        DrvSpec {
            repository: None,
            name: name.into(),
            builder: "nasm".into(),
            tool: tool.into(),
            extra_tools: Vec::new(),
            when: String::new(),
            bootstrap,
            native_frontend: false,
            stage: None,
            host_tool: false,
            allowed_refs: RefPolicy::None,
            sources: Vec::new(),
            src_dirs: Vec::new(),
            source_roots: Vec::new(),
            source_overlays: Vec::new(),
            deps: Vec::new(),
            outputs: vec!["out".into()],
            argv: vec!["{tool-version:project-tool}".into()],
            env: Vec::new(),
            copy: Vec::new(),
            stage_deps: Vec::new(),
            groups: Vec::new(),
            compiles: Vec::new(),
            steps: Vec::new(),
            module: String::new(),
            module_role: String::new(),
            config_keys: Vec::new(),
        }
    }

    #[test]
    fn cancelled_prepare_returns_a_clean_error() {
        let token = CancellationToken::from_flag(Arc::new(AtomicBool::new(true)));
        let spec = Spec {
            repo_root: PathBuf::from("/unused"),
            arch: "x86_64".into(),
            build_host: "x86_64-unknown-linux-gnu".into(),
            target_system: "x86_64".into(),
            flagsets: BTreeMap::new(),
            drvs: BTreeMap::new(),
            variants: BTreeMap::new(),
            kinds: Default::default(),
            tool_providers: BTreeMap::new(),
            stages: BTreeMap::new(),
            configuration: None,
            executor_image: None,
            modules: BTreeMap::new(),
            generators: BTreeMap::new(),
            bootstrap_steps: Vec::new(),
            pending: None,
            spec_inputs: Vec::new(),
        };
        let config = Config::from_values(BTreeMap::new());
        let mut progress = |_: EvalProgress| {};
        let result = prepare_with_progress(
            &spec,
            &config,
            &[],
            ("unknown".into(), "false".into()),
            &token,
            &mut progress,
        );
        assert!(matches!(result, Err(error) if error == "evaluation cancelled"));
    }

    #[test]
    fn required_project_tool_provider_is_a_closure_edge_and_path_identity_input() {
        let consumer = project_tool_drv("consumer", "project-tool", false);
        let mut provider = project_tool_drv("provider", "unused", false);
        provider.builder = "untar".into();
        let mut spec = Spec {
            repo_root: PathBuf::from("/unused"),
            arch: "x86_64".into(),
            build_host: "x86_64-unknown-linux-gnu".into(),
            target_system: "x86_64".into(),
            flagsets: BTreeMap::new(),
            drvs: BTreeMap::from([
                (consumer.name.clone(), consumer.clone()),
                (provider.name.clone(), provider),
            ]),
            variants: BTreeMap::new(),
            kinds: Default::default(),
            tool_providers: BTreeMap::from([(
                "project-tool".into(),
                ToolProviderSpec {
                    derivation: "provider".into(),
                    path: "bin/project-tool".into(),
                    version_flag: None,
                },
            )]),
            stages: BTreeMap::new(),
            configuration: None,
            executor_image: None,
            modules: BTreeMap::new(),
            generators: BTreeMap::new(),
            bootstrap_steps: Vec::new(),
            pending: None,
            spec_inputs: Vec::new(),
        };
        assert_eq!(
            closure(&spec, &["consumer".into()]).unwrap(),
            vec!["provider".to_string(), "consumer".to_string()]
        );

        let config = Config::from_values(BTreeMap::new());
        let mut toolchain = Toolchain::new(Path::new("."));
        let (before, _) = instantiate(
            &spec,
            &config,
            &mut toolchain,
            &consumer,
            &("unknown".into(), "false".into()),
            &ResolvedSources::default(),
        )
        .unwrap();
        assert_eq!(
            before.tools,
            vec![(
                "project-tool".to_string(),
                "store:provider:bin/project-tool".to_string(),
            )]
        );
        assert!(
            before
                .argv
                .iter()
                .any(|arg| arg == "{tool-version:project-tool}")
        );
        let before_hash = before
            .finalize(vec![DepRef {
                name: "provider".into(),
                digest: "provider-digest".into(),
                store_name: "provider-store".into(),
            }])
            .hash();
        let changed_provider_hash = before
            .finalize(vec![DepRef {
                name: "provider".into(),
                digest: "changed-provider-digest".into(),
                store_name: "other-provider-store".into(),
            }])
            .hash();
        assert_ne!(before_hash, changed_provider_hash);

        spec.tool_providers.get_mut("project-tool").unwrap().path = "project-tool".into();
        let (after, _) = instantiate(
            &spec,
            &config,
            &mut toolchain,
            &consumer,
            &("unknown".into(), "false".into()),
            &ResolvedSources::default(),
        )
        .unwrap();
        let after_hash = after
            .finalize(vec![DepRef {
                name: "provider".into(),
                digest: "provider-digest".into(),
                store_name: "provider-store".into(),
            }])
            .hash();
        assert_ne!(before_hash, after_hash);
    }
}

#[cfg(test)]
mod variant_tests {
    use super::*;
    use crate::spec::kinds::Kind;
    use crate::spec::{ToolProviderSpec, Variant};
    use std::path::PathBuf;

    fn node(name: &str, deps: &[&str]) -> DrvSpec {
        DrvSpec {
            repository: None,
            name: name.into(),
            builder: "nasm".into(),
            tool: "project-tool".into(),
            extra_tools: Vec::new(),
            when: String::new(),
            bootstrap: false,
            native_frontend: false,
            stage: None,
            host_tool: false,
            allowed_refs: RefPolicy::None,
            sources: Vec::new(),
            src_dirs: Vec::new(),
            source_roots: Vec::new(),
            source_overlays: Vec::new(),
            deps: deps.iter().map(|d| d.to_string()).collect(),
            outputs: vec!["out".into()],
            argv: Vec::new(),
            env: Vec::new(),
            copy: Vec::new(),
            stage_deps: Vec::new(),
            groups: Vec::new(),
            compiles: Vec::new(),
            steps: Vec::new(),
            module: String::new(),
            module_role: String::new(),
            config_keys: Vec::new(),
        }
    }

    fn set(pairs: &[(&str, &str)]) -> Overrides {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    fn variant(name: &str, base: &str, pairs: &[(&str, &str)]) -> (String, Variant) {
        (
            name.to_string(),
            Variant {
                name: name.into(),
                base: base.into(),
                overrides: set(pairs),
            },
        )
    }

    /// A derived option, as mica computes one from another.
    fn derive(values: &mut BTreeMap<String, String>) {
        let on = values.get("TEST_AUTOSHUTDOWN").map(String::as_str) == Some("true");
        values.insert("DERIVED".into(), if on { "on" } else { "off" }.into());
    }

    fn config() -> Config {
        Config::with_literal_resolver(
            [
                ("TEST_AUTOSHUTDOWN".to_string(), "false".to_string()),
                ("OTHER".to_string(), "x".to_string()),
            ]
            .into_iter()
            .collect(),
            derive,
        )
    }

    fn spec() -> Spec {
        let mut provider = node("provider", &[]);
        provider.builder = "untar".into();
        let mut runner = node("runner", &[]);
        runner.groups = vec![(
            "TEST_AUTOSHUTDOWN".into(),
            vec!["--cfg".into(), "ci".into()],
        )];
        let mut lib = node("lib", &[]);
        lib.groups = vec![("OTHER = \"y\"".into(), vec!["-y".into()])];
        let mut aggregate = node("aggregate", &[]);
        aggregate.argv = vec!["{config.DERIVED}".into()];
        let mut drvs = BTreeMap::new();
        for d in [
            provider,
            runner,
            lib,
            aggregate,
            node("image-bios", &["runner", "lib"]),
            node("image-efi", &["runner", "lib", "aggregate"]),
            node("wrapper", &["runner-quiet"]),
        ] {
            drvs.insert(d.name.clone(), d);
        }
        let variants: BTreeMap<String, Variant> = [
            variant("bios-test", "image-bios", &[("TEST_AUTOSHUTDOWN", "true")]),
            variant("efi-test", "image-efi", &[("TEST_AUTOSHUTDOWN", "true")]),
            variant("bios-test-other", "bios-test", &[("OTHER", "y")]),
            variant("runner-quiet", "runner", &[("TEST_AUTOSHUTDOWN", "false")]),
            variant("wrapper-test", "wrapper", &[("TEST_AUTOSHUTDOWN", "true")]),
        ]
        .into_iter()
        .collect();
        let mut kinds = crate::spec::kinds::Kinds::default();
        for name in ["image-bios", "image-efi", "bios-test", "efi-test"] {
            kinds.expose(Kind::Packages, name, "test").unwrap();
        }
        Spec {
            repo_root: PathBuf::from("/unused"),
            arch: "x86_64".into(),
            build_host: "x86_64-unknown-linux-gnu".into(),
            target_system: "x86_64".into(),
            flagsets: BTreeMap::new(),
            drvs,
            variants,
            kinds,
            tool_providers: BTreeMap::from([(
                "project-tool".into(),
                ToolProviderSpec {
                    derivation: "provider".into(),
                    path: "bin/project-tool".into(),
                    version_flag: None,
                },
            )]),
            stages: BTreeMap::new(),
            configuration: None,
            executor_image: None,
            modules: BTreeMap::new(),
            generators: BTreeMap::new(),
            bootstrap_steps: Vec::new(),
            pending: None,
            spec_inputs: Vec::new(),
        }
    }

    fn closure_of(
        spec: &Spec,
        config: &Config,
        targets: &[&str],
    ) -> Result<ConfiguredGraph, String> {
        let targets: Vec<String> = targets.iter().map(|t| t.to_string()).collect();
        configured_closure(spec, config, &targets, &CancellationToken::never())
    }

    fn deps_of(graph: &ConfiguredGraph, key: &str) -> Vec<String> {
        graph.nodes[key]
            .deps
            .iter()
            .map(|(_, key)| key.clone())
            .collect()
    }

    #[test]
    fn required_both_test_images_share_one_configured_runner_node() {
        let spec = spec();
        let graph = closure_of(&spec, &config(), &["bios-test", "efi-test", "image-bios"]).unwrap();
        let test = set(&[("TEST_AUTOSHUTDOWN", "true")]);
        let runner = address::node_key("runner", &test);
        let bios = address::node_key("image-bios", &test);
        let efi = address::node_key("image-efi", &test);
        assert_eq!(
            graph.roots,
            vec![
                ("bios-test".to_string(), bios.clone()),
                ("efi-test".to_string(), efi.clone()),
                ("image-bios".to_string(), "image-bios".to_string()),
            ]
        );
        assert_eq!(deps_of(&graph, &bios), [runner.as_str(), "lib", "provider"]);
        assert_eq!(deps_of(&graph, &efi)[0], runner);
        // One configured runner node for both images; the default image keeps
        // the default runner and its own default key.
        let runners: Vec<&String> = graph
            .nodes
            .keys()
            .filter(|key| address::base_name(key) == "runner")
            .collect();
        assert_eq!(runners, [&"runner".to_string(), &runner]);
        assert_eq!(deps_of(&graph, "image-bios")[0], "runner");
        assert!(graph.nodes["image-bios"].overrides.is_empty());
        // An override a node reads only through a derived option is relevant.
        let aggregate = address::node_key("aggregate", &test);
        assert!(graph.nodes.contains_key(&aggregate));
        assert_eq!(graph.nodes[&aggregate].config.values["DERIVED"], "on");
        // A node that reads nothing the override changes stays default.
        assert!(graph.nodes.contains_key("lib"));
        assert!(!graph.nodes.keys().any(|key| key.starts_with("lib@")));
    }

    #[test]
    fn required_command_line_overrides_meet_variants_by_value() {
        let spec = spec();
        let mut differing = config();
        differing
            .cli_overrides
            .insert("TEST_AUTOSHUTDOWN".into(), "false".into());
        let error = closure_of(&spec, &differing, &["bios-test"])
            .err()
            .expect("conflicting override must fail");
        assert!(error.contains("-DTEST_AUTOSHUTDOWN=false"), "{error}");

        let mut equal = Config::with_literal_resolver(
            [
                ("TEST_AUTOSHUTDOWN".to_string(), "true".to_string()),
                ("OTHER".to_string(), "x".to_string()),
            ]
            .into_iter()
            .collect(),
            derive,
        );
        equal
            .cli_overrides
            .insert("TEST_AUTOSHUTDOWN".into(), "true".into());
        // The configuration already reads the variant's value, so the
        // variant's node is the default configuration's node.
        let graph = closure_of(&spec, &equal, &["bios-test"]).unwrap();
        assert_eq!(graph.roots[0].1, "image-bios");
    }

    #[test]
    fn required_nested_variants_compose_and_conflicts_are_refused() {
        let spec = spec();
        let graph = closure_of(&spec, &config(), &["bios-test-other"]).unwrap();
        let both = set(&[("OTHER", "y"), ("TEST_AUTOSHUTDOWN", "true")]);
        assert_eq!(graph.roots[0].1, address::node_key("image-bios", &both));
        assert!(
            graph
                .nodes
                .contains_key(&address::node_key("lib", &set(&[("OTHER", "y")])))
        );
        let error = closure_of(&spec, &config(), &["wrapper-test"])
            .err()
            .expect("conflicting nested variant must fail");
        assert!(error.contains("inside a configuration"), "{error}");
    }

    #[test]
    fn required_both_address_forms_reach_one_node_and_unknown_hashes_fail() {
        let spec = spec();
        let readable =
            closure_of(&spec, &config(), &["image-bios[TEST_AUTOSHUTDOWN=true]"]).unwrap();
        let key = readable.roots[0].1.clone();
        assert_eq!(
            key,
            address::node_key("image-bios", &set(&[("TEST_AUTOSHUTDOWN", "true")]))
        );
        let hashed = closure_of(&spec, &config(), &[key.as_str()]).unwrap();
        assert_eq!(hashed.roots[0].1, key);
        let unknown = format!("image-bios@{}", "0".repeat(address::KEY_HASH_LEN));
        assert!(
            closure_of(&spec, &config(), &[unknown.as_str()])
                .err()
                .expect("unknown configured hash must fail")
                .contains("no configured node")
        );
    }
}

/// The repository's git identity as a declared pseudo-input: (short rev,
/// dirty flag). Backs the `{git-rev}` / `{git-dirty}` env tokens.
pub fn git_state(repo_root: &Path) -> (String, String) {
    match source::git::identity_for(repo_root) {
        Some((rev, dirty)) => (rev, if dirty { "true" } else { "false" }.to_string()),
        None => ("unknown".to_string(), "false".to_string()),
    }
}

fn instantiate(
    spec: &Spec,
    config: &Config,
    toolchain: &mut Toolchain,
    dspec: &DrvSpec,
    git: &(String, String),
    resolved_sources: &ResolvedSources,
) -> Result<(Recipe, Option<ActivePlan>), String> {
    if dspec.builder == "source-tree" {
        let hash = dspec
            .env
            .iter()
            .find(|(key, _)| key == "BUILDUTIL_INPUT_TREE")
            .map(|(_, value)| value.clone())
            .ok_or("source-tree input lacks its captured content")?;
        let doc = crate::spec::toml::parse_file(&spec.repo_root.join("buildutil.toml"))?;
        if crate::inputs::codec::bootstrap_inputs(&doc)?.contains(&dspec.name) {
            let lock = crate::inputs::codec::Lock::read(&spec.repo_root.join("buildutil.lock"))?
                .ok_or_else(|| {
                    format!(
                        "bootstrap: missing buildutil.lock [input.{}] entry",
                        dspec.name
                    )
                })?;
            let entry_name = lock.inputs.get(&dspec.name).ok_or_else(|| {
                format!(
                    "bootstrap: missing buildutil.lock [input.{}] entry",
                    dspec.name
                )
            })?;
            if lock.entries[entry_name].content != format!("tree:{hash}") {
                return Err(format!(
                    "bootstrap: selected content differs from buildutil.lock [input.{entry_name}].content"
                ));
            }
        }
        return Ok((
            Recipe {
                name: dspec.name.clone(),
                arch: "any".to_string(),
                builder: dspec.builder.clone(),
                tools: Vec::new(),
                env: Vec::new(),
                srcs: Vec::new(),
                srcdirs: vec![("source".into(), hash)],
                source_roots: Vec::new(),
                source_overlays: Vec::new(),
                copy: Vec::new(),
                stage_deps: Vec::new(),
                allowed_refs: dspec.allowed_refs.clone(),
                dep_names: Vec::new(),
                config: Vec::new(),
                module_config: None,
                argv: Vec::new(),
                plan: Vec::new(),
                outputs: dspec.outputs.clone(),
            },
            None,
        ));
    }
    // Fixed-output derivations — `fetch` (download a pinned file) and
    // `untar` (import a pinned local archive): identity is the declared
    // content hash and nothing else. Mirror moves, blob relocations, tool
    // upgrades, and arch never rebuild a verified import. The URL/archive
    // path rides outside the hash (realization reads it from the spec);
    // `arch` is pinned so both arches share the entry. Builder store tools
    // are still runtime provisioning for a fetch: their `store:` markers and
    // provider dep edges are carried on the recipe so the scheduler orders
    // the provider first and `stage_tool` can stage from it, but the
    // preimage excludes both sections (`Derivation::preimage`), so the
    // identity stays the declared hash alone. An untar import is extracted
    // in-process by buildutil itself (the seed-circularity breaker) — no tools,
    // no deps.
    if crate::spec::builders::is_fixed_output(&dspec.builder) {
        let sha = dspec
            .env
            .iter()
            .find(|(k, _)| k == "BUILDUTIL_FIXED_SHA256")
            .map(|(_, v)| v.clone())
            .ok_or_else(|| {
                format!(
                    "{} `{}` lacks a declared sha256 (BUILDUTIL_FIXED_SHA256)",
                    dspec.builder, dspec.name
                )
            })?;
        let mut argv = vec![format!("fixed-output:sha256:{}", sha)];
        if dspec.builder == "untar" {
            let tree_sha = dspec
                .env
                .iter()
                .find(|(k, _)| k == "BUILDUTIL_FIXED_TREE_SHA256")
                .map(|(_, v)| v.clone())
                .filter(|v| !v.is_empty())
                .ok_or_else(|| {
                    format!(
                        "untar `{}` lacks a declared tree sha256 (BUILDUTIL_FIXED_TREE_SHA256)",
                        dspec.name
                    )
                })?;
            argv.push(format!("fixed-output:tree-sha256:{tree_sha}"));
        }
        let mut tools = Vec::new();
        let mut dep_names: Vec<String> = Vec::new();
        if dspec.builder != "untar" {
            for tool in std::iter::once(&dspec.tool).chain(dspec.extra_tools.iter()) {
                // Store tools need a marker and a provider edge. `untar`
                // is skipped above because it is an in-process import.
                match spec.tool_locator(toolchain, dspec, tool) {
                    ToolLocator::Store { drv, relpath } => {
                        tools.push((tool.clone(), format!("store:{}:{}", drv, relpath)));
                        if !dep_names.contains(&drv) {
                            dep_names.push(drv);
                        }
                    }
                    ToolLocator::Ambient {
                        path,
                        identity_sha256,
                    } => {
                        tools.push((
                            tool.clone(),
                            format!("host-sha256:{}:{}", identity_sha256, path.to_string_lossy()),
                        ));
                    }
                    ToolLocator::Unknown => {
                        return Err(format!(
                            "`{}` declares unknown tool `{}` (all build tools must have store providers)",
                            dspec.name, tool
                        ));
                    }
                }
            }
            tools.sort();
            tools.dedup();
            // The stage's mount providers are execution inputs like the
            // tool providers: ordered first, outside the fixed-output
            // identity.
            for dep in &dspec.deps {
                if !dep_names.contains(dep) {
                    dep_names.push(dep.clone());
                }
            }
        }
        let recipe = Recipe {
            name: dspec.name.clone(),
            arch: if dspec.host_tool {
                format!("host-{}", spec.build_host)
            } else {
                "any".to_string()
            },
            builder: dspec.builder.clone(),
            tools,
            env: Vec::new(),
            srcs: Vec::new(),
            srcdirs: dspec
                .src_dirs
                .iter()
                .map(|d| (d.clone(), "fixed-output".to_string()))
                .collect(),
            source_roots: dspec
                .source_roots
                .iter()
                .map(|d| (d.clone(), "fixed-output".to_string()))
                .collect(),
            source_overlays: dspec.source_overlays.clone(),
            copy: dspec.copy.clone(),
            stage_deps: dspec.stage_deps.clone(),
            allowed_refs: dspec.allowed_refs.clone(),
            dep_names,
            config: Vec::new(),
            module_config: None,
            argv,
            plan: Vec::new(),
            outputs: dspec.outputs.clone(),
        };
        return Ok((recipe, None));
    }

    let mut view = config.view();
    let mut argv = spec.eval_argv(dspec, &mut view)?;
    let mut plan = if dspec.builder == "script-dag" {
        Some(spec.eval_plan(dspec, &mut view)?)
    } else {
        None
    };

    // `{tool-version:NAME}`: a store tool's version line exists only once its
    // provider is realized, so the token stays symbolic through the preimage
    // — the provider's dep digest already carries the content identity — and
    // expands at realization against the staged toolbin.
    let subst_tool_version = |items: &mut Vec<String>| -> Result<(), String> {
        for item in items.iter_mut() {
            let mut search_from = 0;
            while let Some(off) = item[search_from..].find("{tool-version:") {
                let start = search_from + off;
                let end = item[start..]
                    .find('}')
                    .map(|i| start + i)
                    .ok_or_else(|| format!("unterminated {{tool-version:*}} in `{}`", item))?;
                let tool = item[start + "{tool-version:".len()..end].to_string();
                match spec.tool_locator(toolchain, dspec, &tool) {
                    ToolLocator::Store { .. } | ToolLocator::Ambient { .. } => {
                        search_from = end + 1;
                    }
                    ToolLocator::Unknown => {
                        return Err(format!(
                            "`{}` references unknown tool-version `{}`",
                            dspec.name, tool
                        ));
                    }
                }
            }
        }
        Ok(())
    };
    subst_tool_version(&mut argv)?;
    if let Some(plan) = plan.as_mut() {
        for step in plan.steps.iter_mut() {
            subst_tool_version(&mut step.argv)?;
        }
    }

    let mut srcs = Vec::new();
    for source in &dspec.sources {
        let (digest, kind) = resolved_sources.blob(&dspec.source_key(source))?;
        srcs.push((kind, source.clone(), digest));
    }
    let mut srcdirs = Vec::new();
    for dir in &dspec.src_dirs {
        srcdirs.push((dir.clone(), resolved_sources.tree(&dspec.source_key(dir))?));
    }
    let mut source_roots = Vec::new();
    for dir in &dspec.source_roots {
        source_roots.push((
            dir.clone(),
            resolved_sources.tree(&dspec.source_root_key(dir))?,
        ));
    }

    // The static builder environment (private HOME/TMPDIR/PATH are
    // construction details added at realization). Builders report progress
    // through structured signals the build view reads: ninja status lines
    // carry buildutil's marker, and cargo prints no human status lines (its
    // JSON messages carry progress). Tools keep their colors inside the
    // build (ninja would otherwise strip them from command output); the
    // view and the retained log remove them where color is off.
    let mut env: Vec<(String, String)> = vec![
        ("SOURCE_DATE_EPOCH".to_string(), "1".to_string()),
        ("LC_ALL".to_string(), "C".to_string()),
        ("TZ".to_string(), "UTC".to_string()),
        (
            "NINJA_STATUS".to_string(),
            crate::exec::output::NINJA_STATUS.to_string(),
        ),
        ("CLICOLOR_FORCE".to_string(), "1".to_string()),
        ("CARGO_TERM_QUIET".to_string(), "true".to_string()),
        ("CARGO_TERM_COLOR".to_string(), "always".to_string()),
    ];
    env.extend(dspec.env.iter().cloned());
    // A module builder's module and role are identity: the same module in
    // another role is another derivation. Its configuration enters as the
    // `module-config` digest.
    let module_config = if dspec.builder == "module" {
        let module = spec
            .modules
            .get(&dspec.module)
            .ok_or_else(|| format!("`{}` runs undeclared module `{}`", dspec.name, dspec.module))?;
        env.push((crate::spec::MODULE_ENV.to_string(), dspec.module.clone()));
        env.push((
            crate::spec::MODULE_ROLE_ENV.to_string(),
            dspec.module_role.clone(),
        ));
        let mut keys = dspec.config_keys.clone();
        keys.sort();
        keys.dedup();
        env.push((
            crate::spec::MODULE_CONFIG_KEYS_ENV.to_string(),
            keys.join(","),
        ));
        let mut variants: Vec<String> = dspec
            .deps
            .iter()
            .filter(|edge| spec.variants.contains_key(edge.as_str()))
            .map(|edge| format!("{edge}={}", crate::spec::variant_base(&spec.variants, edge)))
            .collect();
        variants.sort();
        if let Some(owner) = &dspec.repository {
            variants.extend(
                owner
                    .source_names
                    .iter()
                    .filter(|(local, resolved)| local != resolved)
                    .map(|(local, resolved)| format!("{local}={resolved}")),
            );
            variants.sort();
            variants.dedup();
        }
        if !variants.is_empty() {
            env.push((
                crate::spec::MODULE_INPUTS_ENV.to_string(),
                variants.join(","),
            ));
        }
        Some(module.config_digest.clone())
    } else {
        None
    };
    // `{git-rev}` / `{git-dirty}` env values make the repository's git
    // identity a declared, hashed input.
    for (_, value) in env.iter_mut() {
        if value == "{git-rev}" || value == "{git-dirty}" {
            let owned_git = dspec
                .repository
                .as_ref()
                .map(|owner| (owner.rev.clone(), owner.dirty.to_string()));
            let (rev, dirty) = owned_git.as_ref().unwrap_or(git);
            *value = if value == "{git-rev}" {
                rev.clone()
            } else {
                dirty.clone()
            };
        }
    }

    // Tool identity: a store tool's identity is a symbolic
    // `store:<drv>:<relpath>` marker, and the provider derivation it names
    // becomes a dependency so the format:2 dep digest supplies the content
    // identity. An in-process builder's host binary is runtime machinery,
    // not an input.
    let mut tools = Vec::new();
    let mut store_tool_deps: Vec<String> = Vec::new();
    if !crate::spec::builders::is_in_process(&dspec.builder) {
        for tool in std::iter::once(&dspec.tool).chain(dspec.extra_tools.iter()) {
            match spec.tool_locator(toolchain, dspec, tool) {
                ToolLocator::Unknown => {
                    return Err(format!(
                        "`{}` declares unknown tool `{}` (all build tools must have store providers)",
                        dspec.name, tool
                    ));
                }
                ToolLocator::Store { drv, relpath } => {
                    tools.push((tool.clone(), format!("store:{}:{}", drv, relpath)));
                    store_tool_deps.push(drv);
                }
                ToolLocator::Ambient {
                    path,
                    identity_sha256,
                } => {
                    tools.push((
                        tool.clone(),
                        format!("host-sha256:{}:{}", identity_sha256, path.to_string_lossy()),
                    ));
                }
            }
        }
    }
    tools.sort();
    tools.dedup();
    let dep_names = if store_tool_deps.is_empty() {
        dspec.deps.clone()
    } else {
        let mut d = dspec.deps.clone();
        for drv in store_tool_deps {
            if !d.contains(&drv) {
                d.push(drv);
            }
        }
        d
    };

    let recipe = Recipe {
        name: dspec.name.clone(),
        // A target-independent host tool is build-host-qualified: every
        // target architecture shares one realization for the same Linux
        // build host, while x86_64 and aarch64 Linux toolchains stay distinct.
        // Target artifacts keep the configured target arch as their suffix;
        // their build-host-specific tools already enter the preimage through
        // tool and dependency digests.
        arch: if dspec.host_tool {
            format!("host-{}", spec.build_host)
        } else {
            spec.arch.clone()
        },
        builder: dspec.builder.clone(),
        tools,
        env,
        srcs,
        srcdirs,
        source_roots,
        source_overlays: dspec.source_overlays.clone(),
        copy: dspec.copy.clone(),
        stage_deps: dspec.stage_deps.clone(),
        allowed_refs: dspec.allowed_refs.clone(),
        dep_names,
        config: view.projection(),
        module_config,
        argv,
        plan: plan
            .as_ref()
            .map(ninja_emit::hash_lines)
            .unwrap_or_default(),
        outputs: dspec.outputs.clone(),
    };
    Ok((recipe, plan))
}
