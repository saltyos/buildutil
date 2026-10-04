//! SPDX-License-Identifier: GPL-2.0-only
//! buildutil — resolved-configuration access
//!
//! Configuration resolves in process through mica, the configuration
//! language used by the configuration commands: the option graph the build specification's
//! `[configuration]` table names, under three override layers — the
//! persistent `config/<arch>/config`, then the invocation's `-D`
//! overrides, then a configuration variant's. Every key a derivation reads
//! is recorded — the per-derivation projection that enters the drv hash.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use super::address::Overrides;

#[derive(Clone)]
pub struct Config {
    pub values: BTreeMap<String, String>,
    /// The `-D` overrides this configuration was resolved with.
    pub cli_overrides: Overrides,
    /// The variant overrides layered over `cli_overrides`; empty for the
    /// configuration a command starts from.
    pub layered: Overrides,
    resolver: Option<Arc<Resolver>>,
}

/// Resolves the option graph with a set of layered overrides. One
/// resolution per distinct set, kept for the life of the configuration.
struct Resolver {
    source: ResolverSource,
    cache: Mutex<BTreeMap<Overrides, Arc<Config>>>,
}

enum ResolverSource {
    Graph {
        graph: mica::config::graph::Graph,
        persistent: PathBuf,
    },
    /// Test configurations: the overrides replace values literally, then
    /// `derive` recomputes dependent keys as a resolver would.
    #[cfg(test)]
    Literal {
        base: BTreeMap<String, String>,
        derive: fn(&mut BTreeMap<String, String>),
    },
}

pub struct ConfigView<'a> {
    config: &'a Config,
    pub referenced: BTreeSet<String>,
}

/// The files a configuration was resolved from: the option graph's `*.toml`
/// files and the persistent override file. A change to any of them makes a
/// retained configuration stale.
pub fn inputs(
    repo_root: &Path,
    state_root: &Path,
    arch: &str,
    configuration: Option<&super::ConfigurationSpec>,
) -> Vec<PathBuf> {
    let mut out = vec![crate::state::config_file(state_root, arch)];
    if let Some(configuration) = configuration {
        let dir = repo_root.join(&configuration.graph);
        if let Ok(entries) = std::fs::read_dir(&dir) {
            let mut graph: Vec<PathBuf> = entries
                .flatten()
                .map(|entry| entry.path())
                .filter(|path| path.extension().is_some_and(|ext| ext == "toml"))
                .collect();
            graph.sort();
            out.extend(graph);
        }
    }
    out
}

impl Config {
    /// A configuration with fixed values and no resolver; variants over it
    /// are refused.
    pub fn from_values(values: BTreeMap<String, String>) -> Config {
        Config {
            values,
            cli_overrides: Overrides::new(),
            layered: Overrides::new(),
            resolver: None,
        }
    }

    /// The configuration a command evaluates against: the declared option
    /// graph resolved under the persistent file and the `-D` overrides, and
    /// a resolver for configuration variants over the same inputs.
    pub fn open(
        repo_root: &Path,
        state_root: &Path,
        arch: &str,
        configuration: Option<&super::ConfigurationSpec>,
        overrides: &[(String, String)],
    ) -> Result<Config, String> {
        let mut cli = Overrides::new();
        for (key, value) in overrides {
            if let Some(previous) = cli.insert(key.clone(), value.clone())
                && previous != *value
            {
                return Err(format!("-D{key} is given twice with different values"));
            }
        }
        let configuration = configuration.ok_or(
            "no [configuration] table names the option graph to resolve",
        )?;
        let persistent = crate::state::config_file(state_root, arch);
        if !persistent.is_file() {
            return Err(format!(
                "no configuration for `{arch}` at {} — run `buildutil setup --arch {arch}`",
                persistent.display()
            ));
        }
        let graph = mica::config::load_graph(&repo_root.join(&configuration.graph))
            .map_err(|diags| {
                format!(
                    "option graph {}:\n{}",
                    configuration.graph,
                    mica::config::render_diagnostics(&diags)
                )
            })?;
        let resolver = Arc::new(Resolver {
            source: ResolverSource::Graph { graph, persistent },
            cache: Mutex::new(BTreeMap::new()),
        });
        let mut config = resolver.resolve(&cli, &Overrides::new())?;
        config.cli_overrides = cli;
        config.resolver = Some(resolver);
        Ok(config)
    }

    /// A test configuration whose variants replace values literally and
    /// then run `derive`, standing in for the resolver's derived options.
    #[cfg(test)]
    pub fn with_literal_resolver(
        values: BTreeMap<String, String>,
        derive: fn(&mut BTreeMap<String, String>),
    ) -> Config {
        let mut config = Config::from_values(values.clone());
        derive(&mut config.values);
        config.resolver = Some(Arc::new(Resolver {
            source: ResolverSource::Literal {
                base: values,
                derive,
            },
            cache: Mutex::new(BTreeMap::new()),
        }));
        config
    }

    /// This configuration with `extra` layered over its `-D` overrides. An
    /// empty `extra` is the configuration itself. The caller has already
    /// refused an `extra` key that contradicts a `-D` override.
    pub fn with_layered(self: &Arc<Self>, extra: &Overrides) -> Result<Arc<Config>, String> {
        if extra.is_empty() {
            return Ok(Arc::clone(self));
        }
        let resolver = self.resolver.as_ref().ok_or_else(|| {
            "configuration variants need the option-graph resolver; this configuration was loaded without one"
                .to_string()
        })?;
        let mut cache = resolver
            .cache
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(config) = cache.get(extra) {
            return Ok(Arc::clone(config));
        }
        let mut config = resolver.resolve(&self.cli_overrides, extra)?;
        config.cli_overrides = self.cli_overrides.clone();
        config.layered = extra.clone();
        config.resolver = Some(Arc::clone(resolver));
        let config = Arc::new(config);
        cache.insert(extra.clone(), Arc::clone(&config));
        Ok(config)
    }

    pub fn view(&self) -> ConfigView<'_> {
        ConfigView {
            config: self,
            referenced: BTreeSet::new(),
        }
    }
}

impl Resolver {
    /// Resolve the persistent file with the `-D` layer and then the
    /// variant layer over it.
    fn resolve(&self, cli: &Overrides, variant: &Overrides) -> Result<Config, String> {
        let (graph, persistent) = match &self.source {
            ResolverSource::Graph { graph, persistent } => (graph, persistent),
            #[cfg(test)]
            ResolverSource::Literal { base, derive } => {
                let mut values = base.clone();
                values.extend(cli.iter().map(|(k, v)| (k.clone(), v.clone())));
                values.extend(variant.iter().map(|(k, v)| (k.clone(), v.clone())));
                derive(&mut values);
                return Ok(Config::from_values(values));
            }
        };
        let cli: Vec<(String, String)> = cli.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
        let variant: Vec<(String, String)> = variant
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        let layers = [
            mica::config::Layer {
                source: "-D",
                pairs: &cli,
            },
            mica::config::Layer {
                source: "configuration variant",
                pairs: &variant,
            },
        ];
        let resolved = mica::config::resolve_layers(graph, Some(persistent), &layers)
            .map_err(|diags| {
                format!(
                    "configuration does not resolve:\n{}",
                    mica::config::render_diagnostics(&diags)
                )
            })?;
        for warning in &resolved.warnings {
            crate::log::warn("config", &warning.to_string());
        }
        Ok(Config::from_values(
            mica::config::emit::keyval_rows(graph, &resolved)
                .into_iter()
                .collect(),
        ))
    }
}

impl<'a> ConfigView<'a> {
    pub fn get(&mut self, key: &str) -> Result<&'a str, String> {
        self.referenced.insert(key.to_string());
        self.config
            .values
            .get(key)
            .map(|s| s.as_str())
            .ok_or_else(|| format!("unknown configuration key `{}`", key))
    }

    /// Evaluate a `when = "…"` predicate in the unified predicate grammar
    /// (the shared `mica` library). Every key the
    /// expression names is recorded into the projection up front, so the
    /// recorded set is complete and independent of `&&` / `||`
    /// short-circuit. Configuration values are strings; a bare atom `KEY`
    /// is true when its value is `"true"`.
    pub fn eval_when(&mut self, expr: &str) -> Result<bool, String> {
        let src = expr.trim();
        if src.is_empty() {
            return Ok(true);
        }
        let ast = mica::parse_expr(src)?;
        let mut names = Vec::new();
        ast.atoms(&mut names);
        // Record and validate every referenced key (an unknown key is a
        // hard error) before evaluating, so the projection is a function of
        // the predicate text rather than of which branch short-circuit took.
        for name in &names {
            self.get(name)?;
        }
        let config = self.config;
        mica::eval(&ast, &mut |name: &str| {
            config.values.get(name).map(|v| mica::Value::Str(v.clone()))
        })
    }

    /// The recorded projection: (key, value) pairs the spec actually read.
    pub fn projection(&self) -> Vec<(String, String)> {
        self.referenced
            .iter()
            .map(|k| {
                (
                    k.clone(),
                    self.config.values.get(k).cloned().unwrap_or_default(),
                )
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(pairs: &[(&str, &str)]) -> Config {
        Config::from_values(
            pairs
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        )
    }

    #[test]
    fn when_grammar_and_projection() {
        let c = config(&[
            ("DEBUG_SYMBOLS", "true"),
            ("KERNEL_LOG_LEVEL", "info"),
            ("USERLAND_DEBUG_PROGRAMS", "fluxd, fluxd-vfsd"),
        ]);
        let mut v = c.view();
        assert!(v.eval_when("DEBUG_SYMBOLS").unwrap());
        assert!(!v.eval_when("!DEBUG_SYMBOLS").unwrap());
        assert!(v.eval_when("KERNEL_LOG_LEVEL = \"info\"").unwrap());
        assert!(v.eval_when("KERNEL_LOG_LEVEL != \"debug\"").unwrap());
        assert!(
            v.eval_when("USERLAND_DEBUG_PROGRAMS contains \"fluxd-vfsd\"")
                .unwrap()
        );
        assert!(
            !v.eval_when("USERLAND_DEBUG_PROGRAMS contains \"vfsd\"")
                .unwrap()
        );
        assert!(v.eval_when("MISSING").is_err());

        let proj = v.projection();
        let keys: Vec<&str> = proj.iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(
            keys,
            vec![
                "DEBUG_SYMBOLS",
                "KERNEL_LOG_LEVEL",
                "MISSING",
                "USERLAND_DEBUG_PROGRAMS"
            ]
        );
    }
}
