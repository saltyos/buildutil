// SPDX-License-Identifier: GPL-2.0-only
//! buildutil_sdk — the API a buildutil module is written against.
//!
//! A module is a program buildutil builds and runs as its own process. Its crate
//! names one entry function with `buildutil_sdk::main!`; the function receives a
//! `Context` describing the role buildutil runs it in and returns `Ok` or an
//! error message. The SDK owns the process boundary: it answers buildutil's
//! version query, reads the request, enforces what each role may read, and
//! writes the verdict and returned files buildutil reads back.
//!
//! Roles and their surfaces:
//! - builder (a derivation with `builder = "module"`) and generator (a
//!   `[generate.<name>]` declaration): confined and cached. They read the
//!   configuration keys their derivation declares — any other key is an
//!   error — their module configuration, declared inputs and tools, and
//!   write outputs, retained artifacts and a verdict; a generator writes
//!   declarations. No graph or plan query exists for them.
//! - formatter and app: uncached. They read the whole resolved
//!   configuration and may query the graph and the plan; the formatter and
//!   build-host apps return work-tree files, and client apps run under the
//!   terminal and may register indirect GC roots.
//!
//! Also provided: the KTAP parser and completeness check (`ktap`), buildutil's
//! TOML-subset reader (`toml`) and writer (`toml_write`), SHA-256 and the
//! wire value model with its JSON text (`wire`).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

pub mod ktap;
pub mod toml_write;
pub mod wire;

#[path = "../flake/spec/toml.rs"]
pub mod toml;

#[path = "../lib/crypto/sha256.rs"]
pub mod sha256;

pub use wire::Value;

/// The SDK version this crate is, as `major.minor.patch`.
pub fn version() -> String {
    wire::version_text(wire::VERSION)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    Builder,
    Generator,
    Formatter,
    /// An app running on the client, under the terminal.
    ClientApp,
    /// An app running on the build host with store tools.
    BuildHostApp,
}

impl Role {
    fn parse(text: &str) -> Result<Role, String> {
        Ok(match text {
            "builder" => Role::Builder,
            "generator" => Role::Generator,
            "formatter" => Role::Formatter,
            "client-app" => Role::ClientApp,
            "build-host-app" => Role::BuildHostApp,
            other => return Err(format!("unknown module role `{other}`")),
        })
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Role::Builder => "builder",
            Role::Generator => "generator",
            Role::Formatter => "formatter",
            Role::ClientApp => "client-app",
            Role::BuildHostApp => "build-host-app",
        }
    }

    /// Cached roles: their result is a derivation output.
    pub fn is_cached(self) -> bool {
        matches!(self, Role::Builder | Role::Generator)
    }

    /// Roles that return work-tree files for buildutil to write.
    fn returns_files(self) -> bool {
        matches!(self, Role::Formatter | Role::BuildHostApp)
    }
}

use wire::{GENERATED_FILE, RETURNED_DIR, RETURNED_LIST};

/// Everything a module sees of its run.
pub struct Context {
    request: Value,
    base: PathBuf,
    role: Role,
    verdict: Mutex<Option<(i64, String)>>,
    returned: Mutex<BTreeMap<String, Option<String>>>,
}

impl Context {
    fn from_request(path: &Path) -> Result<Context, String> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("cannot read the module request {}: {e}", path.display()))?;
        let request = Value::parse_json(&text)
            .map_err(|e| format!("malformed module request {}: {e}", path.display()))?;
        let provided = request
            .get("sdk")
            .and_then(Value::as_str)
            .ok_or("the module request names no SDK version")?;
        // buildutil refuses an incompatible module before running it; this side
        // refuses a request from an engine whose wire this build predates.
        wire::check_compatible(wire::VERSION, wire::parse_version(provided)?)
            .map_err(|e| format!("this module was {e}"))?;
        let role = Role::parse(
            request
                .get("role")
                .and_then(Value::as_str)
                .ok_or("the module request names no role")?,
        )?;
        let base = path
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("."));
        let context = Context {
            request,
            base,
            role,
            verdict: Mutex::new(None),
            returned: Mutex::new(BTreeMap::new()),
        };
        if role.returns_files() {
            // An uncached run's output directory persists between runs;
            // only what this run returns may be read back.
            let out = context.out_dir()?;
            let _ = std::fs::remove_dir_all(out.join(RETURNED_DIR));
            let _ = std::fs::remove_file(out.join(RETURNED_LIST));
        }
        Ok(context)
    }

    fn text(&self, key: &str) -> Result<&str, String> {
        self.request
            .lookup(key)
            .and_then(Value::as_str)
            .ok_or_else(|| format!("the module request has no `{key}`"))
    }

    fn path_at(&self, key: &str) -> Result<PathBuf, String> {
        Ok(self.resolve(self.text(key)?))
    }

    fn resolve(&self, text: &str) -> PathBuf {
        let path = Path::new(text);
        if path.is_absolute() {
            path.to_path_buf()
        } else {
            self.base.join(path)
        }
    }

    pub fn role(&self) -> Role {
        self.role
    }

    /// The module's declared name.
    pub fn module(&self) -> &str {
        self.text("module").unwrap_or("")
    }

    /// The derivation, app or formatter this run serves.
    pub fn name(&self) -> &str {
        self.text("name").unwrap_or("")
    }

    /// The configured target architecture.
    pub fn arch(&self) -> &str {
        self.text("arch").unwrap_or("")
    }

    /// The build host's triple.
    pub fn build_host(&self) -> &str {
        self.text("build-host").unwrap_or("")
    }

    /// A resolved configuration value. A builder or generator reads only
    /// the keys its derivation declares; any other key is an error.
    pub fn config(&self, key: &str) -> Result<String, String> {
        match self.request.get("config").and_then(|c| c.get(key)) {
            Some(Value::Str(value)) => Ok(value.clone()),
            Some(_) => Err(format!("configuration key `{key}` is malformed in the request")),
            None if self.role.is_cached() => Err(format!(
                "configuration key `{key}` is not declared by `{}`; declare it in its `config-keys`",
                self.name()
            )),
            None => Err(format!("configuration has no key `{key}`")),
        }
    }

    /// A configuration value read as an integer list (`4,1`).
    pub fn config_int_list(&self, key: &str) -> Result<Vec<i64>, String> {
        let text = self.config(key)?;
        text.split(',')
            .filter(|part| !part.trim().is_empty())
            .map(|part| {
                part.trim()
                    .parse::<i64>()
                    .map_err(|_| format!("configuration `{key}` = `{text}` is not an integer list"))
            })
            .collect()
    }

    /// The module's `[module.<name>.config]` table, passed unchanged.
    pub fn module_config(&self) -> &Value {
        static EMPTY: Value = Value::Null;
        self.request.get("module-config").unwrap_or(&EMPTY)
    }

    /// The module configuration value at a dotted path.
    pub fn setting(&self, path: &str) -> Option<&Value> {
        self.module_config().lookup(path)
    }

    /// A required string setting.
    pub fn setting_str(&self, path: &str) -> Result<String, String> {
        self.setting(path)
            .and_then(Value::as_str)
            .map(str::to_string)
            .ok_or_else(|| {
                format!(
                    "[module.{}.config] {path} must be a string",
                    self.module()
                )
            })
    }

    /// A required list-of-strings setting.
    pub fn setting_str_list(&self, path: &str) -> Result<Vec<String>, String> {
        self.setting(path)
            .and_then(Value::as_str_list)
            .ok_or_else(|| {
                format!(
                    "[module.{}.config] {path} must be an array of strings",
                    self.module()
                )
            })
    }

    /// The arguments after the tool: a builder's declared `argv`, an
    /// app's arguments after `--`.
    pub fn arguments(&self) -> Vec<String> {
        self.request
            .get("arguments")
            .and_then(Value::as_str_list)
            .unwrap_or_default()
    }

    /// A declared input: a dependency of a builder or generator, a
    /// prepared package of an app or the formatter.
    pub fn input(&self, name: &str) -> Result<PathBuf, String> {
        match self.request.get("inputs").and_then(|i| i.get(name)) {
            Some(Value::Str(path)) => Ok(self.resolve(path)),
            _ => Err(format!("`{name}` is not an input of `{}`", self.name())),
        }
    }

    /// The store entry name of a declared input of a builder or an uncached
    /// run: `<hash>-<name>-<arch>`, the same on the build host and the
    /// client, where the store lives under another root.
    pub fn input_store_name(&self, name: &str) -> Result<String, String> {
        self.request
            .get("input-store-names")
            .and_then(|names| names.get(name))
            .and_then(Value::as_str)
            .map(str::to_string)
            .ok_or_else(|| format!("`{name}` is not an input of `{}`", self.name()))
    }

    /// Every declared input by name.
    pub fn inputs(&self) -> Vec<(String, PathBuf)> {
        self.request
            .get("inputs")
            .and_then(Value::as_table)
            .map(|map| {
                map.iter()
                    .filter_map(|(k, v)| v.as_str().map(|p| (k.clone(), self.resolve(p))))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// The input names in the order they were requested.
    pub fn input_order(&self) -> Vec<String> {
        self.request
            .get("input-order")
            .and_then(Value::as_str_list)
            .unwrap_or_default()
    }

    /// A declared tool, staged for this run.
    pub fn tool(&self, name: &str) -> Result<PathBuf, String> {
        match self.request.get("tools").and_then(|t| t.get(name)) {
            Some(Value::Str(path)) => Ok(self.resolve(path)),
            _ => Err(format!("tool `{name}` is not declared by `{}`", self.name())),
        }
    }

    /// The staged source root: repository-relative declared sources are
    /// found beneath it.
    pub fn source_root(&self) -> Result<PathBuf, String> {
        self.path_at("paths.source-root")
    }

    /// The output directory of a builder or generator.
    pub fn out_dir(&self) -> Result<PathBuf, String> {
        self.path_at("paths.out")
    }

    /// The declared outputs, relative to the output directory.
    pub fn outputs(&self) -> Vec<String> {
        self.request
            .get("outputs")
            .and_then(Value::as_str_list)
            .unwrap_or_default()
    }

    /// Where a builder keeps logs and summaries for the latest attempt,
    /// retained beside its build log whether it passes or fails.
    pub fn artifacts_dir(&self) -> Result<PathBuf, String> {
        self.path_at("paths.artifacts")
    }

    /// How many jobs this run may keep busy: a builder's share of buildutil's
    /// job pool, else the machine's parallelism.
    pub fn jobs(&self) -> usize {
        std::env::var("NPROC")
            .ok()
            .and_then(|value| value.parse().ok())
            .filter(|&n: &usize| n > 0)
            .unwrap_or_else(|| {
                std::thread::available_parallelism()
                    .map(|n| n.get())
                    .unwrap_or(1)
            })
    }

    /// A private scratch directory for this run.
    pub fn temp_dir(&self) -> Result<PathBuf, String> {
        self.path_at("paths.temp")
    }

    /// An app's run-state directory, `run/<module>/`, which buildutil creates
    /// and never reads.
    pub fn run_state(&self) -> Result<PathBuf, String> {
        self.path_at("paths.run-state")
    }

    /// Write a declared output file.
    pub fn write_output(&self, relative: &str, bytes: &[u8]) -> Result<(), String> {
        let path = self.out_dir()?.join(relative);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("cannot create {}: {e}", parent.display()))?;
        }
        std::fs::write(&path, bytes).map_err(|e| format!("cannot write {}: {e}", path.display()))
    }

    /// Record the verdict of a builder or generator: 0 passes, any other
    /// code fails the derivation. Without a call, a run that returns `Ok`
    /// reports 0.
    pub fn set_verdict(&self, code: i64, summary: &str) {
        if let Ok(mut verdict) = self.verdict.lock() {
            *verdict = Some((code, summary.to_string()));
        }
    }

    /// Write a generator's declarations.
    pub fn write_declarations(&self, document: &toml_write::Document) -> Result<(), String> {
        if self.role != Role::Generator {
            return Err("only a generator writes declarations".to_string());
        }
        self.write_output(GENERATED_FILE, document.render()?.as_bytes())
    }

    /// Return a work-tree file for buildutil to write. `based_on` is the
    /// SHA-256 of the content the module read, which buildutil checks the file
    /// still has before it replaces it; `None` returns a file the module
    /// did not read, which buildutil checks against its own read.
    pub fn return_file(
        &self,
        repo_relative: &str,
        content: &[u8],
        based_on: Option<String>,
    ) -> Result<(), String> {
        if !self.role.returns_files() {
            return Err(format!(
                "a {} does not return work-tree files",
                self.role.as_str()
            ));
        }
        let clean = !repo_relative.is_empty()
            && !repo_relative.starts_with('/')
            && repo_relative
                .split('/')
                .all(|c| !c.is_empty() && c != "." && c != "..");
        if !clean {
            return Err(format!("`{repo_relative}` is not a clean repository path"));
        }
        self.write_output(&format!("{RETURNED_DIR}/{repo_relative}"), content)?;
        self.returned
            .lock()
            .map_err(|_| "the returned-file list is poisoned".to_string())?
            .insert(repo_relative.to_string(), based_on);
        Ok(())
    }

    /// The read-only graph query: every derivation of the specification
    /// with its builder, arguments evaluated under the configuration,
    /// declared inputs and dependencies; a derivation the configuration
    /// cannot evaluate carries the reason as `error`. Offered to apps and the
    /// formatter.
    pub fn graph(&self) -> Result<Value, String> {
        self.query("graph")
    }

    /// The read-only plan query: the prepared inputs' configured nodes with
    /// their store paths and dependency closures. Offered to apps and the
    /// formatter.
    pub fn plan(&self) -> Result<Value, String> {
        self.query("plan")
    }

    fn query(&self, which: &str) -> Result<Value, String> {
        if self.role.is_cached() {
            return Err(format!(
                "a {} has no {which} query; cached roles read only their declared inputs",
                self.role.as_str()
            ));
        }
        let path = self.path_at(&format!("queries.{which}"))?;
        let text = std::fs::read_to_string(&path)
            .map_err(|e| format!("cannot read the {which} query {}: {e}", path.display()))?;
        Value::parse_json(&text)
    }

    /// The buildutil executable that started this app.
    pub fn buildutil_executable(&self) -> Result<PathBuf, String> {
        self.path_at("buildutil")
    }

    /// Register `link`, a symlink the app keeps in its run state naming a
    /// store path, as an indirect GC root: the store path stays alive until
    /// the app removes or repoints the link.
    pub fn register_indirect_root(&self, link: &Path) -> Result<(), String> {
        if self.role != Role::ClientApp {
            return Err("only a client app registers indirect roots".to_string());
        }
        let buildutil = self.buildutil_executable()?;
        let status = std::process::Command::new(&buildutil)
            .arg("store")
            .arg("add-indirect-root")
            .arg(link)
            .arg("--store")
            .arg(self.path_at("paths.state-root")?)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .status()
            .map_err(|e| format!("cannot run {}: {e}", buildutil.display()))?;
        if status.success() {
            Ok(())
        } else {
            Err(format!("registering the indirect root {} failed", link.display()))
        }
    }

    /// Report progress: a counted item the build screen shows on its status
    /// row.
    pub fn progress(&self, done: usize, total: usize, text: &str) {
        let line = one_line(text);
        if self.role == Role::ClientApp {
            eprintln!("[{done}/{total}] {line}");
        } else {
            // The structured item marker the build screen reads.
            println!("@buildutil {done}/{total} {line}");
        }
    }

    /// A line for the person reading the build or the terminal.
    pub fn message(&self, text: &str) {
        eprintln!("{}", one_line(text));
    }

    fn finish(&self, result: &Result<(), String>) -> Result<i32, String> {
        let recorded = self.verdict.lock().ok().and_then(|v| v.clone());
        let (code, summary) = match (result, recorded) {
            (Err(message), _) => (1, message.clone()),
            (Ok(()), Some(verdict)) => verdict,
            (Ok(()), None) => (0, String::new()),
        };
        if self.role.returns_files() {
            let out = self.out_dir()?;
            std::fs::create_dir_all(out.join(RETURNED_DIR))
                .map_err(|e| format!("cannot create {}: {e}", out.join(RETURNED_DIR).display()))?;
            let mut list = String::new();
            let returned = self
                .returned
                .lock()
                .map_err(|_| "the returned-file list is poisoned".to_string())?;
            for (path, based_on) in returned.iter() {
                list.push_str(based_on.as_deref().unwrap_or("-"));
                list.push(' ');
                list.push_str(path);
                list.push('\n');
            }
            self.write_output(RETURNED_LIST, list.as_bytes())?;
        }
        if let Some(Value::Str(path)) = self.request.lookup("results.verdict") {
            let mut verdict = Value::table();
            verdict.set("code", Value::Int(code));
            verdict.set("summary", Value::str(one_line(&summary)));
            let path = self.resolve(path);
            std::fs::write(&path, verdict.to_json())
                .map_err(|e| format!("cannot write the verdict {}: {e}", path.display()))?;
        }
        Ok(if code == 0 {
            0
        } else {
            i32::try_from(code).ok().filter(|c| (1..=125).contains(c)).unwrap_or(1)
        })
    }
}

fn one_line(text: &str) -> String {
    text.replace(['\n', '\r'], " ")
}

/// The body of `buildutil_sdk::main!`: answer the version query, or read the
/// request, run `entry` and report its result. The exit status agrees with
/// the verdict: zero exactly when the verdict code is zero.
pub fn run(entry: fn(&Context) -> Result<(), String>) -> i32 {
    let mut args = std::env::args().skip(1);
    if args.next().as_deref() == Some(wire::VERSION_ARGUMENT) {
        println!("{}", version());
        return 0;
    }
    let Some(request) = std::env::var_os(wire::REQUEST_ENV) else {
        eprintln!(
            "this program is a buildutil module; buildutil runs it (it reads its request from {})",
            wire::REQUEST_ENV
        );
        return 2;
    };
    let context = match Context::from_request(Path::new(&request)) {
        Ok(context) => context,
        Err(message) => {
            eprintln!("{message}");
            return 2;
        }
    };
    let result = entry(&context);
    if let Err(message) = &result {
        eprintln!("{}", one_line(message));
    }
    match context.finish(&result) {
        Ok(code) => code,
        Err(message) => {
            eprintln!("{message}");
            1
        }
    }
}

/// Name a module's entry function: `buildutil_sdk::main!(run);` where
/// `fn run(ctx: &buildutil_sdk::Context) -> Result<(), String>`.
#[macro_export]
macro_rules! main {
    ($entry:path) => {
        fn main() {
            ::std::process::exit($crate::run($entry));
        }
    };
}

/// SHA-256 of a byte string as lowercase hex.
pub fn sha256_hex(bytes: &[u8]) -> String {
    sha256::hash_bytes(bytes)
}

/// Read a file and return its content with its SHA-256, for a module that
/// returns an edited version of it.
pub fn read_with_hash(path: &Path) -> Result<(Vec<u8>, String), String> {
    let bytes = std::fs::read(path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    let hash = sha256_hex(&bytes);
    Ok((bytes, hash))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn context(role: &str, config: &[(&str, &str)]) -> (Context, PathBuf) {
        let dir = std::env::temp_dir().join(format!(
            "buildutil-sdk-test-{}-{}",
            std::process::id(),
            role
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("out")).unwrap();
        let mut request = Value::table();
        request.set("sdk", Value::str(version()));
        request.set("role", Value::str(role));
        request.set("module", Value::str("demo"));
        request.set("name", Value::str("check-demo"));
        let mut cfg = Value::table();
        for (k, v) in config {
            cfg.set(k, Value::str(*v));
        }
        request.set("config", cfg);
        let mut paths = Value::table();
        paths.set("out", Value::str("out"));
        request.set("paths", paths);
        let mut results = Value::table();
        results.set("verdict", Value::str("verdict.json"));
        request.set("results", results);
        let path = dir.join("request.json");
        std::fs::write(&path, request.to_json()).unwrap();
        (Context::from_request(&path).unwrap(), dir)
    }

    #[test]
    fn required_builder_reading_an_undeclared_key_fails() {
        let (ctx, _dir) = context("builder", &[("TEST_SMP_PASSES", "4,1")]);
        assert_eq!(ctx.config_int_list("TEST_SMP_PASSES").unwrap(), vec![4, 1]);
        let error = ctx.config("OTHER").unwrap_err();
        assert!(error.contains("not declared"), "{error}");
        assert!(ctx.graph().is_err(), "a cached role has no graph query");
    }

    #[test]
    fn required_verdict_agrees_with_exit_status() {
        let (ctx, dir) = context("builder", &[]);
        ctx.set_verdict(3, "timeout");
        assert_eq!(ctx.finish(&Ok(())).unwrap(), 3);
        let verdict = Value::parse_json(&std::fs::read_to_string(dir.join("verdict.json")).unwrap())
            .unwrap();
        assert_eq!(verdict.get("code").unwrap().as_int(), Some(3));
        let (ctx, _dir) = context("builder", &[]);
        assert_eq!(ctx.finish(&Err("boom".into())).unwrap(), 1);
    }

    #[test]
    fn required_a_newer_sdk_request_is_refused_by_an_older_module() {
        let dir = std::env::temp_dir().join(format!("buildutil-sdk-major-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("request.json");
        std::fs::write(&path, "{\"sdk\":\"2.0.0\",\"role\":\"builder\"}").unwrap();
        assert!(Context::from_request(&path).is_err());
    }
}
