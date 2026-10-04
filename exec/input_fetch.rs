// SPDX-License-Identifier: GPL-2.0-only
//! Unregistered repository archive acquisition with declared tools and sandbox policy.

use crate::input_toml::Value;
use crate::inputs::{codec, content};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// A state-relative view of the fetch tools and their declared provider closure.
pub(crate) struct Request {
    pub(crate) url: String,
    pub(crate) sha256: Option<String>,
    pub(crate) tools: BTreeMap<String, String>,
    pub(crate) providers: Vec<String>,
    pub(crate) mounts: Vec<(String, String)>,
    pub(crate) shell: String,
}

fn quote(value: &str) -> String {
    format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\""))
}

impl Request {
    pub(crate) fn write(&self, path: &Path) -> Result<(), String> {
        let mut text = format!(
            "[fetch]\nurl = {}\nshell = {}\n",
            quote(&self.url),
            quote(&self.shell)
        );
        if let Some(pin) = &self.sha256 {
            text.push_str(&format!("sha256 = {}\n", quote(pin)));
        }
        text.push_str(&format!(
            "providers = [{}]\n",
            self.providers
                .iter()
                .map(|s| quote(s))
                .collect::<Vec<_>>()
                .join(", ")
        ));
        text.push_str(&format!(
            "mounts = [{}]\n",
            self.mounts
                .iter()
                .map(|(target, source)| quote(&format!("{target}={source}")))
                .collect::<Vec<_>>()
                .join(", ")
        ));
        text.push_str(&format!(
            "tools = {{ {} }}\n",
            self.tools
                .iter()
                .map(|(tool, provider)| format!("{tool} = {}", quote(provider)))
                .collect::<Vec<_>>()
                .join(", ")
        ));
        std::fs::write(path, text)
            .map_err(|e| format!("cannot write input acquisition request: {e}"))
    }

    fn read(path: &Path) -> Result<Self, String> {
        let doc = crate::input_toml::parse_file(path)?;
        let table = doc
            .table(&["fetch"])
            .ok_or("input acquisition request has no [fetch]")?;
        let string = |key| {
            table
                .get(key)
                .and_then(Value::as_str)
                .map(str::to_string)
                .ok_or_else(|| format!("input acquisition request lacks {key}"))
        };
        let list = |key| {
            table
                .get(key)
                .and_then(Value::str_items)
                .ok_or_else(|| format!("input acquisition request lacks {key}"))
        };
        let Some(Value::Inline(tools)) = table.get("tools") else {
            return Err("input acquisition request lacks tool providers".into());
        };
        let mut tool_map = BTreeMap::new();
        for (tool, value) in tools {
            codec::name(tool)?;
            let value = value
                .as_str()
                .ok_or("input tool provider must be a string")?
                .to_string();
            codec::clean_path(&value)?;
            if tool_map.insert(tool.clone(), value).is_some() {
                return Err(format!("duplicate input tool `{tool}`"));
            }
        }
        let mut mounts = Vec::new();
        for value in list("mounts")? {
            let (target, source) = value.split_once('=').ok_or("malformed input fetch mount")?;
            if !Path::new(target).is_absolute() || target.contains("..") {
                return Err("invalid input fetch mount target".into());
            }
            codec::clean_path(source)?;
            mounts.push((target.to_string(), source.to_string()));
        }
        let request = Self {
            url: string("url")?,
            shell: string("shell")?,
            tools: tool_map,
            providers: list("providers")?,
            mounts,
            sha256: match table.get("sha256") {
                None => None,
                Some(Value::Str(value)) if codec::hex(value, 64) => Some(value.clone()),
                _ => return Err("invalid input archive pin".into()),
            },
        };
        if !request.url.contains("://") || request.url.chars().any(char::is_control) {
            return Err("input fetch URL must name an archive location".into());
        }
        for provider in &request.providers {
            codec::clean_path(provider)?;
        }
        Ok(request)
    }
}

/// Run the same fetch script as fixed-output derivations, without registering
/// an archive until its controller has verified the selected repository tree.
pub(crate) fn acquire(state_root: &Path, request_path: &Path) -> Result<(), String> {
    let request = Request::read(request_path)?;
    let stem = request_path
        .file_stem()
        .and_then(|s| s.to_str())
        .ok_or("input request has no name")?;
    codec::name(stem)?;
    let build_dir = state_root.join("tmp").join(stem);
    std::fs::create_dir(&build_dir)
        .map_err(|e| format!("cannot create private input fetch: {e}"))?;
    let result = (|| {
        let cwd = build_dir.join("stage/build");
        let toolbin = build_dir.join("toolbin");
        for path in [
            &cwd,
            &toolbin,
            &build_dir.join("out"),
            &build_dir.join("home"),
            &build_dir.join("tmp"),
        ] {
            std::fs::create_dir_all(path).map_err(|e| format!("cannot stage input fetch: {e}"))?;
        }
        let store = crate::store::Store::open(state_root)?;
        let mut roots = Vec::new();
        for name in &request.providers {
            let root = store.root.join(name);
            if !store.has_named(name) {
                return Err(format!(
                    "input fetch provider `{name}` is not a verified store entry"
                ));
            }
            let root = root
                .canonicalize()
                .map_err(|e| format!("cannot resolve input fetch provider `{name}`: {e}"))?;
            if let Some(drv) = super::refscan::store_entry_drv_name(name) {
                let dep = build_dir.join("stage/dep").join(drv);
                if let Some(parent) = dep.parent() {
                    std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
                }
                crate::platform::create_symlink_auto(&root, &dep)
                    .map_err(|e| format!("cannot stage input fetch provider closure: {e}"))?;
            }
            roots.push(root);
        }
        let provider_path = |relative: &str| -> Result<PathBuf, String> {
            codec::clean_path(relative)?;
            let path = store.root.join(relative);
            let canonical = path
                .canonicalize()
                .map_err(|e| format!("input fetch provider is unavailable: {e}"))?;
            if !roots.iter().any(|root| canonical.starts_with(root)) {
                return Err("input fetch path is outside the declared provider closure".into());
            }
            Ok(canonical)
        };
        for (tool, provider) in &request.tools {
            let source = provider_path(provider)?;
            crate::platform::create_symlink_auto(&source, &toolbin.join(tool))
                .map_err(|e| format!("cannot stage input fetch tool: {e}"))?;
        }
        let shell = provider_path(
            request
                .tools
                .get(&request.shell)
                .ok_or("input fetch shell is not declared")?,
        )?;
        if !request.tools.contains_key("curl") {
            return Err("input acquisition requires a declared curl provider".into());
        }
        let script = super::tokens::fetch_script_url(&request.url);
        std::fs::write(cwd.join("fetch.sh"), script)
            .map_err(|e| format!("cannot stage input fetch script: {e}"))?;
        #[cfg(target_os = "linux")]
        let mounts = request
            .mounts
            .iter()
            .map(|(target, source)| {
                provider_path(source).map(|source| (PathBuf::from(target), source))
            })
            .collect::<Result<_, _>>()?;
        let plan = super::sandbox::BuildPlan {
            argv: vec![shell.to_string_lossy().into_owned(), "fetch.sh".into()],
            env: vec![
                ("PATH".into(), toolbin.to_string_lossy().into_owned()),
                (
                    "HOME".into(),
                    build_dir.join("home").to_string_lossy().into_owned(),
                ),
                (
                    "TMPDIR".into(),
                    build_dir.join("tmp").to_string_lossy().into_owned(),
                ),
                ("LC_ALL".into(), "C".into()),
                ("TZ".into(), "UTC".into()),
            ],
            cwd,
            #[cfg(target_os = "linux")]
            stage_root: build_dir.join("stage"),
            #[cfg(target_os = "linux")]
            allowed_read: roots,
            #[cfg(target_os = "linux")]
            net: super::sandbox::NetPolicy::Allow,
            #[cfg(target_os = "linux")]
            jobserver_fifo: None,
            #[cfg(target_os = "linux")]
            shell: Some(shell),
            #[cfg(target_os = "linux")]
            mounts,
            #[cfg(target_os = "linux")]
            readonly: Vec::new(),
            #[cfg(target_os = "linux")]
            devices: Vec::new(),
        };
        let sandbox = super::sandbox::platform_sandbox();
        if sandbox.grade() != "namespace" {
            return Err("input acquisition requires the enforcing build backend".into());
        }
        let outcome = sandbox.run(&plan, None)?;
        if !outcome.status.success() {
            return Err(format!("repository archive fetch failed: {}", outcome.log));
        }
        let archive = build_dir.join("out/source.tar");
        let pin = content::file(&archive)?.0;
        if request
            .sha256
            .as_ref()
            .is_some_and(|expected| expected != &pin)
        {
            return Err(format!("input archive sha256 mismatch: selected {pin}"));
        }
        let cache = state_root.join("sources/input-archives");
        std::fs::create_dir_all(&cache).map_err(|e| e.to_string())?;
        let output = cache.join(format!("{pin}.tar"));
        let mut permissions = std::fs::metadata(&archive)
            .map_err(|e| e.to_string())?
            .permissions();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            permissions.set_mode(0o444);
        }
        #[cfg(not(unix))]
        permissions.set_readonly(true);
        std::fs::set_permissions(&archive, permissions).map_err(|e| e.to_string())?;
        match std::fs::hard_link(&archive, &output) {
            Ok(()) => {}
            Err(_) if output.is_file() && content::file(&output)?.0 == pin => {}
            Err(e) => return Err(format!("cannot retain verified input archive: {e}")),
        }
        std::fs::write(request_path.with_extension("sha256"), format!("{pin}\n"))
            .map_err(|e| e.to_string())?;
        Ok(())
    })();
    let _ = std::fs::remove_dir_all(build_dir);
    result
}

pub(crate) fn dispatch(args: &[String]) -> Result<i32, String> {
    if args.len() != 2 {
        return Err("__acquire-input: expected state root and request path".into());
    }
    let state_root = Path::new(&args[0]);
    let request_path = Path::new(&args[1]);
    let state_root = state_root.canonicalize().map_err(|e| e.to_string())?;
    let request_path = request_path.canonicalize().map_err(|e| e.to_string())?;
    if !request_path.starts_with(crate::state::plans_dir(&state_root)) {
        return Err("input acquisition request is outside the state plans directory".into());
    }
    let _lease = crate::state::lock_store_shared(&state_root)?;
    acquire(&state_root, &request_path).map(|_| 0)
}
