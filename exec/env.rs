//! SPDX-License-Identifier: GPL-2.0-only
//! buildutil — setup-env hook construction
//!
//! Each provider may ship a `<provider>/etc/buildutil-setup-env` file declaring
//! env-var contributions — appending a path to PKG_CONFIG_LIBDIR, setting
//! a sysroot variable, appending a CMake flag with a path. The provider
//! runs at namespace-grade as `/build/stage/dep/<name>/...`, so each
//! declared contribution is rooted there. We apply hooks in dep-declaration
//! order; later conflicts raise, never silently overwrite.

use std::path::{Component, Path};

const EXEC_STAGE_DEP_ROOT: &str = "/build/stage/dep";

pub(super) fn apply_setup_env_hooks(
    env: &mut Vec<(String, String)>,
    drv: &crate::store::derivation::Derivation,
    stage: &Path,
) -> Result<(), String> {
    for dep in &drv.deps {
        let hook_path = stage
            .join("dep")
            .join(&dep.name)
            .join(crate::paths::SETUP_ENV_PATH);
        if hook_path.is_file() {
            let visible_root = Path::new(EXEC_STAGE_DEP_ROOT).join(&dep.name);
            apply_setup_env_file(env, &hook_path, &visible_root)?;
        }
    }
    Ok(())
}

pub(super) fn apply_setup_env_file(
    env: &mut Vec<(String, String)>,
    hook_path: &Path,
    visible_root: &Path,
) -> Result<(), String> {
    let text = std::fs::read_to_string(hook_path)
        .map_err(|e| format!("cannot read {}: {}", hook_path.display(), e))?;
    for (idx, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let parts: Vec<&str> = line.split_whitespace().collect();
        let ctx = format!("{}:{}", hook_path.display(), idx + 1);
        match parts.as_slice() {
            ["append-path", var, rel] => {
                let path = setup_env_path(visible_root, rel, &ctx)?;
                append_env(env, var, &path, ":");
            }
            ["set-path", var, rel] => {
                let path = setup_env_path(visible_root, rel, &ctx)?;
                set_env_unique(env, var, &path, &ctx)?;
            }
            ["append-flag", var, flag, rel] => {
                let path = setup_env_path(visible_root, rel, &ctx)?;
                append_env(env, var, &format!("{flag} {path}"), " ");
            }
            _ => {
                return Err(format!(
                    "{}: malformed setup-env line `{}`",
                    hook_path.display(),
                    raw
                ));
            }
        }
    }
    Ok(())
}

fn setup_env_path(visible_root: &Path, rel: &str, ctx: &str) -> Result<String, String> {
    let path = Path::new(rel);
    if path.is_absolute()
        || path
            .components()
            .any(|c| matches!(c, Component::ParentDir | Component::Prefix(_)))
    {
        return Err(format!(
            "{ctx}: setup-env path must be relative, got `{rel}`"
        ));
    }
    let out = if rel == "." {
        visible_root.to_path_buf()
    } else {
        visible_root.join(path)
    };
    Ok(out.to_string_lossy().into_owned())
}

fn append_env(env: &mut Vec<(String, String)>, key: &str, value: &str, sep: &str) {
    if let Some((_, existing)) = env.iter_mut().find(|(k, _)| k == key) {
        if !existing.is_empty() {
            existing.push_str(sep);
        }
        existing.push_str(value);
    } else {
        env.push((key.to_string(), value.to_string()));
    }
}

fn set_env_unique(
    env: &mut Vec<(String, String)>,
    key: &str,
    value: &str,
    ctx: &str,
) -> Result<(), String> {
    if let Some((_, existing)) = env.iter_mut().find(|(k, _)| k == key) {
        if existing != value {
            return Err(format!(
                "{ctx}: setup-env tries to set {key}={value}, already set to {existing}"
            ));
        }
    } else {
        env.push((key.to_string(), value.to_string()));
    }
    Ok(())
}
