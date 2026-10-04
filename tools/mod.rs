//! SPDX-License-Identifier: GPL-2.0-only
//! buildutil — core tool-provider resolution
//!
//! Provider selection is evaluation mechanism, not a peripheral builder: it
//! contributes dependency edges and tool identity to every derivation. The
//! engine knows only the names the buildutil specification reserves — `buildutil`
//! (the bootstrap-grade or the store-built engine), the composition tools
//! `buildutil-compose` and `buildutil-sysroot`, and the native frontend's ambient
//! `rustc` and `cc`, which carry the identity bootstrap.ninja captured.
//! Every other tool comes from a provider the build specification's stages
//! and `[tool-provider]` tables declare.

use std::path::{Path, PathBuf};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ToolMode {
    Store,
    Bootstrap,
    NativeFrontend,
}

impl ToolMode {
    pub fn for_derivation(bootstrap: bool, native_frontend: bool) -> Self {
        if native_frontend {
            ToolMode::NativeFrontend
        } else if bootstrap {
            ToolMode::Bootstrap
        } else {
            ToolMode::Store
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ToolProvider {
    Store { drv: String, relpath: String },
    Ambient,
}

/// Where a tool comes from after provider selection. Store providers stay
/// symbolic until realization; an ambient provider carries both the executable
/// path and the digest of bootstrap.ninja's captured identity record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ToolLocator {
    Store {
        drv: String,
        relpath: String,
    },
    Ambient {
        path: PathBuf,
        identity_sha256: String,
    },
    Unknown,
}

#[derive(Clone, Debug)]
struct AmbientTool {
    name: &'static str,
    path: PathBuf,
}

pub struct Toolchain {
    ambient_tools: Vec<AmbientTool>,
    ambient_identity_sha256: Option<String>,
}

/// The provider of a name the engine reserves, or `None` for every tool a
/// build specification declares. Pure: graph construction needs to know
/// whether an edge is store-backed before a concrete ambient executable is
/// attached to the Toolchain.
pub fn tool_provider(tool: &str, mode: ToolMode) -> Option<ToolProvider> {
    if mode == ToolMode::NativeFrontend {
        return match tool {
            "rustc" | "cc" => Some(ToolProvider::Ambient),
            _ => None,
        };
    }
    let own = |drv: &str, relpath: &str| {
        Some(ToolProvider::Store {
            drv: drv.to_string(),
            relpath: relpath.to_string(),
        })
    };
    match tool {
        "buildutil" if mode == ToolMode::Bootstrap => own("buildutil-bootstrap", "buildutil"),
        "buildutil" => own("buildutil", "buildutil"),
        "buildutil-compose" => own("buildutil-compose", "buildutil-compose"),
        "buildutil-sysroot" => own("buildutil-sysroot", "buildutil-sysroot"),
        _ => None,
    }
}

/// Whether the engine reserves `tool` for store and bootstrap-grade
/// derivations; a specification may not declare a provider for it. The
/// native frontend's ambient names are reserved only in that mode, so the
/// stages still name their own `rustc` and `cc`.
pub fn is_reserved(tool: &str) -> bool {
    [ToolMode::Store, ToolMode::Bootstrap]
        .into_iter()
        .any(|mode| tool_provider(tool, mode).is_some())
}

impl Toolchain {
    pub fn new(_store_root: &Path) -> Toolchain {
        Toolchain {
            ambient_tools: Vec::new(),
            ambient_identity_sha256: None,
        }
    }

    pub fn with_native_frontend_tools(
        store_root: &Path,
        rustc: PathBuf,
        linker: PathBuf,
        identity_record: &[u8],
    ) -> Toolchain {
        let mut toolchain = Toolchain::new(store_root);
        toolchain.ambient_tools = vec![
            AmbientTool {
                name: "rustc",
                path: rustc,
            },
            AmbientTool {
                name: "cc",
                path: linker,
            },
        ];
        toolchain.ambient_identity_sha256 =
            Some(crate::crypto::sha256::hash_bytes(identity_record));
        toolchain
    }

    pub fn locator(&self, tool: &str, mode: ToolMode) -> ToolLocator {
        self.locator_for_provider(tool, tool_provider(tool, mode))
    }

    /// Attach concrete ambient identity to an already-selected provider.
    /// Store providers remain symbolic until their derivation is realized.
    pub fn locator_for_provider(&self, tool: &str, provider: Option<ToolProvider>) -> ToolLocator {
        match provider {
            Some(ToolProvider::Store { drv, relpath }) => ToolLocator::Store { drv, relpath },
            Some(ToolProvider::Ambient) => self
                .ambient_tools
                .iter()
                .find(|provider| provider.name == tool)
                .and_then(|provider| {
                    self.ambient_identity_sha256
                        .as_ref()
                        .map(|identity| ToolLocator::Ambient {
                            path: provider.path.clone(),
                            identity_sha256: identity.clone(),
                        })
                })
                .unwrap_or(ToolLocator::Unknown),
            None => ToolLocator::Unknown,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{ToolLocator, ToolMode, ToolProvider, Toolchain, is_reserved, tool_provider};
    use std::path::Path;

    #[test]
    fn declared_tools_are_not_engine_knowledge() {
        // Every build tool but the reserved names comes from a stage or a
        // `[tool-provider]` declaration; the engine selects none of them.
        let tc = Toolchain::new(Path::new("."));
        for tool in [
            "sh", "cmake", "ninja", "python3", "nasm", "bindgen", "curl", "git", "clang",
            "ld.lld", "cc", "c++", "rustc", "cargo", "make", "perl", "tar", "strip",
        ] {
            assert_eq!(tool_provider(tool, ToolMode::Store), None, "{tool}");
            assert_eq!(tool_provider(tool, ToolMode::Bootstrap), None, "{tool}");
            assert_eq!(tc.locator(tool, ToolMode::Store), ToolLocator::Unknown);
            assert!(!is_reserved(tool), "{tool}");
        }
    }

    #[test]
    fn reserved_names_resolve_to_the_engine_own_derivations() {
        let store = |drv: &str, rel: &str| {
            Some(ToolProvider::Store {
                drv: drv.into(),
                relpath: rel.into(),
            })
        };
        assert_eq!(
            tool_provider("buildutil", ToolMode::Store),
            store("buildutil", "buildutil")
        );
        assert_eq!(
            tool_provider("buildutil", ToolMode::Bootstrap),
            store("buildutil-bootstrap", "buildutil")
        );
        for tool in ["buildutil-compose", "buildutil-sysroot"] {
            assert_eq!(tool_provider(tool, ToolMode::Store), store(tool, tool));
            assert!(is_reserved(tool));
        }
        assert_eq!(
            tool_provider("rustc", ToolMode::NativeFrontend),
            Some(ToolProvider::Ambient)
        );
        assert_eq!(
            tool_provider("cc", ToolMode::NativeFrontend),
            Some(ToolProvider::Ambient)
        );
        assert_eq!(tool_provider("buildutil", ToolMode::NativeFrontend), None);
    }
}
