//! SPDX-License-Identifier: GPL-2.0-only
//! buildutil — output kinds: the `[packages]`, `[checks]`, `[apps]` and
//! `[formatter]` tables and the verb-scoped resolution of command words.
//!
//! Each kind is reached by one verb. A kind table exposes derivations under
//! their own names and groups two or more members of the same kind; tables
//! may appear in any specification file and merge. Everything outside the
//! tables is reachable only as `drv:<name>`. This module loads, merges and
//! validates the tables and turns command words into evaluation targets; it
//! knows no project's names. Naming conventions are a project's own lint.

use super::address::{self, Address};
use super::toml::{Doc, Table, Value};
use std::collections::{BTreeMap, BTreeSet};

/// The checks `buildutil check` runs itself rather than as derivations. A
/// `[checks]` group may not take one of these names.
pub const BUILTIN_CHECKS: &[&str] = &[
    "license",
    "conformance",
    "plan-parity",
    "daemon-parity",
    "daemon-races",
];

/// The group a bare `buildutil build` or `buildutil check` realizes.
pub const DEFAULT_GROUP: &str = "default";

/// Marks an evaluation target that came from a group expansion: a member
/// disabled by configuration drops out instead of failing. The character
/// cannot start a derivation name, so no command word collides with it.
pub const OPTIONAL_PREFIX: char = '?';

/// Prefix addressing any derivation, exposed or not.
pub const DRV_PREFIX: &str = "drv:";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Packages,
    Checks,
}

impl Kind {
    fn table(self) -> &'static str {
        match self {
            Kind::Packages => "packages",
            Kind::Checks => "checks",
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct KindTable {
    /// Exposed name → the specification file that exposed it.
    pub expose: BTreeMap<String, String>,
    /// Group name → (declared members, origin file).
    pub groups: BTreeMap<String, (Vec<String>, String)>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RunsOn {
    Client,
    BuildHost,
}

impl RunsOn {
    pub fn as_str(self) -> &'static str {
        match self {
            RunsOn::Client => "client",
            RunsOn::BuildHost => "build-host",
        }
    }
}

#[derive(Clone, Debug)]
pub struct AppSpec {
    /// The module implementing the app.
    pub module: String,
    pub runs_on: RunsOn,
    /// Architecture → default input packages.
    pub inputs: BTreeMap<String, Vec<String>>,
    /// Store tools a build-host app runs with.
    pub tools: Vec<String>,
    /// The repository source sets a build-host app reads.
    pub src_dirs: Vec<String>,
    pub sources: Vec<String>,
    pub origin: String,
}

#[derive(Clone, Debug)]
pub struct FormatterSpec {
    pub module: String,
    /// The source sets it formats: repository directories and files.
    pub src_dirs: Vec<String>,
    pub sources: Vec<String>,
    /// Store tools it runs with (formatters of each language).
    pub tools: Vec<String>,
    pub origin: String,
}

#[derive(Clone, Debug, Default)]
pub struct Kinds {
    pub packages: KindTable,
    pub checks: KindTable,
    pub apps: BTreeMap<String, AppSpec>,
    pub formatter: Option<FormatterSpec>,
}

/// Which table a command word resolves through.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scope {
    /// `buildutil build`: `[packages]` names and groups.
    Packages,
    /// `buildutil check`: `[checks]` names and groups (built-ins are the
    /// command's own).
    Checks,
    /// Query commands and `dev`: `[packages]` names and groups and names
    /// exposed in `[checks]`.
    Query,
}

impl Kinds {
    fn table(&self, kind: Kind) -> &KindTable {
        match kind {
            Kind::Packages => &self.packages,
            Kind::Checks => &self.checks,
        }
    }

    fn table_mut(&mut self, kind: Kind) -> &mut KindTable {
        match kind {
            Kind::Packages => &mut self.packages,
            Kind::Checks => &mut self.checks,
        }
    }

    /// Merge one specification file's kind tables. A name exposed twice, a
    /// group defined twice, an app declared twice and a second formatter
    /// are refused here, across every file merged so far.
    pub fn merge_doc(&mut self, doc: &Doc, origin: &str) -> Result<(), String> {
        for kind in [Kind::Packages, Kind::Checks] {
            let name = kind.table();
            for table in doc.tables.iter().filter(|t| t.path.first().map(String::as_str) == Some(name)) {
                if table.is_array {
                    return Err(format!("{origin}: [[{name}]] is not a kind table"));
                }
                match table.path.len() {
                    1 => {
                        for entry in &table.entries {
                            if entry.key != "expose" {
                                return Err(format!(
                                    "{origin}: [{name}] has unknown key `{}`",
                                    entry.key
                                ));
                            }
                        }
                        let expose = string_list(table, "expose", &format!("{origin}: [{name}]"))?;
                        for item in expose {
                            self.expose(kind, &item, origin)?;
                        }
                    }
                    2 if table.path[1] == "group" => {
                        for entry in &table.entries {
                            let members = entry.value.str_items().ok_or_else(|| {
                                format!(
                                    "{origin}: [{name}.group] {} must be an array of names",
                                    entry.key
                                )
                            })?;
                            self.group(kind, &entry.key, members, origin)?;
                        }
                    }
                    _ => {
                        return Err(format!(
                            "{origin}: [{}] is not a kind table (use [{name}] or [{name}.group])",
                            table.path.join(".")
                        ));
                    }
                }
            }
        }
        for table in doc.tables.iter().filter(|t| t.path.first().map(String::as_str) == Some("apps")) {
            if table.is_array || table.path.len() == 1 {
                return Err(format!(
                    "{origin}: apps are declared as named tables, [apps.<name>]"
                ));
            }
            if table.path.len() == 3 && table.path[2] == "inputs" {
                continue;
            }
            if table.path.len() != 2 {
                return Err(format!(
                    "{origin}: [{}] is not an app table",
                    table.path.join(".")
                ));
            }
            let name = table.path[1].clone();
            let app = parse_app(doc, table, &name, origin)?;
            if let Some(existing) = self.apps.get(&name) {
                return Err(format!(
                    "app `{name}` is declared in {} and in {origin}",
                    existing.origin
                ));
            }
            self.apps.insert(name, app);
        }
        for table in doc.tables.iter().filter(|t| t.path.first().map(String::as_str) == Some("formatter")) {
            if table.is_array || table.path.len() != 1 {
                return Err(format!("{origin}: the formatter is one [formatter] table"));
            }
            let ctx = format!("{origin}: [formatter]");
            for entry in &table.entries {
                if !["module", "src-dirs", "sources", "tools"].contains(&entry.key.as_str()) {
                    return Err(format!("{ctx} has unknown key `{}`", entry.key));
                }
            }
            let module = nonempty_str(table, "module", &ctx)?;
            if let Some(existing) = &self.formatter {
                return Err(format!(
                    "the formatter is declared in {} and in {origin}",
                    existing.origin
                ));
            }
            self.formatter = Some(FormatterSpec {
                module,
                src_dirs: string_list(table, "src-dirs", &ctx)?,
                sources: string_list(table, "sources", &ctx)?,
                tools: string_list(table, "tools", &ctx)?,
                origin: origin.to_string(),
            });
        }
        Ok(())
    }

    /// Expose one name in a kind; used by specification files and by
    /// frontend extensions alike.
    pub fn expose(&mut self, kind: Kind, name: &str, origin: &str) -> Result<(), String> {
        let table = self.table_mut(kind);
        if let Some(existing) = table.expose.get(name) {
            return Err(format!(
                "`{name}` is exposed in [{}] by {existing} and again by {origin}",
                kind.table()
            ));
        }
        table.expose.insert(name.to_string(), origin.to_string());
        Ok(())
    }

    /// Define one group in a kind; used by specification files and by
    /// frontend extensions alike.
    pub fn group(
        &mut self,
        kind: Kind,
        name: &str,
        members: Vec<String>,
        origin: &str,
    ) -> Result<(), String> {
        let table = self.table_mut(kind);
        if let Some((_, existing)) = table.groups.get(name) {
            return Err(format!(
                "group `{name}` of [{}] is defined by {existing} and again by {origin}",
                kind.table()
            ));
        }
        table
            .groups
            .insert(name.to_string(), (members, origin.to_string()));
        Ok(())
    }

    /// The load-time rules over the merged tables. `is_derivation` answers
    /// whether a name is a declared derivation or configuration variant.
    pub fn validate(&self, is_derivation: impl Fn(&str) -> bool) -> Result<(), String> {
        for kind in [Kind::Packages, Kind::Checks] {
            let table = self.table(kind);
            let label = kind.table();
            for (name, origin) in &table.expose {
                if !is_derivation(name) {
                    return Err(format!(
                        "{origin}: [{label}] exposes `{name}`, which no specification declares"
                    ));
                }
            }
            for (group, (members, origin)) in &table.groups {
                if table.expose.contains_key(group) {
                    return Err(format!(
                        "{origin}: group `{group}` of [{label}] is named like a name it exposes"
                    ));
                }
                if kind == Kind::Checks && BUILTIN_CHECKS.contains(&group.as_str()) {
                    return Err(format!(
                        "{origin}: group `{group}` of [checks] is named like a built-in check"
                    ));
                }
                let distinct: BTreeSet<&String> = members.iter().collect();
                if distinct.len() < 2 {
                    return Err(format!(
                        "{origin}: group `{group}` of [{label}] needs at least two members"
                    ));
                }
                if distinct.len() != members.len() {
                    return Err(format!(
                        "{origin}: group `{group}` of [{label}] lists a member twice"
                    ));
                }
                for member in members {
                    if !table.expose.contains_key(member) && !table.groups.contains_key(member) {
                        return Err(format!(
                            "{origin}: group `{group}` of [{label}] names `{member}`, which is neither exposed nor a group in [{label}]"
                        ));
                    }
                }
            }
            for group in table.groups.keys() {
                self.expand_group(kind, group)?;
            }
        }
        for (name, app) in &self.apps {
            for (arch, inputs) in &app.inputs {
                for input in inputs {
                    if !self.packages.expose.contains_key(input) {
                        return Err(format!(
                            "{}: app `{name}` input `{input}` for {arch} is not exposed in [packages]",
                            app.origin
                        ));
                    }
                }
            }
        }
        Ok(())
    }

    /// Recursive group expansion to exposed names, in declaration order,
    /// each name once. A cycle is refused.
    pub fn expand_group(&self, kind: Kind, group: &str) -> Result<Vec<String>, String> {
        fn walk(
            table: &KindTable,
            label: &str,
            name: &str,
            stack: &mut Vec<String>,
            out: &mut Vec<String>,
        ) -> Result<(), String> {
            let Some((members, _)) = table.groups.get(name) else {
                if !out.iter().any(|item| item == name) {
                    out.push(name.to_string());
                }
                return Ok(());
            };
            if stack.iter().any(|entry| entry == name) {
                stack.push(name.to_string());
                return Err(format!(
                    "groups of [{label}] form a cycle: {}",
                    stack.join(" -> ")
                ));
            }
            stack.push(name.to_string());
            for member in members {
                walk(table, label, member, stack, out)?;
            }
            stack.pop();
            Ok(())
        }
        let table = self.table(kind);
        if !table.groups.contains_key(group) {
            return Err(format!("[{}] has no group `{group}`", kind.table()));
        }
        let mut out = Vec::new();
        walk(table, kind.table(), group, &mut Vec::new(), &mut out)?;
        Ok(out)
    }

    pub fn is_group(&self, kind: Kind, name: &str) -> bool {
        self.table(kind).groups.contains_key(name)
    }

    pub fn is_exposed(&self, kind: Kind, name: &str) -> bool {
        self.table(kind).expose.contains_key(name)
    }

    /// Resolve command words through `scope` into evaluation targets: an
    /// exposed name or `drv:` address keeps its address; a group expands to
    /// its members, each marked optional so a member disabled by
    /// configuration drops out. `is_derivation` answers for `drv:` names.
    pub fn resolve(
        &self,
        scope: Scope,
        words: &[String],
        is_derivation: impl Fn(&str) -> bool,
    ) -> Result<Vec<String>, String> {
        let mut out: Vec<String> = Vec::new();
        let mut push = |target: String| {
            let plain = target.trim_start_matches(OPTIONAL_PREFIX).to_string();
            if target.starts_with(OPTIONAL_PREFIX) {
                if !out
                    .iter()
                    .any(|existing| existing.trim_start_matches(OPTIONAL_PREFIX) == plain)
                {
                    out.push(target);
                }
            } else {
                // An explicit request outranks an optional group member.
                out.retain(|existing| existing.trim_start_matches(OPTIONAL_PREFIX) != plain);
                out.push(target);
            }
        };
        for word in words {
            if let Some(rest) = word.strip_prefix(DRV_PREFIX) {
                let parsed = address::parse(rest)?;
                if !is_derivation(parsed.name()) {
                    return Err(format!("`{word}`: no derivation is named `{}`", parsed.name()));
                }
                push(parsed.render());
                continue;
            }
            let parsed = address::parse(word)?;
            let name = parsed.name();
            let group_kind = match scope {
                Scope::Packages | Scope::Query => Kind::Packages,
                Scope::Checks => Kind::Checks,
            };
            if self.is_group(group_kind, name) {
                if !matches!(parsed, Address::Plain(_)) {
                    return Err(format!("`{word}`: a group takes no configuration"));
                }
                for member in self.expand_group(group_kind, name)? {
                    push(format!("{OPTIONAL_PREFIX}{member}"));
                }
                continue;
            }
            let exposed = match scope {
                Scope::Packages => self.is_exposed(Kind::Packages, name),
                Scope::Checks => self.is_exposed(Kind::Checks, name),
                Scope::Query => {
                    self.is_exposed(Kind::Packages, name) || self.is_exposed(Kind::Checks, name)
                }
            };
            if exposed {
                push(parsed.render());
                continue;
            }
            return Err(self.not_in_scope(scope, word, name, &is_derivation));
        }
        Ok(out)
    }

    fn not_in_scope(
        &self,
        scope: Scope,
        word: &str,
        name: &str,
        is_derivation: &impl Fn(&str) -> bool,
    ) -> String {
        let elsewhere = if scope != Scope::Checks
            && (self.is_exposed(Kind::Checks, name) || self.is_group(Kind::Checks, name))
        {
            Some("a check; run it with `buildutil check`")
        } else if scope == Scope::Checks
            && (self.is_exposed(Kind::Packages, name) || self.is_group(Kind::Packages, name))
        {
            Some("a package; build it with `buildutil build`")
        } else if self.apps.contains_key(name) {
            Some("an app; run it with `buildutil run`")
        } else {
            None
        };
        let table = match scope {
            Scope::Packages => "[packages]",
            Scope::Checks => "[checks]",
            Scope::Query => "[packages] or [checks]",
        };
        match elsewhere {
            Some(what) => format!("`{word}` is {what}"),
            None if is_derivation(name) => format!(
                "`{word}` is not exposed in {table}; address the derivation as `{DRV_PREFIX}{word}`"
            ),
            None => format!("`{word}` is not exposed in {table}"),
        }
    }
}

fn string_list(table: &Table, key: &str, ctx: &str) -> Result<Vec<String>, String> {
    match table.get(key) {
        None => Ok(Vec::new()),
        Some(value) => value
            .str_items()
            .ok_or_else(|| format!("{ctx}: `{key}` must be an array of names")),
    }
}

fn nonempty_str(table: &Table, key: &str, ctx: &str) -> Result<String, String> {
    match table.get(key).and_then(Value::as_str) {
        Some(value) if !value.is_empty() => Ok(value.to_string()),
        _ => Err(format!("{ctx}: `{key}` must be a non-empty string")),
    }
}

fn parse_app(doc: &Doc, table: &Table, name: &str, origin: &str) -> Result<AppSpec, String> {
    let ctx = format!("{origin}: [apps.{name}]");
    for entry in &table.entries {
        if !["module", "runs-on", "inputs", "tools", "src-dirs", "sources"].contains(&entry.key.as_str()) {
            return Err(format!("{ctx}: unknown key `{}`", entry.key));
        }
    }
    let module = nonempty_str(table, "module", &ctx)?;
    let runs_on = match table.get("runs-on").and_then(Value::as_str) {
        Some("client") => RunsOn::Client,
        Some("build-host") => RunsOn::BuildHost,
        _ => {
            return Err(format!(
                "{ctx}: `runs-on` must be \"client\" or \"build-host\""
            ));
        }
    };
    let mut inputs: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut add = |arch: &str, value: &Value| -> Result<(), String> {
        let items = value
            .str_items()
            .ok_or_else(|| format!("{ctx}: inputs.{arch} must be an array of package names"))?;
        if inputs.insert(arch.to_string(), items).is_some() {
            return Err(format!("{ctx}: inputs.{arch} is declared twice"));
        }
        Ok(())
    };
    match table.get("inputs") {
        None => {}
        Some(Value::Inline(pairs)) => {
            for (arch, value) in pairs {
                add(arch, value)?;
            }
        }
        Some(_) => return Err(format!("{ctx}: `inputs` must be a table of architectures")),
    }
    if let Some(sub) = doc.table(&["apps", name, "inputs"]) {
        for entry in &sub.entries {
            add(&entry.key, &entry.value)?;
        }
    }
    let tools = string_list(table, "tools", &ctx)?;
    let src_dirs = string_list(table, "src-dirs", &ctx)?;
    let sources = string_list(table, "sources", &ctx)?;
    if runs_on == RunsOn::Client && !(tools.is_empty() && src_dirs.is_empty() && sources.is_empty()) {
        return Err(format!(
            "{ctx}: a client app runs on the client with its prepared inputs; store tools and source sets belong to build-host apps"
        ));
    }
    Ok(AppSpec {
        module,
        runs_on,
        inputs,
        tools,
        src_dirs,
        sources,
        origin: origin.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn doc(src: &str) -> Doc {
        super::super::toml::parse(std::path::Path::new("kinds.toml"), src).unwrap()
    }

    fn kinds(files: &[&str]) -> Result<Kinds, String> {
        let mut kinds = Kinds::default();
        for (index, src) in files.iter().enumerate() {
            kinds.merge_doc(&doc(src), &format!("file{index}"))?;
        }
        Ok(kinds)
    }

    const DRVS: &[&str] = &[
        "kernite",
        "buildutil",
        "lib-mica",
        "test-kernite",
        "test-kernite-tools",
        "check-kernite-stack",
        "kernite-obj",
        "image-disk-bios",
    ];

    fn known(name: &str) -> bool {
        DRVS.contains(&name)
    }

    const SURFACE: &str = r#"
[packages]
expose = ["kernite", "buildutil", "lib-mica", "image-disk-bios"]

[packages.group]
default = ["os", "engine"]
os = ["kernite", "image-disk-bios"]
engine = ["buildutil", "lib-mica"]

[checks]
expose = ["test-kernite", "test-kernite-tools", "check-kernite-stack"]

[checks.group]
kernite = ["test-kernite", "test-kernite-tools", "check-kernite-stack"]
default = ["kernite", "test-kernite"]
"#;

    #[test]
    fn required_kind_tables_merge_across_files_and_resolve_by_verb() {
        let kinds = kinds(&[SURFACE, "[apps.qemu]\nmodule = \"vm\"\nruns-on = \"client\"\ninputs = { x86_64 = [\"image-disk-bios\"] }\n[formatter]\nmodule = \"fmt\"\n"]).unwrap();
        kinds.validate(known).unwrap();
        // The verb chooses the kind: `kernite` is a package and a check group.
        assert_eq!(
            kinds.resolve(Scope::Packages, &["kernite".into()], known).unwrap(),
            vec!["kernite"]
        );
        assert_eq!(
            kinds.resolve(Scope::Checks, &["kernite".into()], known).unwrap(),
            vec!["?test-kernite", "?test-kernite-tools", "?check-kernite-stack"]
        );
        assert_eq!(
            kinds.resolve(Scope::Packages, &["default".into()], known).unwrap(),
            vec!["?kernite", "?image-disk-bios", "?buildutil", "?lib-mica"]
        );
        // An explicit request outranks the same optional group member.
        assert_eq!(
            kinds
                .resolve(Scope::Packages, &["os".into(), "kernite".into()], known)
                .unwrap(),
            vec!["?image-disk-bios", "kernite"]
        );
        assert_eq!(kinds.apps["qemu"].runs_on, RunsOn::Client);
        assert_eq!(kinds.formatter.as_ref().unwrap().module, "fmt");
    }

    #[test]
    fn required_bare_names_outside_the_tables_fail_and_drv_reaches_them() {
        let kinds = kinds(&[SURFACE]).unwrap();
        let error = kinds
            .resolve(Scope::Packages, &["kernite-obj".into()], known)
            .unwrap_err();
        assert!(error.contains("drv:kernite-obj"), "{error}");
        assert_eq!(
            kinds
                .resolve(Scope::Packages, &["drv:kernite-obj".into()], known)
                .unwrap(),
            vec!["kernite-obj"]
        );
        assert!(
            kinds
                .resolve(Scope::Packages, &["drv:missing".into()], known)
                .is_err()
        );
        // `check` refuses a package and `build` refuses a check.
        assert!(
            kinds
                .resolve(Scope::Checks, &["buildutil".into()], known)
                .unwrap_err()
                .contains("package")
        );
        assert!(
            kinds
                .resolve(Scope::Packages, &["test-kernite".into()], known)
                .unwrap_err()
                .contains("check")
        );
        // Query commands accept packages, their groups and exposed checks,
        // not check groups.
        assert_eq!(
            kinds
                .resolve(Scope::Query, &["test-kernite".into(), "engine".into()], known)
                .unwrap(),
            vec!["test-kernite", "?buildutil", "?lib-mica"]
        );
    }

    #[test]
    fn required_load_refuses_collisions_cycles_unknown_members_and_small_groups() {
        // Same-kind collision across files.
        assert!(kinds(&[SURFACE, "[packages]\nexpose = [\"kernite\"]\n"]).is_err());
        // A group defined twice.
        assert!(
            kinds(&[SURFACE, "[packages.group]\nos = [\"buildutil\", \"lib-mica\"]\n"]).is_err()
        );
        let refused = |src: &str| {
            let kinds = kinds(&[src]).unwrap();
            kinds.validate(known).unwrap_err()
        };
        // A group of one.
        assert!(refused("[packages]\nexpose = [\"kernite\"]\n[packages.group]\nsolo = [\"kernite\"]\n").contains("two members"));
        // A member repeated to reach two.
        assert!(refused("[packages]\nexpose = [\"kernite\"]\n[packages.group]\npair = [\"kernite\", \"kernite\"]\n").contains("twice"));
        // An unknown member.
        assert!(refused("[packages]\nexpose = [\"kernite\"]\n[packages.group]\npair = [\"kernite\", \"nothing\"]\n").contains("nothing"));
        // A cycle.
        assert!(
            refused(
                "[packages]\nexpose = [\"kernite\", \"buildutil\"]\n[packages.group]\na = [\"b\", \"kernite\"]\nb = [\"a\", \"buildutil\"]\n"
            )
            .contains("cycle")
        );
        // A group named like a name exposed in its own kind.
        assert!(
            refused(
                "[packages]\nexpose = [\"kernite\", \"buildutil\", \"lib-mica\"]\n[packages.group]\nkernite = [\"buildutil\", \"lib-mica\"]\n"
            )
            .contains("exposes")
        );
        // A check group named like a built-in check.
        assert!(refused("[checks]\nexpose = [\"test-kernite\", \"test-kernite-tools\"]\n[checks.group]\nlicense = [\"test-kernite\", \"test-kernite-tools\"]\n").contains("built-in"));
        // An exposed name no specification declares.
        assert!(refused("[packages]\nexpose = [\"ghost\"]\n").contains("ghost"));
        // A group named in another kind is not a member here.
        assert!(refused("[packages]\nexpose = [\"kernite\"]\n[checks]\nexpose = [\"test-kernite\"]\n[packages.group]\nmixed = [\"kernite\", \"test-kernite\"]\n").contains("test-kernite"));
    }

    #[test]
    fn required_app_tables_declare_where_they_run() {
        assert!(kinds(&["[apps.qemu]\nmodule = \"vm\"\nruns-on = \"moon\"\n"]).is_err());
        assert!(kinds(&["[apps.qemu]\nruns-on = \"client\"\n"]).is_err());
        let kinds = kinds(&["[packages]\nexpose = [\"kernite\"]\n[apps.gdb]\nmodule = \"vm\"\nruns-on = \"client\"\n[apps.rust-project]\nmodule = \"rust-project\"\nruns-on = \"build-host\"\n[apps.rust-project.inputs]\nx86_64 = [\"kernite\"]\n"]).unwrap();
        kinds.validate(known).unwrap();
        assert!(kinds.apps["gdb"].inputs.is_empty());
        assert_eq!(kinds.apps["rust-project"].runs_on, RunsOn::BuildHost);
        assert_eq!(kinds.apps["rust-project"].inputs["x86_64"], vec!["kernite"]);
    }
}
