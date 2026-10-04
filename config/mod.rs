//! SPDX-License-Identifier: GPL-2.0-only
//! buildutil configuration commands over mica's option language
//!
//! The person-facing front end over mica's configuration language: a
//! Linux-Kconfig-class option system (`select` / `depends_on` / `choice`,
//! guard defaults) over a strict TOML subset. The option graph, resolution,
//! override reading and emitted artifacts live in mica, which the engine links
//! to resolve in process; this module carries menuconfig, explain, docs, the
//! generated configurations (`--allno`, `--allyes`, `--rand`) and
//! `resolve --out`, whose artifacts hold the values the engine resolves from the
//! same inputs. `validate` is the CI/pre-commit gate; `migrate-options`
//! seeds a starter graph from meson.options (one-time).

mod menuconfig;
mod migrate;

use mica::config::{diag, emit, graph, resolve, toml};

use diag::Diagnostic;
use std::path::PathBuf;

/// Print the configuration verbs and their arguments.
pub(crate) fn usage() {
    say!("Usage: buildutil config <command> [options]");
    say!("");
    say!("Commands:");
    say!(
        "  resolve --graph <dir> --config <file> --out <dir> [-D<KEY>=<value>...] [--report] [--print-keyval]"
    );
    say!("      Parse + validate + resolve + emit all artifacts (write-if-changed).");
    say!("      -D layers overrides over the override file, as buildutil's -D does.");
    say!("      --report prints CHANGED or UNCHANGED on stdout.");
    say!("      --print-keyval prints the resolved KEY=VALUE table on stdout.");
    say!("");
    say!("      --allno | --allyes | --rand --seed <n>  config-space generation.");
    say!("");
    say!("  validate --graph <dir> [--config <file>]");
    say!("      Structural validation plus a full resolution; writes nothing.");
    say!("");
    say!("  explain --graph <dir> [--config <file>] KEY");
    say!("      Print an option/choice: value, origin, visibility, range, help.");
    say!("");
    say!("  docs --graph <dir> --out <file>");
    say!("      Render the option graph as a generated RST reference.");
    say!("");
    say!("  menuconfig --graph <dir> [--config <file>]");
    say!("      Interactive raw-mode editor over the menu tree (needs a TTY).");
    say!("");
    say!("  migrate-options --meson-options <file> --out <dir>");
    say!("      Seed a starter graph (seed.toml) from meson.options (one-time aid).");
}

fn report(diags: &[Diagnostic]) {
    for d in diags {
        say!("{}", d);
    }
}

struct Args {
    graph: Option<PathBuf>,
    config: Option<PathBuf>,
    out: Option<PathBuf>,
    meson_options: Option<PathBuf>,
    report: bool,
    print_keyval: bool,
    mode: Option<resolve::ConfigMode>,
    /// `-D<KEY>=<value>` overrides layered over the override file.
    defines: Vec<(String, String)>,
    /// Positional operand (e.g. the KEY for `explain`).
    key: Option<String>,
}

fn parse_args(args: &[String]) -> Result<Args, String> {
    let mut out = Args {
        graph: None,
        config: None,
        out: None,
        meson_options: None,
        report: false,
        print_keyval: false,
        mode: None,
        defines: Vec::new(),
        key: None,
    };
    let mut rand = false;
    let mut seed: u64 = 0;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--graph" => {
                i += 1;
                out.graph = Some(PathBuf::from(
                    args.get(i).ok_or("--graph needs a directory")?,
                ));
            }
            "--config" => {
                i += 1;
                out.config = Some(PathBuf::from(args.get(i).ok_or("--config needs a file")?));
            }
            "--out" => {
                i += 1;
                out.out = Some(PathBuf::from(args.get(i).ok_or("--out needs a directory")?));
            }
            "--meson-options" => {
                i += 1;
                out.meson_options = Some(PathBuf::from(
                    args.get(i).ok_or("--meson-options needs a file")?,
                ));
            }
            "--report" => out.report = true,
            "--print-keyval" => out.print_keyval = true,
            "--allno" => out.mode = Some(resolve::ConfigMode::AllNo),
            "--allyes" => out.mode = Some(resolve::ConfigMode::AllYes),
            "--rand" => rand = true,
            "--seed" => {
                i += 1;
                seed = args
                    .get(i)
                    .ok_or("--seed needs a number")?
                    .parse()
                    .map_err(|_| "--seed needs a number".to_string())?;
            }
            define if define.starts_with("-D") => {
                let (key, value) = define[2..]
                    .split_once('=')
                    .ok_or_else(|| format!("{} needs the form -D<KEY>=<value>", define))?;
                out.defines.push((key.to_string(), value.to_string()));
            }
            other if !other.starts_with("--") => {
                if out.key.is_some() {
                    return Err(format!("unexpected extra operand: {}", other));
                }
                out.key = Some(other.to_string());
            }
            other => return Err(format!("unknown option: {}", other)),
        }
        i += 1;
    }
    if rand {
        out.mode = Some(resolve::ConfigMode::Rand(seed));
    }
    Ok(out)
}

/// Load the graph, run structural validation, and resolve against the
/// override file (missing file = defaults only) with the `-D` layer over it:
/// the same function the engine calls in process.
fn load_and_resolve(
    graph_dir: &PathBuf,
    config: Option<&PathBuf>,
    defines: &[(String, String)],
) -> Result<(graph::Graph, resolve::Resolved), Vec<Diagnostic>> {
    let g = mica::config::load_graph(graph_dir)?;
    let layers = [mica::config::Layer {
        source: "-D",
        pairs: defines,
    }];
    let resolved = mica::config::resolve_layers(&g, config.map(PathBuf::as_path), &layers)?;
    Ok((g, resolved))
}

fn cmd_resolve(args: &Args) -> i32 {
    let Some(graph_dir) = &args.graph else {
        say!("resolve: --graph is required");
        return 1;
    };
    let Some(out_dir) = &args.out else {
        say!("resolve: --out is required");
        return 1;
    };
    let (g, resolved) = match args.mode {
        Some(mode) => {
            let g = match graph::load(graph_dir) {
                Ok(g) => g,
                Err(d) => {
                    report(&d);
                    return 1;
                }
            };
            let errs = graph::validate(&g);
            if !errs.is_empty() {
                report(&errs);
                return 1;
            }
            match resolve::resolve_config_space(&g, mode) {
                Ok(r) => (g, r),
                Err(d) => {
                    report(&d);
                    return 1;
                }
            }
        }
        None => match load_and_resolve(graph_dir, args.config.as_ref(), &args.defines) {
            Ok(v) => v,
            Err(diags) => {
                report(&diags);
                return 1;
            }
        },
    };
    report(&resolved.warnings);
    let changed = match emit::emit_all(&g, &resolved, out_dir) {
        Ok(c) => c,
        Err(e) => {
            say!("error: cannot write {}: {}", out_dir.display(), e);
            return 1;
        }
    };
    if args.report {
        out!("{}", if changed { "CHANGED" } else { "UNCHANGED" });
    }
    if args.print_keyval {
        match std::fs::read_to_string(out_dir.join("config.keyval")) {
            Ok(kv) => crate::term::result_raw(kv.as_bytes()),
            Err(e) => {
                say!("error: cannot read back config.keyval: {}", e);
                return 1;
            }
        }
    }
    0
}

fn cmd_validate(args: &Args) -> i32 {
    let Some(graph_dir) = &args.graph else {
        say!("validate: --graph is required");
        return 1;
    };
    match load_and_resolve(graph_dir, args.config.as_ref(), &args.defines) {
        Ok((g, resolved)) => {
            report(&resolved.warnings);
            say!(
                "buildutil config: {} options, {} choices — ok",
                g.options.len(),
                g.choices.len()
            );
            0
        }
        Err(diags) => {
            report(&diags);
            1
        }
    }
}

fn value_str(v: &toml::Value) -> String {
    match v {
        toml::Value::Bool(true) => "y".to_string(),
        toml::Value::Bool(false) => "n".to_string(),
        toml::Value::Int(n) => n.to_string(),
        toml::Value::IntList(items) => format!("[{}]", resolve::join_ints(items)),
        toml::Value::Str(s) => format!("\"{}\"", s),
        other => format!("{:?}", other),
    }
}

fn cmd_explain(args: &Args) -> i32 {
    let Some(graph_dir) = &args.graph else {
        say!("explain: --graph is required");
        return 1;
    };
    let Some(key) = &args.key else {
        say!("explain: name a KEY to explain");
        return 1;
    };
    let (g, resolved) = match load_and_resolve(graph_dir, args.config.as_ref(), &args.defines) {
        Ok(v) => v,
        Err(diags) => {
            report(&diags);
            return 1;
        }
    };

    if let Some(def) = g.options.get(key) {
        out!("{} ({})", key, def.ty.name());
        if let Some(t) = &def.title {
            out!("  title    : {}", t);
        }
        if let Some(r) = resolved.values.get(key) {
            out!("  value    : {}", value_str(&r.value));
            out!("  origin   : {}", r.origin.as_str());
            out!("  visible  : {}", r.visible);
            if matches!(r.origin, resolve::Origin::Select) {
                let selectors: Vec<&str> = g
                    .options
                    .values()
                    .filter(|o| {
                        o.select.iter().any(|s| s == key)
                            && resolved
                                .values
                                .get(&o.name)
                                .is_some_and(|rv| matches!(rv.value, toml::Value::Bool(true)))
                    })
                    .map(|o| o.name.as_str())
                    .collect();
                if !selectors.is_empty() {
                    out!("  selected by: {}", selectors.join(", "));
                }
            }
        }
        if let Some(dep) = &def.depends_on {
            let mut atoms = Vec::new();
            dep.atoms(&mut atoms);
            let vals: Vec<String> = atoms
                .iter()
                .map(|a| {
                    let v = resolved
                        .values
                        .get(a)
                        .map(|r| value_str(&r.value))
                        .unwrap_or_else(|| "?".to_string());
                    format!("{}={}", a, v)
                })
                .collect();
            out!("  depends  : {} [{}]", dep.render(), vals.join(", "));
        }
        if def.min.is_some() || def.max.is_some() {
            out!(
                "  range    : [{}, {}]",
                def.min.map_or("-".to_string(), |m| m.to_string()),
                def.max.map_or("-".to_string(), |m| m.to_string())
            );
        }
        if !def.select.is_empty() {
            out!("  selects  : {}", def.select.join(", "));
        }
        if let Some(m) = &def.menu {
            out!("  menu     : {}", m);
        }
        if let Some(h) = &def.help {
            out!("  help     : {}", h);
        }
        0
    } else if let Some(choice) = g.choices.get(key) {
        out!("{} (choice)", key);
        if let Some(title) = &choice.title {
            out!("  title    : {}", title);
        }
        if let Some(cs) = resolved.choices.get(key) {
            out!("  active   : {}", cs.active.as_deref().unwrap_or("(none)"));
            out!("  visible  : {}", cs.visible);
        }
        out!("  default  : {}", choice.default_member);
        out!("  members  : {}", choice.members.join(", "));
        if let Some(h) = &choice.help {
            out!("  help     : {}", h);
        }
        0
    } else {
        say!("explain: no option or choice named `{}`", key);
        1
    }
}

fn cmd_docs(args: &Args) -> i32 {
    let Some(graph_dir) = &args.graph else {
        say!("docs: --graph is required");
        return 1;
    };
    let Some(out) = &args.out else {
        say!("docs: --out <file> is required");
        return 1;
    };
    let g = match graph::load(graph_dir) {
        Ok(g) => g,
        Err(diags) => {
            report(&diags);
            return 1;
        }
    };
    let errs = graph::validate(&g);
    if !errs.is_empty() {
        report(&errs);
        return 1;
    }
    let rst = render_docs(&g);
    if let Some(parent) = out.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Err(e) = std::fs::write(out, rst) {
        say!("error: cannot write {}: {}", out.display(), e);
        return 1;
    }
    say!("buildutil config docs: wrote {}", out.display());
    0
}

fn render_option_block(out: &mut String, def: &graph::OptionDef) {
    out.push_str(&format!(
        "{}\n{}\n\n",
        def.name,
        "~".repeat(def.name.len().max(3))
    ));
    if let Some(t) = &def.title {
        out.push_str(&format!(":Title: {}\n", t));
    }
    out.push_str(&format!(":Type: {}\n", def.ty.name()));
    if let Some(d) = &def.default {
        out.push_str(&format!(":Default: {}\n", d.render()));
    }
    if let Some(dep) = &def.depends_on {
        out.push_str(&format!(":Depends: {}\n", dep.render()));
    }
    if def.min.is_some() || def.max.is_some() {
        out.push_str(&format!(
            ":Range: [{}, {}]\n",
            def.min.map_or("-".to_string(), |m| m.to_string()),
            def.max.map_or("-".to_string(), |m| m.to_string())
        ));
    }
    if !def.select.is_empty() {
        out.push_str(&format!(":Selects: {}\n", def.select.join(", ")));
    }
    if let Some(c) = &def.rust_cfg {
        out.push_str(&format!(":Rust cfg: {}\n", c));
    }
    out.push('\n');
    if let Some(h) = &def.help {
        out.push_str(h);
        out.push_str("\n\n");
    }
}

/// Render the full option graph as an RST configuration reference, organized
/// by the menu tree (menus nest by parent), with an ungrouped tail.
fn render_docs(g: &graph::Graph) -> String {
    let mut out = String::new();
    out.push_str(".. SPDX-License-Identifier: GPL-2.0-only\n\n");
    out.push_str("SaltyOS Configuration Reference\n");
    out.push_str("===============================\n\n");
    out.push_str("Generated by ``buildutil config docs`` — do not edit by hand.\n\n");

    // Menu subtree, options grouped by membership in declaration order.
    fn walk(out: &mut String, g: &graph::Graph, menu: &graph::MenuDef, depth: usize) {
        let underline = match depth {
            0 => "-",
            1 => "~",
            _ => "^",
        };
        out.push_str(&format!(
            "{}\n{}\n\n",
            menu.title,
            underline.repeat(menu.title.len().max(3))
        ));
        for name in &g.decl_order {
            if let Some(def) = g.options.get(name) {
                if def.menu.as_deref() == Some(menu.name.as_str()) && def.parent_choice.is_none() {
                    render_option_block(out, def);
                }
            }
        }
        for child in g.menus.values() {
            if child.parent.as_deref() == Some(menu.name.as_str()) {
                walk(out, g, child, depth + 1);
            }
        }
    }

    for menu in g.menus.values() {
        if menu.parent.is_none() {
            walk(&mut out, g, menu, 0);
        }
    }

    // Ungrouped options (no menu).
    let ungrouped: Vec<&graph::OptionDef> = g
        .decl_order
        .iter()
        .filter_map(|n| g.options.get(n))
        .filter(|o| o.menu.is_none() && o.parent_choice.is_none())
        .collect();
    if !ungrouped.is_empty() {
        out.push_str("Ungrouped Options\n-----------------\n\n");
        for def in ungrouped {
            render_option_block(&mut out, def);
        }
    }

    // Choices.
    if !g.choices.is_empty() {
        out.push_str("Choices\n-------\n\n");
        for choice in g.choices.values() {
            let title = choice.title.clone().unwrap_or_else(|| choice.name.clone());
            out.push_str(&format!(
                "{}\n{}\n\n",
                title,
                "~".repeat(title.len().max(3))
            ));
            out.push_str(&format!(":Default: {}\n", choice.default_member));
            out.push_str(&format!(":Members: {}\n\n", choice.members.join(", ")));
            if let Some(h) = &choice.help {
                out.push_str(h);
                out.push_str("\n\n");
            }
        }
    }
    out
}

fn cmd_menuconfig(args: &Args) -> i32 {
    let Some(graph_dir) = &args.graph else {
        say!("menuconfig: --graph is required");
        return 1;
    };
    let g = match graph::load(graph_dir) {
        Ok(g) => g,
        Err(diags) => {
            report(&diags);
            return 1;
        }
    };
    let errs = graph::validate(&g);
    if !errs.is_empty() {
        report(&errs);
        return 1;
    }
    let config = args
        .config
        .clone()
        .unwrap_or_else(|| PathBuf::from("config"));
    match menuconfig::run(&g, &config) {
        Ok(code) => code,
        Err(e) => {
            say!("menuconfig: {}", e);
            1
        }
    }
}

fn cmd_migrate(args: &Args) -> i32 {
    let Some(meson_options) = &args.meson_options else {
        say!("migrate-options: --meson-options is required");
        return 1;
    };
    let Some(out_dir) = &args.out else {
        say!("migrate-options: --out is required");
        return 1;
    };
    match migrate::migrate(meson_options, out_dir) {
        Ok(count) => {
            say!(
                "buildutil config: seeded {} options into {}",
                count,
                out_dir.join("seed.toml").display()
            );
            0
        }
        Err(diags) => {
            report(&diags);
            1
        }
    }
}

/// Execute a configuration verb without exiting the engine process.
pub fn run(argv: &[String]) -> Result<i32, String> {
    if argv.is_empty() {
        usage();
        return Ok(1);
    }
    let args = match parse_args(&argv[1..]) {
        Ok(a) => a,
        Err(msg) => {
            say!("error: {}", msg);
            usage();
            return Ok(1);
        }
    };
    let code = match argv[0].as_str() {
        "resolve" => cmd_resolve(&args),
        "validate" => cmd_validate(&args),
        "explain" => cmd_explain(&args),
        "docs" => cmd_docs(&args),
        "menuconfig" => cmd_menuconfig(&args),
        "migrate-options" => cmd_migrate(&args),
        "help" | "--help" | "-h" => {
            usage();
            0
        }
        other => {
            say!("error: unknown command `{}`", other);
            usage();
            1
        }
    };
    Ok(code)
}
