// SPDX-License-Identifier: GPL-2.0-only
//! buildutil — help and usage printing.

pub fn usage() {
    say!("Usage: buildutil <command> [options]");
    say!("");
    say!("Commands:");
    say!("  build [<package>...] Realize [packages] names or groups (default: `default`)");
    say!("  lock                 Verify current clean inputs and atomically write buildutil.lock");
    say!("  dev <target> [--watch]   Incremental dev build (deps via store,");
    say!("                       tip against live sources in .buildutil/dev/)");
    say!("  eval <target>...     Print the closure's derivation hashes");
    say!("  plan <target>...     Emit an evaluated action plan");
    say!("  daemon <status|stop|restart|verify>  Manage the persistent eval daemon");
    say!("  why-depends <t> <dep> [--runtime]   Shortest dependency path");
    say!("  graph [<target>]     DOT export of the (sub)graph");
    say!("  explain <target>     Why the target would rebuild (preimage diff)");
    say!("  log <target>         Print the last build log of the target");
    say!("  image dump-cpio|dump-gpt|dump-bios|dump-fat|dump-saltyfs <file>");
    say!("                       Canonical logical-structure dump of an image");
    say!(
        "                       dump-cpio takes the --align declaration the archive was written with"
    );
    say!("  image ...            Assemble a bootable disk image (see image --help)");
    say!("  cpio ...             Build a CPIO newc archive");
    say!("  saltyfs build|verify|dump   Build, verify or dump a SaltyFS image");
    say!("  rootfs ...           Assemble a SaltyFS root image from manifests");
    say!("  mkrootfs [--with-ports]   Copy the declared rootfs image to run/disk/<arch>/");
    say!("  sysroot ...          Assemble the cross sysroot from a build dir");
    say!("  setup [--arch <a>]   Seed and resolve the architecture's configuration");
    say!("  run <app> [<package>...] [--dev] [-- <args>]   Prepare an app's inputs, run it");
    say!("  run [qemu flags] [--dev]   Launch the realized boot image through [launch]");
    say!("  test [--smp N] [qemu flags]   CI gate: boot the test image, scan serial");
    say!("  config [--arch <a>]  The configuration editor over the option graph");
    say!("  config resolve|validate|explain|docs|menuconfig|migrate-options [options]");
    say!("  gdb                  Attach GDB to a running QEMU");
    say!("  fmt [--check]        Run the declared formatter; --check reports its edits");
    say!("  check [<check>...]   Realize [checks] names or groups; bare: `default` + license");
    say!("  check license|conformance|plan-parity|daemon-parity|daemon-races");
    say!("                       Built-in checks, run by name");
    say!("  check conformance [--bless]           Run (or re-pin) the corpus");
    say!(
        "  check license [--fix] [--root <dir>]   Check or repair SPDX headers and LICENSES texts"
    );
    say!("  tc setup             Create resolved toolchain state directories");
    say!("  tc plan              Build host, backend and state locations report");
    say!("  bootstrap [--from=N] Run the declared [[bootstrap.step]] list");
    say!("  remote ls|build <t> [--builder <url>]   SSH push-build-pull");
    say!("  store ls|verify|gc   Store maintenance");
    say!("  store add-root <root-name> <store-dir>");
    say!("  store add-indirect-root <link>   Hold what a run-state link names");
    say!("  store sign <store-dir> <key-file>");
    say!("  store resign <key-file>   Sign every signed record under the current domain");
    say!("  keygen <out-file>    Generate an Ed25519 signing key pair");
    say!("  gen [--selfcheck]    Write (or verify) tools/buildutil/bootstrap.ninja");
    say!("");
    say!("Options:");
    say!("  --locked             Reject missing or differing content pins before building");
    say!("  --override-input <name> path:<checkout>   Select a checkout for this invocation");
    say!("  --arch <a>           Target architecture (default: x86_64)");
    say!("  --build-host <h>     Toolchain build host (auto, x86_64-unknown-linux-musl,");
    say!("                       aarch64-unknown-linux-musl; default: auto)");
    say!("  --backend <b>        Toolchain execution backend (auto, local-linux, docker,");
    say!("                       nerdctl, wsl, remote; default: auto)");
    say!("                       docker/nerdctl run the executor image built from the");
    say!("                       pinned seed and stage-0 Rust, unprivileged, with the");
    say!("                       .buildutil state volume as their only mount");
    say!("  --store <dir>        Buildutil state root (default: <repo>/.buildutil or");
    say!("                       BUILDUTIL_STORE;");
    say!("                       store entries live in <dir>/store)");
    say!("  --no-source-cache    Disable source stat-cache and whole-eval cache hits");
    say!("  --no-daemon          Run engine commands in a child process, not the daemon");
    say!("  --jobs <n>           Worker pool size (default: available parallelism)");
    say!("  --domain <group>     Restrict eval/plan/why-depends/graph and `store gc");
    say!("                       --world` to the closure of a [packages] group");
    say!("  drv:<name>           Address any derivation, exposed or not");
    say!("  <name>[KEY=value,…]  The derivation under these configuration overrides;");
    say!("                       `<name>@<hash>` names a node of the current evaluation");
    say!("  -D<KEY>=<value>      Configuration override over the persistent file");
    say!("  --audit=<warn|error> Depfile read-audit posture (default: warn)");
    say!("  --keep-failed, -K    Keep failed .buildutil/tmp/*.build dirs for debugging");
    say!("  --events <file>      Write JSONL build events");
    say!("  --trace <file>       Write a Chrome trace of the build");
    say!("  --build-output=<all|failed|none>");
    say!("                       Builder output shown (default: all; failed shows the");
    say!("                       last lines of a failed derivation)");
    say!("  -q                   Same as --build-output=failed");
    say!("  -v                   Show every builder line, all configuration options,");
    say!("                       and evaluation timings");
}

pub fn is_help_arg(arg: &str) -> bool {
    arg == "--help" || arg == "-h" || arg == "help"
}

pub fn command_usage(command: &str) -> bool {
    match command {
        "build" => {
            say!("Usage: buildutil build [<package>...] [options]");
            say!("Realizes [packages] names and groups into .buildutil/store/; with no package,");
            say!("the `default` group. `drv:<name>` addresses any other derivation.");
            say!(
                "--locked compares every selected input with buildutil.lock, including overrides."
            );
            say!("Target architecture (--arch) is separate from Linux toolchain build host");
            say!("(--build-host) and execution backend (--backend). On macOS use docker or");
            say!("nerdctl; on Windows use WSL or Docker; Linux normally uses local-linux.");
            say!("The build screen shows the evaluation phases, the build environment, and one");
            say!("line per realized, cached, or failed derivation. The bottom row shows the");
            say!("newest ninja or cargo step; other builder lines appear as the tool wrote them");
            say!("(--build-output). Full logs stay in .buildutil/logs/.");
            say!(
                "Failed build directories under .buildutil/tmp/ are deleted by default; pass --keep-failed (-K) to retain and print the path."
            );
            say!("Examples:");
            say!("  ./buildutil build");
            say!("  ./buildutil build <package> --arch aarch64");
            say!(
                "  ./buildutil build <group> --build-host x86_64-unknown-linux-musl --backend docker"
            );
        }
        "dev" => {
            say!("Usage: buildutil dev <target> [--watch] [options]");
            say!(
                "Builds target deps through the store, then builds the target against live sources under .buildutil/dev/<backend>/<arch>/<target>/."
            );
        }
        "lock" => {
            say!("Usage: buildutil lock [--override-input <name> path:<checkout>] [options]");
            say!("Records clean checkout revisions and verified archive/tree pins; absent");
            say!(
                "inputs retain verified locked resolutions. A dirty input leaves the old lock intact."
            );
        }
        "eval" => {
            say!("Usage: buildutil eval <target>... [--domain <group>]");
            say!("Prints derivation identities for the requested closure without realizing it.");
            say!("`--domain` keeps only targets inside a [packages] group's closure.");
        }
        "plan" => {
            say!("Usage: buildutil plan <target>... [--domain <group>]");
            say!("Evaluates targets, ingests declared sources, emits a content-addressed plan,");
            say!("and prints `<planhash32> <path>`.");
            say!("`--domain` plans only targets inside a [packages] group's closure.");
        }
        "daemon" => {
            say!("Usage: buildutil daemon <status|stop [--force]|restart|verify> [targets...]");
            say!("`stop` finishes the active request and rejects queued requests.");
            say!("`stop --force` cancels the active request immediately.");
            say!("`verify` compares one cache-bypassed evaluation with the resident path.");
        }
        "why-depends" => {
            say!(
                "Usage: buildutil why-depends <target> <dependency> [--runtime] [--domain <group>]"
            );
            say!("Prints the shortest dependency path in the derivation graph.");
            say!("`--domain` confines the search to a [packages] group's closure.");
        }
        "graph" => {
            say!("Usage: buildutil graph [target] [--domain <group>]");
            say!("Emits DOT for the full graph or a target subgraph.");
            say!("`--domain` renders only a [packages] group's closure.");
        }
        "explain" => {
            say!("Usage: buildutil explain <target>");
            say!("Shows why the target would rebuild by diffing derivation preimages.");
        }
        "log" => {
            say!("Usage: buildutil log <target>");
            say!("Prints the retained build log for the latest realization of a target and");
            say!("names its retained-artifact directory when the builder kept one.");
        }
        "setup" => {
            say!("Usage: buildutil setup [--arch <x86_64|aarch64>]");
            say!("Seeds .buildutil/config/<arch>/config (with the architecture, under the");
            say!("option [configuration] arch-option names) and resolves the configuration.");
        }
        "run" => {
            say!("Usage: buildutil run <app> [<package>...] [--dev] [-- <arguments>]");
            say!("Prepares the named packages, or the app's declared inputs, through the");
            say!("engine (the dev path with --dev), holds them, then runs the app with only");
            say!("the arguments after `--`. Build options apply to the preparation.");
            say!(
                "Usage: buildutil run [--arch <a>] [--smp N] [--mem SIZE] [--uefi] [--headless] [--gdb] [--debug] [--dev]"
            );
            say!("Launches the realized boot image through the [launch] command.");
        }
        "mkrootfs" => {
            say!("Usage: buildutil mkrootfs [--with-ports] [options]");
            say!(
                "Copies the declared rootfs writer's realized image into .buildutil/run/disk/<arch>/."
            );
            say!("--with-ports first builds the writer with declared package projections.");
        }
        "test" => {
            say!("Usage: buildutil test [--arch <a>] [--smp N] [qemu passthrough flags...]");
            say!("Boots the realized test image variant headless and reduces");
            say!("the serial stream to an exit code. Default passes: --smp 4 then --smp 1.");
            say!("Exit: 0 pass · 1 test failure · 2 KERNEL PANIC · 3 timeout · 4 infra.");
        }
        "config" => {
            say!("Usage: buildutil config [--arch <x86_64|aarch64>]");
            say!("Opens the configuration editor on .buildutil/config/<arch>/config.");
            crate::config::usage();
        }
        "fmt" => {
            say!("Usage: buildutil fmt [--check]");
            say!("Runs the [formatter] module over its declared source sets on the build host");
            say!("and writes the files it returns; --check reports them as problems instead.");
        }
        "check" => {
            say!("Usage: buildutil check [<check>...] [options]");
            say!("Realizes [checks] names and groups; a check passes when it builds. With no");
            say!("check, runs the [checks] group `default` and the `license` check.");
            say!(
                "Built-in checks: license, conformance, plan-parity, daemon-parity, daemon-races;"
            );
            say!("each runs by itself, and its own options may stand anywhere. A bare check");
            say!("applies `--fix` and `--root <dir>` to its `license` check.");
            say!("--rerun realizes the named checks again: no local reuse, no substitution, and");
            say!("no result taken from a concurrent build of the same check.");
            say!(
                "`license [--fix] [--root <dir>]` checks or repairs SPDX headers and LICENSES texts using root buildutil.toml."
            );
            say!(
                "`daemon-parity` compares daemon and --no-daemon plans across a source edit matrix."
            );
            say!("`daemon-races` adds a resident-versus-fresh snapshot verification.");
        }
        "tc" => {
            say!("Usage: buildutil tc setup [options]");
            say!("Creates toolchain state directories without building or fetching.");
            say!("Usage: buildutil tc plan [options]");
            say!("Reports the target arch, Linux build host, backend and state directories.");
        }
        "bootstrap" => {
            say!("Usage: buildutil bootstrap [--from=N] [--build-host <h>] [--backend <b>]");
            say!("Runs the root buildutil.toml's [[bootstrap.step]] list in order, from step N:");
            say!("each step resolves its architecture's configuration and builds its targets.");
        }
        "store" => {
            say!(
                "Usage: buildutil store ls|verify [--repair]|gc [--dry-run] [--max-age N] [--min-free N] [--prune-roots-older-than DAYS] [--world [PACKAGE...]] [--domain <group>]|optimise|export --out <dir>|add-root <name> <store-dir>|add-indirect-root <link>|sign <store-dir> <key-file>|resign <key-file>"
            );
            say!(
                "Maintains .buildutil/store/, realization records, stale .buildutil/tmp/*.build directories, and active-build temp roots."
            );
        }
        "gen" => {
            say!("Usage: buildutil gen [--selfcheck]");
            say!("Writes or verifies tools/buildutil/bootstrap.ninja.");
        }
        _ => return false,
    }
    say!("");
    say!(
        "Common options: --arch <a>, --build-host <h>, --backend <b>, --store <dir>, --no-source-cache, --no-daemon, --jobs <n>, --keep-failed, --events <file>, --trace <file>, --timings, --build-output=<mode>, -q, -v"
    );
    true
}
