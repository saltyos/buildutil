# buildutil

The SaltyOS build tool: a Nix-style derivation engine (`main.rs` and the
modules beside it), the composition library (`compose/`), the module SDK
(`sdk/`), the conformance corpora (`conformance/`) and the configuration
language library `mica` as the submodule `lib/mica`.

A consumer repository checks this repository out as `tools/buildutil` and
bootstraps it with `ninja -f tools/buildutil/bootstrap.ninja` through its
`./buildutil` wrapper; paths inside this repository are relative to that
consumer root.
