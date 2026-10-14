# Vendored: ironcalc 0.8.3

The `ironcalc` crate (MIT OR Apache-2.0, https://github.com/ironcalc/ironcalc),
copied from crates.io 0.8.3 (`src/`, `examples/` (lib.rs includes them as docs), `build.rs`, `Cargo.toml`, `README.md`;
not its test workbooks, which `build.rs` skips when absent).

One change, in `Cargo.toml`: `zip` with `default-features = false,
features = ["deflate"]`. Its default features pull in bzip2 and zstd, which
are C and do not build for wasm32-unknown-unknown; .xlsx files only use
deflate. `../../Cargo.toml` puts this copy in place with `[patch.crates-io]`.

To bump: copy the new release over this one, redo the change, and keep the
version the same as cce-spreadsheet's and cce-sync's `ironcalc`.
