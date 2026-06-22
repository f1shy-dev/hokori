# 🧺 hokori
<sub>ほこり · dust</sub>

A fast TUI disk cleaner for macOS, made in rust.

```bash
cargo install hokori
```

## Development

```bash
cargo fmt --check
cargo test
cargo clippy --all-targets -- -D warnings
cargo run --release
cargo run --release -- --help
```

The scan and provider architecture is documented in
[`docs/scan_design.md`](docs/scan_design.md),
[`docs/privacy_and_safety.md`](docs/privacy_and_safety.md), and
[`docs/providers.md`](docs/providers.md).

Crates.io release setup is documented in
[`docs/publishing.md`](docs/publishing.md).
