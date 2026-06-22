# 🧺 hokori

Hokori means dust in Japanese. It is a cautious, TUI-first macOS disk cleaner
that combines known filesystem rules with state-aware checks for tools such as
Homebrew, Docker, Xcode, Git, language toolchains, and virtual machines.

The interactive TUI is the primary experience. Running `hokori` in a terminal
opens it directly; the batch commands are available for inspection and
automation.

## Run

Hokori currently targets macOS and requires a recent stable Rust toolchain.

```bash
cargo run --release
```

To inspect commands and scan options:

```bash
cargo run --release -- --help
```

## Safety model

- Scans are non-destructive.
- Filesystem cleanup moves items to the Trash by default.
- Review and risky findings require individual selection.
- Native tool actions are revalidated immediately before execution.
- High-impact and irreversible actions require stronger confirmation.
- Protected and report-only findings cannot execute.
- Command execution uses static allowlists, bounded output, and timeouts.

Hokori records cleanup attempts in
`~/.local/state/hokori/journal.jsonl`. The state directory and journal are
created with private user-only permissions.

User configuration is loaded from `~/.config/hokori/config.toml`.

## Privacy

Hokori has no telemetry or automatic update checks. Normal scans use local
filesystem and tool metadata. Deep Git LFS verification may contact the remote
already configured for that repository.

## Development

```bash
cargo fmt --check
cargo test
cargo clippy --all-targets -- -D warnings
```

The scan and provider architecture is documented in
[`docs/scan_design.md`](docs/scan_design.md) and
[`docs/providers.md`](docs/providers.md).
