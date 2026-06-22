## Safety model

- Scans are non-destructive.
- Filesystem cleanup moves items to the Trash by default.
- Review and risky findings require individual selection.
- Native tool actions are revalidated immediately before execution.
- High-impact and irreversible actions require stronger confirmation.
- Protected and report-only findings cannot execute.
- Command execution uses static allowlists, bounded output, and timeouts.


## Privacy

hokori has no telemetry or automatic update checks. Normal scans use local
filesystem and tool metadata. Deep Git LFS verification may contact the remote
already configured for that repository.

Hokori records cleanup attempts in
`~/.local/state/hokori/journal.jsonl`. The state directory and journal are
created with private user-only permissions.

User configuration is loaded from `~/.config/hokori/config.toml`.