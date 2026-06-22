# Native Providers

Hokori combines filesystem rules with state-aware providers. Filesystem rules
answer “what is stored here?” Providers answer “does the owning tool still
reference this object?”

## Scan Modes

| Mode | Budget | Behavior |
| --- | ---: | --- |
| Quick | 20 seconds | Local metadata and local daemon queries only |
| Deep | 90 seconds | Adds duplicate hashing, app leftovers, Git maintenance, remote-verified Git LFS checks, and orphan diagnostics |
| Action/revalidation | 180 seconds | Rechecks ownership immediately before executing a selected action |

Provider workers are capped at three. Command output is capped at 1 MiB stdout,
256 KiB stderr, and 64 KiB per retained line. A timed-out or cancelled child
process group is killed and reaped.

## Provider Matrix

| Provider | Default | Native actions | Network |
| --- | --- | --- | --- |
| Homebrew | Quick | Exact cache paths, targeted formula cleanup/uninstall | Never |
| Docker | Quick | Image, container, volume, network, and age-filtered BuildKit cleanup | Local active context only |
| Xcode Simulators | Quick | `simctl` device/runtime/dyld actions, Trash-first Xcode storage, SwiftPM purge | Never |
| Git repositories | Quick | Worktree removal/pruning, Git LFS prune, normal maintenance | Deep LFS verification may contact the configured remote |
| Toolchains | Quick | mise, rustup, pyenv, rbenv, asdf, and FVM native removal | Never |
| AI assets | Quick | Hugging Face and Ollama native removal | Never during scanning |
| Android | Quick | `avdmanager` and `sdkmanager` removal when installed | Never |
| Virtual machines | Quick | Lima, OrbStack, Colima, and Multipass native deletion | Never |
| Native package GC | Quick | Conda, Nix, and MacPorts garbage collection | Never |
| App leftovers | Deep | Exact bundle-ID paths, moved to Trash by default | Never |
| Exact duplicates | Deep | User chooses one retained copy; other verified copies go to Trash | Never |

Unavailable tools remain visible in the provider-status modal and do not create
findings. Providers never start Docker Desktop, a VM, an emulator, or another
application merely to inspect it.

## Size Semantics

- **Logical**: nominal content or configured capacity.
- **Physical**: allocated host filesystem bytes where available.
- **Unique**: bytes attributable only to the selected object.
- **Shared**: bytes also referenced by another object.
- **Reclaimable**: the bytes Hokori expects the selected action to release.
- **Exact/estimated**: whether reclaimable bytes come from authoritative object
  metadata or a conservative estimate.

Sparse VM capacity is never presented as reclaimable host space. Docker images
use unique layer size. Hugging Face and Ollama account for retained/shared
blobs. Duplicate-file savings are estimated on APFS because clone-shared extents
can make physical savings lower than allocated-byte totals.

## Safety

- Safe findings may enter safe bulk selection.
- Review and risky findings remain individually selectable.
- Recent and manual-only findings never enter bulk selection.
- Protected and report-only findings cannot execute.
- Native actions and high-impact objects require Shift+Y in the TUI.
- Filesystem cleanup moves data to Trash unless permanent mode is armed.
- Every provider object is revalidated immediately before execution.
- Journal entries record provider, object, action, evidence, estimated bytes,
  actual reported freed bytes, and outcome. Sensitive evidence labels are
  redacted.

Homebrew autoremove is treated as a secondary signal. Hokori builds a complete
receipt graph, including unavailable or migrated taps, and refuses candidates
that remain reachable. Docker named volumes, VM disks, installed models,
archives, runtimes, and app leftovers are always manual.

## TUI Controls

- `m`: switch quick/deep mode and rescan.
- `[` / `]`: lower/raise the provider age threshold.
- `z`: cycle provider minimum size.
- `v`: cycle provider filters.
- `e`: filter exact versus estimated sizes.
- `u`: show/hide recent findings.
- `o`: inspect provider availability, cost, elapsed time, findings, and errors.

## Verification

Focused Rust tests cover destructive parser contracts, command bounds/timeouts,
selection safety, scan cancellation, and provider-specific dependency
regressions.
