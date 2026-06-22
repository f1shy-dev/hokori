# Scan Architecture

## Product Model

The TUI is the primary interface. Findings are grouped into Quick Cleanup,
Developer, Applications, System, and Analysis. Developer findings are further
grouped into Packages, Containers & VMs, Apple & Mobile, Repositories,
Toolchains, AI Assets, IDEs, and Project Artifacts.

A finding has a typed target:

- one filesystem path;
- a bounded group of filesystem paths;
- a native provider object;
- a report-only diagnostic.

It also carries stable identity, owner, reason, evidence, confidence, state,
logical/physical/unique/shared/reclaimable size, size accuracy, safety, and an
optional typed native action.

## Filesystem Pipeline

1. Load and compile embedded or user-supplied rules.
2. Expand targeted known locations and size only those paths.
3. Walk requested roots once for project artifacts, exact files, suffixes,
   residual globs, Git repositories, Git-ignored directories, and CACHEDIR.TAG.
4. Deduplicate hard links with a bounded sharded inode set.
5. Stream findings through a bounded queue. Batch mode retains findings; TUI
   mode transfers ownership to the queue without a duplicate scanner copy.

The macOS walker uses `getattrlistbulk`; portable platforms use bounded
`std::fs` traversal. Nested mounts, cloud-storage roots, `.git`, Trash, and
other unsuitable domains are skipped.

## Provider Pipeline

1. Build the repository set discovered by the filesystem pass.
2. Select providers for the quick/deep profile and optional provider filter.
3. Run at most three providers concurrently under a shared deadline.
4. Probe without starting applications or daemons.
5. Execute only statically declared read-only commands through the bounded
   command runner.
6. Normalize output immediately into findings and discard raw output.
7. Supersede overlapping static rules when an authoritative provider finishes.
8. Stream provider state and findings into the TUI.

Provider actions are not arbitrary command strings. The provider dispatches a
typed action ID, validates every dynamic argument, rechecks current references,
and then calls an allowlisted native command or a strictly rooted Trash action.

## Memory Bounds

- TUI event queue: 1,024 events.
- Retained aggregate member paths: 50,000 maximum.
- Provider workers: three.
- Parsed provider objects: bounded per provider.
- Child stdout/stderr and line lengths: bounded.
- Old scan state is dropped on rescan rather than appended.
- Provider-only cleanup refreshes only affected providers.
- Cancellation kills and reaps process groups.

Regression coverage focuses on bounded queues and retained collections,
repeated scan-state replacement, subprocess output limits, cancellation, and
child-process reaping.

## Deletion

Filesystem paths pass through one validation funnel and move to Trash by
default. Native provider findings are revalidated and dispatched to the owning
provider. Duplicate groups require choosing a retained copy. Native and
high-impact actions require stronger TUI confirmation. Every attempt is written
to the JSONL journal with redacted evidence and actual reported freed bytes.
