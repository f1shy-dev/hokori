# Scan Architecture (Prototype)

## Goals
- Fast traversal with low memory use.
- Classify candidates by rule families (cache/log/temp/build/etc).
- Avoid destructive matches by default; deep-clean requires explicit opt-in.
- Optional git-ignore cleanup that skips sensitive dotfiles.

## Pipeline
1. **Load rules** from `rules/rulesets.toml` (e.g., `macos` ruleset with includes).
2. **Compile globsets** per rule (case-insensitive on macOS/Windows).
3. **Walk roots in parallel** using `ignore::WalkBuilder`:
   - Do not honor gitignore or hidden filters (we need full visibility).
   - Skip `.git` dirs to avoid expensive, non-junk data.
4. **Match each entry** against compiled rules and record:
   - File count + size (bytes) per rule.
   - Directory match counts (size aggregated from files, not dirs).
   - Limited sample paths for quick inspection.

## Git-ignored cleanup (inline)
- Detect repo roots during traversal by locating `.git` (dir or file).
- Parse gitignore rules on the fly while scanning:
  - `.gitignore` files per directory
  - `.git/info/exclude`
  - global excludes from user config
- Apply a hard-coded protect list (`.env*`, `.npmrc`, `.ssh`, `.aws`, etc) and optional user-supplied protect patterns.
- Two modes:
  - `size` (default): traverse ignored dirs to size accurately
  - `prune`: skip ignored dirs (faster, undercounts when whitelists exist)

## Safety model
- Rules are tagged with `cleanable`, `caution`, `deep_clean`, or `protect`.
- `protect` outranks everything else, but is scoped to *roots only* for containers/app support.
- “User data” stores (IndexedDB/LocalStorage/etc) are marked `deep_clean` and should require explicit user confirmation.

## Next performance steps
- Add Windows file-id dedupe (requires per-file handle) if hardlink accuracy matters there.
- Optional size-cache for repeated scans and UI responsiveness.

## Platform backends (fast path only)
- macOS: `getattrlistbulk` + inode dedupe (fileid) with parallel descent.
- Linux: `getdents64` + `statx` (fallback `fstatat`) with `(dev, ino)` dedupe.
- Windows: `FindFirstFileExW` (large fetch) + `WIN32_FIND_DATAW` traversal; optional hardlink dedupe via `--windows-dedupe-hardlinks`.
