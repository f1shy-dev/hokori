//! The two scan engines.
//!
//! Targeted: expand each rule's anchored roots and size them directly — never
//! walks anything that isn't already known dirt.
//!
//! Discovery: one walk over user space; directories are matched by basename
//! hash lookup and, on a hit, the subtree is *claimed* (sized in pure mode,
//! never matched inside). Gitignored dirs and CACHEDIR.TAG dirs are claimed by
//! built-in detectors. Files hit exact-name/suffix tables and one residual
//! globset.

use rayon::prelude::*;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use crate::compiler::{CompiledRule, Engine};
use crate::gitignore::GitIgnoreStack;
use crate::report::{Finding, Progress};
use crate::rules::Safety;
use crate::walk::{self, Entry, InodeDedupe, SubtreeStats};

/// Streaming events for the TUI. `None` sink = batch (CLI) mode.
pub enum ScanEvent {
    Found(Finding),
    Phase(&'static str),
    Done,
}

pub type Sink<'a> = Option<&'a Mutex<std::sync::mpsc::SyncSender<ScanEvent>>>;

pub struct ScanCtx<'a> {
    pub engine: &'a Engine,
    pub dedupe: &'a InodeDedupe,
    pub progress: Option<&'a Progress>,
    pub now: i64,
    pub sink: Sink<'a>,
    pub cancel: Option<&'a AtomicBool>,
}

impl ScanCtx<'_> {
    fn is_cancelled(&self) -> bool {
        self.cancel
            .map(|cancel| cancel.load(Ordering::Relaxed))
            .unwrap_or(false)
    }

    /// Batch mode keeps the finding; streaming mode transfers ownership to
    /// the bounded UI queue so the scanner never retains a duplicate copy.
    fn deliver(&self, finding: Finding) -> Option<Finding> {
        let Some(sink) = self.sink else {
            return Some(finding);
        };
        let delivered = sink
            .lock()
            .map(|tx| tx.send(ScanEvent::Found(finding)).is_ok())
            .unwrap_or(false);
        if !delivered && let Some(cancel) = self.cancel {
            cancel.store(true, Ordering::Relaxed);
        }
        None
    }
}

fn age_days(now: i64, mtime: i64) -> Option<u64> {
    if mtime <= 0 {
        return None;
    }
    Some(((now - mtime).max(0) / 86_400) as u64)
}

fn make_finding(
    rule: &CompiledRule,
    path: PathBuf,
    stats: SubtreeStats,
    effective_mtime: i64,
    now: i64,
) -> Finding {
    let recent =
        rule.min_age_secs > 0 && effective_mtime > 0 && (now - effective_mtime) < rule.min_age_secs;
    Finding {
        rule_id: rule.def.id.clone(),
        category: rule.def.category.clone(),
        safety: rule.def.safety,
        path,
        bytes: stats.bytes,
        files: stats.files,
        dirs: stats.dirs,
        age_days: age_days(now, effective_mtime),
        recent,
        report_only: rule.def.report_only,
        manual_only: false,
        impact: rule.def.impact.clone(),
        clean_via: rule.def.clean_via.clone(),
        member_paths: Vec::new(),
    }
}

// ---------------- targeted ----------------

/// Expand a root pattern: literal components are joined, glob components are
/// expanded by listing that level. Returns existing paths only.
fn expand_root(pattern: &str) -> Vec<PathBuf> {
    let mut current: Vec<PathBuf> = vec![PathBuf::from("/")];
    for component in Path::new(pattern).components() {
        let std::path::Component::Normal(part) = component else {
            continue;
        };
        let part_str = part.to_string_lossy();
        let is_glob = part_str.contains(['*', '?', '[']);
        let mut next = Vec::new();
        if !is_glob {
            for base in &current {
                let candidate = base.join(part);
                if candidate.symlink_metadata().is_ok() {
                    next.push(candidate);
                }
            }
        } else {
            let Ok(glob) = globset::GlobBuilder::new(&part_str)
                .case_insensitive(true)
                .build()
            else {
                continue;
            };
            let matcher = glob.compile_matcher();
            for base in &current {
                if let Some(entries) = walk::list_dir(base) {
                    for entry in entries {
                        if matcher.is_match(&entry.name) {
                            next.push(base.join(&entry.name));
                        }
                    }
                }
            }
        }
        current = next;
        if current.is_empty() {
            break;
        }
        if current.len() > 50_000 {
            break; // runaway glob; refuse to expand further
        }
    }
    current
}

pub struct TargetedResult {
    pub findings: Vec<Finding>,
    /// Every expanded root, so discovery can prune them (already counted).
    pub claimed: HashSet<PathBuf>,
}

pub fn targeted_scan(ctx: &ScanCtx) -> TargetedResult {
    // Expand all roots first; on duplicate paths the rule with the longer
    // (more specific) pattern wins.
    let mut owner: HashMap<PathBuf, (usize, usize)> = HashMap::new();
    for (rule_idx, pattern) in &ctx.engine.targeted {
        if ctx.is_cancelled() {
            break;
        }
        for path in expand_root(pattern) {
            if ctx.is_cancelled() {
                break;
            }
            let path_str = path.to_string_lossy();
            if ctx.engine.is_protected(&path_str) {
                continue;
            }
            let specificity = pattern.len();
            match owner.get(&path) {
                Some((_, existing)) if *existing >= specificity => {}
                _ => {
                    owner.insert(path, (*rule_idx, specificity));
                }
            }
        }
    }

    let claimed: HashSet<PathBuf> = owner.keys().cloned().collect();
    let claimed_ref = &claimed;

    let findings: Vec<Finding> = owner
        .into_iter()
        .collect::<Vec<_>>()
        .into_par_iter()
        .filter_map(|(path, (rule_idx, _))| {
            if ctx.is_cancelled() {
                return None;
            }
            let rule = &ctx.engine.rules[rule_idx];
            let meta = path.symlink_metadata().ok()?;
            if meta.file_type().is_symlink() {
                return None;
            }
            let (stats, mtime) = if meta.is_dir() {
                // Prune nested targeted roots: they get their own finding.
                let stats = size_pruned(&path, ctx, claimed_ref);
                (stats, stats.newest_mtime)
            } else {
                let mtime = meta
                    .modified()
                    .ok()
                    .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                    .map(|d| d.as_secs() as i64)
                    .unwrap_or(0);
                #[cfg(unix)]
                let bytes = {
                    use std::os::unix::fs::MetadataExt;
                    meta.blocks() * 512
                };
                #[cfg(not(unix))]
                let bytes = meta.len();
                (
                    SubtreeStats {
                        bytes,
                        files: 1,
                        dirs: 0,
                        newest_mtime: mtime,
                    },
                    mtime,
                )
            };
            if stats.bytes < rule.min_size_bytes {
                return None;
            }
            let finding = make_finding(rule, path, stats, mtime, ctx.now);
            ctx.deliver(finding)
        })
        .collect();

    TargetedResult { findings, claimed }
}

/// Pure sizing that skips any directory in `prune` (other rules' roots).
fn size_pruned(path: &Path, ctx: &ScanCtx, prune: &HashSet<PathBuf>) -> SubtreeStats {
    if ctx.is_cancelled() {
        return SubtreeStats::default();
    }
    let Some(entries) = walk::list_dir(path) else {
        return SubtreeStats::default();
    };
    let mut stats = SubtreeStats::default();
    let mut subdirs: Vec<PathBuf> = Vec::new();
    for entry in &entries {
        if ctx.is_cancelled() {
            return stats;
        }
        stats.newest_mtime = stats.newest_mtime.max(entry.mtime);
        if entry.is_dir {
            let child = path.join(&entry.name);
            if prune.contains(&child) {
                continue;
            }
            stats.dirs += 1;
            subdirs.push(child);
        } else {
            stats.files += 1;
            stats.bytes += ctx.dedupe.dedup(entry.dev, entry.ino, entry.bytes);
        }
    }
    if let Some(progress) = ctx.progress {
        progress.add(stats.files, stats.dirs, stats.bytes);
    }
    let child_stats = subdirs
        .par_iter()
        .map(|child| size_pruned(child, ctx, prune))
        .reduce(SubtreeStats::default, SubtreeStats::merge);
    stats.merge(child_stats)
}

// ---------------- discovery ----------------

struct FileRuleAcc {
    bytes: AtomicU64,
    count: AtomicU64,
    truncated: AtomicBool,
    paths: Mutex<Vec<PathBuf>>,
}

const MAX_MEMBER_PATHS: usize = 50_000;

struct DiscoveryState<'a> {
    ctx: &'a ScanCtx<'a>,
    findings: Mutex<Vec<Finding>>,
    file_accs: HashMap<usize, FileRuleAcc>,
    /// Targeted roots: already counted, never re-claimed.
    skip: &'a HashSet<PathBuf>,
    /// Mounted filesystems below the requested roots are separate storage
    /// domains and must not be pulled into a local home-directory scan.
    mount_points: HashSet<PathBuf>,
    /// Ancestor-mask bit for "Library": built-in detectors never claim inside
    /// app-managed space (a gitignored dir or CACHEDIR.TAG under ~/Library is
    /// some app's runtime data, not project junk).
    library_bit: u64,
}

/// Directory basenames that are never worth descending into for discovery,
/// independent of rules. Cloud placeholders would all fault in metadata.
fn skip_descent(name_lower: &str) -> bool {
    matches!(
        name_lower,
        ".git" | ".trash" | "mobile documents" | "cloudstorage" | ".documentrevisions-v100"
    )
}

pub fn discovery_scan(
    ctx: &ScanCtx,
    roots: &[PathBuf],
    targeted_claimed: &HashSet<PathBuf>,
) -> Vec<Finding> {
    let mut file_accs = HashMap::new();
    let mut file_rule_idxs: HashSet<usize> = HashSet::new();
    for idxs in ctx.engine.file_names.values() {
        file_rule_idxs.extend(idxs.iter().copied());
    }
    for (_, idx) in &ctx.engine.file_suffixes {
        file_rule_idxs.insert(*idx);
    }
    for idx in &ctx.engine.path_glob_rules {
        file_rule_idxs.insert(*idx);
    }
    for idx in file_rule_idxs {
        file_accs.insert(
            idx,
            FileRuleAcc {
                bytes: AtomicU64::new(0),
                count: AtomicU64::new(0),
                truncated: AtomicBool::new(false),
                paths: Mutex::new(Vec::new()),
            },
        );
    }

    let state = DiscoveryState {
        ctx,
        findings: Mutex::new(Vec::new()),
        file_accs,
        skip: targeted_claimed,
        mount_points: walk::nested_mount_points(roots),
        library_bit: ctx.engine.ancestor_bit("library"),
    };

    roots.par_iter().for_each(|root| {
        if !ctx.is_cancelled() {
            walk_discover(root, &state, 0, None);
        }
    });

    let mut findings = state.findings.into_inner().expect("findings poisoned");

    // Materialize file-table rules into one aggregate finding per rule.
    for (rule_idx, acc) in state.file_accs {
        let count = acc.count.load(Ordering::Relaxed);
        if count == 0 {
            continue;
        }
        let bytes = acc.bytes.load(Ordering::Relaxed);
        let rule = &ctx.engine.rules[rule_idx];
        if bytes < rule.min_size_bytes {
            continue;
        }
        let mut member_paths = acc.paths.into_inner().expect("paths poisoned");
        member_paths.sort();
        let representative = roots.first().cloned().unwrap_or_else(|| PathBuf::from("/"));
        let mut finding = make_finding(
            rule,
            representative,
            SubtreeStats {
                bytes,
                files: count,
                dirs: 0,
                newest_mtime: 0,
            },
            0,
            ctx.now,
        );
        if acc.truncated.load(Ordering::Relaxed) {
            finding.report_only = true;
            finding.impact = Some(format!(
                "matched {count} files; only the first {} paths were retained, so this aggregate is report-only to keep scan memory bounded",
                member_paths.len()
            ));
        }
        finding.member_paths = member_paths;
        if let Some(finding) = ctx.deliver(finding) {
            findings.push(finding);
        }
    }

    findings
}

fn walk_discover(
    dir: &Path,
    state: &DiscoveryState,
    ancestor_mask: u64,
    git_stack: Option<Arc<GitIgnoreStack>>,
) {
    let ctx = state.ctx;
    if ctx.is_cancelled() {
        return;
    }
    let Some(entries) = walk::list_dir(dir) else {
        return;
    };

    let in_app_space = ancestor_mask & state.library_bit != 0;

    // Built-in detector: CACHEDIR.TAG claims this directory itself.
    if !in_app_space
        && entries
            .iter()
            .any(|e| !e.is_dir && e.name == "CACHEDIR.TAG")
        && cachedir_tag_valid(&dir.join("CACHEDIR.TAG"))
    {
        let stats = size_entries(dir, &entries, ctx);
        if stats.bytes >= 1 << 20 {
            push_builtin_finding(
                state,
                "cachedir-tag",
                "tool-cache",
                dir.to_path_buf(),
                stats,
                ctx.now,
                Safety::Review,
                false,
                false,
                Some("directory is tagged CACHEDIR.TAG (regenerable cache)"),
            );
        }
        return;
    }

    // Repo root? Build/extend the gitignore stack.
    let mut git_stack = git_stack;
    let is_repo_root = entries.iter().any(|e| e.name == ".git");
    if is_repo_root {
        git_stack = Some(Arc::new(GitIgnoreStack::for_repo(dir)));
    }
    if let Some(stack) = &git_stack
        && let Some(extended) = stack.extend_for_dir(dir, &entries)
    {
        git_stack = Some(extended);
    }

    let sibling_names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();

    let mut subdirs: Vec<(PathBuf, u64)> = Vec::new();
    let mut progress_files = 0u64;
    let mut progress_bytes = 0u64;

    for entry in &entries {
        if ctx.is_cancelled() {
            break;
        }
        let lower = entry.name.to_lowercase();
        if entry.is_dir {
            let child = dir.join(&entry.name);
            if skip_descent(&lower)
                || state.skip.contains(&child)
                || state.mount_points.contains(&child)
            {
                continue;
            }
            let child_str = child.to_string_lossy();
            if ctx.engine.is_protected(&child_str) {
                continue;
            }

            // Rule claims by directory basename.
            if let Some(rule_idxs) = ctx.engine.dir_names.get(&lower) {
                let claimed = rule_idxs.iter().copied().find(|&idx| {
                    let rule = &ctx.engine.rules[idx];
                    if rule.exclude_mask & ancestor_mask != 0 {
                        return false;
                    }
                    match &rule.sibling_any {
                        Some(globs) => sibling_names.iter().any(|n| globs.is_match(n)),
                        None => true,
                    }
                });
                if let Some(rule_idx) = claimed {
                    let rule = &ctx.engine.rules[rule_idx];
                    let stats = walk::size_subtree_cancellable(
                        &child,
                        ctx.dedupe,
                        ctx.progress,
                        ctx.cancel,
                    );
                    if stats.bytes >= rule.min_size_bytes {
                        // Project activity = newest of subtree content, the
                        // claimed dir itself, and any marker siblings.
                        let mut effective = stats.newest_mtime.max(entry.mtime);
                        if let Some(globs) = &rule.sibling_any {
                            for sibling in &entries {
                                if !sibling.is_dir && globs.is_match(&sibling.name) {
                                    effective = effective.max(sibling.mtime);
                                }
                            }
                        }
                        let finding = make_finding(rule, child.clone(), stats, effective, ctx.now);
                        if let Some(finding) = ctx.deliver(finding) {
                            state
                                .findings
                                .lock()
                                .expect("findings poisoned")
                                .push(finding);
                        }
                    }
                    continue; // claimed (or too small): never descend
                }
            }

            // Built-in detector: git-ignored directory.
            if let Some(stack) = &git_stack
                && !in_app_space
                && stack.is_ignored(&child, true)
                && !protected_basename(&lower)
            {
                let stats =
                    walk::size_subtree_cancellable(&child, ctx.dedupe, ctx.progress, ctx.cancel);
                if stats.bytes >= 1 << 20 {
                    // Git-ignored ≠ junk: this class also covers vendored
                    // source, downloaded SDKs, databases, and session
                    // history. Selectable by hand (so real junk like a
                    // flutter cache can go), but never via bulk select —
                    // manual_only keeps it out of any sweep.
                    push_builtin_finding(
                        state,
                        "gitignored",
                        "gitignored (pick by hand)",
                        child,
                        stats,
                        ctx.now,
                        Safety::Risky,
                        false,
                        true,
                        Some(
                            "git-ignored data — may be source, SDKs, or databases; check before deleting",
                        ),
                    );
                }
                continue;
            }

            let child_mask = ancestor_mask | ctx.engine.ancestor_bit(&lower);
            subdirs.push((child, child_mask));
        } else {
            progress_files += 1;
            let deduped = ctx.dedupe.dedup(entry.dev, entry.ino, entry.bytes);
            progress_bytes += deduped;

            // File tables: exact name, then suffixes, then residual globs.
            let mut matched: Option<usize> = None;
            if let Some(idxs) = ctx.engine.file_names.get(&lower) {
                matched = idxs.first().copied();
            }
            if matched.is_none() {
                for (suffix, idx) in &ctx.engine.file_suffixes {
                    if lower.ends_with(suffix.as_str()) {
                        matched = Some(*idx);
                        break;
                    }
                }
            }
            if matched.is_none() && !ctx.engine.path_glob_rules.is_empty() {
                let full = dir.join(&entry.name);
                let matches = ctx.engine.path_globs.matches(&full);
                if let Some(glob_idx) = matches.first() {
                    matched = Some(ctx.engine.path_glob_rules[*glob_idx]);
                }
            }

            if let Some(rule_idx) = matched {
                let rule = &ctx.engine.rules[rule_idx];
                let full = dir.join(&entry.name);
                let full_str = full.to_string_lossy();
                if ctx.engine.is_protected(&full_str) {
                    continue;
                }
                // Age gate applies per file.
                if rule.min_age_secs > 0 && (ctx.now - entry.mtime) < rule.min_age_secs {
                    continue;
                }
                if let Some(acc) = state.file_accs.get(&rule_idx) {
                    acc.bytes.fetch_add(deduped, Ordering::Relaxed);
                    acc.count.fetch_add(1, Ordering::Relaxed);
                    let mut paths = acc.paths.lock().expect("paths poisoned");
                    if paths.len() < MAX_MEMBER_PATHS {
                        paths.push(full);
                    } else {
                        acc.truncated.store(true, Ordering::Relaxed);
                    }
                }
            }
        }
    }

    if let Some(progress) = ctx.progress {
        progress.add(progress_files, subdirs.len() as u64, progress_bytes);
    }

    subdirs.par_iter().for_each(|(child, mask)| {
        if !ctx.is_cancelled() {
            walk_discover(child, state, *mask, git_stack.clone());
        }
    });
}

#[allow(clippy::too_many_arguments)]
fn push_builtin_finding(
    state: &DiscoveryState,
    rule_id: &str,
    category: &str,
    path: PathBuf,
    stats: SubtreeStats,
    now: i64,
    safety: crate::rules::Safety,
    report_only: bool,
    manual_only: bool,
    impact: Option<&str>,
) {
    let finding = Finding {
        rule_id: rule_id.to_string(),
        category: category.to_string(),
        safety,
        path,
        bytes: stats.bytes,
        files: stats.files,
        dirs: stats.dirs,
        age_days: age_days(now, stats.newest_mtime),
        recent: false,
        report_only,
        manual_only,
        impact: impact.map(|s| s.to_string()),
        clean_via: Vec::new(),
        member_paths: Vec::new(),
    };
    if let Some(finding) = state.ctx.deliver(finding) {
        state
            .findings
            .lock()
            .expect("findings poisoned")
            .push(finding);
    }
}

/// Sum already-listed entries plus recurse into subdirs (used for self-claims).
fn size_entries(dir: &Path, entries: &[Entry], ctx: &ScanCtx) -> SubtreeStats {
    if ctx.is_cancelled() {
        return SubtreeStats::default();
    }
    let mut stats = SubtreeStats::default();
    let mut subdirs = Vec::new();
    for entry in entries {
        if ctx.is_cancelled() {
            return stats;
        }
        stats.newest_mtime = stats.newest_mtime.max(entry.mtime);
        if entry.is_dir {
            stats.dirs += 1;
            subdirs.push(dir.join(&entry.name));
        } else {
            stats.files += 1;
            stats.bytes += ctx.dedupe.dedup(entry.dev, entry.ino, entry.bytes);
        }
    }
    if let Some(progress) = ctx.progress {
        progress.add(stats.files, stats.dirs, stats.bytes);
    }
    let child_stats = subdirs
        .par_iter()
        .map(|child| walk::size_subtree_cancellable(child, ctx.dedupe, ctx.progress, ctx.cancel))
        .reduce(SubtreeStats::default, SubtreeStats::merge);
    stats.merge(child_stats)
}

/// Names that must never be claimed even when gitignored.
fn protected_basename(lower: &str) -> bool {
    matches!(
        lower,
        ".ssh" | ".aws" | ".gnupg" | ".kube" | ".config" | ".env" | "secrets" | ".secrets"
    )
}

fn cachedir_tag_valid(path: &Path) -> bool {
    const SIGNATURE: &[u8] = b"Signature: 8a477f597d28d172789f06886806bc55";
    let Ok(content) = std::fs::read(path) else {
        return false;
    };
    content.starts_with(SIGNATURE)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_finding() -> Finding {
        Finding {
            rule_id: "test".into(),
            category: "test".into(),
            safety: Safety::Safe,
            path: PathBuf::from("/tmp/test"),
            bytes: 1,
            files: 1,
            dirs: 0,
            age_days: None,
            recent: false,
            report_only: false,
            manual_only: false,
            impact: None,
            clean_via: Vec::new(),
            member_paths: Vec::new(),
        }
    }

    #[test]
    fn streaming_transfers_finding_instead_of_retaining_a_copy() {
        let engine = Engine::compile(Vec::new(), &[], None).unwrap();
        let dedupe = InodeDedupe::new();
        let (tx, rx) = std::sync::mpsc::sync_channel(1);
        let sink = Mutex::new(tx);
        let ctx = ScanCtx {
            engine: &engine,
            dedupe: &dedupe,
            progress: None,
            now: 0,
            sink: Some(&sink),
            cancel: None,
        };

        assert!(ctx.deliver(test_finding()).is_none());
        let ScanEvent::Found(finding) = rx.recv().unwrap() else {
            panic!("expected finding event");
        };
        assert_eq!(finding.rule_id, "test");
    }

    #[test]
    fn batch_mode_keeps_the_finding() {
        let engine = Engine::compile(Vec::new(), &[], None).unwrap();
        let dedupe = InodeDedupe::new();
        let ctx = ScanCtx {
            engine: &engine,
            dedupe: &dedupe,
            progress: None,
            now: 0,
            sink: None,
            cancel: None,
        };

        assert_eq!(ctx.deliver(test_finding()).unwrap().rule_id, "test");
    }
}
