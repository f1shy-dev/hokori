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
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use crate::compiler::{CompiledRule, Engine};
use crate::gitignore::GitIgnoreStack;
use crate::report::{Confidence, Finding, FindingSize, FindingState, FindingTarget, Progress};
use crate::rules::Safety;
use crate::taxonomy::category_info;
use crate::walk::{self, Entry, InodeDedupe, SubtreeStats};

/// Streaming events for the TUI. `None` sink = batch (CLI) mode.
pub enum ScanEvent {
    Found(Box<Finding>),
    Phase(&'static str),
    ProviderStatus(crate::providers::ProviderStatus),
    Done,
}

pub type Sink<'a> = Option<&'a Mutex<std::sync::mpsc::SyncSender<ScanEvent>>>;

pub struct ScanCtx<'a> {
    pub engine: &'a Engine,
    pub dedupe: &'a InodeDedupe,
    pub progress: Option<&'a Progress>,
    pub running_commands: &'a [String],
    pub repositories: Option<&'a Mutex<HashSet<PathBuf>>>,
    pub reference_files: Option<&'a Mutex<Vec<PathBuf>>>,
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
            .map(|tx| tx.send(ScanEvent::Found(Box::new(finding))).is_ok())
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
    ctx: &ScanCtx,
) -> Finding {
    let now = ctx.now;
    let recent =
        rule.min_age_secs > 0 && effective_mtime > 0 && (now - effective_mtime) < rule.min_age_secs;
    let in_use = rule.process_names_lower.iter().any(|process| {
        ctx.running_commands
            .iter()
            .any(|command| command.contains(process))
    });
    let category = category_info(&rule.def.category);
    Finding {
        stable_id: format!("path:{}:{}", rule.def.id, path.to_string_lossy()),
        rule_id: rule.def.id.clone(),
        category: rule.def.category.clone(),
        section: category.section,
        subgroup: category.subgroup,
        safety: rule.def.safety,
        target: FindingTarget::Filesystem { path: path.clone() },
        path,
        bytes: stats.bytes,
        size: FindingSize::exact_physical(stats.bytes),
        files: stats.files,
        dirs: stats.dirs,
        age_days: age_days(now, effective_mtime),
        recent,
        report_only: rule.def.report_only,
        in_use,
        manual_only: rule.def.manual_only || in_use,
        confidence: Confidence::High,
        state: if in_use {
            FindingState::InUse
        } else if recent {
            FindingState::Recent
        } else {
            FindingState::Candidate
        },
        provider: None,
        reason: String::new(),
        evidence: Vec::new(),
        native_action: None,
        supersedes: Vec::new(),
        description: rule.def.description.clone(),
        impact: rule.def.impact.clone(),
        recommendation: rule.def.recommendation.clone(),
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
            if ctx.engine.rules[*rule_idx].def.directory_only
                && !path
                    .symlink_metadata()
                    .is_ok_and(|metadata| metadata.is_dir())
            {
                continue;
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
            let finding = make_finding(rule, path, stats, mtime, ctx);
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
    newest_mtime: AtomicI64,
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
                newest_mtime: AtomicI64::new(0),
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
        let newest_mtime = acc.newest_mtime.load(Ordering::Relaxed);
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
                newest_mtime,
            },
            newest_mtime,
            ctx,
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
                "tagged-cache",
                dir.to_path_buf(),
                stats,
                ctx.now,
                Safety::Review,
                false,
                true,
                Some(
                    "The directory contains a valid CACHEDIR.TAG. This marks data that should not need backup, but it does not identify the owner or guarantee that raw deletion is the correct cleanup method.",
                ),
                Some(
                    "The owner may need to rebuild or redownload the contents. Some tools also place this tag in persistent installed environments.",
                ),
                Some(
                    "Review the full path and identify the owning tool. Prefer its native prune or uninstall command; this finding is never bulk-selected.",
                ),
            );
        }
        return;
    }

    // Repo root? Build/extend the gitignore stack.
    let mut git_stack = git_stack;
    let is_repo_root = entries.iter().any(|e| e.name == ".git")
        || (entries.iter().any(|e| !e.is_dir && e.name == "HEAD")
            && entries.iter().any(|e| e.is_dir && e.name == "objects")
            && entries.iter().any(|e| e.is_dir && e.name == "refs"));
    if is_repo_root {
        if let Some(repositories) = ctx.repositories {
            repositories
                .lock()
                .expect("repositories poisoned")
                .insert(dir.to_path_buf());
        }
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
                        let finding = make_finding(rule, child.clone(), stats, effective, ctx);
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
                            "This directory is ignored by a repository's Git rules. It could be generated output, dependencies, an SDK, a local database, or untracked user data.",
                        ),
                        Some(
                            "Deleting it removes the complete ignored directory and anything stored inside it.",
                        ),
                        Some(
                            "Inspect the full path and project context. Select one finding at a time only when you know the directory is reproducible.",
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
            if is_reference_marker(&entry.name)
                && let Some(reference_files) = ctx.reference_files
            {
                let mut reference_files = reference_files.lock().expect("references poisoned");
                if reference_files.len() < 20_000 {
                    reference_files.push(dir.join(&entry.name));
                }
            }

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
                if deduped < rule.min_file_size_bytes {
                    continue;
                }
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
                    acc.newest_mtime.fetch_max(entry.mtime, Ordering::Relaxed);
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
    description: Option<&str>,
    impact: Option<&str>,
    recommendation: Option<&str>,
) {
    let category_info = category_info(category);
    let finding = Finding {
        stable_id: format!("path:{rule_id}:{}", path.to_string_lossy()),
        rule_id: rule_id.to_string(),
        category: category.to_string(),
        section: category_info.section,
        subgroup: category_info.subgroup,
        safety,
        target: FindingTarget::Filesystem { path: path.clone() },
        path,
        bytes: stats.bytes,
        size: FindingSize::exact_physical(stats.bytes),
        files: stats.files,
        dirs: stats.dirs,
        age_days: age_days(now, stats.newest_mtime),
        recent: false,
        report_only,
        in_use: false,
        manual_only,
        confidence: Confidence::Medium,
        state: if report_only {
            FindingState::Informational
        } else {
            FindingState::Candidate
        },
        provider: None,
        reason: String::new(),
        evidence: Vec::new(),
        native_action: None,
        supersedes: Vec::new(),
        description: description.map(str::to_owned),
        impact: impact.map(|s| s.to_string()),
        recommendation: recommendation.map(str::to_owned),
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

fn is_reference_marker(name: &str) -> bool {
    matches!(
        name,
        "rust-toolchain.toml"
            | "rust-toolchain"
            | ".python-version"
            | ".nvmrc"
            | ".ruby-version"
            | ".tool-versions"
            | ".sdkmanrc"
            | ".fvmrc"
            | "fvm_config.json"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::RuleFile;

    fn test_finding() -> Finding {
        let category = category_info("test");
        Finding {
            stable_id: "path:test:/tmp/test".into(),
            rule_id: "test".into(),
            category: "test".into(),
            section: category.section,
            subgroup: category.subgroup,
            safety: Safety::Safe,
            target: FindingTarget::Filesystem {
                path: PathBuf::from("/tmp/test"),
            },
            path: PathBuf::from("/tmp/test"),
            bytes: 1,
            size: FindingSize::exact_physical(1),
            files: 1,
            dirs: 0,
            age_days: None,
            recent: false,
            report_only: false,
            in_use: false,
            manual_only: false,
            confidence: Confidence::High,
            state: FindingState::Candidate,
            provider: None,
            reason: String::new(),
            evidence: Vec::new(),
            native_action: None,
            supersedes: Vec::new(),
            description: None,
            impact: None,
            recommendation: None,
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
            running_commands: &[],
            repositories: None,
            reference_files: None,
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
            running_commands: &[],
            repositories: None,
            reference_files: None,
            now: 0,
            sink: None,
            cancel: None,
        };

        assert_eq!(ctx.deliver(test_finding()).unwrap().rule_id, "test");
    }

    #[test]
    fn running_process_marks_rule_manual_only() {
        let file: RuleFile = toml::from_str(
            r#"
                [[rules]]
                id = "cursor-cache"
                category = "ide-cache"
                safety = "safe"
                roots = ["/tmp/cursor-cache"]
                process_names = ["/Cursor.app/"]
            "#,
        )
        .unwrap();
        let engine = Engine::compile(file.rules, &[], None).unwrap();
        let dedupe = InodeDedupe::new();
        let running = vec!["/Applications/Cursor.app/Contents/MacOS/Cursor".to_lowercase()];
        let ctx = ScanCtx {
            engine: &engine,
            dedupe: &dedupe,
            progress: None,
            running_commands: &running,
            repositories: None,
            reference_files: None,
            now: 0,
            sink: None,
            cancel: None,
        };
        let finding = make_finding(
            &engine.rules[0],
            PathBuf::from("/tmp/cursor-cache"),
            SubtreeStats::default(),
            0,
            &ctx,
        );

        assert!(finding.in_use);
        assert!(finding.manual_only);
    }

    #[test]
    fn compiles_per_file_size_floor() {
        let file: RuleFile = toml::from_str(
            r#"
                [[rules]]
                id = "large-dumps"
                category = "diagnostic"
                safety = "review"
                file_suffixes = [".hprof"]
                min_file_size = "10MB"
            "#,
        )
        .unwrap();
        let engine = Engine::compile(file.rules, &[], None).unwrap();
        assert_eq!(engine.rules[0].min_file_size_bytes, 10 << 20);
    }

    #[test]
    fn targeted_directory_only_roots_skip_files() {
        let root = std::env::temp_dir().join("hokori-directory-only-test");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("tool")).unwrap();
        std::fs::write(root.join(".lock"), b"lock").unwrap();

        let file: RuleFile = toml::from_str(&format!(
            r#"
                [[rules]]
                id = "installed-tools"
                category = "tools"
                safety = "risky"
                roots = ["{}/*"]
                directory_only = true
            "#,
            root.display()
        ))
        .unwrap();
        let engine = Engine::compile(file.rules, &[], None).unwrap();
        let dedupe = InodeDedupe::new();
        let ctx = ScanCtx {
            engine: &engine,
            dedupe: &dedupe,
            progress: None,
            running_commands: &[],
            repositories: None,
            reference_files: None,
            now: 0,
            sink: None,
            cancel: None,
        };
        let result = targeted_scan(&ctx);

        assert_eq!(result.findings.len(), 1);
        assert_eq!(result.findings[0].path, root.join("tool"));
        let _ = std::fs::remove_dir_all(root);
    }
}
