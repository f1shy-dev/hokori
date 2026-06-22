//! The action engine: build a deletion plan from findings, show it (dry-run is
//! the default and only implicit mode), and — only with `--apply` plus
//! confirmation — execute it through a single validation funnel.
//!
//! Every deletion goes to the OS Trash unless `--permanently` is passed, and
//! every attempt is journaled to ~/.local/state/hokori/journal.jsonl first.

use anyhow::{Context, Result, bail};
use serde::Serialize;
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::compiler::Engine;
use crate::providers::{ProviderContext, ProviderExecutionOptions, ProviderRegistry, Revalidation};
use crate::report::{Evidence, Finding, display_path, human_bytes};
use crate::rules::Safety;

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum SafetyArg {
    Safe,
    Review,
    Risky,
}

impl SafetyArg {
    fn allows(self, safety: Safety) -> bool {
        match self {
            SafetyArg::Safe => safety == Safety::Safe,
            SafetyArg::Review => matches!(safety, Safety::Safe | Safety::Review),
            SafetyArg::Risky => {
                matches!(safety, Safety::Safe | Safety::Review | Safety::Risky)
            }
        }
    }
}

pub struct PlanOptions {
    pub safety: SafetyArg,
    pub categories: Vec<String>,
    pub rules: Vec<String>,
    pub min_age_days: Option<u64>,
    pub limit: Option<usize>,
    /// Include findings the rules flagged as recently-used (off by default).
    pub include_recent: bool,
}

pub fn build_plan<'a>(findings: &'a [Finding], options: &PlanOptions) -> Vec<&'a Finding> {
    let mut items: Vec<&Finding> = findings
        .iter()
        .filter(|f| {
            if f.report_only {
                return false;
            }
            // Git-ignored (manual_only) stays out of scripted plans unless the
            // user names the rule explicitly (e.g. --rule gitignored).
            if f.manual_only && !options.rules.iter().any(|r| r == &f.rule_id) {
                return false;
            }
            if f.recent && !options.include_recent {
                return false;
            }
            if !options.safety.allows(f.safety) {
                return false;
            }
            if !options.categories.is_empty()
                && !options.categories.iter().any(|c| c == &f.category)
            {
                return false;
            }
            if !options.rules.is_empty() && !options.rules.iter().any(|r| r == &f.rule_id) {
                return false;
            }
            if let (Some(min), Some(age)) = (options.min_age_days, f.age_days)
                && age < min
            {
                return false;
            }
            true
        })
        .collect();
    items.sort_by_key(|item| std::cmp::Reverse(item.bytes));
    if let Some(limit) = options.limit {
        items.truncate(limit);
    }
    items
}

pub fn print_plan(items: &[&Finding], home: Option<&Path>, apply: bool) {
    if items.is_empty() {
        println!("Nothing matches the plan filters.");
        return;
    }
    let header = if apply {
        "Will delete:"
    } else {
        "Would delete (dry run):"
    };
    println!("{header}");
    let mut total = 0u64;
    for finding in items {
        total += finding.bytes;
        let count = if finding.files > 1 {
            format!(" ({} files)", finding.files)
        } else {
            String::new()
        };
        println!(
            "  {:>9}  [{}/{}]  {}{}",
            human_bytes(finding.bytes),
            finding.rule_id,
            finding.safety.label(),
            finding.display_label(home),
            count
        );
        if let Some(action) = finding.action_preview() {
            println!(
                "             action: {}{}",
                action,
                if finding
                    .native_action
                    .as_ref()
                    .is_some_and(|action| action.irreversible)
                {
                    " (not restorable from Trash)"
                } else {
                    ""
                }
            );
        }
        if let Some(impact) = &finding.impact {
            println!("             impact: {impact}");
        }
    }
    println!("\nTotal: {}", human_bytes(total));
    if !apply {
        println!("Dry run — nothing was deleted. Re-run with --apply to execute.");
    }
}

// ---- execution ----

#[derive(Serialize)]
struct JournalEntry {
    ts: u64,
    target: String,
    estimated_bytes: u64,
    freed_bytes: u64,
    rule_id: String,
    provider: Option<String>,
    object_id: Option<String>,
    action: Option<String>,
    evidence: Vec<Evidence>,
    mode: String,
    result: String,
}

pub struct ExecOptions {
    pub permanently: bool,
}

#[derive(Default)]
pub struct ExecSummary {
    pub deleted: u64,
    pub failed: usize,
    pub changed: usize,
    pub skipped: usize,
    pub freed_bytes: u64,
    pub errors: Vec<String>,
    pub messages: Vec<String>,
}

pub fn execute_plan(
    items: &[&Finding],
    engine: &Engine,
    providers: &ProviderRegistry,
    provider_context: &ProviderContext,
    home: Option<&Path>,
    options: &ExecOptions,
) -> Result<ExecSummary> {
    let home = home.context("cannot delete without a resolvable $HOME")?;
    let mut journal = open_journal(home)?;
    let mode = if options.permanently {
        "delete"
    } else {
        "trash"
    };

    let mut summary = ExecSummary::default();
    for finding in items {
        if finding.is_provider_owned() {
            let revalidation = providers.revalidate(provider_context, finding);
            match revalidation {
                Ok(Revalidation::Valid) => {}
                Ok(Revalidation::Changed(message) | Revalidation::Gone(message)) => {
                    summary.changed += 1;
                    summary.failed += 1;
                    push_error(&mut summary, message);
                    journal_provider(&mut journal, finding, "provider-native", "changed", 0);
                    continue;
                }
                Ok(Revalidation::Blocked(message)) => {
                    summary.skipped += 1;
                    summary.failed += 1;
                    push_error(&mut summary, message);
                    journal_provider(&mut journal, finding, "provider-native", "blocked", 0);
                    continue;
                }
                Err(error) => {
                    summary.failed += 1;
                    push_error(&mut summary, format!("{error:#}"));
                    journal_provider(&mut journal, finding, "provider-native", "error", 0);
                    continue;
                }
            }
            match providers.execute(
                provider_context,
                finding,
                ProviderExecutionOptions {
                    permanently: options.permanently,
                },
            ) {
                Ok(execution) => {
                    summary.deleted += execution.deleted;
                    summary.freed_bytes += execution.freed_bytes;
                    if !execution.message.is_empty() && summary.messages.len() < 20 {
                        summary.messages.push(execution.message);
                    }
                    journal_provider(
                        &mut journal,
                        finding,
                        "provider-native",
                        "ok",
                        execution.freed_bytes,
                    );
                }
                Err(error) => {
                    summary.failed += 1;
                    push_error(&mut summary, format!("{error:#}"));
                    journal_provider(&mut journal, finding, "provider-native", "error", 0);
                }
            }
            continue;
        }

        let targets: Vec<&PathBuf> = if finding.member_paths.is_empty() {
            vec![&finding.path]
        } else {
            finding.member_paths.iter().collect()
        };
        let mut finding_failed = false;
        for target in targets {
            let estimated_bytes = if finding.member_paths.is_empty() {
                finding.bytes
            } else {
                allocated_file_bytes(target)
            };
            let result = validate_for_deletion(target, engine, home)
                .and_then(|()| delete_one(target, options.permanently))
                // Some deletions (notably .DS_Store) report an error yet still
                // remove the file. If the path is gone, it worked.
                .or_else(|err| {
                    if std::fs::symlink_metadata(target).is_err() {
                        Ok(())
                    } else {
                        Err(err)
                    }
                });
            let outcome = match &result {
                Ok(()) => {
                    summary.deleted += 1;
                    "ok"
                }
                Err(_) => {
                    summary.failed += 1;
                    "error"
                }
            };
            write_journal(
                &mut journal,
                JournalEntry {
                    ts: now_secs(),
                    target: target.to_string_lossy().into_owned(),
                    estimated_bytes,
                    freed_bytes: if result.is_ok() { estimated_bytes } else { 0 },
                    rule_id: finding.rule_id.clone(),
                    provider: None,
                    object_id: None,
                    action: None,
                    evidence: redact_evidence(&finding.evidence),
                    mode: mode.into(),
                    result: outcome.into(),
                },
            );
            if let Err(err) = result {
                finding_failed = true;
                if summary.errors.len() < 20 {
                    summary
                        .errors
                        .push(format!("{}: {err:#}", display_path(target, Some(home))));
                }
            }
        }
        if !finding_failed {
            summary.freed_bytes += finding.bytes;
        }
    }
    Ok(summary)
}

fn journal_provider(
    journal: &mut std::fs::File,
    finding: &Finding,
    mode: &str,
    result: &str,
    freed_bytes: u64,
) {
    let action = finding.native_action.as_ref();
    write_journal(
        journal,
        JournalEntry {
            ts: now_secs(),
            target: finding.display_label(None),
            estimated_bytes: finding.bytes,
            freed_bytes,
            rule_id: finding.rule_id.clone(),
            provider: finding
                .provider
                .as_ref()
                .map(|provider| provider.id.clone()),
            object_id: action.map(|action| action.object_id.clone()),
            action: action.map(|action| action.action_id.clone()),
            evidence: redact_evidence(&finding.evidence),
            mode: mode.into(),
            result: result.into(),
        },
    );
}

fn allocated_file_bytes(path: &Path) -> u64 {
    let Ok(metadata) = path.symlink_metadata() else {
        return 0;
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        metadata.blocks().saturating_mul(512)
    }
    #[cfg(not(unix))]
    {
        metadata.len()
    }
}

fn redact_evidence(evidence: &[Evidence]) -> Vec<Evidence> {
    evidence
        .iter()
        .map(|entry| {
            let label = entry.label.to_ascii_lowercase();
            let sensitive = [
                "token",
                "password",
                "secret",
                "cookie",
                "credential",
                "auth",
            ]
            .iter()
            .any(|term| label.contains(term));
            Evidence {
                label: entry.label.clone(),
                value: if sensitive {
                    "[redacted]".into()
                } else {
                    entry.value.clone()
                },
            }
        })
        .collect()
}

fn push_error(summary: &mut ExecSummary, error: String) {
    if summary.errors.len() < 20 {
        summary.errors.push(error);
    }
}

/// The single validation funnel. Every deletion passes through here; rules
/// never get to bypass it.
fn validate_for_deletion(path: &Path, engine: &Engine, home: &Path) -> Result<()> {
    if !path.is_absolute() {
        bail!("refusing relative path");
    }
    let meta = std::fs::symlink_metadata(path).context("path vanished")?;
    if meta.file_type().is_symlink() {
        bail!("refusing symlink");
    }
    if path.components().count() < 4 {
        bail!("refusing shallow path (depth < 4)");
    }
    let allowed = path.starts_with(home)
        || path.starts_with("/tmp")
        || path.starts_with("/private/tmp")
        || path.starts_with("/private/var/folders");
    if !allowed {
        bail!("outside user space");
    }
    if path == home {
        bail!("refusing $HOME itself");
    }
    // Never delete a well-known container directory itself (children are fine).
    const CONTAINERS: &[&str] = &[
        "Library",
        "Library/Caches",
        "Library/Logs",
        "Library/Application Support",
        "Library/Containers",
        "Library/Group Containers",
        "Library/Developer",
        "Library/Preferences",
        "Documents",
        "Desktop",
        "Downloads",
        "Pictures",
        "Movies",
        "Music",
    ];
    for container in CONTAINERS {
        if path == home.join(container) {
            bail!("refusing container directory {container}");
        }
    }
    if engine.is_protected(&path.to_string_lossy()) {
        bail!("protected by rules/config");
    }
    Ok(())
}

fn delete_one(path: &Path, permanently: bool) -> Result<()> {
    if permanently {
        let meta = std::fs::symlink_metadata(path)?;
        if meta.is_dir() {
            std::fs::remove_dir_all(path).context("remove_dir_all failed")
        } else {
            std::fs::remove_file(path).context("remove_file failed")
        }
    } else {
        trash_to_bin(path).context("move to Trash failed")
    }
}

/// Move to the Trash using the native file-manager API rather than driving
/// Finder via AppleScript — the AppleScript path prompts for a password and
/// fails on privileged locations.
#[cfg(target_os = "macos")]
fn trash_to_bin(path: &Path) -> Result<()> {
    use trash::macos::{DeleteMethod, TrashContextExtMacos};
    let mut ctx = trash::TrashContext::default();
    ctx.set_delete_method(DeleteMethod::NsFileManager);
    ctx.delete(path).map_err(Into::into)
}

#[cfg(not(target_os = "macos"))]
fn trash_to_bin(path: &Path) -> Result<()> {
    trash::delete(path).map_err(Into::into)
}

fn open_journal(home: &Path) -> Result<std::fs::File> {
    let dir = home.join(".local/state/hokori");
    std::fs::create_dir_all(&dir).context("failed to create journal dir")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
            .context("failed to secure journal dir")?;
    }

    let mut options = std::fs::OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options
        .open(dir.join("journal.jsonl"))
        .context("failed to open journal")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))
            .context("failed to secure journal")?;
    }
    Ok(file)
}

fn write_journal(file: &mut std::fs::File, entry: JournalEntry) {
    if let Ok(line) = serde_json::to_string(&entry) {
        let _ = writeln!(file, "{line}");
    }
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub fn confirm_or_bail(items: &[&Finding], yes: bool) -> Result<()> {
    if items.is_empty() {
        bail!("plan is empty; nothing to apply");
    }
    if yes {
        return Ok(());
    }
    let total: u64 = items.iter().map(|f| f.bytes).sum();
    eprint!(
        "\nType 'clean' to execute cleanup for {} across {} items. Native actions may be irreversible: ",
        human_bytes(total),
        items.len()
    );
    std::io::stderr().flush().ok();
    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;
    if input.trim() != "clean" {
        bail!("aborted");
    }
    Ok(())
}
