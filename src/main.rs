mod config;
mod gitignore;
mod matcher;
mod scanner;

use anyhow::{Context, Result};
use clap::{ArgAction, Parser};
use std::path::{Path, PathBuf};

use crate::config::{load_ruleset, RuleAction, RuleFile};
use crate::gitignore::{build_protect_globset, GitIgnoreConfig, GitIgnoreMode};
use crate::matcher::RuleMatcher;
use crate::scanner::{RuleTotals, SampleMode, ScanOptions, Scanner};

#[derive(Parser, Debug)]
#[command(author, version, about = "Disk cleaner scanner prototype", long_about = None)]
struct Args {
    #[arg(long, value_name = "PATH")]
    rules: Option<PathBuf>,

    #[arg(long, value_name = "PATH", default_value = "rules/rulesets.toml")]
    rulesets: PathBuf,

    #[arg(long, default_value = "macos")]
    ruleset: String,

    #[arg(long, short = 'r', value_name = "PATH", action = ArgAction::Append)]
    root: Vec<PathBuf>,

    #[arg(
        long,
        aliases = ["no-git-ignored"],
        help = "Disable gitignore parsing (faster, no git-ignored classification)"
    )]
    git_ignored: bool,

    #[arg(long, value_name = "PATTERN", action = ArgAction::Append)]
    git_protect: Vec<String>,

    #[arg(long, default_value_t = 50)]
    max_samples: usize,

    #[arg(long, value_enum, default_value_t = SampleModeArg::First)]
    sample_mode: SampleModeArg,

    #[arg(long, default_value_t = 0, value_name = "PERCENT")]
    sample_bottom_percent: u8,

    #[arg(long)]
    threads: Option<usize>,

    #[arg(long, default_value_t = false, help = "Windows only: dedupe hardlinks via file IDs (slower)")]
    windows_dedupe_hardlinks: bool,

    #[arg(long, value_enum, default_value_t = GitIgnoredMode::Size)]
    git_ignored_mode: GitIgnoredMode,

    #[arg(long, value_name = "RULE_ID", action = ArgAction::Append)]
    disable_rule: Vec<String>,

    #[arg(long, value_name = "GROUP", action = ArgAction::Append)]
    disable_group: Vec<String>,
}

#[derive(clap::ValueEnum, Debug, Clone, Copy)]
enum GitIgnoredMode {
    Size,
    Prune,
}

#[derive(clap::ValueEnum, Debug, Clone, Copy, PartialEq, Eq)]
enum SampleModeArg {
    First,
    Largest,
}

fn main() -> Result<()> {
    let args = Args::parse();

    if args.sample_bottom_percent > 100 {
        anyhow::bail!("--sample-bottom-percent must be between 0 and 100");
    }
    if args.sample_bottom_percent > 0 && args.sample_mode != SampleModeArg::Largest {
        anyhow::bail!("--sample-bottom-percent requires --sample-mode largest");
    }

    let rules = if let Some(path) = &args.rules {
        RuleFile::load_from(path)
            .with_context(|| format!("failed to load rules from {}", path.display()))?
            .rules
    } else {
        load_ruleset(
            &args.rulesets,
            &args.ruleset,
            &args.disable_rule,
            &args.disable_group,
        )?
    };
    let home = home_dir();
    let matcher = std::sync::Arc::new(RuleMatcher::new(&rules, home.as_deref())?);

    let roots = resolve_roots(&args.root, home.as_deref())?;
    if roots.is_empty() {
        anyhow::bail!("no roots to scan; pass --root PATH or set $HOME");
    }

    let gitignore = if args.git_ignored {
        None
    } else {
        let protect = build_protect_globset(&args.git_protect)?;
        Some(GitIgnoreConfig {
            mode: match args.git_ignored_mode {
                GitIgnoredMode::Size => GitIgnoreMode::Size,
                GitIgnoredMode::Prune => GitIgnoreMode::Prune,
            },
            protect: std::sync::Arc::new(protect),
        })
    };

    let options = ScanOptions {
        max_samples: args.max_samples,
        threads: args.threads,
        windows_dedupe_hardlinks: args.windows_dedupe_hardlinks,
        gitignore,
        sample_mode: match args.sample_mode {
            SampleModeArg::First => SampleMode::First,
            SampleModeArg::Largest => SampleMode::Largest,
        },
        sample_bottom_percent: if args.sample_bottom_percent == 0 {
            None
        } else {
            Some(args.sample_bottom_percent)
        },
    };
    let scanner = Scanner::new(std::sync::Arc::clone(&matcher), options);

    let result = scanner.scan(&roots)?;

    println!("Scan roots:");
    for root in &roots {
        println!("  - {}", display_path(root, home.as_deref()));
    }
    #[derive(Clone)]
    struct DisplayEntry {
        id: String,
        action: RuleAction,
        kind: String,
        totals: RuleTotals,
    }

    let mut entries: Vec<DisplayEntry> = Vec::new();
    for (idx, totals) in result.totals.iter().enumerate() {
        let action = matcher.rule_action(idx);
        if action == RuleAction::Protect {
            continue;
        }
        entries.push(DisplayEntry {
            id: matcher.rule_id(idx).to_string(),
            action,
            kind: format!("{:?}", matcher.rule_kind(idx)),
            totals: totals.clone(),
        });
    }
    if let Some(git_ignored) = result.git_ignored.clone() {
        if git_ignored.file_count > 0 || git_ignored.dir_count > 0 {
            entries.push(DisplayEntry {
                id: "git_ignored".to_string(),
                action: RuleAction::Caution,
                kind: "GitIgnored".to_string(),
                totals: RuleTotals {
                    bytes: git_ignored.bytes,
                    file_count: git_ignored.file_count,
                    dir_count: git_ignored.dir_count,
                },
            });
        }
    }

    let mut total_cleanable = RuleTotals::default();
    let mut total_caution = RuleTotals::default();
    let mut total_deep_clean = RuleTotals::default();

    for entry in &entries {
        match entry.action {
            RuleAction::Cleanable => add_totals(&mut total_cleanable, &entry.totals),
            RuleAction::Caution => add_totals(&mut total_caution, &entry.totals),
            RuleAction::DeepClean => add_totals(&mut total_deep_clean, &entry.totals),
            RuleAction::Protect => {}
        }
    }

    println!("\nRule totals:");

    entries.sort_by(|a, b| {
        b.totals
            .bytes
            .cmp(&a.totals.bytes)
            .then_with(|| a.id.cmp(&b.id))
    });

    let mut any = false;
    for entry in &entries {
        if entry.totals.file_count == 0 && entry.totals.dir_count == 0 {
            continue;
        }
        any = true;
            println!(
                "  - {} [{} / {}] files={} dirs={} bytes={}",
                entry.id,
                action_label(entry.action),
                entry.kind,
                entry.totals.file_count,
                entry.totals.dir_count,
                human_bytes(entry.totals.bytes)
            );
    }
    if !any {
        println!("  (no matches)");
    }

    println!("\nTotals by action:");
    print_action_totals("cleanable", &total_cleanable);
    print_action_totals("caution", &total_caution);
    if total_deep_clean.file_count > 0 || total_deep_clean.dir_count > 0 {
        print_action_totals("deep_clean", &total_deep_clean);
    }
    if !result.samples.is_empty() || !result.git_ignored_samples.is_empty() {
        println!("\nSample matches:");
        let mut seen = std::collections::HashSet::new();
        for sample in &result.samples {
            let rule_id = matcher.rule_id(sample.rule_index);
            if matcher.rule_action(sample.rule_index) == RuleAction::Protect {
                continue;
            }
            seen.insert(sample.path.clone());
            let size_label = if args.sample_mode == SampleModeArg::Largest {
                human_bytes(sample.bytes)
            } else {
                "-".to_string()
            };
            println!(
                "  [{}] [{}] {}",
                format_bytes_padded(&size_label, 8),
                rule_id,
                display_path(&sample.path, home.as_deref())
            );
        }
        if let Some(_git_ignored) = result.git_ignored {
            for sample in &result.git_ignored_samples {
                if seen.contains(&sample.path) {
                    continue;
                }
                let size_label = if args.sample_mode == SampleModeArg::Largest {
                    human_bytes(sample.bytes)
                } else {
                    "-".to_string()
                };
                println!(
                    "  [{}] [{}] {}",
                    format_bytes_padded(&size_label, 8),
                    "git_ignored",
                    display_path(&sample.path, home.as_deref())
                );
            }
        }
    }

    Ok(())
}

fn home_dir() -> Option<PathBuf> {
    if let Ok(home) = std::env::var("HOME") {
        if !home.is_empty() {
            return Some(PathBuf::from(home));
        }
    }
    if let Ok(home) = std::env::var("USERPROFILE") {
        if !home.is_empty() {
            return Some(PathBuf::from(home));
        }
    }
    None
}

fn resolve_roots(roots: &[PathBuf], home: Option<&Path>) -> Result<Vec<PathBuf>> {
    let mut resolved = Vec::new();
    if roots.is_empty() {
        if let Some(home) = home {
            resolved.push(home.to_path_buf());
        }
        return Ok(resolved);
    }

    for root in roots {
        let expanded = expand_home(root, home);
        let absolute = if expanded.is_absolute() {
            expanded
        } else {
            std::env::current_dir()?.join(expanded)
        };
        resolved.push(absolute);
    }

    Ok(resolved)
}

fn expand_home(path: &Path, home: Option<&Path>) -> PathBuf {
    if let Some(home) = home {
        if let Some(rest) = path.to_string_lossy().strip_prefix("~/") {
            return home.join(rest);
        }
    }
    path.to_path_buf()
}

fn action_label(action: RuleAction) -> &'static str {
    match action {
        RuleAction::Cleanable => "cleanable",
        RuleAction::Caution => "caution",
        RuleAction::DeepClean => "deep_clean",
        RuleAction::Protect => "protect",
    }
}

fn add_totals(dst: &mut RuleTotals, src: &RuleTotals) {
    dst.bytes = dst.bytes.saturating_add(src.bytes);
    dst.file_count = dst.file_count.saturating_add(src.file_count);
    dst.dir_count = dst.dir_count.saturating_add(src.dir_count);
}

fn print_action_totals(label: &str, totals: &RuleTotals) {
    println!(
        "  - {} files={} dirs={} bytes={}",
        label,
        totals.file_count,
        totals.dir_count,
        human_bytes(totals.bytes)
    );
}

fn display_path(path: &Path, home: Option<&Path>) -> String {
    if let Some(home) = home {
        if let Ok(rest) = path.strip_prefix(home) {
            if rest.as_os_str().is_empty() {
                return "~".to_string();
            }
            return format!("~/{}", rest.to_string_lossy());
        }
    }
    path.to_string_lossy().to_string()
}

fn format_bytes_padded(label: &str, width: usize) -> String {
    let mut out = String::new();
    if label.len() >= width {
        out.push_str(label);
    } else {
        for _ in 0..(width - label.len()) {
            out.push(' ');
        }
        out.push_str(label);
    }
    out
}

fn human_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut size = bytes as f64;
    let mut unit = 0;
    while size >= 1024.0 && unit < UNITS.len() - 1 {
        size /= 1024.0;
        unit += 1;
    }
    format!("{:.1} {}", size, UNITS[unit])
}
