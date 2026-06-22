mod action;
mod compiler;
mod engine;
mod gitignore;
mod report;
mod rules;
mod tui;
mod util;
mod walk;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::collections::HashSet;
use std::io::IsTerminal;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

use crate::action::{ExecOptions, PlanOptions, SafetyArg};
use crate::compiler::Engine;
use crate::engine::{ScanCtx, discovery_scan, targeted_scan};
use crate::report::{Progress, ProgressReporter, Report};
use crate::walk::InodeDedupe;

#[derive(Parser, Debug)]
#[command(
    author,
    version,
    about = "Disk cleaner: targeted + discovery scanning, dry-run by default"
)]
struct Args {
    #[command(subcommand)]
    command: Option<Command>,

    #[command(flatten)]
    scan: ScanArgs,
}

#[derive(Parser, Debug, Clone)]
struct ScanArgs {
    /// Discovery roots (defaults to $HOME).
    #[arg(long, short = 'r', value_name = "PATH")]
    root: Vec<PathBuf>,

    /// Load rules from a directory of .toml files instead of the embedded set.
    #[arg(long, value_name = "DIR")]
    rules_dir: Option<PathBuf>,

    /// Skip the targeted (known locations) engine.
    #[arg(long)]
    no_targeted: bool,

    /// Skip the discovery (full walk) engine.
    #[arg(long)]
    no_discovery: bool,

    /// Worker threads (default: all cores).
    #[arg(long)]
    threads: Option<usize>,

    /// Show every finding instead of the top entries per category.
    #[arg(long, short = 'v')]
    verbose: bool,

    /// Emit the full report as JSON on stdout.
    #[arg(long)]
    json: bool,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Scan and report what could be cleaned (default).
    Scan(ScanArgs),
    /// Build a deletion plan; dry-run unless --apply is passed.
    Clean(CleanArgs),
    /// Interactive TUI: stream findings, select, and clean.
    Tui(ScanArgs),
    /// List compiled rules.
    Rules {
        #[arg(long)]
        json: bool,
        #[arg(long, value_name = "DIR")]
        rules_dir: Option<PathBuf>,
    },
}

#[derive(Parser, Debug)]
struct CleanArgs {
    #[command(flatten)]
    scan: ScanArgs,

    /// Highest safety tier to include (safe < review < risky).
    #[arg(long, value_enum, default_value_t = SafetyArg::Safe)]
    safety: SafetyArg,

    /// Only these categories.
    #[arg(long = "category", value_name = "NAME")]
    categories: Vec<String>,

    /// Only these rule ids.
    #[arg(long = "rule", value_name = "ID")]
    rules: Vec<String>,

    /// Only findings at least this old (days).
    #[arg(long, value_name = "DAYS")]
    min_age: Option<u64>,

    /// Include findings the rules flagged as recently-used (excluded by default).
    #[arg(long)]
    include_recent: bool,

    /// Cap the number of plan items (largest first).
    #[arg(long, value_name = "N")]
    limit: Option<usize>,

    /// Actually delete. Without this flag the plan is printed and nothing happens.
    #[arg(long)]
    apply: bool,

    /// Skip the interactive confirmation (still requires --apply).
    #[arg(long)]
    yes: bool,

    /// Delete permanently instead of moving to the Trash.
    #[arg(long)]
    permanently: bool,
}

fn main() -> Result<()> {
    let args = Args::parse();
    match args.command {
        None => cmd_scan(args.scan),
        Some(Command::Scan(scan)) => cmd_scan(scan),
        Some(Command::Clean(clean)) => cmd_clean(clean),
        Some(Command::Tui(scan)) => cmd_tui(scan),
        Some(Command::Rules { json, rules_dir }) => cmd_rules(json, rules_dir.as_deref()),
    }
}

fn build_engine(scan: &ScanArgs) -> Result<Engine> {
    let home = util::home_dir();
    let mut defs = rules::load_rules(scan.rules_dir.as_deref())?;
    let config = rules::load_user_config()?;
    rules::apply_user_config(&mut defs, &config);
    Engine::compile(defs, &config.protect, home.as_deref())
}

fn init_threads(threads: Option<usize>) {
    let mut builder = rayon::ThreadPoolBuilder::new().stack_size(16 * 1024 * 1024);
    if let Some(n) = threads {
        builder = builder.num_threads(n);
    }
    // Deep recursive descent needs the bigger stacks; ignore double-init.
    let _ = builder.build_global();
}

fn resolve_roots(scan: &ScanArgs) -> Result<Vec<PathBuf>> {
    if scan.root.is_empty() {
        Ok(vec![
            util::home_dir().context("no --root given and $HOME is unset")?,
        ])
    } else {
        Ok(scan.root.clone())
    }
}

fn run_scan(scan: &ScanArgs) -> Result<(Report, Engine)> {
    init_threads(scan.threads);
    let engine = build_engine(scan)?;
    let home = util::home_dir();
    let roots = resolve_roots(scan)?;

    let dedupe = InodeDedupe::new();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let progress_enabled = std::io::stderr().is_terminal() && !scan.json;
    let progress = progress_enabled.then(|| Arc::new(Progress::new()));

    let started = Instant::now();
    let mut findings = Vec::new();
    let mut claimed: HashSet<PathBuf> = HashSet::new();

    if !scan.no_targeted {
        let reporter = progress
            .as_ref()
            .map(|p| ProgressReporter::start(Arc::clone(p), "targeted scan"));
        let ctx = ScanCtx {
            engine: &engine,
            dedupe: &dedupe,
            progress: progress.as_deref(),
            now,
            sink: None,
            cancel: None,
        };
        let result = targeted_scan(&ctx);
        if let Some(reporter) = reporter {
            reporter.stop();
        }
        findings.extend(result.findings);
        claimed = result.claimed;
    }

    if !scan.no_discovery {
        let reporter = progress
            .as_ref()
            .map(|p| ProgressReporter::start(Arc::clone(p), "discovery scan"));
        let ctx = ScanCtx {
            engine: &engine,
            dedupe: &dedupe,
            progress: progress.as_deref(),
            now,
            sink: None,
            cancel: None,
        };
        findings.extend(discovery_scan(&ctx, &roots, &claimed));
        if let Some(reporter) = reporter {
            reporter.stop();
        }
    }

    let (scanned_files, scanned_dirs, _) =
        progress.as_ref().map(|p| p.snapshot()).unwrap_or((0, 0, 0));

    let report = Report {
        roots: roots
            .iter()
            .map(|r| report::display_path(r, home.as_deref()))
            .collect(),
        totals: Report::compute_totals(&findings),
        findings,
        scanned_files,
        scanned_dirs,
        elapsed_ms: started.elapsed().as_millis(),
    };
    Ok((report, engine))
}

fn cmd_scan(scan: ScanArgs) -> Result<()> {
    let json = scan.json;
    let verbose = scan.verbose;
    let (report, _engine) = run_scan(&scan)?;
    if json {
        serde_json::to_writer_pretty(std::io::stdout().lock(), &report)?;
        println!();
    } else {
        report::print_report(&report, util::home_dir().as_deref(), verbose);
    }
    Ok(())
}

fn cmd_clean(clean: CleanArgs) -> Result<()> {
    let (report, engine) = run_scan(&clean.scan)?;
    let options = PlanOptions {
        safety: clean.safety,
        categories: clean.categories,
        rules: clean.rules,
        min_age_days: clean.min_age,
        limit: clean.limit,
        include_recent: clean.include_recent,
    };
    let plan = action::build_plan(&report.findings, &options);
    let home = util::home_dir();

    if clean.scan.json {
        serde_json::to_writer_pretty(std::io::stdout().lock(), &plan)?;
        println!();
    } else {
        action::print_plan(&plan, home.as_deref(), clean.apply);
    }

    if clean.apply {
        action::confirm_or_bail(&plan, clean.yes)?;
        let summary = action::execute_plan(
            &plan,
            &engine,
            home.as_deref(),
            &ExecOptions {
                permanently: clean.permanently,
            },
        )?;
        for err in &summary.errors {
            eprintln!("  skip {err}");
        }
        println!(
            "Freed {} ({} items deleted, {} skipped/failed). Journal: ~/.local/state/cleaner/journal.jsonl",
            report::human_bytes(summary.freed_bytes),
            summary.deleted,
            summary.failed
        );
    }
    Ok(())
}

fn cmd_tui(scan: ScanArgs) -> Result<()> {
    init_threads(scan.threads);
    let engine = std::sync::Arc::new(build_engine(&scan)?);
    let roots = resolve_roots(&scan)?;
    tui::run(engine, roots, scan, util::home_dir())
}

fn cmd_rules(json: bool, rules_dir: Option<&std::path::Path>) -> Result<()> {
    let defs = rules::load_rules(rules_dir)?;
    if json {
        #[derive(serde::Serialize)]
        struct RuleSummary<'a> {
            id: &'a str,
            category: &'a str,
            safety: &'a str,
            targeted: bool,
            report_only: bool,
        }
        let summaries: Vec<_> = defs
            .iter()
            .map(|d| RuleSummary {
                id: &d.id,
                category: &d.category,
                safety: d.safety.label(),
                targeted: !d.roots.is_empty(),
                report_only: d.report_only,
            })
            .collect();
        serde_json::to_writer_pretty(std::io::stdout().lock(), &summaries)?;
        println!();
    } else {
        for def in &defs {
            let mode = if !def.roots.is_empty() {
                "targeted"
            } else {
                "discovery"
            };
            println!(
                "{:<28} {:<24} {:<9} {}{}",
                def.id,
                def.category,
                def.safety.label(),
                mode,
                if def.report_only {
                    " (report only)"
                } else {
                    ""
                }
            );
        }
    }
    Ok(())
}
