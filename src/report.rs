//! Findings, the scan report, and terminal/JSON output.

use serde::Serialize;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use crate::rules::Safety;

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub rule_id: String,
    pub category: String,
    pub safety: Safety,
    pub path: PathBuf,
    pub bytes: u64,
    pub files: u64,
    pub dirs: u64,
    /// Days since the newest mtime seen in the subtree / relevant markers.
    pub age_days: Option<u64>,
    /// True when the rule's min_age gate failed: reported, never planned.
    pub recent: bool,
    pub report_only: bool,
    /// Selectable by hand, but never by bulk select-all (git-ignored data:
    /// could be source, DBs, SDKs — safe to delete one-by-one with eyes on it,
    /// never as part of a sweep).
    #[serde(default)]
    pub manual_only: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub impact: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub clean_via: Vec<String>,
    /// For file-table rules (e.g. .DS_Store): every matched path. Empty for
    /// subtree findings, where `path` is the deletable root.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub member_paths: Vec<PathBuf>,
}

#[derive(Debug, Serialize)]
pub struct Report {
    pub roots: Vec<String>,
    pub findings: Vec<Finding>,
    pub totals: Totals,
    pub scanned_files: u64,
    pub scanned_dirs: u64,
    pub elapsed_ms: u128,
}

#[derive(Debug, Default, Serialize)]
pub struct Totals {
    pub safe_bytes: u64,
    pub review_bytes: u64,
    pub risky_bytes: u64,
    pub report_only_bytes: u64,
    pub recent_bytes: u64,
}

impl Report {
    pub fn compute_totals(findings: &[Finding]) -> Totals {
        let mut totals = Totals::default();
        for f in findings {
            if f.recent {
                totals.recent_bytes += f.bytes;
            } else if f.report_only {
                totals.report_only_bytes += f.bytes;
            } else {
                match f.safety {
                    Safety::Safe => totals.safe_bytes += f.bytes,
                    Safety::Review => totals.review_bytes += f.bytes,
                    Safety::Risky => totals.risky_bytes += f.bytes,
                    Safety::Protected => {}
                }
            }
        }
        totals
    }
}

// ---- progress ----

pub struct Progress {
    files: AtomicU64,
    dirs: AtomicU64,
    bytes: AtomicU64,
}

impl Progress {
    pub fn new() -> Self {
        Self {
            files: AtomicU64::new(0),
            dirs: AtomicU64::new(0),
            bytes: AtomicU64::new(0),
        }
    }

    pub fn add(&self, files: u64, dirs: u64, bytes: u64) {
        if files > 0 {
            self.files.fetch_add(files, Ordering::Relaxed);
        }
        if dirs > 0 {
            self.dirs.fetch_add(dirs, Ordering::Relaxed);
        }
        if bytes > 0 {
            self.bytes.fetch_add(bytes, Ordering::Relaxed);
        }
    }

    pub fn snapshot(&self) -> (u64, u64, u64) {
        (
            self.files.load(Ordering::Relaxed),
            self.dirs.load(Ordering::Relaxed),
            self.bytes.load(Ordering::Relaxed),
        )
    }
}

pub struct ProgressReporter {
    stop: Arc<AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl ProgressReporter {
    pub fn start(progress: Arc<Progress>, label: &'static str) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let stop_clone = Arc::clone(&stop);
        let handle = std::thread::spawn(move || {
            use std::io::Write;
            let mut printed = false;
            while !stop_clone.load(Ordering::Relaxed) {
                std::thread::sleep(Duration::from_millis(500));
                let (files, dirs, bytes) = progress.snapshot();
                if files == 0 && dirs == 0 {
                    continue;
                }
                let mut stderr = std::io::stderr();
                let _ = write!(
                    stderr,
                    "\r\x1b[2K{label}: files={files} dirs={dirs} seen={}",
                    human_bytes(bytes)
                );
                let _ = stderr.flush();
                printed = true;
            }
            if printed {
                let mut stderr = std::io::stderr();
                let _ = write!(stderr, "\r\x1b[2K");
                let _ = stderr.flush();
            }
        });
        Self {
            stop,
            handle: Some(handle),
        }
    }

    pub fn stop(mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

impl Drop for ProgressReporter {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

// ---- terminal output ----

pub fn print_report(report: &Report, home: Option<&Path>, verbose: bool) {
    use std::collections::BTreeMap;

    let mut by_category: BTreeMap<&str, Vec<&Finding>> = BTreeMap::new();
    for finding in &report.findings {
        by_category
            .entry(&finding.category)
            .or_default()
            .push(finding);
    }

    let mut categories: Vec<(&str, u64, Vec<&Finding>)> = by_category
        .into_iter()
        .map(|(cat, mut findings)| {
            findings.sort_by_key(|finding| std::cmp::Reverse(finding.bytes));
            let total = findings.iter().map(|f| f.bytes).sum();
            (cat, total, findings)
        })
        .collect();
    categories.sort_by_key(|category| std::cmp::Reverse(category.1));

    for (category, total, findings) in &categories {
        println!("\n{category}  —  {}", human_bytes(*total));
        let shown = if verbose {
            findings.len()
        } else {
            findings.len().min(12)
        };
        for finding in &findings[..shown] {
            let age = finding
                .age_days
                .map(|d| format!("{d}d"))
                .unwrap_or_else(|| "-".into());
            let mut flags = String::new();
            if finding.recent {
                flags.push_str(" (recent — skipped)");
            }
            if finding.report_only {
                flags.push_str(" (report only)");
            }
            let count = if finding.files > 1 {
                format!(" ({} files)", finding.files)
            } else {
                String::new()
            };
            println!(
                "  {:>9}  {:<7} {:>5}  {}{}{}",
                human_bytes(finding.bytes),
                finding.safety.label(),
                age,
                display_path(&finding.path, home),
                count,
                flags
            );
        }
        if findings.len() > shown {
            let rest: u64 = findings[shown..].iter().map(|f| f.bytes).sum();
            println!(
                "  {:>9}  … {} more (use --verbose)",
                human_bytes(rest),
                findings.len() - shown
            );
        }
    }

    let t = &report.totals;
    println!();
    println!(
        "Totals: safe={}  review={}  risky={}  report-only={}  skipped-recent={}",
        human_bytes(t.safe_bytes),
        human_bytes(t.review_bytes),
        human_bytes(t.risky_bytes),
        human_bytes(t.report_only_bytes),
        human_bytes(t.recent_bytes),
    );
    println!(
        "Scanned {} files / {} dirs in {:.1}s",
        report.scanned_files,
        report.scanned_dirs,
        report.elapsed_ms as f64 / 1000.0
    );
}

pub fn human_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut size = bytes as f64;
    let mut unit = 0;
    while size >= 1024.0 && unit < UNITS.len() - 1 {
        size /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{size:.1} {}", UNITS[unit])
    }
}

pub fn display_path(path: &Path, home: Option<&Path>) -> String {
    if let Some(home) = home
        && let Ok(rest) = path.strip_prefix(home)
    {
        if rest.as_os_str().is_empty() {
            return "~".to_string();
        }
        return format!("~/{}", rest.to_string_lossy());
    }
    path.to_string_lossy().to_string()
}
