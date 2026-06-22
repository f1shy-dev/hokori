//! Native, state-aware cleanup providers. Providers expose normalized findings
//! and typed actions; the filesystem rule engine remains the fallback for
//! tools without authoritative metadata.

mod ai_assets;
mod android;
mod app_leftovers;
pub mod command;
mod docker;
mod duplicates;
mod git;
mod homebrew;
mod native_gc;
mod stale_files;
mod tool_cache_gc;
mod toolchains;
mod vms;
mod xcode;

use anyhow::Result;
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use crate::report::{
    Confidence, Evidence, Finding, FindingSize, FindingState, FindingTarget, ProviderAction,
    ProviderSource, SizeAccuracy,
};
use crate::rules::Safety;
use crate::taxonomy::{Section, Subgroup};

use self::command::CommandRunner;

pub const QUICK_SCAN_BUDGET: Duration = Duration::from_secs(20);
pub const DEEP_SCAN_BUDGET: Duration = Duration::from_secs(90);
pub const ACTION_BUDGET: Duration = Duration::from_secs(180);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanProfile {
    Quick,
    Deep,
}

impl ScanProfile {
    pub fn label(self) -> &'static str {
        match self {
            Self::Quick => "quick",
            Self::Deep => "deep",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanCost {
    Instant,
    Fast,
    Moderate,
    Slow,
}

impl ScanCost {
    pub fn label(self) -> &'static str {
        match self {
            Self::Instant => "instant",
            Self::Fast => "fast",
            Self::Moderate => "moderate",
            Self::Slow => "slow",
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct ProviderMetadata {
    pub id: &'static str,
    pub name: &'static str,
    pub section: Section,
    pub subgroup: Subgroup,
    pub cost: ScanCost,
    pub quick: bool,
    pub deep: bool,
    pub network_in_deep_scan: bool,
    pub supersedes_rules: &'static [&'static str],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderState {
    Waiting,
    Scanning,
    Ready,
    Unavailable,
    TimedOut,
    PermissionDenied,
    Failed,
    Cancelled,
}

impl ProviderState {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Waiting => "waiting",
            Self::Scanning => "scanning",
            Self::Ready => "ready",
            Self::Unavailable => "unavailable",
            Self::TimedOut => "timed out",
            Self::PermissionDenied => "permission denied",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ProviderStatus {
    pub provider_id: String,
    pub name: String,
    pub state: ProviderState,
    pub message: String,
    pub elapsed_ms: u128,
    pub finding_count: usize,
}

impl ProviderStatus {
    pub fn waiting(metadata: ProviderMetadata) -> Self {
        Self {
            provider_id: metadata.id.into(),
            name: metadata.name.into(),
            state: ProviderState::Waiting,
            message: String::new(),
            elapsed_ms: 0,
            finding_count: 0,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Capability {
    Available,
    Unavailable(String),
    PermissionDenied(String),
}

#[derive(Debug, Clone)]
pub struct ProviderSettings {
    pub profile: ScanProfile,
    pub min_age_days: u64,
    pub min_size_bytes: u64,
    pub enabled: Option<Vec<String>>,
}

impl Default for ProviderSettings {
    fn default() -> Self {
        Self {
            profile: ScanProfile::Quick,
            min_age_days: 30,
            min_size_bytes: 1 << 20,
            enabled: None,
        }
    }
}

#[derive(Clone)]
pub struct ProviderContext {
    pub home: Option<PathBuf>,
    pub roots: Vec<PathBuf>,
    pub repositories: Vec<PathBuf>,
    pub reference_files: Vec<PathBuf>,
    pub reference_complete: bool,
    pub running_commands: Vec<String>,
    pub settings: ProviderSettings,
    pub runner: Arc<CommandRunner>,
    pub cancel: Arc<AtomicBool>,
    pub deadline: Instant,
}

impl ProviderContext {
    pub fn is_cancelled(&self) -> bool {
        self.cancel.load(Ordering::Relaxed) || Instant::now() >= self.deadline
    }

    pub fn remaining(&self, maximum: Duration) -> Duration {
        self.deadline
            .saturating_duration_since(Instant::now())
            .min(maximum)
    }

    pub fn for_action(&self) -> Self {
        Self {
            deadline: Instant::now() + ACTION_BUDGET,
            cancel: Arc::new(AtomicBool::new(false)),
            ..self.clone()
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Revalidation {
    Valid,
    Changed(String),
    Gone(String),
    Blocked(String),
}

#[derive(Debug, Clone, Default)]
pub struct ProviderExecution {
    pub deleted: u64,
    pub freed_bytes: u64,
    pub message: String,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct ProviderExecutionOptions {
    pub permanently: bool,
}

pub trait Provider: Send + Sync {
    fn metadata(&self) -> ProviderMetadata;
    fn probe(&self, context: &ProviderContext) -> Capability;
    fn scan(&self, context: &ProviderContext) -> Result<Vec<Finding>>;
    fn revalidate(&self, context: &ProviderContext, finding: &Finding) -> Result<Revalidation>;
    fn execute(
        &self,
        context: &ProviderContext,
        finding: &Finding,
        options: ProviderExecutionOptions,
    ) -> Result<ProviderExecution>;

    fn refresh(&self, context: &ProviderContext) -> Result<Vec<Finding>> {
        self.scan(context)
    }
}

pub struct ProviderFinding {
    metadata: ProviderMetadata,
    rule_id: String,
    category: String,
    object_id: String,
    label: String,
    safety: Safety,
    size: FindingSize,
    age_days: Option<u64>,
    recent: bool,
    manual_only: bool,
    report_only: bool,
    confidence: Confidence,
    state: FindingState,
    reason: String,
    evidence: Vec<Evidence>,
    description: Option<String>,
    impact: Option<String>,
    recommendation: Option<String>,
    action: Option<ProviderAction>,
    target: Option<FindingTarget>,
    supersedes: Vec<String>,
}

impl ProviderFinding {
    pub fn object(
        metadata: ProviderMetadata,
        rule_id: impl Into<String>,
        category: impl Into<String>,
        object_id: impl Into<String>,
        label: impl Into<String>,
        safety: Safety,
        reclaimable_bytes: u64,
    ) -> Self {
        Self {
            metadata,
            rule_id: rule_id.into(),
            category: category.into(),
            object_id: object_id.into(),
            label: label.into(),
            safety,
            size: FindingSize::exact_physical(reclaimable_bytes),
            age_days: None,
            recent: false,
            manual_only: false,
            report_only: false,
            confidence: Confidence::Exact,
            state: FindingState::Candidate,
            reason: String::new(),
            evidence: Vec::new(),
            description: None,
            impact: None,
            recommendation: None,
            action: None,
            target: None,
            supersedes: Vec::new(),
        }
    }

    pub fn size(mut self, size: FindingSize) -> Self {
        self.size = size;
        self
    }

    pub fn estimated(mut self) -> Self {
        self.size.accuracy = SizeAccuracy::Estimated;
        self
    }

    pub fn age(mut self, age_days: Option<u64>, recent: bool) -> Self {
        self.age_days = age_days;
        self.recent = recent;
        if recent {
            self.state = FindingState::Recent;
        }
        self
    }

    pub fn manual(mut self) -> Self {
        self.manual_only = true;
        self
    }

    pub fn in_use(mut self) -> Self {
        self.manual_only = true;
        self.state = FindingState::InUse;
        self
    }

    pub fn report_only(mut self) -> Self {
        self.report_only = true;
        self.state = FindingState::Informational;
        self
    }

    pub fn protected(mut self) -> Self {
        self.report_only = true;
        self.safety = Safety::Protected;
        self.state = FindingState::Protected;
        self.size.reclaimable = 0;
        self
    }

    pub fn confidence(mut self, confidence: Confidence) -> Self {
        self.confidence = confidence;
        self
    }

    pub fn reason(mut self, reason: impl Into<String>) -> Self {
        self.reason = reason.into();
        self
    }

    pub fn evidence(mut self, label: impl Into<String>, value: impl Into<String>) -> Self {
        self.evidence.push(Evidence {
            label: label.into(),
            value: value.into(),
        });
        self
    }

    pub fn copy(
        mut self,
        description: impl Into<String>,
        impact: impl Into<String>,
        recommendation: impl Into<String>,
    ) -> Self {
        self.description = Some(description.into());
        self.impact = Some(impact.into());
        self.recommendation = Some(recommendation.into());
        self
    }

    pub fn action(
        mut self,
        action_id: impl Into<String>,
        preview: Vec<String>,
        irreversible: bool,
        strong_confirmation: bool,
    ) -> Self {
        self.action = Some(ProviderAction {
            provider_id: self.metadata.id.into(),
            action_id: action_id.into(),
            object_id: self.object_id.clone(),
            preview,
            irreversible,
            strong_confirmation,
        });
        self
    }

    pub fn grouped_paths(mut self, paths: Vec<PathBuf>) -> Self {
        self.target = Some(FindingTarget::GroupedPaths {
            paths,
            label: self.label.clone(),
        });
        self
    }

    pub fn filesystem_path(mut self, path: PathBuf) -> Self {
        self.target = Some(FindingTarget::Filesystem { path });
        self
    }

    pub fn diagnostic(mut self) -> Self {
        self.target = Some(FindingTarget::Diagnostic {
            provider_id: Some(self.metadata.id.into()),
            diagnostic_id: self.object_id.clone(),
            label: self.label.clone(),
        });
        self
    }

    pub fn supersedes(mut self, rule_id: impl Into<String>) -> Self {
        self.supersedes.push(rule_id.into());
        self
    }

    pub fn build(self) -> Finding {
        let stable_id = format!(
            "provider:{}:{}:{}",
            self.metadata.id, self.rule_id, self.object_id
        );
        let target = self
            .target
            .unwrap_or_else(|| FindingTarget::ProviderObject {
                provider_id: self.metadata.id.into(),
                object_id: self.object_id.clone(),
                label: self.label,
            });
        let (path, member_paths) = match &target {
            FindingTarget::Filesystem { path } => (path.clone(), Vec::new()),
            FindingTarget::GroupedPaths { paths, .. } => (
                paths.first().cloned().unwrap_or_default(),
                paths.iter().take(50_000).cloned().collect(),
            ),
            FindingTarget::ProviderObject { .. } | FindingTarget::Diagnostic { .. } => {
                (PathBuf::new(), Vec::new())
            }
        };
        Finding {
            stable_id,
            rule_id: self.rule_id,
            category: self.category,
            section: self.metadata.section,
            subgroup: self.metadata.subgroup,
            safety: self.safety,
            target,
            path,
            bytes: self.size.reclaimable,
            size: self.size,
            files: 0,
            dirs: 0,
            age_days: self.age_days,
            recent: self.recent,
            report_only: self.report_only,
            in_use: self.state == FindingState::InUse,
            manual_only: self.manual_only,
            confidence: self.confidence,
            state: self.state,
            provider: Some(ProviderSource {
                id: self.metadata.id.into(),
                name: self.metadata.name.into(),
            }),
            reason: self.reason,
            evidence: self.evidence,
            native_action: self.action,
            supersedes: self.supersedes,
            description: self.description,
            impact: self.impact,
            recommendation: self.recommendation,
            clean_via: Vec::new(),
            member_paths,
        }
    }
}

pub fn physical_file_size(path: &Path) -> u64 {
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

pub fn parse_human_bytes(value: &str) -> Option<u64> {
    let value = value.trim().replace(',', "");
    if value.is_empty() || value == "N/A" {
        return None;
    }
    let split = value
        .find(|character: char| !character.is_ascii_digit() && character != '.')
        .unwrap_or(value.len());
    let number: f64 = value[..split].parse().ok()?;
    let unit = value[split..].trim().to_ascii_lowercase();
    let multiplier = match unit.as_str() {
        "" | "b" | "bytes" => 1f64,
        "kb" | "kib" => 1024f64,
        "mb" | "mib" => 1024f64.powi(2),
        "gb" | "gib" => 1024f64.powi(3),
        "tb" | "tib" => 1024f64.powi(4),
        _ => return None,
    };
    Some((number * multiplier).max(0.0) as u64)
}

pub fn age_from_human(value: &str) -> Option<u64> {
    let words: Vec<_> = value.split_whitespace().collect();
    let amount: u64 = words.first()?.parse().ok()?;
    let unit = words.get(1)?.trim_end_matches('s');
    match unit {
        "second" | "minute" | "hour" => Some(0),
        "day" => Some(amount),
        "week" => Some(amount.saturating_mul(7)),
        "month" => Some(amount.saturating_mul(30)),
        "year" => Some(amount.saturating_mul(365)),
        _ => None,
    }
}

pub fn age_from_iso8601(value: &str) -> Option<u64> {
    let date = value.get(..10)?;
    let mut parts = date.split('-');
    let year: i64 = parts.next()?.parse().ok()?;
    let month: i64 = parts.next()?.parse().ok()?;
    let day: i64 = parts.next()?.parse().ok()?;
    let then = days_from_civil(year, month, day);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_secs() as i64
        / 86_400;
    Some(now.saturating_sub(then).max(0) as u64)
}

fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = year - i64::from(month <= 2);
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let year_of_era = year - era * 400;
    let adjusted_month = month + if month > 2 { -3 } else { 9 };
    let day_of_year = (153 * adjusted_month + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

pub struct ProviderRegistry {
    providers: Vec<Arc<dyn Provider>>,
    by_id: HashMap<&'static str, Arc<dyn Provider>>,
}

impl ProviderRegistry {
    pub fn empty() -> Self {
        Self {
            providers: Vec::new(),
            by_id: HashMap::new(),
        }
    }

    pub fn standard() -> Self {
        Self::new(vec![
            Arc::new(ai_assets::AiAssetsProvider),
            Arc::new(app_leftovers::AppLeftoversProvider),
            Arc::new(android::AndroidProvider),
            Arc::new(duplicates::DuplicateProvider),
            Arc::new(homebrew::HomebrewProvider),
            Arc::new(docker::DockerProvider),
            Arc::new(xcode::XcodeProvider),
            Arc::new(git::GitProvider),
            Arc::new(toolchains::ToolchainProvider),
            Arc::new(tool_cache_gc::ToolCacheGcProvider),
            Arc::new(vms::VmProvider),
            Arc::new(native_gc::NativeGcProvider),
            Arc::new(stale_files::StaleFilesProvider),
        ])
    }

    pub fn new(providers: Vec<Arc<dyn Provider>>) -> Self {
        let by_id = providers
            .iter()
            .map(|provider| (provider.metadata().id, Arc::clone(provider)))
            .collect();
        Self { providers, by_id }
    }

    pub fn statuses_for(&self, settings: &ProviderSettings) -> Vec<ProviderStatus> {
        self.providers
            .iter()
            .filter(|provider| provider_enabled(provider.metadata(), settings))
            .map(|provider| ProviderStatus::waiting(provider.metadata()))
            .collect()
    }

    pub fn provider(&self, id: &str) -> Option<&Arc<dyn Provider>> {
        self.by_id.get(id)
    }

    pub fn scan_all(
        &self,
        context: Arc<ProviderContext>,
        on_status: &(dyn Fn(ProviderStatus) + Sync),
        on_finding: &(dyn Fn(Finding) + Sync),
    ) {
        let eligible: Vec<_> = self
            .providers
            .iter()
            .filter(|provider| provider_enabled(provider.metadata(), &context.settings))
            .cloned()
            .collect();
        let index = AtomicUsize::new(0);
        let finished = AtomicBool::new(false);
        let processed = std::sync::Mutex::new(HashSet::new());
        let worker_count = eligible.len().min(3);
        std::thread::scope(|scope| {
            let watchdog = scope.spawn(|| {
                while !finished.load(Ordering::Relaxed) && Instant::now() < context.deadline {
                    std::thread::sleep(Duration::from_millis(10));
                }
                if !finished.load(Ordering::Relaxed) {
                    context.cancel.store(true, Ordering::Relaxed);
                }
            });
            let mut workers = Vec::new();
            for _ in 0..worker_count {
                workers.push(scope.spawn(|| {
                    loop {
                        let next = index.fetch_add(1, Ordering::Relaxed);
                        let Some(provider) = eligible.get(next) else {
                            break;
                        };
                        if context.is_cancelled() {
                            break;
                        }
                        processed
                            .lock()
                            .expect("processed providers poisoned")
                            .insert(provider.metadata().id);
                        scan_one(provider.as_ref(), &context, on_status, on_finding);
                    }
                }));
            }
            for worker in workers {
                let _ = worker.join();
            }
            finished.store(true, Ordering::Relaxed);
            let _ = watchdog.join();
            if context.cancel.load(Ordering::Relaxed) {
                let processed = processed.lock().expect("processed providers poisoned");
                for provider in &eligible {
                    let metadata = provider.metadata();
                    if !processed.contains(metadata.id) {
                        on_status(ProviderStatus {
                            provider_id: metadata.id.into(),
                            name: metadata.name.into(),
                            state: ProviderState::Cancelled,
                            message: "Not started before the shared scan budget expired.".into(),
                            elapsed_ms: 0,
                            finding_count: 0,
                        });
                    }
                }
            }
        });
    }

    pub fn revalidate(&self, context: &ProviderContext, finding: &Finding) -> Result<Revalidation> {
        let Some(source) = &finding.provider else {
            return Ok(Revalidation::Valid);
        };
        let provider = self
            .provider(&source.id)
            .ok_or_else(|| anyhow::anyhow!("provider {} is not registered", source.id))?;
        provider.revalidate(context, finding)
    }

    pub fn execute(
        &self,
        context: &ProviderContext,
        finding: &Finding,
        options: ProviderExecutionOptions,
    ) -> Result<ProviderExecution> {
        let source = finding
            .provider
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("finding is not provider-owned"))?;
        let provider = self
            .provider(&source.id)
            .ok_or_else(|| anyhow::anyhow!("provider {} is not registered", source.id))?;
        provider.execute(context, finding, options)
    }
}

fn provider_enabled(metadata: ProviderMetadata, settings: &ProviderSettings) -> bool {
    let profile_enabled = match settings.profile {
        ScanProfile::Quick => metadata.quick,
        ScanProfile::Deep => metadata.deep,
    };
    let explicitly_enabled = settings
        .enabled
        .as_ref()
        .is_none_or(|ids| ids.iter().any(|id| id == metadata.id));
    profile_enabled && explicitly_enabled
}

fn scan_one(
    provider: &dyn Provider,
    context: &ProviderContext,
    on_status: &(dyn Fn(ProviderStatus) + Sync),
    on_finding: &(dyn Fn(Finding) + Sync),
) {
    let metadata = provider.metadata();
    let started = Instant::now();
    on_status(ProviderStatus {
        provider_id: metadata.id.into(),
        name: metadata.name.into(),
        state: ProviderState::Scanning,
        message: format!("Running {} analysis.", context.settings.profile.label()),
        elapsed_ms: 0,
        finding_count: 0,
    });
    let capability = provider.probe(context);
    match capability {
        Capability::Unavailable(message) => {
            on_status(final_status(
                metadata,
                ProviderState::Unavailable,
                message,
                started,
                0,
            ));
            return;
        }
        Capability::PermissionDenied(message) => {
            on_status(final_status(
                metadata,
                ProviderState::PermissionDenied,
                message,
                started,
                0,
            ));
            return;
        }
        Capability::Available => {}
    }
    if context.is_cancelled() {
        on_status(final_status(
            metadata,
            ProviderState::Cancelled,
            "Scan cancelled.".into(),
            started,
            0,
        ));
        return;
    }
    match provider.scan(context) {
        Ok(findings) => {
            if context.is_cancelled() {
                on_status(final_status(
                    metadata,
                    ProviderState::Cancelled,
                    "Provider exceeded the scan budget or the scan was cancelled.".into(),
                    started,
                    0,
                ));
                return;
            }
            let count = findings.len();
            let cleanup_candidates = findings
                .iter()
                .filter(|finding| {
                    !finding.report_only
                        && finding.safety != Safety::Protected
                        && finding.native_action.is_some()
                })
                .count();
            for finding in findings {
                on_finding(finding);
            }
            on_status(final_status(
                metadata,
                ProviderState::Ready,
                if count == 0 {
                    "No reclaimable objects found.".into()
                } else {
                    let noun = if count == 1 { "finding" } else { "findings" };
                    format!("Found {cleanup_candidates} cleanup candidates; {count} {noun} total.")
                },
                started,
                count,
            ));
        }
        Err(error) => {
            let message = format!("{error:#}");
            let state = if context.is_cancelled() {
                ProviderState::Cancelled
            } else if message.contains("timed out") {
                ProviderState::TimedOut
            } else if message.contains("permission") || message.contains("not permitted") {
                ProviderState::PermissionDenied
            } else {
                ProviderState::Failed
            };
            on_status(final_status(metadata, state, message, started, 0));
        }
    }
}

fn final_status(
    metadata: ProviderMetadata,
    state: ProviderState,
    message: String,
    started: Instant,
    finding_count: usize,
) -> ProviderStatus {
    ProviderStatus {
        provider_id: metadata.id.into(),
        name: metadata.name.into(),
        state,
        message,
        elapsed_ms: started.elapsed().as_millis(),
        finding_count,
    }
}
