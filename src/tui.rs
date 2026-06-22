//! Interactive front-end for scanning, reviewing, and cleaning findings.

use anyhow::{Context, Result};
use crossterm::event::{
    self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEventKind, KeyModifiers,
    MouseButton, MouseEvent, MouseEventKind,
};
use crossterm::execute;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::stdout;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use ratatui::Frame;
use ratatui::layout::{Alignment, Constraint, Layout, Margin, Position, Rect};
use ratatui::style::{Color, Modifier, Style, Stylize};
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::{
    Block, Borders, Clear, Gauge, List, ListItem, ListState, Paragraph, Scrollbar,
    ScrollbarOrientation, ScrollbarState, Wrap,
};

use crate::ScanArgs;
use crate::action::{self, ExecOptions};
use crate::compiler::Engine;
use crate::engine::{ScanCtx, ScanEvent, discovery_scan, targeted_scan};
use crate::providers::command::CommandRunner;
use crate::providers::{
    ACTION_BUDGET, DEEP_SCAN_BUDGET, ProviderContext, ProviderRegistry, ProviderSettings,
    ProviderState, ProviderStatus, QUICK_SCAN_BUDGET, ScanProfile,
};
use crate::report::{
    self, Finding, FindingState, Progress, ProviderAction, SizeAccuracy, display_path, human_bytes,
};
use crate::rules::Safety;
use crate::taxonomy::{Section, Subgroup, category_info};
use crate::walk::InodeDedupe;

const EVENT_QUEUE_CAPACITY: usize = 1024;
const MIN_TERMINAL_WIDTH: u16 = 58;
const MIN_TERMINAL_HEIGHT: u16 = 16;

pub fn run(
    engine: Arc<Engine>,
    providers: Arc<ProviderRegistry>,
    mut provider_settings: ProviderSettings,
    roots: Vec<PathBuf>,
    scan: ScanArgs,
    home: Option<PathBuf>,
) -> Result<()> {
    let reference_complete = !scan.no_discovery
        && home
            .as_ref()
            .is_some_and(|home| roots.iter().any(|root| root == home));
    let mut terminal = ratatui::init();
    if let Err(error) = execute!(stdout(), EnableMouseCapture) {
        ratatui::restore();
        return Err(error).context("failed to enable terminal mouse capture");
    }

    let result = (|| -> Result<()> {
        let mut generation = 1u64;
        loop {
            let worker = ScanWorker::spawn(
                Arc::clone(&engine),
                Arc::clone(&providers),
                provider_settings.clone(),
                roots.clone(),
                home.clone(),
                &scan,
            )?;
            let mut app = App::new(
                Arc::clone(&engine),
                Arc::clone(&providers),
                provider_settings.clone(),
                roots.clone(),
                home.clone(),
                Arc::clone(&worker.progress),
                Arc::clone(&worker.repositories),
                Arc::clone(&worker.reference_files),
                worker.rx,
                generation,
                reference_complete,
            );
            let outcome = app.run(&mut terminal);

            worker.cancel.store(true, Ordering::Relaxed);
            drop(app);
            let _ = worker.handle.join();

            match outcome? {
                AppOutcome::Quit => break,
                AppOutcome::Rescan(settings) => {
                    provider_settings = settings;
                    generation = generation.saturating_add(1);
                }
            }
        }
        Ok(())
    })();

    let _ = execute!(stdout(), DisableMouseCapture);
    ratatui::restore();
    result
}

struct ScanWorker {
    progress: Arc<Progress>,
    repositories: Arc<Mutex<HashSet<PathBuf>>>,
    reference_files: Arc<Mutex<Vec<PathBuf>>>,
    rx: Receiver<ScanEvent>,
    cancel: Arc<AtomicBool>,
    handle: JoinHandle<()>,
}

impl ScanWorker {
    fn spawn(
        engine: Arc<Engine>,
        providers: Arc<ProviderRegistry>,
        provider_settings: ProviderSettings,
        roots: Vec<PathBuf>,
        home: Option<PathBuf>,
        scan: &ScanArgs,
    ) -> Result<Self> {
        let progress = Arc::new(Progress::new());
        let repositories = Arc::new(Mutex::new(HashSet::new()));
        let reference_files = Arc::new(Mutex::new(Vec::new()));
        let cancel = Arc::new(AtomicBool::new(false));
        let (tx, rx) = mpsc::sync_channel::<ScanEvent>(EVENT_QUEUE_CAPACITY);
        let worker_progress = Arc::clone(&progress);
        let worker_repositories = Arc::clone(&repositories);
        let worker_reference_files = Arc::clone(&reference_files);
        let worker_cancel = Arc::clone(&cancel);
        let no_targeted = scan.no_targeted;
        let no_discovery = scan.no_discovery;
        let deep = provider_settings.profile == ScanProfile::Deep;
        let reference_complete = !no_discovery
            && home
                .as_ref()
                .is_some_and(|home| roots.iter().any(|root| root == home));

        let handle = std::thread::Builder::new()
            .name("hokori-scan".into())
            .stack_size(16 * 1024 * 1024)
            .spawn(move || {
                let dedupe = InodeDedupe::new();
                let running_commands = crate::util::running_commands();
                let now = now_secs();
                let phase_tx = tx.clone();
                let sink = Mutex::new(tx);

                let mut claimed = HashSet::new();
                if !no_targeted {
                    let _ = phase_tx.send(ScanEvent::Phase("targeted"));
                    let ctx = ScanCtx {
                        engine: engine.as_ref(),
                        dedupe: &dedupe,
                        progress: Some(&worker_progress),
                        running_commands: &running_commands,
                        repositories: Some(worker_repositories.as_ref()),
                        reference_files: Some(worker_reference_files.as_ref()),
                        now,
                        sink: Some(&sink),
                        cancel: Some(&worker_cancel),
                    };
                    claimed = targeted_scan(&ctx).claimed;
                }
                if !no_discovery && !worker_cancel.load(Ordering::Relaxed) {
                    let _ = phase_tx.send(ScanEvent::Phase("discovery"));
                    let ctx = ScanCtx {
                        engine: engine.as_ref(),
                        dedupe: &dedupe,
                        progress: Some(&worker_progress),
                        running_commands: &running_commands,
                        repositories: Some(worker_repositories.as_ref()),
                        reference_files: Some(worker_reference_files.as_ref()),
                        now,
                        sink: Some(&sink),
                        cancel: Some(&worker_cancel),
                    };
                    discovery_scan(&ctx, &roots, &claimed);
                }
                if !worker_cancel.load(Ordering::Relaxed) {
                    let _ = phase_tx.send(ScanEvent::Phase("providers"));
                    let repositories = worker_repositories
                        .lock()
                        .expect("repositories poisoned")
                        .iter()
                        .cloned()
                        .collect();
                    let context = Arc::new(ProviderContext {
                        home: home.clone(),
                        roots: roots.clone(),
                        repositories,
                        reference_files: worker_reference_files
                            .lock()
                            .expect("references poisoned")
                            .clone(),
                        reference_complete,
                        running_commands: running_commands.clone(),
                        settings: provider_settings,
                        runner: Arc::new(CommandRunner::new(home)),
                        cancel: Arc::clone(&worker_cancel),
                        deadline: Instant::now()
                            + if deep {
                                DEEP_SCAN_BUDGET
                            } else {
                                QUICK_SCAN_BUDGET
                            },
                    });
                    let status_tx = phase_tx.clone();
                    let finding_tx = phase_tx.clone();
                    providers.scan_all(
                        context,
                        &|status| {
                            let _ = status_tx.send(ScanEvent::ProviderStatus(status));
                        },
                        &|finding| {
                            let _ = finding_tx.send(ScanEvent::Found(Box::new(finding)));
                        },
                    );
                }
                let _ = phase_tx.send(ScanEvent::Done);
            })?;

        Ok(Self {
            progress,
            repositories,
            reference_files,
            rx,
            cancel,
            handle,
        })
    }
}

#[derive(Debug, Clone)]
enum AppOutcome {
    Quit,
    Rescan(ProviderSettings),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ViewMode {
    All,
    Safe,
    Review,
    Risky,
    Manual,
    Selected,
}

impl ViewMode {
    fn next(self) -> Self {
        match self {
            Self::All => Self::Safe,
            Self::Safe => Self::Review,
            Self::Review => Self::Risky,
            Self::Risky => Self::Manual,
            Self::Manual => Self::Selected,
            Self::Selected => Self::All,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::All => "all",
            Self::Safe => "safe",
            Self::Review => "review",
            Self::Risky => "risky",
            Self::Manual => "manual",
            Self::Selected => "selected",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SortMode {
    Size,
    Age,
    Path,
}

impl SortMode {
    fn next(self) -> Self {
        match self {
            Self::Size => Self::Age,
            Self::Age => Self::Path,
            Self::Path => Self::Size,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Size => "size",
            Self::Age => "age",
            Self::Path => "path",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SizeFilter {
    All,
    Exact,
    Estimated,
}

impl SizeFilter {
    fn next(self) -> Self {
        match self {
            Self::All => Self::Exact,
            Self::Exact => Self::Estimated,
            Self::Estimated => Self::All,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::All => "all sizes",
            Self::Exact => "exact",
            Self::Estimated => "estimated",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum VisibleRow {
    Section(Section),
    Group {
        section: Section,
        subgroup: Subgroup,
    },
    Finding {
        section: Section,
        subgroup: Subgroup,
        index: usize,
    },
}

enum Modal {
    None,
    Confirm,
    Result {
        message: String,
        rescan_after_close: bool,
    },
    Help {
        scroll: u16,
    },
    Providers {
        scroll: u16,
    },
    DuplicateChoice {
        finding_index: usize,
        retained: usize,
    },
    Detail {
        scroll: u16,
    },
    Search {
        draft: String,
    },
}

struct App {
    engine: Arc<Engine>,
    providers: Arc<ProviderRegistry>,
    provider_settings: ProviderSettings,
    roots: Vec<PathBuf>,
    home: Option<PathBuf>,
    progress: Arc<Progress>,
    repositories: Arc<Mutex<HashSet<PathBuf>>>,
    reference_files: Arc<Mutex<Vec<PathBuf>>>,
    rx: Receiver<ScanEvent>,
    provider_statuses: HashMap<String, ProviderStatus>,
    generation: u64,
    reference_complete: bool,

    findings: Vec<Finding>,
    checked: HashSet<usize>,
    open_sections: HashSet<Section>,
    open_groups: HashSet<(Section, Subgroup)>,
    rows: Vec<VisibleRow>,
    rows_dirty: bool,
    list_state: ListState,

    view_mode: ViewMode,
    sort_mode: SortMode,
    size_filter: SizeFilter,
    provider_filter: Option<String>,
    show_recent: bool,
    search_query: String,

    phase: &'static str,
    scanning: bool,
    scan_error: Option<String>,
    status: String,
    permanently: bool,
    modal: Modal,

    list_area: Rect,
    detail_area: Rect,
    page_size: u16,
}

impl App {
    #[allow(clippy::too_many_arguments)]
    fn new(
        engine: Arc<Engine>,
        providers: Arc<ProviderRegistry>,
        provider_settings: ProviderSettings,
        roots: Vec<PathBuf>,
        home: Option<PathBuf>,
        progress: Arc<Progress>,
        repositories: Arc<Mutex<HashSet<PathBuf>>>,
        reference_files: Arc<Mutex<Vec<PathBuf>>>,
        rx: Receiver<ScanEvent>,
        generation: u64,
        reference_complete: bool,
    ) -> Self {
        let provider_statuses = providers
            .statuses_for(&provider_settings)
            .into_iter()
            .map(|status| (status.provider_id.clone(), status))
            .collect();
        Self {
            engine,
            providers,
            provider_settings,
            roots,
            home,
            progress,
            repositories,
            reference_files,
            rx,
            provider_statuses,
            generation,
            reference_complete,
            findings: Vec::new(),
            checked: HashSet::new(),
            open_sections: HashSet::from([Section::QuickCleanup, Section::Developer]),
            open_groups: HashSet::from([
                (Section::QuickCleanup, Subgroup::Recommended),
                (Section::Developer, Subgroup::Packages),
                (Section::Developer, Subgroup::ContainersVms),
            ]),
            rows: Vec::new(),
            rows_dirty: true,
            list_state: ListState::default(),
            view_mode: ViewMode::All,
            sort_mode: SortMode::Size,
            size_filter: SizeFilter::All,
            provider_filter: None,
            show_recent: true,
            search_query: String::new(),
            phase: "starting",
            scanning: true,
            scan_error: None,
            status: "Scanning. Findings will appear as they are discovered.".into(),
            permanently: false,
            modal: Modal::None,
            list_area: Rect::ZERO,
            detail_area: Rect::ZERO,
            page_size: 1,
        }
    }

    fn run(&mut self, terminal: &mut ratatui::DefaultTerminal) -> Result<AppOutcome> {
        let mut dirty = true;
        let mut last_progress = self.progress.snapshot();

        loop {
            if self.drain_events() {
                dirty = true;
            }
            let progress = self.progress.snapshot();
            if progress != last_progress {
                last_progress = progress;
                dirty = true;
            }
            if self.rows_dirty {
                self.rebuild_rows();
                dirty = true;
            }
            if dirty {
                terminal.draw(|frame| self.draw(frame))?;
                dirty = false;
            }

            let timeout = if self.scanning {
                Duration::from_millis(100)
            } else {
                Duration::from_secs(3600)
            };
            if !event::poll(timeout)? {
                continue;
            }

            match event::read()? {
                Event::Key(key)
                    if matches!(key.kind, KeyEventKind::Press | KeyEventKind::Repeat) =>
                {
                    if let Some(outcome) = self.on_key(key.code, key.modifiers) {
                        return Ok(outcome);
                    }
                    dirty = true;
                }
                Event::Mouse(mouse) if self.on_mouse(mouse) => dirty = true,
                Event::Resize(_, _) => dirty = true,
                _ => {}
            }
        }
    }

    fn drain_events(&mut self) -> bool {
        let mut changed = false;
        for _ in 0..10_000 {
            match self.rx.try_recv() {
                Ok(ScanEvent::Found(finding)) => {
                    if finding.bytes > 0
                        || !finding.member_paths.is_empty()
                        || finding.is_provider_owned()
                    {
                        self.merge_finding(*finding);
                        self.rows_dirty = true;
                        changed = true;
                    }
                }
                Ok(ScanEvent::Phase(phase)) => {
                    self.phase = phase;
                    changed = true;
                }
                Ok(ScanEvent::ProviderStatus(status)) => {
                    if status.state == ProviderState::Ready
                        && let Some(provider) = self.providers.provider(&status.provider_id)
                    {
                        let superseded = provider.metadata().supersedes_rules;
                        self.retain_findings(|finding| {
                            !superseded.iter().any(|rule_id| *rule_id == finding.rule_id)
                        });
                    }
                    self.provider_statuses
                        .insert(status.provider_id.clone(), status);
                    self.rows_dirty = true;
                    changed = true;
                }
                Ok(ScanEvent::Done) => {
                    self.scanning = false;
                    self.phase = "done";
                    self.status = if self.findings.is_empty() {
                        "Scan complete. No findings were found under the selected roots.".into()
                    } else {
                        "Scan complete. Review findings before cleaning.".into()
                    };
                    changed = true;
                }
                Err(mpsc::TryRecvError::Empty) => break,
                Err(mpsc::TryRecvError::Disconnected) => {
                    if self.scanning {
                        self.scan_error = Some("The scan worker stopped unexpectedly.".into());
                        self.status = "Scan stopped unexpectedly. Press r to retry.".into();
                    }
                    self.scanning = false;
                    changed = true;
                    break;
                }
            }
        }
        changed
    }

    fn checked_stable_ids(&self) -> HashSet<String> {
        self.checked
            .iter()
            .filter_map(|index| self.findings.get(*index))
            .map(|finding| finding.stable_id.clone())
            .collect()
    }

    fn restore_checked(&mut self, stable_ids: &HashSet<String>) {
        self.checked = self
            .findings
            .iter()
            .enumerate()
            .filter(|(_, finding)| stable_ids.contains(&finding.stable_id))
            .map(|(index, _)| index)
            .collect();
    }

    fn merge_finding(&mut self, finding: Finding) {
        let checked = self.checked_stable_ids();
        report::merge_finding(&mut self.findings, finding);
        self.restore_checked(&checked);
    }

    fn retain_findings(&mut self, mut keep: impl FnMut(&Finding) -> bool) {
        let checked = self.checked_stable_ids();
        self.findings.retain(|finding| keep(finding));
        self.restore_checked(&checked);
    }

    fn rebuild_rows(&mut self) {
        let selected = self.selected_row().cloned();
        let mut by_group: BTreeMap<(Section, Subgroup), Vec<usize>> = BTreeMap::new();

        for (index, finding) in self.findings.iter().enumerate() {
            if self.finding_matches_view(index) && self.finding_matches_query(finding) {
                by_group
                    .entry((finding.section, finding.subgroup))
                    .or_default()
                    .push(index);
            }
        }

        let mut groups: Vec<((Section, Subgroup), Vec<usize>)> = by_group.into_iter().collect();
        for (_, indices) in &mut groups {
            self.sort_findings(indices);
        }
        groups.sort_by(|a, b| {
            a.0.0
                .order()
                .cmp(&b.0.0.order())
                .then_with(|| a.0.1.label().cmp(b.0.1.label()))
        });

        self.rows.clear();
        let force_open = !self.search_query.is_empty() || self.view_mode == ViewMode::Selected;
        for section in [
            Section::QuickCleanup,
            Section::Developer,
            Section::Applications,
            Section::System,
            Section::Analysis,
        ] {
            let section_groups: Vec<_> = groups
                .iter()
                .filter(|((candidate, _), _)| *candidate == section)
                .collect();
            if section_groups.is_empty() {
                continue;
            }
            self.rows.push(VisibleRow::Section(section));
            if force_open || self.open_sections.contains(&section) {
                for ((_, subgroup), indices) in section_groups {
                    self.rows.push(VisibleRow::Group {
                        section,
                        subgroup: *subgroup,
                    });
                    if force_open || self.open_groups.contains(&(section, *subgroup)) {
                        self.rows.extend(indices.iter().copied().map(|index| {
                            VisibleRow::Finding {
                                section,
                                subgroup: *subgroup,
                                index,
                            }
                        }));
                    }
                }
            }
        }

        let next_selection = selected
            .and_then(|selected| self.rows.iter().position(|row| row == &selected))
            .or_else(|| (!self.rows.is_empty()).then_some(0));
        self.list_state.select(next_selection);
        if next_selection.is_none() {
            *self.list_state.offset_mut() = 0;
        }
        self.rows_dirty = false;
    }

    fn finding_matches_view(&self, index: usize) -> bool {
        let finding = &self.findings[index];
        if !self.show_recent && finding.recent {
            return false;
        }
        if let Some(provider) = &self.provider_filter
            && finding.provider.as_ref().map(|source| &source.id) != Some(provider)
        {
            return false;
        }
        let size_matches = match self.size_filter {
            SizeFilter::All => true,
            SizeFilter::Exact => finding.size.accuracy == SizeAccuracy::Exact,
            SizeFilter::Estimated => finding.size.accuracy != SizeAccuracy::Exact,
        };
        size_matches
            && match self.view_mode {
                ViewMode::All => true,
                ViewMode::Safe => finding.safety == Safety::Safe,
                ViewMode::Review => finding.safety == Safety::Review,
                ViewMode::Risky => finding.safety == Safety::Risky,
                ViewMode::Manual => finding.manual_only,
                ViewMode::Selected => self.checked.contains(&index),
            }
    }

    fn finding_matches_query(&self, finding: &Finding) -> bool {
        if self.search_query.is_empty() {
            return true;
        }
        let query = self.search_query.to_lowercase();
        let label = finding.display_label(self.home.as_deref()).to_lowercase();
        finding.rule_id.to_lowercase().contains(&query)
            || finding.category.to_lowercase().contains(&query)
            || finding.section.label().to_lowercase().contains(&query)
            || finding.subgroup.label().to_lowercase().contains(&query)
            || finding.safety.label().contains(&query)
            || finding.confidence.label().contains(&query)
            || finding
                .provider
                .as_ref()
                .is_some_and(|provider| provider.name.to_lowercase().contains(&query))
            || (finding.in_use && "running app in use".contains(&query))
            || (finding.manual_only && "manual review".contains(&query))
            || (finding.report_only && "report only".contains(&query))
            || label.contains(&query)
            || finding.reason.to_lowercase().contains(&query)
            || finding.evidence.iter().any(|evidence| {
                evidence.label.to_lowercase().contains(&query)
                    || evidence.value.to_lowercase().contains(&query)
            })
            || finding.member_paths.iter().any(|member| {
                display_path(member, self.home.as_deref())
                    .to_lowercase()
                    .contains(&query)
            })
            || finding
                .description
                .as_deref()
                .is_some_and(|description| description.to_lowercase().contains(&query))
            || finding
                .impact
                .as_deref()
                .is_some_and(|impact| impact.to_lowercase().contains(&query))
            || finding
                .recommendation
                .as_deref()
                .is_some_and(|recommendation| recommendation.to_lowercase().contains(&query))
    }

    fn sort_findings(&self, indices: &mut [usize]) {
        match self.sort_mode {
            SortMode::Size => indices.sort_by(|&a, &b| {
                self.findings[b]
                    .bytes
                    .cmp(&self.findings[a].bytes)
                    .then_with(|| {
                        category_info(&self.findings[a].category)
                            .order
                            .cmp(&category_info(&self.findings[b].category).order)
                    })
                    .then_with(|| {
                        self.findings[a]
                            .display_label(self.home.as_deref())
                            .cmp(&self.findings[b].display_label(self.home.as_deref()))
                    })
            }),
            SortMode::Age => indices.sort_by(|&a, &b| {
                self.findings[b]
                    .age_days
                    .unwrap_or(0)
                    .cmp(&self.findings[a].age_days.unwrap_or(0))
                    .then_with(|| self.findings[b].bytes.cmp(&self.findings[a].bytes))
            }),
            SortMode::Path => indices.sort_by(|&a, &b| {
                self.findings[a]
                    .display_label(self.home.as_deref())
                    .cmp(&self.findings[b].display_label(self.home.as_deref()))
                    .then_with(|| self.findings[b].bytes.cmp(&self.findings[a].bytes))
            }),
        }
    }

    fn selected_row(&self) -> Option<&VisibleRow> {
        self.list_state
            .selected()
            .and_then(|index| self.rows.get(index))
    }

    fn selected_finding(&self) -> Option<usize> {
        match self.selected_row()? {
            VisibleRow::Finding { index, .. } => Some(*index),
            VisibleRow::Section(_) | VisibleRow::Group { .. } => None,
        }
    }

    fn selected_scope_indices(&self) -> Vec<usize> {
        match self.selected_row() {
            Some(VisibleRow::Section(section)) => self
                .visible_finding_indices()
                .into_iter()
                .filter(|index| self.findings[*index].section == *section)
                .collect(),
            Some(VisibleRow::Group { section, subgroup })
            | Some(VisibleRow::Finding {
                section, subgroup, ..
            }) => self
                .visible_finding_indices()
                .into_iter()
                .filter(|index| {
                    self.findings[*index].section == *section
                        && self.findings[*index].subgroup == *subgroup
                })
                .collect(),
            None => Vec::new(),
        }
    }

    fn selected_scope_label(&self) -> String {
        match self.selected_row() {
            Some(VisibleRow::Section(section)) => section.label().to_string(),
            Some(VisibleRow::Group { subgroup, .. })
            | Some(VisibleRow::Finding { subgroup, .. }) => subgroup.label().to_string(),
            None => "current view".into(),
        }
    }

    fn selectable(finding: &Finding) -> bool {
        !finding.report_only && finding.safety != Safety::Protected
    }

    fn bulk_selectable(finding: &Finding, safe_only: bool) -> bool {
        Self::selectable(finding)
            && !finding.recent
            && !finding.manual_only
            && (!safe_only || finding.safety == Safety::Safe)
    }

    fn visible_finding_indices(&self) -> Vec<usize> {
        self.findings
            .iter()
            .enumerate()
            .filter(|(index, finding)| {
                self.finding_matches_view(*index) && self.finding_matches_query(finding)
            })
            .map(|(index, _)| index)
            .collect()
    }

    fn visible_section_indices(&self, section: Section) -> Vec<usize> {
        self.visible_finding_indices()
            .into_iter()
            .filter(|index| self.findings[*index].section == section)
            .collect()
    }

    fn visible_group_indices(&self, section: Section, subgroup: Subgroup) -> Vec<usize> {
        self.visible_finding_indices()
            .into_iter()
            .filter(|index| {
                self.findings[*index].section == section
                    && self.findings[*index].subgroup == subgroup
            })
            .collect()
    }

    fn toggle_selected(&mut self) {
        if let Some(index) = self.selected_finding() {
            let finding = &self.findings[index];
            if finding.rule_id == "exact-duplicate-files"
                && finding.report_only
                && finding.member_paths.len() > 1
            {
                self.modal = Modal::DuplicateChoice {
                    finding_index: index,
                    retained: 0,
                };
                return;
            }
            if !Self::selectable(finding) {
                self.status =
                    "This finding is protected or report-only and cannot be deleted.".into();
                return;
            }
            if !self.checked.remove(&index) {
                self.checked.insert(index);
                self.status = if finding.manual_only {
                    "Selected one manual-review item. Verify the full path in Details before cleaning."
                        .into()
                } else if finding.recent {
                    "Selected one recently-used item. Confirm that it is no longer needed.".into()
                } else {
                    format!("Selected {}.", finding.display_label(self.home.as_deref()))
                };
            } else {
                self.status = "Finding unselected.".into();
            }
        } else if self.selected_row().is_some() {
            let label = self.selected_scope_label();
            let indices = self.selected_scope_indices();
            let eligible: Vec<usize> = indices
                .iter()
                .copied()
                .filter(|&index| Self::bulk_selectable(&self.findings[index], false))
                .collect();
            let skipped = indices.len().saturating_sub(eligible.len());
            if eligible.is_empty() {
                self.status = format!(
                    "No bulk-selectable findings in {label}; recent and manual-review items must be selected individually."
                );
                return;
            }
            let all_checked = eligible.iter().all(|index| self.checked.contains(index));
            for index in eligible.iter().copied() {
                if all_checked {
                    self.checked.remove(&index);
                } else {
                    self.checked.insert(index);
                }
            }
            self.status = if all_checked {
                format!(
                    "Cleared {} bulk-selectable findings in {label}.",
                    eligible.len()
                )
            } else if skipped > 0 {
                format!(
                    "Selected {} findings in {label}; skipped {skipped} recent/manual-review items.",
                    eligible.len()
                )
            } else {
                format!("Selected {} findings in {label}.", eligible.len())
            };
        }
        self.rows_dirty = true;
    }

    fn select_all(&mut self, safe_only: bool) {
        let indices = self.visible_finding_indices();
        self.checked.clear();
        for index in indices.iter().copied() {
            if Self::bulk_selectable(&self.findings[index], safe_only) {
                self.checked.insert(index);
            }
        }
        let skipped = indices.len().saturating_sub(self.checked.len());
        self.status = if safe_only {
            format!(
                "Selected {} visible safe findings; skipped {skipped} non-safe, recent, manual, or blocked findings.",
                self.checked.len()
            )
        } else {
            format!(
                "Selected {} visible bulk-cleanable findings; skipped {skipped} recent, manual, or blocked findings.",
                self.checked.len()
            )
        };
        self.rows_dirty = true;
    }

    fn checked_bytes(&self) -> u64 {
        self.checked
            .iter()
            .filter_map(|&index| self.findings.get(index))
            .map(|finding| finding.bytes)
            .sum()
    }

    fn checked_breakdown(&self) -> (usize, usize, usize, usize, usize) {
        let mut safe = 0;
        let mut review = 0;
        let mut risky = 0;
        let mut manual = 0;
        let mut recent = 0;
        for finding in self
            .checked
            .iter()
            .filter_map(|&index| self.findings.get(index))
        {
            match finding.safety {
                Safety::Safe => safe += 1,
                Safety::Review => review += 1,
                Safety::Risky => risky += 1,
                Safety::Protected => {}
            }
            manual += usize::from(finding.manual_only);
            recent += usize::from(finding.recent);
        }
        (safe, review, risky, manual, recent)
    }

    fn checked_target_count(&self) -> usize {
        self.checked
            .iter()
            .filter_map(|&index| self.findings.get(index))
            .map(|finding| {
                if finding
                    .native_action
                    .as_ref()
                    .is_some_and(|action| action.action_id == "delete-duplicate-copies")
                {
                    finding.member_paths.len().saturating_sub(1)
                } else {
                    finding.member_paths.len().max(1)
                }
            })
            .sum()
    }

    fn configure_duplicate(&mut self, finding_index: usize, retained: usize) {
        let Some(finding) = self.findings.get_mut(finding_index) else {
            self.modal = Modal::None;
            return;
        };
        let Some(retained_path) = finding.member_paths.get(retained).cloned() else {
            self.modal = Modal::None;
            return;
        };
        let removed = finding.member_paths.len().saturating_sub(1);
        finding.report_only = false;
        finding.manual_only = true;
        finding.state = FindingState::Candidate;
        finding.native_action = Some(ProviderAction {
            provider_id: "duplicates".into(),
            action_id: "delete-duplicate-copies".into(),
            object_id: retained_path.to_string_lossy().into_owned(),
            preview: vec![
                "keep".into(),
                retained_path.to_string_lossy().into_owned(),
                "and move".into(),
                removed.to_string(),
                "duplicate copies to Trash".into(),
            ],
            irreversible: false,
            strong_confirmation: true,
        });
        self.checked.insert(finding_index);
        self.rows_dirty = true;
        self.status = format!(
            "Selected duplicate group; keeping {}.",
            display_path(&retained_path, self.home.as_deref())
        );
        self.modal = Modal::None;
    }

    fn checked_requires_strong_confirmation(&self) -> bool {
        self.permanently
            || self
                .checked
                .iter()
                .filter_map(|index| self.findings.get(*index))
                .any(|finding| {
                    finding.safety == Safety::Risky
                        || finding.requires_strong_confirmation()
                        || finding
                            .native_action
                            .as_ref()
                            .is_some_and(|action| action.irreversible)
                })
    }

    fn move_selection(&mut self, delta: isize) {
        if self.rows.is_empty() {
            self.list_state.select(None);
            return;
        }
        let current = self.list_state.selected().unwrap_or(0);
        let next = if delta.is_negative() {
            current.saturating_sub(delta.unsigned_abs())
        } else {
            current.saturating_add(delta as usize)
        }
        .min(self.rows.len() - 1);
        self.list_state.select(Some(next));
        self.status.clear();
    }

    fn select_first(&mut self) {
        if !self.rows.is_empty() {
            self.list_state.select(Some(0));
            self.status.clear();
        }
    }

    fn select_last(&mut self) {
        if !self.rows.is_empty() {
            self.list_state.select(Some(self.rows.len() - 1));
            self.status.clear();
        }
    }

    fn set_node_open(&mut self, open: bool) {
        match self.selected_row().cloned() {
            Some(VisibleRow::Section(section)) => {
                if open {
                    self.open_sections.insert(section);
                } else {
                    self.open_sections.remove(&section);
                }
                self.rows_dirty = true;
            }
            Some(VisibleRow::Group { section, subgroup }) => {
                if open {
                    self.open_groups.insert((section, subgroup));
                } else {
                    self.open_groups.remove(&(section, subgroup));
                }
                self.rows_dirty = true;
            }
            Some(VisibleRow::Finding {
                section, subgroup, ..
            }) if !open => {
                if let Some(index) = self.rows.iter().position(|row| {
                    matches!(
                        row,
                        VisibleRow::Group {
                            section: candidate_section,
                            subgroup: candidate_subgroup,
                            } if *candidate_section == section && *candidate_subgroup == subgroup
                    )
                }) {
                    self.list_state.select(Some(index));
                }
            }
            _ => {}
        }
    }

    fn toggle_node_open(&mut self) {
        match self.selected_row().cloned() {
            Some(VisibleRow::Section(section)) => {
                if !self.open_sections.remove(&section) {
                    self.open_sections.insert(section);
                }
            }
            Some(VisibleRow::Group { section, subgroup }) => {
                if !self.open_groups.remove(&(section, subgroup)) {
                    self.open_groups.insert((section, subgroup));
                }
            }
            _ => return,
        }
        self.rows_dirty = true;
    }

    fn cycle_provider_filter(&mut self) {
        let mut ids: Vec<_> = self.provider_statuses.keys().cloned().collect();
        ids.sort();
        self.provider_filter = match &self.provider_filter {
            None => ids.first().cloned(),
            Some(current) => ids
                .iter()
                .position(|id| id == current)
                .and_then(|index| ids.get(index + 1).cloned()),
        };
        self.rows_dirty = true;
        self.status = match &self.provider_filter {
            Some(provider) => format!("Showing provider {provider}."),
            None => "Provider filter cleared.".into(),
        };
    }

    fn cycle_min_size(&mut self) {
        const SIZES: &[u64] = &[1 << 20, 10 << 20, 100 << 20, 1 << 30];
        let current = SIZES
            .iter()
            .position(|size| *size == self.provider_settings.min_size_bytes)
            .unwrap_or(0);
        self.provider_settings.min_size_bytes = SIZES[(current + 1) % SIZES.len()];
    }

    fn adjust_min_age(&mut self, forward: bool) {
        const AGES: &[u64] = &[7, 14, 30, 60, 90, 180];
        let current = AGES
            .iter()
            .position(|age| *age == self.provider_settings.min_age_days)
            .unwrap_or(2);
        let next = if forward {
            (current + 1).min(AGES.len() - 1)
        } else {
            current.saturating_sub(1)
        };
        self.provider_settings.min_age_days = AGES[next];
    }

    fn show_detail(&mut self) {
        if self.selected_row().is_some() {
            self.modal = Modal::Detail { scroll: 0 };
        } else {
            self.status = "Select a finding or category first.".into();
        }
    }

    fn on_key(&mut self, code: KeyCode, modifiers: KeyModifiers) -> Option<AppOutcome> {
        if !matches!(self.modal, Modal::None) {
            return self.on_modal_key(code, modifiers);
        }

        match code {
            KeyCode::Char('q') | KeyCode::Esc => return Some(AppOutcome::Quit),
            KeyCode::Char('c') if modifiers.contains(KeyModifiers::CONTROL) => {
                return Some(AppOutcome::Quit);
            }
            KeyCode::Down | KeyCode::Char('j') => self.move_selection(1),
            KeyCode::Up | KeyCode::Char('k') => self.move_selection(-1),
            KeyCode::PageDown => self.move_selection(self.page_size.saturating_sub(1) as isize),
            KeyCode::PageUp => {
                self.move_selection(-(self.page_size.saturating_sub(1) as isize));
            }
            KeyCode::Home | KeyCode::Char('g') => self.select_first(),
            KeyCode::End | KeyCode::Char('G') => self.select_last(),
            KeyCode::Left | KeyCode::Char('h') => self.set_node_open(false),
            KeyCode::Right | KeyCode::Char('l') => {
                if matches!(self.selected_row(), Some(VisibleRow::Finding { .. })) {
                    self.show_detail();
                } else {
                    self.set_node_open(true);
                }
            }
            KeyCode::Enter => {
                if matches!(
                    self.selected_row(),
                    Some(VisibleRow::Section(_) | VisibleRow::Group { .. })
                ) {
                    self.toggle_node_open();
                } else {
                    self.show_detail();
                }
            }
            KeyCode::Char(' ') => self.toggle_selected(),
            KeyCode::Char('a') => self.select_all(true),
            KeyCode::Char('A') => self.select_all(false),
            KeyCode::Char('n') => {
                self.checked.clear();
                self.status = "Selection cleared.".into();
                self.rows_dirty = true;
            }
            KeyCode::Char('p') => {
                self.permanently = !self.permanently;
                self.status = if self.permanently {
                    "Permanent deletion is armed. Every cleanup still requires confirmation.".into()
                } else {
                    "Cleanup mode changed to Trash.".into()
                };
            }
            KeyCode::Char('d') => {
                if self.checked.is_empty() {
                    self.status = "Nothing selected. Press Space to select a finding.".into();
                } else {
                    self.modal = Modal::Confirm;
                }
            }
            KeyCode::Char('i') => self.show_detail(),
            KeyCode::Char('?') => self.modal = Modal::Help { scroll: 0 },
            KeyCode::Char('o') => self.modal = Modal::Providers { scroll: 0 },
            KeyCode::Char('/') => {
                self.modal = Modal::Search {
                    draft: self.search_query.clone(),
                };
            }
            KeyCode::Char('f') => {
                self.view_mode = self.view_mode.next();
                self.rows_dirty = true;
                self.status = format!("View changed to {}.", self.view_mode.label());
            }
            KeyCode::Char('s') => {
                self.sort_mode = self.sort_mode.next();
                self.rows_dirty = true;
                self.status = format!("Sorted by {}.", self.sort_mode.label());
            }
            KeyCode::Char('e') => {
                self.size_filter = self.size_filter.next();
                self.rows_dirty = true;
                self.status = format!("Size evidence filter: {}.", self.size_filter.label());
            }
            KeyCode::Char('u') => {
                self.show_recent = !self.show_recent;
                self.rows_dirty = true;
                self.status = if self.show_recent {
                    "Recent findings are visible.".into()
                } else {
                    "Recent findings are hidden.".into()
                };
            }
            KeyCode::Char('v') => self.cycle_provider_filter(),
            KeyCode::Char('m') => {
                self.provider_settings.profile = match self.provider_settings.profile {
                    ScanProfile::Quick => ScanProfile::Deep,
                    ScanProfile::Deep => ScanProfile::Quick,
                };
                return Some(AppOutcome::Rescan(self.provider_settings.clone()));
            }
            KeyCode::Char('[') => {
                self.adjust_min_age(false);
                return Some(AppOutcome::Rescan(self.provider_settings.clone()));
            }
            KeyCode::Char(']') => {
                self.adjust_min_age(true);
                return Some(AppOutcome::Rescan(self.provider_settings.clone()));
            }
            KeyCode::Char('z') => {
                self.cycle_min_size();
                return Some(AppOutcome::Rescan(self.provider_settings.clone()));
            }
            KeyCode::Char('r') => {
                return Some(AppOutcome::Rescan(self.provider_settings.clone()));
            }
            _ => {}
        }
        None
    }

    fn on_modal_key(&mut self, code: KeyCode, modifiers: KeyModifiers) -> Option<AppOutcome> {
        enum Action {
            None,
            Close,
            Execute,
            ApplySearch(String),
            ConfigureDuplicate {
                finding_index: usize,
                retained: usize,
            },
            CloseAndRescan,
        }

        let strong_confirmation = self.checked_requires_strong_confirmation();
        let duplicate_len = match &self.modal {
            Modal::DuplicateChoice { finding_index, .. } => self
                .findings
                .get(*finding_index)
                .map(|finding| finding.member_paths.len())
                .unwrap_or(0),
            _ => 0,
        };
        let action = match &mut self.modal {
            Modal::Confirm => match code {
                KeyCode::Char('Y') if strong_confirmation => Action::Execute,
                KeyCode::Char('y') | KeyCode::Enter if !strong_confirmation => Action::Execute,
                KeyCode::Esc | KeyCode::Char('n') => Action::Close,
                _ => Action::None,
            },
            Modal::Result {
                rescan_after_close, ..
            } => {
                if *rescan_after_close {
                    Action::CloseAndRescan
                } else {
                    Action::Close
                }
            }
            Modal::Help { scroll } | Modal::Providers { scroll } | Modal::Detail { scroll } => {
                match code {
                    KeyCode::Esc | KeyCode::Char('q') | KeyCode::Char('?') => Action::Close,
                    KeyCode::Down | KeyCode::Char('j') => {
                        *scroll = scroll.saturating_add(1);
                        Action::None
                    }
                    KeyCode::Up | KeyCode::Char('k') => {
                        *scroll = scroll.saturating_sub(1);
                        Action::None
                    }
                    KeyCode::PageDown => {
                        *scroll = scroll.saturating_add(8);
                        Action::None
                    }
                    KeyCode::PageUp => {
                        *scroll = scroll.saturating_sub(8);
                        Action::None
                    }
                    KeyCode::Home => {
                        *scroll = 0;
                        Action::None
                    }
                    _ => Action::None,
                }
            }
            Modal::DuplicateChoice {
                finding_index,
                retained,
            } => match code {
                KeyCode::Esc | KeyCode::Char('n') => Action::Close,
                KeyCode::Down | KeyCode::Char('j') => {
                    *retained = retained
                        .saturating_add(1)
                        .min(duplicate_len.saturating_sub(1));
                    Action::None
                }
                KeyCode::Up | KeyCode::Char('k') => {
                    *retained = retained.saturating_sub(1);
                    Action::None
                }
                KeyCode::Enter => Action::ConfigureDuplicate {
                    finding_index: *finding_index,
                    retained: *retained,
                },
                _ => Action::None,
            },
            Modal::Search { draft } => match code {
                KeyCode::Esc => Action::Close,
                KeyCode::Enter => Action::ApplySearch(draft.trim().to_string()),
                KeyCode::Backspace => {
                    draft.pop();
                    Action::None
                }
                KeyCode::Char('u') if modifiers.contains(KeyModifiers::CONTROL) => {
                    draft.clear();
                    Action::None
                }
                KeyCode::Char(character)
                    if !modifiers.intersects(KeyModifiers::CONTROL | KeyModifiers::META) =>
                {
                    draft.push(character);
                    Action::None
                }
                _ => Action::None,
            },
            Modal::None => Action::None,
        };

        match action {
            Action::None => {}
            Action::Close => self.modal = Modal::None,
            Action::Execute => self.execute(),
            Action::ConfigureDuplicate {
                finding_index,
                retained,
            } => self.configure_duplicate(finding_index, retained),
            Action::ApplySearch(query) => {
                self.search_query = query;
                self.rows_dirty = true;
                self.modal = Modal::None;
                self.status = if self.search_query.is_empty() {
                    "Search cleared.".into()
                } else {
                    format!("Search applied: {}.", self.search_query)
                };
            }
            Action::CloseAndRescan => {
                return Some(AppOutcome::Rescan(self.provider_settings.clone()));
            }
        }
        None
    }

    fn on_mouse(&mut self, mouse: MouseEvent) -> bool {
        match mouse.kind {
            MouseEventKind::ScrollDown => {
                self.move_selection(3);
                true
            }
            MouseEventKind::ScrollUp => {
                self.move_selection(-3);
                true
            }
            MouseEventKind::Down(MouseButton::Left) => {
                let position = Position::new(mouse.column, mouse.row);
                if !self.list_area.contains(position) || self.list_area.height < 3 {
                    return false;
                }
                let first_row = self.list_area.y.saturating_add(1);
                let last_row = self
                    .list_area
                    .y
                    .saturating_add(self.list_area.height.saturating_sub(1));
                if mouse.row < first_row || mouse.row >= last_row {
                    return false;
                }
                let relative = (mouse.row - first_row) as usize;
                let index = self.list_state.offset().saturating_add(relative);
                if index >= self.rows.len() {
                    return false;
                }
                self.list_state.select(Some(index));
                self.status.clear();

                let action_column = self.list_area.x.saturating_add(8);
                if mouse.column < action_column {
                    if matches!(
                        self.selected_row(),
                        Some(VisibleRow::Section(_) | VisibleRow::Group { .. })
                    ) {
                        self.toggle_node_open();
                    } else {
                        self.toggle_selected();
                    }
                }
                true
            }
            _ => false,
        }
    }

    fn execute(&mut self) {
        let mut checked: Vec<usize> = self.checked.iter().copied().collect();
        checked.sort_unstable();
        let plan: Vec<&Finding> = checked
            .iter()
            .filter_map(|&index| self.findings.get(index))
            .filter(|finding| Self::selectable(finding))
            .collect();
        let affected_providers: HashSet<String> = plan
            .iter()
            .filter_map(|finding| {
                finding
                    .provider
                    .as_ref()
                    .map(|provider| provider.id.clone())
            })
            .collect();
        let needs_full_rescan = plan.iter().any(|finding| !finding.is_provider_owned());
        let provider_context = ProviderContext {
            home: self.home.clone(),
            roots: self.roots.clone(),
            repositories: self
                .repositories
                .lock()
                .expect("repositories poisoned")
                .iter()
                .cloned()
                .collect(),
            reference_files: self
                .reference_files
                .lock()
                .expect("references poisoned")
                .clone(),
            reference_complete: self.reference_complete,
            running_commands: crate::util::running_commands(),
            settings: self.provider_settings.clone(),
            runner: Arc::new(CommandRunner::new(self.home.clone())),
            cancel: Arc::new(AtomicBool::new(false)),
            deadline: Instant::now() + ACTION_BUDGET,
        };
        let summary = action::execute_plan(
            &plan,
            &self.engine,
            &self.providers,
            &provider_context,
            self.home.as_deref(),
            &ExecOptions {
                permanently: self.permanently,
            },
        );
        drop(plan);
        match summary {
            Ok(summary) => {
                let mut message = format!(
                    "Freed {}.\n\n{} paths deleted; {} paths failed or were skipped.",
                    human_bytes(summary.freed_bytes),
                    summary.deleted,
                    summary.failed
                );
                if summary.changed > 0 || summary.skipped > 0 {
                    message.push_str(&format!(
                        "\n{} changed since scan; {} were blocked.",
                        summary.changed, summary.skipped
                    ));
                }
                if let Some(first) = summary.messages.first() {
                    message.push_str(&format!("\n\n{first}"));
                }
                if let Some(first) = summary.errors.first() {
                    message.push_str(&format!("\n\nFirst error:\n{first}"));
                }
                let refreshed = if needs_full_rescan {
                    false
                } else {
                    self.refresh_providers(&affected_providers, &provider_context)
                };
                self.checked.clear();
                self.rows_dirty = true;
                message.push_str(if refreshed {
                    "\n\nAffected providers were refreshed. Press any key to close."
                } else {
                    "\n\nPress any key to rescan."
                });
                self.modal = Modal::Result {
                    message,
                    rescan_after_close: !refreshed,
                };
            }
            Err(error) => {
                self.modal = Modal::Result {
                    message: format!("Cleanup failed:\n\n{error:#}"),
                    rescan_after_close: false,
                };
            }
        }
    }

    fn refresh_providers(
        &mut self,
        provider_ids: &HashSet<String>,
        context: &ProviderContext,
    ) -> bool {
        let mut success = true;
        for provider_id in provider_ids {
            let Some(provider) = self.providers.provider(provider_id).cloned() else {
                success = false;
                continue;
            };
            let metadata = provider.metadata();
            self.provider_statuses.insert(
                provider_id.clone(),
                ProviderStatus {
                    provider_id: provider_id.clone(),
                    name: metadata.name.into(),
                    state: ProviderState::Scanning,
                    message: "Refreshing after cleanup.".into(),
                    elapsed_ms: 0,
                    finding_count: 0,
                },
            );
            let started = Instant::now();
            let refresh_context = context.for_action();
            match provider.refresh(&refresh_context) {
                Ok(findings) => {
                    self.retain_findings(|finding| {
                        finding.provider.as_ref().map(|source| &source.id) != Some(provider_id)
                    });
                    let count = findings.len();
                    for finding in findings {
                        self.merge_finding(finding);
                    }
                    self.provider_statuses.insert(
                        provider_id.clone(),
                        ProviderStatus {
                            provider_id: provider_id.clone(),
                            name: metadata.name.into(),
                            state: ProviderState::Ready,
                            message: format!("Refreshed {count} findings."),
                            elapsed_ms: started.elapsed().as_millis(),
                            finding_count: count,
                        },
                    );
                }
                Err(error) => {
                    success = false;
                    self.provider_statuses.insert(
                        provider_id.clone(),
                        ProviderStatus {
                            provider_id: provider_id.clone(),
                            name: metadata.name.into(),
                            state: ProviderState::Failed,
                            message: format!("{error:#}"),
                            elapsed_ms: started.elapsed().as_millis(),
                            finding_count: 0,
                        },
                    );
                }
            }
        }
        success
    }

    fn draw(&mut self, frame: &mut Frame) {
        let area = frame.area();
        if area.width < MIN_TERMINAL_WIDTH || area.height < MIN_TERMINAL_HEIGHT {
            self.list_area = Rect::ZERO;
            self.detail_area = Rect::ZERO;
            draw_too_small(frame, area);
            return;
        }

        let footer_height = 3;
        let layout = Layout::vertical([
            Constraint::Length(3),
            Constraint::Min(5),
            Constraint::Length(footer_height),
        ])
        .split(area);

        self.draw_header(frame, layout[0]);
        let wide = layout[1].width >= 112 && layout[1].height >= 18;
        if wide {
            let columns =
                Layout::horizontal([Constraint::Percentage(66), Constraint::Percentage(34)])
                    .split(layout[1]);
            self.draw_findings(frame, columns[0]);
            self.draw_details(frame, columns[1]);
        } else {
            self.detail_area = Rect::ZERO;
            self.draw_findings(frame, layout[1]);
        }
        self.draw_footer(frame, layout[2]);

        match &self.modal {
            Modal::None => {}
            Modal::Confirm => self.draw_confirm(frame),
            Modal::Result { message, .. } => {
                draw_text_modal(frame, "Cleanup result", message, Color::Green, 0, 76, 13);
            }
            Modal::Help { scroll } => {
                draw_text_modal(frame, "Help", HELP_TEXT, Color::Cyan, *scroll, 86, 26);
            }
            Modal::Providers { scroll } => {
                let text = self.provider_status_text();
                draw_text_modal(
                    frame,
                    "Provider status",
                    &text,
                    Color::Cyan,
                    *scroll,
                    92,
                    26,
                );
            }
            Modal::DuplicateChoice {
                finding_index,
                retained,
            } => self.draw_duplicate_choice(frame, *finding_index, *retained),
            Modal::Detail { scroll } => {
                let text = self.detail_text_plain();
                draw_text_modal(frame, "Details", &text, Color::Cyan, *scroll, 88, 24);
            }
            Modal::Search { draft } => self.draw_search(frame, draft),
        }
    }

    fn draw_header(&self, frame: &mut Frame, area: Rect) {
        let mode = if self.permanently {
            Span::styled(
                " PERMANENT ",
                Style::default()
                    .fg(Color::White)
                    .bg(Color::Red)
                    .add_modifier(Modifier::BOLD),
            )
        } else {
            Span::styled(" Trash ", Style::default().fg(Color::Cyan))
        };
        let phase = if self.scanning {
            format!(
                " 🧺 hokori · {} · run {} · {} scan ·",
                self.provider_settings.profile.label(),
                self.generation,
                self.phase
            )
        } else if self.scan_error.is_some() {
            " 🧺 hokori · scan stopped ·".into()
        } else {
            format!(
                " 🧺 hokori · {} · run {} · scan complete ·",
                self.provider_settings.profile.label(),
                self.generation
            )
        };
        let block = Block::default()
            .borders(Borders::ALL)
            .title(Line::from(vec![Span::raw(phase), mode]))
            .title_alignment(Alignment::Left);
        let inner = block.inner(area);
        frame.render_widget(block, area);

        let (files, dirs, bytes) = self.progress.snapshot();
        let selected_bytes = human_bytes(self.checked_bytes());
        let provider_ready = self
            .provider_statuses
            .values()
            .filter(|status| status.state == ProviderState::Ready)
            .count();
        let provider_active = self
            .provider_statuses
            .values()
            .filter(|status| {
                matches!(
                    status.state,
                    ProviderState::Waiting | ProviderState::Scanning
                )
            })
            .count();
        let provider_issues = self
            .provider_statuses
            .values()
            .filter(|status| {
                matches!(
                    status.state,
                    ProviderState::TimedOut
                        | ProviderState::PermissionDenied
                        | ProviderState::Failed
                )
            })
            .count();
        let summary = if inner.width >= 92 {
            format!(
                "seen {}  ({} files / {} dirs)   {} findings   selected {} ({selected_bytes})   providers {provider_ready}/{provider_active}/{provider_issues}",
                human_bytes(bytes),
                files,
                dirs,
                self.findings.len(),
                self.checked.len()
            )
        } else if inner.width >= 68 {
            format!(
                "{} seen · {} findings · {} selected ({selected_bytes})",
                human_bytes(bytes),
                self.findings.len(),
                self.checked.len()
            )
        } else {
            format!(
                "{} · {} items · {} selected",
                human_bytes(bytes),
                self.findings.len(),
                selected_bytes
            )
        };

        if self.scanning && inner.width >= 82 {
            let columns =
                Layout::horizontal([Constraint::Min(10), Constraint::Length(13)]).split(inner);
            frame.render_widget(Paragraph::new(summary), columns[0]);
            let gauge = Gauge::default()
                .gauge_style(Style::default().fg(Color::Cyan))
                .ratio(spinner_ratio(files))
                .label("scanning");
            frame.render_widget(gauge, columns[1]);
        } else {
            frame.render_widget(Paragraph::new(summary), inner);
        }
    }

    fn draw_findings(&mut self, frame: &mut Frame, area: Rect) {
        self.list_area = area;
        self.page_size = area.height.saturating_sub(2).max(1);

        let search = if self.search_query.is_empty() {
            String::new()
        } else {
            format!(" · /{}", self.search_query)
        };
        let title = format!(
            " findings · {} · {} · {}{} ",
            self.provider_settings.profile.label(),
            self.view_mode.label(),
            self.sort_mode.label(),
            search
        );
        let block = Block::default().borders(Borders::ALL).title(title);

        if self.rows.is_empty() {
            frame.render_widget(block, area);
            let inner = area.inner(Margin {
                horizontal: 2,
                vertical: 1,
            });
            let message = if self.scanning {
                "Scanning. Findings will appear here.".to_string()
            } else if self.scan_error.is_some() {
                "The scan stopped before producing findings. Press r to retry.".to_string()
            } else if self.findings.is_empty() {
                format!("No findings were found under {}.", self.roots_summary())
            } else {
                "No findings match the current search or view.".to_string()
            };
            frame.render_widget(
                Paragraph::new(message)
                    .alignment(Alignment::Center)
                    .fg(Color::DarkGray),
                inner,
            );
            self.list_state.select(None);
            return;
        }

        let content_width = area.width.saturating_sub(6) as usize;
        let items: Vec<ListItem<'static>> = self
            .rows
            .iter()
            .map(|row| ListItem::new(self.row_line(row, content_width)))
            .collect();
        let list = List::new(items)
            .block(block)
            .highlight_symbol("▌ ")
            .highlight_style(
                Style::default()
                    .fg(Color::White)
                    .bg(Color::Rgb(42, 72, 85))
                    .add_modifier(Modifier::BOLD),
            );
        frame.render_stateful_widget(list, area, &mut self.list_state);

        if self.rows.len() > self.page_size as usize {
            let position = self.list_state.selected().unwrap_or(0);
            let mut scrollbar_state = ScrollbarState::new(self.rows.len())
                .position(position)
                .viewport_content_length(self.page_size as usize);
            let scrollbar = Scrollbar::new(ScrollbarOrientation::VerticalRight)
                .begin_symbol(None)
                .end_symbol(None);
            frame.render_stateful_widget(
                scrollbar,
                area.inner(Margin {
                    horizontal: 0,
                    vertical: 1,
                }),
                &mut scrollbar_state,
            );
        }
    }

    fn row_line(&self, row: &VisibleRow, width: usize) -> Line<'static> {
        match row {
            VisibleRow::Section(section) => {
                let indices = self.visible_section_indices(*section);
                let total: u64 = indices
                    .iter()
                    .map(|&index| self.findings[index].bytes)
                    .sum();
                let eligible: Vec<_> = indices
                    .iter()
                    .copied()
                    .filter(|index| Self::bulk_selectable(&self.findings[*index], false))
                    .collect();
                let checked = eligible
                    .iter()
                    .filter(|index| self.checked.contains(index))
                    .count();
                let mark = if checked == 0 {
                    "[ ]"
                } else if checked == eligible.len() {
                    "[x]"
                } else {
                    "[~]"
                };
                let open = !self.search_query.is_empty()
                    || self.view_mode == ViewMode::Selected
                    || self.open_sections.contains(section);
                let disclosure = if open { "▾" } else { "▸" };
                let text = format!(
                    "{disclosure} {mark} {}  {}  ({} {})",
                    section.label(),
                    human_bytes(total),
                    indices.len(),
                    count_label(indices.len(), "finding")
                );
                Line::styled(
                    truncate_end(&text, width),
                    Style::default().add_modifier(Modifier::BOLD),
                )
            }
            VisibleRow::Group { section, subgroup } => {
                let indices = self.visible_group_indices(*section, *subgroup);
                let total: u64 = indices
                    .iter()
                    .map(|index| self.findings[*index].bytes)
                    .sum();
                let eligible: Vec<_> = indices
                    .iter()
                    .copied()
                    .filter(|index| Self::bulk_selectable(&self.findings[*index], false))
                    .collect();
                let checked = eligible
                    .iter()
                    .filter(|index| self.checked.contains(index))
                    .count();
                let mark = if checked == 0 {
                    "[ ]"
                } else if checked == eligible.len() {
                    "[x]"
                } else {
                    "[~]"
                };
                let open = !self.search_query.is_empty()
                    || self.view_mode == ViewMode::Selected
                    || self.open_groups.contains(&(*section, *subgroup));
                let disclosure = if open { "▾" } else { "▸" };
                let text = format!(
                    "  {disclosure} {mark} {}  {}  ({} {})",
                    subgroup.label(),
                    human_bytes(total),
                    indices.len(),
                    count_label(indices.len(), "finding")
                );
                Line::styled(truncate_end(&text, width), Style::default().fg(Color::Cyan))
            }
            VisibleRow::Finding { index, .. } => {
                let finding = &self.findings[*index];
                let checkbox = if self.checked.contains(index) {
                    Span::styled("[x]", Style::default().fg(Color::Green))
                } else if !Self::selectable(finding) {
                    Span::styled("[-]", Style::default().fg(Color::DarkGray))
                } else if finding.manual_only || finding.recent {
                    Span::styled("[ ]", Style::default().fg(Color::Yellow))
                } else {
                    Span::raw("[ ]")
                };
                let (safety, color) = match finding.safety {
                    Safety::Safe => ("safe", Color::Green),
                    Safety::Review => ("review", Color::Yellow),
                    Safety::Risky => ("risky", Color::Red),
                    Safety::Protected => ("protected", Color::DarkGray),
                };
                let age = finding
                    .age_days
                    .map(|days| format!("{days}d"))
                    .unwrap_or_else(|| "-".into());
                let size = format!(
                    "{}{}",
                    if finding.size.accuracy == SizeAccuracy::Exact {
                        ""
                    } else {
                        "~"
                    },
                    human_bytes(finding.bytes)
                );
                let prefix = format!("    {}  {:>9}  {:<9} {:>5}  ", "[]", size, safety, age);
                let available = width.saturating_sub(prefix.chars().count());
                let path = self.finding_path_and_flags(finding);
                Line::from(vec![
                    Span::raw("    "),
                    checkbox,
                    Span::styled(
                        format!("  {size:>9}  "),
                        Style::default().add_modifier(Modifier::BOLD),
                    ),
                    Span::styled(format!("{safety:<9} "), Style::default().fg(color)),
                    Span::styled(format!("{age:>5}  "), Style::default().fg(Color::DarkGray)),
                    Span::raw(truncate_middle(&path, available)),
                ])
            }
        }
    }

    fn finding_path_and_flags(&self, finding: &Finding) -> String {
        let mut output = finding.display_label(self.home.as_deref());
        let category = category_info(&finding.category);
        if category.label != finding.subgroup.label() {
            output.push_str(&format!(" · {} {}", category.icon, category.label));
        }
        if finding.recent {
            output.push_str(" · recent");
        }
        if finding.in_use {
            output.push_str(" · running");
        }
        if finding.manual_only {
            output.push_str(" · manual");
        }
        if finding.report_only {
            output.push_str(" · report only");
        }
        if let Some(provider) = &finding.provider {
            output.push_str(&format!(" · {}", provider.name));
        }
        if finding.files > 1 {
            output.push_str(&format!(" · {} files", finding.files));
        }
        output
    }

    fn draw_details(&mut self, frame: &mut Frame, area: Rect) {
        self.detail_area = area;
        let block = Block::default().borders(Borders::ALL).title(" details ");
        let inner = block.inner(area);
        frame.render_widget(block, area);
        frame.render_widget(
            Paragraph::new(self.detail_text())
                .wrap(Wrap { trim: false })
                .scroll((0, 0)),
            inner,
        );
    }

    fn detail_text(&self) -> Text<'static> {
        match self.selected_row() {
            Some(VisibleRow::Finding { index, .. }) => {
                let finding = &self.findings[*index];
                let category = category_info(&finding.category);
                let mut lines = vec![
                    detail_line("Finding", finding.display_label(self.home.as_deref())),
                    detail_line("Rule", finding.rule_id.clone()),
                    detail_line(
                        "Section",
                        format!("{} / {}", finding.section.label(), finding.subgroup.label()),
                    ),
                    detail_line("Category", format!("{} ({})", category.label, category.id)),
                    detail_line("Category info", category.description.to_string()),
                    detail_line(
                        "Provider",
                        finding
                            .provider
                            .as_ref()
                            .map(|provider| provider.name.clone())
                            .unwrap_or_else(|| "Filesystem rules".into()),
                    ),
                    detail_line("Safety", finding.safety.label().to_string()),
                    detail_line("Confidence", finding.confidence.label().to_string()),
                    detail_line("State", format!("{:?}", finding.state).to_lowercase()),
                    detail_line("Reclaimable", human_bytes(finding.size.reclaimable)),
                    detail_line(
                        "Size evidence",
                        format!("{:?}", finding.size.accuracy).to_lowercase(),
                    ),
                    detail_line("Logical", human_bytes(finding.size.logical)),
                    detail_line("Physical", human_bytes(finding.size.physical)),
                    detail_line("Unique", human_bytes(finding.size.unique)),
                    detail_line("Shared", human_bytes(finding.size.shared)),
                    detail_line(
                        "Age",
                        finding
                            .age_days
                            .map(|days| format!("{days} days"))
                            .unwrap_or_else(|| "unknown".into()),
                    ),
                    Line::raw(""),
                ];
                if finding.files > 0 || finding.dirs > 0 {
                    lines.insert(
                        lines.len() - 1,
                        detail_line(
                            "Contents",
                            format!(
                                "{} {} · {} {}",
                                finding.files,
                                count_label(finding.files as usize, "file"),
                                finding.dirs,
                                count_label(finding.dirs as usize, "dir")
                            ),
                        ),
                    );
                }
                if finding.member_paths.is_empty() {
                    if !finding.path.as_os_str().is_empty() {
                        lines.push(detail_line(
                            "Path",
                            display_path(&finding.path, self.home.as_deref()),
                        ));
                    }
                } else {
                    lines.push(detail_line(
                        "Matched",
                        format!(
                            "{} {}",
                            finding.member_paths.len(),
                            count_label(finding.member_paths.len(), "path")
                        ),
                    ));
                    lines.push(Line::styled(
                        "Matched paths",
                        Style::default()
                            .fg(Color::Cyan)
                            .add_modifier(Modifier::BOLD),
                    ));
                    for member in finding.member_paths.iter().take(100) {
                        lines.push(Line::raw(format!(
                            "  {}",
                            display_path(member, self.home.as_deref())
                        )));
                    }
                    if finding.member_paths.len() > 100 {
                        lines.push(Line::raw(format!(
                            "  … {} more paths",
                            finding.member_paths.len() - 100
                        )));
                    }
                    lines.push(Line::raw(""));
                }
                if !finding.reason.is_empty() {
                    lines.push(detail_line("Why", finding.reason.clone()));
                    lines.push(Line::raw(""));
                }
                for evidence in &finding.evidence {
                    lines.push(detail_line(&evidence.label, evidence.value.clone()));
                }
                if !finding.evidence.is_empty() {
                    lines.push(Line::raw(""));
                }
                if finding.manual_only {
                    lines.push(Line::styled(
                        if finding.rule_id == "gitignored" {
                            "Manual review: this may contain source, SDKs, databases, or session data."
                        } else {
                            "Manual review: this finding is excluded from bulk selection. Verify its paths and impact before cleaning."
                        },
                        Style::default().fg(Color::Yellow),
                    ));
                }
                if finding.in_use {
                    lines.push(Line::styled(
                        "In use: an owning application appears to be running. Close it before cleanup.",
                        Style::default().fg(Color::Yellow),
                    ));
                }
                if finding.recent {
                    lines.push(Line::styled(
                        "Recent: this item was used inside the rule's safety window.",
                        Style::default().fg(Color::Yellow),
                    ));
                }
                if finding.report_only {
                    lines.push(Line::styled(
                        "Report only: this item cannot be deleted from the TUI.",
                        Style::default().fg(Color::DarkGray),
                    ));
                }
                if let Some(description) = &finding.description {
                    lines.push(Line::raw(""));
                    lines.push(detail_line("What", description.clone()));
                }
                if let Some(impact) = &finding.impact {
                    lines.push(Line::raw(""));
                    lines.push(detail_line("If cleaned", impact.clone()));
                }
                if let Some(recommendation) = &finding.recommendation {
                    lines.push(Line::raw(""));
                    lines.push(detail_line("Recommendation", recommendation.clone()));
                }
                if let Some(action) = finding.action_preview() {
                    lines.push(Line::raw(""));
                    lines.push(detail_line(
                        "Deletion",
                        if finding.native_action.is_some() {
                            if finding
                                .native_action
                                .as_ref()
                                .is_some_and(|action| action.irreversible)
                            {
                                "Native command (not restorable from Trash)".into()
                            } else {
                                "Provider-managed file action".into()
                            }
                        } else if self.permanently {
                            "Permanent filesystem deletion".into()
                        } else {
                            "Move to Trash".into()
                        },
                    ));
                    lines.push(detail_line("Action", action));
                }
                lines.push(Line::raw(""));
                lines.push(Line::styled(
                    if self.checked.contains(index) {
                        "Selected for cleanup."
                    } else if Self::selectable(finding) {
                        "Press Space to select this finding."
                    } else {
                        "This finding cannot be selected."
                    },
                    Style::default().fg(Color::Cyan),
                ));
                Text::from(lines)
            }
            Some(VisibleRow::Section(section)) => {
                let indices = self.visible_section_indices(*section);
                let bytes: u64 = indices
                    .iter()
                    .map(|&index| self.findings[index].bytes)
                    .sum();
                let checked = indices
                    .iter()
                    .filter(|index| self.checked.contains(index))
                    .count();
                let bulk = indices
                    .iter()
                    .filter(|&&index| Self::bulk_selectable(&self.findings[index], false))
                    .count();
                Text::from(vec![
                    detail_line("Section", section.label().to_string()),
                    detail_line(
                        "Visible",
                        format!(
                            "{} {}",
                            indices.len(),
                            count_label(indices.len(), "finding")
                        ),
                    ),
                    detail_line("Reclaimable", human_bytes(bytes)),
                    detail_line("Selected", checked.to_string()),
                    detail_line("Bulk eligible", bulk.to_string()),
                    Line::raw(""),
                    Line::raw(
                        "Space toggles only bulk-eligible findings. Recent and manual-review findings must be selected individually.",
                    ),
                ])
            }
            Some(VisibleRow::Group { section, subgroup }) => {
                let indices = self.visible_group_indices(*section, *subgroup);
                let bytes: u64 = indices
                    .iter()
                    .map(|index| self.findings[*index].bytes)
                    .sum();
                let checked = indices
                    .iter()
                    .filter(|index| self.checked.contains(index))
                    .count();
                let bulk = indices
                    .iter()
                    .filter(|index| Self::bulk_selectable(&self.findings[**index], false))
                    .count();
                Text::from(vec![
                    detail_line("Section", section.label().to_string()),
                    detail_line("Group", subgroup.label().to_string()),
                    detail_line(
                        "Visible",
                        format!(
                            "{} {}",
                            indices.len(),
                            count_label(indices.len(), "finding")
                        ),
                    ),
                    detail_line("Reclaimable", human_bytes(bytes)),
                    detail_line("Selected", checked.to_string()),
                    detail_line("Bulk eligible", bulk.to_string()),
                    Line::raw(""),
                    Line::raw(
                        "Space toggles only bulk-eligible findings. Recent and manual-review findings must be selected individually.",
                    ),
                ])
            }
            None => Text::from("Select a section, group, or finding to inspect it."),
        }
    }

    fn detail_text_plain(&self) -> String {
        self.detail_text()
            .lines
            .iter()
            .map(|line| {
                line.spans
                    .iter()
                    .map(|span| span.content.as_ref())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn draw_footer(&self, frame: &mut Frame, area: Rect) {
        let lines = Layout::vertical([
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Length(1),
        ])
        .split(area);
        let status = if self.status.is_empty() {
            self.selection_status()
        } else {
            self.status.clone()
        };
        frame.render_widget(
            Paragraph::new(truncate_end(&status, area.width as usize)).fg(Color::Yellow),
            lines[0],
        );

        let (primary, secondary) = if area.width >= 108 {
            (
                "↑↓ move  PgUp/PgDn page  ←→ fold  Space select  / search  i details  d clean",
                "a safe-all  A all  f view  s sort  v provider  e evidence  u recent  o status",
            )
        } else if area.width >= 78 {
            (
                "↑↓ move  PgUp/PgDn page  Space select  / search  i details  d clean",
                "a safe-all  f view  s sort  v provider  o status  ? help  q quit",
            )
        } else {
            (
                "↑↓ move  Space select  / search  i details",
                "f view  d clean  o status  ? help  q quit",
            )
        };
        frame.render_widget(
            Paragraph::new(truncate_end(primary, area.width as usize)).fg(Color::DarkGray),
            lines[1],
        );
        let context = format!(
            "{}   {} · age {}d · min {} · view {} · sort {} · {} · recent {}{}{}{}",
            secondary,
            self.provider_settings.profile.label(),
            self.provider_settings.min_age_days,
            human_bytes(self.provider_settings.min_size_bytes),
            self.view_mode.label(),
            self.sort_mode.label(),
            self.size_filter.label(),
            if self.show_recent { "shown" } else { "hidden" },
            self.provider_filter
                .as_ref()
                .map(|provider| format!(" · provider {provider}"))
                .unwrap_or_default(),
            if self.search_query.is_empty() {
                String::new()
            } else {
                format!(" · search {}", self.search_query)
            },
            " · m mode · [/] age · z size · r rescan · p trash/permanent",
        );
        frame.render_widget(
            Paragraph::new(truncate_end(&context, area.width as usize)).fg(Color::DarkGray),
            lines[2],
        );
    }

    fn selection_status(&self) -> String {
        match self.selected_row() {
            Some(VisibleRow::Finding { index, .. }) => {
                let finding = &self.findings[*index];
                format!(
                    "{} / {} · {} · {} · {}{}",
                    finding.section.label(),
                    finding.subgroup.label(),
                    finding.display_label(self.home.as_deref()),
                    finding.safety.label(),
                    if finding.size.accuracy == SizeAccuracy::Exact {
                        ""
                    } else {
                        "~"
                    },
                    human_bytes(finding.bytes),
                )
            }
            Some(VisibleRow::Section(section)) => format!("Section: {}.", section.label()),
            Some(VisibleRow::Group { section, subgroup }) => {
                format!("{} / {}.", section.label(), subgroup.label())
            }
            None if self.scanning => "Scanning.".into(),
            None => "No visible findings.".into(),
        }
    }

    fn roots_summary(&self) -> String {
        let shown: Vec<String> = self
            .roots
            .iter()
            .take(2)
            .map(|root| display_path(root, self.home.as_deref()))
            .collect();
        if self.roots.len() > shown.len() {
            format!(
                "{} and {} more roots",
                shown.join(", "),
                self.roots.len() - shown.len()
            )
        } else {
            shown.join(", ")
        }
    }

    fn provider_status_text(&self) -> String {
        let mut statuses: Vec<_> = self.provider_statuses.values().collect();
        statuses.sort_by(|left, right| left.name.cmp(&right.name));
        let mut lines = vec![format!(
            "Mode: {}  Age: {} days  Minimum: {}",
            self.provider_settings.profile.label(),
            self.provider_settings.min_age_days,
            human_bytes(self.provider_settings.min_size_bytes)
        )];
        lines.push(String::new());
        for status in statuses {
            let metadata = self
                .providers
                .provider(&status.provider_id)
                .map(|provider| provider.metadata());
            let cost = metadata
                .map(|metadata| metadata.cost.label())
                .unwrap_or("unknown");
            let network = metadata.is_some_and(|metadata| metadata.network_in_deep_scan);
            lines.push(format!(
                "{} [{}]  {} ms  {} findings  cost {}{}",
                status.name,
                status.state.label(),
                status.elapsed_ms,
                status.finding_count,
                cost,
                if network {
                    "  network in deep mode"
                } else {
                    ""
                }
            ));
            if !status.message.is_empty() {
                lines.push(format!("  {}", status.message));
            }
        }
        lines.join("\n")
    }

    fn draw_confirm(&self, frame: &mut Frame) {
        let (safe, review, risky, manual, recent) = self.checked_breakdown();
        let first = self
            .checked
            .iter()
            .filter_map(|&index| self.findings.get(index))
            .next()
            .map(|finding| finding.display_label(self.home.as_deref()))
            .unwrap_or_default();
        let selected: Vec<_> = self
            .checked
            .iter()
            .filter_map(|index| self.findings.get(*index))
            .collect();
        let native = selected
            .iter()
            .filter(|finding| finding.native_action.is_some())
            .count();
        let filesystem = selected.len().saturating_sub(native);
        let irreversible = selected
            .iter()
            .filter(|finding| {
                finding
                    .native_action
                    .as_ref()
                    .is_some_and(|action| action.irreversible)
                    || (finding.native_action.is_none() && self.permanently)
            })
            .count();
        let previews = selected
            .iter()
            .filter_map(|finding| finding.action_preview())
            .take(4)
            .collect::<Vec<_>>();
        let strong = self.checked_requires_strong_confirmation();
        let target_count = self.checked_target_count();
        let target_summary = if target_count == self.checked.len() {
            format!(
                "{} {}",
                self.checked.len(),
                count_label(self.checked.len(), "finding")
            )
        } else {
            format!(
                "{} {} ({} {})",
                self.checked.len(),
                count_label(self.checked.len(), "finding"),
                target_count,
                count_label(target_count, "path")
            )
        };
        let mut message = format!(
            "Clean {} across {target_summary}?\n\nFilesystem {filesystem} · Native {native} · Irreversible {irreversible}\nSafe {safe} · Review {review} · Risky {risky}\nManual {manual} · Recent {recent}",
            human_bytes(self.checked_bytes()),
        );
        if !first.is_empty() {
            message.push_str(&format!("\n\nFirst selected:\n{first}"));
        }
        if !previews.is_empty() {
            message.push_str("\n\nActions:");
            for preview in previews {
                message.push_str(&format!("\n  {preview}"));
            }
        }
        message.push_str(if strong {
            "\n\nPress Shift+Y to confirm. Esc or n cancels."
        } else {
            "\n\nEnter or y confirms. Esc or n cancels."
        });
        draw_text_modal(
            frame,
            if irreversible > 0 || self.permanently {
                "Confirm irreversible cleanup"
            } else if strong {
                "Confirm reviewed cleanup"
            } else {
                "Confirm cleanup"
            },
            &message,
            if irreversible > 0 || self.permanently {
                Color::Red
            } else {
                Color::Yellow
            },
            0,
            88,
            20,
        );
    }

    fn draw_duplicate_choice(&self, frame: &mut Frame, finding_index: usize, retained: usize) {
        let Some(finding) = self.findings.get(finding_index) else {
            return;
        };
        let start = retained.saturating_sub(5);
        let end = (start + 11).min(finding.member_paths.len());
        let mut body = String::from(
            "Choose the copy to keep. Every other verified copy will move to Trash.\n\n",
        );
        for (index, path) in finding
            .member_paths
            .iter()
            .enumerate()
            .skip(start)
            .take(end.saturating_sub(start))
        {
            body.push_str(if index == retained {
                "> KEEP  "
            } else {
                "        "
            });
            body.push_str(&display_path(path, self.home.as_deref()));
            body.push('\n');
        }
        if end < finding.member_paths.len() {
            body.push_str(&format!(
                "        ... {} more\n",
                finding.member_paths.len() - end
            ));
        }
        body.push_str("\nUp/Down changes the retained copy. Enter confirms. Esc cancels.");
        draw_text_modal(
            frame,
            "Choose retained duplicate",
            &body,
            Color::Yellow,
            0,
            100,
            22,
        );
    }

    fn draw_search(&self, frame: &mut Frame, draft: &str) {
        let area = modal_rect(frame.area(), 76, 7);
        frame.render_widget(Clear, area);
        let block = Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Cyan))
            .title(" Search findings ");
        let inner = block.inner(area);
        frame.render_widget(block, area);
        let body = format!("{}_\n\nEnter applies. Esc cancels. Ctrl+U clears.", draft);
        frame.render_widget(Paragraph::new(body).wrap(Wrap { trim: false }), inner);
    }
}

fn detail_line(label: &str, value: String) -> Line<'static> {
    Line::from(vec![
        Span::styled(
            format!("{label}: "),
            Style::default()
                .fg(Color::DarkGray)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(value),
    ])
}

fn draw_too_small(frame: &mut Frame, area: Rect) {
    let body = format!(
        "🧺 hokori needs at least {MIN_TERMINAL_WIDTH} columns × {MIN_TERMINAL_HEIGHT} rows.\n\nCurrent size: {} × {}\n\nResize the terminal, or press q to quit.",
        area.width, area.height
    );
    frame.render_widget(
        Paragraph::new(body)
            .block(Block::default().borders(Borders::ALL).title(" 🧺 hokori "))
            .alignment(Alignment::Center)
            .wrap(Wrap { trim: false }),
        area,
    );
}

fn draw_text_modal(
    frame: &mut Frame,
    title: &str,
    body: &str,
    color: Color,
    scroll: u16,
    preferred_width: u16,
    preferred_height: u16,
) {
    let area = modal_rect(frame.area(), preferred_width, preferred_height);
    frame.render_widget(Clear, area);
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(color))
        .title(format!(" {title} "));
    let paragraph = Paragraph::new(body.to_string())
        .block(block)
        .wrap(Wrap { trim: false })
        .scroll((scroll, 0));
    frame.render_widget(paragraph, area);
}

fn modal_rect(area: Rect, preferred_width: u16, preferred_height: u16) -> Rect {
    let width = preferred_width.min(area.width.saturating_sub(4)).max(1);
    let height = preferred_height.min(area.height.saturating_sub(2)).max(1);
    Rect {
        x: area.x + area.width.saturating_sub(width) / 2,
        y: area.y + area.height.saturating_sub(height) / 2,
        width,
        height,
    }
}

fn truncate_end(value: &str, max_chars: usize) -> String {
    let count = value.chars().count();
    if count <= max_chars {
        return value.to_string();
    }
    if max_chars <= 1 {
        return "…".chars().take(max_chars).collect();
    }
    let mut output: String = value.chars().take(max_chars - 1).collect();
    output.push('…');
    output
}

fn truncate_middle(value: &str, max_chars: usize) -> String {
    let count = value.chars().count();
    if count <= max_chars {
        return value.to_string();
    }
    if max_chars <= 1 {
        return "…".chars().take(max_chars).collect();
    }
    let left = (max_chars - 1) * 2 / 3;
    let right = max_chars - 1 - left;
    let start: String = value.chars().take(left).collect();
    let end: String = value
        .chars()
        .rev()
        .take(right)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    format!("{start}…{end}")
}

fn count_label(count: usize, singular: &'static str) -> &'static str {
    if count == 1 {
        singular
    } else {
        match singular {
            "finding" => "findings",
            "file" => "files",
            "dir" => "dirs",
            "path" => "paths",
            _ => singular,
        }
    }
}

fn spinner_ratio(files: u64) -> f64 {
    ((files as f64 / 5000.0).sin().abs()).clamp(0.05, 1.0)
}

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(0)
}

const HELP_TEXT: &str = "\
Navigation
  Up/Down or j/k       Move one row
  PageUp/PageDown      Move one page
  Home/End or g/G      First/last row
  Left/Right or h/l    Collapse/open section or group
  Enter                Open section/group or show finding details
  Mouse wheel/click    Scroll or select

Review
  /                    Search rule, category, path, safety, or impact
  f                    Cycle view: all, safe, review, risky, manual, selected
  s                    Cycle sort: size, age, path
  v                    Cycle native-provider filter
  e                    Cycle exact/estimated size evidence
  u                    Show or hide recent findings
  i                    Show full details
  o                    Show provider availability and scan state

Selection
  Space                Toggle one finding
  Space on section     Toggle bulk-eligible findings in that scope
  a                    Select visible safe findings
  A                    Select all visible bulk-cleanable findings
  n                    Clear all selections

Recent and manual-review findings are never bulk-selected.
Git-ignored findings may contain source, SDKs, databases, or session data.
They can be selected individually only after reviewing the full path.
Findings owned by a running app become manual-review for that scan.
Protected and report-only findings cannot be selected.

Actions
  d                    Clean selected findings
  p                    Toggle Trash/permanent mode
  r                    Rescan current roots
  m                    Toggle quick/deep scan and rescan
  [ / ]                Lower/raise provider age threshold
  z                    Cycle provider minimum size
  ?                    Open/close this help
  q or Esc             Quit

Native tool actions are not restorable from Trash and may require Shift+Y.
Help and Details scroll with Up/Down or PageUp/PageDown.";

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::{Confidence, FindingSize, FindingState, FindingTarget};
    use crate::taxonomy::category_info;

    fn finding(category: &str, safety: Safety, recent: bool, manual_only: bool) -> Finding {
        let info = category_info(category);
        Finding {
            stable_id: format!("path:{category}:/tmp/{category}"),
            rule_id: category.into(),
            category: category.into(),
            section: info.section,
            subgroup: info.subgroup,
            safety,
            target: FindingTarget::Filesystem {
                path: PathBuf::from(format!("/tmp/{category}")),
            },
            path: PathBuf::from(format!("/tmp/{category}")),
            bytes: 1024,
            size: FindingSize::exact_physical(1024),
            files: 1,
            dirs: 0,
            age_days: Some(10),
            recent,
            report_only: false,
            in_use: false,
            manual_only,
            confidence: Confidence::High,
            state: if recent {
                FindingState::Recent
            } else {
                FindingState::Candidate
            },
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

    fn test_app(findings: Vec<Finding>) -> App {
        let engine = Arc::new(Engine::compile(Vec::new(), &[], None).unwrap());
        let providers = Arc::new(ProviderRegistry::empty());
        let progress = Arc::new(Progress::new());
        let repositories = Arc::new(Mutex::new(HashSet::new()));
        let reference_files = Arc::new(Mutex::new(Vec::new()));
        let (_tx, rx) = mpsc::sync_channel(1);
        let mut app = App::new(
            engine,
            providers,
            ProviderSettings::default(),
            vec![PathBuf::from("/tmp")],
            None,
            progress,
            repositories,
            reference_files,
            rx,
            1,
            true,
        );
        app.findings = findings;
        app.scanning = false;
        for finding in &app.findings {
            app.open_sections.insert(finding.section);
            app.open_groups.insert((finding.section, finding.subgroup));
        }
        app.rebuild_rows();
        app
    }

    #[test]
    fn category_bulk_selection_skips_recent_and_manual_findings() {
        let mut app = test_app(vec![
            finding("mixed", Safety::Safe, false, false),
            finding("mixed", Safety::Review, true, false),
            finding("mixed", Safety::Risky, false, true),
        ]);
        app.list_state.select(Some(0));
        app.toggle_selected();

        assert_eq!(app.checked, HashSet::from([0]));
        assert!(app.status.contains("skipped 2"));
    }

    #[test]
    fn safe_select_all_respects_the_current_view() {
        let mut app = test_app(vec![
            finding("mixed", Safety::Safe, false, false),
            finding("mixed", Safety::Review, false, false),
            finding("mixed", Safety::Safe, true, false),
        ]);
        app.select_all(true);
        assert_eq!(app.checked, HashSet::from([0]));
    }

    #[test]
    fn search_matches_full_path_and_opens_results() {
        let mut app = test_app(vec![
            finding("mixed", Safety::Safe, false, false),
            finding("other", Safety::Safe, false, false),
        ]);
        app.search_query = "other".into();
        app.rows_dirty = true;
        app.rebuild_rows();

        assert_eq!(app.rows.len(), 3);
        assert!(matches!(app.rows[2], VisibleRow::Finding { index: 1, .. }));
    }

    #[test]
    fn aggregate_findings_search_and_display_member_paths() {
        let mut aggregate = finding("archives", Safety::Review, false, true);
        aggregate.member_paths = vec![
            PathBuf::from("/tmp/Downloads/first.zip"),
            PathBuf::from("/tmp/Downloads/second.zip"),
        ];
        aggregate.target = FindingTarget::GroupedPaths {
            paths: aggregate.member_paths.clone(),
            label: "2 matched paths".into(),
        };
        let mut app = test_app(vec![aggregate]);
        app.search_query = "second.zip".into();
        app.rows_dirty = true;
        app.rebuild_rows();

        assert_eq!(app.rows.len(), 3);
        app.list_state.select(Some(2));
        assert!(
            app.finding_path_and_flags(&app.findings[0])
                .contains("2 matched paths")
        );
        assert!(app.detail_text_plain().contains("second.zip"));
    }

    #[test]
    fn truncation_marks_clipped_content() {
        assert_eq!(truncate_end("abcdef", 4), "abc…");
        assert_eq!(truncate_middle("abcdefghij", 6), "abc…ij");
    }

    #[test]
    fn modal_rect_stays_inside_small_terminals() {
        let terminal = Rect::new(0, 0, 60, 18);
        let modal = modal_rect(terminal, 80, 30);
        assert!(modal.width <= terminal.width);
        assert!(modal.height <= terminal.height);
        assert!(terminal.contains(modal.as_position()));
    }
}
