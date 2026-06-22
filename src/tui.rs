//! Interactive front-end: streams findings from the engine into a category
//! tree, lets you multi-select, and cleans the checked items to the Trash.

use anyhow::Result;
use std::collections::{BTreeMap, HashSet};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ratatui::Frame;
use ratatui::crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use ratatui::layout::{Alignment, Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style, Stylize};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Gauge, Paragraph, Wrap};
use tui_tree_widget::{Tree, TreeItem, TreeState};

use crate::ScanArgs;
use crate::action::{self, ExecOptions};
use crate::compiler::Engine;
use crate::engine::{ScanCtx, ScanEvent, discovery_scan, targeted_scan};
use crate::report::{Finding, Progress, display_path, human_bytes};
use crate::rules::Safety;
use crate::walk::InodeDedupe;

const EVENT_QUEUE_CAPACITY: usize = 1024;

pub fn run(
    engine: Arc<Engine>,
    roots: Vec<PathBuf>,
    scan: ScanArgs,
    home: Option<PathBuf>,
) -> Result<()> {
    let progress = Arc::new(Progress::new());
    let cancel = Arc::new(AtomicBool::new(false));
    let (tx, rx) = mpsc::sync_channel::<ScanEvent>(EVENT_QUEUE_CAPACITY);

    // Background scan thread streams findings; the UI owns `rx`.
    let scan_thread = {
        let engine = Arc::clone(&engine);
        let progress = Arc::clone(&progress);
        let cancel = Arc::clone(&cancel);
        let no_targeted = scan.no_targeted;
        let no_discovery = scan.no_discovery;
        std::thread::Builder::new()
            .stack_size(16 * 1024 * 1024)
            .spawn(move || {
                let dedupe = InodeDedupe::new();
                let now = now_secs();
                let phase_tx = tx.clone();
                let sink = Mutex::new(tx);

                let mut claimed = HashSet::new();
                if !no_targeted {
                    let _ = phase_tx.send(ScanEvent::Phase("targeted"));
                    let ctx = ScanCtx {
                        engine: engine.as_ref(),
                        dedupe: &dedupe,
                        progress: Some(&progress),
                        now,
                        sink: Some(&sink),
                        cancel: Some(&cancel),
                    };
                    claimed = targeted_scan(&ctx).claimed;
                }
                if !no_discovery && !cancel.load(Ordering::Relaxed) {
                    let _ = phase_tx.send(ScanEvent::Phase("discovery"));
                    let ctx = ScanCtx {
                        engine: engine.as_ref(),
                        dedupe: &dedupe,
                        progress: Some(&progress),
                        now,
                        sink: Some(&sink),
                        cancel: Some(&cancel),
                    };
                    discovery_scan(&ctx, &roots, &claimed);
                }
                let _ = phase_tx.send(ScanEvent::Done);
            })?
    };

    let mut app = App::new(engine, home, progress, rx);
    let mut terminal = ratatui::init();
    let result = app.run(&mut terminal);
    ratatui::restore();
    cancel.store(true, Ordering::Relaxed);
    drop(app);
    let _ = scan_thread.join();
    result
}

struct App {
    engine: Arc<Engine>,
    home: Option<PathBuf>,
    progress: Arc<Progress>,
    rx: Receiver<ScanEvent>,

    findings: Vec<Finding>,
    checked: HashSet<usize>,
    tree_state: TreeState<String>,
    tree_items: Vec<TreeItem<'static, String>>,
    tree_dirty: bool,
    phase: &'static str,
    scanning: bool,

    modal: Modal,
    status: String,
    permanently: bool,
    quit: bool,
}

enum Modal {
    None,
    Confirm,
    Result(String),
    Help,
}

impl App {
    fn new(
        engine: Arc<Engine>,
        home: Option<PathBuf>,
        progress: Arc<Progress>,
        rx: Receiver<ScanEvent>,
    ) -> Self {
        Self {
            engine,
            home,
            progress,
            rx,
            findings: Vec::new(),
            checked: HashSet::new(),
            tree_state: TreeState::default(),
            tree_items: Vec::new(),
            tree_dirty: true,
            phase: "starting",
            scanning: true,
            modal: Modal::None,
            status: "Scanning… select with space, ? for help".into(),
            permanently: false,
            quit: false,
        }
    }

    fn run(&mut self, terminal: &mut ratatui::DefaultTerminal) -> Result<()> {
        let tick = Duration::from_millis(100);
        let mut last = Instant::now();
        while !self.quit {
            self.drain_events();
            self.rebuild_tree_if_dirty();
            terminal.draw(|frame| self.draw(frame))?;
            if !self.scanning && self.tree_state.selected().is_empty() {
                self.tree_state.select_first();
            }

            let timeout = tick.saturating_sub(last.elapsed());
            if event::poll(timeout)?
                && let Event::Key(key) = event::read()?
                && key.kind == KeyEventKind::Press
            {
                self.on_key(key.code, key.modifiers);
            }
            if last.elapsed() >= tick {
                last = Instant::now();
            }
        }
        Ok(())
    }

    /// Pull streamed findings without blocking the render loop.
    fn drain_events(&mut self) {
        for _ in 0..10_000 {
            match self.rx.try_recv() {
                Ok(ScanEvent::Found(f)) => {
                    if f.bytes > 0 || !f.member_paths.is_empty() {
                        self.findings.push(f);
                        self.tree_dirty = true;
                    }
                }
                Ok(ScanEvent::Phase(p)) => self.phase = p,
                Ok(ScanEvent::Done) => {
                    self.scanning = false;
                    self.phase = "done";
                }
                Err(mpsc::TryRecvError::Empty) => break,
                Err(mpsc::TryRecvError::Disconnected) => {
                    self.scanning = false;
                    break;
                }
            }
        }
    }

    fn rebuild_tree_if_dirty(&mut self) {
        if !self.tree_dirty {
            return;
        }
        self.tree_items.clear();
        self.tree_items = self.build_tree();
        self.tree_dirty = false;
    }

    // ---- selection helpers ----

    /// Can the user check this at all? Git-ignored (report-only) and protected
    /// findings never; recent ones yes (manually) — recency only gates *bulk*
    /// select-all, never manual control.
    fn selectable(finding: &Finding) -> bool {
        !finding.report_only && finding.safety != Safety::Protected
    }

    /// Included by select-all: selectable, not recent, not git-ignored
    /// (manual_only), and within the tier.
    fn auto_selectable(finding: &Finding, safe_only: bool) -> bool {
        Self::selectable(finding)
            && !finding.recent
            && !finding.manual_only
            && (!safe_only || finding.safety == Safety::Safe)
    }

    fn category_order(&self) -> Vec<(&str, Vec<usize>)> {
        let mut by_cat: BTreeMap<&str, Vec<usize>> = BTreeMap::new();
        for (idx, finding) in self.findings.iter().enumerate() {
            by_cat
                .entry(finding.category.as_str())
                .or_default()
                .push(idx);
        }
        let mut cats: Vec<(&str, Vec<usize>)> = by_cat.into_iter().collect();
        // Sort categories by total bytes desc; findings within by bytes desc.
        for (_, idxs) in &mut cats {
            idxs.sort_by(|&a, &b| self.findings[b].bytes.cmp(&self.findings[a].bytes));
        }
        cats.sort_by(|a, b| {
            let sa: u64 = a.1.iter().map(|&i| self.findings[i].bytes).sum();
            let sb: u64 = b.1.iter().map(|&i| self.findings[i].bytes).sum();
            sb.cmp(&sa)
        });
        cats
    }

    fn build_tree(&self) -> Vec<TreeItem<'static, String>> {
        let mut items = Vec::new();
        for (cat, idxs) in self.category_order() {
            let total: u64 = idxs.iter().map(|&i| self.findings[i].bytes).sum();
            let checked_in_cat = idxs.iter().filter(|i| self.checked.contains(i)).count();
            let mark = if checked_in_cat == 0 {
                "  "
            } else if checked_in_cat == idxs.len() {
                "[x]"
            } else {
                "[~]"
            };
            let header = Line::from(vec![
                Span::raw(format!("{mark} ")),
                Span::styled(
                    cat.to_string(),
                    Style::default().add_modifier(Modifier::BOLD),
                ),
                Span::raw(format!("  {}  ", human_bytes(total))),
                Span::styled(
                    format!("({} items)", idxs.len()),
                    Style::default().fg(Color::DarkGray),
                ),
            ]);

            let mut children = Vec::new();
            for &idx in &idxs {
                children.push(TreeItem::new_leaf(
                    format!("#{idx}"),
                    self.finding_line(idx),
                ));
            }
            if let Ok(node) = TreeItem::new(format!("cat:{cat}"), header, children) {
                items.push(node);
            }
        }
        items
    }

    fn finding_line(&self, idx: usize) -> Line<'static> {
        let f = &self.findings[idx];
        let checkbox = if self.checked.contains(&idx) {
            Span::styled("[x] ", Style::default().fg(Color::Green))
        } else if !Self::selectable(f) {
            Span::styled("[-] ", Style::default().fg(Color::DarkGray))
        } else if f.recent || f.manual_only {
            // Selectable by hand, but skipped by select-all.
            Span::styled("[ ] ", Style::default().fg(Color::DarkGray))
        } else {
            Span::raw("[ ] ")
        };
        let (safety_label, safety_color) = match f.safety {
            Safety::Safe => ("safe ", Color::Green),
            Safety::Review => ("rev  ", Color::Yellow),
            Safety::Risky => ("risk ", Color::Red),
            Safety::Protected => ("prot ", Color::DarkGray),
        };
        let age = f.age_days.map(|d| format!("{d}d")).unwrap_or_default();
        let mut suffix = String::new();
        if f.recent {
            suffix.push_str(" ·recent");
        }
        if f.manual_only {
            suffix.push_str(" ·git-ignored");
        }
        if f.report_only {
            suffix.push_str(" ·report-only");
        }
        if f.files > 1 {
            suffix.push_str(&format!(" ·{} files", f.files));
        }
        Line::from(vec![
            checkbox,
            Span::styled(
                format!("{:>9} ", human_bytes(f.bytes)),
                Style::default().add_modifier(Modifier::BOLD),
            ),
            Span::styled(safety_label, Style::default().fg(safety_color)),
            Span::styled(format!("{age:>4} "), Style::default().fg(Color::DarkGray)),
            Span::raw(display_path(&f.path, self.home.as_deref())),
            Span::styled(suffix, Style::default().fg(Color::DarkGray)),
        ])
    }

    fn selected_finding(&self) -> Option<usize> {
        self.tree_state
            .selected()
            .last()
            .and_then(|id| id.strip_prefix('#'))
            .and_then(|n| n.parse::<usize>().ok())
    }

    fn selected_category(&self) -> Option<String> {
        self.tree_state
            .selected()
            .first()
            .and_then(|id| id.strip_prefix("cat:").map(|s| s.to_string()))
    }

    fn toggle_selected(&mut self) {
        if let Some(idx) = self.selected_finding() {
            if Self::selectable(&self.findings[idx]) {
                if !self.checked.remove(&idx) {
                    self.checked.insert(idx);
                    let f = &self.findings[idx];
                    if f.manual_only {
                        self.status =
                            "git-ignored — could be source/DB/SDK. Confirm this path before cleaning.".into();
                    } else if f.recent {
                        self.status =
                            "Selected a recently-used item — make sure you're done with it.".into();
                    }
                }
            } else {
                self.status = "Not deletable: protected or report-only.".into();
            }
        } else if let Some(cat) = self.selected_category() {
            // Toggle the whole category: if any unchecked selectable, check all;
            // else uncheck all.
            let idxs: Vec<usize> = self
                .findings
                .iter()
                .enumerate()
                .filter(|(_, f)| f.category == cat && Self::selectable(f))
                .map(|(i, _)| i)
                .collect();
            let all_checked = idxs.iter().all(|i| self.checked.contains(i));
            for i in idxs {
                if all_checked {
                    self.checked.remove(&i);
                } else {
                    self.checked.insert(i);
                }
            }
        }
        self.tree_dirty = true;
    }

    /// `safe_only` true → only the `safe` tier (the conservative default for
    /// "select all"). false → every deletable finding, including review/risky.
    fn select_all(&mut self, safe_only: bool) {
        self.checked.clear();
        let mut count = 0usize;
        for (idx, f) in self.findings.iter().enumerate() {
            if Self::auto_selectable(f, safe_only) {
                self.checked.insert(idx);
                count += 1;
            }
        }
        self.status = if safe_only {
            format!(
                "Selected {count} safe items (recent skipped; A adds review/risky, space picks recent)."
            )
        } else {
            format!("Selected {count} deletable items (recent skipped — select those by hand).")
        };
        self.tree_dirty = true;
    }

    fn checked_bytes(&self) -> u64 {
        self.checked.iter().map(|&i| self.findings[i].bytes).sum()
    }

    // ---- input ----

    fn on_key(&mut self, code: KeyCode, mods: KeyModifiers) {
        // Modal handling first.
        match &self.modal {
            Modal::Confirm => {
                match code {
                    KeyCode::Char('y') | KeyCode::Enter => self.execute(),
                    _ => self.modal = Modal::None,
                }
                return;
            }
            Modal::Result(_) | Modal::Help => {
                self.modal = Modal::None;
                return;
            }
            Modal::None => {}
        }

        match code {
            KeyCode::Char('q') | KeyCode::Esc => self.quit = true,
            KeyCode::Char('c') if mods.contains(KeyModifiers::CONTROL) => self.quit = true,
            KeyCode::Char('?') => self.modal = Modal::Help,
            KeyCode::Down | KeyCode::Char('j') => {
                self.tree_state.key_down();
            }
            KeyCode::Up | KeyCode::Char('k') => {
                self.tree_state.key_up();
            }
            KeyCode::Left | KeyCode::Char('h') => {
                self.tree_state.key_left();
            }
            KeyCode::Right | KeyCode::Char('l') => {
                self.tree_state.key_right();
            }
            KeyCode::Enter => {
                self.tree_state.toggle_selected();
            }
            KeyCode::Char(' ') => self.toggle_selected(),
            KeyCode::Char('a') => self.select_all(true),
            KeyCode::Char('A') => self.select_all(false),
            KeyCode::Char('n') => {
                self.checked.clear();
                self.status = "Selection cleared.".into();
                self.tree_dirty = true;
            }
            KeyCode::Char('p') => {
                self.permanently = !self.permanently;
                self.status = if self.permanently {
                    "Permanent delete ON (bypasses Trash)".into()
                } else {
                    "Deletes go to Trash".into()
                };
            }
            KeyCode::Char('d') => {
                if self.checked.is_empty() {
                    self.status = "Nothing checked. Use space to select.".into();
                } else {
                    self.modal = Modal::Confirm;
                }
            }
            _ => {}
        }
    }

    fn execute(&mut self) {
        let plan: Vec<&Finding> = self
            .checked
            .iter()
            .filter(|&&i| Self::selectable(&self.findings[i]))
            .map(|&i| &self.findings[i])
            .collect();
        let summary = action::execute_plan(
            &plan,
            &self.engine,
            self.home.as_deref(),
            &ExecOptions {
                permanently: self.permanently,
            },
        );
        match summary {
            Ok(summary) => {
                let mut msg = format!(
                    "Freed {} — {} deleted, {} failed.",
                    human_bytes(summary.freed_bytes),
                    summary.deleted,
                    summary.failed
                );
                if let Some(first) = summary.errors.first() {
                    msg.push_str(&format!("\nFirst error: {first}"));
                }
                // Drop the deleted findings from the list.
                let checked = std::mem::take(&mut self.checked);
                let deleted_idxs: HashSet<usize> = checked
                    .into_iter()
                    .filter(|&i| Self::selectable(&self.findings[i]))
                    .collect();
                let mut keep = Vec::new();
                for (i, f) in self.findings.drain(..).enumerate() {
                    if !deleted_idxs.contains(&i) {
                        keep.push(f);
                    }
                }
                self.findings = keep;
                self.tree_state = TreeState::default();
                self.tree_dirty = true;
                self.status = "Deleted. Recover from Trash if needed.".into();
                self.modal = Modal::Result(msg);
            }
            Err(err) => {
                self.modal = Modal::Result(format!("Deletion failed: {err:#}"));
            }
        }
    }

    // ---- rendering ----

    fn draw(&mut self, frame: &mut Frame) {
        let layout = Layout::vertical([
            Constraint::Length(3),
            Constraint::Min(3),
            Constraint::Length(2),
        ])
        .split(frame.area());

        self.draw_header(frame, layout[0]);
        draw_tree(frame, layout[1], &self.tree_items, &mut self.tree_state);
        self.draw_footer(frame, layout[2]);

        match &self.modal {
            Modal::Confirm => self.draw_confirm(frame),
            Modal::Result(msg) => draw_modal(frame, "Result", msg, Color::Green),
            Modal::Help => draw_modal(frame, "Keys", HELP_TEXT, Color::Cyan),
            Modal::None => {}
        }
    }

    fn draw_header(&self, frame: &mut Frame, area: Rect) {
        let (files, dirs, bytes) = self.progress.snapshot();
        let title = if self.scanning {
            format!(" cleaner · {} scan ", self.phase)
        } else {
            " cleaner · scan complete ".to_string()
        };
        let block = Block::default()
            .borders(Borders::ALL)
            .title(title)
            .title_alignment(Alignment::Left);
        let inner = block.inner(area);
        frame.render_widget(block, area);

        let checked_count = self.checked.len();
        let line = Line::from(vec![
            Span::styled(
                format!("seen {} ", human_bytes(bytes)),
                Style::default().fg(Color::DarkGray),
            ),
            Span::styled(
                format!("({files} files / {dirs} dirs)   "),
                Style::default().fg(Color::DarkGray),
            ),
            Span::raw(format!("{} findings   ", self.findings.len())),
            Span::styled(
                format!(
                    "selected {} ({})",
                    checked_count,
                    human_bytes(self.checked_bytes())
                ),
                Style::default()
                    .fg(Color::Green)
                    .add_modifier(Modifier::BOLD),
            ),
        ]);
        if self.scanning {
            let cols =
                Layout::horizontal([Constraint::Min(10), Constraint::Length(14)]).split(inner);
            frame.render_widget(Paragraph::new(line), cols[0]);
            let gauge = Gauge::default()
                .gauge_style(Style::default().fg(Color::Cyan))
                .ratio(spinner_ratio(files))
                .label("scanning");
            frame.render_widget(gauge, cols[1]);
        } else {
            frame.render_widget(Paragraph::new(line), inner);
        }
    }

    fn draw_footer(&self, frame: &mut Frame, area: Rect) {
        let keys = "↑↓ move  ←→ fold  space select  a safe-all  A all  n none  d clean  p trash/perm  ? help  q quit";
        let footer = Layout::vertical([Constraint::Length(1), Constraint::Length(1)]).split(area);
        frame.render_widget(
            Paragraph::new(Line::from(self.status.clone()).fg(Color::Yellow)),
            footer[0],
        );
        frame.render_widget(
            Paragraph::new(Line::from(keys).fg(Color::DarkGray)),
            footer[1],
        );
    }

    fn draw_confirm(&self, frame: &mut Frame) {
        let mode = if self.permanently {
            "PERMANENTLY DELETE"
        } else {
            "move to Trash"
        };
        let msg = format!(
            "{} {} across {} items?\n\n[y / Enter] confirm     [any other key] cancel",
            mode,
            human_bytes(self.checked_bytes()),
            self.checked.len(),
        );
        let color = if self.permanently {
            Color::Red
        } else {
            Color::Yellow
        };
        draw_modal(frame, "Confirm cleanup", &msg, color);
    }
}

fn draw_tree(
    frame: &mut Frame,
    area: Rect,
    items: &[TreeItem<'static, String>],
    state: &mut TreeState<String>,
) {
    let tree = match Tree::new(items) {
        Ok(tree) => tree,
        Err(_) => return,
    };
    let tree = tree
        .block(Block::default().borders(Borders::ALL).title(" findings "))
        .highlight_style(
            Style::default()
                .bg(Color::Rgb(40, 44, 52))
                .add_modifier(Modifier::BOLD),
        )
        .node_closed_symbol("▸ ")
        .node_open_symbol("▾ ")
        .node_no_children_symbol("  ");
    frame.render_stateful_widget(tree, area, state);
}

const HELP_TEXT: &str = "\
Navigation
  ↑/↓ or j/k    move cursor
  ←/→ or h/l    collapse / expand
  Enter         fold/unfold node

Selection
  space         toggle item (or whole category)
  a             select all SAFE items (conservative)
  A             select all deletable (review + risky too)
  n             clear selection

Note: git-ignored data is report-only ([-]). It may be
source, SDKs, or databases — the tool never deletes it.

Actions
  d             clean checked items
  p             toggle Trash vs permanent delete
  q / Esc       quit

Legend
  [x] checked   [ ] selectable   [-] not deletable
  safe / rev / risk = safety tier
  ·recent     = used recently; skipped by select-all
  ·git-ignored = pick by hand only; never bulk-selected
                 (may be source, DBs, or SDKs — check!)
  Both are selectable with space; select-all skips them.
  [-] = protected or report-only — never deletable here";

fn draw_modal(frame: &mut Frame, title: &str, body: &str, color: Color) {
    let area = centered_rect(60, 40, frame.area());
    frame.render_widget(Clear, area);
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(color))
        .title(format!(" {title} "));
    let para = Paragraph::new(body).block(block).wrap(Wrap { trim: false });
    frame.render_widget(para, area);
}

fn centered_rect(percent_x: u16, percent_y: u16, area: Rect) -> Rect {
    let vertical = Layout::vertical([
        Constraint::Percentage((100 - percent_y) / 2),
        Constraint::Percentage(percent_y),
        Constraint::Percentage((100 - percent_y) / 2),
    ])
    .split(area);
    Layout::horizontal([
        Constraint::Percentage((100 - percent_x) / 2),
        Constraint::Percentage(percent_x),
        Constraint::Percentage((100 - percent_x) / 2),
    ])
    .split(vertical[1])[1]
}

fn spinner_ratio(files: u64) -> f64 {
    // Cosmetic indeterminate bar driven by scan volume.
    ((files as f64 / 5000.0).sin().abs()).clamp(0.05, 1.0)
}

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}
