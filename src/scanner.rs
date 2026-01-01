use anyhow::Result;
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::{Arc, LazyLock, Mutex};

use crate::gitignore::GitIgnoreConfig;
use crate::config::SampleStrategy;
use crate::matcher::{CompiledContext, RuleMatcher};

#[derive(Debug, Clone)]
pub struct ScanOptions {
    pub max_samples: usize,
    pub threads: Option<usize>,
    #[allow(dead_code)]
    pub windows_dedupe_hardlinks: bool,
    pub gitignore: Option<GitIgnoreConfig>,
    pub sample_mode: SampleMode,
    pub sample_bottom_percent: Option<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SampleMode {
    First,
    Largest,
}

#[derive(Debug, Default, Clone)]
pub struct RuleTotals {
    pub bytes: u64,
    pub file_count: u64,
    pub dir_count: u64,
}

#[derive(Debug, Clone)]
pub struct SampleMatch {
    pub path: PathBuf,
    pub bytes: u64,
    pub rule_index: usize,
}

#[derive(Debug, Clone)]
pub struct SamplePath {
    pub path: PathBuf,
    pub bytes: u64,
}

#[derive(Debug, Clone)]
pub struct ScanResult {
    pub totals: Vec<RuleTotals>,
    pub samples: Vec<SampleMatch>,
    pub git_ignored: Option<GitIgnoredTotals>,
    pub git_ignored_samples: Vec<SamplePath>,
}

#[derive(Debug, Default, Clone)]
pub struct GitIgnoredTotals {
    pub bytes: u64,
    pub file_count: u64,
    pub dir_count: u64,
}

#[derive(Debug)]
struct ScanState {
    totals: Vec<RuleTotals>,
    samples: Vec<SampleMatch>,
    max_samples: usize,
    sample_sets: Option<Vec<HashSet<PathBuf>>>,
    sample_mode: SampleMode,
    sample_bottom_percent: Option<u8>,
    sample_bytes: Option<Vec<HashMap<PathBuf, u64>>>,
    git_ignored: GitIgnoredTotals,
    git_ignored_samples: Vec<SamplePath>,
    git_ignored_sample_set: HashSet<PathBuf>,
    git_ignored_sample_bytes: Option<HashMap<PathBuf, u64>>,
    gitignore_enabled: bool,
}

pub struct Scanner {
    matcher: Arc<RuleMatcher>,
    options: ScanOptions,
}

impl Scanner {
    pub fn new(matcher: Arc<RuleMatcher>, options: ScanOptions) -> Self {
        Self { matcher, options }
    }

    pub fn scan(&self, roots: &[PathBuf]) -> Result<ScanResult> {
        platform::scan(roots, &self.matcher, &self.options)
    }
}

fn new_state(
    rule_len: usize,
    max_samples: usize,
    gitignore_enabled: bool,
    sample_mode: SampleMode,
    sample_bottom_percent: Option<u8>,
) -> Arc<Mutex<ScanState>> {
    let sample_sets = if sample_mode == SampleMode::First {
        Some(vec![HashSet::new(); rule_len])
    } else {
        None
    };
    let sample_bytes = if sample_mode == SampleMode::Largest {
        Some(vec![HashMap::new(); rule_len])
    } else {
        None
    };
    let git_ignored_sample_bytes = if sample_mode == SampleMode::Largest {
        Some(HashMap::new())
    } else {
        None
    };
    Arc::new(Mutex::new(ScanState {
        totals: vec![RuleTotals::default(); rule_len],
        samples: Vec::new(),
        max_samples,
        sample_sets,
        sample_mode,
        sample_bottom_percent,
        sample_bytes,
        git_ignored: GitIgnoredTotals::default(),
        git_ignored_samples: Vec::new(),
        git_ignored_sample_set: HashSet::new(),
        git_ignored_sample_bytes,
        gitignore_enabled,
    }))
}

fn finalize_state(state: Arc<Mutex<ScanState>>) -> Result<ScanResult> {
    let final_state = Arc::try_unwrap(state)
        .map_err(|_| anyhow::anyhow!("scan state still shared"))?
        .into_inner()
        .map_err(|_| anyhow::anyhow!("scan state mutex poisoned"))?;

    let samples = if final_state.sample_mode == SampleMode::Largest {
        build_largest_samples(
            final_state.sample_bytes,
            final_state.max_samples,
            final_state.sample_bottom_percent,
        )
    } else {
        final_state.samples
    };

    let git_ignored_samples = if final_state.sample_mode == SampleMode::Largest {
        build_largest_paths(
            final_state.git_ignored_sample_bytes,
            final_state.max_samples,
            final_state.sample_bottom_percent,
        )
    } else {
        final_state.git_ignored_samples
    };

    Ok(ScanResult {
        totals: final_state.totals,
        samples,
        git_ignored: if final_state.gitignore_enabled {
            Some(final_state.git_ignored)
        } else {
            None
        },
        git_ignored_samples,
    })
}

fn record_match(
    matcher: &RuleMatcher,
    state: &Arc<Mutex<ScanState>>,
    match_path: &str,
    sample_path: PathBuf,
    bytes: u64,
    is_dir: bool,
) -> Option<usize> {
    if let Some(matched) = matcher.match_path(match_path) {
        if let Some(context) = matcher.rule_context(matched.rule_index) {
            if !context_allows(context, match_path, &sample_path, is_dir) {
                return None;
            }
        }
        if let Ok(mut guard) = state.lock() {
            let totals = &mut guard.totals[matched.rule_index];
            if is_dir {
                totals.dir_count += 1;
            } else {
                totals.file_count += 1;
                totals.bytes = totals.bytes.saturating_add(bytes);
            }
            if let Some(sample_path) =
                sample_path_for(matcher.rule_context(matched.rule_index), &sample_path, is_dir)
            {
                match guard.sample_mode {
                    SampleMode::First => {
                        add_sample_first_mode(
                            &mut guard,
                            SampleMatch {
                                path: sample_path,
                                bytes: 0,
                                rule_index: matched.rule_index,
                            },
                        );
                    }
                    SampleMode::Largest => {
                        if let Some(sample_bytes) = guard.sample_bytes.as_mut() {
                            let entry = sample_bytes[matched.rule_index]
                                .entry(sample_path)
                                .or_insert(0);
                            *entry = entry.saturating_add(bytes);
                        }
                    }
                }
            }
        }
        return Some(matched.rule_index);
    }
    None
}

fn context_allows(context: &CompiledContext, match_path: &str, sample_path: &PathBuf, _is_dir: bool) -> bool {
    if let Some(exclude_ancestor_any) = &context.exclude_ancestor_any {
        for ancestor in sample_path.ancestors() {
            let Some(name) = ancestor.file_name().and_then(|s| s.to_str()) else {
                continue;
            };
            if exclude_ancestor_any.is_match(name) {
                return false;
            }
        }
    }
    let context_parent = context_parent_dir(context, sample_path);
    if let Some(parent_any) = &context.require_parent_any {
        let Some(parent) = context_parent.as_ref() else {
            return false;
        };
        let names = dir_entries_cached(parent);
        let Some(names) = names else {
            return false;
        };
        if !names.iter().any(|name| parent_any.is_match(name)) {
            return false;
        }
    }
    if let Some(parent_none) = &context.require_parent_none {
        if let Some(parent) = context_parent.as_ref() {
            if let Some(names) = dir_entries_cached(parent) {
                if names.iter().any(|name| parent_none.is_match(name)) {
                    return false;
                }
            }
        }
    }
    if !context.require_ancestor_files_any.is_empty() {
        let max_depth = context.ancestor_depth;
        if !ancestor_has_any_file(sample_path, &context.require_ancestor_files_any, max_depth) {
            return false;
        }
    }
    let _ = match_path;
    true
}

fn sample_path_for(
    context: Option<&CompiledContext>,
    path: &PathBuf,
    is_dir: bool,
) -> Option<PathBuf> {
    if let Some(context) = context {
        if let Some(strategy) = context.sample_strategy {
            let strategy_path = match strategy {
                SampleStrategy::ChromiumProfile => sample_root_chromium_profile(path),
                SampleStrategy::MacosLibraryApp => sample_root_macos_library_app(path),
            };
            if strategy_path.is_some() {
                return strategy_path;
            }
        }
        if !context.sample_ancestor_files_any.is_empty() {
            if let Some(ancestor) = ancestor_with_any_file(
                path,
                &context.sample_ancestor_files_any,
                context.sample_ancestor_depth,
            ) {
                return Some(ancestor);
            }
        }
        if let Some(sample_parent_any) = &context.sample_parent_any {
            let mut chosen: Option<PathBuf> = None;
            for ancestor in path.ancestors() {
                let Some(name) = ancestor.file_name().and_then(|s| s.to_str()) else {
                    continue;
                };
                if sample_parent_any.is_match(name) {
                    chosen = Some(ancestor.to_path_buf());
                }
            }
            if chosen.is_some() {
                return chosen;
            }
        }
    }
    if is_dir {
        Some(path.clone())
    } else {
        Some(path.clone())
    }
}

fn ancestor_with_any_file(path: &PathBuf, names: &[String], max_depth: usize) -> Option<PathBuf> {
    let mut current = path.parent();
    let mut depth = 0usize;
    while let Some(parent) = current {
        if names.iter().any(|name| file_exists_cached(&parent.join(name))) {
            return Some(parent.to_path_buf());
        }
        depth += 1;
        if depth >= max_depth {
            break;
        }
        current = parent.parent();
    }
    None
}

fn ancestor_with_any_file_str(path: &PathBuf, names: &[&str], max_depth: usize) -> Option<PathBuf> {
    let mut current = path.parent();
    let mut depth = 0usize;
    while let Some(parent) = current {
        if names.iter().any(|name| file_exists_cached(&parent.join(name))) {
            return Some(parent.to_path_buf());
        }
        depth += 1;
        if depth >= max_depth {
            break;
        }
        current = parent.parent();
    }
    None
}

fn sample_root_chromium_profile(path: &PathBuf) -> Option<PathBuf> {
    const LOCAL_STATE: [&str; 1] = ["Local State"];
    if let Some(root) = ancestor_with_any_file_str(path, &LOCAL_STATE, 8) {
        return Some(root);
    }

    let mut chosen: Option<PathBuf> = None;
    for ancestor in path.ancestors() {
        let Some(name) = ancestor.file_name().and_then(|s| s.to_str()) else {
            continue;
        };
        let is_profile = name == "Default"
            || name == "Profile"
            || name.starts_with("Profile ")
            || name == "Partitions"
            || name == "DesktopProfile"
            || name == "EBWebView"
            || name.starts_with("WV2Profile");
        if is_profile {
            chosen = ancestor.parent().map(|p| p.to_path_buf());
        }
    }
    chosen
}

fn sample_root_macos_library_app(path: &PathBuf) -> Option<PathBuf> {
    let mut chosen: Option<PathBuf> = None;
    for ancestor in path.ancestors() {
        let Some(parent) = ancestor.parent() else {
            continue;
        };
        let Some(parent_name) = parent.file_name().and_then(|s| s.to_str()) else {
            continue;
        };
        if parent_name == "Caches"
            || parent_name == "Application Support"
            || parent_name == "Logs"
            || parent_name == "HTTPStorages"
        {
            chosen = Some(ancestor.to_path_buf());
        }
        if parent_name == "Containers"
            || parent_name == "Group Containers"
            || parent_name == "Daemon Containers"
        {
            chosen = Some(ancestor.to_path_buf());
        }
    }
    if chosen.is_some() {
        return chosen;
    }
    for ancestor in path.ancestors() {
        let Some(name) = ancestor.file_name().and_then(|s| s.to_str()) else {
            continue;
        };
        if name == "Safari" || name == "WebKit" {
            return Some(ancestor.to_path_buf());
        }
    }
    None
}

fn context_parent_dir(context: &CompiledContext, path: &PathBuf) -> Option<PathBuf> {
    if let Some(anchor) = &context.parent_anchor_any {
        let mut chosen: Option<PathBuf> = None;
        for ancestor in path.ancestors() {
            let Some(name) = ancestor.file_name().and_then(|s| s.to_str()) else {
                continue;
            };
            if anchor.is_match(name) {
                chosen = ancestor.parent().map(|p| p.to_path_buf());
            }
        }
        return chosen;
    }
    path.parent().map(|p| p.to_path_buf())
}

fn ancestor_has_any_file(path: &PathBuf, names: &[String], max_depth: usize) -> bool {
    let mut current = path.parent();
    let mut depth = 0usize;
    while let Some(parent) = current {
        if names.iter().any(|name| file_exists_cached(&parent.join(name))) {
            return true;
        }
        depth += 1;
        if depth >= max_depth {
            break;
        }
        current = parent.parent();
    }
    false
}

fn file_exists_cached(path: &PathBuf) -> bool {
    static FILE_EXISTS: LazyLock<Mutex<HashMap<PathBuf, bool>>> =
        LazyLock::new(|| Mutex::new(HashMap::new()));
    if let Ok(cache) = FILE_EXISTS.lock() {
        if let Some(found) = cache.get(path) {
            return *found;
        }
    }
    let found = path.is_file();
    if let Ok(mut cache) = FILE_EXISTS.lock() {
        if cache.len() > 8192 {
            cache.clear();
        }
        cache.insert(path.clone(), found);
    }
    found
}

fn dir_entries_cached(dir: &std::path::Path) -> Option<Vec<String>> {
    static DIR_ENTRIES: LazyLock<Mutex<HashMap<PathBuf, Vec<String>>>> =
        LazyLock::new(|| Mutex::new(HashMap::new()));
    if let Ok(cache) = DIR_ENTRIES.lock() {
        if let Some(found) = cache.get(dir) {
            return Some(found.clone());
        }
    }
    let mut names = Vec::new();
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            names.push(name);
        }
    } else {
        return None;
    }
    if let Ok(mut cache) = DIR_ENTRIES.lock() {
        if cache.len() > 2048 {
            cache.clear();
        }
        cache.insert(dir.to_path_buf(), names.clone());
    }
    Some(names)
}

fn record_git_ignored(
    state: &Arc<Mutex<ScanState>>,
    path: PathBuf,
    bytes: u64,
    is_dir: bool,
) {
    if let Ok(mut guard) = state.lock() {
        if !guard.gitignore_enabled {
            return;
        }
        if is_dir {
            guard.git_ignored.dir_count += 1;
        } else {
            guard.git_ignored.file_count += 1;
            guard.git_ignored.bytes = guard.git_ignored.bytes.saturating_add(bytes);
        }
        match guard.sample_mode {
            SampleMode::First => {
                if let Some(sample_path) = sample_path_for(None, &path, is_dir) {
                    add_git_ignored_sample(
                        &mut guard,
                        SamplePath {
                            path: sample_path,
                            bytes,
                        },
                    );
                }
            }
            SampleMode::Largest => {
                if let Some(sample_path) = sample_path_for(None, &path, is_dir) {
                    if let Some(map) = guard.git_ignored_sample_bytes.as_mut() {
                        let entry = map.entry(sample_path).or_insert(0);
                        *entry = entry.saturating_add(bytes);
                    }
                }
            }
        }
    }
}

fn add_sample_first_mode(guard: &mut ScanState, sample: SampleMatch) {
    if guard.max_samples == 0 {
        return;
    }
    let Some(sample_sets) = guard.sample_sets.as_mut() else {
        return;
    };
    let rule_index = sample.rule_index;
    let sample_set = &mut sample_sets[rule_index];
    if sample_set.contains(&sample.path) {
        return;
    }
    if guard.samples.iter().any(|existing| {
        existing.rule_index == rule_index && sample.path.starts_with(&existing.path)
    }) {
        return;
    }

    let mut to_remove = Vec::new();
    for existing in guard.samples.iter() {
        if existing.rule_index == rule_index && existing.path.starts_with(&sample.path) {
            to_remove.push(existing.path.clone());
        }
    }
    if !to_remove.is_empty() {
        guard.samples.retain(|existing| {
            !(existing.rule_index == rule_index && existing.path.starts_with(&sample.path))
        });
        for path in to_remove {
            sample_set.remove(&path);
        }
    }

    if guard.samples.len() >= guard.max_samples {
        return;
    }
    sample_set.insert(sample.path.clone());
    guard.samples.push(sample);
}

fn add_git_ignored_sample(guard: &mut ScanState, sample: SamplePath) {
    if guard.max_samples == 0 {
        return;
    }
    if guard.git_ignored_sample_set.contains(&sample.path) {
        return;
    }
    if guard
        .git_ignored_samples
        .iter()
        .any(|existing| sample.path.starts_with(&existing.path))
    {
        return;
    }

    let mut to_remove = Vec::new();
    for existing in guard.git_ignored_samples.iter() {
        if existing.path.starts_with(&sample.path) {
            to_remove.push(existing.path.clone());
        }
    }
    if !to_remove.is_empty() {
        guard
            .git_ignored_samples
            .retain(|existing| !existing.path.starts_with(&sample.path));
        for existing in to_remove {
            guard.git_ignored_sample_set.remove(&existing);
        }
    }

    if guard.git_ignored_samples.len() >= guard.max_samples {
        return;
    }
    guard.git_ignored_sample_set.insert(sample.path.clone());
    guard.git_ignored_samples.push(sample);
}

fn build_largest_samples(
    sample_bytes: Option<Vec<HashMap<PathBuf, u64>>>,
    max_samples: usize,
    bottom_percent: Option<u8>,
) -> Vec<SampleMatch> {
    let Some(sample_bytes) = sample_bytes else {
        return Vec::new();
    };
    if max_samples == 0 {
        return Vec::new();
    }

    let mut output = Vec::new();
    for (rule_index, entries) in sample_bytes.into_iter().enumerate() {
        let mut candidates: Vec<SampleMatch> = entries
            .into_iter()
            .map(|(path, bytes)| SampleMatch {
                path,
                bytes,
                rule_index,
            })
            .collect();
        if candidates.is_empty() {
            continue;
        }

        if let Some(percent) = bottom_percent {
            if percent > 0 && percent < 100 {
                candidates.sort_by(|a, b| a.bytes.cmp(&b.bytes));
                let drop_count =
                    ((candidates.len() as f64) * (percent as f64 / 100.0)).floor() as usize;
                if drop_count >= candidates.len() {
                    continue;
                }
                candidates.drain(0..drop_count);
            } else if percent >= 100 {
                continue;
            }
        }

        candidates.sort_by(|a, b| {
            b.bytes
                .cmp(&a.bytes)
                .then_with(|| a.path.cmp(&b.path))
        });

        let mut selected: Vec<SampleMatch> = Vec::new();
        for candidate in candidates {
            if selected.len() >= max_samples {
                break;
            }
            if selected
                .iter()
                .any(|existing| candidate.path.starts_with(&existing.path))
            {
                continue;
            }
            selected.push(candidate);
        }
        output.extend(selected);
    }

    output
}

fn build_largest_paths(
    sample_bytes: Option<HashMap<PathBuf, u64>>,
    max_samples: usize,
    bottom_percent: Option<u8>,
) -> Vec<SamplePath> {
    let Some(sample_bytes) = sample_bytes else {
        return Vec::new();
    };
    let mut candidates: Vec<SamplePath> = sample_bytes
        .into_iter()
        .map(|(path, bytes)| SamplePath { path, bytes })
        .collect();
    if candidates.is_empty() || max_samples == 0 {
        return Vec::new();
    }

    if let Some(percent) = bottom_percent {
        if percent > 0 && percent < 100 {
            candidates.sort_by(|a, b| a.bytes.cmp(&b.bytes));
            let drop_count =
                ((candidates.len() as f64) * (percent as f64 / 100.0)).floor() as usize;
            if drop_count >= candidates.len() {
                return Vec::new();
            }
            candidates.drain(0..drop_count);
        } else if percent >= 100 {
            return Vec::new();
        }
    }

    candidates.sort_by(|a, b| {
        b.bytes
            .cmp(&a.bytes)
            .then_with(|| a.path.cmp(&b.path))
    });

    let mut selected: Vec<SamplePath> = Vec::new();
    for candidate in candidates {
        if selected.len() >= max_samples {
            break;
        }
        if selected
            .iter()
            .any(|existing| candidate.path.starts_with(&existing.path))
        {
            continue;
        }
        selected.push(candidate);
    }

    selected
}

#[cfg(target_os = "macos")]
mod platform {
    use super::{
        finalize_state, new_state, record_git_ignored, record_match, GitIgnoredTotals, ScanOptions,
        ScanResult,
    };
    use anyhow::{Context, Result};
    use rayon::prelude::*;
    use std::collections::HashSet;
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    use std::path::{Path, PathBuf};
    use std::sync::{Arc, LazyLock, Mutex};

    use crate::gitignore::{
        extend_stack_for_dir, repo_stack_for_root, GitIgnoreMode, GitIgnoreStack, IgnoreDecision,
    };
    use crate::matcher::RuleMatcher;

    // macOS-specific constants not in libc crate
    const ATTR_CMN_ERROR: u32 = 0x2000_0000;
    const VNON: u32 = 0;
    const VDIR: u32 = 2;

    const MAX_FILE_HANDLES: usize = 224;
    const SHARD_COUNT: usize = 128;

    static SEEN_INODES: LazyLock<[Mutex<HashSet<u64>>; SHARD_COUNT]> =
        LazyLock::new(|| std::array::from_fn(|_| Mutex::new(HashSet::new())));

    pub(super) fn scan(
        roots: &[PathBuf],
        matcher: &Arc<RuleMatcher>,
        options: &ScanOptions,
    ) -> Result<ScanResult> {
        if roots.is_empty() {
            return Ok(ScanResult {
                totals: vec![Default::default(); matcher.len()],
                samples: Vec::new(),
                git_ignored: options.gitignore.as_ref().map(|_| GitIgnoredTotals::default()),
                git_ignored_samples: Vec::new(),
            });
        }

        clear_seen_inodes();

        let threads = options
            .threads
            .unwrap_or_else(|| std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1))
            .min(MAX_FILE_HANDLES);

        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(threads)
            .stack_size(16 * 1024 * 1024)
            .build()
            .context("failed to build thread pool")?;

        let state = new_state(
            matcher.len(),
            options.max_samples,
            options.gitignore.is_some(),
            options.sample_mode,
            options.sample_bottom_percent,
        );
        let matcher = Arc::clone(matcher);

        pool.install(|| {
            roots.par_iter().for_each(|root| {
                if let Err(err) = scan_dir(root, &matcher, &state, options, None) {
                    eprintln!("warning: scan failed for {}: {err}", root.display());
                }
            });
        });

        finalize_state(state)
    }

    fn scan_dir(
        path: &Path,
        matcher: &Arc<RuleMatcher>,
        state: &Arc<Mutex<super::ScanState>>,
        options: &ScanOptions,
        git_stack: Option<Arc<GitIgnoreStack>>,
    ) -> Result<()> {
        let mut git_stack = git_stack;
        if let Some(config) = options.gitignore.as_ref() {
            if let Some(stack) = repo_stack_for_root(path, config) {
                git_stack = Some(Arc::new(stack));
            }
            if let Some(stack) = git_stack.as_ref() {
                git_stack = Some(extend_stack_for_dir(stack, path));
            }
        }
        let c_path = CString::new(path.as_os_str().as_bytes())
            .with_context(|| format!("invalid path: {}", path.display()))?;

        let dirfd = unsafe {
            libc::open(
                c_path.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        };
        if dirfd == -1 {
            return Ok(());
        }

        let mut attrlist = libc::attrlist {
            bitmapcount: libc::ATTR_BIT_MAP_COUNT as u16,
            reserved: 0,
            commonattr: libc::ATTR_CMN_RETURNED_ATTRS
                | libc::ATTR_CMN_NAME
                | ATTR_CMN_ERROR
                | libc::ATTR_CMN_OBJTYPE
                | libc::ATTR_CMN_FILEID,
            volattr: 0,
            dirattr: 0,
            fileattr: libc::ATTR_FILE_ALLOCSIZE,
            forkattr: 0,
        };

        let mut buf = vec![0u8; 128 * 1024];
        let base = base_path(path);
        let mut subdirs: Vec<String> = Vec::new();

        loop {
            let retcount = unsafe {
                libc::getattrlistbulk(
                    dirfd,
                    &mut attrlist as *mut libc::attrlist as *mut libc::c_void,
                    buf.as_mut_ptr() as *mut libc::c_void,
                    buf.len(),
                    0,
                )
            };
            if retcount < 0 {
                let err = std::io::Error::last_os_error();
                if err.raw_os_error() == Some(libc::EINVAL) {
                    buf.resize(buf.len().saturating_mul(2), 0);
                    continue;
                }
                break;
            }
            if retcount == 0 {
                break;
            }

            let mut entry_ptr = buf.as_ptr();
            for _ in 0..retcount {
                unsafe {
                    let entry_len = std::ptr::read_unaligned(entry_ptr as *const u32) as usize;
                    let mut field_ptr = entry_ptr.add(std::mem::size_of::<u32>());

                    let returned =
                        std::ptr::read_unaligned(field_ptr as *const libc::attribute_set_t);
                    field_ptr = field_ptr.add(std::mem::size_of::<libc::attribute_set_t>());

                    let mut filename: Option<String> = None;
                    if returned.commonattr & libc::ATTR_CMN_NAME != 0 {
                        let name_start = field_ptr;
                        let name_info =
                            std::ptr::read_unaligned(field_ptr as *const libc::attrreference_t);
                        field_ptr = field_ptr.add(std::mem::size_of::<libc::attrreference_t>());

                        if name_info.attr_length > 0 {
                            let name_ptr = name_start.add(name_info.attr_dataoffset as usize);
                            let name_slice = std::slice::from_raw_parts(
                                name_ptr,
                                (name_info.attr_length - 1) as usize,
                            );
                            if let Ok(name_str) = std::str::from_utf8(name_slice) {
                                if name_str == "." || name_str == ".." {
                                    entry_ptr = entry_ptr.add(entry_len);
                                    continue;
                                }
                                filename = Some(name_str.to_string());
                            }
                        }
                    }

                    if returned.commonattr & ATTR_CMN_ERROR != 0 {
                        let error_code = std::ptr::read_unaligned(field_ptr as *const u32);
                        field_ptr = field_ptr.add(std::mem::size_of::<u32>());
                        if error_code != 0 {
                            entry_ptr = entry_ptr.add(entry_len);
                            continue;
                        }
                    }

                    let obj_type = if returned.commonattr & libc::ATTR_CMN_OBJTYPE != 0 {
                        let obj_type = std::ptr::read_unaligned(field_ptr as *const u32);
                        field_ptr = field_ptr.add(std::mem::size_of::<u32>());
                        obj_type
                    } else {
                        VNON
                    };

                    let inode = if returned.commonattr & libc::ATTR_CMN_FILEID != 0 {
                        let inode = std::ptr::read_unaligned(field_ptr as *const u64);
                        field_ptr = field_ptr.add(std::mem::size_of::<u64>());
                        inode
                    } else {
                        0
                    };

                    let alloc_size = if returned.fileattr & libc::ATTR_FILE_ALLOCSIZE != 0 {
                        let alloc_size = std::ptr::read_unaligned(field_ptr as *const i64);
                        let _ = field_ptr.add(std::mem::size_of::<i64>());
                        alloc_size
                    } else {
                        0
                    };

                    if let Some(name) = filename {
                        if name == ".git" {
                            entry_ptr = entry_ptr.add(entry_len);
                            continue;
                        }

                        let full_path = format!("{}{}", base, name);
                        let is_dir = obj_type == VDIR;
                        let sample_path = PathBuf::from(&full_path);
                        let mut prune = false;
                        let mut ignored = false;

                        if let Some(stack) = git_stack.as_ref() {
                            match stack.decision(&sample_path, is_dir) {
                                IgnoreDecision::Ignore => {
                                    if !stack.is_protected_str(&full_path) {
                                        ignored = true;
                                        if is_dir && stack.mode() == GitIgnoreMode::Prune {
                                            prune = true;
                                        }
                                    }
                                }
                                IgnoreDecision::Whitelist | IgnoreDecision::None => {}
                            }
                        }

                        if is_dir {
                            let matched =
                                record_match(matcher, state, &full_path, sample_path.clone(), 0, true)
                                    .is_some();
                            if ignored && !matched {
                                if let Some(stack) = git_stack.as_ref() {
                                    let sample =
                                        stack.topmost_ignored_path(&sample_path, true);
                                    record_git_ignored(state, sample, 0, true);
                                }
                            }
                            if !prune {
                                subdirs.push(full_path);
                            }
                        } else {
                            let size = check_and_add_inode(inode, alloc_size.max(0) as u64);
                            let matched =
                                record_match(matcher, state, &full_path, sample_path.clone(), size, false)
                                    .is_some();
                            if ignored && !matched {
                                if let Some(stack) = git_stack.as_ref() {
                                    let sample =
                                        stack.topmost_ignored_path(&sample_path, false);
                                    record_git_ignored(state, sample, size, false);
                                }
                            }
                        }
                    }

                    entry_ptr = entry_ptr.add(entry_len);
                }
            }
        }

        unsafe {
            libc::close(dirfd);
        }

        if !subdirs.is_empty() {
            let git_stack = git_stack.clone();
            subdirs.par_iter().for_each(|subdir| {
                let path = Path::new(subdir);
                if let Err(err) = scan_dir(path, matcher, state, options, git_stack.clone()) {
                    eprintln!("warning: scan failed for {}: {err}", path.display());
                }
            });
        }

        Ok(())
    }

    fn base_path(path: &Path) -> String {
        let mut base = path.to_string_lossy().to_string();
        if !base.ends_with('/') {
            base.push('/');
        }
        base
    }

    fn shard_for_inode(inode: u64) -> usize {
        ((inode >> 8) % SHARD_COUNT as u64) as usize
    }

    fn check_and_add_inode(inode: u64, bytes: u64) -> u64 {
        if inode == 0 {
            return bytes;
        }
        let shard_idx = shard_for_inode(inode);
        let mut seen = SEEN_INODES[shard_idx].lock().expect("inode mutex poisoned");
        if seen.insert(inode) {
            bytes
        } else {
            0
        }
    }

    fn clear_seen_inodes() {
        for shard in SEEN_INODES.iter() {
            if let Ok(mut guard) = shard.lock() {
                guard.clear();
            }
        }
    }
}

#[cfg(target_os = "linux")]
mod platform {
    use super::{
        finalize_state, new_state, record_git_ignored, record_match, GitIgnoredTotals, ScanOptions,
        ScanResult,
    };
    use anyhow::{Context, Result};
    use rayon::prelude::*;
    use std::collections::HashSet;
    use std::ffi::{CStr, CString};
    use std::os::unix::ffi::OsStrExt;
    use std::path::{Path, PathBuf};
    use std::sync::{Arc, LazyLock, Mutex};

    use crate::gitignore::{
        extend_stack_for_dir, repo_stack_for_root, GitIgnoreMode, GitIgnoreStack, IgnoreDecision,
    };
    use crate::matcher::RuleMatcher;

    const MAX_THREADS: usize = 256;
    const SHARD_COUNT: usize = 128;

    const D_RECLEN_OFFSET: usize = 16;
    const D_NAME_OFFSET: usize = 19;

    static SEEN_INODES: LazyLock<[Mutex<HashSet<u128>>; SHARD_COUNT]> =
        LazyLock::new(|| std::array::from_fn(|_| Mutex::new(HashSet::new())));

    pub(super) fn scan(
        roots: &[PathBuf],
        matcher: &Arc<RuleMatcher>,
        options: &ScanOptions,
    ) -> Result<ScanResult> {
        if roots.is_empty() {
            return Ok(ScanResult {
                totals: vec![Default::default(); matcher.len()],
                samples: Vec::new(),
                git_ignored: options.gitignore.as_ref().map(|_| GitIgnoredTotals::default()),
                git_ignored_samples: Vec::new(),
            });
        }

        clear_seen_inodes();

        let threads = options
            .threads
            .unwrap_or_else(|| std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1))
            .min(MAX_THREADS);

        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(threads)
            .stack_size(16 * 1024 * 1024)
            .build()
            .context("failed to build thread pool")?;

        let state = new_state(
            matcher.len(),
            options.max_samples,
            options.gitignore.is_some(),
            options.sample_mode,
            options.sample_bottom_percent,
        );
        let matcher = Arc::clone(matcher);

        pool.install(|| {
            roots.par_iter().for_each(|root| {
                if let Err(err) = scan_dir(root, &matcher, &state, options, None) {
                    eprintln!("warning: scan failed for {}: {err}", root.display());
                }
            });
        });

        finalize_state(state)
    }

    fn scan_dir(
        path: &Path,
        matcher: &Arc<RuleMatcher>,
        state: &Arc<Mutex<super::ScanState>>,
        options: &ScanOptions,
        git_stack: Option<Arc<GitIgnoreStack>>,
    ) -> Result<()> {
        let mut git_stack = git_stack;
        if let Some(config) = options.gitignore.as_ref() {
            if let Some(stack) = repo_stack_for_root(path, config) {
                git_stack = Some(Arc::new(stack));
            }
            if let Some(stack) = git_stack.as_ref() {
                git_stack = Some(extend_stack_for_dir(stack, path));
            }
        }
        let c_path = CString::new(path.as_os_str().as_bytes())
            .with_context(|| format!("invalid path: {}", path.display()))?;

        let dirfd = unsafe {
            libc::open(
                c_path.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        };
        if dirfd == -1 {
            return Ok(());
        }

        let mut buf = vec![0u8; 512 * 1024];
        let base = base_path(path);
        let mut subdirs: Vec<PathBuf> = Vec::new();

        loop {
            let nread = unsafe {
                libc::syscall(
                    libc::SYS_getdents64,
                    dirfd,
                    buf.as_mut_ptr(),
                    buf.len(),
                )
            } as isize;

            if nread < 0 {
                let err = std::io::Error::last_os_error();
                if err.raw_os_error() == Some(libc::EINVAL) {
                    buf.resize(buf.len().saturating_mul(2), 0);
                    continue;
                }
                break;
            }
            if nread == 0 {
                break;
            }

            let mut bpos = 0usize;
            while bpos < nread as usize {
                let base_ptr = unsafe { buf.as_ptr().add(bpos) };
                let reclen = unsafe { *(base_ptr.add(D_RECLEN_OFFSET) as *const u16) } as usize;
                if reclen == 0 {
                    break;
                }

                let name_ptr = unsafe { base_ptr.add(D_NAME_OFFSET) };
                let name_cstr = unsafe { CStr::from_ptr(name_ptr as *const i8) };
                let name_bytes = name_cstr.to_bytes();
                if name_bytes.is_empty() {
                    bpos += reclen;
                    continue;
                }
                if name_bytes == b"." || name_bytes == b".." {
                    bpos += reclen;
                    continue;
                }

                let name = match std::str::from_utf8(name_bytes) {
                    Ok(name) => name,
                    Err(_) => {
                        bpos += reclen;
                        continue;
                    }
                };

                let entry_stat = match stat_entry(dirfd, name_ptr) {
                    Some(stat) => stat,
                    None => {
                        bpos += reclen;
                        continue;
                    }
                };

                let is_dir = (entry_stat.mode & libc::S_IFMT) == libc::S_IFDIR;
                if name == ".git" {
                    bpos += reclen;
                    continue;
                }

                let full_path = format!("{}{}", base, name);
                let sample_path = PathBuf::from(&full_path);
                let mut prune = false;
                let mut ignored = false;

                if let Some(stack) = git_stack.as_ref() {
                    match stack.decision(&sample_path, is_dir) {
                        IgnoreDecision::Ignore => {
                            if !stack.is_protected_str(&full_path) {
                                ignored = true;
                                if is_dir && stack.mode() == GitIgnoreMode::Prune {
                                    prune = true;
                                }
                            }
                        }
                        IgnoreDecision::Whitelist | IgnoreDecision::None => {}
                    }
                }

                if is_dir {
                    let matched =
                        record_match(matcher, state, &full_path, sample_path.clone(), 0, true)
                            .is_some();
                    if ignored && !matched {
                        if let Some(stack) = git_stack.as_ref() {
                            let sample = stack.topmost_ignored_path(&sample_path, true);
                            record_git_ignored(state, sample, 0, true);
                        }
                    }
                    if !prune {
                        subdirs.push(sample_path);
                    }
                } else {
                    let size = file_size(&entry_stat);
                    let key = inode_key(&entry_stat);
                    let deduped = check_and_add_inode(key, size);
                    let matched =
                        record_match(matcher, state, &full_path, sample_path.clone(), deduped, false)
                            .is_some();
                    if ignored && !matched {
                        if let Some(stack) = git_stack.as_ref() {
                            let sample = stack.topmost_ignored_path(&sample_path, false);
                            record_git_ignored(state, sample, deduped, false);
                        }
                    }
                }

                bpos += reclen;
            }
        }

        unsafe {
            libc::close(dirfd);
        }

        if !subdirs.is_empty() {
            let git_stack = git_stack.clone();
            subdirs.par_iter().for_each(|subdir| {
                if let Err(err) = scan_dir(subdir, matcher, state, options, git_stack.clone()) {
                    eprintln!("warning: scan failed for {}: {err}", subdir.display());
                }
            });
        }

        Ok(())
    }

    fn base_path(path: &Path) -> String {
        let mut base = path.to_string_lossy().to_string();
        if !base.ends_with('/') {
            base.push('/');
        }
        base
    }

    #[derive(Debug, Copy, Clone)]
    struct EntryStat {
        mode: u32,
        blocks: u64,
        size: u64,
        dev: u64,
        ino: u64,
    }

    fn stat_entry(dirfd: i32, name_ptr: *const u8) -> Option<EntryStat> {
        let mut statx_buf: libc::statx = unsafe { std::mem::zeroed() };
        let res = unsafe {
            libc::statx(
                dirfd,
                name_ptr as *const i8,
                libc::AT_SYMLINK_NOFOLLOW | libc::AT_NO_AUTOMOUNT,
                libc::STATX_BASIC_STATS,
                &mut statx_buf,
            )
        };
        if res == 0 {
            let dev = ((statx_buf.stx_dev_major as u64) << 32) | statx_buf.stx_dev_minor as u64;
            return Some(EntryStat {
                mode: statx_buf.stx_mode as u32,
                blocks: statx_buf.stx_blocks as u64,
                size: statx_buf.stx_size as u64,
                dev,
                ino: statx_buf.stx_ino as u64,
            });
        }

        let err = std::io::Error::last_os_error();
        if matches!(err.raw_os_error(), Some(libc::ENOSYS) | Some(libc::EINVAL)) {
            let mut st: libc::stat = unsafe { std::mem::zeroed() };
            let res = unsafe {
                libc::fstatat(dirfd, name_ptr as *const i8, &mut st, libc::AT_SYMLINK_NOFOLLOW)
            };
            if res != 0 {
                return None;
            }
            return Some(EntryStat {
                mode: st.st_mode as u32,
                blocks: st.st_blocks as u64,
                size: st.st_size as u64,
                dev: st.st_dev as u64,
                ino: st.st_ino as u64,
            });
        }

        None
    }

    fn file_size(stat: &EntryStat) -> u64 {
        if stat.blocks > 0 {
            stat.blocks.saturating_mul(512)
        } else {
            stat.size
        }
    }

    fn inode_key(stat: &EntryStat) -> u128 {
        ((stat.dev as u128) << 64) | stat.ino as u128
    }

    fn shard_for_inode(key: u128) -> usize {
        ((key >> 8) % SHARD_COUNT as u128) as usize
    }

    fn check_and_add_inode(key: u128, bytes: u64) -> u64 {
        if key == 0 {
            return bytes;
        }
        let shard_idx = shard_for_inode(key);
        let mut seen = SEEN_INODES[shard_idx].lock().expect("inode mutex poisoned");
        if seen.insert(key) {
            bytes
        } else {
            0
        }
    }

    fn clear_seen_inodes() {
        for shard in SEEN_INODES.iter() {
            if let Ok(mut guard) = shard.lock() {
                guard.clear();
            }
        }
    }
}

#[cfg(target_os = "windows")]
mod platform {
    use super::{
        finalize_state, new_state, record_git_ignored, record_match, GitIgnoredTotals, ScanOptions,
        ScanResult,
    };
    use anyhow::{Context, Result};
    use rayon::prelude::*;
    use std::collections::HashSet;
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use std::path::{Path, PathBuf};
    use std::sync::{Arc, LazyLock, Mutex};
    use windows_sys::Win32::Foundation::{CloseHandle, FindClose, HANDLE, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, FindExInfoBasic, FindExSearchNameMatch, FindFirstFileExW, FindNextFileW,
        GetFileInformationByHandle, GetFileInformationByHandleEx, FILE_ATTRIBUTE_DIRECTORY,
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
        FILE_ID_INFO, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
        FIND_FIRST_EX_LARGE_FETCH, OPEN_EXISTING, WIN32_FIND_DATAW, BY_HANDLE_FILE_INFORMATION,
        FileIdInfo,
    };

    use crate::gitignore::{
        extend_stack_for_dir, repo_stack_for_root, GitIgnoreMode, GitIgnoreStack, IgnoreDecision,
    };
    use crate::matcher::RuleMatcher;

    const MAX_THREADS: usize = 256;
    const SHARD_COUNT: usize = 128;

    #[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
    struct FileKey {
        volume: u64,
        id: [u8; 16],
    }

    static SEEN_FILE_KEYS: LazyLock<[Mutex<HashSet<FileKey>>; SHARD_COUNT]> =
        LazyLock::new(|| std::array::from_fn(|_| Mutex::new(HashSet::new())));

    pub(super) fn scan(
        roots: &[PathBuf],
        matcher: &Arc<RuleMatcher>,
        options: &ScanOptions,
    ) -> Result<ScanResult> {
        if roots.is_empty() {
            return Ok(ScanResult {
                totals: vec![Default::default(); matcher.len()],
                samples: Vec::new(),
                git_ignored: options.gitignore.as_ref().map(|_| GitIgnoredTotals::default()),
                git_ignored_samples: Vec::new(),
            });
        }

        if options.windows_dedupe_hardlinks {
            clear_seen_keys();
        }

        let threads = options
            .threads
            .unwrap_or_else(|| std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1))
            .min(MAX_THREADS);

        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(threads)
            .stack_size(16 * 1024 * 1024)
            .build()
            .context("failed to build thread pool")?;

        let state = new_state(
            matcher.len(),
            options.max_samples,
            options.gitignore.is_some(),
            options.sample_mode,
            options.sample_bottom_percent,
        );
        let matcher = Arc::clone(matcher);

        pool.install(|| {
            roots.par_iter().for_each(|root| {
                if let Err(err) = scan_dir(root, &matcher, &state, options, None) {
                    eprintln!("warning: scan failed for {}: {err}", root.display());
                }
            });
        });

        finalize_state(state)
    }

    fn scan_dir(
        path: &Path,
        matcher: &Arc<RuleMatcher>,
        state: &Arc<Mutex<super::ScanState>>,
        options: &ScanOptions,
        git_stack: Option<Arc<GitIgnoreStack>>,
    ) -> Result<()> {
        let mut git_stack = git_stack;
        if let Some(config) = options.gitignore.as_ref() {
            if let Some(stack) = repo_stack_for_root(path, config) {
                git_stack = Some(Arc::new(stack));
            }
            if let Some(stack) = git_stack.as_ref() {
                git_stack = Some(extend_stack_for_dir(stack, path));
            }
        }
        let mut search = PathBuf::from(path);
        search.push("*");
        let search_wide = to_wide(&search);

        let mut data: WIN32_FIND_DATAW = unsafe { std::mem::zeroed() };
        let mut handle = unsafe {
            FindFirstFileExW(
                search_wide.as_ptr(),
                FindExInfoBasic,
                &mut data as *mut WIN32_FIND_DATAW as *mut _,
                FindExSearchNameMatch,
                std::ptr::null_mut(),
                FIND_FIRST_EX_LARGE_FETCH,
            )
        };

        if handle == INVALID_HANDLE_VALUE {
            handle = unsafe {
                FindFirstFileExW(
                    search_wide.as_ptr(),
                    FindExInfoBasic,
                    &mut data as *mut WIN32_FIND_DATAW as *mut _,
                    FindExSearchNameMatch,
                    std::ptr::null_mut(),
                    0,
                )
            };
            if handle == INVALID_HANDLE_VALUE {
                return Ok(());
            }
        }

        let mut subdirs: Vec<PathBuf> = Vec::new();
        loop {
            let name = match utf16_to_string(&data.cFileName) {
                Some(name) => name,
                None => {
                    if unsafe { FindNextFileW(handle, &mut data) } == 0 {
                        break;
                    }
                    continue;
                }
            };

            if name == "." || name == ".." {
                if unsafe { FindNextFileW(handle, &mut data) } == 0 {
                    break;
                }
                continue;
            }

            let attr = data.dwFileAttributes;
            let is_dir = (attr & FILE_ATTRIBUTE_DIRECTORY) != 0;
            let is_reparse = (attr & FILE_ATTRIBUTE_REPARSE_POINT) != 0;

            let full_path = path.join(&name);
            let match_path = normalize_match_path(&full_path);

            if name == ".git" {
                if unsafe { FindNextFileW(handle, &mut data) } == 0 {
                    break;
                }
                continue;
            }

            let mut prune = false;
            let mut ignored = false;
            if let Some(stack) = git_stack.as_ref() {
                match stack.decision(&full_path, is_dir) {
                    IgnoreDecision::Ignore => {
                        if !stack.is_protected_str(&match_path) {
                            ignored = true;
                            if is_dir && stack.mode() == GitIgnoreMode::Prune {
                                prune = true;
                            }
                        }
                    }
                    IgnoreDecision::Whitelist | IgnoreDecision::None => {}
                }
            }

            if is_dir {
                let matched = record_match(
                    matcher,
                    state,
                    &match_path,
                    full_path.clone(),
                    0,
                    true,
                )
                .is_some();
                if ignored && !matched {
                    if let Some(stack) = git_stack.as_ref() {
                        let sample = stack.topmost_ignored_path(&full_path, true);
                        record_git_ignored(state, sample, 0, true);
                    }
                }
                if !is_reparse && !prune {
                    subdirs.push(full_path);
                }
            } else {
                let size = ((data.nFileSizeHigh as u64) << 32) | data.nFileSizeLow as u64;
                let deduped = maybe_dedupe_size(&full_path, size, options);
                let matched =
                    record_match(matcher, state, &match_path, full_path.clone(), deduped, false)
                        .is_some();
                if ignored && !matched {
                    if let Some(stack) = git_stack.as_ref() {
                        let sample = stack.topmost_ignored_path(&full_path, false);
                        record_git_ignored(state, sample, deduped, false);
                    }
                }
            }

            if unsafe { FindNextFileW(handle, &mut data) } == 0 {
                break;
            }
        }

        unsafe {
            FindClose(handle);
        }

        if !subdirs.is_empty() {
            let git_stack = git_stack.clone();
            subdirs.par_iter().for_each(|subdir| {
                if let Err(err) = scan_dir(subdir, matcher, state, options, git_stack.clone()) {
                    eprintln!("warning: scan failed for {}: {err}", subdir.display());
                }
            });
        }

        Ok(())
    }

    fn maybe_dedupe_size(path: &Path, size: u64, options: &ScanOptions) -> u64 {
        if !options.windows_dedupe_hardlinks {
            return size;
        }
        let key = match file_key(path) {
            Some(key) => key,
            None => return size,
        };
        check_and_add_key(key, size)
    }

    fn file_key(path: &Path) -> Option<FileKey> {
        let handle = open_handle(path)?;
        let mut key = file_key_from_handle(handle);
        if key.is_none() {
            key = file_key_legacy(handle);
        }
        unsafe {
            CloseHandle(handle);
        }
        key
    }

    fn open_handle(path: &Path) -> Option<HANDLE> {
        let wide = to_wide(path);
        let handle = unsafe {
            CreateFileW(
                wide.as_ptr(),
                FILE_READ_ATTRIBUTES,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                std::ptr::null_mut(),
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                0,
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            None
        } else {
            Some(handle)
        }
    }

    fn file_key_from_handle(handle: HANDLE) -> Option<FileKey> {
        let mut info: FILE_ID_INFO = unsafe { std::mem::zeroed() };
        let ok = unsafe {
            GetFileInformationByHandleEx(
                handle,
                FileIdInfo,
                &mut info as *mut FILE_ID_INFO as *mut _,
                std::mem::size_of::<FILE_ID_INFO>() as u32,
            )
        };
        if ok == 0 {
            return None;
        }
        Some(FileKey {
            volume: info.VolumeSerialNumber,
            id: info.FileId.Identifier,
        })
    }

    fn file_key_legacy(handle: HANDLE) -> Option<FileKey> {
        let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
        let ok = unsafe { GetFileInformationByHandle(handle, &mut info) };
        if ok == 0 {
            return None;
        }
        let file_index = ((info.nFileIndexHigh as u64) << 32) | info.nFileIndexLow as u64;
        let mut id = [0u8; 16];
        id[..8].copy_from_slice(&file_index.to_le_bytes());
        Some(FileKey {
            volume: info.dwVolumeSerialNumber as u64,
            id,
        })
    }

    fn check_and_add_key(key: FileKey, bytes: u64) -> u64 {
        let shard_idx = shard_for_key(&key);
        let mut seen = SEEN_FILE_KEYS[shard_idx].lock().expect("file key mutex poisoned");
        if seen.insert(key) {
            bytes
        } else {
            0
        }
    }

    fn shard_for_key(key: &FileKey) -> usize {
        ((key.volume ^ u64::from_le_bytes(key.id[0..8].try_into().unwrap())) as usize)
            % SHARD_COUNT
    }

    fn clear_seen_keys() {
        for shard in SEEN_FILE_KEYS.iter() {
            if let Ok(mut guard) = shard.lock() {
                guard.clear();
            }
        }
    }

    fn to_wide(path: &Path) -> Vec<u16> {
        let wide: Vec<u16> = OsStr::new(path).encode_wide().collect();
        let mut wide_null = Vec::with_capacity(wide.len() + 1);
        wide_null.extend_from_slice(&wide);
        wide_null.push(0);
        wide_null
    }

    fn utf16_to_string(buf: &[u16]) -> Option<String> {
        let len = buf.iter().position(|c| *c == 0)?;
        Some(String::from_utf16_lossy(&buf[..len]))
    }

    fn normalize_match_path(path: &Path) -> String {
        path.to_string_lossy().replace('\\', "/")
    }
}

#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
mod platform {
    use super::{
        finalize_state, new_state, record_git_ignored, record_match, GitIgnoredTotals, ScanOptions,
        ScanResult,
    };
    use anyhow::Result;
    use ignore::{DirEntry, WalkBuilder, WalkState};
    use std::path::{Path, PathBuf};
    use std::sync::{Arc, Mutex};

    use crate::gitignore::{GitIgnoreMode, GitIgnoreStack, IgnoreDecision};
    use crate::matcher::RuleMatcher;

    pub(super) fn scan(
        roots: &[PathBuf],
        matcher: &Arc<RuleMatcher>,
        options: &ScanOptions,
    ) -> Result<ScanResult> {
        if roots.is_empty() {
            return Ok(ScanResult {
                totals: vec![Default::default(); matcher.len()],
                samples: Vec::new(),
                git_ignored: options.gitignore.as_ref().map(|_| GitIgnoredTotals::default()),
                git_ignored_samples: Vec::new(),
            });
        }

        let mut builder = WalkBuilder::new(&roots[0]);
        for root in roots.iter().skip(1) {
            builder.add(root);
        }

        builder
            .hidden(false)
            .git_ignore(false)
            .git_global(false)
            .git_exclude(false)
            .ignore(false)
            .follow_links(false);

        if let Some(threads) = options.threads {
            builder.threads(threads);
        }

        let state = new_state(
            matcher.len(),
            options.max_samples,
            options.gitignore.is_some(),
            options.sample_mode,
            options.sample_bottom_percent,
        );
        let matcher = Arc::clone(matcher);
        let options = options.clone();
        let git_stack: Option<Arc<GitIgnoreStack>> = None;

        builder.build_parallel().run(|| {
            let matcher = Arc::clone(&matcher);
            let state = Arc::clone(&state);
            let git_stack = git_stack.clone();
            Box::new(move |entry| visit_entry(entry, &matcher, &state, &options, &git_stack))
        });

        finalize_state(state)
    }

    fn visit_entry(
        entry: Result<DirEntry, ignore::Error>,
        matcher: &RuleMatcher,
        state: &Arc<Mutex<super::ScanState>>,
        options: &ScanOptions,
        git_stack: &Option<Arc<GitIgnoreStack>>,
    ) -> WalkState {
        let entry = match entry {
            Ok(entry) => entry,
            Err(_) => return WalkState::Continue,
        };

        if is_git_dir(&entry) {
            return WalkState::Skip;
        }

        let path = entry.path();
        let path_str = normalize_path(path);
        let sample_path = entry.path().to_path_buf();

        let is_dir = entry.file_type().map(|ft| ft.is_dir()).unwrap_or(false);
        let bytes = if is_dir { 0 } else { file_size(&entry) };
        let mut prune = false;
        let mut ignored = false;
        if let Some(stack) = git_stack.as_ref() {
            match stack.decision(&sample_path, is_dir) {
                IgnoreDecision::Ignore => {
                    if !stack.is_protected_str(&path_str) {
                        ignored = true;
                        if is_dir && stack.mode() == GitIgnoreMode::Prune {
                            prune = true;
                        }
                    }
                }
                IgnoreDecision::Whitelist | IgnoreDecision::None => {}
            }
        }
        let matched = record_match(matcher, state, &path_str, sample_path.clone(), bytes, is_dir)
            .is_some();
        if ignored && !matched {
            if let Some(stack) = git_stack.as_ref() {
                let sample = stack.topmost_ignored_path(&sample_path, is_dir);
                record_git_ignored(state, sample, bytes, is_dir);
            }
        }

        if prune {
            WalkState::Skip
        } else {
            WalkState::Continue
        }
    }

    fn normalize_path(path: &Path) -> String {
        path.to_string_lossy().replace('\\', "/")
    }

    fn is_git_dir(entry: &DirEntry) -> bool {
        entry
            .file_type()
            .map(|ft| ft.is_dir())
            .unwrap_or(false)
            && entry.file_name() == ".git"
    }

    fn file_size(entry: &DirEntry) -> u64 {
        let metadata = match entry.metadata() {
            Ok(meta) => meta,
            Err(_) => return 0,
        };
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let blocks = metadata.blocks();
            if blocks > 0 {
                return blocks.saturating_mul(512);
            }
        }
        metadata.len()
    }
}
