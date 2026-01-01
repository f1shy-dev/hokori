use anyhow::Result;
use globset::{GlobBuilder, GlobSet, GlobSetBuilder};
use ignore::gitignore::{Gitignore, GitignoreBuilder};
use ignore::Match;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

const DEFAULT_PROTECT_PATTERNS: &[&str] = &[
    "**/.env",
    "**/.env.*",
    "**/.envrc",
    "**/.npmrc",
    "**/.pypirc",
    "**/.python-version",
    "**/.tool-versions",
    "**/.ruby-version",
    "**/.node-version",
    "**/.terraformrc",
    "**/.aws/**",
    "**/.ssh/**",
    "**/.gnupg/**",
    "**/.kube/**",
    "**/.git/**",
    "**/.gitignore",
    "**/.gitmodules",
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GitIgnoreMode {
    Size,
    Prune,
}

#[derive(Clone, Debug)]
pub struct GitIgnoreConfig {
    pub mode: GitIgnoreMode,
    pub protect: Arc<GlobSet>,
}

#[derive(Clone, Debug)]
pub struct GitIgnoreStack {
    layers: Vec<Arc<Gitignore>>,
    protect: Arc<GlobSet>,
    mode: GitIgnoreMode,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IgnoreDecision {
    Ignore,
    Whitelist,
    None,
}

pub fn build_protect_globset(extra: &[String]) -> Result<GlobSet> {
    let mut builder = GlobSetBuilder::new();
    for pattern in DEFAULT_PROTECT_PATTERNS.iter().copied() {
        builder.add(build_protect_glob(pattern)?);
    }
    for pattern in extra {
        builder.add(build_protect_glob(pattern)?);
    }
    Ok(builder.build()?)
}

pub fn repo_stack_for_root(repo_root: &Path, config: &GitIgnoreConfig) -> Option<GitIgnoreStack> {
    let git_dir = resolve_git_dir(repo_root)?;
    let mut layers = Vec::new();

    let (global, _) = GitignoreBuilder::new(repo_root).build_global();
    if !global.is_empty() {
        layers.push(Arc::new(global));
    }

    let info_exclude = git_dir.join("info").join("exclude");
    if info_exclude.is_file() {
        if let Some(gi) = load_gitignore(repo_root, &info_exclude) {
            layers.push(gi);
        }
    }

    Some(GitIgnoreStack {
        layers,
        protect: Arc::clone(&config.protect),
        mode: config.mode,
    })
}

pub fn extend_stack_for_dir(stack: &Arc<GitIgnoreStack>, dir: &Path) -> Arc<GitIgnoreStack> {
    let gitignore_path = dir.join(".gitignore");
    if !gitignore_path.is_file() {
        return Arc::clone(stack);
    }
    let gi = match load_gitignore(dir, &gitignore_path) {
        Some(gi) => gi,
        None => return Arc::clone(stack),
    };
    let mut layers = stack.layers.clone();
    layers.push(gi);
    Arc::new(GitIgnoreStack {
        layers,
        protect: Arc::clone(&stack.protect),
        mode: stack.mode,
    })
}

impl GitIgnoreStack {
    pub fn decision(&self, path: &Path, is_dir: bool) -> IgnoreDecision {
        if self.layers.is_empty() {
            return IgnoreDecision::None;
        }
        for layer in self.layers.iter().rev() {
            match layer.matched_path_or_any_parents(path, is_dir) {
                Match::Ignore(_) => return IgnoreDecision::Ignore,
                Match::Whitelist(_) => return IgnoreDecision::Whitelist,
                Match::None => {}
            }
        }
        IgnoreDecision::None
    }

    pub fn is_protected_str(&self, path_str: &str) -> bool {
        self.protect.is_match(path_str)
    }

    pub fn topmost_ignored_path(&self, path: &Path, is_dir: bool) -> PathBuf {
        let mut selected = path.to_path_buf();
        for (idx, ancestor) in path.ancestors().enumerate() {
            let ancestor_is_dir = if idx == 0 { is_dir } else { true };
            match self.decision(ancestor, ancestor_is_dir) {
                IgnoreDecision::Ignore => {
                    selected = ancestor.to_path_buf();
                }
                IgnoreDecision::Whitelist | IgnoreDecision::None => {
                    break;
                }
            }
        }
        selected
    }

    pub fn mode(&self) -> GitIgnoreMode {
        self.mode
    }
}

fn build_protect_glob(pattern: &str) -> Result<globset::Glob> {
    let mut gb = GlobBuilder::new(pattern);
    gb.literal_separator(true);
    gb.case_insensitive(cfg!(windows) || cfg!(target_os = "macos"));
    Ok(gb.build()?)
}

fn load_gitignore(root: &Path, path: &Path) -> Option<Arc<Gitignore>> {
    let mut builder = GitignoreBuilder::new(root);
    let _ = builder.add(path);
    match builder.build() {
        Ok(gi) if !gi.is_empty() => Some(Arc::new(gi)),
        _ => None,
    }
}

pub fn resolve_git_dir(repo_root: &Path) -> Option<PathBuf> {
    let git_path = repo_root.join(".git");
    let meta = fs::symlink_metadata(&git_path).ok()?;
    if meta.is_dir() {
        return Some(git_path);
    }
    if meta.is_file() {
        let contents = fs::read_to_string(&git_path).ok()?;
        let line = contents.lines().next()?.trim();
        let rest = line.strip_prefix("gitdir:")?.trim();
        if rest.is_empty() {
            return None;
        }
        let path = PathBuf::from(rest);
        if path.is_absolute() {
            return Some(path);
        }
        return Some(repo_root.join(path));
    }
    None
}
