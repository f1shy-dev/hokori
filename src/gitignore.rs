//! Lean gitignore stack for the discovery walk: per-repo global excludes +
//! info/exclude + per-directory .gitignore layers, queried per *directory*
//! (the engine claims ignored dirs whole; it never matches individual files).

use ignore::Match;
use ignore::gitignore::{Gitignore, GitignoreBuilder};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::walk::Entry;

#[derive(Debug)]
pub struct GitIgnoreStack {
    layers: Vec<Layer>,
}

#[derive(Debug, Clone)]
struct Layer {
    root: PathBuf,
    matcher: Arc<Gitignore>,
}

impl GitIgnoreStack {
    pub fn for_repo(repo_root: &Path) -> Self {
        let mut layers = Vec::new();

        let (global, _) = GitignoreBuilder::new(repo_root).build_global();
        if !global.is_empty() {
            layers.push(Layer {
                root: repo_root.to_path_buf(),
                matcher: Arc::new(global),
            });
        }

        if let Some(git_dir) = resolve_git_dir(repo_root) {
            let info_exclude = git_dir.join("info").join("exclude");
            if info_exclude.is_file()
                && let Some(gi) = load_gitignore(repo_root, &info_exclude)
            {
                layers.push(Layer {
                    root: repo_root.to_path_buf(),
                    matcher: gi,
                });
            }
        }

        Self { layers }
    }

    /// Push a layer for `dir`'s .gitignore if the listing shows one.
    pub fn extend_for_dir(
        self: &Arc<Self>,
        dir: &Path,
        entries: &[Entry],
    ) -> Option<Arc<GitIgnoreStack>> {
        if !entries.iter().any(|e| !e.is_dir && e.name == ".gitignore") {
            return None;
        }
        let gi = load_gitignore(dir, &dir.join(".gitignore"))?;
        let mut layers = self.layers.clone();
        layers.push(Layer {
            root: dir.to_path_buf(),
            matcher: gi,
        });
        Some(Arc::new(GitIgnoreStack { layers }))
    }

    pub fn is_ignored(&self, path: &Path, is_dir: bool) -> bool {
        for layer in self.layers.iter().rev() {
            if !path.starts_with(&layer.root) {
                continue;
            }
            match layer.matcher.matched_path_or_any_parents(path, is_dir) {
                Match::Ignore(_) => return true,
                Match::Whitelist(_) => return false,
                Match::None => {}
            }
        }
        false
    }
}

fn load_gitignore(root: &Path, path: &Path) -> Option<Arc<Gitignore>> {
    let mut builder = GitignoreBuilder::new(root);
    let _ = builder.add(path);
    match builder.build() {
        Ok(gi) if !gi.is_empty() => Some(Arc::new(gi)),
        _ => None,
    }
}

fn resolve_git_dir(repo_root: &Path) -> Option<PathBuf> {
    let git_path = repo_root.join(".git");
    let meta = std::fs::symlink_metadata(&git_path).ok()?;
    if meta.is_dir() {
        return Some(git_path);
    }
    if meta.is_file() {
        let contents = std::fs::read_to_string(&git_path).ok()?;
        let line = contents.lines().next()?.trim();
        let rest = line.strip_prefix("gitdir:")?.trim();
        if rest.is_empty() {
            return None;
        }
        let path = PathBuf::from(rest);
        return Some(if path.is_absolute() {
            path
        } else {
            repo_root.join(path)
        });
    }
    None
}
