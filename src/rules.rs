//! Rule schema v2: declarative cleaning rules loaded from TOML.
//!
//! A rule is either *targeted* (has `roots`: concrete, enumerable locations that
//! are sized directly without walking anything else) or *discovery* (has
//! `dir_names` / `file_names` / `file_suffixes` / `path_globs`: triggers evaluated
//! during the full walk). `protect` rules carve paths out of both engines.

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Safety {
    /// Regenerated automatically; deleting costs nothing but a warm cache.
    Safe,
    /// Regenerable but with a real cost (re-download, re-build, re-login).
    Review,
    /// May contain user data; deletion needs explicit, per-item consent.
    Risky,
    /// Never deleted, never offered.
    Protected,
}

impl Safety {
    pub fn label(self) -> &'static str {
        match self {
            Safety::Safe => "safe",
            Safety::Review => "review",
            Safety::Risky => "risky",
            Safety::Protected => "protected",
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct RuleDef {
    pub id: String,
    /// Free-form taxonomy label used for grouping (e.g. "app-cache",
    /// "package-manager-cache", "project-artifact").
    pub category: String,
    pub safety: Safety,
    /// One human sentence: what deleting this costs the user.
    #[serde(default)]
    pub impact: Option<String>,

    // -- targeted enumeration --
    /// Anchored locations. `~` expands to $HOME; a path component may contain
    /// glob characters (expanded by listing that directory level).
    #[serde(default)]
    pub roots: Vec<String>,

    // -- discovery triggers --
    /// Directory basenames that claim their whole subtree on match.
    #[serde(default)]
    pub dir_names: Vec<String>,
    /// Exact file basenames (e.g. ".DS_Store").
    #[serde(default)]
    pub file_names: Vec<String>,
    /// File basename suffixes (e.g. ".pyc"). Matched case-insensitively.
    #[serde(default)]
    pub file_suffixes: Vec<String>,
    /// Escape hatch: full-path globs for patterns the tables can't express.
    #[serde(default)]
    pub path_globs: Vec<String>,

    // -- context predicates (discovery) --
    /// Claim only if a sibling entry matches one of these globs
    /// (e.g. "package.json" next to node_modules).
    #[serde(default)]
    pub require_sibling_any: Vec<String>,
    /// Never claim while one of these directory names is an ancestor.
    #[serde(default)]
    pub exclude_ancestors: Vec<String>,

    // -- gates --
    /// Skip (mark recent) when the newest of dir-mtime / marker-sibling mtimes
    /// is younger than this.
    #[serde(default)]
    pub min_age_days: Option<u64>,
    /// Ignore findings smaller than this (bytes, accepts "10MB" style).
    #[serde(default)]
    pub min_size: Option<String>,

    // -- actions --
    /// Preferred tool-native GC command, e.g. ["pnpm", "store", "prune"].
    #[serde(default)]
    pub clean_via: Vec<String>,
    /// Surface in reports but never include in a deletion plan
    /// (e.g. Trash bin, Docker advice).
    #[serde(default)]
    pub report_only: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RuleFile {
    #[serde(default)]
    pub rules: Vec<RuleDef>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct UserConfig {
    /// Extra protect globs (full paths, ~ allowed).
    #[serde(default)]
    pub protect: Vec<String>,
    /// Rule ids to disable entirely.
    #[serde(default)]
    pub disable_rules: Vec<String>,
    /// Global floor for min_age_days applied to every non-protect rule.
    #[serde(default)]
    pub min_age_days: Option<u64>,
}

/// Rule files compiled into the binary so the tool works from any directory.
pub const EMBEDDED_RULES: &[(&str, &str)] = &[
    ("macos.toml", include_str!("../rules/macos.toml")),
    ("projects.toml", include_str!("../rules/projects.toml")),
    ("protect.toml", include_str!("../rules/protect.toml")),
];

pub fn load_rules(rules_dir: Option<&Path>) -> Result<Vec<RuleDef>> {
    let mut rules = Vec::new();
    match rules_dir {
        Some(dir) => {
            let mut paths: Vec<_> = std::fs::read_dir(dir)
                .with_context(|| format!("failed to read rules dir {}", dir.display()))?
                .filter_map(|e| e.ok())
                .map(|e| e.path())
                .filter(|p| p.extension().is_some_and(|e| e == "toml"))
                .collect();
            paths.sort();
            for path in paths {
                let content = std::fs::read_to_string(&path)
                    .with_context(|| format!("failed to read {}", path.display()))?;
                let file: RuleFile = toml::from_str(&content)
                    .with_context(|| format!("failed to parse {}", path.display()))?;
                rules.extend(file.rules);
            }
        }
        None => {
            for (name, content) in EMBEDDED_RULES {
                let file: RuleFile = toml::from_str(content)
                    .with_context(|| format!("failed to parse embedded {name}"))?;
                rules.extend(file.rules);
            }
        }
    }
    validate(&rules)?;
    Ok(rules)
}

pub fn load_user_config() -> Result<UserConfig> {
    let Some(home) = crate::util::home_dir() else {
        return Ok(UserConfig::default());
    };
    let path = home.join(".config/cleaner/config.toml");
    if !path.is_file() {
        return Ok(UserConfig::default());
    }
    let content = std::fs::read_to_string(&path)
        .with_context(|| format!("failed to read {}", path.display()))?;
    toml::from_str(&content).with_context(|| format!("failed to parse {}", path.display()))
}

pub fn apply_user_config(rules: &mut Vec<RuleDef>, config: &UserConfig) {
    rules.retain(|r| !config.disable_rules.iter().any(|id| id == &r.id));
    if let Some(floor) = config.min_age_days {
        for rule in rules.iter_mut() {
            if rule.safety != Safety::Protected {
                let current = rule.min_age_days.unwrap_or(0);
                rule.min_age_days = Some(current.max(floor));
            }
        }
    }
}

fn validate(rules: &[RuleDef]) -> Result<()> {
    let mut seen = std::collections::HashSet::new();
    for rule in rules {
        if !seen.insert(rule.id.as_str()) {
            bail!("duplicate rule id: {}", rule.id);
        }
        let has_trigger = !rule.roots.is_empty()
            || !rule.dir_names.is_empty()
            || !rule.file_names.is_empty()
            || !rule.file_suffixes.is_empty()
            || !rule.path_globs.is_empty();
        if !has_trigger {
            bail!("rule {} has no roots and no discovery triggers", rule.id);
        }
        if let Some(size) = &rule.min_size {
            parse_size(size).with_context(|| format!("rule {}: bad min_size", rule.id))?;
        }
    }
    Ok(())
}

pub fn parse_size(input: &str) -> Result<u64> {
    let trimmed = input.trim();
    let split = trimmed
        .find(|c: char| !c.is_ascii_digit() && c != '.')
        .unwrap_or(trimmed.len());
    let (num, unit) = trimmed.split_at(split);
    let value: f64 = num.parse().with_context(|| format!("bad size: {input}"))?;
    let mult: u64 = match unit.trim().to_ascii_uppercase().as_str() {
        "" | "B" => 1,
        "KB" | "K" => 1 << 10,
        "MB" | "M" => 1 << 20,
        "GB" | "G" => 1 << 30,
        "TB" | "T" => 1 << 40,
        other => bail!("unknown size unit {other:?} in {input:?}"),
    };
    Ok((value * mult as f64) as u64)
}
