use anyhow::{Context, Result};
use serde::Deserialize;
use std::path::Path;

#[derive(Debug, Deserialize, Clone)]
pub struct RuleFile {
    pub rules: Vec<RuleDef>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct RuleDef {
    pub id: String,
    pub kind: RuleKind,
    #[serde(default = "default_action")]
    pub action: RuleAction,
    pub patterns: Vec<String>,
    #[serde(default)]
    pub group: Option<String>,
    #[serde(default)]
    pub context: Option<RuleContext>,
    #[serde(default)]
    #[allow(dead_code)]
    pub notes: Option<String>,
    #[serde(default)]
    pub priority: Option<u32>,
}

#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RuleKind {
    Cache,
    Log,
    Temp,
    Crash,
    Download,
    Build,
    Trash,
    Data,
    Dev,
    System,
    GitIgnored,
    Other,
}

#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RuleAction {
    Cleanable,
    Caution,
    DeepClean,
    Protect,
}

#[derive(Debug, Deserialize, Clone, Default)]
pub struct RuleContext {
    #[serde(default)]
    pub parent_anchor_any: Vec<String>,
    #[serde(default)]
    pub require_parent_any: Vec<String>,
    #[serde(default)]
    pub require_parent_none: Vec<String>,
    #[serde(default)]
    pub exclude_ancestor_any: Vec<String>,
    #[serde(default)]
    pub require_ancestor_files_any: Vec<String>,
    #[serde(default)]
    pub ancestor_depth: Option<usize>,
    #[serde(default)]
    pub sample_ancestor_files_any: Vec<String>,
    #[serde(default)]
    pub sample_ancestor_depth: Option<usize>,
    #[serde(default)]
    pub sample_parent_any: Vec<String>,
    #[serde(default)]
    pub sample_strategy: Option<SampleStrategy>,
}

#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SampleStrategy {
    ChromiumProfile,
    MacosLibraryApp,
}

fn default_action() -> RuleAction {
    RuleAction::Cleanable
}

impl RuleAction {
    pub fn priority(self) -> u32 {
        match self {
            RuleAction::Protect => 100,
            RuleAction::DeepClean => 80,
            RuleAction::Caution => 60,
            RuleAction::Cleanable => 40,
        }
    }
}

impl RuleDef {
    pub fn effective_priority(&self) -> u32 {
        self.priority.unwrap_or_else(|| self.action.priority())
    }
}

impl RuleFile {
    pub fn load_from(path: &Path) -> Result<Self> {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read rules file: {}", path.display()))?;
        let rules = toml::from_str(&content)
            .with_context(|| format!("failed to parse rules file: {}", path.display()))?;
        Ok(rules)
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct RulesetFile {
    pub rulesets: Vec<RulesetDef>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct RulesetDef {
    pub name: String,
    pub includes: Vec<String>,
    #[serde(default)]
    pub disabled: Vec<String>,
    #[serde(default)]
    pub disabled_groups: Vec<String>,
}

impl RulesetFile {
    pub fn load_from(path: &Path) -> Result<Self> {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read rulesets file: {}", path.display()))?;
        let rulesets = toml::from_str(&content)
            .with_context(|| format!("failed to parse rulesets file: {}", path.display()))?;
        Ok(rulesets)
    }
}

pub fn load_ruleset(
    rulesets_path: &Path,
    name: &str,
    disable_ids: &[String],
    disable_groups: &[String],
) -> Result<Vec<RuleDef>> {
    let rulesets = RulesetFile::load_from(rulesets_path)?;
    let ruleset = rulesets
        .rulesets
        .iter()
        .find(|rs| rs.name == name)
        .with_context(|| format!("ruleset '{}' not found", name))?;

    let base_dir = rulesets_path.parent().unwrap_or(Path::new("."));
    let mut rules = Vec::new();
    for include in &ruleset.includes {
        let path = base_dir.join(include);
        let file = RuleFile::load_from(&path)?;
        rules.extend(file.rules);
    }

    let mut disabled_ids = ruleset.disabled.clone();
    disabled_ids.extend_from_slice(disable_ids);
    let mut disabled_groups = ruleset.disabled_groups.clone();
    disabled_groups.extend_from_slice(disable_groups);

    Ok(filter_rules(rules, &disabled_ids, &disabled_groups))
}

fn filter_rules(
    rules: Vec<RuleDef>,
    disabled_ids: &[String],
    disabled_groups: &[String],
) -> Vec<RuleDef> {
    rules
        .into_iter()
        .filter(|rule| {
            if disabled_ids.iter().any(|id| id == &rule.id) {
                return false;
            }
            if let Some(group) = &rule.group {
                if disabled_groups.iter().any(|g| g == group) {
                    return false;
                }
            }
            true
        })
        .collect()
}
