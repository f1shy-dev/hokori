use anyhow::{Context, Result};
use globset::{GlobSet, GlobSetBuilder};
use std::path::Path;

use crate::config::{RuleAction, RuleContext, RuleDef, RuleKind, SampleStrategy};

#[derive(Debug)]
pub struct MatchResult {
    pub rule_index: usize,
}

#[derive(Debug)]
struct CompiledRule {
    id: String,
    kind: RuleKind,
    action: RuleAction,
    priority: u32,
    globset: GlobSet,
    context: Option<CompiledContext>,
}

#[derive(Debug)]
pub struct RuleMatcher {
    rules: Vec<CompiledRule>,
}

#[derive(Debug, Clone)]
pub struct CompiledContext {
    pub parent_anchor_any: Option<GlobSet>,
    pub require_parent_any: Option<GlobSet>,
    pub require_parent_none: Option<GlobSet>,
    pub exclude_ancestor_any: Option<GlobSet>,
    pub require_ancestor_files_any: Vec<String>,
    pub ancestor_depth: usize,
    pub sample_ancestor_files_any: Vec<String>,
    pub sample_ancestor_depth: usize,
    pub sample_parent_any: Option<GlobSet>,
    pub sample_strategy: Option<SampleStrategy>,
}

impl RuleMatcher {
    pub fn new(rules: &[RuleDef], home: Option<&Path>) -> Result<Self> {
        let mut compiled = Vec::with_capacity(rules.len());
        for rule in rules {
            let mut builder = GlobSetBuilder::new();
            for pattern in &rule.patterns {
                let expanded = expand_pattern(pattern, home);
                let mut gb = globset::GlobBuilder::new(&expanded);
                gb.literal_separator(true);
                gb.case_insensitive(cfg!(windows) || cfg!(target_os = "macos"));
                let glob = gb
                    .build()
                    .with_context(|| format!("invalid glob pattern: {}", expanded))?;
                builder.add(glob);
            }
            let globset = builder.build()
                .with_context(|| format!("failed to build globset for rule {}", rule.id))?;
            let context = compile_context(rule.context.as_ref(), home)
                .with_context(|| format!("failed to build context for rule {}", rule.id))?;
            compiled.push(CompiledRule {
                id: rule.id.clone(),
                kind: rule.kind,
                action: rule.action,
                priority: rule.effective_priority(),
                globset,
                context,
            });
        }
        Ok(Self { rules: compiled })
    }

    pub fn match_path(&self, path: &str) -> Option<MatchResult> {
        let mut best: Option<(usize, u32)> = None;
        for (idx, rule) in self.rules.iter().enumerate() {
            if rule.globset.is_match(path) {
                let priority = rule.priority;
                if best.map(|(_, p)| priority > p).unwrap_or(true) {
                    best = Some((idx, priority));
                }
            }
        }
        best.map(|(idx, _)| MatchResult { rule_index: idx })
    }

    pub fn rule_id(&self, index: usize) -> &str {
        &self.rules[index].id
    }

    pub fn rule_action(&self, index: usize) -> RuleAction {
        self.rules[index].action
    }

    pub fn rule_kind(&self, index: usize) -> RuleKind {
        self.rules[index].kind
    }

    pub fn rule_context(&self, index: usize) -> Option<&CompiledContext> {
        self.rules[index].context.as_ref()
    }

    pub fn len(&self) -> usize {
        self.rules.len()
    }
}

fn expand_pattern(pattern: &str, home: Option<&Path>) -> String {
    if let Some(home_dir) = home {
        if let Some(rest) = pattern.strip_prefix("~/") {
            let mut path = home_dir.to_path_buf();
            path.push(rest);
            return path.to_string_lossy().replace('\\', "/");
        }
    }
    pattern.to_string()
}

fn compile_context(context: Option<&RuleContext>, home: Option<&Path>) -> Result<Option<CompiledContext>> {
    let Some(context) = context else {
        return Ok(None);
    };
    let parent_anchor_any = compile_context_globs(&context.parent_anchor_any, home)?;
    let parent_any = compile_context_globs(&context.require_parent_any, home)?;
    let parent_none = compile_context_globs(&context.require_parent_none, home)?;
    let exclude_ancestor_any = compile_context_globs(&context.exclude_ancestor_any, home)?;
    let sample_parent_any = compile_context_globs(&context.sample_parent_any, home)?;
    let sample_strategy = context.sample_strategy;
    let ancestor_files_any = context.require_ancestor_files_any.clone();
    let ancestor_depth = context.ancestor_depth.unwrap_or(3);
    let sample_ancestor_files_any = context.sample_ancestor_files_any.clone();
    let sample_ancestor_depth = context.sample_ancestor_depth.unwrap_or(6);
    if parent_anchor_any.is_none()
        && parent_any.is_none()
        && parent_none.is_none()
        && exclude_ancestor_any.is_none()
        && ancestor_files_any.is_empty()
        && sample_ancestor_files_any.is_empty()
        && sample_parent_any.is_none()
        && sample_strategy.is_none()
    {
        return Ok(None);
    }
    Ok(Some(CompiledContext {
        parent_anchor_any,
        require_parent_any: parent_any,
        require_parent_none: parent_none,
        exclude_ancestor_any,
        require_ancestor_files_any: ancestor_files_any,
        ancestor_depth,
        sample_ancestor_files_any,
        sample_ancestor_depth,
        sample_parent_any,
        sample_strategy,
    }))
}

fn compile_context_globs(patterns: &[String], home: Option<&Path>) -> Result<Option<GlobSet>> {
    if patterns.is_empty() {
        return Ok(None);
    }
    let mut builder = GlobSetBuilder::new();
    for pattern in patterns {
        let expanded = expand_pattern(pattern, home);
        let mut gb = globset::GlobBuilder::new(&expanded);
        gb.literal_separator(true);
        gb.case_insensitive(cfg!(windows) || cfg!(target_os = "macos"));
        let glob = gb
            .build()
            .with_context(|| format!("invalid context glob pattern: {}", expanded))?;
        builder.add(glob);
    }
    Ok(Some(builder.build()?))
}
