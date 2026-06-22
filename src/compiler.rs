//! Compiles rule definitions into dispatch indexes so per-entry matching cost
//! is one hash lookup (plus occasional predicates), independent of rule count.

use anyhow::{Context, Result, bail};
use globset::{GlobBuilder, GlobSet, GlobSetBuilder};
use std::collections::HashMap;
use std::path::Path;

use crate::rules::{RuleDef, Safety, parse_size};

pub struct CompiledRule {
    pub def: RuleDef,
    pub sibling_any: Option<GlobSet>,
    /// Bits in the ancestor mask that disqualify this rule.
    pub exclude_mask: u64,
    pub min_size_bytes: u64,
    pub min_age_secs: i64,
}

pub struct Engine {
    pub rules: Vec<CompiledRule>,
    /// lowercase dir basename -> rule indexes (discovery claims).
    pub dir_names: HashMap<String, Vec<usize>>,
    /// lowercase file basename -> rule indexes.
    pub file_names: HashMap<String, Vec<usize>>,
    /// (lowercase suffix, rule index).
    pub file_suffixes: Vec<(String, usize)>,
    /// Residual full-path globs, one automaton pass for all rules.
    pub path_globs: GlobSet,
    pub path_glob_rules: Vec<usize>,
    /// lowercase ancestor name -> bit in the descent mask.
    pub ancestor_bits: HashMap<String, u64>,
    /// Protection: full-path globs from protect rules + user config.
    pub protect_globs: GlobSet,
    /// Targeted work items: (rule index, root pattern with ~ expanded).
    pub targeted: Vec<(usize, String)>,
}

impl Engine {
    pub fn compile(
        defs: Vec<RuleDef>,
        extra_protect: &[String],
        home: Option<&Path>,
    ) -> Result<Self> {
        let mut dir_names: HashMap<String, Vec<usize>> = HashMap::new();
        let mut file_names: HashMap<String, Vec<usize>> = HashMap::new();
        let mut file_suffixes = Vec::new();
        let mut path_glob_builder = GlobSetBuilder::new();
        let mut path_glob_rules = Vec::new();
        let mut protect_builder = GlobSetBuilder::new();
        let mut targeted = Vec::new();
        let mut ancestor_bits: HashMap<String, u64> = HashMap::new();
        let mut next_bit = 0u32;

        let mut rules = Vec::with_capacity(defs.len());
        for (idx, def) in defs.into_iter().enumerate() {
            let mut exclude_mask = 0u64;
            for name in &def.exclude_ancestors {
                let key = name.to_lowercase();
                let bit = *ancestor_bits.entry(key).or_insert_with(|| {
                    let bit = 1u64 << next_bit;
                    next_bit += 1;
                    bit
                });
                exclude_mask |= bit;
            }
            if next_bit > 64 {
                bail!("more than 64 distinct exclude_ancestors names");
            }

            let sibling_any = if def.require_sibling_any.is_empty() {
                None
            } else {
                let mut builder = GlobSetBuilder::new();
                for pattern in &def.require_sibling_any {
                    builder.add(name_glob(pattern)?);
                }
                Some(
                    builder
                        .build()
                        .with_context(|| format!("rule {}: bad require_sibling_any", def.id))?,
                )
            };

            if def.safety == Safety::Protected {
                for root in &def.roots {
                    let expanded = expand_home(root, home);
                    protect_builder.add(path_glob(&expanded)?);
                    protect_builder.add(path_glob(&format!(
                        "{}/**",
                        expanded.trim_end_matches('/')
                    ))?);
                }
                for glob in &def.path_globs {
                    protect_builder.add(path_glob(&expand_home(glob, home))?);
                }
            } else {
                for root in &def.roots {
                    targeted.push((idx, expand_home(root, home)));
                }
                for name in &def.dir_names {
                    dir_names.entry(name.to_lowercase()).or_default().push(idx);
                }
                for name in &def.file_names {
                    file_names.entry(name.to_lowercase()).or_default().push(idx);
                }
                for suffix in &def.file_suffixes {
                    file_suffixes.push((suffix.to_lowercase(), idx));
                }
                for glob in &def.path_globs {
                    path_glob_builder.add(path_glob(&expand_home(glob, home))?);
                    path_glob_rules.push(idx);
                }
            }

            let min_size_bytes = match &def.min_size {
                Some(s) => parse_size(s)?,
                None => 0,
            };
            let min_age_secs = def.min_age_days.unwrap_or(0) as i64 * 86_400;

            rules.push(CompiledRule {
                def,
                sibling_any,
                exclude_mask,
                min_size_bytes,
                min_age_secs,
            });
        }

        for pattern in extra_protect {
            protect_builder.add(path_glob(&expand_home(pattern, home))?);
        }

        Ok(Self {
            rules,
            dir_names,
            file_names,
            file_suffixes,
            path_globs: path_glob_builder.build().context("bad path_globs")?,
            path_glob_rules,
            ancestor_bits,
            protect_globs: protect_builder.build().context("bad protect globs")?,
            targeted,
        })
    }

    pub fn is_protected(&self, full_path: &str) -> bool {
        self.protect_globs.is_match(full_path)
    }

    /// Bit for a directory name encountered during descent (0 if no rule
    /// excludes it).
    pub fn ancestor_bit(&self, lower_name: &str) -> u64 {
        self.ancestor_bits.get(lower_name).copied().unwrap_or(0)
    }
}

fn expand_home(pattern: &str, home: Option<&Path>) -> String {
    if let (Some(home), Some(rest)) = (home, pattern.strip_prefix("~/")) {
        format!("{}/{}", home.to_string_lossy().trim_end_matches('/'), rest)
    } else {
        pattern.to_string()
    }
}

fn path_glob(pattern: &str) -> Result<globset::Glob> {
    GlobBuilder::new(pattern)
        .literal_separator(true)
        .case_insensitive(cfg!(target_os = "macos") || cfg!(windows))
        .build()
        .with_context(|| format!("invalid glob: {pattern}"))
}

fn name_glob(pattern: &str) -> Result<globset::Glob> {
    GlobBuilder::new(pattern)
        .case_insensitive(true)
        .build()
        .with_context(|| format!("invalid glob: {pattern}"))
}
