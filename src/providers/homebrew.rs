use anyhow::{Context, Result, bail};
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::report::{Confidence, Finding, FindingTarget};
use crate::rules::Safety;
use crate::taxonomy::{Section, Subgroup};
use crate::walk::{InodeDedupe, size_subtree_cancellable};

use super::command::{CommandMode, CommandPolicy, MAX_PARSED_ITEMS, safe_token};
use super::{
    Capability, Provider, ProviderContext, ProviderExecution, ProviderExecutionOptions,
    ProviderFinding, ProviderMetadata, Revalidation, ScanCost, ScanProfile, physical_file_size,
};

pub struct HomebrewProvider;

const BREW_EXECUTABLES: &[&str] = &["/opt/homebrew/bin/brew", "/usr/local/bin/brew", "brew"];

const BREW_PREFIX: CommandPolicy = CommandPolicy {
    id: "homebrew-prefix",
    executables: BREW_EXECUTABLES,
    mutating: false,
    network: false,
    validate_args: args_prefix,
};
const BREW_CACHE: CommandPolicy = CommandPolicy {
    id: "homebrew-cache",
    executables: BREW_EXECUTABLES,
    mutating: false,
    network: false,
    validate_args: args_cache,
};
const BREW_VERSION: CommandPolicy = CommandPolicy {
    id: "homebrew-version",
    executables: BREW_EXECUTABLES,
    mutating: false,
    network: false,
    validate_args: args_version,
};
const BREW_PINNED: CommandPolicy = CommandPolicy {
    id: "homebrew-pinned",
    executables: BREW_EXECUTABLES,
    mutating: false,
    network: false,
    validate_args: args_pinned,
};
const BREW_AUTOREMOVE: CommandPolicy = CommandPolicy {
    id: "homebrew-autoremove-preview",
    executables: BREW_EXECUTABLES,
    mutating: false,
    network: false,
    validate_args: args_autoremove,
};
const BREW_INFO_INSTALLED: CommandPolicy = CommandPolicy {
    id: "homebrew-installed-metadata",
    executables: BREW_EXECUTABLES,
    mutating: false,
    network: false,
    validate_args: args_info_installed,
};
const BREW_CLEANUP_FORMULA: CommandPolicy = CommandPolicy {
    id: "homebrew-cleanup-formula",
    executables: BREW_EXECUTABLES,
    mutating: true,
    network: false,
    validate_args: args_cleanup_formula,
};
const BREW_UNINSTALL_FORMULA: CommandPolicy = CommandPolicy {
    id: "homebrew-uninstall-formula",
    executables: BREW_EXECUTABLES,
    mutating: true,
    network: false,
    validate_args: args_uninstall_formula,
};

fn args_prefix(args: &[OsString]) -> bool {
    args == [OsStr::new("--prefix")]
}

fn args_cache(args: &[OsString]) -> bool {
    args == [OsStr::new("--cache")]
}

fn args_version(args: &[OsString]) -> bool {
    args == [OsStr::new("--version")]
}

fn args_pinned(args: &[OsString]) -> bool {
    args == [
        OsStr::new("list"),
        OsStr::new("--pinned"),
        OsStr::new("--formula"),
    ]
}

fn args_autoremove(args: &[OsString]) -> bool {
    args == [OsStr::new("autoremove"), OsStr::new("--dry-run")]
}

fn args_info_installed(args: &[OsString]) -> bool {
    args == [
        OsStr::new("info"),
        OsStr::new("--json=v2"),
        OsStr::new("--installed"),
    ]
}

fn args_cleanup_formula(args: &[OsString]) -> bool {
    args.len() == 2 && args[0] == "cleanup" && safe_token(&args[1])
}

fn args_uninstall_formula(args: &[OsString]) -> bool {
    args.len() == 3 && args[0] == "uninstall" && args[1] == "--formula" && safe_token(&args[2])
}

#[derive(Debug, Clone)]
struct BrewLayout {
    prefix: PathBuf,
    cellar: PathBuf,
    caskroom: PathBuf,
    cache: PathBuf,
    version: String,
    architecture: String,
}

#[derive(Debug, Clone)]
struct FormulaReceipt {
    full_name: String,
    version: String,
    path: PathBuf,
    keg_path: PathBuf,
    requested: Option<bool>,
    poured_from_bottle: bool,
    dependencies: Vec<String>,
    aliases: Vec<String>,
}

impl Provider for HomebrewProvider {
    fn metadata(&self) -> ProviderMetadata {
        metadata()
    }

    fn probe(&self, context: &ProviderContext) -> Capability {
        if context.runner.resolve(BREW_PREFIX).is_some() {
            Capability::Available
        } else {
            Capability::Unavailable("Homebrew is not installed.".into())
        }
    }

    fn scan(&self, context: &ProviderContext) -> Result<Vec<Finding>> {
        let layout = discover_layout(context)?;
        let pinned = pinned_formulae(context);
        let linked = linked_formulae(&layout.prefix);
        let receipts = read_formula_receipts(&layout.cellar, context)?;
        let cask_dependencies = read_cask_dependencies(&layout.caskroom);
        let excluded = cleanup_exclusions();
        let graph = dependency_analysis(&receipts, &cask_dependencies, &pinned, &linked, &excluded);

        let mut findings = Vec::new();
        findings.extend(cache_findings(&layout, context)?);
        findings.extend(old_keg_findings(&layout, &receipts, &pinned, context));
        findings.extend(dependency_findings(&layout, &receipts, &graph.unreachable));

        if context.settings.profile == ScanProfile::Deep {
            findings.extend(autoremove_disagreements(
                context,
                &layout,
                &graph.reachable,
                &receipts,
            )?);
        }
        Ok(findings)
    }

    fn revalidate(&self, context: &ProviderContext, finding: &Finding) -> Result<Revalidation> {
        let action = finding
            .native_action
            .as_ref()
            .context("Homebrew finding has no native action")?;
        let layout = discover_layout(context)?;
        match action.action_id.as_str() {
            "delete-cache-paths" => {
                let paths = finding_paths(finding);
                if paths.is_empty() {
                    return Ok(Revalidation::Gone("Cache paths no longer exist.".into()));
                }
                for path in paths {
                    if !path.starts_with(&layout.cache) {
                        return Ok(Revalidation::Blocked(
                            "A selected path is outside Homebrew's cache.".into(),
                        ));
                    }
                    if path.symlink_metadata().is_err() {
                        return Ok(Revalidation::Changed(format!(
                            "{} no longer exists.",
                            path.display()
                        )));
                    }
                }
                Ok(Revalidation::Valid)
            }
            "cleanup-formula" | "uninstall-formula" => {
                let refreshed = self.scan(context)?;
                if refreshed
                    .iter()
                    .any(|candidate| candidate.stable_id == finding.stable_id)
                {
                    Ok(Revalidation::Valid)
                } else {
                    Ok(Revalidation::Changed(
                        "Homebrew metadata changed and this object is no longer a candidate."
                            .into(),
                    ))
                }
            }
            _ => Ok(Revalidation::Blocked("Unknown Homebrew action.".into())),
        }
    }

    fn execute(
        &self,
        context: &ProviderContext,
        finding: &Finding,
        options: ProviderExecutionOptions,
    ) -> Result<ProviderExecution> {
        match self.revalidate(context, finding)? {
            Revalidation::Valid => {}
            Revalidation::Changed(message)
            | Revalidation::Gone(message)
            | Revalidation::Blocked(message) => bail!("{message}"),
        }
        let action = finding
            .native_action
            .as_ref()
            .context("Homebrew action missing")?;
        match action.action_id.as_str() {
            "delete-cache-paths" => {
                let mut deleted = 0;
                for path in finding_paths(finding) {
                    delete_path(path, options.permanently)?;
                    deleted += 1;
                }
                Ok(ProviderExecution {
                    deleted,
                    freed_bytes: finding.bytes,
                    message: "Homebrew cache paths removed.".into(),
                })
            }
            "cleanup-formula" => {
                run_mutation(
                    context,
                    BREW_CLEANUP_FORMULA,
                    &["cleanup", &action.object_id],
                )?;
                Ok(ProviderExecution {
                    deleted: 1,
                    freed_bytes: finding.bytes,
                    message: format!("Cleaned old Homebrew kegs for {}.", action.object_id),
                })
            }
            "uninstall-formula" => {
                run_mutation(
                    context,
                    BREW_UNINSTALL_FORMULA,
                    &["uninstall", "--formula", &action.object_id],
                )?;
                Ok(ProviderExecution {
                    deleted: 1,
                    freed_bytes: finding.bytes,
                    message: format!("Uninstalled unused formula {}.", action.object_id),
                })
            }
            _ => bail!("unknown Homebrew action {}", action.action_id),
        }
    }
}

fn metadata() -> ProviderMetadata {
    ProviderMetadata {
        id: "homebrew",
        name: "Homebrew",
        section: Section::Developer,
        subgroup: Subgroup::Packages,
        cost: ScanCost::Fast,
        quick: true,
        deep: true,
        network_in_deep_scan: false,
        supersedes_rules: &["homebrew-cache"],
    }
}

fn discover_layout(context: &ProviderContext) -> Result<BrewLayout> {
    let prefix = run_text(context, BREW_PREFIX, &["--prefix"], Duration::from_secs(2))?;
    let cache = run_text(context, BREW_CACHE, &["--cache"], Duration::from_secs(2))?;
    let version = run_text(
        context,
        BREW_VERSION,
        &["--version"],
        Duration::from_secs(2),
    )?;
    let prefix = PathBuf::from(prefix.lines().next().unwrap_or_default());
    if !prefix.is_absolute() {
        bail!("Homebrew returned an invalid prefix");
    }
    let cache = PathBuf::from(cache.lines().next().unwrap_or_default());
    if !cache.is_absolute() {
        bail!("Homebrew returned an invalid cache path");
    }
    Ok(BrewLayout {
        cellar: prefix.join("Cellar"),
        caskroom: prefix.join("Caskroom"),
        prefix,
        cache,
        version: version.lines().next().unwrap_or("Homebrew").to_string(),
        architecture: std::env::consts::ARCH.to_string(),
    })
}

fn run_text(
    context: &ProviderContext,
    policy: CommandPolicy,
    args: &[&str],
    timeout: Duration,
) -> Result<String> {
    let args: Vec<OsString> = args.iter().map(OsString::from).collect();
    let output = context.runner.run(
        policy,
        &args,
        CommandMode::ReadOnly,
        Some(context.remaining(timeout)),
        &context.cancel,
    )?;
    if !output.status.success() {
        bail!(
            "{} failed: {}",
            policy.id,
            output.stderr.lines().next().unwrap_or("unknown error")
        );
    }
    Ok(output.stdout)
}

fn run_mutation(context: &ProviderContext, policy: CommandPolicy, args: &[&str]) -> Result<()> {
    let args: Vec<OsString> = args.iter().map(OsString::from).collect();
    let output = context.runner.run(
        policy,
        &args,
        CommandMode::Mutation,
        Some(context.remaining(Duration::from_secs(120))),
        &context.cancel,
    )?;
    if !output.status.success() {
        bail!(
            "{} failed: {}",
            policy.id,
            output.stderr.lines().next().unwrap_or("unknown error")
        );
    }
    Ok(())
}

fn pinned_formulae(context: &ProviderContext) -> HashSet<String> {
    run_text(
        context,
        BREW_PINNED,
        &["list", "--pinned", "--formula"],
        Duration::from_secs(3),
    )
    .map(|output| output.lines().map(normalize_name).collect())
    .unwrap_or_default()
}

fn cleanup_exclusions() -> HashSet<String> {
    std::env::var("HOMEBREW_NO_CLEANUP_FORMULAE")
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(normalize_name)
        .collect()
}

fn linked_formulae(prefix: &Path) -> HashSet<String> {
    prefix
        .join("var/homebrew/linked")
        .read_dir()
        .into_iter()
        .flatten()
        .flatten()
        .map(|entry| normalize_name(entry.file_name().to_string_lossy()))
        .collect()
}

fn read_formula_receipts(
    cellar: &Path,
    context: &ProviderContext,
) -> Result<HashMap<String, Vec<FormulaReceipt>>> {
    let mut result = HashMap::new();
    let Ok(racks) = cellar.read_dir() else {
        return Ok(result);
    };
    for rack in racks.flatten().take(MAX_PARSED_ITEMS) {
        if context.cancel.load(Ordering::Relaxed) {
            break;
        }
        let Ok(metadata) = rack.file_type() else {
            continue;
        };
        if !metadata.is_dir() {
            continue;
        }
        let name = rack.file_name().to_string_lossy().to_string();
        let mut versions = Vec::new();
        if let Ok(entries) = rack.path().read_dir() {
            for version in entries.flatten().take(1_000) {
                if !version.file_type().is_ok_and(|kind| kind.is_dir()) {
                    continue;
                }
                let receipt_path = version.path().join("INSTALL_RECEIPT.json");
                let Ok(data) = std::fs::read_to_string(&receipt_path) else {
                    continue;
                };
                let Ok(json) = serde_json::from_str::<Value>(&data) else {
                    continue;
                };
                let source_tap = json
                    .pointer("/source/tap")
                    .and_then(Value::as_str)
                    .unwrap_or("homebrew/core");
                let full_name = if source_tap == "homebrew/core" {
                    name.clone()
                } else {
                    format!("{source_tap}/{name}")
                };
                let dependencies = json
                    .get("runtime_dependencies")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                    .filter_map(|dependency| {
                        dependency
                            .get("full_name")
                            .and_then(Value::as_str)
                            .map(normalize_name)
                    })
                    .collect();
                let aliases = json
                    .get("aliases")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                    .filter_map(Value::as_str)
                    .map(normalize_name)
                    .collect();
                versions.push(FormulaReceipt {
                    full_name,
                    version: version.file_name().to_string_lossy().to_string(),
                    path: receipt_path,
                    keg_path: version.path(),
                    requested: json.get("installed_on_request").and_then(Value::as_bool),
                    poured_from_bottle: json
                        .get("poured_from_bottle")
                        .and_then(Value::as_bool)
                        .unwrap_or(false),
                    dependencies,
                    aliases,
                });
            }
        }
        if !versions.is_empty() {
            result.insert(name, versions);
        }
    }
    Ok(result)
}

fn read_cask_dependencies(caskroom: &Path) -> HashSet<String> {
    let mut dependencies = HashSet::new();
    let Ok(casks) = caskroom.read_dir() else {
        return dependencies;
    };
    for cask in casks.flatten().take(10_000) {
        let receipt = cask.path().join(".metadata/INSTALL_RECEIPT.json");
        let Ok(data) = std::fs::read_to_string(receipt) else {
            continue;
        };
        let Ok(json) = serde_json::from_str::<Value>(&data) else {
            continue;
        };
        if let Some(formulae) = json
            .pointer("/runtime_dependencies/formula")
            .and_then(Value::as_array)
        {
            for formula in formulae {
                if let Some(name) = formula.get("full_name").and_then(Value::as_str) {
                    dependencies.insert(normalize_name(name));
                }
            }
        }
    }
    dependencies
}

struct DependencyGraph {
    reachable: HashSet<String>,
    unreachable: Vec<String>,
}

fn dependency_analysis(
    receipts: &HashMap<String, Vec<FormulaReceipt>>,
    cask_dependencies: &HashSet<String>,
    pinned: &HashSet<String>,
    linked: &HashSet<String>,
    excluded: &HashSet<String>,
) -> DependencyGraph {
    let mut roots = Vec::new();
    for (name, versions) in receipts {
        if versions
            .iter()
            .any(|receipt| receipt.requested != Some(false) || !receipt.poured_from_bottle)
            || pinned.contains(name)
            || linked.contains(name)
            || excluded.contains(name)
        {
            roots.push(name.clone());
        }
    }
    roots.extend(cask_dependencies.iter().cloned());

    let aliases: HashMap<String, String> = receipts
        .iter()
        .flat_map(|(name, versions)| {
            versions
                .iter()
                .flat_map(|receipt| receipt.aliases.iter())
                .map(move |alias| (alias.clone(), name.clone()))
        })
        .collect();
    let mut reachable = HashSet::new();
    let mut stack = roots;
    while let Some(raw_name) = stack.pop() {
        let name = aliases.get(&raw_name).cloned().unwrap_or(raw_name);
        if !reachable.insert(name.clone()) {
            continue;
        }
        if let Some(versions) = receipts.get(&name) {
            stack.extend(
                versions
                    .iter()
                    .flat_map(|receipt| receipt.dependencies.iter().cloned()),
            );
        }
    }
    let mut unreachable: Vec<_> = receipts
        .iter()
        .filter(|(name, versions)| {
            versions
                .iter()
                .all(|receipt| receipt.requested == Some(false) && receipt.poured_from_bottle)
                && !reachable.contains(*name)
        })
        .map(|(name, _)| name.clone())
        .collect();
    unreachable.sort();
    DependencyGraph {
        reachable,
        unreachable,
    }
}

fn active_receipt(receipts: &[FormulaReceipt]) -> Option<&FormulaReceipt> {
    receipts.iter().max_by_key(|receipt| {
        receipt
            .path
            .metadata()
            .and_then(|metadata| metadata.modified())
            .unwrap_or(UNIX_EPOCH)
    })
}

fn cache_findings(layout: &BrewLayout, context: &ProviderContext) -> Result<Vec<Finding>> {
    let mut incomplete = Vec::new();
    let mut old = Vec::new();
    let mut stale_metadata = stale_api_source_files(layout, context);
    collect_cache_files(
        &layout.cache,
        &layout.cache,
        context,
        &mut incomplete,
        &mut old,
        0,
    )?;
    let stale_set: HashSet<_> = stale_metadata.iter().cloned().collect();
    old.retain(|path| !stale_set.contains(path));
    let mut findings = Vec::new();
    let active = context.running_commands.iter().any(|command| {
        command.contains("brew install")
            || command.contains("brew upgrade")
            || command.contains("brew cleanup")
    });
    if !incomplete.is_empty() {
        findings.push(cache_group(
            layout,
            "homebrew-incomplete-downloads",
            "incomplete-downloads",
            "Incomplete Homebrew downloads",
            incomplete,
            "These partial downloads cannot be installed and Homebrew will fetch them again.",
            active,
        ));
    }
    if !old.is_empty() {
        findings.push(cache_group(
            layout,
            "homebrew-old-cache",
            "old-cache",
            "Homebrew downloads older than 120 days",
            old,
            "These files exceed Homebrew's normal cache-retention window.",
            active,
        ));
    }
    if !stale_metadata.is_empty() {
        findings.push(cache_group(
            layout,
            "homebrew-stale-api-metadata",
            "stale-api-metadata",
            "Stale Homebrew API source metadata",
            std::mem::take(&mut stale_metadata),
            "The cached tap commit does not match the current local tap HEAD.",
            active,
        ));
    }
    Ok(findings)
}

fn stale_api_source_files(layout: &BrewLayout, context: &ProviderContext) -> Vec<PathBuf> {
    let heads = local_tap_heads(&layout.prefix);
    let root = layout.cache.join("api-source");
    let mut files = Vec::new();
    let Ok(organizations) = root.read_dir() else {
        return files;
    };
    for organization in organizations.flatten().take(5_000) {
        let org = organization.file_name().to_string_lossy().to_string();
        let Ok(repositories) = organization.path().read_dir() else {
            continue;
        };
        for repository in repositories.flatten().take(5_000) {
            let repo = repository.file_name().to_string_lossy().to_string();
            let head = heads
                .get(&(org.clone(), repo.clone()))
                .or_else(|| heads.get(&(org.clone(), format!("homebrew-{repo}"))));
            let Some(head) = head else {
                continue;
            };
            let Ok(commits) = repository.path().read_dir() else {
                continue;
            };
            for commit in commits.flatten().take(5_000) {
                if context.is_cancelled() {
                    return files;
                }
                if commit.file_name().to_string_lossy() != head.as_str() {
                    collect_regular_files(&commit.path(), &mut files, 0);
                }
            }
        }
    }
    files
}

fn local_tap_heads(prefix: &Path) -> HashMap<(String, String), String> {
    let mut heads = HashMap::new();
    let taps = prefix.join("Library/Taps");
    let Ok(organizations) = taps.read_dir() else {
        return heads;
    };
    for organization in organizations.flatten() {
        let org = organization.file_name().to_string_lossy().to_string();
        let Ok(repositories) = organization.path().read_dir() else {
            continue;
        };
        for repository in repositories.flatten() {
            if let Some(head) = read_git_head(&repository.path().join(".git")) {
                heads.insert(
                    (
                        org.clone(),
                        repository.file_name().to_string_lossy().to_string(),
                    ),
                    head,
                );
            }
        }
    }
    heads
}

fn read_git_head(git_dir: &Path) -> Option<String> {
    let head = std::fs::read_to_string(git_dir.join("HEAD")).ok()?;
    let head = head.trim();
    if let Some(reference) = head.strip_prefix("ref: ") {
        if let Ok(value) = std::fs::read_to_string(git_dir.join(reference)) {
            return Some(value.trim().to_string());
        }
        let packed = std::fs::read_to_string(git_dir.join("packed-refs")).ok()?;
        return packed.lines().find_map(|line| {
            let (hash, name) = line.split_once(' ')?;
            (name == reference).then(|| hash.to_string())
        });
    }
    Some(head.to_string())
}

fn collect_regular_files(directory: &Path, files: &mut Vec<PathBuf>, depth: usize) {
    if depth > 12 || files.len() >= 50_000 {
        return;
    }
    let Ok(entries) = directory.read_dir() else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let Ok(metadata) = path.symlink_metadata() else {
            continue;
        };
        if metadata.is_dir() {
            collect_regular_files(&path, files, depth + 1);
        } else if metadata.is_file() {
            files.push(path);
        }
    }
}

fn collect_cache_files(
    cache_root: &Path,
    directory: &Path,
    context: &ProviderContext,
    incomplete: &mut Vec<PathBuf>,
    old: &mut Vec<PathBuf>,
    depth: usize,
) -> Result<()> {
    if depth > 12 || context.is_cancelled() {
        return Ok(());
    }
    let Ok(entries) = directory.read_dir() else {
        return Ok(());
    };
    let now = SystemTime::now();
    for entry in entries.flatten().take(50_000) {
        let path = entry.path();
        if !path.starts_with(cache_root) {
            continue;
        }
        let Ok(metadata) = path.symlink_metadata() else {
            continue;
        };
        if metadata.file_type().is_symlink() {
            continue;
        }
        if metadata.is_dir() {
            collect_cache_files(cache_root, &path, context, incomplete, old, depth + 1)?;
            continue;
        }
        let name = entry.file_name().to_string_lossy().to_ascii_lowercase();
        if name.ends_with(".incomplete") || name.contains(".incomplete.") {
            incomplete.push(path);
            continue;
        }
        let age = metadata
            .modified()
            .ok()
            .and_then(|modified| now.duration_since(modified).ok())
            .map(|duration| duration.as_secs() / 86_400)
            .unwrap_or(0);
        if age >= 120 {
            old.push(path);
        }
    }
    Ok(())
}

fn cache_group(
    layout: &BrewLayout,
    rule_id: &str,
    object_id: &str,
    label: &str,
    paths: Vec<PathBuf>,
    reason: &str,
    active: bool,
) -> Finding {
    let bytes = paths.iter().map(|path| physical_file_size(path)).sum();
    let builder = ProviderFinding::object(
        metadata(),
        rule_id,
        "package-manager-cache",
        object_id,
        label,
        Safety::Safe,
        bytes,
    )
    .grouped_paths(paths)
    .supersedes("homebrew-cache")
    .reason(reason)
    .evidence("Homebrew", &layout.version)
    .evidence("Architecture", &layout.architecture)
    .evidence("Cache", layout.cache.display().to_string())
    .copy(
        "Download and metadata files owned by Homebrew's cache.",
        "Homebrew downloads the selected files again if they are needed.",
        "Safe to clean when no Homebrew install or upgrade is currently running.",
    )
    .action(
        "delete-cache-paths",
        vec!["remove exact Homebrew cache paths".into()],
        false,
        false,
    );
    if active {
        builder.in_use().build()
    } else {
        builder.build()
    }
}

fn old_keg_findings(
    layout: &BrewLayout,
    receipts: &HashMap<String, Vec<FormulaReceipt>>,
    pinned: &HashSet<String>,
    context: &ProviderContext,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    for (name, versions) in receipts {
        if versions.len() < 2 || pinned.contains(name) || context.is_cancelled() {
            continue;
        }
        let active = active_keg_version(layout, name)
            .or_else(|| active_receipt(versions).map(|receipt| receipt.version.clone()));
        let old: Vec<_> = versions
            .iter()
            .filter(|receipt| {
                Some(&receipt.version) != active.as_ref()
                    && !has_live_keepme_reference(&receipt.keg_path)
            })
            .collect();
        if old.is_empty() {
            continue;
        }
        let dedupe = InodeDedupe::new();
        let mut bytes = 0;
        let mut paths = Vec::new();
        for receipt in &old {
            let stats = size_subtree_cancellable(
                &receipt.keg_path,
                &dedupe,
                None,
                Some(context.cancel.as_ref()),
            );
            bytes += stats.bytes;
            paths.push(receipt.keg_path.clone());
        }
        if bytes < context.settings.min_size_bytes {
            continue;
        }
        let full_name = active_receipt(versions)
            .map(|receipt| receipt.full_name.clone())
            .unwrap_or_else(|| name.clone());
        let old_versions = old
            .iter()
            .map(|receipt| receipt.version.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        findings.push(
            ProviderFinding::object(
                metadata(),
                "homebrew-old-kegs",
                "installed-tools",
                &full_name,
                format!("{name}: old installed versions"),
                Safety::Review,
                bytes,
            )
            .grouped_paths(paths)
            .manual()
            .reason("The formula rack contains versions other than the active keg.")
            .evidence("Active version", active.unwrap_or_else(|| "unknown".into()))
            .evidence("Old versions", old_versions)
            .evidence("Architecture", &layout.architecture)
            .copy(
                "Older installed Homebrew keg versions retained beside the active version.",
                "Commands or projects pinned to an old keg may stop working.",
                "Let Homebrew validate and remove eligible old kegs for this formula.",
            )
            .action(
                "cleanup-formula",
                vec!["brew".into(), "cleanup".into(), full_name],
                true,
                true,
            )
            .build(),
        );
    }
    findings
}

fn active_keg_version(layout: &BrewLayout, name: &str) -> Option<String> {
    let target = std::fs::read_link(layout.prefix.join("opt").join(name)).ok()?;
    target
        .file_name()
        .map(|name| name.to_string_lossy().to_string())
}

fn has_live_keepme_reference(keg: &Path) -> bool {
    std::fs::read_to_string(keg.join(".keepme"))
        .ok()
        .is_some_and(|contents| {
            contents
                .lines()
                .map(str::trim)
                .any(|path| !path.is_empty() && Path::new(path).exists())
        })
}

fn dependency_findings(
    layout: &BrewLayout,
    receipts: &HashMap<String, Vec<FormulaReceipt>>,
    candidates: &[String],
) -> Vec<Finding> {
    candidates
        .iter()
        .filter_map(|name| {
            let receipt = active_receipt(receipts.get(name)?)?;
            let bytes = size_subtree_cancellable(
                &receipt.keg_path,
                &InodeDedupe::new(),
                None,
                None,
            )
            .bytes;
            Some(
                ProviderFinding::object(
                    metadata(),
                    "homebrew-unused-dependency",
                    "installed-tools",
                    &receipt.full_name,
                    format!("{name}: probable unused dependency"),
                    Safety::Review,
                    bytes,
                )
                .manual()
                .confidence(Confidence::High)
                .reason(
                    "No requested formula, source build, pinned formula, cask, or retained receipt dependency reaches this keg.",
                )
                .evidence("Installed version", &receipt.version)
                .evidence("Cellar", layout.cellar.display().to_string())
                .evidence("Architecture", &layout.architecture)
                .copy(
                    "A bottled formula installed as a dependency that is unreachable in the complete local receipt graph.",
                    "Removing it is safe only while no external/manual software links against the keg.",
                    "Review the formula name. Hokori rechecks the graph immediately before asking Homebrew to uninstall it.",
                )
                .action(
                    "uninstall-formula",
                    vec![
                        "brew".into(),
                        "uninstall".into(),
                        "--formula".into(),
                        receipt.full_name.clone(),
                    ],
                    true,
                    true,
                )
                .build(),
            )
        })
        .collect()
}

fn autoremove_disagreements(
    context: &ProviderContext,
    layout: &BrewLayout,
    reachable: &HashSet<String>,
    receipts: &HashMap<String, Vec<FormulaReceipt>>,
) -> Result<Vec<Finding>> {
    let output = run_text(
        context,
        BREW_AUTOREMOVE,
        &["autoremove", "--dry-run"],
        Duration::from_secs(8),
    )?;
    let suggested: HashSet<_> = output
        .lines()
        .map(str::trim)
        .filter(|line| {
            !line.is_empty()
                && !line.starts_with("==>")
                && !line.starts_with("Warning:")
                && !line.contains(' ')
        })
        .map(normalize_name)
        .collect();
    let current_metadata = current_formula_names(context);
    Ok(suggested
        .intersection(reachable)
        .map(|name| {
            let receipt_dependents: Vec<_> = receipts
                .iter()
                .filter_map(|(dependent, versions)| {
                    active_receipt(versions)
                        .filter(|receipt| receipt.dependencies.contains(name))
                        .map(|_| dependent.clone())
                })
                .collect();
            let omitted: Vec<_> = receipt_dependents
                .iter()
                .filter(|dependent| !current_metadata.contains(*dependent))
                .cloned()
                .collect();
            let binary_links = binary_link_dependents(name, receipts, &layout.prefix);
            ProviderFinding::object(
                metadata(),
                "homebrew-autoremove-disagreement",
                "installed-tools",
                name,
                format!("{name}: protected despite Homebrew autoremove"),
                Safety::Protected,
                0,
            )
            .protected()
            .confidence(Confidence::Exact)
            .reason(
                "Homebrew proposed removal, but at least one installed receipt or cask still reaches this formula.",
            )
            .evidence("Homebrew", &layout.version)
            .evidence("Architecture", &layout.architecture)
            .evidence(
                "Receipt dependents",
                if receipt_dependents.is_empty() {
                    "none".into()
                } else {
                    receipt_dependents.join(", ")
                },
            )
            .evidence(
                "Current metadata omissions",
                if omitted.is_empty() {
                    "none".into()
                } else {
                    omitted.join(", ")
                },
            )
            .evidence(
                "Binary linkage",
                if binary_links.is_empty() {
                    "not observed".into()
                } else {
                    binary_links.join(", ")
                },
            )
            .copy(
                "A disagreement between Homebrew's resolved formula inventory and the complete installed receipt graph.",
                "Following Homebrew's bulk autoremove output could break an installed formula from a migrated or unavailable tap.",
                "Leave this formula installed until the dependent formula is removed or repaired.",
            )
            .build()
        })
        .collect())
}

fn current_formula_names(context: &ProviderContext) -> HashSet<String> {
    run_text(
        context,
        BREW_INFO_INSTALLED,
        &["info", "--json=v2", "--installed"],
        Duration::from_secs(8),
    )
    .ok()
    .and_then(|output| serde_json::from_str::<Value>(&output).ok())
    .and_then(|json| json.get("formulae").and_then(Value::as_array).cloned())
    .into_iter()
    .flatten()
    .filter_map(|formula| {
        formula
            .get("name")
            .and_then(Value::as_str)
            .map(normalize_name)
    })
    .collect()
}

fn binary_link_dependents(
    dependency: &str,
    receipts: &HashMap<String, Vec<FormulaReceipt>>,
    prefix: &Path,
) -> Vec<String> {
    let needle = format!("{}/opt/{dependency}/", prefix.display()).into_bytes();
    let mut linked = Vec::new();
    for (name, versions) in receipts {
        let Some(receipt) = active_receipt(versions) else {
            continue;
        };
        if !receipt.dependencies.contains(&dependency.to_string()) {
            continue;
        }
        let mut inspected = 0usize;
        if tree_contains_bytes(&receipt.keg_path, &needle, 0, &mut inspected) {
            linked.push(name.clone());
        }
    }
    linked
}

fn tree_contains_bytes(
    directory: &Path,
    needle: &[u8],
    depth: usize,
    inspected: &mut usize,
) -> bool {
    if depth > 8 || *inspected >= 500 {
        return false;
    }
    let Ok(entries) = directory.read_dir() else {
        return false;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let Ok(metadata) = path.symlink_metadata() else {
            continue;
        };
        if metadata.is_dir() {
            if tree_contains_bytes(&path, needle, depth + 1, inspected) {
                return true;
            }
        } else if metadata.is_file() && metadata.len() <= 32 * 1024 * 1024 {
            *inspected += 1;
            if let Ok(bytes) = std::fs::read(&path)
                && bytes.windows(needle.len()).any(|window| window == needle)
            {
                return true;
            }
        }
    }
    false
}

fn normalize_name(name: impl AsRef<str>) -> String {
    name.as_ref()
        .rsplit('/')
        .next()
        .unwrap_or_default()
        .to_string()
}

fn finding_paths(finding: &Finding) -> Vec<&Path> {
    match &finding.target {
        FindingTarget::Filesystem { path } => vec![path.as_path()],
        FindingTarget::GroupedPaths { paths, .. } => paths.iter().map(PathBuf::as_path).collect(),
        FindingTarget::ProviderObject { .. } | FindingTarget::Diagnostic { .. } => Vec::new(),
    }
}

fn delete_path(path: &Path, permanently: bool) -> Result<()> {
    if permanently {
        if path.is_dir() {
            std::fs::remove_dir_all(path)?;
        } else {
            std::fs::remove_file(path)?;
        }
        return Ok(());
    }
    #[cfg(target_os = "macos")]
    {
        use trash::macos::{DeleteMethod, TrashContextExtMacos};
        let mut context = trash::TrashContext::default();
        context.set_delete_method(DeleteMethod::NsFileManager);
        context.delete(path)?;
    }
    #[cfg(not(target_os = "macos"))]
    trash::delete(path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn receipt(name: &str, requested: bool, dependencies: &[&str]) -> FormulaReceipt {
        FormulaReceipt {
            full_name: name.into(),
            version: "1.0".into(),
            path: PathBuf::from(format!("/{name}/INSTALL_RECEIPT.json")),
            keg_path: PathBuf::from(format!("/{name}/1.0")),
            requested: Some(requested),
            poured_from_bottle: true,
            dependencies: dependencies.iter().map(|name| name.to_string()).collect(),
            aliases: Vec::new(),
        }
    }

    #[test]
    fn complete_receipt_graph_protects_untrusted_tap_dependencies() {
        let receipts = HashMap::from([
            (
                "krunkit".into(),
                vec![receipt("krunkit", true, &["libkrun"])],
            ),
            (
                "libkrun".into(),
                vec![receipt("libkrun", false, &["libepoxy"])],
            ),
            ("libepoxy".into(), vec![receipt("libepoxy", false, &[])]),
        ]);
        let graph = dependency_analysis(
            &receipts,
            &HashSet::new(),
            &HashSet::new(),
            &HashSet::new(),
            &HashSet::new(),
        );
        assert!(graph.reachable.contains("libepoxy"));
        assert!(!graph.unreachable.contains(&"libepoxy".into()));
    }

    #[test]
    fn aliases_keep_renamed_formulae_reachable() {
        let mut renamed = receipt("new-name", false, &["leaf"]);
        renamed.aliases.push("old-name".into());
        let receipts = HashMap::from([
            ("root".into(), vec![receipt("root", true, &["old-name"])]),
            ("new-name".into(), vec![renamed]),
            ("leaf".into(), vec![receipt("leaf", false, &[])]),
        ]);
        let graph = dependency_analysis(
            &receipts,
            &HashSet::new(),
            &HashSet::new(),
            &HashSet::new(),
            &HashSet::new(),
        );
        assert!(graph.reachable.contains("new-name"));
        assert!(graph.reachable.contains("leaf"));
    }
}
