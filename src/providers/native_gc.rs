use anyhow::{Context, Result, bail};
use serde_json::Value;
use std::ffi::{OsStr, OsString};
use std::time::Duration;

use crate::report::{Confidence, Finding};
use crate::rules::Safety;
use crate::taxonomy::{Section, Subgroup};

use super::command::{CommandMode, CommandPolicy};
use super::{
    Capability, Provider, ProviderContext, ProviderExecution, ProviderExecutionOptions,
    ProviderFinding, ProviderMetadata, Revalidation, ScanCost, parse_human_bytes,
};

pub struct NativeGcProvider;

const CONDA: &[&str] = &["conda"];
const NIX: &[&str] = &["nix"];
const PORT: &[&str] = &["/opt/local/bin/port", "port"];

const CONDA_PREVIEW: CommandPolicy = CommandPolicy {
    id: "conda-clean-preview",
    executables: CONDA,
    mutating: false,
    network: false,
    validate_args: args_conda_preview,
};
const CONDA_CLEAN: CommandPolicy = CommandPolicy {
    id: "conda-clean",
    executables: CONDA,
    mutating: true,
    network: false,
    validate_args: args_conda_clean,
};
const NIX_PREVIEW: CommandPolicy = CommandPolicy {
    id: "nix-store-gc-preview",
    executables: NIX,
    mutating: false,
    network: false,
    validate_args: args_nix_preview,
};
const NIX_GC: CommandPolicy = CommandPolicy {
    id: "nix-store-gc",
    executables: NIX,
    mutating: true,
    network: false,
    validate_args: args_nix_gc,
};
const PORT_PREVIEW: CommandPolicy = CommandPolicy {
    id: "macports-reclaim-preview",
    executables: PORT,
    mutating: false,
    network: false,
    validate_args: args_port_preview,
};
const PORT_RECLAIM: CommandPolicy = CommandPolicy {
    id: "macports-reclaim",
    executables: PORT,
    mutating: true,
    network: false,
    validate_args: args_port_reclaim,
};

fn args_conda_preview(args: &[OsString]) -> bool {
    args == [
        OsStr::new("clean"),
        OsStr::new("--all"),
        OsStr::new("--dry-run"),
        OsStr::new("--json"),
    ]
}

fn args_conda_clean(args: &[OsString]) -> bool {
    args == [
        OsStr::new("clean"),
        OsStr::new("--all"),
        OsStr::new("--yes"),
    ]
}

fn args_nix_preview(args: &[OsString]) -> bool {
    args == [
        OsStr::new("store"),
        OsStr::new("gc"),
        OsStr::new("--dry-run"),
        OsStr::new("--json"),
    ]
}

fn args_nix_gc(args: &[OsString]) -> bool {
    args == [OsStr::new("store"), OsStr::new("gc")]
}

fn args_port_preview(args: &[OsString]) -> bool {
    args == [OsStr::new("-y"), OsStr::new("reclaim")]
}

fn args_port_reclaim(args: &[OsString]) -> bool {
    args == [OsStr::new("-N"), OsStr::new("reclaim")]
}

impl Provider for NativeGcProvider {
    fn metadata(&self) -> ProviderMetadata {
        metadata()
    }

    fn probe(&self, context: &ProviderContext) -> Capability {
        if [CONDA_PREVIEW, NIX_PREVIEW, PORT_PREVIEW]
            .into_iter()
            .any(|policy| context.runner.resolve(policy).is_some())
        {
            Capability::Available
        } else {
            Capability::Unavailable("Conda, Nix, and MacPorts are not installed.".into())
        }
    }

    fn scan(&self, context: &ProviderContext) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        if context.runner.resolve(CONDA_PREVIEW).is_some() {
            findings.extend(conda_findings(context));
        }
        if context.runner.resolve(NIX_PREVIEW).is_some() {
            findings.extend(nix_findings(context));
        }
        if context.runner.resolve(PORT_PREVIEW).is_some() {
            findings.extend(macports_findings(context));
        }
        Ok(findings)
    }

    fn revalidate(&self, context: &ProviderContext, finding: &Finding) -> Result<Revalidation> {
        let refreshed = self.scan(context)?;
        if refreshed
            .iter()
            .any(|candidate| candidate.stable_id == finding.stable_id)
        {
            Ok(Revalidation::Valid)
        } else {
            Ok(Revalidation::Changed(
                "The package manager's garbage-collection result changed.".into(),
            ))
        }
    }

    fn execute(
        &self,
        context: &ProviderContext,
        finding: &Finding,
        _options: ProviderExecutionOptions,
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
            .context("native GC action missing")?;
        let (policy, args): (CommandPolicy, &[&str]) = match action.action_id.as_str() {
            "conda-clean" => (CONDA_CLEAN, &["clean", "--all", "--yes"]),
            "nix-gc" => (NIX_GC, &["store", "gc"]),
            "macports-reclaim" => (PORT_RECLAIM, &["-N", "reclaim"]),
            _ => bail!("unknown native GC action {}", action.action_id),
        };
        run_mutation(context, policy, args)?;
        Ok(ProviderExecution {
            deleted: 1,
            freed_bytes: finding.bytes,
            message: format!("{} completed.", action.preview.join(" ")),
        })
    }
}

fn metadata() -> ProviderMetadata {
    ProviderMetadata {
        id: "native-gc",
        name: "Native package garbage collectors",
        section: Section::Developer,
        subgroup: Subgroup::Packages,
        cost: ScanCost::Moderate,
        quick: true,
        deep: true,
        network_in_deep_scan: false,
        supersedes_rules: &["conda-package-cache"],
    }
}

fn conda_findings(context: &ProviderContext) -> Vec<Finding> {
    let Ok(output) = run_read(
        context,
        CONDA_PREVIEW,
        &["clean", "--all", "--dry-run", "--json"],
        Duration::from_secs(12),
    ) else {
        return Vec::new();
    };
    let Ok(json) = serde_json::from_str::<Value>(&output) else {
        return Vec::new();
    };
    let bytes = recursive_size(&json);
    let count = recursive_path_count(&json);
    if bytes < context.settings.min_size_bytes && count == 0 {
        return Vec::new();
    }
    vec![
        ProviderFinding::object(
            metadata(),
            "conda-native-gc",
            "package-manager-cache",
            "conda-clean-all",
            "Conda unused packages and caches",
            Safety::Review,
            bytes,
        )
        .confidence(Confidence::Exact)
        .reason("Conda's own dry run identified package caches, tarballs, indexes, locks, or logs it can remove.")
        .evidence("Objects", count.to_string())
        .copy(
            "Unused package cache entries selected by Conda itself; environments are not removed.",
            "Future environment solves may download packages again.",
            "Use Conda's native clean command so linked package files and environments remain consistent.",
        )
        .action(
            "conda-clean",
            vec!["conda".into(), "clean".into(), "--all".into(), "--yes".into()],
            true,
            false,
        )
        .build(),
    ]
}

fn nix_findings(context: &ProviderContext) -> Vec<Finding> {
    let Ok(output) = run_read(
        context,
        NIX_PREVIEW,
        &["store", "gc", "--dry-run", "--json"],
        Duration::from_secs(20),
    ) else {
        return Vec::new();
    };
    let json = serde_json::from_str::<Value>(&output).ok();
    let bytes = json.as_ref().map(recursive_size).unwrap_or_else(|| {
        output
            .lines()
            .filter_map(|line| line.split_whitespace().find_map(parse_human_bytes))
            .sum()
    });
    let count = json.as_ref().map(recursive_path_count).unwrap_or_else(|| {
        output
            .lines()
            .filter(|line| line.contains("/nix/store/"))
            .count()
    });
    if bytes < context.settings.min_size_bytes && count == 0 {
        return Vec::new();
    }
    vec![
        ProviderFinding::object(
            metadata(),
            "nix-unreachable-store-paths",
            "package-manager-cache",
            "nix-store-gc",
            "Unreachable Nix store paths",
            Safety::Safe,
            bytes,
        )
        .confidence(Confidence::Exact)
        .reason("Nix's garbage collector reports these store paths unreachable from current roots.")
        .evidence("Store paths", count.to_string())
        .copy(
            "Immutable Nix store paths unreachable from current profiles and garbage-collector roots.",
            "Rebuilding an old environment may download or rebuild the paths.",
            "Profile-generation deletion remains separate; this action runs only Nix store GC.",
        )
        .action(
            "nix-gc",
            vec!["nix".into(), "store".into(), "gc".into()],
            true,
            false,
        )
        .build(),
    ]
}

fn macports_findings(context: &ProviderContext) -> Vec<Finding> {
    let Ok(output) = run_read(
        context,
        PORT_PREVIEW,
        &["-y", "reclaim"],
        Duration::from_secs(20),
    ) else {
        return Vec::new();
    };
    if output.trim().is_empty() || output.to_ascii_lowercase().contains("nothing to reclaim") {
        return Vec::new();
    }
    let bytes = output
        .split_whitespace()
        .filter_map(parse_human_bytes)
        .max()
        .unwrap_or(0);
    vec![
        ProviderFinding::object(
            metadata(),
            "macports-reclaim",
            "package-manager-cache",
            "macports-reclaim",
            "MacPorts reclaimable files",
            Safety::Review,
            bytes,
        )
        .estimated()
        .reason("MacPorts' reclaim dry run reports inactive or obsolete package-manager data.")
        .evidence(
            "Preview",
            output.lines().take(8).collect::<Vec<_>>().join(" | "),
        )
        .copy(
            "Inactive ports, distfiles, archives, and other data selected by MacPorts.",
            "Reinstalling old ports may require downloads or rebuilds.",
            "Review the native preview before running MacPorts reclaim.",
        )
        .action(
            "macports-reclaim",
            vec!["port".into(), "-N".into(), "reclaim".into()],
            true,
            true,
        )
        .build(),
    ]
}

fn run_read(
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
    Ok(if output.stdout.is_empty() {
        output.stderr
    } else {
        output.stdout
    })
}

fn run_mutation(context: &ProviderContext, policy: CommandPolicy, args: &[&str]) -> Result<()> {
    let args: Vec<OsString> = args.iter().map(OsString::from).collect();
    let output = context.runner.run(
        policy,
        &args,
        CommandMode::Mutation,
        Some(context.remaining(Duration::from_secs(600))),
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

fn recursive_size(value: &Value) -> u64 {
    match value {
        Value::Object(values) => values
            .iter()
            .map(|(key, value)| {
                if key.contains("size") || key.contains("bytes") {
                    value
                        .as_u64()
                        .or_else(|| value.as_str().and_then(parse_human_bytes))
                        .unwrap_or_else(|| recursive_size(value))
                } else {
                    recursive_size(value)
                }
            })
            .max()
            .unwrap_or(0),
        Value::Array(values) => values.iter().map(recursive_size).sum(),
        Value::String(value) => parse_human_bytes(value).unwrap_or(0),
        Value::Number(value) => value.as_u64().unwrap_or(0),
        _ => 0,
    }
}

fn recursive_path_count(value: &Value) -> usize {
    match value {
        Value::Object(values) => values.values().map(recursive_path_count).sum(),
        Value::Array(values) => values
            .len()
            .max(values.iter().map(recursive_path_count).sum()),
        Value::String(value) => usize::from(value.starts_with('/')),
        _ => 0,
    }
}
