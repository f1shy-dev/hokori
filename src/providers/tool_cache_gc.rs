use anyhow::{Context, Result, bail};
use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::report::{Confidence, Finding, FindingSize, SizeAccuracy};
use crate::rules::Safety;
use crate::taxonomy::{Section, Subgroup};
use crate::walk::{InodeDedupe, size_subtree_cancellable};

use super::command::{CommandMode, CommandPolicy};
use super::{
    Capability, Provider, ProviderContext, ProviderExecution, ProviderExecutionOptions,
    ProviderFinding, ProviderMetadata, Revalidation, ScanCost,
};

pub struct ToolCacheGcProvider;

const UV: CommandPolicy = policy("uv-cache-prune", &["uv"], args_uv, true);
const PNPM: CommandPolicy = policy("pnpm-store-prune", &["pnpm"], args_pnpm, true);
const PIP: CommandPolicy = policy("pip-cache-purge", &["pip"], args_pip, true);
const POD: CommandPolicy = policy("pod-cache-clean", &["pod"], args_pod, true);
const GO_BUILD: CommandPolicy = policy("go-build-cache-clean", &["go"], args_go_build, true);
const GO_MOD: CommandPolicy = policy("go-module-cache-clean", &["go"], args_go_mod, true);
const NUGET: CommandPolicy = policy("nuget-cache-clean", &["dotnet"], args_nuget, true);

const fn policy(
    id: &'static str,
    executables: &'static [&'static str],
    validate_args: fn(&[OsString]) -> bool,
    mutating: bool,
) -> CommandPolicy {
    CommandPolicy {
        id,
        executables,
        mutating,
        network: false,
        validate_args,
    }
}

fn args_uv(args: &[OsString]) -> bool {
    args == [OsStr::new("cache"), OsStr::new("prune")]
}

fn args_pnpm(args: &[OsString]) -> bool {
    args == [OsStr::new("store"), OsStr::new("prune")]
}

fn args_pip(args: &[OsString]) -> bool {
    args == [OsStr::new("cache"), OsStr::new("purge")]
}

fn args_pod(args: &[OsString]) -> bool {
    args == [
        OsStr::new("cache"),
        OsStr::new("clean"),
        OsStr::new("--all"),
    ]
}

fn args_go_build(args: &[OsString]) -> bool {
    args == [
        OsStr::new("clean"),
        OsStr::new("-cache"),
        OsStr::new("-testcache"),
    ]
}

fn args_go_mod(args: &[OsString]) -> bool {
    args == [OsStr::new("clean"), OsStr::new("-modcache")]
}

fn args_nuget(args: &[OsString]) -> bool {
    args == [
        OsStr::new("nuget"),
        OsStr::new("locals"),
        OsStr::new("all"),
        OsStr::new("--clear"),
    ]
}

struct CacheDefinition {
    rule_id: &'static str,
    object_id: &'static str,
    label: &'static str,
    safety: Safety,
    paths: Vec<PathBuf>,
    policy: CommandPolicy,
    args: &'static [&'static str],
    prune_only: bool,
    process_markers: &'static [&'static str],
}

impl Provider for ToolCacheGcProvider {
    fn metadata(&self) -> ProviderMetadata {
        metadata()
    }

    fn probe(&self, context: &ProviderContext) -> Capability {
        if definitions(context)
            .iter()
            .any(|definition| context.runner.resolve(definition.policy).is_some())
        {
            Capability::Available
        } else {
            Capability::Unavailable("No supported native cache manager is installed.".into())
        }
    }

    fn scan(&self, context: &ProviderContext) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        for definition in definitions(context) {
            if context.runner.resolve(definition.policy).is_none() {
                continue;
            }
            let existing: Vec<_> = definition
                .paths
                .into_iter()
                .filter(|path| path.exists())
                .collect();
            if existing.is_empty() {
                continue;
            }
            let bytes: u64 = existing
                .iter()
                .map(|path| directory_size(path, context))
                .sum();
            if bytes < context.settings.min_size_bytes {
                continue;
            }
            let in_use = definition.process_markers.iter().any(|marker| {
                context
                    .running_commands
                    .iter()
                    .any(|command| command.contains(marker))
            });
            let builder = ProviderFinding::object(
                metadata(),
                definition.rule_id,
                "package-manager-cache",
                definition.object_id,
                definition.label,
                definition.safety,
                bytes,
            )
            .grouped_paths(existing)
            .confidence(if definition.prune_only {
                Confidence::High
            } else {
                Confidence::Exact
            })
            .reason(if definition.prune_only {
                "The owning tool can prune objects it considers unreachable; displayed bytes are the store size before pruning."
            } else {
                "The owning tool exposes an explicit command to clear this cache."
            })
            .copy(
                "A package-manager cache managed by the named tool.",
                "Packages or build artifacts are downloaded or rebuilt when needed again.",
                "Use the native command so the tool preserves its own metadata and shared-store invariants.",
            )
            .action(
                definition.policy.id,
                std::iter::once(
                    definition
                        .policy
                        .executables
                        .first()
                        .copied()
                        .unwrap_or("tool")
                        .to_string(),
                )
                .chain(definition.args.iter().map(|value| value.to_string()))
                .collect(),
                true,
                definition.safety != Safety::Safe,
            );
            let builder = if definition.prune_only {
                builder.size(FindingSize {
                    logical: bytes,
                    physical: bytes,
                    unique: 0,
                    shared: 0,
                    reclaimable: 0,
                    accuracy: SizeAccuracy::Unknown,
                })
            } else {
                builder
            };
            findings.push(if in_use {
                builder.in_use().build()
            } else if definition.safety == Safety::Safe {
                builder.build()
            } else {
                builder.manual().build()
            });
        }
        Ok(findings)
    }

    fn revalidate(&self, context: &ProviderContext, finding: &Finding) -> Result<Revalidation> {
        let refreshed = self.scan(context)?;
        if refreshed
            .iter()
            .any(|candidate| candidate.stable_id == finding.stable_id && !candidate.in_use)
        {
            Ok(Revalidation::Valid)
        } else {
            Ok(Revalidation::Changed(
                "The cache changed, disappeared, or is now in use.".into(),
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
            .context("native cache action missing")?;
        let definition = definitions(context)
            .into_iter()
            .find(|definition| definition.policy.id == action.action_id)
            .context("native cache definition missing")?;
        let args: Vec<OsString> = definition.args.iter().map(OsString::from).collect();
        let before: u64 = definition
            .paths
            .iter()
            .filter(|path| path.exists())
            .map(|path| directory_size(path, context))
            .sum();
        let output = context.runner.run(
            definition.policy,
            &args,
            CommandMode::Mutation,
            Some(context.remaining(Duration::from_secs(600))),
            &context.cancel,
        )?;
        if !output.status.success() {
            bail!(
                "{} failed: {}",
                definition.policy.id,
                output.stderr.lines().next().unwrap_or("unknown error")
            );
        }
        let after: u64 = definition
            .paths
            .iter()
            .filter(|path| path.exists())
            .map(|path| directory_size(path, context))
            .sum();
        Ok(ProviderExecution {
            deleted: 1,
            freed_bytes: before.saturating_sub(after),
            message: format!("{} completed.", definition.label),
        })
    }
}

fn metadata() -> ProviderMetadata {
    ProviderMetadata {
        id: "tool-cache-gc",
        name: "Package-manager cache pruning",
        section: Section::Developer,
        subgroup: Subgroup::Packages,
        cost: ScanCost::Fast,
        quick: true,
        deep: true,
        network_in_deep_scan: false,
        supersedes_rules: &[
            "uv-cache",
            "pnpm-store",
            "pip-cache",
            "cocoapods-cache",
            "go-build-cache",
            "go-module-cache",
            "nuget-cache",
        ],
    }
}

fn definitions(context: &ProviderContext) -> Vec<CacheDefinition> {
    let Some(home) = &context.home else {
        return Vec::new();
    };
    vec![
        CacheDefinition {
            rule_id: "uv-native-prune",
            object_id: "uv-cache",
            label: "uv unreachable cache objects",
            safety: Safety::Safe,
            paths: vec![home.join(".cache/uv")],
            policy: UV,
            args: &["cache", "prune"],
            prune_only: true,
            process_markers: &["uv ", "/.cache/uv/"],
        },
        CacheDefinition {
            rule_id: "pnpm-native-prune",
            object_id: "pnpm-store",
            label: "pnpm unreferenced store packages",
            safety: Safety::Safe,
            paths: vec![
                home.join("Library/pnpm/store"),
                home.join(".local/share/pnpm/store"),
            ],
            policy: PNPM,
            args: &["store", "prune"],
            prune_only: true,
            process_markers: &["pnpm "],
        },
        CacheDefinition {
            rule_id: "pip-native-purge",
            object_id: "pip-cache",
            label: "pip download and wheel cache",
            safety: Safety::Safe,
            paths: vec![home.join(".cache/pip"), home.join("Library/Caches/pip")],
            policy: PIP,
            args: &["cache", "purge"],
            prune_only: false,
            process_markers: &["pip install", "pip download"],
        },
        CacheDefinition {
            rule_id: "cocoapods-native-clean",
            object_id: "cocoapods-cache",
            label: "CocoaPods download cache",
            safety: Safety::Review,
            paths: vec![home.join("Library/Caches/CocoaPods")],
            policy: POD,
            args: &["cache", "clean", "--all"],
            prune_only: false,
            process_markers: &["pod install", "pod update"],
        },
        CacheDefinition {
            rule_id: "go-native-build-clean",
            object_id: "go-build-cache",
            label: "Go build and test cache",
            safety: Safety::Safe,
            paths: vec![home.join("Library/Caches/go-build")],
            policy: GO_BUILD,
            args: &["clean", "-cache", "-testcache"],
            prune_only: false,
            process_markers: &["go build", "go test"],
        },
        CacheDefinition {
            rule_id: "go-native-module-clean",
            object_id: "go-module-cache",
            label: "Go module download cache",
            safety: Safety::Review,
            paths: vec![home.join("go/pkg/mod")],
            policy: GO_MOD,
            args: &["clean", "-modcache"],
            prune_only: false,
            process_markers: &["go build", "go test", "go mod"],
        },
        CacheDefinition {
            rule_id: "nuget-native-clean",
            object_id: "nuget-cache",
            label: "NuGet global packages and HTTP caches",
            safety: Safety::Review,
            paths: vec![
                home.join(".nuget/packages"),
                home.join("Library/Caches/NuGet"),
            ],
            policy: NUGET,
            args: &["nuget", "locals", "all", "--clear"],
            prune_only: false,
            process_markers: &["dotnet ", "msbuild"],
        },
    ]
}

fn directory_size(path: &Path, context: &ProviderContext) -> u64 {
    if !path.is_dir() {
        return 0;
    }
    size_subtree_cancellable(
        path,
        &InodeDedupe::new(),
        None,
        Some(context.cancel.as_ref()),
    )
    .bytes
}
