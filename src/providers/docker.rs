use anyhow::{Context, Result, bail};
use serde_json::Value;
use std::ffi::{OsStr, OsString};
use std::sync::atomic::Ordering;
use std::time::Duration;

use crate::report::{Finding, FindingSize, SizeAccuracy};
use crate::rules::Safety;
use crate::taxonomy::{Section, Subgroup};

use super::command::{CommandMode, CommandPolicy, safe_token};
use super::{
    Capability, Provider, ProviderContext, ProviderExecution, ProviderExecutionOptions,
    ProviderFinding, ProviderMetadata, Revalidation, ScanCost, age_from_human, parse_human_bytes,
};

pub struct DockerProvider;

const DOCKER_EXECUTABLES: &[&str] = &[
    "/usr/local/bin/docker",
    "/opt/homebrew/bin/docker",
    "docker",
];

const DOCKER_INFO: CommandPolicy = CommandPolicy {
    id: "docker-info",
    executables: DOCKER_EXECUTABLES,
    mutating: false,
    network: false,
    validate_args: args_info,
};
const DOCKER_CONTEXT_SHOW: CommandPolicy = CommandPolicy {
    id: "docker-context-show",
    executables: DOCKER_EXECUTABLES,
    mutating: false,
    network: false,
    validate_args: args_context_show,
};
const DOCKER_CONTEXT_INSPECT: CommandPolicy = CommandPolicy {
    id: "docker-context-inspect",
    executables: DOCKER_EXECUTABLES,
    mutating: false,
    network: false,
    validate_args: args_context_inspect,
};
const DOCKER_DF: CommandPolicy = CommandPolicy {
    id: "docker-system-df",
    executables: DOCKER_EXECUTABLES,
    mutating: false,
    network: false,
    validate_args: args_df,
};
const DOCKER_DF_SUMMARY: CommandPolicy = CommandPolicy {
    id: "docker-system-df-summary",
    executables: DOCKER_EXECUTABLES,
    mutating: false,
    network: false,
    validate_args: args_df_summary,
};
const DOCKER_NETWORKS: CommandPolicy = CommandPolicy {
    id: "docker-network-list",
    executables: DOCKER_EXECUTABLES,
    mutating: false,
    network: false,
    validate_args: args_networks,
};
const DOCKER_NETWORK_INSPECT: CommandPolicy = CommandPolicy {
    id: "docker-network-inspect",
    executables: DOCKER_EXECUTABLES,
    mutating: false,
    network: false,
    validate_args: args_network_inspect,
};
const DOCKER_IMAGE_RM: CommandPolicy = CommandPolicy {
    id: "docker-image-rm",
    executables: DOCKER_EXECUTABLES,
    mutating: true,
    network: false,
    validate_args: args_image_rm,
};
const DOCKER_CONTAINER_RM: CommandPolicy = CommandPolicy {
    id: "docker-container-rm",
    executables: DOCKER_EXECUTABLES,
    mutating: true,
    network: false,
    validate_args: args_container_rm,
};
const DOCKER_VOLUME_RM: CommandPolicy = CommandPolicy {
    id: "docker-volume-rm",
    executables: DOCKER_EXECUTABLES,
    mutating: true,
    network: false,
    validate_args: args_volume_rm,
};
const DOCKER_NETWORK_RM: CommandPolicy = CommandPolicy {
    id: "docker-network-rm",
    executables: DOCKER_EXECUTABLES,
    mutating: true,
    network: false,
    validate_args: args_network_rm,
};
const DOCKER_BUILDER_PRUNE: CommandPolicy = CommandPolicy {
    id: "docker-builder-prune",
    executables: DOCKER_EXECUTABLES,
    mutating: true,
    network: false,
    validate_args: args_builder_prune,
};

fn args_info(args: &[OsString]) -> bool {
    args == [
        OsStr::new("info"),
        OsStr::new("--format"),
        OsStr::new("{{json .ServerVersion}}"),
    ]
}

fn args_context_show(args: &[OsString]) -> bool {
    args == [OsStr::new("context"), OsStr::new("show")]
}

fn args_context_inspect(args: &[OsString]) -> bool {
    args.len() == 5
        && args[0] == "context"
        && args[1] == "inspect"
        && safe_token(&args[2])
        && args[3] == "--format"
        && args[4] == "{{json .Endpoints.docker.Host}}"
}

fn args_df(args: &[OsString]) -> bool {
    args == [
        OsStr::new("system"),
        OsStr::new("df"),
        OsStr::new("-v"),
        OsStr::new("--format"),
        OsStr::new("json"),
    ]
}

fn args_df_summary(args: &[OsString]) -> bool {
    args == [
        OsStr::new("system"),
        OsStr::new("df"),
        OsStr::new("--format"),
        OsStr::new("{{json .}}"),
    ]
}

fn args_networks(args: &[OsString]) -> bool {
    args == [
        OsStr::new("network"),
        OsStr::new("ls"),
        OsStr::new("--filter"),
        OsStr::new("type=custom"),
        OsStr::new("--format"),
        OsStr::new("{{json .}}"),
    ]
}

fn args_network_inspect(args: &[OsString]) -> bool {
    args.len() >= 5
        && args[0] == "network"
        && args[1] == "inspect"
        && args[2] == "--format"
        && args[3] == "{{len .Containers}}"
        && args[4..].iter().all(|value| safe_token(value))
}

fn args_image_rm(args: &[OsString]) -> bool {
    args.len() == 3 && args[0] == "image" && args[1] == "rm" && safe_token(&args[2])
}

fn args_container_rm(args: &[OsString]) -> bool {
    args.len() == 3 && args[0] == "container" && args[1] == "rm" && safe_token(&args[2])
}

fn args_volume_rm(args: &[OsString]) -> bool {
    args.len() == 3 && args[0] == "volume" && args[1] == "rm" && safe_token(&args[2])
}

fn args_network_rm(args: &[OsString]) -> bool {
    args.len() == 3 && args[0] == "network" && args[1] == "rm" && safe_token(&args[2])
}

fn args_builder_prune(args: &[OsString]) -> bool {
    args.len() == 5
        && args[0] == "builder"
        && args[1] == "prune"
        && args[2] == "--force"
        && args[3] == "--filter"
        && args[4]
            .to_string_lossy()
            .strip_prefix("until=")
            .is_some_and(|value| !value.is_empty() && !value.contains(['\n', '\r', '\0']))
}

impl Provider for DockerProvider {
    fn metadata(&self) -> ProviderMetadata {
        metadata()
    }

    fn probe(&self, context: &ProviderContext) -> Capability {
        if context.runner.resolve(DOCKER_INFO).is_none() {
            return Capability::Unavailable("Docker CLI is not installed.".into());
        }
        if let Ok(name) = run_read(
            context,
            DOCKER_CONTEXT_SHOW,
            &["context", "show"],
            Duration::from_secs(2),
        ) {
            let name = name.trim();
            if !name.is_empty()
                && let Ok(host) = run_context_inspect(context, name)
                && !host.is_empty()
                && !host.starts_with("unix://")
                && !host.starts_with("npipe://")
            {
                return Capability::Unavailable(format!(
                    "Active Docker context `{name}` is remote ({host}); remote storage is not scanned by default."
                ));
            }
        }
        match run_read(
            context,
            DOCKER_INFO,
            &["info", "--format", "{{json .ServerVersion}}"],
            Duration::from_secs(2),
        ) {
            Ok(_) => Capability::Available,
            Err(error) => {
                let message = format!("{error:#}");
                if message.to_ascii_lowercase().contains("permission denied") {
                    Capability::PermissionDenied(message)
                } else {
                    Capability::Unavailable(format!(
                        "Docker engine is not reachable; it was not started automatically. {message}"
                    ))
                }
            }
        }
    }

    fn scan(&self, context: &ProviderContext) -> Result<Vec<Finding>> {
        let output = run_read(
            context,
            DOCKER_DF,
            &["system", "df", "-v", "--format", "json"],
            Duration::from_secs(5),
        )?;
        let root: Value =
            serde_json::from_str(output.trim()).context("invalid Docker disk JSON")?;
        let build_reclaimable = run_read(
            context,
            DOCKER_DF_SUMMARY,
            &["system", "df", "--format", "{{json .}}"],
            Duration::from_secs(4),
        )
        .ok()
        .map(|output| docker_build_reclaimable(&output))
        .unwrap_or(0);
        let mut findings = Vec::new();
        findings.extend(image_findings(&root, context));
        findings.extend(container_findings(&root, context));
        findings.extend(volume_findings(&root, context));
        findings.extend(build_cache_findings(&root, context, build_reclaimable));
        findings.extend(network_findings(context)?);
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
                "Docker references changed and this object is no longer reclaimable.".into(),
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
            .context("Docker action missing")?;
        let (policy, args): (CommandPolicy, Vec<String>) = match action.action_id.as_str() {
            "remove-image" => (
                DOCKER_IMAGE_RM,
                vec!["image".into(), "rm".into(), action.object_id.clone()],
            ),
            "remove-container" => (
                DOCKER_CONTAINER_RM,
                vec!["container".into(), "rm".into(), action.object_id.clone()],
            ),
            "remove-volume" => (
                DOCKER_VOLUME_RM,
                vec!["volume".into(), "rm".into(), action.object_id.clone()],
            ),
            "remove-network" => (
                DOCKER_NETWORK_RM,
                vec!["network".into(), "rm".into(), action.object_id.clone()],
            ),
            "prune-build-cache" => {
                let days = action
                    .object_id
                    .strip_prefix("older-than-")
                    .and_then(|value| value.strip_suffix("-days"))
                    .and_then(|value| value.parse::<u64>().ok())
                    .context("invalid BuildKit age filter")?;
                (
                    DOCKER_BUILDER_PRUNE,
                    vec![
                        "builder".into(),
                        "prune".into(),
                        "--force".into(),
                        "--filter".into(),
                        format!("until={}h", days.saturating_mul(24)),
                    ],
                )
            }
            _ => bail!("unknown Docker action {}", action.action_id),
        };
        run_mutation(context, policy, &args)?;
        Ok(ProviderExecution {
            deleted: 1,
            freed_bytes: finding.bytes,
            message: format!("Docker action {} completed.", action.action_id),
        })
    }
}

fn run_context_inspect(context: &ProviderContext, name: &str) -> Result<String> {
    let args = vec![
        "context".into(),
        "inspect".into(),
        name.into(),
        "--format".into(),
        "{{json .Endpoints.docker.Host}}".into(),
    ];
    let output = context.runner.run(
        DOCKER_CONTEXT_INSPECT,
        &args,
        CommandMode::ReadOnly,
        Some(context.remaining(Duration::from_secs(2))),
        &context.cancel,
    )?;
    if !output.status.success() {
        bail!("docker context inspect failed");
    }
    Ok(output.stdout.trim().trim_matches('"').to_string())
}

fn metadata() -> ProviderMetadata {
    ProviderMetadata {
        id: "docker",
        name: "Docker",
        section: Section::Developer,
        subgroup: Subgroup::ContainersVms,
        cost: ScanCost::Fast,
        quick: true,
        deep: true,
        network_in_deep_scan: false,
        supersedes_rules: &["docker-advice", "docker-user-cache"],
    }
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
    if output.stdout_truncated {
        bail!("{} output exceeded the safety limit", policy.id);
    }
    Ok(output.stdout)
}

fn run_mutation(context: &ProviderContext, policy: CommandPolicy, args: &[String]) -> Result<()> {
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

fn image_findings(root: &Value, context: &ProviderContext) -> Vec<Finding> {
    root.get("Images")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .take(20_000)
        .filter_map(|image| {
            if string(image, "Containers").parse::<u64>().unwrap_or(0) != 0 {
                return None;
            }
            let id = string(image, "ID");
            if id.is_empty() {
                return None;
            }
            let repository = string(image, "Repository");
            let tag = string(image, "Tag");
            let dangling = repository == "<none>" || tag == "<none>";
            let unique = bytes(image, "UniqueSize");
            if unique < context.settings.min_size_bytes {
                return None;
            }
            let shared = bytes(image, "SharedSize");
            let logical = bytes(image, "Size");
            let age = age_from_human(&string(image, "CreatedSince"));
            let recent = age.is_some_and(|days| days < context.settings.min_age_days);
            let label = if dangling {
                format!("Dangling image {}", short_id(&id))
            } else {
                format!("{repository}:{tag}")
            };
            Some(
                ProviderFinding::object(
                    metadata(),
                    if dangling {
                        "docker-dangling-image"
                    } else {
                        "docker-unused-image"
                    },
                    "virtualization",
                    &id,
                    label,
                    if dangling {
                        Safety::Safe
                    } else {
                        Safety::Review
                    },
                    unique,
                )
                .size(FindingSize {
                    logical,
                    physical: unique.saturating_add(shared),
                    unique,
                    shared,
                    reclaimable: unique,
                    accuracy: SizeAccuracy::Exact,
                })
                .age(age, recent)
                .reason("No container currently references this image.")
                .evidence("Image ID", short_id(&id))
                .evidence("Repository", repository)
                .evidence("Tag", tag)
                .copy(
                    "A local Docker image with no container references.",
                    "The image must be pulled or rebuilt if it is needed again.",
                    "Remove dangling images freely; review named images that may represent recent local builds.",
                )
                .action(
                    "remove-image",
                    vec!["docker".into(), "image".into(), "rm".into(), id],
                    true,
                    !dangling,
                )
                .build(),
            )
        })
        .collect()
}

fn container_findings(root: &Value, context: &ProviderContext) -> Vec<Finding> {
    root.get("Containers")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .take(20_000)
        .filter_map(|container| {
            let state = string(container, "State").to_ascii_lowercase();
            if state == "running" || state == "restarting" {
                return None;
            }
            let id = string(container, "ID");
            if id.is_empty() {
                return None;
            }
            let name = string(container, "Names");
            let size = bytes(container, "Size");
            if size < context.settings.min_size_bytes {
                return None;
            }
            Some(
                ProviderFinding::object(
                    metadata(),
                    "docker-stopped-container",
                    "virtualization",
                    &id,
                    if name.is_empty() {
                        format!("Stopped container {}", short_id(&id))
                    } else {
                        name.clone()
                    },
                    Safety::Review,
                    size,
                )
                .reason("The container is not running.")
                .evidence("Container ID", short_id(&id))
                .evidence("State", state)
                .evidence("Image", string(container, "Image"))
                .evidence("Compose project", compose_project(&string(container, "Labels")))
                .copy(
                    "A stopped Docker container and its writable layer.",
                    "Container-local changes and logs are permanently removed; named volumes remain untouched.",
                    "Review the Compose project and container name before removal.",
                )
                .action(
                    "remove-container",
                    vec!["docker".into(), "container".into(), "rm".into(), id],
                    true,
                    true,
                )
                .build(),
            )
        })
        .collect()
}

fn volume_findings(root: &Value, context: &ProviderContext) -> Vec<Finding> {
    root.get("Volumes")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .take(20_000)
        .filter_map(|volume| {
            if string(volume, "Links").parse::<u64>().unwrap_or(0) != 0 {
                return None;
            }
            let name = string(volume, "Name");
            if name.is_empty() {
                return None;
            }
            let labels = string(volume, "Labels");
            let anonymous = labels.is_empty()
                && name.len() >= 48
                && name.chars().all(|character| character.is_ascii_hexdigit());
            let size = bytes(volume, "Size");
            if size < context.settings.min_size_bytes {
                return None;
            }
            let builder = ProviderFinding::object(
                    metadata(),
                    "docker-unused-volume",
                    "virtualization",
                    &name,
                    format!("Unused volume {name}"),
                    Safety::Review,
                    size,
                )
                .reason("Docker reports no container links to this volume.")
                .evidence("Volume", &name)
                .evidence(
                    "Ownership",
                    if anonymous {
                        "anonymous volume"
                    } else {
                        "named or Compose-managed volume"
                    },
                )
                .evidence("Compose project", compose_project(&labels))
                .copy(
                    "Persistent data stored in a Docker volume with no current container links.",
                    "Deleting the volume permanently removes databases, uploads, and other persistent service data.",
                    if anonymous {
                        "Review the creation context before removal, even though the volume appears anonymous."
                    } else {
                        "Named and Compose volumes always require explicit manual selection."
                    },
                )
                .action(
                    "remove-volume",
                    vec!["docker".into(), "volume".into(), "rm".into(), name],
                    true,
                    true,
                );
            Some(if anonymous {
                builder.build()
            } else {
                builder.manual().build()
            })
        })
        .collect()
}

fn build_cache_findings(
    root: &Value,
    context: &ProviderContext,
    aggregate_reclaimable: u64,
) -> Vec<Finding> {
    if aggregate_reclaimable == 0 {
        return Vec::new();
    }
    let mut old_bytes = 0u64;
    let mut old_count = 0usize;
    let mut recent_bytes = 0u64;
    let mut recent_count = 0usize;
    for cache in root
        .get("BuildCache")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .take(20_000)
    {
        if string(cache, "InUse") == "true" || string(cache, "Reclaimable") == "false" {
            continue;
        }
        let size = bytes(cache, "Size");
        let age = age_from_human(&string(cache, "LastUsedAt"))
            .or_else(|| age_from_human(&string(cache, "LastUsedSince")))
            .unwrap_or(0);
        if age >= context.settings.min_age_days {
            old_bytes = old_bytes.saturating_add(size);
            old_count += 1;
        } else {
            recent_bytes = recent_bytes.saturating_add(size);
            recent_count += 1;
        }
    }
    let detailed_total = old_bytes.saturating_add(recent_bytes);
    let stale_reclaimable = aggregate_reclaimable
        .saturating_mul(old_bytes)
        .checked_div(detailed_total)
        .unwrap_or(0);
    let recent_reclaimable = aggregate_reclaimable.saturating_sub(stale_reclaimable);
    let mut findings = Vec::new();
    if old_count > 0 && stale_reclaimable >= context.settings.min_size_bytes {
        findings.push(
            ProviderFinding::object(
                metadata(),
                "docker-stale-build-cache",
                "virtualization-cache",
                format!("older-than-{}-days", context.settings.min_age_days),
                format!(
                    "BuildKit cache older than {} days",
                    context.settings.min_age_days
                ),
                Safety::Safe,
                stale_reclaimable,
            )
            .size(FindingSize {
                logical: old_bytes,
                physical: old_bytes,
                unique: stale_reclaimable,
                shared: old_bytes.saturating_sub(stale_reclaimable),
                reclaimable: stale_reclaimable,
                accuracy: if recent_count == 0 {
                    SizeAccuracy::Exact
                } else {
                    SizeAccuracy::Estimated
                },
            })
            .reason("BuildKit marks these records reclaimable and they exceed the age threshold.")
            .evidence("Records", old_count.to_string())
            .evidence("Age threshold", format!("{} days", context.settings.min_age_days))
            .copy(
                "Unused Docker/BuildKit build layers older than the configured threshold.",
                "Future image builds may need to download dependencies or rebuild layers.",
                "The action uses an age-filtered BuildKit prune rather than a full Docker system prune.",
            )
            .action(
                "prune-build-cache",
                vec![
                    "docker".into(),
                    "builder".into(),
                    "prune".into(),
                    "--filter".into(),
                    format!("until={}h", context.settings.min_age_days.saturating_mul(24)),
                ],
                true,
                false,
            )
            .build(),
        );
    }
    if recent_count > 0 && recent_reclaimable >= context.settings.min_size_bytes {
        findings.push(
            ProviderFinding::object(
                metadata(),
                "docker-recent-build-cache",
                "virtualization-cache",
                "recent-build-cache",
                "Recent reclaimable BuildKit cache",
                Safety::Safe,
                recent_reclaimable,
            )
            .age(Some(0), true)
            .size(FindingSize {
                logical: recent_bytes,
                physical: recent_bytes,
                unique: recent_reclaimable,
                shared: recent_bytes.saturating_sub(recent_reclaimable),
                reclaimable: recent_reclaimable,
                accuracy: if old_count == 0 {
                    SizeAccuracy::Exact
                } else {
                    SizeAccuracy::Estimated
                },
            })
            .report_only()
            .reason("BuildKit reports the records as reclaimable, but they are inside the recent-use window.")
            .evidence("Records", recent_count.to_string())
            .copy(
                "Recently used build layers that are technically reclaimable.",
                "Deleting them now is likely to slow the next Docker build.",
                "Leave recent build cache in place or lower the provider age threshold explicitly.",
            )
            .build(),
        );
    }
    findings
}

fn docker_build_reclaimable(output: &str) -> u64 {
    output
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .find(|entry| string(entry, "Type") == "Build Cache")
        .and_then(|entry| {
            let reclaimable = string(&entry, "Reclaimable");
            parse_human_bytes(reclaimable.split_whitespace().next().unwrap_or_default())
        })
        .unwrap_or(0)
}

fn network_findings(context: &ProviderContext) -> Result<Vec<Finding>> {
    if context.cancel.load(Ordering::Relaxed) {
        return Ok(Vec::new());
    }
    let output = run_read(
        context,
        DOCKER_NETWORKS,
        &[
            "network",
            "ls",
            "--filter",
            "type=custom",
            "--format",
            "{{json .}}",
        ],
        Duration::from_secs(3),
    )?;
    let networks: Vec<Value> = output
        .lines()
        .take(200)
        .filter_map(|line| serde_json::from_str(line).ok())
        .collect();
    if networks.is_empty() {
        return Ok(Vec::new());
    }
    let mut args = vec![
        "network".to_string(),
        "inspect".to_string(),
        "--format".to_string(),
        "{{len .Containers}}".to_string(),
    ];
    args.extend(networks.iter().map(|network| string(network, "ID")));
    let refs: Vec<OsString> = args.iter().map(OsString::from).collect();
    let output = context.runner.run(
        DOCKER_NETWORK_INSPECT,
        &refs,
        CommandMode::ReadOnly,
        Some(context.remaining(Duration::from_secs(4))),
        &context.cancel,
    )?;
    if !output.status.success() {
        return Ok(Vec::new());
    }
    let counts: Vec<u64> = output
        .stdout
        .lines()
        .filter_map(|line| line.trim().parse().ok())
        .collect();
    Ok(networks
        .into_iter()
        .zip(counts)
        .filter(|(_, count)| *count == 0)
        .filter_map(|(network, _)| {
            let id = string(&network, "ID");
            let name = string(&network, "Name");
            (!id.is_empty()).then(|| {
                ProviderFinding::object(
                    metadata(),
                    "docker-unused-network",
                    "virtualization",
                    &id,
                    format!("Unused network {name}"),
                    Safety::Safe,
                    0,
                )
                .reason("The custom Docker network has no attached containers.")
                .evidence("Driver", string(&network, "Driver"))
                .evidence("Network ID", short_id(&id))
                .copy(
                    "A custom Docker network with no attached containers.",
                    "Docker Compose or another tool recreates the network when needed.",
                    "Safe to remove after confirming no stopped workflow expects the network to persist.",
                )
                .action(
                    "remove-network",
                    vec!["docker".into(), "network".into(), "rm".into(), id],
                    true,
                    false,
                )
                .build()
            })
        })
        .collect())
}

fn string(value: &Value, key: &str) -> String {
    value
        .get(key)
        .and_then(|value| match value {
            Value::String(value) => Some(value.clone()),
            Value::Number(value) => Some(value.to_string()),
            Value::Bool(value) => Some(value.to_string()),
            _ => None,
        })
        .unwrap_or_default()
}

fn bytes(value: &Value, key: &str) -> u64 {
    parse_human_bytes(&string(value, key)).unwrap_or(0)
}

fn short_id(id: &str) -> String {
    id.strip_prefix("sha256:")
        .unwrap_or(id)
        .chars()
        .take(12)
        .collect()
}

fn compose_project(labels: &str) -> String {
    labels
        .split(',')
        .find_map(|label| {
            label
                .trim()
                .strip_prefix("com.docker.compose.project=")
                .map(str::to_string)
        })
        .unwrap_or_else(|| "none".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn image_savings_use_unique_not_shared_bytes() {
        let root: Value = serde_json::json!({
            "Images": [{
                "Containers": "0",
                "ID": "sha256:abc",
                "Repository": "local",
                "Tag": "test",
                "UniqueSize": "25MB",
                "SharedSize": "75MB",
                "Size": "100MB",
                "CreatedSince": "2 months ago"
            }]
        });
        let context = ProviderContext {
            home: None,
            roots: Vec::new(),
            repositories: Vec::new(),
            reference_files: Vec::new(),
            reference_complete: true,
            running_commands: Vec::new(),
            settings: super::super::ProviderSettings::default(),
            runner: std::sync::Arc::new(super::super::command::CommandRunner::new(None)),
            cancel: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            deadline: std::time::Instant::now() + Duration::from_secs(1),
        };
        let findings = image_findings(&root, &context);
        assert_eq!(findings[0].bytes, 25 * 1024 * 1024);
        assert_eq!(findings[0].size.shared, 75 * 1024 * 1024);
    }
}
