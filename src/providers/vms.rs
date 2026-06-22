use anyhow::{Context, Result, bail};
use serde_json::Value;
use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use crate::report::{Confidence, Finding, FindingSize, SizeAccuracy};
use crate::rules::Safety;
use crate::taxonomy::{Section, Subgroup};
use crate::walk::{InodeDedupe, size_subtree_cancellable};

use super::command::{CommandMode, CommandPolicy, safe_token};
use super::{
    Capability, Provider, ProviderContext, ProviderExecution, ProviderExecutionOptions,
    ProviderFinding, ProviderMetadata, Revalidation, ScanCost, parse_human_bytes,
};

pub struct VmProvider;

const LIMACTL: &[&str] = &["/opt/homebrew/bin/limactl", "limactl"];
const ORBCTL: &[&str] = &[
    "/usr/local/bin/orbctl",
    "/opt/homebrew/bin/orbctl",
    "orbctl",
];
const COLIMA: &[&str] = &["/opt/homebrew/bin/colima", "colima"];
const MULTIPASS: &[&str] = &["/usr/local/bin/multipass", "multipass"];

const LIMA_LIST: CommandPolicy = CommandPolicy {
    id: "lima-list",
    executables: LIMACTL,
    mutating: false,
    network: false,
    validate_args: args_lima_list,
};
const LIMA_DELETE: CommandPolicy = CommandPolicy {
    id: "lima-delete",
    executables: LIMACTL,
    mutating: true,
    network: false,
    validate_args: args_lima_delete,
};
const ORB_LIST: CommandPolicy = CommandPolicy {
    id: "orbstack-list",
    executables: ORBCTL,
    mutating: false,
    network: false,
    validate_args: args_orb_list,
};
const ORB_DELETE: CommandPolicy = CommandPolicy {
    id: "orbstack-delete",
    executables: ORBCTL,
    mutating: true,
    network: false,
    validate_args: args_orb_delete,
};
const COLIMA_LIST: CommandPolicy = CommandPolicy {
    id: "colima-list",
    executables: COLIMA,
    mutating: false,
    network: false,
    validate_args: args_colima_list,
};
const COLIMA_DELETE: CommandPolicy = CommandPolicy {
    id: "colima-delete",
    executables: COLIMA,
    mutating: true,
    network: false,
    validate_args: args_colima_delete,
};
const MULTIPASS_LIST: CommandPolicy = CommandPolicy {
    id: "multipass-list",
    executables: MULTIPASS,
    mutating: false,
    network: false,
    validate_args: args_multipass_list,
};
const MULTIPASS_DELETE: CommandPolicy = CommandPolicy {
    id: "multipass-delete",
    executables: MULTIPASS,
    mutating: true,
    network: false,
    validate_args: args_multipass_delete,
};

fn args_lima_list(args: &[OsString]) -> bool {
    args == [
        OsStr::new("list"),
        OsStr::new("--format"),
        OsStr::new("json"),
    ]
}

fn args_lima_delete(args: &[OsString]) -> bool {
    args.len() == 3 && args[0] == "delete" && args[1] == "--yes" && safe_token(&args[2])
}

fn args_orb_list(args: &[OsString]) -> bool {
    args == [
        OsStr::new("list"),
        OsStr::new("--format"),
        OsStr::new("json"),
    ]
}

fn args_orb_delete(args: &[OsString]) -> bool {
    args.len() == 3 && args[0] == "delete" && args[1] == "--force" && safe_token(&args[2])
}

fn args_colima_list(args: &[OsString]) -> bool {
    args == [OsStr::new("list"), OsStr::new("--json")]
}

fn args_colima_delete(args: &[OsString]) -> bool {
    args.len() == 4
        && args[0] == "delete"
        && args[1] == "--force"
        && args[2] == "--profile"
        && safe_token(&args[3])
}

fn args_multipass_list(args: &[OsString]) -> bool {
    args == [
        OsStr::new("list"),
        OsStr::new("--format"),
        OsStr::new("json"),
    ]
}

fn args_multipass_delete(args: &[OsString]) -> bool {
    args.len() == 3 && args[0] == "delete" && args[1] == "--purge" && safe_token(&args[2])
}

impl Provider for VmProvider {
    fn metadata(&self) -> ProviderMetadata {
        metadata()
    }

    fn probe(&self, context: &ProviderContext) -> Capability {
        if [LIMA_LIST, ORB_LIST, COLIMA_LIST, MULTIPASS_LIST]
            .into_iter()
            .any(|policy| context.runner.resolve(policy).is_some())
        {
            Capability::Available
        } else {
            Capability::Unavailable("No supported virtual machine manager is installed.".into())
        }
    }

    fn scan(&self, context: &ProviderContext) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        if context.runner.resolve(LIMA_LIST).is_some() {
            findings.extend(lima_findings(context));
        }
        if context.runner.resolve(ORB_LIST).is_some() {
            findings.extend(orbstack_findings(context));
        }
        if context.runner.resolve(COLIMA_LIST).is_some() {
            findings.extend(colima_findings(context));
        }
        if context.runner.resolve(MULTIPASS_LIST).is_some() {
            findings.extend(multipass_findings(context));
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
                "Virtual machine state changed since the scan.".into(),
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
            .context("VM action missing")?;
        let (policy, args): (CommandPolicy, Vec<String>) = match action.action_id.as_str() {
            "lima-delete" => (
                LIMA_DELETE,
                vec!["delete".into(), "--yes".into(), action.object_id.clone()],
            ),
            "orbstack-delete" => (
                ORB_DELETE,
                vec!["delete".into(), "--force".into(), action.object_id.clone()],
            ),
            "colima-delete" => (
                COLIMA_DELETE,
                vec![
                    "delete".into(),
                    "--force".into(),
                    "--profile".into(),
                    action.object_id.clone(),
                ],
            ),
            "multipass-delete" => (
                MULTIPASS_DELETE,
                vec!["delete".into(), "--purge".into(), action.object_id.clone()],
            ),
            _ => bail!("unknown VM action {}", action.action_id),
        };
        run_mutation(context, policy, &args)?;
        Ok(ProviderExecution {
            deleted: 1,
            freed_bytes: finding.bytes,
            message: format!("Deleted virtual machine {}.", action.object_id),
        })
    }
}

fn metadata() -> ProviderMetadata {
    ProviderMetadata {
        id: "virtual-machines",
        name: "Virtual machines",
        section: Section::Developer,
        subgroup: Subgroup::ContainersVms,
        cost: ScanCost::Fast,
        quick: true,
        deep: true,
        network_in_deep_scan: false,
        supersedes_rules: &[],
    }
}

fn lima_findings(context: &ProviderContext) -> Vec<Finding> {
    let Ok(output) = run_read(
        context,
        LIMA_LIST,
        &["list", "--format", "json"],
        Duration::from_secs(4),
    ) else {
        return Vec::new();
    };
    output
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .filter_map(|machine| {
            let name = string(&machine, "name");
            if name.is_empty() || is_container_engine_vm(&name) {
                return None;
            }
            let status = string(&machine, "status");
            let running = status.eq_ignore_ascii_case("running");
            let directory = PathBuf::from(string(&machine, "dir"));
            let physical = directory_size(&directory, context);
            let configured = machine.get("disk").and_then(Value::as_u64).unwrap_or(0);
            let age = path_age_days(&directory);
            if !running
                && age.is_some_and(|age| age < context.settings.min_age_days)
                && physical < context.settings.min_size_bytes
            {
                return None;
            }
            Some(vm_finding(
                context,
                "Lima",
                &name,
                &status,
                directory,
                configured,
                physical,
                age,
                "lima-delete",
                vec![
                    "limactl".into(),
                    "delete".into(),
                    "--yes".into(),
                    name.clone(),
                ],
            ))
        })
        .collect()
}

fn orbstack_findings(context: &ProviderContext) -> Vec<Finding> {
    let Ok(output) = run_read(
        context,
        ORB_LIST,
        &["list", "--format", "json"],
        Duration::from_secs(4),
    ) else {
        return Vec::new();
    };
    let Ok(json) = serde_json::from_str::<Value>(&output) else {
        return Vec::new();
    };
    json.as_array()
        .into_iter()
        .flatten()
        .filter_map(|machine| {
            let name = string(machine, "name");
            if name.is_empty() {
                return None;
            }
            let status = first_string(machine, &["status", "state"]);
            let running = status.eq_ignore_ascii_case("running");
            let directory = context
                .home
                .as_ref()
                .map(|home| home.join(".orbstack").join(&name))
                .unwrap_or_default();
            let physical = directory_size(&directory, context);
            let age = path_age_days(&directory);
            Some(vm_finding(
                context,
                "OrbStack",
                &name,
                if running { "Running" } else { &status },
                directory,
                0,
                physical,
                age,
                "orbstack-delete",
                vec![
                    "orbctl".into(),
                    "delete".into(),
                    "--force".into(),
                    name.clone(),
                ],
            ))
        })
        .collect()
}

fn colima_findings(context: &ProviderContext) -> Vec<Finding> {
    let Ok(output) = run_read(
        context,
        COLIMA_LIST,
        &["list", "--json"],
        Duration::from_secs(4),
    ) else {
        return Vec::new();
    };
    let Ok(json) = serde_json::from_str::<Value>(&output) else {
        return Vec::new();
    };
    let machines = json
        .as_array()
        .cloned()
        .or_else(|| json.get("profiles").and_then(Value::as_array).cloned())
        .unwrap_or_default();
    machines
        .iter()
        .filter_map(|machine| {
            let name = first_string(machine, &["name", "profile"]);
            if name.is_empty() {
                return None;
            }
            let status = first_string(machine, &["status", "state"]);
            let directory = context
                .home
                .as_ref()
                .map(|home| home.join(".colima").join(&name))
                .unwrap_or_default();
            Some(vm_finding(
                context,
                "Colima",
                &name,
                &status,
                directory.clone(),
                machine.get("disk").and_then(Value::as_u64).unwrap_or(0),
                directory_size(&directory, context),
                path_age_days(&directory),
                "colima-delete",
                vec![
                    "colima".into(),
                    "delete".into(),
                    "--force".into(),
                    "--profile".into(),
                    name.clone(),
                ],
            ))
        })
        .collect()
}

fn multipass_findings(context: &ProviderContext) -> Vec<Finding> {
    let Ok(output) = run_read(
        context,
        MULTIPASS_LIST,
        &["list", "--format", "json"],
        Duration::from_secs(4),
    ) else {
        return Vec::new();
    };
    let Ok(json) = serde_json::from_str::<Value>(&output) else {
        return Vec::new();
    };
    json.get("list")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|machine| {
            let name = string(machine, "name");
            if name.is_empty() {
                return None;
            }
            let status = string(machine, "state");
            let configured = machine
                .get("disk")
                .and_then(Value::as_str)
                .and_then(parse_human_bytes)
                .unwrap_or(0);
            Some(vm_finding(
                context,
                "Multipass",
                &name,
                &status,
                PathBuf::new(),
                configured,
                0,
                None,
                "multipass-delete",
                vec![
                    "multipass".into(),
                    "delete".into(),
                    "--purge".into(),
                    name.clone(),
                ],
            ))
        })
        .collect()
}

#[allow(clippy::too_many_arguments)]
fn vm_finding(
    context: &ProviderContext,
    manager: &str,
    name: &str,
    status: &str,
    directory: PathBuf,
    configured: u64,
    physical: u64,
    age: Option<u64>,
    action_id: &str,
    preview: Vec<String>,
) -> Finding {
    let status_lower = status.to_ascii_lowercase();
    let running = status_lower == "running";
    let stopped = matches!(
        status_lower.as_str(),
        "stopped" | "stop" | "suspended" | "suspend"
    );
    let protected = running || !stopped;
    let recent = age.is_some_and(|age| age < context.settings.min_age_days);
    let builder = ProviderFinding::object(
        metadata(),
        if protected {
            "running-virtual-machine"
        } else {
            "stopped-virtual-machine"
        },
        "virtualization",
        format!("{manager}:{name}"),
        format!("{manager} VM {name}"),
        if protected {
            Safety::Protected
        } else {
            Safety::Risky
        },
        if protected { 0 } else { physical },
    )
    .size(FindingSize {
        logical: configured,
        physical,
        unique: physical,
        shared: 0,
        reclaimable: if protected { 0 } else { physical },
        accuracy: if physical > 0 {
            SizeAccuracy::Exact
        } else {
            SizeAccuracy::Unknown
        },
    })
    .age(age, recent)
    .manual()
    .confidence(Confidence::High)
    .reason(if running {
        "The virtual machine is running and cannot be considered reclaimable."
    } else if !stopped {
        "The virtual machine manager did not report a safely deletable stopped state."
    } else {
        "The virtual machine is stopped; deleting it would reclaim its physical host storage."
    })
    .evidence("Manager", manager)
    .evidence("Status", status)
    .evidence(
        "Storage directory",
        if directory.as_os_str().is_empty() {
            "manager-owned".into()
        } else {
            directory.display().to_string()
        },
    )
    .evidence("Configured capacity", configured.to_string())
    .evidence("Physical host bytes", physical.to_string())
    .copy(
        "A complete virtual machine disk, configuration, and guest-local data.",
        "Deleting the machine permanently removes everything stored inside the guest.",
        if running {
            "Running machines are protected. Stop the VM before reviewing it."
        } else if !stopped {
            "The manager state is unknown, so Hokori will not offer deletion."
        } else {
            "Review guest-local data and mounted host paths before deleting through the VM manager."
        },
    );
    if protected {
        builder.protected().build()
    } else {
        builder.action(action_id, preview, true, true).build()
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
    Ok(output.stdout)
}

fn run_mutation(context: &ProviderContext, policy: CommandPolicy, args: &[String]) -> Result<()> {
    let args: Vec<OsString> = args.iter().map(OsString::from).collect();
    let output = context.runner.run(
        policy,
        &args,
        CommandMode::Mutation,
        Some(context.remaining(Duration::from_secs(300))),
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

fn path_age_days(path: &Path) -> Option<u64> {
    let modified = path.metadata().ok()?.modified().ok()?;
    SystemTime::now()
        .duration_since(modified)
        .ok()
        .map(|duration| duration.as_secs() / 86_400)
}

fn string(value: &Value, key: &str) -> String {
    value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string()
}

fn first_string(value: &Value, keys: &[&str]) -> String {
    keys.iter()
        .find_map(|key| value.get(*key).and_then(Value::as_str))
        .unwrap_or_default()
        .to_string()
}

fn is_container_engine_vm(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "colima" | "docker" | "podman" | "rancher-desktop"
    )
}
