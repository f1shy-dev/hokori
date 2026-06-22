use anyhow::{Context, Result, bail};
use plist::Value as PlistValue;
use serde_json::Value;
use std::collections::HashSet;
use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::report::{Confidence, Finding, FindingSize, SizeAccuracy};
use crate::rules::Safety;
use crate::taxonomy::{Section, Subgroup};
use crate::walk::{InodeDedupe, size_subtree_cancellable};

use super::command::{CommandMode, CommandPolicy, safe_token};
use super::{
    Capability, Provider, ProviderContext, ProviderExecution, ProviderExecutionOptions,
    ProviderFinding, ProviderMetadata, Revalidation, ScanCost, age_from_iso8601,
    physical_file_size,
};

pub struct XcodeProvider;

const XCRUN_EXECUTABLES: &[&str] = &["/usr/bin/xcrun", "xcrun"];

const SIMCTL_DEVICES: CommandPolicy = CommandPolicy {
    id: "simctl-devices",
    executables: XCRUN_EXECUTABLES,
    mutating: false,
    network: false,
    validate_args: args_devices,
};
const SIMCTL_RUNTIMES: CommandPolicy = CommandPolicy {
    id: "simctl-runtimes",
    executables: XCRUN_EXECUTABLES,
    mutating: false,
    network: false,
    validate_args: args_runtimes,
};
const SIMCTL_MATCHES: CommandPolicy = CommandPolicy {
    id: "simctl-runtime-matches",
    executables: XCRUN_EXECUTABLES,
    mutating: false,
    network: false,
    validate_args: args_matches,
};
const SIMCTL_RUNTIME_DRY_RUN: CommandPolicy = CommandPolicy {
    id: "simctl-runtime-delete-preview",
    executables: XCRUN_EXECUTABLES,
    mutating: false,
    network: false,
    validate_args: args_runtime_dry_run,
};
const SIMCTL_DELETE_DEVICE: CommandPolicy = CommandPolicy {
    id: "simctl-delete-device",
    executables: XCRUN_EXECUTABLES,
    mutating: true,
    network: false,
    validate_args: args_delete_device,
};
const SIMCTL_DELETE_RUNTIME: CommandPolicy = CommandPolicy {
    id: "simctl-delete-runtime",
    executables: XCRUN_EXECUTABLES,
    mutating: true,
    network: false,
    validate_args: args_delete_runtime,
};
const SIMCTL_REMOVE_DYLD: CommandPolicy = CommandPolicy {
    id: "simctl-remove-dyld-cache",
    executables: XCRUN_EXECUTABLES,
    mutating: true,
    network: false,
    validate_args: args_remove_dyld,
};
const SWIFT_EXECUTABLES: &[&str] = &["/usr/bin/swift", "swift"];
const SWIFT_PURGE_CACHE: CommandPolicy = CommandPolicy {
    id: "swift-package-purge-cache",
    executables: SWIFT_EXECUTABLES,
    mutating: true,
    network: false,
    validate_args: args_swift_purge,
};

fn args_devices(args: &[OsString]) -> bool {
    args == [
        OsStr::new("simctl"),
        OsStr::new("list"),
        OsStr::new("devices"),
        OsStr::new("--json"),
    ]
}

fn args_runtimes(args: &[OsString]) -> bool {
    args == [
        OsStr::new("simctl"),
        OsStr::new("runtime"),
        OsStr::new("list"),
        OsStr::new("--json"),
    ]
}

fn args_matches(args: &[OsString]) -> bool {
    args == [
        OsStr::new("simctl"),
        OsStr::new("runtime"),
        OsStr::new("match"),
        OsStr::new("list"),
        OsStr::new("--json"),
    ]
}

fn args_runtime_dry_run(args: &[OsString]) -> bool {
    if args.len() < 5
        || args[0] != "simctl"
        || args[1] != "runtime"
        || args[2] != "delete"
        || args.last().is_none_or(|value| value != "--dry-run")
    {
        return false;
    }
    match args[3].to_string_lossy().as_ref() {
        "--outdated" | "--unusable" => args.len() == 5,
        "--notUsedSinceDays" => {
            args.len() == 6
                && args[4]
                    .to_string_lossy()
                    .chars()
                    .all(|character| character.is_ascii_digit())
        }
        _ => false,
    }
}

fn args_delete_device(args: &[OsString]) -> bool {
    args.len() == 3 && args[0] == "simctl" && args[1] == "delete" && safe_token(&args[2])
}

fn args_delete_runtime(args: &[OsString]) -> bool {
    args.len() == 4
        && args[0] == "simctl"
        && args[1] == "runtime"
        && args[2] == "delete"
        && safe_token(&args[3])
}

fn args_remove_dyld(args: &[OsString]) -> bool {
    args.len() == 5
        && args[0] == "simctl"
        && args[1] == "runtime"
        && args[2] == "dyld_shared_cache"
        && args[3] == "remove"
        && safe_token(&args[4])
}

fn args_swift_purge(args: &[OsString]) -> bool {
    args == [OsStr::new("package"), OsStr::new("purge-cache")]
}

impl Provider for XcodeProvider {
    fn metadata(&self) -> ProviderMetadata {
        metadata()
    }

    fn probe(&self, context: &ProviderContext) -> Capability {
        if context.runner.resolve(SIMCTL_DEVICES).is_none()
            && !context.home.as_ref().is_some_and(|home| {
                home.join("Library/Developer/Xcode").is_dir()
                    || home.join("Library/org.swift.swiftpm").is_dir()
            })
        {
            return Capability::Unavailable("Xcode and SwiftPM storage were not found.".into());
        }
        if context.runner.resolve(SIMCTL_DEVICES).is_none() {
            return Capability::Available;
        }
        match run_read(
            context,
            SIMCTL_DEVICES,
            &["simctl", "list", "devices", "--json"],
            Duration::from_secs(3),
        ) {
            Ok(_) => Capability::Available,
            Err(error) => {
                Capability::Unavailable(format!("CoreSimulator is unavailable. {error:#}"))
            }
        }
    }

    fn scan(&self, context: &ProviderContext) -> Result<Vec<Finding>> {
        let mut findings = xcode_storage_findings(context);
        if context.runner.resolve(SIMCTL_DEVICES).is_none() {
            return Ok(findings);
        }
        let devices_json = run_read(
            context,
            SIMCTL_DEVICES,
            &["simctl", "list", "devices", "--json"],
            Duration::from_secs(4),
        )?;
        let runtimes_json = run_read(
            context,
            SIMCTL_RUNTIMES,
            &["simctl", "runtime", "list", "--json"],
            Duration::from_secs(4),
        )?;
        let matches_json = run_read(
            context,
            SIMCTL_MATCHES,
            &["simctl", "runtime", "match", "list", "--json"],
            Duration::from_secs(4),
        )
        .unwrap_or_else(|_| "{}".into());

        let devices: Value =
            serde_json::from_str(&devices_json).context("invalid simctl device JSON")?;
        let runtimes: Value =
            serde_json::from_str(&runtimes_json).context("invalid simctl runtime JSON")?;
        let matches: Value = serde_json::from_str(&matches_json).unwrap_or(Value::Null);
        let booted_runtime_ids = booted_runtime_identifiers(&devices);
        let preferred_builds = preferred_runtime_builds(&matches);
        let outdated = runtime_preview_ids(context, "--outdated", None);
        let unusable = runtime_preview_ids(context, "--unusable", None);
        let unused = runtime_preview_ids(
            context,
            "--notUsedSinceDays",
            Some(context.settings.min_age_days),
        );

        findings.extend(unavailable_device_findings(&devices, context));
        findings.extend(runtime_findings(
            &runtimes,
            context,
            &booted_runtime_ids,
            &preferred_builds,
            &outdated,
            &unusable,
            &unused,
        ));
        if context.settings.profile == super::ScanProfile::Deep {
            findings.extend(dyld_cache_findings(
                &runtimes,
                &booted_runtime_ids,
                &preferred_builds,
            ));
            findings.extend(orphaned_runtime_storage_findings(context, &runtimes));
        }
        Ok(findings)
    }

    fn revalidate(&self, context: &ProviderContext, finding: &Finding) -> Result<Revalidation> {
        if let Some(action) = &finding.native_action {
            if action.action_id == "trash-xcode-path"
                && context
                    .running_commands
                    .iter()
                    .any(|command| command.contains("/Xcode.app/"))
            {
                return Ok(Revalidation::Blocked(
                    "Xcode is now running; close it before removing developer data.".into(),
                ));
            }
            if action.action_id == "swift-purge-cache"
                && context
                    .running_commands
                    .iter()
                    .any(|command| command.contains("swift package"))
            {
                return Ok(Revalidation::Blocked(
                    "A Swift package command is currently running.".into(),
                ));
            }
        }
        let refreshed = self.scan(context)?;
        if refreshed
            .iter()
            .any(|candidate| candidate.stable_id == finding.stable_id)
        {
            Ok(Revalidation::Valid)
        } else {
            Ok(Revalidation::Changed(
                "Simulator state changed and this object is no longer eligible.".into(),
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
            .context("Simulator action missing")?;
        let (policy, args): (CommandPolicy, Vec<String>) = match action.action_id.as_str() {
            "delete-device" => (
                SIMCTL_DELETE_DEVICE,
                vec!["simctl".into(), "delete".into(), action.object_id.clone()],
            ),
            "delete-runtime" => (
                SIMCTL_DELETE_RUNTIME,
                vec![
                    "simctl".into(),
                    "runtime".into(),
                    "delete".into(),
                    action.object_id.clone(),
                ],
            ),
            "remove-dyld-cache" => (
                SIMCTL_REMOVE_DYLD,
                vec![
                    "simctl".into(),
                    "runtime".into(),
                    "dyld_shared_cache".into(),
                    "remove".into(),
                    action.object_id.clone(),
                ],
            ),
            "swift-purge-cache" => (
                SWIFT_PURGE_CACHE,
                vec!["package".into(), "purge-cache".into()],
            ),
            "trash-xcode-path" => {
                let path = PathBuf::from(&action.object_id);
                let Some(home) = &context.home else {
                    bail!("home directory unavailable");
                };
                if !allowed_xcode_path(home, &path) {
                    bail!("Xcode path is outside the allowed storage roots");
                }
                delete_path(&path, _options.permanently)?;
                return Ok(ProviderExecution {
                    deleted: 1,
                    freed_bytes: finding.bytes,
                    message: format!("Removed {}.", path.display()),
                });
            }
            _ => bail!("unknown Simulator action {}", action.action_id),
        };
        run_mutation(context, policy, &args)?;
        Ok(ProviderExecution {
            deleted: 1,
            freed_bytes: finding.bytes,
            message: format!("Simulator action {} completed.", action.action_id),
        })
    }
}

fn metadata() -> ProviderMetadata {
    ProviderMetadata {
        id: "xcode-simulators",
        name: "Xcode Simulators",
        section: Section::Developer,
        subgroup: Subgroup::AppleMobile,
        cost: ScanCost::Fast,
        quick: true,
        deep: true,
        network_in_deep_scan: false,
        supersedes_rules: &[
            "coresimulator-caches",
            "xcode-derived-data",
            "xcode-archives",
            "xcode-device-support",
            "swiftpm-cache",
        ],
    }
}

fn xcode_storage_findings(context: &ProviderContext) -> Vec<Finding> {
    let Some(home) = &context.home else {
        return Vec::new();
    };
    let xcode_running = context
        .running_commands
        .iter()
        .any(|command| command.contains("/Xcode.app/"));
    let mut findings = Vec::new();

    let derived = home.join("Library/Developer/Xcode/DerivedData");
    if let Ok(entries) = derived.read_dir() {
        for entry in entries.flatten().take(20_000) {
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }
            let age = path_age_days(&path);
            if age.is_none_or(|age| age < 7.max(context.settings.min_age_days / 4)) {
                continue;
            }
            let bytes = directory_size(&path, context);
            if bytes < context.settings.min_size_bytes {
                continue;
            }
            let project = derived_data_project(&path)
                .unwrap_or_else(|| entry.file_name().to_string_lossy().to_string());
            let builder = ProviderFinding::object(
                metadata(),
                "xcode-derived-data",
                "dev-cache",
                path.display().to_string(),
                format!("{project} DerivedData"),
                Safety::Safe,
                bytes,
            )
            .filesystem_path(path.clone())
            .age(age, false)
            .reason("This Xcode build/index directory is outside the recent-use window.")
            .evidence("Project", project)
            .copy(
                "Xcode indexes, intermediates, logs, and build products for one project or workspace.",
                "Xcode rebuilds the data; the next build and index can be slow.",
                "Safe after Xcode and related build processes are closed.",
            )
            .action(
                "trash-xcode-path",
                vec!["move DerivedData path to Trash".into()],
                false,
                false,
            );
            findings.push(if xcode_running {
                builder.in_use().build()
            } else {
                builder.build()
            });
        }
    }

    let archives = home.join("Library/Developer/Xcode/Archives");
    let mut archive_paths = Vec::new();
    collect_xcarchives(&archives, &mut archive_paths, 0);
    for path in archive_paths {
        let age = path_age_days(&path);
        if age.is_none_or(|age| age < context.settings.min_age_days.max(60)) {
            continue;
        }
        let bytes = directory_size(&path, context);
        if bytes < context.settings.min_size_bytes {
            continue;
        }
        let label = archive_label(&path).unwrap_or_else(|| {
            path.file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .to_string()
        });
        findings.push(
            ProviderFinding::object(
                metadata(),
                "xcode-archive",
                "dev-cache",
                path.display().to_string(),
                label,
                Safety::Review,
                bytes,
            )
            .filesystem_path(path)
            .age(age, false)
            .manual()
            .reason("This Xcode archive is older than the archive retention threshold.")
            .copy(
                "An archived application build containing dSYMs, signing metadata, and exportable products.",
                "Deleting it can prevent symbolication or re-export of a shipped build.",
                "Keep archives for released versions unless dSYMs and exported artifacts are stored elsewhere.",
            )
            .action(
                "trash-xcode-path",
                vec!["move Xcode archive to Trash".into()],
                false,
                true,
            )
            .build(),
        );
    }

    let support = home.join("Library/Developer/Xcode/iOS DeviceSupport");
    if let Ok(entries) = support.read_dir() {
        for entry in entries.flatten().take(5_000) {
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }
            let age = path_age_days(&path);
            if age.is_none_or(|age| age < context.settings.min_age_days) {
                continue;
            }
            let bytes = directory_size(&path, context);
            if bytes < context.settings.min_size_bytes {
                continue;
            }
            findings.push(
                ProviderFinding::object(
                    metadata(),
                    "xcode-device-support",
                    "dev-cache",
                    path.display().to_string(),
                    format!("iOS DeviceSupport {}", entry.file_name().to_string_lossy()),
                    Safety::Review,
                    bytes,
                )
                .filesystem_path(path)
                .age(age, false)
                .manual()
                .reason("This extracted device-support version is outside the age threshold.")
                .copy(
                    "Symbols and support files extracted when a physical iOS device connects to Xcode.",
                    "Xcode recreates the directory on the next connection to that OS build.",
                    "Review versions used by current physical devices before removal.",
                )
                .action(
                    "trash-xcode-path",
                    vec!["move DeviceSupport version to Trash".into()],
                    false,
                    true,
                )
                .build(),
            );
        }
    }

    let swift_paths = [
        home.join(".swiftpm/cache"),
        home.join("Library/Caches/org.swift.swiftpm"),
        home.join("Library/org.swift.swiftpm/cache"),
    ];
    let swift_bytes: u64 = swift_paths
        .iter()
        .filter(|path| path.is_dir())
        .map(|path| directory_size(path, context))
        .sum();
    if swift_bytes >= context.settings.min_size_bytes {
        let builder = ProviderFinding::object(
            metadata(),
            "swiftpm-native-cache",
            "package-manager-cache",
            "global-repository-cache",
            "SwiftPM global repository cache",
            Safety::Safe,
            swift_bytes,
        )
        .grouped_paths(
            swift_paths
                .into_iter()
                .filter(|path| path.exists())
                .collect(),
        )
        .reason("SwiftPM owns these global repository and metadata caches.")
        .copy(
            "Swift Package Manager's global repository and dependency cache.",
            "Packages are fetched again during the next dependency resolution.",
            "Prefer SwiftPM's native purge-cache command.",
        );
        findings.push(if context.runner.resolve(SWIFT_PURGE_CACHE).is_some() {
            builder
                .action(
                    "swift-purge-cache",
                    vec!["swift".into(), "package".into(), "purge-cache".into()],
                    true,
                    false,
                )
                .build()
        } else {
            builder.report_only().build()
        });
    }
    findings
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
        Some(context.remaining(Duration::from_secs(180))),
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

fn unavailable_device_findings(devices: &Value, context: &ProviderContext) -> Vec<Finding> {
    devices
        .get("devices")
        .and_then(Value::as_object)
        .into_iter()
        .flat_map(|runtimes| runtimes.iter())
        .flat_map(|(runtime, devices)| {
            devices
                .as_array()
                .into_iter()
                .flatten()
                .map(move |device| (runtime, device))
        })
        .filter(|(_, device)| device.get("isAvailable").and_then(Value::as_bool) == Some(false))
        .filter_map(|(runtime, device)| {
            let udid = string(device, "udid");
            if udid.is_empty() {
                return None;
            }
            let data_path = PathBuf::from(string(device, "dataPath"));
            let bytes = if data_path.is_dir() {
                size_subtree_cancellable(
                    &data_path,
                    &InodeDedupe::new(),
                    None,
                    Some(context.cancel.as_ref()),
                )
                .bytes
            } else {
                0
            };
            Some(
                ProviderFinding::object(
                    metadata(),
                    "xcode-unavailable-simulator",
                    "simulator-runtime",
                    &udid,
                    format!("{} ({})", string(device, "name"), runtime_label(runtime)),
                    Safety::Safe,
                    bytes,
                )
                .reason("The selected Xcode SDK no longer supports this simulator device.")
                .evidence("UDID", &udid)
                .evidence("Runtime", runtime_label(runtime))
                .evidence("State", string(device, "state"))
                .copy(
                    "A simulator device whose runtime is unavailable to the current Xcode installation.",
                    "The simulator's installed apps and local test data are deleted.",
                    "Safe when the unavailable device is no longer needed for migration or forensic debugging.",
                )
                .action(
                    "delete-device",
                    vec!["xcrun".into(), "simctl".into(), "delete".into(), udid],
                    true,
                    false,
                )
                .build(),
            )
        })
        .collect()
}

#[allow(clippy::too_many_arguments)]
fn runtime_findings(
    runtimes: &Value,
    context: &ProviderContext,
    booted_runtime_ids: &HashSet<String>,
    preferred_builds: &HashSet<String>,
    outdated: &HashSet<String>,
    unusable: &HashSet<String>,
    unused: &HashSet<String>,
) -> Vec<Finding> {
    runtimes
        .as_object()
        .into_iter()
        .flat_map(|runtimes| runtimes.iter())
        .filter_map(|(id, runtime)| {
            let state = string(runtime, "state");
            let runtime_identifier = string(runtime, "runtimeIdentifier");
            let build = string(runtime, "build");
            let deletable = runtime
                .get("deletable")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            if !deletable
                || booted_runtime_ids.contains(&runtime_identifier)
                || preferred_builds.contains(&build)
            {
                return None;
            }
            let last_used = string(runtime, "lastUsedAt");
            let age = age_from_iso8601(&last_used);
            let is_unusable = unusable.contains(id) || state != "Ready";
            let is_outdated = outdated.contains(id);
            let is_unused = unused.contains(id)
                || age.is_some_and(|days| days >= context.settings.min_age_days);
            if !is_unusable && !is_outdated && !is_unused {
                return None;
            }
            let reported_size = runtime
                .get("sizeBytes")
                .and_then(Value::as_u64)
                .unwrap_or(0);
            let path = PathBuf::from(string(runtime, "path"));
            let physical = physical_file_size(&path);
            let (rule_id, reason, safety) = if is_unusable {
                (
                    "xcode-unusable-runtime",
                    "CoreSimulator marks this runtime unusable.",
                    Safety::Safe,
                )
            } else if is_outdated {
                (
                    "xcode-outdated-runtime",
                    "A newer runtime build exists for the same platform version.",
                    Safety::Review,
                )
            } else {
                (
                    "xcode-unused-runtime",
                    "CoreSimulator reports that this runtime has not been used inside the configured age window.",
                    Safety::Review,
                )
            };
            Some(
                ProviderFinding::object(
                    metadata(),
                    rule_id,
                    "simulator-runtime",
                    id,
                    format!(
                        "{} {} ({build})",
                        platform_label(&string(runtime, "platformIdentifier")),
                        string(runtime, "version")
                    ),
                    safety,
                    reported_size.max(physical),
                )
                .size(FindingSize {
                    logical: reported_size,
                    physical,
                    unique: reported_size.max(physical),
                    shared: 0,
                    reclaimable: reported_size.max(physical),
                    accuracy: SizeAccuracy::Estimated,
                })
                .age(age, false)
                .manual()
                .confidence(Confidence::High)
                .reason(reason)
                .evidence("Runtime ID", id)
                .evidence("Build", build)
                .evidence("State", state)
                .evidence(
                    "Last used",
                    if last_used.is_empty() {
                        "unknown".into()
                    } else {
                        last_used
                    },
                )
                .copy(
                    "A downloadable simulator runtime image managed by CoreSimulator.",
                    "The runtime must be downloaded again before simulators using that OS version can boot.",
                    "Review installed projects and test requirements. Hokori uses `simctl runtime delete`, never raw file deletion.",
                )
                .action(
                    "delete-runtime",
                    vec![
                        "xcrun".into(),
                        "simctl".into(),
                        "runtime".into(),
                        "delete".into(),
                        id.clone(),
                    ],
                    true,
                    true,
                )
                .build(),
            )
        })
        .collect()
}

fn dyld_cache_findings(
    runtimes: &Value,
    booted_runtime_ids: &HashSet<String>,
    preferred_builds: &HashSet<String>,
) -> Vec<Finding> {
    runtimes
        .as_object()
        .into_iter()
        .flat_map(|runtimes| runtimes.iter())
        .filter_map(|(id, runtime)| {
            let runtime_identifier = string(runtime, "runtimeIdentifier");
            let build = string(runtime, "build");
            let state = string(runtime, "state");
            if state != "Ready"
                || booted_runtime_ids.contains(&runtime_identifier)
                || preferred_builds.contains(&build)
            {
                return None;
            }
            let bundle = PathBuf::from(string(runtime, "runtimeBundlePath"));
            let marker = dyld_cache_marker(&bundle)?;
            let bytes = marker
                .parent()
                .map(|path| {
                    size_subtree_cancellable(path, &InodeDedupe::new(), None, None).bytes
                })
                .unwrap_or(0);
            (bytes >= 100 * 1024 * 1024).then(|| {
                ProviderFinding::object(
                    metadata(),
                    "xcode-runtime-dyld-cache",
                    "simulator-runtime",
                    id,
                    format!(
                        "{} {} dyld cache",
                        platform_label(&string(runtime, "platformIdentifier")),
                        string(runtime, "version")
                    ),
                    Safety::Review,
                    bytes,
                )
                .manual()
                .reason("A generated dyld shared cache is present for this retained runtime.")
                .evidence("Build", build)
                .copy(
                    "A generated simulator dyld shared cache used to speed application launch.",
                    "CoreSimulator must rebuild the cache before the next simulator launch.",
                    "Remove only when disk pressure is high and no simulator using this runtime is booted.",
                )
                .action(
                    "remove-dyld-cache",
                    vec![
                        "xcrun".into(),
                        "simctl".into(),
                        "runtime".into(),
                        "dyld_shared_cache".into(),
                        "remove".into(),
                        id.clone(),
                    ],
                    true,
                    true,
                )
                .build()
            })
        })
        .collect()
}

fn orphaned_runtime_storage_findings(context: &ProviderContext, runtimes: &Value) -> Vec<Finding> {
    let known_paths: Vec<PathBuf> = runtimes
        .as_object()
        .into_iter()
        .flat_map(|runtimes| runtimes.values())
        .flat_map(|runtime| {
            ["path", "mountPath", "runtimeBundlePath"]
                .into_iter()
                .filter_map(|key| {
                    let value = string(runtime, key);
                    (!value.is_empty()).then(|| PathBuf::from(value))
                })
        })
        .collect();
    let mut candidates = Vec::new();
    if let Ok(images) = Path::new("/Library/Developer/CoreSimulator/Images").read_dir() {
        for image in images.flatten().take(5_000) {
            let path = image.path();
            if path.is_file()
                && !known_paths.iter().any(|known| known == &path)
                && path_age_days(&path).is_some_and(|age| age >= context.settings.min_age_days)
            {
                candidates.push((path.clone(), physical_file_size(&path)));
            }
        }
    }
    if let Ok(volumes) = Path::new("/Library/Developer/CoreSimulator/Volumes").read_dir() {
        for volume in volumes.flatten().take(5_000) {
            let path = volume.path();
            if path.is_dir()
                && !known_paths
                    .iter()
                    .any(|known| known.starts_with(&path) || path.starts_with(known))
                && path_age_days(&path).is_some_and(|age| age >= context.settings.min_age_days)
            {
                candidates.push((path.clone(), directory_size(&path, context)));
            }
        }
    }
    candidates
        .into_iter()
        .filter(|(_, bytes)| *bytes >= context.settings.min_size_bytes)
        .map(|(path, bytes)| {
            ProviderFinding::object(
                metadata(),
                "xcode-orphaned-runtime-storage",
                "simulator-runtime",
                path.display().to_string(),
                format!(
                    "Unregistered CoreSimulator storage {}",
                    path.file_name().unwrap_or_default().to_string_lossy()
                ),
                Safety::Protected,
                bytes,
            )
            .filesystem_path(path.clone())
            .manual()
            .report_only()
            .confidence(Confidence::High)
            .reason("No runtime returned by `simctl runtime list` references this image or mounted volume.")
            .evidence("Path", path.display().to_string())
            .copy(
                "A CoreSimulator image or mounted runtime volume not registered in the current runtime inventory.",
                "Raw deletion could damage a runtime being staged or managed by another Xcode installation.",
                "Report-only. Inspect with `simctl runtime scan-and-mount` and Xcode settings before taking action.",
            )
            .build()
        })
        .collect()
}

fn runtime_preview_ids(
    context: &ProviderContext,
    selector: &str,
    days: Option<u64>,
) -> HashSet<String> {
    let mut args = vec!["simctl", "runtime", "delete", selector];
    let days_string;
    if let Some(days) = days {
        days_string = days.to_string();
        args.push(&days_string);
    }
    args.push("--dry-run");
    run_read(
        context,
        SIMCTL_RUNTIME_DRY_RUN,
        &args,
        Duration::from_secs(4),
    )
    .map(|output| extract_uuids(&output))
    .unwrap_or_default()
}

fn booted_runtime_identifiers(devices: &Value) -> HashSet<String> {
    devices
        .get("devices")
        .and_then(Value::as_object)
        .into_iter()
        .flat_map(|runtimes| runtimes.iter())
        .filter(|(_, devices)| {
            devices.as_array().is_some_and(|devices| {
                devices
                    .iter()
                    .any(|device| string(device, "state") == "Booted")
            })
        })
        .map(|(runtime, _)| runtime.clone())
        .collect()
}

fn preferred_runtime_builds(matches: &Value) -> HashSet<String> {
    matches
        .as_object()
        .into_iter()
        .flat_map(|matches| matches.values())
        .filter_map(|entry| entry.get("chosenRuntimeBuild").and_then(Value::as_str))
        .map(str::to_string)
        .collect()
}

fn extract_uuids(output: &str) -> HashSet<String> {
    output
        .split(|character: char| !character.is_ascii_hexdigit() && character != '-')
        .filter(|token| {
            token.len() == 36
                && token.chars().enumerate().all(|(index, character)| {
                    matches!(index, 8 | 13 | 18 | 23)
                        .then_some(character == '-')
                        .unwrap_or_else(|| character.is_ascii_hexdigit())
                })
        })
        .map(|token| token.to_ascii_uppercase())
        .collect()
}

fn dyld_cache_marker(bundle: &Path) -> Option<PathBuf> {
    [
        bundle.join("Contents/Resources/RuntimeRoot/System/Library/dyld"),
        bundle.join("System/Library/dyld"),
    ]
    .into_iter()
    .find(|path| path.is_dir())
}

fn string(value: &Value, key: &str) -> String {
    value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string()
}

fn runtime_label(identifier: &str) -> String {
    identifier
        .rsplit('.')
        .next()
        .unwrap_or(identifier)
        .replace('-', " ")
}

fn platform_label(identifier: &str) -> &'static str {
    if identifier.contains("iphone") {
        "iOS"
    } else if identifier.contains("appletv") {
        "tvOS"
    } else if identifier.contains("watch") {
        "watchOS"
    } else if identifier.contains("xros") {
        "visionOS"
    } else {
        "Simulator"
    }
}

fn derived_data_project(path: &Path) -> Option<String> {
    let info = PlistValue::from_file(path.join("info.plist")).ok()?;
    let workspace = info.as_dictionary()?.get("WorkspacePath")?.as_string()?;
    Path::new(workspace)
        .file_stem()
        .map(|name| name.to_string_lossy().to_string())
}

fn collect_xcarchives(directory: &Path, archives: &mut Vec<PathBuf>, depth: usize) {
    if depth > 3 || archives.len() >= 20_000 {
        return;
    }
    let Ok(entries) = directory.read_dir() else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        if path
            .extension()
            .is_some_and(|extension| extension == "xcarchive")
        {
            archives.push(path);
        } else {
            collect_xcarchives(&path, archives, depth + 1);
        }
    }
}

fn archive_label(path: &Path) -> Option<String> {
    let info = PlistValue::from_file(path.join("Info.plist")).ok()?;
    let properties = info
        .as_dictionary()?
        .get("ApplicationProperties")?
        .as_dictionary()?;
    let name = properties
        .get("CFBundleDisplayName")
        .or_else(|| properties.get("CFBundleName"))
        .and_then(PlistValue::as_string)
        .unwrap_or("Xcode archive");
    let version = properties
        .get("CFBundleShortVersionString")
        .and_then(PlistValue::as_string)
        .unwrap_or("unknown version");
    Some(format!("{name} {version} archive"))
}

fn directory_size(path: &Path, context: &ProviderContext) -> u64 {
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
    std::time::SystemTime::now()
        .duration_since(modified)
        .ok()
        .map(|duration| duration.as_secs() / 86_400)
}

fn allowed_xcode_path(home: &Path, path: &Path) -> bool {
    [
        "Library/Developer/Xcode/DerivedData",
        "Library/Developer/Xcode/Archives",
        "Library/Developer/Xcode/iOS DeviceSupport",
    ]
    .into_iter()
    .any(|root| path.starts_with(home.join(root)))
}

fn delete_path(path: &Path, permanently: bool) -> Result<()> {
    if path
        .symlink_metadata()
        .is_ok_and(|metadata| metadata.file_type().is_symlink())
    {
        bail!("refusing to remove a symlink");
    }
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

    #[test]
    fn dry_run_uuid_parser_ignores_unrelated_tokens() {
        let ids = extract_uuids("Would delete D945E812-4FB8-4260-B022-EC2FC3A01A7C\nNo 1234-5678");
        assert!(ids.contains("D945E812-4FB8-4260-B022-EC2FC3A01A7C"));
        assert_eq!(ids.len(), 1);
    }
}
