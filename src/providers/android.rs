use anyhow::{Context, Result, bail};
use std::collections::{HashMap, HashSet};
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use crate::report::{Confidence, Finding};
use crate::rules::Safety;
use crate::taxonomy::{Section, Subgroup};
use crate::walk::{InodeDedupe, size_subtree_cancellable};

use super::command::{CommandMode, CommandPolicy, safe_token};
use super::{
    Capability, Provider, ProviderContext, ProviderExecution, ProviderExecutionOptions,
    ProviderFinding, ProviderMetadata, Revalidation, ScanCost, ScanProfile,
};

pub struct AndroidProvider;

const AVDMANAGER_EXECUTABLES: &[&str] = &["avdmanager"];
const SDKMANAGER_EXECUTABLES: &[&str] = &["sdkmanager"];

const AVD_DELETE: CommandPolicy = CommandPolicy {
    id: "android-delete-avd",
    executables: AVDMANAGER_EXECUTABLES,
    mutating: true,
    network: false,
    validate_args: args_avd_delete,
};
const SDK_UNINSTALL: CommandPolicy = CommandPolicy {
    id: "android-uninstall-sdk-package",
    executables: SDKMANAGER_EXECUTABLES,
    mutating: true,
    network: false,
    validate_args: args_sdk_uninstall,
};

fn args_avd_delete(args: &[OsString]) -> bool {
    args.len() == 4
        && args[0] == "delete"
        && args[1] == "avd"
        && args[2] == "--name"
        && safe_token(&args[3])
}

fn args_sdk_uninstall(args: &[OsString]) -> bool {
    args.len() == 2 && args[0] == "--uninstall" && safe_token(&args[1])
}

#[derive(Debug, Clone)]
struct Avd {
    name: String,
    ini_path: PathBuf,
    data_path: PathBuf,
    image_relative: Option<String>,
    target: Option<String>,
    running: bool,
    age_days: Option<u64>,
}

impl Provider for AndroidProvider {
    fn metadata(&self) -> ProviderMetadata {
        metadata()
    }

    fn probe(&self, context: &ProviderContext) -> Capability {
        let available = android_home(context).is_some_and(|path| path.exists())
            || context
                .home
                .as_ref()
                .is_some_and(|home| home.join(".android/avd").is_dir());
        if available {
            Capability::Available
        } else {
            Capability::Unavailable("Android SDK and AVD storage were not found.".into())
        }
    }

    fn scan(&self, context: &ProviderContext) -> Result<Vec<Finding>> {
        let Some(home) = &context.home else {
            return Ok(Vec::new());
        };
        let sdk = android_home(context);
        let avds = read_avds(&home.join(".android/avd"), sdk.as_deref());
        let mut findings = avd_findings(context, sdk.as_deref(), &avds);
        if let Some(sdk) = &sdk {
            findings.extend(system_image_findings(context, sdk, &avds));
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
                "Android emulator or SDK references changed since the scan.".into(),
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
            .context("Android action missing")?;
        let (policy, args): (CommandPolicy, Vec<String>) = match action.action_id.as_str() {
            "delete-avd" => (
                AVD_DELETE,
                vec![
                    "delete".into(),
                    "avd".into(),
                    "--name".into(),
                    action.object_id.clone(),
                ],
            ),
            "uninstall-system-image" => (
                SDK_UNINSTALL,
                vec!["--uninstall".into(), action.object_id.clone()],
            ),
            _ => bail!("unknown Android action {}", action.action_id),
        };
        run_mutation(context, policy, &args)?;
        Ok(ProviderExecution {
            deleted: 1,
            freed_bytes: finding.bytes,
            message: format!("Removed Android object {}.", action.object_id),
        })
    }
}

fn metadata() -> ProviderMetadata {
    ProviderMetadata {
        id: "android",
        name: "Android SDK and emulators",
        section: Section::Developer,
        subgroup: Subgroup::AppleMobile,
        cost: ScanCost::Instant,
        quick: true,
        deep: true,
        network_in_deep_scan: false,
        supersedes_rules: &[],
    }
}

fn android_home(context: &ProviderContext) -> Option<PathBuf> {
    std::env::var_os("ANDROID_SDK_ROOT")
        .or_else(|| std::env::var_os("ANDROID_HOME"))
        .map(PathBuf::from)
        .or_else(|| {
            context
                .home
                .as_ref()
                .map(|home| home.join("Library/Android/sdk"))
        })
        .filter(|path| path.is_dir())
}

fn read_avds(directory: &Path, sdk: Option<&Path>) -> Vec<Avd> {
    let Ok(entries) = directory.read_dir() else {
        return Vec::new();
    };
    entries
        .flatten()
        .filter(|entry| {
            entry
                .path()
                .extension()
                .is_some_and(|extension| extension == "ini")
        })
        .take(10_000)
        .filter_map(|entry| {
            let values = read_properties(&entry.path());
            let name = entry
                .path()
                .file_stem()
                .map(|name| name.to_string_lossy().to_string())?;
            let data_path = values
                .get("path")
                .map(PathBuf::from)
                .unwrap_or_else(|| directory.join(format!("{name}.avd")));
            let config = read_properties(&data_path.join("config.ini"));
            let image_relative = config
                .get("image.sysdir.1")
                .map(|value| value.trim_end_matches('/').to_string());
            let target = values
                .get("target")
                .cloned()
                .or_else(|| config.get("target").cloned());
            let age_days = path_age_days(&data_path);
            let _image_exists = image_relative
                .as_ref()
                .and_then(|relative| sdk.map(|sdk| sdk.join(relative)))
                .is_some_and(|path| path.is_dir());
            Some(Avd {
                name,
                ini_path: entry.path(),
                data_path,
                image_relative,
                target,
                running: false,
                age_days,
            })
        })
        .collect()
}

fn avd_findings(context: &ProviderContext, sdk: Option<&Path>, avds: &[Avd]) -> Vec<Finding> {
    avds.iter()
        .filter_map(|avd| {
            let image = avd
                .image_relative
                .as_ref()
                .and_then(|relative| sdk.map(|sdk| sdk.join(relative)));
            let invalid = !avd.data_path.is_dir() || image.as_ref().is_some_and(|path| !path.is_dir());
            let stale = avd
                .age_days
                .is_some_and(|age| age >= context.settings.min_age_days);
            if !invalid && !stale {
                return None;
            }
            let bytes = directory_size(&avd.data_path, context);
            if !invalid && bytes < context.settings.min_size_bytes {
                return None;
            }
            let protected = avd.running
                || context.running_commands.iter().any(|command| {
                    command.contains("emulator")
                        && (command.contains(&format!("@{}", avd.name))
                            || command.contains(&format!("-avd {}", avd.name)))
                });
            let builder = ProviderFinding::object(
                metadata(),
                if invalid {
                    "android-invalid-avd"
                } else if protected {
                    "android-running-stale-avd"
                } else {
                    "android-stale-avd"
                },
                "android-emulator",
                &avd.name,
                format!("Android emulator {}", avd.name),
                if protected {
                    Safety::Protected
                } else if invalid {
                    Safety::Review
                } else {
                    Safety::Risky
                },
                bytes,
            )
            .age(avd.age_days, false)
            .manual()
            .confidence(if invalid {
                Confidence::Exact
            } else {
                Confidence::High
            })
            .reason(if protected {
                "The AVD appears to be running and is protected."
            } else if invalid {
                "The AVD data directory or its configured system image is missing."
            } else {
                "The AVD data directory has not changed inside the configured age window."
            })
            .evidence("Definition", avd.ini_path.display().to_string())
            .evidence(
                "System image",
                avd.image_relative
                    .clone()
                    .unwrap_or_else(|| "unknown".into()),
            )
            .evidence(
                "Target",
                avd.target.clone().unwrap_or_else(|| "unknown".into()),
            )
            .copy(
                "An Android Virtual Device containing installed apps, snapshots, accounts, and test data.",
                "Deleting it permanently removes all emulator-local state.",
                if protected {
                    "Shut down the emulator before considering removal."
                } else {
                    "Review the AVD name and data before deleting it through avdmanager."
                },
            );
            Some(if protected {
                builder.protected().build()
            } else if context.runner.resolve(AVD_DELETE).is_some() {
                builder
                    .action(
                        "delete-avd",
                        vec![
                            "avdmanager".into(),
                            "delete".into(),
                            "avd".into(),
                            "--name".into(),
                            avd.name.clone(),
                        ],
                        true,
                        true,
                    )
                    .build()
            } else {
                builder.report_only().build()
            })
        })
        .collect()
}

fn system_image_findings(context: &ProviderContext, sdk: &Path, avds: &[Avd]) -> Vec<Finding> {
    let referenced: HashSet<_> = avds
        .iter()
        .filter_map(|avd| avd.image_relative.as_deref())
        .map(normalize_relative)
        .collect();
    let mut images = Vec::new();
    collect_system_images(&sdk.join("system-images"), &mut images, 0);
    images
        .into_iter()
        .filter_map(|path| {
            let relative = path.strip_prefix(sdk).ok()?.to_string_lossy().to_string();
            let normalized = normalize_relative(&relative);
            let package = normalized.replace('/', ";");
            let bytes = directory_size(&path, context);
            if bytes < context.settings.min_size_bytes {
                return None;
            }
            let consumers: Vec<_> = avds
                .iter()
                .filter(|avd| {
                    avd.image_relative
                        .as_deref()
                        .map(normalize_relative)
                        .as_deref()
                        == Some(normalized.as_str())
                })
                .map(|avd| avd.name.clone())
                .collect();
            if referenced.contains(&normalized) {
                return (context.settings.profile == ScanProfile::Deep).then(|| {
                    ProviderFinding::object(
                        metadata(),
                        "android-referenced-system-image",
                        "tool-cache",
                        &package,
                        format!("Referenced Android image {}", normalized),
                        Safety::Protected,
                        bytes,
                    )
                    .diagnostic()
                    .protected()
                    .confidence(Confidence::Exact)
                    .reason("At least one configured AVD references this system image.")
                    .evidence("AVDs", consumers.join(", "))
                    .copy(
                        "An installed Android emulator system image.",
                        "Removing it prevents the listed AVDs from booting.",
                        "Protected because Hokori found explicit AVD references.",
                    )
                    .build()
                });
            }
            let builder = ProviderFinding::object(
                metadata(),
                "android-unreferenced-system-image",
                "tool-cache",
                &package,
                format!("Unreferenced Android image {}", normalized),
                Safety::Review,
                bytes,
            )
            .manual()
            .confidence(Confidence::Exact)
            .reason("No configured AVD references this installed system image.")
            .evidence("SDK package", &package)
            .copy(
                "A downloaded Android emulator system image not referenced by any configured AVD.",
                "Creating an emulator for this platform requires downloading the image again.",
                "Review platform requirements before uninstalling it through sdkmanager.",
            );
            Some(if context.runner.resolve(SDK_UNINSTALL).is_some() {
                builder
                    .action(
                        "uninstall-system-image",
                        vec!["sdkmanager".into(), "--uninstall".into(), package],
                        true,
                        true,
                    )
                    .build()
            } else {
                builder.report_only().build()
            })
        })
        .collect()
}

fn collect_system_images(directory: &Path, images: &mut Vec<PathBuf>, depth: usize) {
    if depth > 5 || images.len() >= 10_000 {
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
        if path.join("package.xml").is_file() {
            images.push(path);
        } else {
            collect_system_images(&path, images, depth + 1);
        }
    }
}

fn read_properties(path: &Path) -> HashMap<String, String> {
    std::fs::read_to_string(path)
        .ok()
        .map(|contents| {
            contents
                .lines()
                .filter_map(|line| line.split_once('='))
                .map(|(key, value)| (key.trim().to_string(), value.trim().to_string()))
                .collect()
        })
        .unwrap_or_default()
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

fn normalize_relative(value: &str) -> String {
    value
        .trim_start_matches('/')
        .trim_end_matches('/')
        .to_string()
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
