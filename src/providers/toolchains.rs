use anyhow::{Context, Result, bail};
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::report::{Confidence, Finding};
use crate::rules::Safety;
use crate::taxonomy::{Section, Subgroup};
use crate::walk::{InodeDedupe, size_subtree_cancellable};

use super::command::{CommandMode, CommandPolicy, safe_token};
use super::{
    Capability, Provider, ProviderContext, ProviderExecution, ProviderExecutionOptions,
    ProviderFinding, ProviderMetadata, Revalidation, ScanCost,
};

pub struct ToolchainProvider;

const MISE_EXECUTABLES: &[&str] = &["mise"];
const RUSTUP_EXECUTABLES: &[&str] = &["rustup"];
const PYENV_EXECUTABLES: &[&str] = &["pyenv"];
const PIPX_EXECUTABLES: &[&str] = &["pipx"];
const RBENV_EXECUTABLES: &[&str] = &["rbenv"];
const ASDF_EXECUTABLES: &[&str] = &["asdf"];
const FVM_EXECUTABLES: &[&str] = &["fvm"];

const MISE_PRUNABLE: CommandPolicy = CommandPolicy {
    id: "mise-prunable",
    executables: MISE_EXECUTABLES,
    mutating: false,
    network: false,
    validate_args: args_mise_prunable,
};
const MISE_UNINSTALL: CommandPolicy = CommandPolicy {
    id: "mise-uninstall",
    executables: MISE_EXECUTABLES,
    mutating: true,
    network: false,
    validate_args: args_mise_uninstall,
};
const MISE_PRUNE_CONFIGS: CommandPolicy = CommandPolicy {
    id: "mise-prune-configs",
    executables: MISE_EXECUTABLES,
    mutating: true,
    network: false,
    validate_args: args_mise_prune_configs,
};
const RUSTUP_LIST: CommandPolicy = CommandPolicy {
    id: "rustup-list",
    executables: RUSTUP_EXECUTABLES,
    mutating: false,
    network: false,
    validate_args: args_rustup_list,
};
const RUSTUP_OVERRIDES: CommandPolicy = CommandPolicy {
    id: "rustup-overrides",
    executables: RUSTUP_EXECUTABLES,
    mutating: false,
    network: false,
    validate_args: args_rustup_overrides,
};
const RUSTUP_UNINSTALL: CommandPolicy = CommandPolicy {
    id: "rustup-uninstall",
    executables: RUSTUP_EXECUTABLES,
    mutating: true,
    network: false,
    validate_args: args_rustup_uninstall,
};
const PYENV_VERSIONS: CommandPolicy = CommandPolicy {
    id: "pyenv-versions",
    executables: PYENV_EXECUTABLES,
    mutating: false,
    network: false,
    validate_args: args_pyenv_versions,
};
const PYENV_GLOBAL: CommandPolicy = CommandPolicy {
    id: "pyenv-global",
    executables: PYENV_EXECUTABLES,
    mutating: false,
    network: false,
    validate_args: args_pyenv_global,
};
const PYENV_UNINSTALL: CommandPolicy = CommandPolicy {
    id: "pyenv-uninstall",
    executables: PYENV_EXECUTABLES,
    mutating: true,
    network: false,
    validate_args: args_pyenv_uninstall,
};
const PIPX_LIST: CommandPolicy = CommandPolicy {
    id: "pipx-list",
    executables: PIPX_EXECUTABLES,
    mutating: false,
    network: false,
    validate_args: args_pipx_list,
};
const RBENV_UNINSTALL: CommandPolicy = CommandPolicy {
    id: "rbenv-uninstall",
    executables: RBENV_EXECUTABLES,
    mutating: true,
    network: false,
    validate_args: args_rbenv_uninstall,
};
const ASDF_UNINSTALL: CommandPolicy = CommandPolicy {
    id: "asdf-uninstall",
    executables: ASDF_EXECUTABLES,
    mutating: true,
    network: false,
    validate_args: args_asdf_uninstall,
};
const FVM_REMOVE: CommandPolicy = CommandPolicy {
    id: "fvm-remove",
    executables: FVM_EXECUTABLES,
    mutating: true,
    network: false,
    validate_args: args_fvm_remove,
};

fn args_mise_prunable(args: &[OsString]) -> bool {
    args == [
        OsStr::new("ls"),
        OsStr::new("--prunable"),
        OsStr::new("--json"),
    ]
}

fn args_mise_uninstall(args: &[OsString]) -> bool {
    args.len() == 3 && args[0] == "uninstall" && args[1] == "--yes" && safe_token(&args[2])
}

fn args_mise_prune_configs(args: &[OsString]) -> bool {
    args == [
        OsStr::new("prune"),
        OsStr::new("--configs"),
        OsStr::new("--yes"),
    ]
}

fn args_rustup_list(args: &[OsString]) -> bool {
    args == [OsStr::new("toolchain"), OsStr::new("list")]
}

fn args_rustup_overrides(args: &[OsString]) -> bool {
    args == [OsStr::new("override"), OsStr::new("list")]
}

fn args_rustup_uninstall(args: &[OsString]) -> bool {
    args.len() == 3 && args[0] == "toolchain" && args[1] == "uninstall" && safe_token(&args[2])
}

fn args_pyenv_versions(args: &[OsString]) -> bool {
    args == [OsStr::new("versions"), OsStr::new("--bare")]
}

fn args_pyenv_global(args: &[OsString]) -> bool {
    args == [OsStr::new("global")]
}

fn args_pyenv_uninstall(args: &[OsString]) -> bool {
    args.len() == 3 && args[0] == "uninstall" && args[1] == "-f" && safe_token(&args[2])
}

fn args_pipx_list(args: &[OsString]) -> bool {
    args == [OsStr::new("list"), OsStr::new("--json")]
}

fn args_rbenv_uninstall(args: &[OsString]) -> bool {
    args.len() == 3 && args[0] == "uninstall" && args[1] == "-f" && safe_token(&args[2])
}

fn args_asdf_uninstall(args: &[OsString]) -> bool {
    args.len() == 3 && args[0] == "uninstall" && safe_token(&args[1]) && safe_token(&args[2])
}

fn args_fvm_remove(args: &[OsString]) -> bool {
    args.len() == 2 && args[0] == "remove" && safe_token(&args[1])
}

impl Provider for ToolchainProvider {
    fn metadata(&self) -> ProviderMetadata {
        metadata()
    }

    fn probe(&self, context: &ProviderContext) -> Capability {
        let installed = [MISE_PRUNABLE, RUSTUP_LIST, PYENV_VERSIONS]
            .into_iter()
            .any(|policy| context.runner.resolve(policy).is_some())
            || context.home.as_ref().is_some_and(|home| {
                [
                    ".nvm/versions/node",
                    ".rbenv/versions",
                    ".asdf/installs",
                    ".sdkman/candidates",
                    ".fvm/versions",
                ]
                .iter()
                .any(|path| home.join(path).is_dir())
            });
        if installed {
            Capability::Available
        } else {
            Capability::Unavailable("No supported toolchain manager is installed.".into())
        }
    }

    fn scan(&self, context: &ProviderContext) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        let reference_files = if context.reference_complete {
            context.reference_files.clone()
        } else if context.settings.profile == super::ScanProfile::Deep {
            find_reference_files(
                context,
                &[
                    "rust-toolchain.toml",
                    "rust-toolchain",
                    ".python-version",
                    ".nvmrc",
                    ".ruby-version",
                    ".tool-versions",
                    ".sdkmanrc",
                    ".fvmrc",
                    "fvm_config.json",
                ],
            )
        } else {
            Vec::new()
        };
        if context.runner.resolve(MISE_PRUNABLE).is_some() {
            findings.extend(mise_findings(context));
        }
        if context.reference_complete || context.settings.profile == super::ScanProfile::Deep {
            if context.runner.resolve(RUSTUP_LIST).is_some() {
                findings.extend(rustup_findings(context, &reference_files));
            }
            if context.runner.resolve(PYENV_VERSIONS).is_some() {
                findings.extend(pyenv_findings(context, &reference_files));
            }
            findings.extend(additional_manager_findings(context, &reference_files));
        }
        if context.settings.profile == super::ScanProfile::Deep {
            findings.extend(path_diagnostics(context));
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
                "Toolchain references changed and this version is no longer prunable.".into(),
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
            .context("toolchain action missing")?;
        let (policy, args): (CommandPolicy, Vec<String>) = match action.action_id.as_str() {
            "mise-uninstall" => (
                MISE_UNINSTALL,
                vec!["uninstall".into(), "--yes".into(), action.object_id.clone()],
            ),
            "mise-prune-configs" => (
                MISE_PRUNE_CONFIGS,
                vec!["prune".into(), "--configs".into(), "--yes".into()],
            ),
            "rustup-uninstall" => (
                RUSTUP_UNINSTALL,
                vec![
                    "toolchain".into(),
                    "uninstall".into(),
                    action.object_id.clone(),
                ],
            ),
            "pyenv-uninstall" => (
                PYENV_UNINSTALL,
                vec!["uninstall".into(), "-f".into(), action.object_id.clone()],
            ),
            "rbenv-uninstall" => (
                RBENV_UNINSTALL,
                vec!["uninstall".into(), "-f".into(), action.object_id.clone()],
            ),
            "asdf-uninstall" => {
                let (tool, version) = action
                    .object_id
                    .split_once('@')
                    .context("invalid asdf object ID")?;
                (
                    ASDF_UNINSTALL,
                    vec!["uninstall".into(), tool.into(), version.into()],
                )
            }
            "fvm-remove" => (FVM_REMOVE, vec!["remove".into(), action.object_id.clone()]),
            _ => bail!("unknown toolchain action {}", action.action_id),
        };
        run_mutation(context, policy, &args)?;
        Ok(ProviderExecution {
            deleted: 1,
            freed_bytes: finding.bytes,
            message: format!("Removed toolchain object {}.", action.object_id),
        })
    }
}

fn metadata() -> ProviderMetadata {
    ProviderMetadata {
        id: "toolchains",
        name: "Language toolchains",
        section: Section::Developer,
        subgroup: Subgroup::Toolchains,
        cost: ScanCost::Fast,
        quick: true,
        deep: true,
        network_in_deep_scan: false,
        supersedes_rules: &[],
    }
}

fn mise_findings(context: &ProviderContext) -> Vec<Finding> {
    let mut findings = Vec::new();
    if let Ok(output) = run_read(
        context,
        MISE_PRUNABLE,
        &["ls", "--prunable", "--json"],
        Duration::from_secs(4),
    ) && let Ok(json) = serde_json::from_str::<Value>(&output)
        && let Some(tools) = json.as_object()
    {
        for (tool, versions) in tools {
            for version in versions.as_array().into_iter().flatten().take(1_000) {
                let version_name = string(version, "version");
                if version_name.is_empty() {
                    continue;
                }
                let object_id = format!("{tool}@{version_name}");
                let install_path = PathBuf::from(string(version, "install_path"));
                let bytes = directory_size(&install_path, context);
                findings.push(
                        ProviderFinding::object(
                            metadata(),
                            "mise-prunable-tool",
                            "installed-tools",
                            &object_id,
                            object_id.clone(),
                            Safety::Review,
                            bytes,
                        )
                        .manual()
                        .confidence(Confidence::Exact)
                        .reason("mise marks this installed version prunable from its tracked configuration graph.")
                        .evidence("Manager", "mise")
                        .evidence("Install path", install_path.display().to_string())
                        .copy(
                            "A mise-managed tool version no longer referenced by tracked configuration.",
                            "Projects that selected this version only through environment variables or one-off commands may need to reinstall it.",
                            "Use mise's native uninstall command after reviewing the version.",
                        )
                        .action(
                            "mise-uninstall",
                            vec!["mise".into(), "uninstall".into(), "--yes".into(), object_id],
                            true,
                            true,
                        )
                        .build(),
                    );
            }
        }
    }

    if let Some(home) = &context.home {
        let tracked = home.join(".local/state/mise/tracked-configs");
        let broken: Vec<_> = tracked
            .read_dir()
            .into_iter()
            .flatten()
            .flatten()
            .filter_map(|entry| {
                let path = entry.path();
                path.symlink_metadata()
                    .ok()
                    .filter(|metadata| metadata.file_type().is_symlink())
                    .and_then(|_| path.exists().then_some(()).or(Some(())))
                    .and_then(|_| (!path.exists()).then_some(path))
            })
            .collect();
        if !broken.is_empty() {
            findings.push(
                ProviderFinding::object(
                    metadata(),
                    "mise-stale-config-links",
                    "toolchain-cache",
                    "stale-config-links",
                    "Stale mise tracked configuration links",
                    Safety::Safe,
                    0,
                )
                .grouped_paths(broken)
                .reason("Tracked mise configuration symlinks point to files that no longer exist.")
                .copy(
                    "Bookkeeping links used by mise to determine referenced tool versions.",
                    "Only broken tracked-configuration links are removed.",
                    "Safe to prune through mise.",
                )
                .action(
                    "mise-prune-configs",
                    vec![
                        "mise".into(),
                        "prune".into(),
                        "--configs".into(),
                        "--yes".into(),
                    ],
                    true,
                    false,
                )
                .build(),
            );
        }
    }
    findings
}

fn rustup_findings(context: &ProviderContext, reference_files: &[PathBuf]) -> Vec<Finding> {
    let Ok(output) = run_read(
        context,
        RUSTUP_LIST,
        &["toolchain", "list"],
        Duration::from_secs(4),
    ) else {
        return Vec::new();
    };
    let mut referenced = HashMap::<String, Vec<String>>::new();
    for line in output.lines() {
        if line.contains("(active") || line.contains("(default") {
            let toolchain = line.split_whitespace().next().unwrap_or_default();
            referenced
                .entry(rust_channel(toolchain))
                .or_default()
                .push("active/default rustup toolchain".into());
        }
    }
    if let Ok(overrides) = run_read(
        context,
        RUSTUP_OVERRIDES,
        &["override", "list"],
        Duration::from_secs(4),
    ) {
        for line in overrides.lines() {
            let mut fields = line.split_whitespace();
            if let (Some(path), Some(toolchain)) = (fields.next(), fields.next()) {
                referenced
                    .entry(rust_channel(toolchain))
                    .or_default()
                    .push(format!("rustup override at {path}"));
            }
        }
    }
    for path in reference_files_named(reference_files, &["rust-toolchain.toml", "rust-toolchain"]) {
        let Ok(contents) = std::fs::read_to_string(&path) else {
            continue;
        };
        if let Some(channel) = rust_toolchain_channel(&contents) {
            referenced
                .entry(channel)
                .or_default()
                .push(path.display().to_string());
        }
    }

    let root = context
        .home
        .as_ref()
        .map(|home| home.join(".rustup/toolchains"));
    output
        .lines()
        .filter_map(|line| {
            let installed = line.split_whitespace().next()?;
            let channel = rust_channel(installed);
            let path = root.as_ref()?.join(installed);
            let bytes = directory_size(&path, context);
            if bytes < context.settings.min_size_bytes {
                return None;
            }
            if let Some(consumers) = referenced.get(&channel) {
                return Some(
                    ProviderFinding::object(
                        metadata(),
                        "rustup-referenced-toolchain",
                        "installed-tools",
                        installed,
                        format!("Rust {installed} (referenced)"),
                        Safety::Protected,
                        bytes,
                    )
                    .diagnostic()
                    .protected()
                    .confidence(Confidence::Exact)
                    .reason("This installed Rust toolchain is active or referenced by project configuration.")
                    .evidence("Manager", "rustup")
                    .evidence("References", consumers.join(", "))
                    .copy(
                        "A Rust toolchain required by the current default, an override, or a discovered project.",
                        "Removing it would break the listed consumer until rustup downloads it again.",
                        "Protected because Hokori found an explicit consumer.",
                    )
                    .build(),
                );
            }
            Some({
                ProviderFinding::object(
                    metadata(),
                    "rustup-unreferenced-toolchain",
                    "installed-tools",
                    installed,
                    format!("Rust {installed}"),
                    Safety::Review,
                    bytes,
                )
                .manual()
                .confidence(Confidence::High)
                .reason("No default, active override, or discovered rust-toolchain file references this installed toolchain.")
                .evidence("Manager", "rustup")
                .evidence("Channel", channel)
                .evidence("Install path", path.display().to_string())
                .copy(
                    "A complete Rust compiler, standard library, components, and installed targets.",
                    "Projects that require this exact channel will trigger a new toolchain download.",
                    "Review external or non-repository consumers before using rustup's native uninstall command.",
                )
                .action(
                    "rustup-uninstall",
                    vec![
                        "rustup".into(),
                        "toolchain".into(),
                        "uninstall".into(),
                        installed.into(),
                    ],
                    true,
                    true,
                )
                .build()
            })
        })
        .collect()
}

fn pyenv_findings(context: &ProviderContext, reference_files: &[PathBuf]) -> Vec<Finding> {
    let Ok(output) = run_read(
        context,
        PYENV_VERSIONS,
        &["versions", "--bare"],
        Duration::from_secs(4),
    ) else {
        return Vec::new();
    };
    let installed: Vec<_> = output
        .lines()
        .map(str::trim)
        .filter(|version| !version.is_empty() && !version.contains('/'))
        .map(str::to_string)
        .collect();
    let mut references = HashMap::<String, Vec<String>>::new();
    if let Ok(global) = run_read(context, PYENV_GLOBAL, &["global"], Duration::from_secs(3)) {
        for requested in global
            .lines()
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            for version in &installed {
                if version_matches(requested, version) {
                    references
                        .entry(version.clone())
                        .or_default()
                        .push("pyenv global".into());
                }
            }
        }
    }
    for path in reference_files_named(reference_files, &[".python-version"]) {
        let Ok(contents) = std::fs::read_to_string(&path) else {
            continue;
        };
        for requested in contents
            .lines()
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            for version in &installed {
                if version_matches(requested, version) {
                    references
                        .entry(version.clone())
                        .or_default()
                        .push(path.display().to_string());
                }
            }
        }
    }
    if context.runner.resolve(PIPX_LIST).is_some()
        && let Ok(output) = run_read(
            context,
            PIPX_LIST,
            &["list", "--json"],
            Duration::from_secs(5),
        )
        && let Ok(json) = serde_json::from_str::<Value>(&output)
        && let Some(venvs) = json.get("venvs").and_then(Value::as_object)
    {
        for (tool, data) in venvs {
            if let Some(path) = data
                .pointer("/metadata/source_interpreter/__Path__")
                .and_then(Value::as_str)
            {
                for version in &installed {
                    if path.contains(&format!("/versions/{version}/")) {
                        references
                            .entry(version.clone())
                            .or_default()
                            .push(format!("pipx tool {tool}"));
                    }
                }
            }
        }
    }
    if let Some(versions_root) = context
        .home
        .as_ref()
        .map(|home| home.join(".pyenv/versions"))
        && let Ok(environments) = versions_root.read_dir()
    {
        for environment in environments.flatten().take(5_000) {
            let config = environment.path().join("pyvenv.cfg");
            let Ok(contents) = std::fs::read_to_string(&config) else {
                continue;
            };
            for version in &installed {
                if contents.contains(&format!("/versions/{version}"))
                    || contents.lines().any(|line| {
                        line.strip_prefix("version =")
                            .is_some_and(|value| version_matches(value.trim(), version))
                    })
                {
                    references.entry(version.clone()).or_default().push(format!(
                        "pyenv virtualenv {}",
                        environment.file_name().to_string_lossy()
                    ));
                }
            }
        }
    }
    let root = context
        .home
        .as_ref()
        .map(|home| home.join(".pyenv/versions"));
    installed
        .into_iter()
        .filter_map(|version| {
            let path = root.as_ref()?.join(&version);
            let bytes = directory_size(&path, context);
            if bytes < context.settings.min_size_bytes {
                return None;
            }
            if let Some(consumers) = references.get(&version) {
                return Some(
                    ProviderFinding::object(
                        metadata(),
                        "pyenv-referenced-version",
                        "installed-tools",
                        &version,
                        format!("Python {version} (referenced)"),
                        Safety::Protected,
                        bytes,
                    )
                    .diagnostic()
                    .protected()
                    .confidence(Confidence::Exact)
                    .reason("This Python version is referenced by pyenv configuration or an installed pipx tool.")
                    .evidence("Manager", "pyenv")
                    .evidence("References", consumers.join(", "))
                    .copy(
                        "A pyenv-managed Python installation with explicit consumers.",
                        "Removing it would break the listed project or installed tool.",
                        "Protected because Hokori found an explicit consumer.",
                    )
                    .build(),
                );
            }
            Some({
                ProviderFinding::object(
                    metadata(),
                    "pyenv-unreferenced-version",
                    "installed-tools",
                    &version,
                    format!("Python {version}"),
                    Safety::Review,
                    bytes,
                )
                .manual()
                .confidence(Confidence::High)
                .reason("No pyenv global/local file or installed pipx environment references this Python version.")
                .evidence("Manager", "pyenv")
                .evidence("Install path", path.display().to_string())
                .copy(
                    "A complete pyenv-managed Python installation.",
                    "Scripts, virtual environments, or tools outside the scanned repositories may stop working.",
                    "Review non-project consumers before using pyenv's native uninstall command.",
                )
                .action(
                    "pyenv-uninstall",
                    vec![
                        "pyenv".into(),
                        "uninstall".into(),
                        "-f".into(),
                        version.clone(),
                    ],
                    true,
                    true,
                )
                .build()
            })
        })
        .collect()
}

fn additional_manager_findings(
    context: &ProviderContext,
    reference_files: &[PathBuf],
) -> Vec<Finding> {
    let Some(home) = &context.home else {
        return Vec::new();
    };
    let mut findings = Vec::new();

    let mut nvm_refs: HashSet<String> = reference_files_named(reference_files, &[".nvmrc"])
        .into_iter()
        .filter_map(|path| std::fs::read_to_string(path).ok())
        .flat_map(|contents| {
            contents
                .lines()
                .map(str::trim)
                .filter(|line| !line.is_empty())
                .map(|line| line.trim_start_matches('v').to_string())
                .collect::<Vec<_>>()
        })
        .collect();
    if let Ok(default) = std::fs::read_to_string(home.join(".nvm/alias/default")) {
        nvm_refs.insert(default.trim().trim_start_matches('v').to_string());
    }
    findings.extend(installed_versions(
        context,
        "nvm",
        &home.join(".nvm/versions/node"),
        &nvm_refs,
        None,
    ));

    let mut ruby_refs: HashSet<String> = reference_files_named(reference_files, &[".ruby-version"])
        .into_iter()
        .filter_map(|path| std::fs::read_to_string(path).ok())
        .flat_map(|contents| {
            contents
                .lines()
                .map(str::trim)
                .filter(|line| !line.is_empty())
                .map(str::to_string)
                .collect::<Vec<_>>()
        })
        .collect();
    if let Ok(global) = std::fs::read_to_string(home.join(".rbenv/version")) {
        ruby_refs.insert(global.trim().to_string());
    }
    findings.extend(installed_versions(
        context,
        "rbenv",
        &home.join(".rbenv/versions"),
        &ruby_refs,
        context
            .runner
            .resolve(RBENV_UNINSTALL)
            .map(|_| ("rbenv-uninstall", "rbenv uninstall -f")),
    ));

    let asdf_refs = asdf_references(reference_files);
    let asdf_root = home.join(".asdf/installs");
    if let Ok(tools) = asdf_root.read_dir() {
        for tool in tools.flatten().take(1_000) {
            if !tool.path().is_dir() {
                continue;
            }
            let tool_name = tool.file_name().to_string_lossy().to_string();
            let refs = asdf_refs.get(&tool_name).cloned().unwrap_or_default();
            if let Ok(versions) = tool.path().read_dir() {
                for version in versions.flatten().take(1_000) {
                    if !version.path().is_dir()
                        || refs.contains(&version.file_name().to_string_lossy().to_string())
                    {
                        continue;
                    }
                    let version_name = version.file_name().to_string_lossy().to_string();
                    let object_id = format!("{tool_name}@{version_name}");
                    let bytes = directory_size(&version.path(), context);
                    if bytes < context.settings.min_size_bytes {
                        continue;
                    }
                    let builder =
                        manager_finding(context, "asdf", &object_id, &version.path(), bytes);
                    findings.push(if context.runner.resolve(ASDF_UNINSTALL).is_some() {
                        builder
                            .action(
                                "asdf-uninstall",
                                vec![
                                    "asdf".into(),
                                    "uninstall".into(),
                                    tool_name.clone(),
                                    version_name,
                                ],
                                true,
                                true,
                            )
                            .build()
                    } else {
                        builder.report_only().build()
                    });
                }
            }
        }
    }

    let sdkman_refs = sdkman_references(reference_files, home);
    let candidates = home.join(".sdkman/candidates");
    if let Ok(tools) = candidates.read_dir() {
        for tool in tools.flatten().take(1_000) {
            let tool_name = tool.file_name().to_string_lossy().to_string();
            let refs = sdkman_refs.get(&tool_name).cloned().unwrap_or_default();
            if let Ok(versions) = tool.path().read_dir() {
                for version in versions.flatten().take(1_000) {
                    if version.file_name() == "current" || !version.path().is_dir() {
                        continue;
                    }
                    let version_name = version.file_name().to_string_lossy().to_string();
                    if refs.contains(&version_name) {
                        continue;
                    }
                    let object_id = format!("{tool_name}@{version_name}");
                    let bytes = directory_size(&version.path(), context);
                    if bytes >= context.settings.min_size_bytes {
                        findings.push(
                            manager_finding(context, "SDKMAN", &object_id, &version.path(), bytes)
                                .report_only()
                                .build(),
                        );
                    }
                }
            }
        }
    }

    let fvm_refs = fvm_references(reference_files);
    findings.extend(installed_versions(
        context,
        "FVM",
        &home.join(".fvm/versions"),
        &fvm_refs,
        context
            .runner
            .resolve(FVM_REMOVE)
            .map(|_| ("fvm-remove", "fvm remove")),
    ));
    findings
}

fn installed_versions(
    context: &ProviderContext,
    manager: &str,
    root: &Path,
    referenced: &HashSet<String>,
    action: Option<(&str, &str)>,
) -> Vec<Finding> {
    let Ok(entries) = root.read_dir() else {
        return Vec::new();
    };
    entries
        .flatten()
        .take(5_000)
        .filter_map(|entry| {
            if !entry.path().is_dir() {
                return None;
            }
            let mut version = entry.file_name().to_string_lossy().to_string();
            let normalized = version.trim_start_matches('v').to_string();
            if referenced.contains(&version) || referenced.contains(&normalized) {
                return None;
            }
            let bytes = directory_size(&entry.path(), context);
            if bytes < context.settings.min_size_bytes {
                return None;
            }
            if manager == "nvm" {
                version = normalized;
            }
            let builder = manager_finding(context, manager, &version, &entry.path(), bytes);
            Some(if let Some((action_id, preview)) = action {
                builder
                    .action(
                        action_id,
                        preview
                            .split_whitespace()
                            .map(str::to_string)
                            .chain(std::iter::once(version))
                            .collect(),
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

fn manager_finding(
    _context: &ProviderContext,
    manager: &str,
    object_id: &str,
    path: &Path,
    bytes: u64,
) -> ProviderFinding {
    ProviderFinding::object(
        metadata(),
        "unreferenced-manager-version",
        "installed-tools",
        object_id,
        format!("{manager} {object_id}"),
        Safety::Review,
        bytes,
    )
    .manual()
    .confidence(Confidence::Medium)
    .reason(format!(
        "No discovered project marker or manager default references this {manager} version."
    ))
    .evidence("Manager", manager)
    .evidence("Install path", path.display().to_string())
    .copy(
        "An installed language or SDK version managed outside the primary mise/rustup/pyenv providers.",
        "Projects or shell scripts outside the scanned locations may stop working.",
        "Review external consumers and remove through the owning manager.",
    )
}

fn asdf_references(reference_files: &[PathBuf]) -> HashMap<String, HashSet<String>> {
    let mut references = HashMap::<String, HashSet<String>>::new();
    for path in reference_files_named(reference_files, &[".tool-versions"]) {
        let Ok(contents) = std::fs::read_to_string(path) else {
            continue;
        };
        for line in contents.lines() {
            let mut fields = line.split_whitespace();
            let Some(tool) = fields.next() else {
                continue;
            };
            for version in fields {
                references
                    .entry(tool.to_string())
                    .or_default()
                    .insert(version.to_string());
            }
        }
    }
    references
}

fn sdkman_references(reference_files: &[PathBuf], home: &Path) -> HashMap<String, HashSet<String>> {
    let mut references = HashMap::<String, HashSet<String>>::new();
    for path in reference_files_named(reference_files, &[".sdkmanrc"]) {
        let Ok(contents) = std::fs::read_to_string(path) else {
            continue;
        };
        for line in contents.lines() {
            if let Some((tool, version)) = line.split_once('=') {
                references
                    .entry(tool.trim().to_string())
                    .or_default()
                    .insert(version.trim().to_string());
            }
        }
    }
    let candidates = home.join(".sdkman/candidates");
    if let Ok(tools) = candidates.read_dir() {
        for tool in tools.flatten() {
            let current = tool.path().join("current");
            if let Ok(target) = std::fs::read_link(current)
                && let Some(version) = target.file_name()
            {
                references
                    .entry(tool.file_name().to_string_lossy().to_string())
                    .or_default()
                    .insert(version.to_string_lossy().to_string());
            }
        }
    }
    references
}

fn fvm_references(reference_files: &[PathBuf]) -> HashSet<String> {
    let mut references = HashSet::new();
    for path in reference_files_named(reference_files, &[".fvmrc", "fvm_config.json"]) {
        let Ok(contents) = std::fs::read_to_string(path) else {
            continue;
        };
        if let Ok(json) = serde_json::from_str::<Value>(&contents)
            && let Some(version) = json
                .get("flutter")
                .or_else(|| json.get("flutterSdkVersion"))
                .and_then(Value::as_str)
        {
            references.insert(version.to_string());
        }
    }
    references
}

fn path_diagnostics(context: &ProviderContext) -> Vec<Finding> {
    let path = std::env::var_os("PATH").unwrap_or_default();
    let mut commands = HashMap::<String, Vec<PathBuf>>::new();
    let mut broken = Vec::new();
    for directory in std::env::split_paths(&path).take(100) {
        let managed = directory.to_string_lossy().contains(".cargo/bin")
            || directory.to_string_lossy().contains(".pyenv/shims")
            || directory.to_string_lossy().contains(".local/share/mise")
            || directory == Path::new("/opt/homebrew/bin")
            || directory == Path::new("/usr/local/bin");
        if !managed {
            continue;
        }
        let Ok(entries) = directory.read_dir() else {
            continue;
        };
        for entry in entries.flatten().take(5_000) {
            let path = entry.path();
            let Ok(metadata) = path.symlink_metadata() else {
                continue;
            };
            if metadata.file_type().is_symlink() && !path.exists() {
                broken.push(path);
                continue;
            }
            if metadata.is_file() || metadata.file_type().is_symlink() {
                commands
                    .entry(entry.file_name().to_string_lossy().to_string())
                    .or_default()
                    .push(path);
            }
        }
    }
    let conflicts: Vec<_> = commands
        .into_iter()
        .filter(|(_, locations)| locations.len() > 1)
        .take(50)
        .collect();
    let mut findings = Vec::new();
    if !conflicts.is_empty() {
        let summary = conflicts
            .iter()
            .take(20)
            .map(|(command, locations)| {
                format!(
                    "{command}: {}",
                    locations
                        .iter()
                        .map(|path| path.display().to_string())
                        .collect::<Vec<_>>()
                        .join(" | ")
                )
            })
            .collect::<Vec<_>>()
            .join("; ");
        findings.push(
            ProviderFinding::object(
                metadata(),
                "path-command-conflict",
                "installed-tools",
                "path-conflicts",
                format!("{} managed command conflicts on PATH", conflicts.len()),
                Safety::Protected,
                0,
            )
            .diagnostic()
            .report_only()
            .confidence(Confidence::Exact)
            .reason("Command names are provided by multiple managed PATH directories.")
            .evidence("Conflicts", summary)
            .copy(
                "Duplicate command installations or shims from different package and version managers.",
                "Removing the wrong copy can change which runtime or package manager is active.",
                "Resolve the conflict through the owning manager; this diagnostic is report-only.",
            )
            .build(),
        );
    }
    if !broken.is_empty() {
        findings.push(
            ProviderFinding::object(
                metadata(),
                "broken-path-shims",
                "installed-tools",
                "broken-shims",
                "Broken managed PATH shims",
                Safety::Protected,
                0,
            )
            .diagnostic()
            .grouped_paths(broken)
            .report_only()
            .reason("Managed PATH entries contain symlinks whose targets no longer exist.")
            .copy(
                "Broken command shims left behind by removed tools or runtimes.",
                "Removing or repairing a shim changes command resolution.",
                "Use the owning manager to reshim or uninstall; Hokori does not delete these automatically.",
            )
            .build(),
        );
    }
    let _ = context;
    findings
}

fn reference_files_named(reference_files: &[PathBuf], names: &[&str]) -> Vec<PathBuf> {
    let names: HashSet<&str> = names.iter().copied().collect();
    reference_files
        .iter()
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| names.contains(name))
        })
        .cloned()
        .collect()
}

fn find_reference_files(context: &ProviderContext, names: &[&str]) -> Vec<PathBuf> {
    let names: HashSet<&str> = names.iter().copied().collect();
    let mut roots = context.repositories.clone();
    if roots.is_empty()
        && let Some(home) = &context.home
    {
        for name in ["Development", "Developer", "Projects", "Code", "src"] {
            let path = home.join(name);
            if path.is_dir() {
                roots.push(path);
            }
        }
    }
    roots.sort();
    roots.dedup();
    let mut found = HashSet::new();
    for root in roots {
        collect_reference_files(&root, &names, 0, &mut found, context);
        if found.len() >= 5_000 || context.is_cancelled() {
            break;
        }
    }
    let mut found: Vec<_> = found.into_iter().collect();
    found.sort();
    found
}

fn collect_reference_files(
    directory: &Path,
    names: &HashSet<&str>,
    depth: usize,
    found: &mut HashSet<PathBuf>,
    context: &ProviderContext,
) {
    if depth > 8 || found.len() >= 5_000 || context.is_cancelled() {
        return;
    }
    let Ok(entries) = directory.read_dir() else {
        return;
    };
    for entry in entries.flatten().take(20_000) {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        let path = entry.path();
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        if file_type.is_file() && names.contains(name_str.as_ref()) {
            found.insert(path);
        } else if file_type.is_dir()
            && !matches!(
                name_str.as_ref(),
                ".git"
                    | "node_modules"
                    | "target"
                    | ".venv"
                    | "venv"
                    | "vendor"
                    | ".gradle"
                    | "build"
                    | "dist"
                    | ".next"
                    | "Library"
            )
        {
            collect_reference_files(&path, names, depth + 1, found, context);
        }
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

fn rust_channel(installed: &str) -> String {
    for target in [
        "-aarch64-apple-darwin",
        "-x86_64-apple-darwin",
        "-x86_64-unknown-linux-gnu",
        "-aarch64-unknown-linux-gnu",
    ] {
        if let Some(channel) = installed.strip_suffix(target) {
            return channel.to_string();
        }
    }
    installed.to_string()
}

fn rust_toolchain_channel(contents: &str) -> Option<String> {
    if let Ok(value) = toml::from_str::<toml::Value>(contents)
        && let Some(channel) = value
            .get("toolchain")
            .and_then(|toolchain| toolchain.get("channel"))
            .and_then(toml::Value::as_str)
    {
        return Some(channel.to_string());
    }
    contents
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty() && !line.starts_with('['))
        .map(str::to_string)
}

fn version_matches(requested: &str, installed: &str) -> bool {
    requested == installed
        || installed
            .strip_prefix(requested)
            .is_some_and(|suffix| suffix.starts_with('.'))
}

fn string(value: &Value, key: &str) -> String {
    value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string()
}
