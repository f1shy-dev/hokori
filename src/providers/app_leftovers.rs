use anyhow::{Context, Result, bail};
use plist::Value;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use crate::report::{Confidence, Finding};
use crate::rules::Safety;
use crate::taxonomy::{Section, Subgroup};
use crate::walk::{InodeDedupe, size_subtree_cancellable};

use super::{
    Capability, Provider, ProviderContext, ProviderExecution, ProviderExecutionOptions,
    ProviderFinding, ProviderMetadata, Revalidation, ScanCost,
};

pub struct AppLeftoversProvider;

impl Provider for AppLeftoversProvider {
    fn metadata(&self) -> ProviderMetadata {
        metadata()
    }

    fn probe(&self, context: &ProviderContext) -> Capability {
        if context
            .home
            .as_ref()
            .is_some_and(|home| home.join("Library").is_dir())
        {
            Capability::Available
        } else {
            Capability::Unavailable("The user Library directory is unavailable.".into())
        }
    }

    fn scan(&self, context: &ProviderContext) -> Result<Vec<Finding>> {
        let Some(home) = &context.home else {
            return Ok(Vec::new());
        };
        let mut installed = installed_bundle_ids(home);
        installed.extend(installed_receipt_ids());
        let protected = launch_service_labels(home);
        let candidates = leftover_candidates(home);
        let mut findings = Vec::new();
        for (bundle_id, paths) in candidates {
            if owned_by_installed_app(&bundle_id, &installed)
                || protected.contains(&bundle_id)
                || bundle_id.starts_with("com.apple.")
            {
                continue;
            }
            let existing: Vec<_> = paths
                .into_iter()
                .filter(|path| path.symlink_metadata().is_ok())
                .collect();
            if existing.is_empty() {
                continue;
            }
            let bytes: u64 = existing.iter().map(|path| path_size(path, context)).sum();
            if bytes < context.settings.min_size_bytes {
                continue;
            }
            let strong = existing.iter().any(|path| {
                path.starts_with(home.join("Library/Containers"))
                    || path.starts_with(home.join("Library/Application Scripts"))
            });
            let confidence = if strong || existing.len() >= 2 {
                Confidence::High
            } else {
                Confidence::Low
            };
            let age = existing.iter().filter_map(|path| path_age_days(path)).min();
            let recent = age.is_some_and(|age| age < context.settings.min_age_days);
            findings.push(
                ProviderFinding::object(
                    metadata(),
                    "uninstalled-app-leftovers",
                    "app-cache",
                    &bundle_id,
                    format!("{bundle_id} app leftovers"),
                    Safety::Risky,
                    bytes,
                )
                .grouped_paths(existing.clone())
                .age(age, recent)
                .manual()
                .confidence(confidence)
                .reason(if confidence == Confidence::High {
                    "No installed app or launch service owns this exact third-party bundle ID, and multiple or container-scoped paths remain."
                } else {
                    "No installed app owns this exact third-party bundle ID, but only one low-confidence path was found."
                })
                .evidence("Bundle ID", &bundle_id)
                .evidence("Locations", existing.len().to_string())
                .copy(
                    "Files whose names exactly match a third-party bundle identifier that is no longer installed.",
                    "The paths may contain preferences, caches, local databases, or user-created application data.",
                    "Review every path. App leftovers are never bulk-selected and are moved to Trash by default.",
                )
                .action(
                    "trash-leftovers",
                    vec!["move exact leftover paths to Trash".into()],
                    false,
                    true,
                )
                .build(),
            );
        }
        Ok(findings)
    }

    fn revalidate(&self, context: &ProviderContext, finding: &Finding) -> Result<Revalidation> {
        let Some(home) = &context.home else {
            return Ok(Revalidation::Blocked(
                "Home directory is unavailable.".into(),
            ));
        };
        let bundle_id = finding
            .native_action
            .as_ref()
            .map(|action| action.object_id.as_str())
            .context("leftover bundle ID missing")?;
        if installed_bundle_ids(home).contains(bundle_id) {
            return Ok(Revalidation::Blocked(
                "An installed app now owns this bundle identifier.".into(),
            ));
        }
        for path in finding_paths(finding) {
            if !allowed_leftover_path(home, path) {
                return Ok(Revalidation::Blocked(format!(
                    "{} is outside allowed app-leftover locations.",
                    path.display()
                )));
            }
            if path.symlink_metadata().is_err() {
                return Ok(Revalidation::Changed(format!(
                    "{} no longer exists.",
                    path.display()
                )));
            }
            if path
                .symlink_metadata()
                .is_ok_and(|metadata| metadata.file_type().is_symlink())
            {
                return Ok(Revalidation::Blocked(format!(
                    "{} is a symlink.",
                    path.display()
                )));
            }
        }
        Ok(Revalidation::Valid)
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
        let mut deleted = 0;
        for path in finding_paths(finding) {
            delete_path(path, options.permanently)?;
            deleted += 1;
        }
        Ok(ProviderExecution {
            deleted,
            freed_bytes: finding.bytes,
            message: "App leftover paths removed.".into(),
        })
    }
}

fn metadata() -> ProviderMetadata {
    ProviderMetadata {
        id: "app-leftovers",
        name: "Uninstalled app leftovers",
        section: Section::Analysis,
        subgroup: Subgroup::Leftovers,
        cost: ScanCost::Moderate,
        quick: false,
        deep: true,
        network_in_deep_scan: false,
        supersedes_rules: &[],
    }
}

fn installed_bundle_ids(home: &Path) -> HashSet<String> {
    let mut ids = HashSet::new();
    for root in [
        PathBuf::from("/Applications"),
        PathBuf::from("/System/Applications"),
        PathBuf::from("/System/Library/CoreServices"),
        home.join("Applications"),
    ] {
        collect_apps(&root, 0, &mut ids);
    }
    ids
}

fn owned_by_installed_app(bundle_id: &str, installed: &HashSet<String>) -> bool {
    installed.iter().any(|installed| {
        bundle_id == installed
            || bundle_id
                .strip_prefix(installed)
                .is_some_and(|suffix| suffix.starts_with('.'))
    })
}

fn collect_apps(directory: &Path, depth: usize, ids: &mut HashSet<String>) {
    if depth > 8 || ids.len() >= 20_000 {
        return;
    }
    let Ok(entries) = directory.read_dir() else {
        return;
    };
    for entry in entries.flatten().take(50_000) {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        if path.extension().is_some_and(|extension| extension == "app")
            && let Some(id) = bundle_id_from_plist(&path.join("Contents/Info.plist"))
        {
            ids.insert(id);
        }
        collect_apps(&path, depth + 1, ids);
    }
}

fn bundle_id_from_plist(path: &Path) -> Option<String> {
    Value::from_file(path)
        .ok()?
        .as_dictionary()?
        .get("CFBundleIdentifier")?
        .as_string()
        .map(str::to_string)
}

fn launch_service_labels(home: &Path) -> HashSet<String> {
    let mut labels = HashSet::new();
    for directory in [
        home.join("Library/LaunchAgents"),
        PathBuf::from("/Library/LaunchAgents"),
        PathBuf::from("/Library/LaunchDaemons"),
    ] {
        let Ok(entries) = directory.read_dir() else {
            continue;
        };
        for entry in entries.flatten().take(20_000) {
            if let Ok(value) = Value::from_file(entry.path())
                && let Some(label) = value
                    .as_dictionary()
                    .and_then(|dictionary| dictionary.get("Label"))
                    .and_then(Value::as_string)
            {
                labels.insert(label.to_string());
            }
        }
    }
    labels
}

fn installed_receipt_ids() -> HashSet<String> {
    let mut identifiers = HashSet::new();
    let directory = Path::new("/var/db/receipts");
    let Ok(entries) = directory.read_dir() else {
        return identifiers;
    };
    for entry in entries.flatten().take(100_000) {
        if entry
            .path()
            .extension()
            .is_none_or(|extension| extension != "plist")
        {
            continue;
        }
        if let Ok(value) = Value::from_file(entry.path())
            && let Some(identifier) = value
                .as_dictionary()
                .and_then(|dictionary| dictionary.get("PackageIdentifier"))
                .and_then(Value::as_string)
        {
            identifiers.insert(identifier.to_string());
        }
    }
    identifiers
}

fn leftover_candidates(home: &Path) -> HashMap<String, Vec<PathBuf>> {
    let library = home.join("Library");
    let mut candidates = HashMap::<String, Vec<PathBuf>>::new();
    for (directory, suffix) in [
        (library.join("Caches"), None),
        (library.join("Containers"), None),
        (library.join("Application Scripts"), None),
        (library.join("HTTPStorages"), None),
        (library.join("WebKit"), None),
        (library.join("Logs"), None),
        (library.join("Application Support"), None),
        (library.join("Saved Application State"), Some(".savedState")),
        (library.join("Preferences"), Some(".plist")),
    ] {
        let Ok(entries) = directory.read_dir() else {
            continue;
        };
        for entry in entries.flatten().take(100_000) {
            let name = entry.file_name().to_string_lossy().to_string();
            let candidate = suffix
                .and_then(|suffix| name.strip_suffix(suffix))
                .unwrap_or(&name);
            if plausible_bundle_id(candidate) {
                candidates
                    .entry(candidate.to_string())
                    .or_default()
                    .push(entry.path());
            }
        }
    }
    candidates
}

fn plausible_bundle_id(value: &str) -> bool {
    value.matches('.').count() >= 2
        && value.len() <= 255
        && !value.starts_with("group.")
        && value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || ".-_".contains(character))
}

fn allowed_leftover_path(home: &Path, path: &Path) -> bool {
    [
        "Library/Caches",
        "Library/Containers",
        "Library/Application Scripts",
        "Library/HTTPStorages",
        "Library/WebKit",
        "Library/Logs",
        "Library/Application Support",
        "Library/Saved Application State",
        "Library/Preferences",
    ]
    .into_iter()
    .any(|root| path.starts_with(home.join(root)))
}

fn finding_paths(finding: &Finding) -> Vec<&Path> {
    match &finding.target {
        crate::report::FindingTarget::Filesystem { path } => vec![path],
        crate::report::FindingTarget::GroupedPaths { paths, .. } => {
            paths.iter().map(PathBuf::as_path).collect()
        }
        crate::report::FindingTarget::ProviderObject { .. }
        | crate::report::FindingTarget::Diagnostic { .. } => Vec::new(),
    }
}

fn path_size(path: &Path, context: &ProviderContext) -> u64 {
    if path.is_dir() {
        size_subtree_cancellable(
            path,
            &InodeDedupe::new(),
            None,
            Some(context.cancel.as_ref()),
        )
        .bytes
    } else {
        super::physical_file_size(path)
    }
}

fn path_age_days(path: &Path) -> Option<u64> {
    let modified = path.metadata().ok()?.modified().ok()?;
    SystemTime::now()
        .duration_since(modified)
        .ok()
        .map(|duration| duration.as_secs() / 86_400)
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
