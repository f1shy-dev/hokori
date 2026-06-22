use anyhow::{Context, Result, bail};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::report::{Confidence, Finding};
use crate::rules::Safety;
use crate::taxonomy::{Section, Subgroup};

use super::{
    Capability, Provider, ProviderContext, ProviderExecution, ProviderExecutionOptions,
    ProviderFinding, ProviderMetadata, Revalidation, ScanCost, physical_file_size,
};

pub struct StaleFilesProvider;

impl Provider for StaleFilesProvider {
    fn metadata(&self) -> ProviderMetadata {
        metadata()
    }

    fn probe(&self, context: &ProviderContext) -> Capability {
        if roots(context).is_empty() {
            Capability::Unavailable("No user-file analysis roots are available.".into())
        } else {
            Capability::Available
        }
    }

    fn scan(&self, context: &ProviderContext) -> Result<Vec<Finding>> {
        let mut files = Vec::new();
        let threshold = context.settings.min_age_days.max(180);
        let floor = context.settings.min_size_bytes.max(500 * 1024 * 1024);
        for root in roots(context) {
            collect(&root, 0, threshold, floor, context, &mut files);
            if files.len() >= 5_000 || context.is_cancelled() {
                break;
            }
        }
        Ok(files)
    }

    fn revalidate(&self, context: &ProviderContext, finding: &Finding) -> Result<Revalidation> {
        let path = PathBuf::from(
            &finding
                .native_action
                .as_ref()
                .context("stale-file action missing")?
                .object_id,
        );
        if !roots(context).iter().any(|root| path.starts_with(root)) {
            return Ok(Revalidation::Blocked(
                "The file is outside the configured user-file roots.".into(),
            ));
        }
        let Ok(metadata) = path.symlink_metadata() else {
            return Ok(Revalidation::Gone("The file no longer exists.".into()));
        };
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Ok(Revalidation::Blocked(
                "The path is no longer a regular file.".into(),
            ));
        }
        let age = latest_age_days(&metadata);
        if age < context.settings.min_age_days.max(180) {
            return Ok(Revalidation::Changed(
                "The file has been accessed or modified recently.".into(),
            ));
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
        let path = PathBuf::from(
            &finding
                .native_action
                .as_ref()
                .context("stale-file action missing")?
                .object_id,
        );
        let bytes = physical_file_size(&path);
        if options.permanently {
            std::fs::remove_file(&path)?;
        } else {
            #[cfg(target_os = "macos")]
            {
                use trash::macos::{DeleteMethod, TrashContextExtMacos};
                let mut trash = trash::TrashContext::default();
                trash.set_delete_method(DeleteMethod::NsFileManager);
                trash.delete(&path)?;
            }
            #[cfg(not(target_os = "macos"))]
            trash::delete(&path)?;
        }
        Ok(ProviderExecution {
            deleted: 1,
            freed_bytes: bytes,
            message: format!("Removed stale file {}.", path.display()),
        })
    }
}

fn metadata() -> ProviderMetadata {
    ProviderMetadata {
        id: "stale-files",
        name: "Large stale files",
        section: Section::Analysis,
        subgroup: Subgroup::Storage,
        cost: ScanCost::Slow,
        quick: false,
        deep: true,
        network_in_deep_scan: false,
        supersedes_rules: &["old-screen-recordings"],
    }
}

fn roots(context: &ProviderContext) -> Vec<PathBuf> {
    let Some(home) = &context.home else {
        return context.roots.clone();
    };
    if context.roots.len() == 1 && context.roots[0] == *home {
        ["Desktop", "Documents", "Downloads", "Movies"]
            .into_iter()
            .map(|name| home.join(name))
            .filter(|path| path.is_dir())
            .collect()
    } else {
        context.roots.clone()
    }
}

fn collect(
    directory: &Path,
    depth: usize,
    threshold: u64,
    floor: u64,
    context: &ProviderContext,
    findings: &mut Vec<Finding>,
) {
    if depth > 10 || findings.len() >= 5_000 || context.is_cancelled() {
        return;
    }
    let Ok(entries) = directory.read_dir() else {
        return;
    };
    for entry in entries.flatten().take(100_000) {
        let path = entry.path();
        let name = entry.file_name();
        let name = name.to_string_lossy();
        let Ok(file_metadata) = path.symlink_metadata() else {
            continue;
        };
        if file_metadata.file_type().is_symlink() {
            continue;
        }
        if file_metadata.is_dir() {
            if matches!(
                name.as_ref(),
                ".git"
                    | "node_modules"
                    | "target"
                    | "Library"
                    | "CloudStorage"
                    | "Mobile Documents"
                    | "Backups.backupdb"
                    | "MobileSync"
            ) || name.ends_with(".photoslibrary")
                || path.join(".git").exists()
            {
                continue;
            }
            collect(&path, depth + 1, threshold, floor, context, findings);
        } else if file_metadata.is_file()
            && !name.ends_with(".icloud")
            && file_metadata.len() >= floor
        {
            let age = latest_age_days(&file_metadata);
            if age < threshold {
                continue;
            }
            let bytes = physical_file_size(&path);
            findings.push(
                ProviderFinding::object(
                    metadata(),
                    "large-stale-file",
                    "large-old-files",
                    path.display().to_string(),
                    path.file_name()
                        .unwrap_or_default()
                        .to_string_lossy()
                        .to_string(),
                    Safety::Risky,
                    bytes,
                )
                .filesystem_path(path.clone())
                .age(Some(age), false)
                .manual()
                .confidence(Confidence::Exact)
                .reason("Both the last-access and modification timestamps are outside the stale-file threshold.")
                .evidence(
                    "Last accessed",
                    timestamp(file_metadata.accessed().ok()),
                )
                .evidence(
                    "Last modified",
                    timestamp(file_metadata.modified().ok()),
                )
                .copy(
                    "A very large regular file in a user-content directory that has not been accessed or modified recently.",
                    "The file may be unique user data and cannot be regenerated automatically.",
                    "Open or identify the file before selecting it. Cloud placeholders, backups, libraries, and project repositories are excluded.",
                )
                .action(
                    "trash-stale-file",
                    vec!["move file to Trash".into()],
                    false,
                    true,
                )
                .build(),
            );
        }
    }
}

fn latest_age_days(metadata: &std::fs::Metadata) -> u64 {
    let latest = [metadata.accessed().ok(), metadata.modified().ok()]
        .into_iter()
        .flatten()
        .max()
        .unwrap_or(UNIX_EPOCH);
    SystemTime::now()
        .duration_since(latest)
        .map(|duration| duration.as_secs() / 86_400)
        .unwrap_or(0)
}

fn timestamp(value: Option<SystemTime>) -> String {
    value
        .and_then(|value| value.duration_since(UNIX_EPOCH).ok())
        .map(|duration| format!("Unix {}", duration.as_secs()))
        .unwrap_or_else(|| "unknown".into())
}
