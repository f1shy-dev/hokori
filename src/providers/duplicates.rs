use anyhow::{Context, Result, bail};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use crate::report::{Confidence, Finding, FindingSize, SizeAccuracy};
use crate::rules::Safety;
use crate::taxonomy::{Section, Subgroup};

use super::{
    Capability, Provider, ProviderContext, ProviderExecution, ProviderExecutionOptions,
    ProviderFinding, ProviderMetadata, Revalidation, ScanCost, physical_file_size,
};

pub struct DuplicateProvider;

#[derive(Debug, Clone)]
struct Candidate {
    path: PathBuf,
    logical: u64,
    physical: u64,
    identity: Option<(u64, u64)>,
}

impl Provider for DuplicateProvider {
    fn metadata(&self) -> ProviderMetadata {
        metadata()
    }

    fn probe(&self, context: &ProviderContext) -> Capability {
        if duplicate_roots(context).is_empty() {
            Capability::Unavailable("No duplicate-analysis roots are available.".into())
        } else {
            Capability::Available
        }
    }

    fn scan(&self, context: &ProviderContext) -> Result<Vec<Finding>> {
        let floor = context.settings.min_size_bytes.max(10 * 1024 * 1024);
        let mut by_size = HashMap::<u64, Vec<Candidate>>::new();
        let mut count = 0usize;
        for root in duplicate_roots(context) {
            collect_candidates(&root, 0, floor, &mut by_size, &mut count, context);
            if count >= 20_000 || context.is_cancelled() {
                break;
            }
        }

        let mut groups = Vec::new();
        for candidates in by_size.into_values().filter(|group| group.len() > 1) {
            let mut by_partial = HashMap::<[u8; 32], Vec<Candidate>>::new();
            for candidate in candidates {
                if let Ok(hash) = partial_hash(&candidate.path, candidate.logical) {
                    by_partial.entry(hash).or_default().push(candidate);
                }
            }
            for candidates in by_partial.into_values().filter(|group| group.len() > 1) {
                let mut by_full = HashMap::<[u8; 32], Vec<Candidate>>::new();
                for candidate in candidates {
                    if context.is_cancelled() {
                        break;
                    }
                    if let Ok(hash) = full_hash(&candidate.path) {
                        by_full.entry(hash).or_default().push(candidate);
                    }
                }
                groups.extend(
                    by_full
                        .into_iter()
                        .filter(|(_, group)| distinct_files(group).len() > 1),
                );
            }
        }

        groups.sort_by_key(|(_, group)| {
            std::cmp::Reverse(
                group
                    .iter()
                    .map(|candidate| candidate.physical)
                    .sum::<u64>(),
            )
        });
        Ok(groups
            .into_iter()
            .take(200)
            .filter_map(|(hash, group)| duplicate_finding(hash, group))
            .collect())
    }

    fn revalidate(&self, context: &ProviderContext, finding: &Finding) -> Result<Revalidation> {
        let Some(action) = &finding.native_action else {
            return Ok(Revalidation::Blocked(
                "Duplicate deletion requires choosing a retained copy in the TUI.".into(),
            ));
        };
        if action.action_id != "delete-duplicate-copies" {
            return Ok(Revalidation::Blocked("Unknown duplicate action.".into()));
        }
        let retained = PathBuf::from(&action.object_id);
        if !finding.member_paths.contains(&retained) {
            return Ok(Revalidation::Blocked(
                "The retained copy is not part of this duplicate group.".into(),
            ));
        }
        let mut expected = None;
        for path in &finding.member_paths {
            if !context.roots.iter().any(|root| path.starts_with(root)) {
                return Ok(Revalidation::Blocked(format!(
                    "{} is outside the scan roots.",
                    path.display()
                )));
            }
            if path.symlink_metadata().is_err()
                || path
                    .symlink_metadata()
                    .is_ok_and(|metadata| metadata.file_type().is_symlink() || !metadata.is_file())
            {
                return Ok(Revalidation::Changed(format!(
                    "{} changed or disappeared.",
                    path.display()
                )));
            }
            let hash = full_hash(path)?;
            if expected
                .replace(hash)
                .is_some_and(|expected| expected != hash)
            {
                return Ok(Revalidation::Changed(
                    "The files no longer have identical content.".into(),
                ));
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
        let retained = PathBuf::from(
            &finding
                .native_action
                .as_ref()
                .context("duplicate action missing")?
                .object_id,
        );
        let mut deleted = 0;
        let mut freed = 0;
        for path in &finding.member_paths {
            if path == &retained {
                continue;
            }
            freed += physical_file_size(path);
            delete_path(path, options.permanently)?;
            deleted += 1;
        }
        Ok(ProviderExecution {
            deleted,
            freed_bytes: freed,
            message: format!(
                "Kept {}; removed {deleted} duplicate copies.",
                retained.display()
            ),
        })
    }
}

fn metadata() -> ProviderMetadata {
    ProviderMetadata {
        id: "duplicates",
        name: "Exact duplicate files",
        section: Section::Analysis,
        subgroup: Subgroup::Duplicates,
        cost: ScanCost::Slow,
        quick: false,
        deep: true,
        network_in_deep_scan: false,
        supersedes_rules: &[],
    }
}

fn duplicate_roots(context: &ProviderContext) -> Vec<PathBuf> {
    let Some(home) = &context.home else {
        return context.roots.clone();
    };
    if context.roots.len() == 1 && context.roots[0] == *home {
        [
            "Desktop",
            "Documents",
            "Downloads",
            "Movies",
            "Music",
            "Pictures",
            "Development",
            "Developer",
            "Projects",
        ]
        .into_iter()
        .map(|name| home.join(name))
        .filter(|path| path.is_dir())
        .collect()
    } else {
        context
            .roots
            .iter()
            .filter(|path| path.is_dir())
            .cloned()
            .collect()
    }
}

fn collect_candidates(
    directory: &Path,
    depth: usize,
    floor: u64,
    by_size: &mut HashMap<u64, Vec<Candidate>>,
    count: &mut usize,
    context: &ProviderContext,
) {
    if depth > 16 || *count >= 20_000 || context.is_cancelled() {
        return;
    }
    let Ok(entries) = directory.read_dir() else {
        return;
    };
    for entry in entries.flatten().take(100_000) {
        let path = entry.path();
        let name = entry.file_name();
        let name = name.to_string_lossy();
        let Ok(metadata) = path.symlink_metadata() else {
            continue;
        };
        if metadata.file_type().is_symlink() {
            continue;
        }
        if metadata.is_dir() {
            if matches!(
                name.as_ref(),
                ".git"
                    | "node_modules"
                    | "target"
                    | ".venv"
                    | "venv"
                    | "vendor"
                    | ".gradle"
                    | ".next"
                    | "dist"
                    | "build"
                    | "DerivedData"
                    | "Pods"
                    | ".Trash"
            ) {
                continue;
            }
            collect_candidates(&path, depth + 1, floor, by_size, count, context);
        } else if metadata.is_file() && metadata.len() >= floor {
            *count += 1;
            #[cfg(unix)]
            let identity = {
                use std::os::unix::fs::MetadataExt;
                Some((metadata.dev(), metadata.ino()))
            };
            #[cfg(not(unix))]
            let identity = None;
            by_size.entry(metadata.len()).or_default().push(Candidate {
                physical: physical_file_size(&path),
                path,
                logical: metadata.len(),
                identity,
            });
        }
    }
}

fn partial_hash(path: &Path, size: u64) -> Result<[u8; 32]> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 64 * 1024];
    let read = file.read(&mut buffer)?;
    hasher.update(&buffer[..read]);
    if size > buffer.len() as u64 {
        file.seek(SeekFrom::End(-(buffer.len() as i64)))?;
        let read = file.read(&mut buffer)?;
        hasher.update(&buffer[..read]);
    }
    hasher.update(size.to_le_bytes());
    Ok(hasher.finalize().into())
}

fn full_hash(path: &Path) -> Result<[u8; 32]> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 1024 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hasher.finalize().into())
}

fn distinct_files(group: &[Candidate]) -> Vec<&Candidate> {
    let mut identities = HashSet::new();
    group
        .iter()
        .filter(|candidate| {
            candidate
                .identity
                .is_none_or(|identity| identities.insert(identity))
        })
        .collect()
}

fn duplicate_finding(hash: [u8; 32], group: Vec<Candidate>) -> Option<Finding> {
    let distinct = distinct_files(&group);
    if distinct.len() < 2 {
        return None;
    }
    let paths: Vec<_> = distinct
        .iter()
        .map(|candidate| candidate.path.clone())
        .collect();
    let logical = distinct[0].logical;
    let physical: u64 = distinct.iter().map(|candidate| candidate.physical).sum();
    let retained = distinct
        .iter()
        .map(|candidate| candidate.physical)
        .min()
        .unwrap_or(0);
    let potential = physical.saturating_sub(retained);
    let apfs = paths.first().is_some_and(|path| is_apfs(path));
    let hash_hex = hash
        .iter()
        .take(8)
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    Some(
        ProviderFinding::object(
            metadata(),
            "exact-duplicate-files",
            "large-old-files",
            &hash_hex,
            format!("{} exact copies of a {} file", paths.len(), human_size(logical)),
            Safety::Risky,
            potential,
        )
        .grouped_paths(paths)
        .size(FindingSize {
            logical: logical.saturating_mul(distinct.len() as u64),
            physical,
            unique: potential,
            shared: 0,
            reclaimable: potential,
            accuracy: SizeAccuracy::Estimated,
        })
        .manual()
        .report_only()
        .confidence(Confidence::Exact)
        .reason("All files have the same logical length and complete SHA-256 content hash.")
        .evidence("SHA-256 prefix", hash_hex)
        .evidence(
            "Storage estimate",
            if apfs {
                "APFS detected; clone-shared extents may make actual savings lower."
            } else {
                "Allocated bytes of all but one retained copy."
            },
        )
        .copy(
            "Byte-for-byte duplicate files at different paths.",
            "Deleting the wrong copy may remove the version referenced by a project, library, or application.",
            "Choose which copy to retain. Hokori will not auto-delete duplicate groups.",
        )
        .build(),
    )
}

#[cfg(target_os = "macos")]
fn is_apfs(path: &Path) -> bool {
    use std::ffi::{CStr, CString};
    use std::os::unix::ffi::OsStrExt;
    let Ok(path) = CString::new(path.as_os_str().as_bytes()) else {
        return false;
    };
    let mut stats = std::mem::MaybeUninit::<libc::statfs>::uninit();
    if unsafe { libc::statfs(path.as_ptr(), stats.as_mut_ptr()) } != 0 {
        return false;
    }
    let stats = unsafe { stats.assume_init() };
    let name = unsafe { CStr::from_ptr(stats.f_fstypename.as_ptr()) };
    name.to_bytes() == b"apfs"
}

#[cfg(not(target_os = "macos"))]
fn is_apfs(_path: &Path) -> bool {
    false
}

fn human_size(bytes: u64) -> String {
    crate::report::human_bytes(bytes)
}

fn delete_path(path: &Path, permanently: bool) -> Result<()> {
    if permanently {
        std::fs::remove_file(path)?;
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
