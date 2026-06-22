use anyhow::{Context, Result, bail};
use std::collections::HashMap;
use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::report::{Confidence, Finding};
use crate::rules::Safety;
use crate::taxonomy::{Section, Subgroup};
use crate::walk::{InodeDedupe, size_subtree_cancellable};

use super::command::{CommandMode, CommandPolicy, safe_absolute_path, safe_token};
use super::{
    Capability, Provider, ProviderContext, ProviderExecution, ProviderExecutionOptions,
    ProviderFinding, ProviderMetadata, Revalidation, ScanCost, ScanProfile, parse_human_bytes,
    physical_file_size,
};

pub struct GitProvider;

const GIT_EXECUTABLES: &[&str] = &["/usr/bin/git", "/opt/homebrew/bin/git", "git"];

const WORKTREE_LIST: CommandPolicy = CommandPolicy {
    id: "git-worktree-list",
    executables: GIT_EXECUTABLES,
    mutating: false,
    network: false,
    validate_args: args_worktree_list,
};
const WORKTREE_PRUNE_DRY: CommandPolicy = CommandPolicy {
    id: "git-worktree-prune-preview",
    executables: GIT_EXECUTABLES,
    mutating: false,
    network: false,
    validate_args: args_worktree_prune_dry,
};
const GIT_STATUS: CommandPolicy = CommandPolicy {
    id: "git-status",
    executables: GIT_EXECUTABLES,
    mutating: false,
    network: false,
    validate_args: args_status,
};
const GIT_LAST_COMMIT: CommandPolicy = CommandPolicy {
    id: "git-last-commit",
    executables: GIT_EXECUTABLES,
    mutating: false,
    network: false,
    validate_args: args_last_commit,
};
const GIT_UPSTREAM: CommandPolicy = CommandPolicy {
    id: "git-upstream",
    executables: GIT_EXECUTABLES,
    mutating: false,
    network: false,
    validate_args: args_upstream,
};
const GIT_REV_COUNTS: CommandPolicy = CommandPolicy {
    id: "git-rev-counts",
    executables: GIT_EXECUTABLES,
    mutating: false,
    network: false,
    validate_args: args_rev_counts,
};
const GIT_COUNT_OBJECTS: CommandPolicy = CommandPolicy {
    id: "git-count-objects",
    executables: GIT_EXECUTABLES,
    mutating: false,
    network: false,
    validate_args: args_count_objects,
};
const GIT_LFS_PRUNE_DRY: CommandPolicy = CommandPolicy {
    id: "git-lfs-prune-preview",
    executables: GIT_EXECUTABLES,
    mutating: false,
    network: false,
    validate_args: args_lfs_prune_dry,
};
const GIT_LFS_PRUNE_VERIFY_DRY: CommandPolicy = CommandPolicy {
    id: "git-lfs-prune-verify-preview",
    executables: GIT_EXECUTABLES,
    mutating: false,
    network: true,
    validate_args: args_lfs_prune_verify_dry,
};
const WORKTREE_REMOVE: CommandPolicy = CommandPolicy {
    id: "git-worktree-remove",
    executables: GIT_EXECUTABLES,
    mutating: true,
    network: false,
    validate_args: args_worktree_remove,
};
const WORKTREE_PRUNE: CommandPolicy = CommandPolicy {
    id: "git-worktree-prune",
    executables: GIT_EXECUTABLES,
    mutating: true,
    network: false,
    validate_args: args_worktree_prune,
};
const GIT_LFS_PRUNE: CommandPolicy = CommandPolicy {
    id: "git-lfs-prune",
    executables: GIT_EXECUTABLES,
    mutating: true,
    network: false,
    validate_args: args_lfs_prune,
};
const GIT_LFS_PRUNE_VERIFY: CommandPolicy = CommandPolicy {
    id: "git-lfs-prune-verify",
    executables: GIT_EXECUTABLES,
    mutating: true,
    network: true,
    validate_args: args_lfs_prune_verify,
};
const GIT_MAINTENANCE: CommandPolicy = CommandPolicy {
    id: "git-maintenance",
    executables: GIT_EXECUTABLES,
    mutating: true,
    network: false,
    validate_args: args_maintenance,
};

fn has_cwd(args: &[OsString]) -> bool {
    args.len() >= 3 && args[0] == "-C" && safe_absolute_path(&args[1])
}

fn tail_eq(args: &[OsString], expected: &[&str]) -> bool {
    args.len() == expected.len() + 2
        && has_cwd(args)
        && args[2..]
            .iter()
            .zip(expected)
            .all(|(actual, expected)| actual == OsStr::new(expected))
}

fn args_worktree_list(args: &[OsString]) -> bool {
    tail_eq(args, &["worktree", "list", "--porcelain", "-z"])
}

fn args_worktree_prune_dry(args: &[OsString]) -> bool {
    tail_eq(args, &["worktree", "prune", "--dry-run", "--verbose"])
}

fn args_status(args: &[OsString]) -> bool {
    tail_eq(
        args,
        &["status", "--porcelain=v1", "-z", "--untracked-files=all"],
    )
}

fn args_last_commit(args: &[OsString]) -> bool {
    tail_eq(args, &["log", "-1", "--format=%ct"])
}

fn args_upstream(args: &[OsString]) -> bool {
    tail_eq(
        args,
        &["rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{u}"],
    )
}

fn args_rev_counts(args: &[OsString]) -> bool {
    args.len() == 7
        && has_cwd(args)
        && args[2] == "rev-list"
        && args[3] == "--left-right"
        && args[4] == "--count"
        && safe_token(&args[5])
        && args[6] == "--"
}

fn args_count_objects(args: &[OsString]) -> bool {
    tail_eq(args, &["count-objects", "-vH"])
}

fn args_lfs_prune_dry(args: &[OsString]) -> bool {
    tail_eq(args, &["lfs", "prune", "--dry-run", "--verbose"])
}

fn args_lfs_prune_verify_dry(args: &[OsString]) -> bool {
    tail_eq(
        args,
        &["lfs", "prune", "--dry-run", "--verbose", "--verify-remote"],
    )
}

fn args_worktree_remove(args: &[OsString]) -> bool {
    args.len() == 6
        && has_cwd(args)
        && args[2] == "worktree"
        && args[3] == "remove"
        && args[4] == "--"
        && safe_absolute_path(&args[5])
}

fn args_worktree_prune(args: &[OsString]) -> bool {
    tail_eq(args, &["worktree", "prune", "--verbose"])
}

fn args_lfs_prune(args: &[OsString]) -> bool {
    tail_eq(args, &["lfs", "prune"])
}

fn args_lfs_prune_verify(args: &[OsString]) -> bool {
    tail_eq(args, &["lfs", "prune", "--verify-remote"])
}

fn args_maintenance(args: &[OsString]) -> bool {
    tail_eq(args, &["maintenance", "run", "--auto"])
}

#[derive(Debug, Clone)]
struct Worktree {
    path: PathBuf,
    head: String,
    branch: Option<String>,
    detached: bool,
    locked: Option<String>,
    prunable: Option<String>,
}

impl Provider for GitProvider {
    fn metadata(&self) -> ProviderMetadata {
        metadata()
    }

    fn probe(&self, context: &ProviderContext) -> Capability {
        if context.runner.resolve(WORKTREE_LIST).is_some() {
            Capability::Available
        } else {
            Capability::Unavailable("Git is not installed.".into())
        }
    }

    fn scan(&self, context: &ProviderContext) -> Result<Vec<Finding>> {
        let repositories = main_repositories(&context.repositories);
        let mut findings = Vec::new();
        for repository in repositories.into_iter().take(100) {
            if context.is_cancelled() {
                break;
            }
            let common = common_git_dir(&repository);
            if common
                .as_ref()
                .is_some_and(|common| common.join("worktrees").is_dir())
            {
                findings.extend(worktree_findings(context, &repository)?);
            }
            if common
                .as_ref()
                .is_some_and(|common| common.join("lfs/objects").is_dir())
            {
                findings.extend(lfs_findings(context, &repository));
            }
            if context.settings.profile == ScanProfile::Deep
                && common
                    .as_ref()
                    .is_some_and(|common| packed_object_size(common) >= 100 * 1024 * 1024)
            {
                findings.extend(repository_maintenance_findings(context, &repository));
            }
        }
        Ok(findings)
    }

    fn revalidate(&self, context: &ProviderContext, finding: &Finding) -> Result<Revalidation> {
        let action = finding
            .native_action
            .as_ref()
            .context("Git action missing")?;
        if action.action_id == "remove-worktree" {
            let path = PathBuf::from(&action.object_id);
            if !path.is_dir() {
                return Ok(Revalidation::Gone("The worktree no longer exists.".into()));
            }
            if !run_read(
                context,
                GIT_STATUS,
                status_args(&path),
                Duration::from_secs(3),
            )?
            .is_empty()
            {
                return Ok(Revalidation::Blocked(
                    "The worktree now contains uncommitted or untracked files.".into(),
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
                "Repository state changed and this action is no longer eligible.".into(),
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
            .context("Git action missing")?;
        let repository =
            evidence_path(finding, "Repository").context("repository evidence missing")?;
        let (policy, args): (CommandPolicy, Vec<OsString>) = match action.action_id.as_str() {
            "remove-worktree" => (
                WORKTREE_REMOVE,
                vec![
                    "-C".into(),
                    repository.into_os_string(),
                    "worktree".into(),
                    "remove".into(),
                    "--".into(),
                    OsString::from(&action.object_id),
                ],
            ),
            "prune-worktree-metadata" => (
                WORKTREE_PRUNE,
                command_args(&repository, &["worktree", "prune", "--verbose"]),
            ),
            "prune-lfs" => (GIT_LFS_PRUNE, command_args(&repository, &["lfs", "prune"])),
            "prune-lfs-verified" => (
                GIT_LFS_PRUNE_VERIFY,
                command_args(&repository, &["lfs", "prune", "--verify-remote"]),
            ),
            "maintenance" => (
                GIT_MAINTENANCE,
                command_args(&repository, &["maintenance", "run", "--auto"]),
            ),
            _ => bail!("unknown Git action {}", action.action_id),
        };
        run_mutation(context, policy, args)?;
        Ok(ProviderExecution {
            deleted: 1,
            freed_bytes: finding.bytes,
            message: format!("Git action {} completed.", action.action_id),
        })
    }
}

fn metadata() -> ProviderMetadata {
    ProviderMetadata {
        id: "git",
        name: "Git repositories",
        section: Section::Developer,
        subgroup: Subgroup::Repositories,
        cost: ScanCost::Moderate,
        quick: true,
        deep: true,
        network_in_deep_scan: true,
        supersedes_rules: &[],
    }
}

fn main_repositories(repositories: &[PathBuf]) -> Vec<PathBuf> {
    let mut by_common = HashMap::<PathBuf, PathBuf>::new();
    for repository in repositories {
        let Some(common) = common_git_dir(repository) else {
            continue;
        };
        let candidate = if repository.join(".git").is_dir() {
            repository.clone()
        } else {
            by_common
                .get(&common)
                .cloned()
                .unwrap_or_else(|| repository.clone())
        };
        by_common.entry(common).or_insert(candidate);
    }
    let mut repositories: Vec<_> = by_common.into_values().collect();
    repositories.sort();
    repositories
}

fn common_git_dir(repository: &Path) -> Option<PathBuf> {
    let dot_git = repository.join(".git");
    if dot_git.is_dir() {
        return dot_git.canonicalize().ok().or(Some(dot_git));
    }
    if repository.join("HEAD").is_file()
        && repository.join("objects").is_dir()
        && repository.join("refs").is_dir()
    {
        return repository
            .canonicalize()
            .ok()
            .or_else(|| Some(repository.to_path_buf()));
    }
    let contents = std::fs::read_to_string(dot_git).ok()?;
    let raw = contents.trim().strip_prefix("gitdir:")?.trim();
    let git_dir = if Path::new(raw).is_absolute() {
        PathBuf::from(raw)
    } else {
        repository.join(raw)
    };
    let git_dir = git_dir.canonicalize().unwrap_or(git_dir);
    let parent = git_dir.parent()?;
    if parent.file_name().is_some_and(|name| name == "worktrees") {
        parent.parent().map(Path::to_path_buf)
    } else {
        Some(git_dir)
    }
}

fn packed_object_size(common: &Path) -> u64 {
    common
        .join("objects/pack")
        .read_dir()
        .into_iter()
        .flatten()
        .flatten()
        .filter(|entry| {
            entry
                .path()
                .extension()
                .is_some_and(|extension| extension == "pack")
        })
        .map(|entry| physical_file_size(&entry.path()))
        .sum()
}

fn worktree_findings(context: &ProviderContext, repository: &Path) -> Result<Vec<Finding>> {
    let output = run_read(
        context,
        WORKTREE_LIST,
        command_args(repository, &["worktree", "list", "--porcelain", "-z"]),
        Duration::from_secs(4),
    )?;
    let worktrees = parse_worktrees(output.as_bytes());
    if worktrees.is_empty() {
        return Ok(Vec::new());
    }
    let main = worktrees[0].path.clone();
    let mut findings = Vec::new();

    let prunable: Vec<_> = worktrees
        .iter()
        .filter(|worktree| worktree.prunable.is_some())
        .collect();
    if !prunable.is_empty() {
        let preview = run_read(
            context,
            WORKTREE_PRUNE_DRY,
            command_args(&main, &["worktree", "prune", "--dry-run", "--verbose"]),
            Duration::from_secs(4),
        )
        .unwrap_or_default();
        findings.push(
            ProviderFinding::object(
                metadata(),
                "git-prunable-worktree-metadata",
                "project-junk",
                main.display().to_string(),
                format!(
                    "{}: stale worktree metadata",
                    main.file_name().unwrap_or_default().to_string_lossy()
                ),
                Safety::Safe,
                0,
            )
            .reason("Git reports linked-worktree records whose directories no longer exist.")
            .evidence("Repository", main.display().to_string())
            .evidence("Records", prunable.len().to_string())
            .evidence(
                "Git preview",
                preview.lines().next().unwrap_or("stale metadata confirmed"),
            )
            .copy(
                "Administrative records for linked worktrees that are already missing.",
                "Only stale metadata under the repository's Git directory is removed.",
                "Safe to prune through Git's own worktree command.",
            )
            .action(
                "prune-worktree-metadata",
                vec![
                    "git".into(),
                    "-C".into(),
                    main.display().to_string(),
                    "worktree".into(),
                    "prune".into(),
                    "--verbose".into(),
                ],
                true,
                false,
            )
            .build(),
        );
    }

    for worktree in worktrees
        .iter()
        .filter(|worktree| worktree.path != main && worktree.prunable.is_none())
        .take(200)
    {
        if !worktree.path.is_dir() || worktree.locked.is_some() || context.is_cancelled() {
            continue;
        }
        let last_commit = run_read(
            context,
            GIT_LAST_COMMIT,
            command_args(&worktree.path, &["log", "-1", "--format=%ct"]),
            Duration::from_secs(3),
        )
        .ok()
        .and_then(|value| value.trim().parse::<u64>().ok());
        let age = last_commit.map(epoch_age_days).unwrap_or(0);
        if age < context.settings.min_age_days {
            continue;
        }
        let bytes = size_subtree_cancellable(
            &worktree.path,
            &InodeDedupe::new(),
            None,
            Some(context.cancel.as_ref()),
        )
        .bytes;
        if bytes < context.settings.min_size_bytes {
            continue;
        }
        let dirty = !run_read(
            context,
            GIT_STATUS,
            status_args(&worktree.path),
            Duration::from_secs(4),
        )
        .unwrap_or_else(|_| "unknown".into())
        .is_empty();
        let upstream = run_read(
            context,
            GIT_UPSTREAM,
            command_args(
                &worktree.path,
                &["rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{u}"],
            ),
            Duration::from_secs(3),
        )
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());
        let counts = upstream.as_ref().and_then(|upstream| {
            let range = format!("{upstream}...HEAD");
            run_read(
                context,
                GIT_REV_COUNTS,
                vec![
                    "-C".into(),
                    worktree.path.clone().into_os_string(),
                    "rev-list".into(),
                    "--left-right".into(),
                    "--count".into(),
                    range.into(),
                    "--".into(),
                ],
                Duration::from_secs(3),
            )
            .ok()
            .and_then(|value| parse_counts(&value))
        });
        let branch = worktree.branch.as_deref().unwrap_or(if worktree.detached {
            "detached HEAD"
        } else {
            "unknown"
        });
        let protected = dirty || worktree.detached || upstream.is_none() || counts.is_none();
        let ahead = counts.map(|(_, ahead)| ahead).unwrap_or(0);
        let protected = protected || ahead > 0;
        let builder = ProviderFinding::object(
            metadata(),
            if protected {
                "git-protected-stale-worktree"
            } else {
                "git-stale-worktree"
            },
            "project-junk",
            worktree.path.display().to_string(),
            format!(
                "{}: {}",
                worktree.path.file_name().unwrap_or_default().to_string_lossy(),
                branch.trim_start_matches("refs/heads/")
            ),
            if protected {
                Safety::Protected
            } else {
                Safety::Review
            },
            bytes,
        )
        .age(Some(age), false)
        .manual()
        .confidence(Confidence::High)
        .reason(if dirty {
            "The worktree is old but contains uncommitted or untracked files."
        } else if worktree.detached {
            "The worktree is old and detached, so branch ownership is ambiguous."
        } else if upstream.is_none() {
            "The worktree is old but its branch has no configured upstream."
        } else if ahead > 0 {
            "The worktree branch contains commits not present in its upstream."
        } else {
            "The worktree is clean, old, and has no commits ahead of its upstream."
        })
        .evidence("Repository", main.display().to_string())
        .evidence("Worktree", worktree.path.display().to_string())
        .evidence("Branch", branch)
        .evidence("HEAD", short_hash(&worktree.head))
        .evidence("Age", format!("{age} days"))
        .evidence("Upstream", upstream.unwrap_or_else(|| "none".into()))
        .evidence(
            "Ahead/behind",
            counts
                .map(|(behind, ahead)| format!("{ahead} ahead, {behind} behind"))
                .unwrap_or_else(|| "unknown".into()),
        )
        .copy(
            "A linked Git worktree that has not received a commit in the configured age window.",
            "Removing the worktree deletes its checked-out files; the branch and commits remain in the repository.",
            if protected {
                "Hokori will not remove this worktree because its local state cannot be proven disposable."
            } else {
                "Review the branch and path. Hokori rechecks dirtiness and upstream state before using `git worktree remove`."
            },
        );
        findings.push(if protected {
            builder.protected().build()
        } else {
            builder
                .action(
                    "remove-worktree",
                    vec![
                        "git".into(),
                        "-C".into(),
                        main.display().to_string(),
                        "worktree".into(),
                        "remove".into(),
                        "--".into(),
                        worktree.path.display().to_string(),
                    ],
                    true,
                    true,
                )
                .build()
        });
    }
    Ok(findings)
}

fn lfs_findings(context: &ProviderContext, repository: &Path) -> Vec<Finding> {
    let Some(common) = common_git_dir(repository) else {
        return Vec::new();
    };
    let objects = common.join("lfs/objects");
    if !objects.is_dir() {
        return Vec::new();
    }
    let policy = if context.settings.profile == ScanProfile::Deep {
        GIT_LFS_PRUNE_VERIFY_DRY
    } else {
        GIT_LFS_PRUNE_DRY
    };
    let tail: &[&str] = if context.settings.profile == ScanProfile::Deep {
        &["lfs", "prune", "--dry-run", "--verbose", "--verify-remote"]
    } else {
        &["lfs", "prune", "--dry-run", "--verbose"]
    };
    let Ok(output) = run_read(
        context,
        policy,
        command_args(repository, tail),
        if context.settings.profile == ScanProfile::Deep {
            Duration::from_secs(20)
        } else {
            Duration::from_secs(8)
        },
    ) else {
        return Vec::new();
    };
    let hashes: Vec<_> = output
        .lines()
        .filter_map(|line| line.trim().strip_prefix('*'))
        .map(str::trim)
        .filter(|hash| hash.len() >= 32 && hash.chars().all(|c| c.is_ascii_hexdigit()))
        .take(20_000)
        .collect();
    if hashes.is_empty() {
        return Vec::new();
    }
    let bytes: u64 = hashes
        .iter()
        .map(|hash| physical_file_size(&objects.join(&hash[..2]).join(&hash[2..4]).join(hash)))
        .sum();
    if bytes < context.settings.min_size_bytes {
        return Vec::new();
    }
    vec![
        ProviderFinding::object(
            metadata(),
            "git-lfs-prunable-objects",
            "project-artifact",
            repository.display().to_string(),
            format!(
                "{}: prunable Git LFS objects",
                repository.file_name().unwrap_or_default().to_string_lossy()
            ),
            Safety::Safe,
            bytes,
        )
        .reason(if context.settings.profile == ScanProfile::Deep {
            "Git LFS verified the candidate objects against the configured remote."
        } else {
            "Git LFS reports these objects as old, unused, and not uniquely unpushed."
        })
        .evidence("Repository", repository.display().to_string())
        .evidence("Objects", hashes.len().to_string())
        .copy(
            "Local Git LFS object copies that are not needed by current, recent, stashed, unpushed, or other-worktree references.",
            "The objects must be downloaded again if an old commit needs them.",
            "Deep scan additionally asks the remote to verify reachable copies before cleanup.",
        )
        .action(
            if context.settings.profile == ScanProfile::Deep {
                "prune-lfs-verified"
            } else {
                "prune-lfs"
            },
            if context.settings.profile == ScanProfile::Deep {
                vec![
                    "git".into(),
                    "-C".into(),
                    repository.display().to_string(),
                    "lfs".into(),
                    "prune".into(),
                    "--verify-remote".into(),
                ]
            } else {
                vec![
                    "git".into(),
                    "-C".into(),
                    repository.display().to_string(),
                    "lfs".into(),
                    "prune".into(),
                ]
            },
            true,
            false,
        )
        .build(),
    ]
}

fn repository_maintenance_findings(context: &ProviderContext, repository: &Path) -> Vec<Finding> {
    let Ok(output) = run_read(
        context,
        GIT_COUNT_OBJECTS,
        command_args(repository, &["count-objects", "-vH"]),
        Duration::from_secs(4),
    ) else {
        return Vec::new();
    };
    let values: HashMap<_, _> = output
        .lines()
        .filter_map(|line| line.split_once(':'))
        .map(|(key, value)| (key.trim(), value.trim()))
        .collect();
    let loose_count = values
        .get("count")
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(0);
    let loose_size = values
        .get("size")
        .and_then(|value| parse_human_bytes(value))
        .unwrap_or(0);
    if loose_count < 1_000 || loose_size < context.settings.min_size_bytes {
        return Vec::new();
    }
    vec![
        ProviderFinding::object(
            metadata(),
            "git-maintenance-recommended",
            "project-artifact",
            repository.display().to_string(),
            format!(
                "{}: loose Git objects",
                repository.file_name().unwrap_or_default().to_string_lossy()
            ),
            Safety::Safe,
            loose_size / 2,
        )
        .estimated()
        .reason("The repository contains enough loose objects for normal Git maintenance to help.")
        .evidence("Repository", repository.display().to_string())
        .evidence("Loose objects", loose_count.to_string())
        .evidence(
            "Loose size",
            values.get("size").copied().unwrap_or("unknown"),
        )
        .copy(
            "Loose Git objects that Git can pack during ordinary maintenance.",
            "Git rewrites internal object storage without changing commits or working files.",
            "Hokori runs `git maintenance run --auto`; it never uses aggressive immediate pruning.",
        )
        .action(
            "maintenance",
            vec![
                "git".into(),
                "-C".into(),
                repository.display().to_string(),
                "maintenance".into(),
                "run".into(),
                "--auto".into(),
            ],
            true,
            false,
        )
        .build(),
    ]
}

fn run_read(
    context: &ProviderContext,
    policy: CommandPolicy,
    args: Vec<OsString>,
    timeout: Duration,
) -> Result<String> {
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
    let text = if output.stdout.is_empty() {
        output.stderr
    } else {
        output.stdout
    };
    Ok(text.trim_end_matches('\n').to_string())
}

fn run_mutation(
    context: &ProviderContext,
    policy: CommandPolicy,
    args: Vec<OsString>,
) -> Result<()> {
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

fn command_args(repository: &Path, tail: &[&str]) -> Vec<OsString> {
    let mut args = vec!["-C".into(), repository.as_os_str().to_owned()];
    args.extend(tail.iter().map(OsString::from));
    args
}

fn status_args(repository: &Path) -> Vec<OsString> {
    command_args(
        repository,
        &["status", "--porcelain=v1", "-z", "--untracked-files=all"],
    )
}

fn parse_worktrees(bytes: &[u8]) -> Vec<Worktree> {
    let mut worktrees = Vec::new();
    let mut current: Option<Worktree> = None;
    for field in bytes.split(|byte| *byte == 0) {
        if field.is_empty() {
            if let Some(worktree) = current.take() {
                worktrees.push(worktree);
            }
            continue;
        }
        let field = String::from_utf8_lossy(field);
        if let Some(path) = field.strip_prefix("worktree ") {
            if let Some(worktree) = current.take() {
                worktrees.push(worktree);
            }
            current = Some(Worktree {
                path: PathBuf::from(path),
                head: String::new(),
                branch: None,
                detached: false,
                locked: None,
                prunable: None,
            });
        } else if let Some(worktree) = current.as_mut() {
            if let Some(head) = field.strip_prefix("HEAD ") {
                worktree.head = head.into();
            } else if let Some(branch) = field.strip_prefix("branch ") {
                worktree.branch = Some(branch.into());
            } else if field == "detached" {
                worktree.detached = true;
            } else if let Some(reason) = field.strip_prefix("locked") {
                worktree.locked = Some(reason.trim().into());
            } else if let Some(reason) = field.strip_prefix("prunable") {
                worktree.prunable = Some(reason.trim().into());
            }
        }
    }
    if let Some(worktree) = current {
        worktrees.push(worktree);
    }
    worktrees
}

fn parse_counts(value: &str) -> Option<(u64, u64)> {
    let mut counts = value.split_whitespace();
    Some((counts.next()?.parse().ok()?, counts.next()?.parse().ok()?))
}

fn epoch_age_days(epoch: u64) -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH + Duration::from_secs(epoch))
        .map(|duration| duration.as_secs() / 86_400)
        .unwrap_or(0)
}

fn short_hash(hash: &str) -> String {
    hash.chars().take(12).collect()
}

fn evidence_path(finding: &Finding, label: &str) -> Option<PathBuf> {
    finding
        .evidence
        .iter()
        .find(|entry| entry.label == label)
        .map(|entry| PathBuf::from(&entry.value))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_nul_delimited_worktree_porcelain() {
        let data = b"worktree /repo\0HEAD abc\0branch refs/heads/main\0\0worktree /tmp/missing\0HEAD def\0prunable gone\0\0";
        let worktrees = parse_worktrees(data);
        assert_eq!(worktrees.len(), 2);
        assert_eq!(worktrees[0].branch.as_deref(), Some("refs/heads/main"));
        assert_eq!(worktrees[1].prunable.as_deref(), Some("gone"));
    }
}
