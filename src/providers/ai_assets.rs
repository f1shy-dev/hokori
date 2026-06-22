use anyhow::{Context, Result, bail};
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use crate::report::{Confidence, Finding, FindingSize, SizeAccuracy};
use crate::rules::Safety;
use crate::taxonomy::{Section, Subgroup};
use crate::walk::{InodeDedupe, size_subtree_cancellable};

use super::command::{CommandMode, CommandPolicy, safe_absolute_path, safe_token};
use super::{
    Capability, Provider, ProviderContext, ProviderExecution, ProviderExecutionOptions,
    ProviderFinding, ProviderMetadata, Revalidation, ScanCost, physical_file_size,
};

pub struct AiAssetsProvider;

const HF_EXECUTABLES: &[&str] = &["/opt/homebrew/bin/hf", "hf"];
const OLLAMA_EXECUTABLES: &[&str] = &[
    "/Applications/Ollama.app/Contents/Resources/ollama",
    "/usr/local/bin/ollama",
    "/opt/homebrew/bin/ollama",
    "ollama",
];

const HF_PRUNE_DRY: CommandPolicy = CommandPolicy {
    id: "hf-cache-prune-preview",
    executables: HF_EXECUTABLES,
    mutating: false,
    network: false,
    validate_args: args_hf_prune_dry,
};
const HF_PRUNE: CommandPolicy = CommandPolicy {
    id: "hf-cache-prune",
    executables: HF_EXECUTABLES,
    mutating: true,
    network: false,
    validate_args: args_hf_prune,
};
const HF_REMOVE: CommandPolicy = CommandPolicy {
    id: "hf-cache-remove",
    executables: HF_EXECUTABLES,
    mutating: true,
    network: false,
    validate_args: args_hf_remove,
};
const OLLAMA_PS: CommandPolicy = CommandPolicy {
    id: "ollama-ps",
    executables: OLLAMA_EXECUTABLES,
    mutating: false,
    network: false,
    validate_args: args_ollama_ps,
};
const OLLAMA_REMOVE: CommandPolicy = CommandPolicy {
    id: "ollama-remove",
    executables: OLLAMA_EXECUTABLES,
    mutating: true,
    network: false,
    validate_args: args_ollama_remove,
};

fn args_hf_prune_dry(args: &[OsString]) -> bool {
    args.len() == 6
        && args[0] == "cache"
        && args[1] == "prune"
        && args[2] == "--dry-run"
        && args[3] == "--cache-dir"
        && safe_absolute_path(&args[4])
        && args[5] == "--yes"
}

fn args_hf_prune(args: &[OsString]) -> bool {
    args.len() == 5
        && args[0] == "cache"
        && args[1] == "prune"
        && args[2] == "--cache-dir"
        && safe_absolute_path(&args[3])
        && args[4] == "--yes"
}

fn args_hf_remove(args: &[OsString]) -> bool {
    args.len() == 6
        && args[0] == "cache"
        && args[1] == "rm"
        && safe_token(&args[2])
        && args[3] == "--cache-dir"
        && safe_absolute_path(&args[4])
        && args[5] == "--yes"
}

fn args_ollama_ps(args: &[OsString]) -> bool {
    args == [OsStr::new("ps")]
}

fn args_ollama_remove(args: &[OsString]) -> bool {
    args.len() == 2 && args[0] == "rm" && safe_token(&args[1])
}

impl Provider for AiAssetsProvider {
    fn metadata(&self) -> ProviderMetadata {
        metadata()
    }

    fn probe(&self, context: &ProviderContext) -> Capability {
        let roots = asset_roots(context);
        if roots.iter().any(|path| path.exists())
            || context.runner.resolve(HF_PRUNE_DRY).is_some()
            || context.runner.resolve(OLLAMA_PS).is_some()
        {
            Capability::Available
        } else {
            Capability::Unavailable("No supported local AI asset store was found.".into())
        }
    }

    fn scan(&self, context: &ProviderContext) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        if let Some(hub) = huggingface_hub(context) {
            findings.extend(huggingface_findings(context, &hub));
        }
        if let Some(models) = ollama_models_root(context) {
            findings.extend(ollama_findings(context, &models));
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
                "Model references or running state changed since the scan.".into(),
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
            .context("AI asset action missing")?;
        match action.action_id.as_str() {
            "hf-prune-detached" => {
                let cache = evidence_path(finding, "Cache").context("HF cache path missing")?;
                run_mutation(
                    context,
                    HF_PRUNE,
                    &[
                        "cache".into(),
                        "prune".into(),
                        "--cache-dir".into(),
                        cache.into_os_string(),
                        "--yes".into(),
                    ],
                )?;
            }
            "hf-remove-repository" => {
                let cache = evidence_path(finding, "Cache").context("HF cache path missing")?;
                run_mutation(
                    context,
                    HF_REMOVE,
                    &[
                        "cache".into(),
                        "rm".into(),
                        action.object_id.clone().into(),
                        "--cache-dir".into(),
                        cache.into_os_string(),
                        "--yes".into(),
                    ],
                )?;
            }
            "ollama-remove-model" => {
                run_mutation(
                    context,
                    OLLAMA_REMOVE,
                    &["rm".into(), action.object_id.clone().into()],
                )?;
            }
            _ => bail!("unknown AI asset action {}", action.action_id),
        }
        Ok(ProviderExecution {
            deleted: 1,
            freed_bytes: finding.bytes,
            message: format!("Removed AI asset {}.", action.object_id),
        })
    }
}

fn metadata() -> ProviderMetadata {
    ProviderMetadata {
        id: "ai-assets",
        name: "AI models and datasets",
        section: Section::Developer,
        subgroup: Subgroup::AiAssets,
        cost: ScanCost::Moderate,
        quick: true,
        deep: true,
        network_in_deep_scan: false,
        supersedes_rules: &["huggingface-cache", "ollama-models"],
    }
}

fn asset_roots(context: &ProviderContext) -> Vec<PathBuf> {
    let Some(home) = &context.home else {
        return Vec::new();
    };
    vec![
        home.join(".cache/huggingface"),
        home.join(".ollama/models"),
        home.join(".cache/lm-studio"),
        home.join(".lmstudio/models"),
        home.join("Library/Application Support/nomic.ai/GPT4All"),
    ]
}

fn huggingface_hub(context: &ProviderContext) -> Option<PathBuf> {
    if let Some(root) = std::env::var_os("HF_HOME") {
        let hub = PathBuf::from(root).join("hub");
        if hub.is_dir() {
            return Some(hub);
        }
    }
    context
        .home
        .as_ref()
        .map(|home| home.join(".cache/huggingface/hub"))
        .filter(|path| path.is_dir())
}

fn huggingface_findings(context: &ProviderContext, hub: &Path) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut detached_paths = Vec::new();
    let mut detached_blobs = HashSet::new();
    let mut retained_blobs = HashSet::new();
    let mut detached_repos = Vec::new();
    let Ok(entries) = hub.read_dir() else {
        return findings;
    };
    for repository in entries.flatten().take(10_000) {
        if context.is_cancelled() || !repository.path().is_dir() {
            break;
        }
        let repo_path = repository.path();
        let Some(repo_id) = hf_repo_id(&repository.file_name().to_string_lossy()) else {
            continue;
        };
        let refs = hf_referenced_revisions(&repo_path);
        let snapshots = repo_path.join("snapshots");
        let mut repo_detached = Vec::new();
        if let Ok(revisions) = snapshots.read_dir() {
            for revision in revisions.flatten().take(20_000) {
                if !revision.path().is_dir() {
                    continue;
                }
                let hash = revision.file_name().to_string_lossy().to_string();
                let blobs = snapshot_blobs(&revision.path());
                if refs.contains(&hash) {
                    retained_blobs.extend(blobs);
                } else {
                    detached_blobs.extend(blobs);
                    detached_paths.push(revision.path());
                    repo_detached.push(hash);
                }
            }
        }
        if !repo_detached.is_empty() {
            detached_repos.push(format!("{repo_id} ({})", repo_detached.len()));
        }

        let bytes = directory_size(&repo_path, context);
        let age = path_age_days(&repo_path);
        if bytes >= context.settings.min_size_bytes
            && age.is_some_and(|age| age >= context.settings.min_age_days)
        {
            let running = false;
            let builder = ProviderFinding::object(
                metadata(),
                "huggingface-stale-repository",
                "ai-models",
                &repo_id,
                format!("Hugging Face {repo_id}"),
                if running {
                    Safety::Protected
                } else {
                    Safety::Review
                },
                bytes,
            )
            .manual()
            .age(age, false)
            .confidence(Confidence::High)
            .reason("This cached repository has not changed inside the configured age window.")
            .evidence("Cache", hub.display().to_string())
            .evidence("Repository", &repo_id)
            .copy(
                "A locally cached Hugging Face model, dataset, or Space with all retained revisions.",
                "The repository must be downloaded again, and local modifications inside the cache are lost.",
                "Review the repository name and remote availability before removal.",
            );
            findings.push(if context.runner.resolve(HF_REMOVE).is_some() {
                builder
                    .action(
                        "hf-remove-repository",
                        vec![
                            "hf".into(),
                            "cache".into(),
                            "rm".into(),
                            repo_id,
                            "--cache-dir".into(),
                            hub.display().to_string(),
                            "--yes".into(),
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
    let unique_detached: HashSet<_> = detached_blobs
        .difference(&retained_blobs)
        .cloned()
        .collect();
    let detached_bytes: u64 = unique_detached
        .iter()
        .map(|path| physical_file_size(path))
        .sum();
    if !detached_paths.is_empty() && detached_bytes >= context.settings.min_size_bytes {
        let builder = ProviderFinding::object(
            metadata(),
            "huggingface-detached-revisions",
            "ai-ml-cache",
            "detached-revisions",
            "Detached Hugging Face revisions",
            Safety::Safe,
            detached_bytes,
        )
        .grouped_paths(detached_paths)
        .size(FindingSize {
            logical: detached_bytes,
            physical: detached_bytes,
            unique: detached_bytes,
            shared: 0,
            reclaimable: detached_bytes,
            accuracy: SizeAccuracy::Exact,
        })
        .reason("These snapshot revisions are not referenced by any local Hugging Face ref.")
        .evidence("Cache", hub.display().to_string())
        .evidence("Repositories", detached_repos.join(", "))
        .copy(
            "Detached cached revisions whose blobs are not needed by any retained revision.",
            "A detached revision must be downloaded again if referenced explicitly later.",
            "Safe to prune through Hugging Face's cache manager.",
        );
        findings.push(
            if context.runner.resolve(HF_PRUNE).is_some() && hf_prune_preview(context, hub).is_ok()
            {
                builder
                    .action(
                        "hf-prune-detached",
                        vec![
                            "hf".into(),
                            "cache".into(),
                            "prune".into(),
                            "--cache-dir".into(),
                            hub.display().to_string(),
                            "--yes".into(),
                        ],
                        true,
                        false,
                    )
                    .build()
            } else {
                builder.report_only().build()
            },
        );
    }
    findings
}

fn hf_prune_preview(context: &ProviderContext, hub: &Path) -> Result<()> {
    let args = vec![
        "cache".into(),
        "prune".into(),
        "--dry-run".into(),
        "--cache-dir".into(),
        hub.as_os_str().to_owned(),
        "--yes".into(),
    ];
    let output = context.runner.run(
        HF_PRUNE_DRY,
        &args,
        CommandMode::ReadOnly,
        Some(context.remaining(Duration::from_secs(8))),
        &context.cancel,
    )?;
    if output.status.success() {
        Ok(())
    } else {
        bail!("hf cache prune preview failed")
    }
}

fn hf_referenced_revisions(repository: &Path) -> HashSet<String> {
    let mut revisions = HashSet::new();
    collect_ref_values(&repository.join("refs"), &mut revisions, 0);
    revisions
}

fn collect_ref_values(directory: &Path, revisions: &mut HashSet<String>, depth: usize) {
    if depth > 8 {
        return;
    }
    let Ok(entries) = directory.read_dir() else {
        return;
    };
    for entry in entries.flatten().take(20_000) {
        if entry.path().is_dir() {
            collect_ref_values(&entry.path(), revisions, depth + 1);
        } else if let Ok(value) = std::fs::read_to_string(entry.path()) {
            let value = value.trim();
            if !value.is_empty() {
                revisions.insert(value.to_string());
            }
        }
    }
}

fn snapshot_blobs(snapshot: &Path) -> HashSet<PathBuf> {
    let mut blobs = HashSet::new();
    collect_snapshot_blobs(snapshot, &mut blobs, 0);
    blobs
}

fn collect_snapshot_blobs(directory: &Path, blobs: &mut HashSet<PathBuf>, depth: usize) {
    if depth > 32 {
        return;
    }
    let Ok(entries) = directory.read_dir() else {
        return;
    };
    for entry in entries.flatten().take(100_000) {
        let path = entry.path();
        let Ok(metadata) = path.symlink_metadata() else {
            continue;
        };
        if metadata.is_dir() {
            collect_snapshot_blobs(&path, blobs, depth + 1);
        } else if metadata.file_type().is_symlink()
            && let Ok(target) = path.canonicalize()
        {
            blobs.insert(target);
        }
    }
}

fn hf_repo_id(directory: &str) -> Option<String> {
    let (prefix, name) = directory.split_once("--")?;
    let kind = match prefix {
        "models" => "model",
        "datasets" => "dataset",
        "spaces" => "space",
        _ => return None,
    };
    Some(format!("{kind}/{}", name.replace("--", "/")))
}

#[derive(Debug)]
struct OllamaModel {
    name: String,
    manifest: PathBuf,
    blobs: HashSet<PathBuf>,
    age_days: Option<u64>,
}

fn ollama_models_root(context: &ProviderContext) -> Option<PathBuf> {
    context
        .home
        .as_ref()
        .map(|home| home.join(".ollama/models"))
        .filter(|path| path.is_dir())
}

fn ollama_findings(context: &ProviderContext, root: &Path) -> Vec<Finding> {
    let models = read_ollama_models(root);
    if models.is_empty() {
        return Vec::new();
    }
    let running = ollama_running_models(context);
    let mut owners = HashMap::<PathBuf, usize>::new();
    for model in &models {
        for blob in &model.blobs {
            *owners.entry(blob.clone()).or_default() += 1;
        }
    }
    models
        .into_iter()
        .filter_map(|model| {
            let unique: u64 = model
                .blobs
                .iter()
                .filter(|blob| owners.get(*blob) == Some(&1))
                .map(|blob| physical_file_size(blob))
                .sum();
            let shared: u64 = model
                .blobs
                .iter()
                .filter(|blob| owners.get(*blob).is_some_and(|count| *count > 1))
                .map(|blob| physical_file_size(blob))
                .sum();
            if unique < context.settings.min_size_bytes
                || model
                    .age_days
                    .is_none_or(|age| age < context.settings.min_age_days)
            {
                return None;
            }
            let is_running = running.contains(&model.name);
            let builder = ProviderFinding::object(
                metadata(),
                "ollama-stale-model",
                "ai-models",
                &model.name,
                format!("Ollama {}", model.name),
                if is_running {
                    Safety::Protected
                } else {
                    Safety::Review
                },
                unique,
            )
            .size(FindingSize {
                logical: unique.saturating_add(shared),
                physical: unique.saturating_add(shared),
                unique,
                shared,
                reclaimable: unique,
                accuracy: SizeAccuracy::Exact,
            })
            .age(model.age_days, false)
            .manual()
            .confidence(Confidence::High)
            .reason(if is_running {
                "Ollama currently reports this model as loaded."
            } else {
                "The model manifest is older than the configured age threshold."
            })
            .evidence("Manifest", model.manifest.display().to_string())
            .evidence("Shared blob bytes", shared.to_string())
            .copy(
                "A locally installed Ollama model and the blob layers unique to it.",
                "The model must be downloaded again before it can run.",
                if is_running {
                    "Stop the running model before removal."
                } else {
                    "Remove through Ollama so its manifest and shared layers remain consistent."
                },
            );
            Some(if is_running {
                builder.protected().build()
            } else if context.runner.resolve(OLLAMA_REMOVE).is_some() {
                builder
                    .action(
                        "ollama-remove-model",
                        vec!["ollama".into(), "rm".into(), model.name],
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

fn read_ollama_models(root: &Path) -> Vec<OllamaModel> {
    let manifests = root.join("manifests");
    let blobs_root = root.join("blobs");
    let mut files = Vec::new();
    collect_manifest_files(&manifests, &mut files, 0);
    files
        .into_iter()
        .filter_map(|manifest| {
            let contents = std::fs::read_to_string(&manifest).ok()?;
            let json: Value = serde_json::from_str(&contents).ok()?;
            let mut blobs = HashSet::new();
            if let Some(digest) = json.pointer("/config/digest").and_then(Value::as_str) {
                blobs.insert(blobs_root.join(digest.replace(':', "-")));
            }
            for layer in json
                .get("layers")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                if let Some(digest) = layer.get("digest").and_then(Value::as_str) {
                    blobs.insert(blobs_root.join(digest.replace(':', "-")));
                }
            }
            let relative = manifest.strip_prefix(&manifests).ok()?;
            let components: Vec<_> = relative
                .components()
                .map(|component| component.as_os_str().to_string_lossy())
                .collect();
            let name = if components.len() >= 3 {
                format!(
                    "{}/{}:{}",
                    components[components.len() - 3],
                    components[components.len() - 2],
                    components[components.len() - 1]
                )
            } else {
                relative.to_string_lossy().replace('/', ":")
            };
            Some(OllamaModel {
                name,
                age_days: path_age_days(&manifest),
                manifest,
                blobs,
            })
        })
        .collect()
}

fn collect_manifest_files(directory: &Path, files: &mut Vec<PathBuf>, depth: usize) {
    if depth > 8 || files.len() >= 20_000 {
        return;
    }
    let Ok(entries) = directory.read_dir() else {
        return;
    };
    for entry in entries.flatten() {
        if entry.path().is_dir() {
            collect_manifest_files(&entry.path(), files, depth + 1);
        } else {
            files.push(entry.path());
        }
    }
}

fn ollama_running_models(context: &ProviderContext) -> HashSet<String> {
    let Some(_) = context.runner.resolve(OLLAMA_PS) else {
        return HashSet::new();
    };
    let args = [OsString::from("ps")];
    context
        .runner
        .run(
            OLLAMA_PS,
            &args,
            CommandMode::ReadOnly,
            Some(context.remaining(Duration::from_secs(3))),
            &context.cancel,
        )
        .ok()
        .filter(|output| output.status.success())
        .map(|output| {
            output
                .stdout
                .lines()
                .skip(1)
                .filter_map(|line| line.split_whitespace().next())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

fn run_mutation(context: &ProviderContext, policy: CommandPolicy, args: &[OsString]) -> Result<()> {
    let output = context.runner.run(
        policy,
        args,
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

fn evidence_path(finding: &Finding, label: &str) -> Option<PathBuf> {
    finding
        .evidence
        .iter()
        .find(|entry| entry.label == label)
        .map(|entry| PathBuf::from(&entry.value))
}
