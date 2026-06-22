# Rule provenance

Hokori rule definitions are independently authored. External projects and
documentation are used to validate cache locations, cleanup semantics, and
safety exclusions; their source files are not vendored.

## Primary documentation

- pip cache: https://pip.pypa.io/en/stable/cli/pip_cache/
- uv cache: https://docs.astral.sh/uv/concepts/cache/
- npm cache: https://docs.npmjs.com/cli/commands/npm-cache/
- Corepack cache: https://github.com/nodejs/corepack/blob/main/README.md
- Go build/module caches: https://go.dev/src/cmd/go/internal/clean/clean.go
- Composer cache: https://getcomposer.org/doc/03-cli.md#clear-cache-clearcache-cc
- Conda cache: https://docs.conda.io/projects/conda/en/stable/commands/clean.html
- NuGet caches: https://learn.microsoft.com/dotnet/core/tools/dotnet-nuget-locals
- CocoaPods cache location: https://guides.cocoapods.org/using/faq.html
- Apple cache-directory semantics:
  https://developer.apple.com/documentation/foundation/using-the-file-system-effectively
- Apple CloudKit overview: https://developer.apple.com/documentation/cloudkit
- Cache Directory Tagging Specification: https://bford.info/cachedir/
- uv installed-tool semantics: https://docs.astral.sh/uv/concepts/tools/
- uv persistent storage layout: https://docs.astral.sh/uv/reference/storage/
- pipx tool and run environments: https://pipx.pypa.io/stable/docs/
- Homebrew cleanup/autoremove implementation:
  https://github.com/Homebrew/brew/tree/master/Library/Homebrew
- Docker disk usage and pruning:
  https://docs.docker.com/reference/cli/docker/system/df/
- Git worktree porcelain and pruning:
  https://git-scm.com/docs/git-worktree
- Git LFS pruning:
  https://github.com/git-lfs/git-lfs/blob/main/docs/man/git-lfs-prune.adoc
- mise pruning:
  https://mise.jdx.dev/cli/prune.html
- Hugging Face cache management:
  https://huggingface.co/docs/huggingface_hub/guides/manage-cache
- Android SDK and AVD management:
  https://developer.android.com/tools/sdkmanager
  and https://developer.android.com/tools/avdmanager
- Lima instance management: https://lima-vm.io/docs/reference/limactl/
- Nix garbage collection:
  https://nix.dev/manual/nix/latest/command-ref/new-cli/nix3-store-gc

## Cross-check projects

- PureMac (MIT): https://github.com/momenbasel/PureMac
- mac-cleanup-py (Apache-2.0): https://github.com/mac-cleanup/mac-cleanup-py
- Mike's macOS developer cleanup (MIT):
  https://github.com/cunneen/mikes-macos-developer-disk-cleanup
- Czkawka (MIT core): https://github.com/qarmin/czkawka
- null-e (MIT) was reviewed for high-level provider/category ideas:
  https://github.com/us/null-e

Mole, CleanerML, Winapp2, and Pearcleaner were reviewed for product behavior,
negative safety lessons, and missing categories. Their rule databases are not
copied into this repository.

Before a public release, the repository itself still needs an explicit license
chosen by the project owner.

Homebrew is BSD-2-Clause. Hokori does not vendor its source or rule database;
implementations and descriptions here are independently authored against
documented behavior and local structured outputs.
