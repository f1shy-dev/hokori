//! Stable product taxonomy shared by filesystem rules, native providers, and
//! every output surface. Rule categories remain precise; sections and groups
//! keep the TUI navigable as coverage grows.

use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Section {
    QuickCleanup,
    Developer,
    Applications,
    System,
    Analysis,
}

impl Section {
    pub fn label(self) -> &'static str {
        match self {
            Self::QuickCleanup => "Quick Cleanup",
            Self::Developer => "Developer",
            Self::Applications => "Applications",
            Self::System => "System",
            Self::Analysis => "Analysis",
        }
    }

    pub fn order(self) -> u8 {
        match self {
            Self::QuickCleanup => 0,
            Self::Developer => 1,
            Self::Applications => 2,
            Self::System => 3,
            Self::Analysis => 4,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Subgroup {
    Recommended,
    Packages,
    ContainersVms,
    AppleMobile,
    Repositories,
    Toolchains,
    AiAssets,
    Ides,
    ProjectArtifacts,
    Browsers,
    Media,
    Communication,
    Cloud,
    AppCaches,
    Diagnostics,
    Storage,
    Duplicates,
    Leftovers,
}

impl Subgroup {
    pub fn label(self) -> &'static str {
        match self {
            Self::Recommended => "Recommended",
            Self::Packages => "Packages",
            Self::ContainersVms => "Containers & VMs",
            Self::AppleMobile => "Apple & Mobile",
            Self::Repositories => "Repositories",
            Self::Toolchains => "Toolchains",
            Self::AiAssets => "AI Assets",
            Self::Ides => "IDEs",
            Self::ProjectArtifacts => "Project Artifacts",
            Self::Browsers => "Browsers",
            Self::Media => "Media",
            Self::Communication => "Communication",
            Self::Cloud => "Cloud",
            Self::AppCaches => "App Caches",
            Self::Diagnostics => "Diagnostics",
            Self::Storage => "Storage",
            Self::Duplicates => "Duplicates",
            Self::Leftovers => "Leftovers",
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct CategoryInfo<'a> {
    pub id: &'a str,
    pub label: &'static str,
    pub icon: &'static str,
    pub description: &'static str,
    pub section: Section,
    pub subgroup: Subgroup,
    pub order: u16,
}

pub fn category_info(id: &str) -> CategoryInfo<'_> {
    let (label, description, section, subgroup, order) = match id {
        "package-manager-cache" => (
            "Package caches",
            "Download and package stores owned by package managers.",
            Section::Developer,
            Subgroup::Packages,
            100,
        ),
        "project-artifact" | "project-junk" | "gitignored (pick by hand)" => (
            "Project artifacts",
            "Generated dependencies, build products, and project-local caches.",
            Section::Developer,
            Subgroup::ProjectArtifacts,
            110,
        ),
        "compiler-cache" | "dev-cache" | "tool-cache" => (
            "Developer caches",
            "Compiler and developer-tool data that can be regenerated.",
            Section::Developer,
            Subgroup::ProjectArtifacts,
            120,
        ),
        "toolchain-cache" | "installed-tools" => (
            "Toolchains",
            "Installed language runtimes, SDKs, and their download caches.",
            Section::Developer,
            Subgroup::Toolchains,
            130,
        ),
        "virtualization" | "virtualization-cache" => (
            "Containers & VMs",
            "Container engines, virtual machines, images, and build cache.",
            Section::Developer,
            Subgroup::ContainersVms,
            140,
        ),
        "simulator-runtime" => (
            "Simulator runtimes",
            "Xcode simulator devices, runtime images, and generated runtime caches.",
            Section::Developer,
            Subgroup::AppleMobile,
            141,
        ),
        "android-emulator" => (
            "Android emulators",
            "Android Virtual Devices and their installed system images.",
            Section::Developer,
            Subgroup::AppleMobile,
            142,
        ),
        "ai-ml-cache" | "ai-models" => (
            "AI assets",
            "Downloaded models, datasets, revisions, and generated extensions.",
            Section::Developer,
            Subgroup::AiAssets,
            150,
        ),
        "ide-cache" | "browser-binaries" => (
            "IDEs & test runtimes",
            "IDE indexes, runtime bundles, and downloaded test browsers.",
            Section::Developer,
            Subgroup::Ides,
            160,
        ),
        "browser-cache" => (
            "Browsers",
            "Browser caches and offline web application data.",
            Section::Applications,
            Subgroup::Browsers,
            200,
        ),
        "media-cache" | "creative-cache" | "game-cache" => (
            "Media & creative apps",
            "Generated media, artwork, game, and creative-application caches.",
            Section::Applications,
            Subgroup::Media,
            210,
        ),
        "message-cache" | "communication-cache" => (
            "Communication",
            "Message previews and communication application caches.",
            Section::Applications,
            Subgroup::Communication,
            220,
        ),
        "cloud-cache" | "cloud-sync-cache" => (
            "Cloud storage",
            "Cloud-client caches and offline copies.",
            Section::Applications,
            Subgroup::Cloud,
            230,
        ),
        "app-cache" | "app-state" | "updater-cache" | "account-cache" | "ai-system-cache"
        | "maps-cache" => (
            "Application caches",
            "Application runtime, updater, account, and service caches.",
            Section::Applications,
            Subgroup::AppCaches,
            240,
        ),
        "trash" | "logs" | "system-cache" | "finder-metadata" => (
            "System cleanup",
            "Trash, logs, metadata, and ordinary system-generated files.",
            Section::QuickCleanup,
            Subgroup::Recommended,
            10,
        ),
        "installers" | "old-downloads" => (
            "Old downloads",
            "Old installers and archives that are often safe to discard.",
            Section::QuickCleanup,
            Subgroup::Recommended,
            20,
        ),
        "backups" | "device-firmware" | "mail-attachments" => (
            "Apple storage",
            "Backups, device support, firmware, and downloaded attachments.",
            Section::System,
            Subgroup::AppleMobile,
            300,
        ),
        "diagnostic-artifact" | "large-old-files" => (
            "Diagnostics & large files",
            "Crash data, heap dumps, and unusually large old files.",
            Section::Analysis,
            Subgroup::Diagnostics,
            400,
        ),
        "tagged-cache" => (
            "Tagged caches",
            "Owner-declared cache directories requiring manual review.",
            Section::Analysis,
            Subgroup::Storage,
            410,
        ),
        _ => (
            "Other findings",
            "Findings that do not yet have a dedicated product category.",
            Section::Analysis,
            Subgroup::Storage,
            999,
        ),
    };
    let icon = match subgroup {
        Subgroup::Recommended => "*",
        Subgroup::Packages => "P",
        Subgroup::ContainersVms => "V",
        Subgroup::AppleMobile => "A",
        Subgroup::Repositories => "G",
        Subgroup::Toolchains => "T",
        Subgroup::AiAssets => "M",
        Subgroup::Ides => "I",
        Subgroup::ProjectArtifacts => "B",
        Subgroup::Browsers => "W",
        Subgroup::Media => "C",
        Subgroup::Communication => "@",
        Subgroup::Cloud => "^",
        Subgroup::AppCaches => "C",
        Subgroup::Diagnostics => "!",
        Subgroup::Storage => "D",
        Subgroup::Duplicates => "=",
        Subgroup::Leftovers => "?",
    };
    CategoryInfo {
        id,
        label,
        icon,
        description,
        section,
        subgroup,
        order,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn developer_categories_are_grouped_under_developer() {
        let info = category_info("package-manager-cache");
        assert_eq!(info.section, Section::Developer);
        assert_eq!(info.subgroup, Subgroup::Packages);
    }

    #[test]
    fn narrow_apple_cache_categories_are_consolidated() {
        for category in ["maps-cache", "message-cache", "account-cache"] {
            assert_ne!(category_info(category).label, category);
        }
    }
}
