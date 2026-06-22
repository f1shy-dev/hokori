use std::path::PathBuf;

pub fn home_dir() -> Option<PathBuf> {
    for var in ["HOME", "USERPROFILE"] {
        if let Ok(home) = std::env::var(var)
            && !home.is_empty()
        {
            return Some(PathBuf::from(home));
        }
    }
    None
}

pub fn running_commands() -> Vec<String> {
    let Ok(output) = std::process::Command::new("ps")
        .args(["-axo", "command="])
        .output()
    else {
        return Vec::new();
    };
    if !output.status.success() {
        return Vec::new();
    }
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(|line| line.trim().to_lowercase())
        .filter(|line| !line.is_empty())
        .collect()
}
