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
