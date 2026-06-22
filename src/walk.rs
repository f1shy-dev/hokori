//! Directory listing primitives.
//!
//! One job: list a directory and return name / type / allocated size / mtime /
//! (dev, ino) per entry in as few syscalls as possible. macOS uses
//! `getattrlistbulk` (everything in one batched call per buffer); other
//! platforms fall back to std::fs.

use std::collections::{HashSet, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

#[derive(Debug, Clone)]
pub struct Entry {
    pub name: String,
    pub is_dir: bool,
    /// Allocated bytes on disk (0 for dirs).
    pub bytes: u64,
    /// Unix seconds.
    pub mtime: i64,
    pub dev: u64,
    pub ino: u64,
}

/// Sharded (dev, ino) set so hardlinked files are counted once per scan.
pub struct InodeDedupe {
    shards: Vec<std::sync::Mutex<InodeShard>>,
}

struct InodeShard {
    seen: HashSet<u128>,
    order: VecDeque<u128>,
    limit: usize,
}

impl InodeDedupe {
    pub fn new() -> Self {
        const SHARDS: usize = 128;
        const MAX_ENTRIES: usize = 1_048_576;
        let per_shard = (MAX_ENTRIES / SHARDS).max(1);
        Self {
            shards: (0..SHARDS)
                .map(|_| std::sync::Mutex::new(InodeShard::new(per_shard)))
                .collect(),
        }
    }

    /// Returns `bytes` the first time a (dev, ino) pair is seen, 0 after.
    pub fn dedup(&self, dev: u64, ino: u64, bytes: u64) -> u64 {
        if ino == 0 {
            return bytes;
        }
        let key = ((dev as u128) << 64) | ino as u128;
        let shard = &self.shards[((key >> 8) % self.shards.len() as u128) as usize];
        let mut shard = shard.lock().expect("inode shard poisoned");
        shard.dedup(key, bytes)
    }
}

impl InodeShard {
    fn new(limit: usize) -> Self {
        Self {
            seen: HashSet::new(),
            order: VecDeque::new(),
            limit,
        }
    }

    fn dedup(&mut self, key: u128, bytes: u64) -> u64 {
        if !self.seen.insert(key) {
            return 0;
        }
        self.order.push_back(key);
        while self.seen.len() > self.limit {
            if let Some(oldest) = self.order.pop_front() {
                self.seen.remove(&oldest);
            } else {
                break;
            }
        }
        bytes
    }
}

/// Mounted filesystems nested under a discovery root. A home-directory scan
/// should not walk device images, network shares, or virtual filesystems just
/// because they happen to be mounted below `$HOME`.
pub fn nested_mount_points(roots: &[PathBuf]) -> HashSet<PathBuf> {
    platform_mount_points()
        .into_iter()
        .filter(|mount| {
            roots
                .iter()
                .any(|root| mount != root && mount.starts_with(root))
        })
        .collect()
}

#[cfg(target_os = "macos")]
fn platform_mount_points() -> Vec<PathBuf> {
    use std::ffi::CStr;
    use std::os::unix::ffi::OsStrExt;

    let mut mounts = std::ptr::null_mut();
    let count = unsafe { libc::getmntinfo(&mut mounts, libc::MNT_NOWAIT) };
    if count <= 0 || mounts.is_null() {
        return Vec::new();
    }
    let stats = unsafe { std::slice::from_raw_parts(mounts, count as usize) };
    stats
        .iter()
        .filter_map(|stat| {
            let path = unsafe { CStr::from_ptr(stat.f_mntonname.as_ptr()) };
            if path.to_bytes().is_empty() {
                None
            } else {
                Some(PathBuf::from(std::ffi::OsStr::from_bytes(path.to_bytes())))
            }
        })
        .collect()
}

#[cfg(not(target_os = "macos"))]
fn platform_mount_points() -> Vec<PathBuf> {
    Vec::new()
}

#[cfg(target_os = "macos")]
pub use macos::list_dir;

#[cfg(not(target_os = "macos"))]
pub use portable::list_dir;

#[cfg(target_os = "macos")]
mod macos {
    use super::Entry;
    use std::ffi::CString;
    use std::fmt;
    use std::os::unix::ffi::OsStrExt;
    use std::path::Path;

    // Not exposed by the libc crate.
    const ATTR_CMN_ERROR: u32 = 0x2000_0000;
    const VDIR: u32 = 2;
    const INITIAL_BULK_BUFFER: usize = 128 * 1024;
    const MAX_BULK_BUFFER: usize = 1024 * 1024;

    /// Use the bulk syscall when the filesystem supports this attribute set,
    /// otherwise restart the listing through std::fs.
    pub fn list_dir(path: &Path) -> Option<Vec<Entry>> {
        match list_dir_bulk(path) {
            Ok(entries) => Some(entries),
            Err(BulkFailure::Open) => super::portable::list_dir(path),
            Err(error) => {
                if std::env::var_os("HOKORI_TRACE_WALK").is_some() {
                    eprintln!(
                        "hokori: getattrlistbulk fallback for {}: {error}",
                        path.display()
                    );
                }
                super::portable::list_dir(path)
            }
        }
    }

    fn list_dir_bulk(path: &Path) -> Result<Vec<Entry>, BulkFailure> {
        let c_path =
            CString::new(path.as_os_str().as_bytes()).map_err(|_| BulkFailure::Malformed)?;
        let dirfd = unsafe {
            libc::open(
                c_path.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        };
        if dirfd == -1 {
            return Err(BulkFailure::Open);
        }
        let dirfd = OwnedFd(dirfd);

        let mut attrlist = libc::attrlist {
            bitmapcount: libc::ATTR_BIT_MAP_COUNT,
            reserved: 0,
            commonattr: libc::ATTR_CMN_RETURNED_ATTRS
                | libc::ATTR_CMN_NAME
                | ATTR_CMN_ERROR
                | libc::ATTR_CMN_DEVID
                | libc::ATTR_CMN_OBJTYPE
                | libc::ATTR_CMN_MODTIME
                | libc::ATTR_CMN_FILEID,
            volattr: 0,
            dirattr: 0,
            fileattr: libc::ATTR_FILE_ALLOCSIZE,
            forkattr: 0,
        };

        let mut buf = vec![0u8; INITIAL_BULK_BUFFER];
        let mut entries = Vec::new();

        loop {
            let retcount = unsafe {
                libc::getattrlistbulk(
                    dirfd.0,
                    &mut attrlist as *mut libc::attrlist as *mut libc::c_void,
                    buf.as_mut_ptr() as *mut libc::c_void,
                    buf.len(),
                    0,
                )
            };
            if retcount < 0 {
                let err = std::io::Error::last_os_error();
                if let Some(next_len) = next_bulk_buffer_len(err.raw_os_error(), buf.len()) {
                    buf.resize(next_len, 0);
                    continue;
                }
                return Err(BulkFailure::Io(err));
            }
            if retcount == 0 {
                break;
            }

            let mut batch =
                parse_bulk_entries(&buf, retcount as usize).ok_or(BulkFailure::Malformed)?;
            entries.append(&mut batch);
        }

        Ok(entries)
    }

    pub(super) fn next_bulk_buffer_len(errno: Option<i32>, current: usize) -> Option<usize> {
        if errno != Some(libc::ERANGE) || current >= MAX_BULK_BUFFER {
            return None;
        }
        Some(current.saturating_mul(2).min(MAX_BULK_BUFFER))
    }

    fn parse_bulk_entries(buf: &[u8], count: usize) -> Option<Vec<Entry>> {
        let mut entries = Vec::with_capacity(count);
        let mut offset = 0usize;
        for _ in 0..count {
            let entry_len = read_at::<u32>(buf, offset)? as usize;
            let end = offset.checked_add(entry_len)?;
            let record = buf.get(offset..end)?;
            if let Some(entry) = parse_bulk_entry(record)? {
                entries.push(entry);
            }
            offset = end;
        }
        Some(entries)
    }

    fn parse_bulk_entry(record: &[u8]) -> Option<Option<Entry>> {
        let mut field = std::mem::size_of::<u32>();
        let returned = read_next::<libc::attribute_set_t>(record, &mut field)?;

        // macOS currently packs ATTR_CMN_ERROR after the name reference for
        // this request. Bounds checks make a different layout fail closed and
        // restart through the portable backend.
        let name = if returned.commonattr & libc::ATTR_CMN_NAME != 0 {
            let reference_offset = field;
            let name_info = read_next::<libc::attrreference_t>(record, &mut field)?;
            parse_name(record, reference_offset, name_info)
        } else {
            None
        };

        if returned.commonattr & ATTR_CMN_ERROR != 0 {
            let error_code = read_next::<u32>(record, &mut field)?;
            if error_code != 0 {
                return Some(None);
            }
        }

        let dev = if returned.commonattr & libc::ATTR_CMN_DEVID != 0 {
            read_next::<i32>(record, &mut field)? as u32 as u64
        } else {
            0
        };
        let obj_type = if returned.commonattr & libc::ATTR_CMN_OBJTYPE != 0 {
            read_next::<u32>(record, &mut field)?
        } else {
            0
        };
        let mtime = if returned.commonattr & libc::ATTR_CMN_MODTIME != 0 {
            read_next::<libc::timespec>(record, &mut field)?.tv_sec as i64
        } else {
            0
        };
        let ino = if returned.commonattr & libc::ATTR_CMN_FILEID != 0 {
            read_next::<u64>(record, &mut field)?
        } else {
            0
        };
        let bytes = if returned.fileattr & libc::ATTR_FILE_ALLOCSIZE != 0 {
            read_next::<i64>(record, &mut field)?.max(0) as u64
        } else {
            0
        };

        let Some(name) = name else {
            return Some(None);
        };
        if name == "." || name == ".." {
            return Some(None);
        }
        Some(Some(Entry {
            name,
            is_dir: obj_type == VDIR,
            bytes,
            mtime,
            dev,
            ino,
        }))
    }

    fn parse_name(
        record: &[u8],
        reference_offset: usize,
        name_info: libc::attrreference_t,
    ) -> Option<String> {
        if name_info.attr_length == 0 {
            return None;
        }
        let start = i64::try_from(reference_offset)
            .ok()?
            .checked_add(i64::from(name_info.attr_dataoffset))?;
        let start = usize::try_from(start).ok()?;
        let end = start.checked_add(name_info.attr_length as usize)?;
        let bytes = record.get(start..end)?.strip_suffix(&[0])?;
        std::str::from_utf8(bytes).ok().map(str::to_owned)
    }

    fn read_next<T: Copy>(bytes: &[u8], offset: &mut usize) -> Option<T> {
        let value = read_at(bytes, *offset)?;
        *offset = (*offset).checked_add(std::mem::size_of::<T>())?;
        Some(value)
    }

    fn read_at<T: Copy>(bytes: &[u8], offset: usize) -> Option<T> {
        let end = offset.checked_add(std::mem::size_of::<T>())?;
        let source = bytes.get(offset..end)?;
        Some(unsafe { std::ptr::read_unaligned(source.as_ptr().cast::<T>()) })
    }

    struct OwnedFd(i32);

    impl Drop for OwnedFd {
        fn drop(&mut self) {
            unsafe {
                libc::close(self.0);
            }
        }
    }

    enum BulkFailure {
        Open,
        Io(std::io::Error),
        Malformed,
    }

    impl fmt::Display for BulkFailure {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                Self::Open => f.write_str("directory could not be opened"),
                Self::Io(error) => error.fmt(f),
                Self::Malformed => f.write_str("malformed attribute record"),
            }
        }
    }
}

mod portable {
    use super::Entry;
    use std::path::Path;

    pub fn list_dir(path: &Path) -> Option<Vec<Entry>> {
        let read = std::fs::read_dir(path).ok()?;
        let mut entries = Vec::new();
        for item in read.flatten() {
            let Ok(meta) = item.metadata() else { continue };
            let file_type = meta.file_type();
            if file_type.is_symlink() {
                continue;
            }
            let name = item.file_name().to_string_lossy().to_string();
            let mtime = meta
                .modified()
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0);
            #[cfg(unix)]
            let (bytes, dev, ino) = {
                use std::os::unix::fs::MetadataExt;
                (meta.blocks() * 512, meta.dev(), meta.ino())
            };
            #[cfg(not(unix))]
            let (bytes, dev, ino) = (meta.len(), 0u64, 0u64);
            entries.push(Entry {
                name,
                is_dir: file_type.is_dir(),
                bytes: if file_type.is_dir() { 0 } else { bytes },
                mtime,
                dev,
                ino,
            });
        }
        Some(entries)
    }
}

/// Parallel subtree sizing: pure descent, no matching. Used for claimed
/// subtrees and targeted roots.
#[derive(Debug, Default, Clone, Copy)]
pub struct SubtreeStats {
    pub bytes: u64,
    pub files: u64,
    pub dirs: u64,
    pub newest_mtime: i64,
}

impl SubtreeStats {
    pub fn merge(mut self, other: SubtreeStats) -> SubtreeStats {
        self.bytes += other.bytes;
        self.files += other.files;
        self.dirs += other.dirs;
        self.newest_mtime = self.newest_mtime.max(other.newest_mtime);
        self
    }
}

pub fn size_subtree_cancellable(
    path: &Path,
    dedupe: &InodeDedupe,
    progress: Option<&crate::report::Progress>,
    cancel: Option<&AtomicBool>,
) -> SubtreeStats {
    size_subtree_inner(path, dedupe, progress, cancel)
}

fn size_subtree_inner(
    path: &Path,
    dedupe: &InodeDedupe,
    progress: Option<&crate::report::Progress>,
    cancel: Option<&AtomicBool>,
) -> SubtreeStats {
    use rayon::prelude::*;

    if cancel
        .map(|cancel| cancel.load(Ordering::Relaxed))
        .unwrap_or(false)
    {
        return SubtreeStats::default();
    }

    let Some(entries) = list_dir(path) else {
        return SubtreeStats::default();
    };

    let mut stats = SubtreeStats::default();
    let mut subdirs: Vec<String> = Vec::new();
    for entry in &entries {
        if cancel
            .map(|cancel| cancel.load(Ordering::Relaxed))
            .unwrap_or(false)
        {
            return stats;
        }
        stats.newest_mtime = stats.newest_mtime.max(entry.mtime);
        if entry.is_dir {
            stats.dirs += 1;
            subdirs.push(entry.name.clone());
        } else {
            stats.files += 1;
            stats.bytes += dedupe.dedup(entry.dev, entry.ino, entry.bytes);
        }
    }
    if let Some(progress) = progress {
        progress.add(stats.files, stats.dirs, stats.bytes);
    }

    let child_stats = subdirs
        .par_iter()
        .map(|name| size_subtree_inner(&path.join(name), dedupe, progress, cancel))
        .reduce(SubtreeStats::default, SubtreeStats::merge);

    stats.merge(child_stats)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The bulk listing must agree with std::fs metadata on every field —
    /// this guards the attribute packing order in the macOS backend.
    #[test]
    fn list_dir_matches_std_fs() {
        let dir = std::env::temp_dir().join("hokori-walk-test");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("subdir")).unwrap();
        std::fs::write(dir.join("file.txt"), vec![0u8; 10_000]).unwrap();

        let entries = list_dir(&dir).expect("list_dir failed");
        assert_eq!(entries.len(), 2);
        for entry in &entries {
            let meta = std::fs::symlink_metadata(dir.join(&entry.name)).unwrap();
            assert_eq!(entry.is_dir, meta.is_dir(), "is_dir for {}", entry.name);
            let std_mtime = meta
                .modified()
                .unwrap()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64;
            assert_eq!(entry.mtime, std_mtime, "mtime for {}", entry.name);
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                assert_eq!(entry.ino, meta.ino(), "ino for {}", entry.name);
                assert_eq!(entry.dev, meta.dev() as u64, "dev for {}", entry.name);
                if !entry.is_dir {
                    assert_eq!(entry.bytes, meta.blocks() * 512, "bytes for {}", entry.name);
                }
            }
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn bulk_buffer_growth_is_bounded_and_only_for_erange() {
        use super::macos::next_bulk_buffer_len;

        assert_eq!(next_bulk_buffer_len(Some(libc::EINVAL), 128 * 1024), None);
        assert_eq!(
            next_bulk_buffer_len(Some(libc::ERANGE), 128 * 1024),
            Some(256 * 1024)
        );
        assert_eq!(next_bulk_buffer_len(Some(libc::ERANGE), 1024 * 1024), None);
    }
}
