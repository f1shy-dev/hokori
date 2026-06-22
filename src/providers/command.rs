//! Bounded subprocess execution for provider probes, scans, revalidation, and
//! native cleanup. Providers declare static command policies; callers cannot
//! pass a shell command or bypass argument validation.

use anyhow::{Context, Result, bail};
use std::ffi::{OsStr, OsString};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

pub const MAX_STDOUT_BYTES: usize = 1 << 20;
pub const MAX_STDERR_BYTES: usize = 256 << 10;
pub const MAX_LINE_BYTES: usize = 64 << 10;
pub const MAX_PARSED_ITEMS: usize = 20_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommandMode {
    ReadOnly,
    Mutation,
}

#[derive(Clone, Copy)]
pub struct CommandPolicy {
    pub id: &'static str,
    pub executables: &'static [&'static str],
    pub mutating: bool,
    pub network: bool,
    pub validate_args: fn(&[OsString]) -> bool,
}

impl std::fmt::Debug for CommandPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CommandPolicy")
            .field("id", &self.id)
            .field("executables", &self.executables)
            .field("mutating", &self.mutating)
            .field("network", &self.network)
            .finish_non_exhaustive()
    }
}

#[allow(dead_code)]
#[derive(Debug)]
pub struct CommandOutput {
    pub executable: PathBuf,
    pub status: ExitStatus,
    pub stdout: String,
    pub stderr: String,
    pub stdout_truncated: bool,
    pub stderr_truncated: bool,
    pub elapsed: Duration,
}

#[derive(Debug, Clone)]
pub struct CommandRunner {
    home: Option<PathBuf>,
    path: OsString,
    default_timeout: Duration,
}

impl CommandRunner {
    pub fn new(home: Option<PathBuf>) -> Self {
        Self {
            home,
            path: std::env::var_os("PATH").unwrap_or_default(),
            default_timeout: Duration::from_secs(5),
        }
    }

    #[cfg(test)]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.default_timeout = timeout;
        self
    }

    pub fn resolve(&self, policy: CommandPolicy) -> Option<PathBuf> {
        policy
            .executables
            .iter()
            .find_map(|candidate| resolve_candidate(candidate, &self.path, self.home.as_deref()))
    }

    pub fn run(
        &self,
        policy: CommandPolicy,
        args: &[OsString],
        mode: CommandMode,
        timeout: Option<Duration>,
        cancel: &Arc<AtomicBool>,
    ) -> Result<CommandOutput> {
        if policy.mutating && mode != CommandMode::Mutation {
            bail!(
                "command policy {} is mutating and cannot run during discovery",
                policy.id
            );
        }
        if !policy.mutating && mode == CommandMode::Mutation {
            bail!("command policy {} is not an action", policy.id);
        }
        if !(policy.validate_args)(args) {
            bail!("arguments rejected by command policy {}", policy.id);
        }
        if cancel.load(Ordering::Relaxed) {
            bail!("command cancelled before launch");
        }

        let executable = self
            .resolve(policy)
            .with_context(|| format!("{} is not installed", policy.executables.join(" or ")))?;
        let mut command = Command::new(&executable);
        command.args(args);
        command.stdin(Stdio::null());
        command.stdout(Stdio::piped());
        command.stderr(Stdio::piped());
        command.env_clear();
        command.env("PATH", &self.path);
        command.env("LANG", "C.UTF-8");
        command.env("LC_ALL", "C.UTF-8");
        command.env("NO_COLOR", "1");
        command.env("TERM", "dumb");
        command.env("HOMEBREW_NO_AUTO_UPDATE", "1");
        command.env("HOMEBREW_NO_ANALYTICS", "1");
        command.env("HOMEBREW_NO_ENV_HINTS", "1");
        command.env("GIT_TERMINAL_PROMPT", "0");
        if let Some(home) = &self.home {
            command.env("HOME", home);
        }
        if let Some(tmp) = std::env::var_os("TMPDIR") {
            command.env("TMPDIR", tmp);
        }
        if policy.network {
            for key in [
                "SSH_AUTH_SOCK",
                "HTTPS_PROXY",
                "HTTP_PROXY",
                "ALL_PROXY",
                "NO_PROXY",
            ] {
                if let Some(value) = std::env::var_os(key) {
                    command.env(key, value);
                }
            }
        }
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            command.process_group(0);
        }

        let started = Instant::now();
        let mut child = command
            .spawn()
            .with_context(|| format!("failed to launch {}", executable.display()))?;
        let stdout = child.stdout.take().context("stdout pipe missing")?;
        let stderr = child.stderr.take().context("stderr pipe missing")?;
        let stdout_reader = std::thread::spawn(move || read_bounded(stdout, MAX_STDOUT_BYTES));
        let stderr_reader = std::thread::spawn(move || read_bounded(stderr, MAX_STDERR_BYTES));

        let deadline = started + timeout.unwrap_or(self.default_timeout);
        let status = loop {
            if let Some(status) = child.try_wait().context("failed to poll child")? {
                break status;
            }
            if cancel.load(Ordering::Relaxed) {
                terminate_child_tree(&mut child);
                let _ = child.wait();
                let _ = stdout_reader.join();
                let _ = stderr_reader.join();
                bail!("command {} cancelled", policy.id);
            }
            if Instant::now() >= deadline {
                terminate_child_tree(&mut child);
                let _ = child.wait();
                let _ = stdout_reader.join();
                let _ = stderr_reader.join();
                bail!(
                    "command {} timed out after {} ms",
                    policy.id,
                    deadline.duration_since(started).as_millis()
                );
            }
            std::thread::sleep(Duration::from_millis(10));
        };

        let (stdout, stdout_truncated) = stdout_reader
            .join()
            .map_err(|_| anyhow::anyhow!("stdout reader panicked"))?;
        let (stderr, stderr_truncated) = stderr_reader
            .join()
            .map_err(|_| anyhow::anyhow!("stderr reader panicked"))?;
        Ok(CommandOutput {
            executable,
            status,
            stdout: normalize_output(stdout),
            stderr: normalize_output(stderr),
            stdout_truncated,
            stderr_truncated,
            elapsed: started.elapsed(),
        })
    }
}

pub fn safe_token(value: &OsStr) -> bool {
    let value = value.to_string_lossy();
    !value.is_empty()
        && value.len() <= 1024
        && !value.contains(['\0', '\n', '\r'])
        && !value.starts_with('-')
        && value != "."
        && value != ".."
}

pub fn safe_absolute_path(value: &OsStr) -> bool {
    safe_token(value) && Path::new(value).is_absolute()
}

fn resolve_candidate(candidate: &str, path: &OsStr, home: Option<&Path>) -> Option<PathBuf> {
    let candidate_path = Path::new(candidate);
    if candidate_path.is_absolute() {
        return candidate_path
            .is_file()
            .then(|| candidate_path.to_path_buf());
    }
    let from_path = std::env::split_paths(path)
        .map(|dir| dir.join(candidate))
        .find(|path| path.is_file());
    if from_path.is_some() {
        return from_path;
    }
    let home = home?;
    [
        home.join("Library/Android/sdk/cmdline-tools/latest/bin"),
        home.join("Library/Android/sdk/platform-tools"),
        home.join(".local/bin"),
        home.join(".cargo/bin"),
        home.join(".pyenv/bin"),
        home.join(".local/share/mise/shims"),
    ]
    .into_iter()
    .map(|directory| directory.join(candidate))
    .find(|path| path.is_file())
}

fn read_bounded(mut reader: impl Read, cap: usize) -> (Vec<u8>, bool) {
    let mut output = Vec::with_capacity(cap.min(8192));
    let mut truncated = false;
    let mut buffer = [0u8; 8192];
    while let Ok(read) = reader.read(&mut buffer) {
        if read == 0 {
            break;
        }
        let remaining = cap.saturating_sub(output.len());
        if remaining > 0 {
            output.extend_from_slice(&buffer[..read.min(remaining)]);
        }
        if read > remaining {
            truncated = true;
        }
    }
    (output, truncated)
}

fn normalize_output(bytes: Vec<u8>) -> String {
    let text = String::from_utf8_lossy(&bytes);
    let mut output = String::with_capacity(text.len());
    for line in text.lines() {
        if line.len() > MAX_LINE_BYTES {
            let mut end = MAX_LINE_BYTES;
            while !line.is_char_boundary(end) {
                end -= 1;
            }
            output.push_str(&line[..end]);
            output.push_str("...[line truncated]");
        } else {
            output.push_str(line);
        }
        output.push('\n');
    }
    output
}

fn terminate_child_tree(child: &mut std::process::Child) {
    #[cfg(unix)]
    unsafe {
        let pid = child.id() as i32;
        libc::kill(-pid, libc::SIGKILL);
    }
    let _ = child.kill();
}

#[cfg(test)]
mod tests {
    use super::*;

    const SHELL: CommandPolicy = CommandPolicy {
        id: "test-shell",
        executables: &["/bin/sh"],
        mutating: false,
        network: false,
        validate_args: |_| true,
    };

    #[test]
    fn output_is_bounded() {
        let runner = CommandRunner::new(None);
        let cancel = Arc::new(AtomicBool::new(false));
        let args = [
            OsString::from("-c"),
            OsString::from("yes x | head -c 2000000"),
        ];
        let output = runner
            .run(
                SHELL,
                &args,
                CommandMode::ReadOnly,
                Some(Duration::from_secs(3)),
                &cancel,
            )
            .unwrap();
        assert!(output.stdout.len() <= MAX_STDOUT_BYTES + 32);
        assert!(output.stdout_truncated);
    }

    #[test]
    fn timed_out_children_are_reaped() {
        let runner = CommandRunner::new(None).with_timeout(Duration::from_millis(50));
        let cancel = Arc::new(AtomicBool::new(false));
        let args = [OsString::from("-c"), OsString::from("sleep 5")];
        let error = runner
            .run(SHELL, &args, CommandMode::ReadOnly, None, &cancel)
            .unwrap_err();
        assert!(error.to_string().contains("timed out"));
    }

    #[test]
    fn cancelled_children_are_reaped() {
        let runner = CommandRunner::new(None);
        let cancel = Arc::new(AtomicBool::new(false));
        let worker_cancel = Arc::clone(&cancel);
        let canceller = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(50));
            worker_cancel.store(true, Ordering::Relaxed);
        });
        let args = [OsString::from("-c"), OsString::from("sleep 5")];
        let error = runner
            .run(
                SHELL,
                &args,
                CommandMode::ReadOnly,
                Some(Duration::from_secs(2)),
                &cancel,
            )
            .unwrap_err();
        canceller.join().unwrap();
        assert!(error.to_string().contains("cancelled"));
    }
}
