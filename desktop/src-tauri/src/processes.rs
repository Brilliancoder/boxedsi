//! What the sidecar manager needs to know about processes beyond what std offers: the process group of a sidecar, and a pid that may
//! be the sidecar of an app that was killed. macOS and Linux; on Windows the sidecar is ended as a process and nothing is looked for.

use std::fs;
use std::path::{Path, PathBuf};

/// Ends the process group `pid` leads, and with it what the sidecar started; a pid that leads none (it was not started by this
/// manager) only itself.
#[cfg(unix)]
pub fn end_group(pid: u32) {
    let pid = pid as libc::pid_t;
    // SAFETY: system calls on plain integers.
    unsafe {
        if libc::getpgid(pid) == pid {
            libc::killpg(pid, libc::SIGKILL);
        } else {
            libc::kill(pid, libc::SIGKILL);
        }
    }
}

fn pid_file(dir: &Path) -> PathBuf {
    dir.join(format!("sidecar-{}.pid", std::process::id()))
}

/// Records the pid of the sidecar of this app in the app's data folder, for the next start to find if this app is killed.
pub fn write_pid_file(dir: &Path, pid: u32) {
    let _ = fs::create_dir_all(dir);
    let _ = fs::write(pid_file(dir), format!("{pid}\n"));
}

pub fn remove_pid_file(dir: &Path) {
    let _ = fs::remove_file(pid_file(dir));
}

/// (parent, command line) of a process, from ps; None when there is no such process. ps is named by its path: the PATH of an app
/// started from the Finder is short, and that of one started by a script may hold nothing.
#[cfg(unix)]
fn look_up(pid: u32) -> Option<(u32, String)> {
    let out = std::process::Command::new("/bin/ps").args(["-ww", "-o", "ppid=", "-o", "command=", "-p", &pid.to_string()]).output().ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    let (parent, command) = text.trim().split_once(char::is_whitespace)?;
    Some((parent.parse().ok()?, command.trim().to_string()))
}

/// A sidecar that its app left behind (the app was killed or crashed) and that the end of its input did not end, because it was
/// busy or hung, keeps the lock of the vault, and every request of the next sidecar waits for it. Each file in `dir` names the
/// sidecar of an app that ran here. A sidecar that is still there, is the program of this app (its command line is
/// `command_line`) and has lost its parent (pid 1 has it now) is ended. A file whose pid is gone, or is another program now, is
/// stale and removed. A sidecar that still has a parent belongs to an app that runs, perhaps another copy of this one: left alone.
#[cfg(unix)]
pub fn end_leftovers(dir: &Path, command_line: &str) {
    let Ok(entries) = fs::read_dir(dir) else { return };
    let own = pid_file(dir);
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if entry.path() == own || !(name.starts_with("sidecar-") && name.ends_with(".pid")) {
            continue;
        }
        let pid = fs::read_to_string(entry.path()).ok().and_then(|text| text.trim().parse::<u32>().ok());
        match pid.and_then(|pid| look_up(pid).map(|found| (pid, found))) {
            Some((pid, (1, command))) if command == command_line => {
                end_group(pid);
                let _ = fs::remove_file(entry.path());
            }
            Some((_, (_, command))) if command == command_line => {}
            _ => {
                let _ = fs::remove_file(entry.path());
            }
        }
    }
}

#[cfg(not(unix))]
pub fn end_leftovers(_dir: &Path, _command_line: &str) {}
