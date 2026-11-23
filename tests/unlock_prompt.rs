//! Interactive master-password prompt on a real terminal (`rpassword`).
//!
//! When neither a keyfile-only key nor the OS keyring can unlock the vault,
//! `kprun run` falls back to prompting on the controlling terminal. These
//! tests give a real `kprun` process a pseudo-terminal as its controlling
//! terminal and type into it, so the actual `rpassword` code path in the
//! unlock flow runs — not the `KPRUN_TEST_MASTER` bypass.
//!
//! Pinned behaviour:
//! - the typed master password unlocks the vault and secrets reach the child;
//! - the password is never echoed back to the terminal;
//! - Ctrl+C at the prompt aborts before anything is disclosed (no child, no
//!   audit record) **and leaves the terminal usable** (echo, line editing and
//!   signals restored). The last part regressed before rpassword 7.5.5: the
//!   process died inside `raise(SIGINT)` with the terminal still in raw mode,
//!   so the user's shell no longer echoed what they typed.
#![cfg(any(target_os = "linux", target_os = "macos"))]

mod common;

use std::fs::File;
use std::io::{self, Read, Write};
use std::mem::MaybeUninit;
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Output, Stdio};
use std::time::{Duration, Instant};

use common::create_vault_with_entries;
use kprun_core::test_support;

const SECRET: &str = "s3cr3t-from-vault";
const PROMPT: &str = "KeePass master password: ";
/// Terminal modes rpassword switches off while reading and must restore.
const WATCHED: libc::tcflag_t = libc::ECHO | libc::ICANON | libc::ISIG;
/// Generous: a debug build on a loaded CI runner, plus Argon2 unlock.
const TIMEOUT: Duration = Duration::from_secs(60);

struct Pty {
    master: File,
    slave: File,
}

fn open_pty() -> Pty {
    let (mut master, mut slave) = (-1, -1);
    // SAFETY: out-pointers are valid; name/termios/winsize may be null.
    let rc = unsafe {
        libc::openpty(
            &mut master,
            &mut slave,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    assert_eq!(rc, 0, "openpty: {}", io::Error::last_os_error());
    // SAFETY: openpty succeeded, so both fds are fresh and owned by us.
    unsafe {
        Pty {
            master: File::from_raw_fd(master),
            slave: File::from_raw_fd(slave),
        }
    }
}

fn local_flags(fd: RawFd) -> libc::tcflag_t {
    let mut term = MaybeUninit::<libc::termios>::uninit();
    // SAFETY: valid fd and out-pointer; initialised on success.
    assert_eq!(unsafe { libc::tcgetattr(fd, term.as_mut_ptr()) }, 0);
    unsafe { term.assume_init() }.c_lflag
}

struct Fixture {
    _dir: tempfile::TempDir,
    db: PathBuf,
    keystore: PathBuf,
    audit_log: PathBuf,
    marker: PathBuf,
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("secrets.kdbx");
    create_vault_with_entries(&db, &[("demo", &[("DEMO_KEY", SECRET)])]);
    let keystore = dir.path().join("empty-keystore");
    std::fs::create_dir(&keystore).unwrap();
    Fixture {
        db,
        keystore,
        audit_log: dir.path().join("access.log"),
        marker: dir.path().join("child-ran"),
        _dir: dir,
    }
}

/// Start `kprun run demo -- sh -c 'printf %s "$DEMO_KEY" > marker'` in a new
/// session whose controlling terminal is the pty slave — what a user's shell
/// gives it. The keystore seam points at an empty directory, so the keyring
/// has no entry and unlock falls through to the interactive prompt.
fn spawn_kprun_run(pty: &Pty, fx: &Fixture) -> Child {
    let tty = pty.slave.try_clone().unwrap();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_kprun"));
    cmd.args([
        "run",
        "demo",
        "--",
        "sh",
        "-c",
        "printf %s \"$DEMO_KEY\" > \"$1\"",
        "sh",
    ])
    .arg(&fx.marker)
    .env_remove("KPRUN_TEST_MASTER")
    .env_remove("KPRUN_KEYFILE")
    .env("KPRUN_DB", &fx.db)
    .env("KPRUN_TEST_KEYSTORE", &fx.keystore)
    .env("KPRUN_LOG", &fx.audit_log)
    .stdin(Stdio::from(tty))
    .stdout(Stdio::piped())
    .stderr(Stdio::piped());
    // SAFETY: only async-signal-safe libc calls between fork and exec.
    unsafe {
        cmd.pre_exec(|| {
            // An interactive shell runs its foreground job with default
            // SIGINT handling; do not inherit an `ignore` from the harness.
            libc::signal(libc::SIGINT, libc::SIG_DFL);
            if libc::setsid() == -1 {
                return Err(io::Error::last_os_error());
            }
            // stdin is the pty slave: make it the controlling terminal so
            // rpassword's /dev/tty resolves to it.
            if libc::ioctl(0, libc::TIOCSCTTY as _, 0) == -1 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    cmd.spawn().expect("spawn kprun")
}

/// Wait until rpassword has put the terminal into raw mode (ISIG cleared):
/// only then is input read by the prompt rather than the line discipline.
fn wait_for_raw_mode(pty: &Pty, child: &mut Child) {
    let deadline = Instant::now() + TIMEOUT;
    while local_flags(pty.slave.as_raw_fd()) & libc::ISIG != 0 {
        if let Some(status) = child.try_wait().unwrap() {
            panic!("kprun exited before prompting: {status}");
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            panic!("kprun never switched the terminal to password mode");
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

fn type_keys(pty: &mut Pty, bytes: &[u8]) {
    pty.master.write_all(bytes).unwrap();
    pty.master.flush().unwrap();
}

fn wait_with_timeout(mut child: Child) -> (ExitStatus, Output) {
    let deadline = Instant::now() + TIMEOUT;
    loop {
        if child.try_wait().unwrap().is_some() {
            let out = child.wait_with_output().unwrap();
            return (out.status, out);
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            panic!("kprun did not exit after input");
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

/// Everything kprun wrote to the terminal so far (non-blocking drain).
fn terminal_output(pty: &mut Pty) -> String {
    let fd = pty.master.as_raw_fd();
    // SAFETY: plain fcntl flag update on an fd we own.
    unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFL);
        libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
    }
    let mut out = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        match pty.master.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => out.extend_from_slice(&buf[..n]),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            // EAGAIN: drained. EIO: Linux reports this once no slave is open.
            Err(_) => break,
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn assert_terminal_restored(pty: &Pty, before: libc::tcflag_t) {
    assert_eq!(
        local_flags(pty.slave.as_raw_fd()) & WATCHED,
        before,
        "terminal left without echo / line editing / signals after kprun exited"
    );
}

fn audit_written(path: &Path) -> bool {
    std::fs::read_to_string(path).is_ok_and(|s| !s.trim().is_empty())
}

#[test]
fn typed_master_password_unlocks_vault_without_echo() {
    let fx = fixture();
    let mut pty = open_pty();
    let before = local_flags(pty.slave.as_raw_fd()) & WATCHED;
    assert_eq!(before, WATCHED, "fresh pty must start in cooked mode");

    let mut child = spawn_kprun_run(&pty, &fx);
    wait_for_raw_mode(&pty, &mut child);
    // A real Enter key sends CR.
    type_keys(
        &mut pty,
        format!("{}\r", test_support::vault_password()).as_bytes(),
    );
    let (status, out) = wait_with_timeout(child);

    assert!(
        status.success(),
        "kprun run failed: {status}; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        std::fs::read_to_string(&fx.marker).unwrap(),
        SECRET,
        "secret from the unlocked vault must reach the child"
    );
    assert!(
        out.stdout.is_empty(),
        "kprun run must write nothing to stdout"
    );
    assert!(
        audit_written(&fx.audit_log),
        "successful run must be audited"
    );

    let screen = terminal_output(&mut pty);
    // The fixture password ("pass") is a substring of the prompt text itself,
    // so only what the terminal shows *after* the prompt may be checked.
    let (_, after_prompt) = screen
        .split_once(PROMPT)
        .unwrap_or_else(|| panic!("prompt missing; terminal: {screen:?}"));
    assert!(
        !after_prompt.contains(test_support::vault_password()),
        "master password was echoed to the terminal: {screen:?}"
    );
    assert_terminal_restored(&pty, before);
}

#[test]
fn ctrl_c_at_master_password_prompt_aborts_and_restores_terminal() {
    let fx = fixture();
    let mut pty = open_pty();
    let before = local_flags(pty.slave.as_raw_fd()) & WATCHED;
    assert_eq!(before, WATCHED, "fresh pty must start in cooked mode");

    let mut child = spawn_kprun_run(&pty, &fx);
    wait_for_raw_mode(&pty, &mut child);
    type_keys(&mut pty, b"pa\x03");
    let (status, out) = wait_with_timeout(child);

    assert_eq!(
        status.signal(),
        Some(libc::SIGINT),
        "Ctrl+C must terminate kprun via SIGINT, got {status}; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        !fx.marker.exists(),
        "child must not run after an aborted unlock"
    );
    assert!(
        !audit_written(&fx.audit_log),
        "aborted unlock disclosed nothing, so nothing may be audited"
    );
    assert!(out.stdout.is_empty());
    assert_terminal_restored(&pty, before);
}
