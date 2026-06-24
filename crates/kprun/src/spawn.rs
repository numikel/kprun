use std::collections::HashMap;
use std::env;
use std::ffi::OsString;
use std::path::PathBuf;
use std::process::Command;

pub fn resolve_executable(cmd: &str) -> PathBuf {
    if cmd.contains('.') || cfg!(not(windows)) {
        return PathBuf::from(cmd);
    }
    if let Ok(path_var) = env::var("PATHEXT") {
        for ext in path_var.split(';') {
            let ext = ext.trim();
            if ext.is_empty() {
                continue;
            }
            let candidate = format!("{cmd}{ext}");
            if which::which(&candidate).is_ok() {
                return PathBuf::from(candidate);
            }
        }
    }
    PathBuf::from(cmd)
}

pub fn run_child(
    command: &[String],
    extra_env: &HashMap<String, String>,
    clean: bool,
) -> std::io::Result<i32> {
    if command.is_empty() {
        return Ok(1);
    }
    let program = resolve_executable(&command[0]);
    let mut cmd = Command::new(program);
    cmd.args(&command[1..]);
    cmd.stdin(std::process::Stdio::inherit());
    cmd.stdout(std::process::Stdio::inherit());
    cmd.stderr(std::process::Stdio::inherit());

    if clean {
        cmd.env_clear();
        for key in [
            "PATH",
            "HOME",
            "USER",
            "LOGNAME",
            "TMPDIR",
            "TEMP",
            "TMP",
            "SystemRoot",
            "USERPROFILE",
        ] {
            if let Some(val) = env::var_os(key) {
                cmd.env(key, val);
            }
        }
        for (k, v) in extra_env {
            cmd.env(OsString::from(k), OsString::from(v));
        }
    } else {
        let mut env_map: HashMap<OsString, OsString> = env::vars_os().collect();
        for (k, v) in extra_env {
            env_map.insert(OsString::from(k), OsString::from(v));
        }
        cmd.envs(env_map);
    }

    let status = cmd.status()?;
    Ok(status.code().unwrap_or(1))
}
