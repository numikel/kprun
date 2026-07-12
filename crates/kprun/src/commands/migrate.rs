use std::io::IsTerminal;
use std::path::{Path, PathBuf};

use kprun_core::audit::AuditRecord;
use kprun_core::dotenv::parse_dotenv;
use kprun_core::import::{apply_import, ImportEntry, ImportMode};
use kprun_core::{KprunError, Result};

use super::{audit_access, mutate_vault, run_command};
use crate::ui;

pub fn execute(
    file: String,
    entry: Option<String>,
    merge: bool,
    gitignore: bool,
    delete: bool,
) -> i32 {
    run_command(|| run(&file, entry, merge, gitignore, delete))
}

fn run(
    file: &str,
    entry: Option<String>,
    merge: bool,
    gitignore: bool,
    delete: bool,
) -> Result<()> {
    ui::maybe_banner();
    let path = Path::new(file);

    // 1. Read + parse before unlocking: a missing or malformed file must
    //    fail fast without prompting for the master password.
    let content = std::fs::read_to_string(path)
        .map_err(|e| KprunError::Other(format!("cannot read {file}: {e}")))?;
    let parsed = parse_dotenv(&content)?;
    if parsed.pairs.is_empty() {
        return Err(KprunError::Other(format!(
            "no KEY=value lines found in {file}"
        )));
    }
    for key in &parsed.duplicate_keys {
        eprintln!("WARNING: duplicate key '{key}' in {file}; last value wins");
    }

    // 2. Entry title: --entry or the directory-name default.
    let title = match entry {
        Some(t) => t,
        None => default_entry_title(path)?,
    };

    // 3. Vault write. Merge-only semantics: migrate must never delete
    //    unrelated entries, so ImportMode::Replace is not used.
    let key_names: Vec<String> = parsed.pairs.iter().map(|(k, _)| k.clone()).collect();
    let import_entries = [ImportEntry {
        title: title.clone(),
        pairs: parsed.pairs,
    }];
    let cfg = mutate_vault(|vault| {
        match vault.find_entry_by_title(&title) {
            Ok(_) if !merge => {
                return Err(KprunError::Other(format!(
                    "entry '{title}' already exists; rerun with --merge to add keys to it"
                )));
            }
            Ok(_) | Err(KprunError::EntryNotFound(_)) => {}
            Err(e) => return Err(e), // DuplicateEntry etc. propagate as-is
        }
        apply_import(vault, &import_entries, ImportMode::Merge)
    })?;

    let count = key_names.len();
    let noun = if count == 1 { "key" } else { "keys" };
    ui::success(&format!("{count} {noun} imported into entry '{title}'"));

    // 4./5. Repo cleanup, destructive-last. The audit command string
    // reflects the actions actually performed.
    let mut audit_command = String::from("migrate");
    let mut repo_error: Option<KprunError> = None;

    // Repo cleanup must not short-circuit before the audit write below: the
    // vault mutation already happened, so any failure here is captured into
    // `repo_error` (never propagated with `?`) to keep the audit record. This
    // mirrors the gitignore/delete failure handling further down.
    let filename = match file_name_of(path) {
        Ok(name) => Some(name),
        Err(e) => {
            repo_error = Some(e);
            None
        }
    };
    let wants_gitignore = match filename.as_deref() {
        None => false, // file_name_of failed above; nothing to add
        Some(_) if gitignore => true,
        Some(name) if std::io::stdin().is_terminal() => {
            match ui::confirm(&format!("Add \"{name}\" to .gitignore?"), true) {
                Ok(answer) => answer,
                Err(e) => {
                    ui::hint("could not read your answer; skipping .gitignore");
                    repo_error = Some(KprunError::Io(e));
                    false
                }
            }
        }
        Some(_) => {
            ui::hint("use --gitignore to update .gitignore non-interactively");
            false
        }
    };
    if let (true, Some(filename)) = (wants_gitignore, filename.as_deref()) {
        match add_to_gitignore(path, filename) {
            Ok(GitignoreOutcome::Added(gi)) => {
                audit_command.push_str(" --gitignore");
                ui::info(&format!("added \"{filename}\" to {}", gi.display()));
            }
            Ok(GitignoreOutcome::AlreadyPresent(gi)) => {
                ui::info(&format!(
                    "\"{filename}\" already listed in {}",
                    gi.display()
                ));
            }
            Err(e) => {
                // The rerun needs --merge: the entry exists now.
                let rerun_flags = if delete {
                    "--gitignore --delete"
                } else {
                    "--gitignore"
                };
                ui::hint(&format!(
                    "secrets are already in the vault; fix the .gitignore problem, \
                     then rerun: kprun migrate {file} --merge {rerun_flags}"
                ));
                repo_error = Some(e);
            }
        }
    }

    if delete {
        if repo_error.is_none() {
            match std::fs::remove_file(path) {
                Ok(()) => {
                    audit_command.push_str(" --delete");
                    ui::info(&format!("deleted {file}"));
                }
                Err(e) => {
                    ui::hint(&format!(
                        "the file is still on disk; delete it manually or rerun: \
                         kprun migrate {file} --merge --delete"
                    ));
                    repo_error = Some(KprunError::Io(e));
                }
            }
        } else {
            eprintln!("WARNING: {file} NOT deleted because the .gitignore step failed");
        }
    } else {
        ui::info(&format!("{file} kept (use --delete to remove it)"));
    }

    // 6. Audit: entry title + key names, never values. A failed audit
    //    write warns and does not abort — the import already happened.
    let record = AuditRecord::new(&cfg.db_path, vec![title], key_names, Some(audit_command));
    if let Err(e) = audit_access(&cfg, record) {
        eprintln!("WARNING: failed to write audit log: {e}");
    }

    match repo_error {
        Some(e) => {
            // The success line above already reported the import; make the
            // partial-failure state unmistakable before the error exit.
            eprintln!("WARNING: vault import succeeded, but repo cleanup failed");
            Err(e)
        }
        None => Ok(()),
    }
}

/// Directory-derived entry title: `repo/backend/.env` → `backend`.
/// Falls back to `default` at the filesystem root or directly under $HOME.
fn default_entry_title(path: &Path) -> Result<String> {
    let canonical = std::fs::canonicalize(path)?;
    let home = std::fs::canonicalize(kprun_core::config::home_dir()).ok();
    Ok(entry_title_from(&canonical, home.as_deref()))
}

fn entry_title_from(canonical: &Path, home: Option<&Path>) -> String {
    let Some(parent) = canonical.parent() else {
        return "default".to_string();
    };
    if home == Some(parent) {
        return "default".to_string();
    }
    match parent.file_name() {
        Some(name) => name.to_string_lossy().into_owned(),
        None => "default".to_string(),
    }
}

fn file_name_of(path: &Path) -> Result<String> {
    path.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .ok_or_else(|| {
            KprunError::Other(format!("cannot determine file name of {}", path.display()))
        })
}

enum GitignoreOutcome {
    /// A line was written; holds the `.gitignore` path for the summary.
    Added(PathBuf),
    /// The exact line already existed; nothing written.
    AlreadyPresent(PathBuf),
}

/// Append `filename` to the `.gitignore` sitting next to `env_path`.
/// Exact-match (trimmed) duplicates are skipped; the file is created when
/// missing. Plain `std::fs` — `.gitignore` is not a secret.
fn add_to_gitignore(env_path: &Path, filename: &str) -> Result<GitignoreOutcome> {
    let dir = env_path.parent().unwrap_or_else(|| Path::new("."));
    let gitignore = dir.join(".gitignore");
    match std::fs::read_to_string(&gitignore) {
        Ok(content) => {
            if content.lines().any(|l| l.trim() == filename) {
                return Ok(GitignoreOutcome::AlreadyPresent(gitignore));
            }
            let mut updated = content;
            if !updated.is_empty() && !updated.ends_with('\n') {
                updated.push('\n');
            }
            updated.push_str(filename);
            updated.push('\n');
            std::fs::write(&gitignore, updated)?;
            Ok(GitignoreOutcome::Added(gitignore))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            std::fs::write(&gitignore, format!("{filename}\n"))?;
            Ok(GitignoreOutcome::Added(gitignore))
        }
        Err(e) => Err(KprunError::Io(e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entry_title_from_directory_name() {
        let home = Path::new("/home/user");
        assert_eq!(
            entry_title_from(Path::new("/repo/backend/.env"), Some(home)),
            "backend"
        );
    }

    #[test]
    fn entry_title_defaults_directly_under_home() {
        let home = Path::new("/home/user");
        assert_eq!(
            entry_title_from(Path::new("/home/user/.env"), Some(home)),
            "default"
        );
    }

    #[test]
    fn entry_title_defaults_at_filesystem_root() {
        assert_eq!(entry_title_from(Path::new("/.env"), None), "default");
    }

    #[test]
    fn entry_title_uses_directory_when_home_unknown() {
        assert_eq!(entry_title_from(Path::new("/srv/api/.env"), None), "api");
    }

    #[test]
    fn gitignore_created_when_missing() {
        let dir = tempfile::tempdir().unwrap();
        let env_path = dir.path().join(".env");
        let outcome = add_to_gitignore(&env_path, ".env").unwrap();
        assert!(matches!(outcome, GitignoreOutcome::Added(_)));
        let content = std::fs::read_to_string(dir.path().join(".gitignore")).unwrap();
        assert_eq!(content, ".env\n");
    }

    #[test]
    fn gitignore_appends_and_fixes_missing_trailing_newline() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(".gitignore"), "target").unwrap();
        let env_path = dir.path().join(".env");
        add_to_gitignore(&env_path, ".env").unwrap();
        let content = std::fs::read_to_string(dir.path().join(".gitignore")).unwrap();
        assert_eq!(content, "target\n.env\n");
    }

    #[test]
    fn gitignore_skips_exact_duplicate_line() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(".gitignore"), "target\n.env\n").unwrap();
        let env_path = dir.path().join(".env");
        let outcome = add_to_gitignore(&env_path, ".env").unwrap();
        assert!(matches!(outcome, GitignoreOutcome::AlreadyPresent(_)));
        let content = std::fs::read_to_string(dir.path().join(".gitignore")).unwrap();
        assert_eq!(content, "target\n.env\n");
    }
}
