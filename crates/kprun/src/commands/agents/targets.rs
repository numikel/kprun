//! Tool → instruction-file map and config-directory detection for
//! `kprun agents install -g`. Pure functions of an injected base path —
//! testable without touching real environment variables.

use std::path::{Path, PathBuf};

/// Coding agents accepted by `--target`. `Cursor` is accepted but has no
/// global rules file — selecting it only prints guidance. Gemini CLI is
/// deliberately absent (sunset in favor of Antigravity, which reads
/// AGENTS.md).
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub(crate) enum Target {
    Claude,
    Codex,
    Opencode,
    Windsurf,
    Copilot,
    Cursor,
}

/// Declaration order = detection and report order.
pub(crate) const ALL_TARGETS: [Target; 6] = [
    Target::Claude,
    Target::Codex,
    Target::Opencode,
    Target::Windsurf,
    Target::Copilot,
    Target::Cursor,
];

/// Directory whose presence marks the tool as installed. `copilot_home`
/// mirrors `$COPILOT_HOME`: when set, it replaces `~/.copilot` for both
/// detection and the target file.
pub(crate) fn detection_dir(tool: Target, home: &Path, copilot_home: Option<&Path>) -> PathBuf {
    match tool {
        Target::Claude => home.join(".claude"),
        Target::Codex => home.join(".codex"),
        Target::Opencode => home.join(".config").join("opencode"),
        Target::Windsurf => home.join(".codeium").join("windsurf"),
        Target::Copilot => copilot_home
            .map(Path::to_path_buf)
            .unwrap_or_else(|| home.join(".copilot")),
        Target::Cursor => home.join(".cursor"),
    }
}

/// Global instruction file receiving the full policy block.
/// `None` = the tool has no global file (Cursor: GUI-only rules).
pub(crate) fn target_file(
    tool: Target,
    home: &Path,
    copilot_home: Option<&Path>,
) -> Option<PathBuf> {
    match tool {
        Target::Claude => Some(home.join(".claude").join("CLAUDE.md")),
        Target::Codex => Some(home.join(".codex").join("AGENTS.md")),
        Target::Opencode => Some(home.join(".config").join("opencode").join("AGENTS.md")),
        Target::Windsurf => Some(
            home.join(".codeium")
                .join("windsurf")
                .join("memories")
                .join("global_rules.md"),
        ),
        Target::Copilot => {
            Some(detection_dir(tool, home, copilot_home).join("copilot-instructions.md"))
        }
        Target::Cursor => None,
    }
}

/// Tools whose config directory exists under `home` (Copilot CLI honors
/// `copilot_home`).
pub(crate) fn detect_installed(home: &Path, copilot_home: Option<&Path>) -> Vec<Target> {
    ALL_TARGETS
        .into_iter()
        .filter(|tool| detection_dir(*tool, home, copilot_home).is_dir())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn detects_only_existing_config_dirs() {
        let home = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(home.path().join(".claude")).unwrap();
        std::fs::create_dir_all(home.path().join(".codex")).unwrap();
        let detected = detect_installed(home.path(), None);
        assert_eq!(detected, vec![Target::Claude, Target::Codex]);
    }

    #[test]
    fn copilot_home_overrides_default_location() {
        let home = tempfile::tempdir().unwrap();
        let copilot = tempfile::tempdir().unwrap();
        assert_eq!(
            detection_dir(Target::Copilot, home.path(), Some(copilot.path())),
            copilot.path().to_path_buf()
        );
        assert_eq!(
            target_file(Target::Copilot, home.path(), Some(copilot.path())),
            Some(copilot.path().join("copilot-instructions.md"))
        );
        assert_eq!(
            detect_installed(home.path(), Some(copilot.path())),
            vec![Target::Copilot]
        );
    }

    #[test]
    fn global_paths_match_design_spec() {
        let home = Path::new("home");
        let file = |t| target_file(t, home, None);
        assert_eq!(
            file(Target::Claude),
            Some(home.join(".claude").join("CLAUDE.md"))
        );
        assert_eq!(
            file(Target::Codex),
            Some(home.join(".codex").join("AGENTS.md"))
        );
        assert_eq!(
            file(Target::Opencode),
            Some(home.join(".config").join("opencode").join("AGENTS.md"))
        );
        assert_eq!(
            file(Target::Windsurf),
            Some(
                home.join(".codeium")
                    .join("windsurf")
                    .join("memories")
                    .join("global_rules.md")
            )
        );
        assert_eq!(
            file(Target::Copilot),
            Some(home.join(".copilot").join("copilot-instructions.md"))
        );
        assert_eq!(
            file(Target::Cursor),
            None,
            "Cursor global rules are GUI-only"
        );
    }
}
