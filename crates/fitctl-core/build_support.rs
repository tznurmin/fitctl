// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GitLayout {
    pub(crate) git_dir: PathBuf,
    pub(crate) common_dir: PathBuf,
}

pub(crate) fn vcs_embedding_enabled(value: Option<&OsStr>) -> Result<bool, String> {
    let Some(value) = value else {
        return Ok(false);
    };
    let value = value
        .to_str()
        .ok_or_else(|| "FITCTL_EMBED_VCS must be valid UTF-8 and equal 0 or 1".to_string())?;
    match value {
        "0" => Ok(false),
        "1" => Ok(true),
        _ => Err("FITCTL_EMBED_VCS must equal 0 or 1".to_string()),
    }
}

pub(crate) fn expected_repository_root(manifest_dir: &Path) -> Result<PathBuf, String> {
    if manifest_dir.file_name() != Some(OsStr::new("fitctl-core")) {
        return Err("fitctl-core manifest directory has an unexpected name".to_string());
    }
    let crates_dir = manifest_dir
        .parent()
        .ok_or_else(|| "fitctl-core manifest directory has no parent".to_string())?;
    if crates_dir.file_name() != Some(OsStr::new("crates")) {
        return Err("fitctl-core manifest directory is not under crates/".to_string());
    }
    let root = crates_dir
        .parent()
        .ok_or_else(|| "fitctl workspace root is unavailable".to_string())?;
    if !root.join("Cargo.toml").is_file() || !manifest_dir.join("Cargo.toml").is_file() {
        return Err("expected fitctl workspace manifests are unavailable".to_string());
    }
    validate_dot_git_entry(root)?;
    Ok(root.to_path_buf())
}

pub(crate) fn resolve_git_layout(repo_root: &Path) -> Result<GitLayout, String> {
    validate_dot_git_entry(repo_root)?;
    let git_dir = resolve_reported_git_directory(
        repo_root,
        &git_stdout(repo_root, &["rev-parse", "--git-dir"])?,
    )?;
    let common_dir = resolve_reported_git_directory(
        repo_root,
        &git_stdout(repo_root, &["rev-parse", "--git-common-dir"])?,
    )?;
    Ok(GitLayout {
        git_dir,
        common_dir,
    })
}

pub(crate) fn current_head_ref(repo_root: &Path) -> Result<Option<String>, String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(repo_root)
        .args(["symbolic-ref", "-q", "HEAD"])
        .output()
        .map_err(|error| format!("failed to execute git: {error}"))?;
    if output.status.success() {
        let value = decode_stdout(output.stdout)?;
        return Ok(Some(require_non_empty(value)?));
    }
    if output.status.code() == Some(1) {
        return Ok(None);
    }
    Err(format!(
        "git symbolic-ref exited with status {}",
        output.status
    ))
}

pub(crate) fn git_stdout(repo_root: &Path, args: &[&str]) -> Result<String, String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(repo_root)
        .args(args)
        .output()
        .map_err(|error| format!("failed to execute git: {error}"))?;
    if !output.status.success() {
        return Err(format!("git exited with status {}", output.status));
    }
    require_non_empty(decode_stdout(output.stdout)?)
}

pub(crate) fn git_dirty(repo_root: &Path) -> Result<bool, String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(repo_root)
        .args(["status", "--porcelain", "--untracked-files=normal"])
        .output()
        .map_err(|error| format!("failed to execute git: {error}"))?;
    if !output.status.success() {
        return Err(format!("git exited with status {}", output.status));
    }
    Ok(!decode_stdout(output.stdout)?.trim().is_empty())
}

pub(crate) fn render_build_provenance_constants(
    revision: Option<&str>,
    describe: Option<&str>,
    dirty: Option<bool>,
) -> String {
    format!(
        "pub const FITCTL_VCS_REVISION: Option<&str> = {};\n\
         pub const FITCTL_VCS_DESCRIBE: Option<&str> = {};\n\
         pub const FITCTL_BUILD_DIRTY: Option<bool> = {};\n",
        option_string_literal(revision),
        option_string_literal(describe),
        option_bool_literal(dirty),
    )
}

fn validate_dot_git_entry(repo_root: &Path) -> Result<(), String> {
    let dot_git = repo_root.join(".git");
    let metadata = fs::symlink_metadata(&dot_git)
        .map_err(|_| "expected fitctl workspace root does not own .git".to_string())?;
    if metadata.file_type().is_symlink() || !(metadata.is_dir() || metadata.is_file()) {
        return Err("expected fitctl workspace .git entry is invalid".to_string());
    }
    Ok(())
}

fn resolve_reported_git_directory(repo_root: &Path, raw: &str) -> Result<PathBuf, String> {
    let raw = PathBuf::from(raw);
    let path = if raw.is_absolute() {
        raw
    } else {
        repo_root.join(raw)
    };
    let metadata = fs::symlink_metadata(&path)
        .map_err(|error| format!("cannot inspect Git directory {}: {error}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(format!(
            "Git directory is not an owned directory: {}",
            path.display()
        ));
    }
    fs::canonicalize(&path)
        .map_err(|error| format!("cannot resolve Git directory {}: {error}", path.display()))
}

fn decode_stdout(bytes: Vec<u8>) -> Result<String, String> {
    String::from_utf8(bytes).map_err(|_| "git emitted non-UTF-8 stdout".to_string())
}

fn require_non_empty(value: String) -> Result<String, String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        Err("git emitted empty stdout".to_string())
    } else {
        Ok(trimmed.to_string())
    }
}

fn option_string_literal(value: Option<&str>) -> String {
    value.map_or_else(|| "None".to_string(), |value| format!("Some({value:?})"))
}

fn option_bool_literal(value: Option<bool>) -> &'static str {
    match value {
        Some(true) => "Some(true)",
        Some(false) => "Some(false)",
        None => "None",
    }
}
