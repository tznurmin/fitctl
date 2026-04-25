// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    let manifest_dir = PathBuf::from(
        env::var_os("CARGO_MANIFEST_DIR").expect("Cargo should provide CARGO_MANIFEST_DIR"),
    );
    let Some(repo_root) = find_repo_root(&manifest_dir) else {
        return;
    };
    let Some(git_dir) = resolve_git_dir(&repo_root) else {
        return;
    };

    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed={}", git_dir.join("HEAD").display());
    println!("cargo:rerun-if-changed={}", git_dir.join("index").display());
    if let Some(head_ref) = current_head_ref(&git_dir) {
        println!(
            "cargo:rerun-if-changed={}",
            git_dir.join(head_ref).display()
        );
    }

    if let Some(revision) = git_stdout(&repo_root, &["rev-parse", "HEAD"]) {
        println!("cargo:rustc-env=FITCTL_VCS_REVISION={revision}");
    }
    if let Some(describe) = git_stdout(&repo_root, &["describe", "--always", "--tags", "--long"]) {
        println!("cargo:rustc-env=FITCTL_VCS_DESCRIBE={describe}");
    }
    if let Some(dirty) = git_dirty(&repo_root) {
        println!("cargo:rustc-env=FITCTL_BUILD_DIRTY={dirty}");
    }
}

fn find_repo_root(start: &Path) -> Option<PathBuf> {
    start
        .ancestors()
        .find(|path| path.join(".git").exists())
        .map(Path::to_path_buf)
}

fn resolve_git_dir(repo_root: &Path) -> Option<PathBuf> {
    let dot_git = repo_root.join(".git");
    if dot_git.is_dir() {
        return Some(dot_git);
    }
    let contents = fs::read_to_string(dot_git).ok()?;
    let git_dir = contents.strip_prefix("gitdir:")?.trim();
    let path = PathBuf::from(git_dir);
    Some(if path.is_absolute() {
        path
    } else {
        repo_root.join(path)
    })
}

fn current_head_ref(git_dir: &Path) -> Option<String> {
    let head = fs::read_to_string(git_dir.join("HEAD")).ok()?;
    let reference = head.strip_prefix("ref:")?.trim();
    Some(reference.to_string())
}

fn git_stdout(repo_root: &Path, args: &[&str]) -> Option<String> {
    let output = Command::new("git")
        .args(["-C", repo_root.to_str()?])
        .args(args)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8(output.stdout).ok()?;
    let trimmed = text.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

fn git_dirty(repo_root: &Path) -> Option<bool> {
    let output = Command::new("git")
        .args([
            "-C",
            repo_root.to_str()?,
            "status",
            "--porcelain",
            "--untracked-files=no",
        ])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8(output.stdout).ok()?;
    Some(!text.trim().is_empty())
}
