// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

mod build_support;

use std::env;
use std::fs;
use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=build_support.rs");
    println!("cargo:rerun-if-env-changed=FITCTL_EMBED_VCS");

    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("Cargo should provide OUT_DIR"));
    let enabled = build_support::vcs_embedding_enabled(env::var_os("FITCTL_EMBED_VCS").as_deref())
        .unwrap_or_else(|error| panic!("invalid VCS provenance configuration: {error}"));
    let generated = if enabled {
        // Git status includes unstaged and untracked worktree changes outside this crate. An
        // intentionally absent Cargo input refreshes this opt-in snapshot on every invocation,
        // without recursively watching ignored caches or relying on Git metadata mtimes alone.
        let refresh_input = out_dir.join("fitctl-vcs-refresh-required");
        match fs::symlink_metadata(&refresh_input) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => watch(refresh_input),
            _ => panic!("VCS refresh input must remain absent"),
        }
        collect_build_provenance()
    } else {
        build_support::render_build_provenance_constants(None, None, None)
    };

    fs::write(out_dir.join("fitctl_build_provenance.rs"), generated)
        .expect("generated build provenance constants should write");
}

fn collect_build_provenance() -> String {
    let manifest_dir = PathBuf::from(
        env::var_os("CARGO_MANIFEST_DIR").expect("Cargo should provide CARGO_MANIFEST_DIR"),
    );
    let repo_root = build_support::expected_repository_root(&manifest_dir)
        .unwrap_or_else(|error| panic!("cannot embed VCS provenance: {error}"));
    let layout = build_support::resolve_git_layout(&repo_root)
        .unwrap_or_else(|error| panic!("cannot resolve fitctl Git metadata: {error}"));

    watch(layout.git_dir.join("HEAD"));
    watch(layout.git_dir.join("index"));
    watch(layout.common_dir.join("packed-refs"));
    watch(layout.common_dir.join("refs").join("tags"));
    if let Some(head_ref) = build_support::current_head_ref(&repo_root)
        .unwrap_or_else(|error| panic!("cannot resolve current Git reference: {error}"))
    {
        watch(layout.common_dir.join(head_ref));
    }

    let revision = build_support::git_stdout(&repo_root, &["rev-parse", "HEAD"])
        .unwrap_or_else(|error| panic!("cannot collect VCS revision: {error}"));
    let describe =
        build_support::git_stdout(&repo_root, &["describe", "--always", "--tags", "--long"])
            .unwrap_or_else(|error| panic!("cannot collect VCS description: {error}"));
    let dirty = build_support::git_dirty(&repo_root)
        .unwrap_or_else(|error| panic!("cannot collect VCS dirty state: {error}"));

    build_support::render_build_provenance_constants(Some(&revision), Some(&describe), Some(dirty))
}

fn watch(path: PathBuf) {
    println!("cargo:rerun-if-changed={}", path.display());
}
