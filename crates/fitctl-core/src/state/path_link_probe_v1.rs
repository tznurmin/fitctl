// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

use super::{observed, unknown};
use crate::artifacts::path_probe_cleanup_v1::{
    HostStatePathProbeCleanupV1, PathProbeCleanupOutcomeV1,
};
use crate::artifacts::state_v1::{
    HostStatePathLinkCapabilitiesV1, HostStatePathLinkPairV1, StateFieldV1,
};
use std::fs::{self, File, OpenOptions};
use std::io;
use std::os::unix::fs::{symlink, MetadataExt};
use std::os::unix::io::AsRawFd;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

trait ProbeIo {
    fn create_dir(&self, path: &Path) -> io::Result<()> {
        fs::create_dir(path)
    }
    fn write(&self, path: &Path, bytes: &[u8]) -> io::Result<()> {
        fs::write(path, bytes)
    }
    fn remove_dir_all(&self, path: &Path) -> io::Result<()> {
        fs::remove_dir_all(path)
    }
    fn suffix(&self, prefix: &str) -> String {
        format!(
            "{prefix}{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        )
    }
}

struct LocalProbeIo;
impl ProbeIo for LocalProbeIo {}

fn uncreated(root: &Path) -> HostStatePathProbeCleanupV1 {
    HostStatePathProbeCleanupV1 {
        probe_root: root.to_string_lossy().into_owned(),
        outcome: PathProbeCleanupOutcomeV1::NotCreated,
        error: None,
    }
}

// Called only for roots whose create_dir succeeded in this probe.
fn remove_owned(io: &impl ProbeIo, root: &Path) -> HostStatePathProbeCleanupV1 {
    let mut cleanup = uncreated(root);
    match io.remove_dir_all(root) {
        Ok(()) => cleanup.outcome = PathProbeCleanupOutcomeV1::Removed,
        Err(error) => {
            cleanup.outcome = PathProbeCleanupOutcomeV1::RemoveFailed;
            cleanup.error = Some(error.to_string());
        }
    }
    cleanup
}

pub(super) fn probe_path_link_capabilities(
    path: &Path,
    observed_at: &str,
) -> HostStatePathLinkCapabilitiesV1 {
    probe_single(path, observed_at, &LocalProbeIo)
}

fn probe_single(
    path: &Path,
    observed_at: &str,
    io: &impl ProbeIo,
) -> HostStatePathLinkCapabilitiesV1 {
    let mut result = HostStatePathLinkCapabilitiesV1 {
        cleanup: Some(Vec::new()),
        probe_method: Some("temporary-files-under-checked-path".to_string()),
        observed_at: Some(observed_at.to_string()),
        ..HostStatePathLinkCapabilitiesV1::default()
    };

    if !path.is_dir() {
        result.hardlink_supported = observed(false);
        result.reflink_supported = observed(false);
        result.symlink_supported = observed(false);
        result.copy_possible = observed(false);
        result.probe_error = Some("checked path is not an existing directory".to_string());
        return result;
    }

    let probe_root = path.join(io.suffix(".fitctl-link-probe-"));

    result.probe_root = Some(probe_root.to_string_lossy().to_string());
    result.cleanup = Some(vec![uncreated(&probe_root)]);
    if let Err(error) = io.create_dir(&probe_root) {
        result.hardlink_supported = observed(false);
        result.reflink_supported = observed(false);
        result.symlink_supported = observed(false);
        result.copy_possible = observed(false);
        result.probe_error = Some(format!("failed to create probe root: {error}"));
        return result;
    }

    let source = probe_root.join("source");
    let hardlink = probe_root.join("hardlink");
    let symlink_path = probe_root.join("symlink");
    let reflink_path = probe_root.join("reflink");
    let copy_path = probe_root.join("copy");

    let source_created = io.write(&source, b"fitctl-link-probe\n");
    if let Err(error) = source_created {
        result.hardlink_supported = observed(false);
        result.reflink_supported = observed(false);
        result.symlink_supported = observed(false);
        result.copy_possible = observed(false);
        result.probe_error = Some(format!("failed to create probe file: {error}"));
        result.cleanup = Some(vec![remove_owned(io, &probe_root)]);
        return result;
    }

    result.hardlink_supported = observed(fs::hard_link(&source, &hardlink).is_ok());
    result.symlink_supported = observed(symlink(&source, &symlink_path).is_ok());
    result.copy_possible = observed(fs::copy(&source, &copy_path).is_ok());
    result.reflink_supported = observed(try_reflink(&source, &reflink_path).unwrap_or(false));

    result.cleanup = Some(vec![remove_owned(io, &probe_root)]);
    result
}

pub(super) fn probe_path_link_pair_capabilities(
    from_path_id: &str,
    from_path: &Path,
    to_path_id: &str,
    to_path: &Path,
    observed_at: &str,
) -> HostStatePathLinkPairV1 {
    probe_pair(
        from_path_id,
        from_path,
        to_path_id,
        to_path,
        observed_at,
        &LocalProbeIo,
    )
}

fn probe_pair(
    from_path_id: &str,
    from_path: &Path,
    to_path_id: &str,
    to_path: &Path,
    observed_at: &str,
    io: &impl ProbeIo,
) -> HostStatePathLinkPairV1 {
    let mut result = HostStatePathLinkPairV1 {
        cleanup: Some(Vec::new()),
        pair_id: format!("{from_path_id}-to-{to_path_id}"),
        from_path_id: from_path_id.to_string(),
        to_path_id: to_path_id.to_string(),
        same_filesystem: same_filesystem_field(from_path, to_path),
        hardlink_supported: observed(false),
        reflink_supported: observed(false),
        symlink_supported: observed(false),
        copy_possible: observed(false),
        probe_method: Some("temporary-files-under-checked-path-pair".to_string()),
        probe_error: None,
        observed_at: Some(observed_at.to_string()),
    };

    if !from_path.is_dir() || !to_path.is_dir() {
        result.probe_error =
            Some("both checked paths must be existing directories for pair probes".to_string());
        return result;
    }

    let probe_suffix = io.suffix(".fitctl-link-pair-probe-");
    let from_probe_root = from_path.join(format!("{probe_suffix}-source"));
    let to_probe_root = to_path.join(format!("{probe_suffix}-destination"));
    result.cleanup = Some(vec![uncreated(&from_probe_root), uncreated(&to_probe_root)]);

    if let Err(error) = io.create_dir(&from_probe_root) {
        result.probe_error = Some(format!("failed to create source probe root: {error}"));
        return result;
    }
    if let Err(error) = io.create_dir(&to_probe_root) {
        result.probe_error = Some(format!("failed to create destination probe root: {error}"));
        result.cleanup = Some(vec![
            remove_owned(io, &from_probe_root),
            uncreated(&to_probe_root),
        ]);
        return result;
    }

    let source = from_probe_root.join("source");
    let hardlink = to_probe_root.join("hardlink");
    let symlink_path = to_probe_root.join("symlink");
    let reflink_path = to_probe_root.join("reflink");
    let copy_path = to_probe_root.join("copy");

    if let Err(error) = io.write(&source, b"fitctl-link-pair-probe\n") {
        result.probe_error = Some(format!("failed to create pair probe file: {error}"));
        result.cleanup = Some(vec![
            remove_owned(io, &from_probe_root),
            remove_owned(io, &to_probe_root),
        ]);
        return result;
    }

    result.hardlink_supported = observed(fs::hard_link(&source, &hardlink).is_ok());
    result.symlink_supported = observed(symlink(&source, &symlink_path).is_ok());
    result.copy_possible = observed(fs::copy(&source, &copy_path).is_ok());
    result.reflink_supported = observed(try_reflink(&source, &reflink_path).unwrap_or(false));

    result.cleanup = Some(vec![
        remove_owned(io, &from_probe_root),
        remove_owned(io, &to_probe_root),
    ]);
    result
}

fn same_filesystem_field(left: &Path, right: &Path) -> StateFieldV1<bool> {
    match (fs::metadata(left), fs::metadata(right)) {
        (Ok(left), Ok(right)) => observed(left.dev() == right.dev()),
        _ => unknown(),
    }
}

#[cfg(target_os = "linux")]
fn try_reflink(source: &Path, destination: &Path) -> Option<bool> {
    const FICLONE: libc::c_ulong = 0x4004_9409;
    let source_file = File::open(source).ok()?;
    let destination_file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(destination)
        .ok()?;
    let result = unsafe {
        libc::ioctl(
            destination_file.as_raw_fd(),
            FICLONE,
            source_file.as_raw_fd(),
        )
    };
    Some(result == 0)
}

#[cfg(not(target_os = "linux"))]
fn try_reflink(_source: &Path, _destination: &Path) -> Option<bool> {
    Some(false)
}

#[cfg(test)]
#[path = "path_link_probe_tests.rs"]
mod tests;
