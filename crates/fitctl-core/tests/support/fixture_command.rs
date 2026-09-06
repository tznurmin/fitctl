// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{symlink, OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};

pub fn body_path(command: &Path) -> PathBuf {
    let mut path = command.as_os_str().to_owned();
    path.push(".body");
    PathBuf::from(path)
}

/// Publish a test command without executing a runtime-written inode. The caller owns `root`.
pub fn write(repo: &Path, root: &Path, name: &str, body: &str, mode: u32) -> io::Result<PathBuf> {
    let components: Vec<_> = Path::new(name).components().collect();
    if !matches!(components.as_slice(), [Component::Normal(_)])
        || Path::new(name).file_name() != Some(name.as_ref())
        || mode & !0o777 != 0
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid fixture command name or mode",
        ));
    }
    let shim = repo.join("crates/fitctl-core/tests/fixtures/provider-command.sh");
    let shim = shim.canonicalize()?;
    if !shim.is_file() || fs::metadata(&shim)?.permissions().mode() & 0o111 == 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "fixture shim is not executable",
        ));
    }
    let command = root.join(name);
    match command.symlink_metadata() {
        Ok(_) => {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "fixture command exists",
            ))
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => (),
        Err(error) => return Err(error),
    }
    let payload = body_path(&command);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&payload)?;
    let result = (|| {
        writeln!(file, "{body}")?;
        drop(file);
        if mode & 0o111 == 0 {
            // Real permission-negative executable lookup, not a shell-simulated error.
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(mode)
                .open(&command)?;
        } else {
            symlink(shim, &command)?;
        }
        Ok(command)
    })();
    if result.is_err() {
        let _ = fs::remove_file(payload);
    }
    result
}
