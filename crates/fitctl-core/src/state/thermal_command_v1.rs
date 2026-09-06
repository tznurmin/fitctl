// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

//! Bounded provider subprocess execution without blocking pipe readers.

#[cfg(unix)]
use std::io;
use std::process::Output;

#[cfg(unix)]
use std::{
    io::Read,
    os::fd::AsRawFd,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

use crate::artifacts::categorical_values_v1::THERMAL_PROVIDER_UNAVAILABLE;
#[cfg(unix)]
use crate::artifacts::categorical_values_v1::{
    THERMAL_PROVIDER_COMMAND_FAILED, THERMAL_PROVIDER_COMMAND_TIMEOUT,
    THERMAL_PROVIDER_PERMISSION_DENIED,
};
use crate::artifacts::state_v1::ThermalProviderOutcomeV1;

#[cfg(unix)]
use super::thermal_config_v1::DEFAULT_PROVIDER_TIMEOUT_SECONDS;
use super::ThermalProviderConfigEntryV1;

pub(super) const MAX_PROVIDER_OUTPUT_BYTES: usize = 1_048_576;
#[cfg(unix)]
const MAX_PROVIDER_STDERR_BYTES: usize = 4096;

#[derive(Debug, Clone)]
pub(crate) struct ProviderFailure {
    pub(crate) outcome: ThermalProviderOutcomeV1,
    pub(crate) error_code: &'static str,
    pub(crate) diagnostics: String,
}

#[cfg(unix)]
pub(crate) fn run_provider_command(
    provider: &ThermalProviderConfigEntryV1,
) -> Result<Output, ProviderFailure> {
    let (program, args) = provider.command.split_first().ok_or_else(|| {
        capture_error(io::Error::new(
            io::ErrorKind::InvalidInput,
            "provider command is empty",
        ))
    })?;
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(provider_spawn_error)?;
    let timeout = Duration::from_secs(
        provider
            .timeout_seconds
            .unwrap_or(DEFAULT_PROVIDER_TIMEOUT_SECONDS),
    );
    let result = capture_output(&mut child, timeout);
    if result.is_err() {
        // Keep the caller's process-group ownership. Close pipes without joining readers, then
        // kill/reap only this direct child; inherited writers cannot extend the capture deadline.
        let _ = child.kill();
        let _ = child.wait();
    }
    result.map_err(capture_error)
}

#[cfg(not(unix))]
pub(crate) fn run_provider_command(
    _provider: &ThermalProviderConfigEntryV1,
) -> Result<Output, ProviderFailure> {
    Err(ProviderFailure {
        outcome: ThermalProviderOutcomeV1::Unavailable,
        error_code: THERMAL_PROVIDER_UNAVAILABLE,
        diagnostics: "bounded thermal provider execution requires Unix pipes".to_string(),
    })
}

#[cfg(unix)]
fn capture_output(child: &mut Child, timeout: Duration) -> io::Result<Output> {
    let started = Instant::now();
    let mut stdout = child
        .stdout
        .take()
        .ok_or_else(|| io::Error::other("missing provider stdout pipe"))?;
    let mut stderr = child
        .stderr
        .take()
        .ok_or_else(|| io::Error::other("missing provider stderr pipe"))?;
    set_nonblocking(&stdout)?;
    set_nonblocking(&stderr)?;
    // The extra stdout byte preserves overflow rejection without retaining arbitrary output.
    let mut out = BoundedCapture::new(MAX_PROVIDER_OUTPUT_BYTES + 1);
    let mut err = BoundedCapture::new(MAX_PROVIDER_STDERR_BYTES);
    let mut status = None;

    loop {
        if started.elapsed() >= timeout {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "provider command timed out",
            ));
        }
        if status.is_none() {
            status = child.try_wait()?;
        }
        let stdout_progress = out.drain_available(&mut stdout)?;
        let stderr_progress = err.drain_available(&mut stderr)?;
        if let Some(status) = status {
            if out.eof && err.eof {
                return Ok(Output {
                    status,
                    stdout: out.bytes,
                    stderr: err.bytes,
                });
            }
        }
        if !stdout_progress && !stderr_progress {
            std::thread::sleep(
                Duration::from_millis(10).min(timeout.saturating_sub(started.elapsed())),
            );
        }
    }
}

#[cfg(unix)]
fn set_nonblocking(pipe: &impl AsRawFd) -> io::Result<()> {
    let fd = pipe.as_raw_fd();
    // These descriptors are owned child pipes. Preserve existing flags and change only their
    // parent-side read behavior; no borrowed descriptor is closed or transferred here.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags == -1 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(unix)]
struct BoundedCapture {
    bytes: Vec<u8>,
    limit: usize,
    eof: bool,
}

#[cfg(unix)]
impl BoundedCapture {
    fn new(limit: usize) -> Self {
        Self {
            bytes: Vec::with_capacity(limit),
            limit,
            eof: false,
        }
    }

    fn drain_available(&mut self, input: &mut impl Read) -> io::Result<bool> {
        if self.eof {
            return Ok(false);
        }
        let mut progress = false;
        let mut chunk = [0_u8; 8192];
        // Budget every turn so a continuously writing stream cannot starve the other stream,
        // process observation, or the deadline. Discard excess bytes but keep draining them.
        for _ in 0..8 {
            match input.read(&mut chunk) {
                Ok(0) => {
                    self.eof = true;
                    return Ok(true);
                }
                Ok(count) => {
                    let retain = count.min(self.limit - self.bytes.len());
                    self.bytes.extend_from_slice(&chunk[..retain]);
                    progress = true;
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error),
            }
        }
        Ok(progress)
    }
}

#[cfg(unix)]
fn provider_spawn_error(error: io::Error) -> ProviderFailure {
    match error.kind() {
        io::ErrorKind::NotFound => ProviderFailure {
            outcome: ThermalProviderOutcomeV1::Unavailable,
            error_code: THERMAL_PROVIDER_UNAVAILABLE,
            diagnostics: "provider command was not found".to_string(),
        },
        io::ErrorKind::PermissionDenied => ProviderFailure {
            outcome: ThermalProviderOutcomeV1::PermissionDenied,
            error_code: THERMAL_PROVIDER_PERMISSION_DENIED,
            diagnostics: "provider command permission denied".to_string(),
        },
        _ => ProviderFailure {
            outcome: ThermalProviderOutcomeV1::CommandFailed,
            error_code: THERMAL_PROVIDER_COMMAND_FAILED,
            diagnostics: format!("failed to start provider command: {error}"),
        },
    }
}

#[cfg(unix)]
fn capture_error(error: io::Error) -> ProviderFailure {
    let timed_out = error.kind() == io::ErrorKind::TimedOut;
    ProviderFailure {
        outcome: ThermalProviderOutcomeV1::CommandFailed,
        error_code: if timed_out {
            THERMAL_PROVIDER_COMMAND_TIMEOUT
        } else {
            THERMAL_PROVIDER_COMMAND_FAILED
        },
        diagnostics: if timed_out {
            "provider command timed out".to_string()
        } else {
            format!("failed to collect provider output: {error}")
        },
    }
}

#[cfg(all(test, unix))]
#[path = "thermal_command_tests.rs"]
mod tests;
