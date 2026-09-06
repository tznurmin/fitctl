// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

use crate::{cli, common};
use std::{fs, path::PathBuf, process::Command};

pub(crate) struct Fixture(pub(crate) PathBuf);
impl Fixture {
    pub(crate) fn new() -> Self {
        Self(common::unique_temp_dir("hardware-sensors"))
    }
    pub(crate) fn script(&self, name: &str, body: &str) {
        self.script_with_mode(name, body, 0o700);
    }
    pub(crate) fn script_with_mode(&self, name: &str, body: &str, mode: u32) {
        common::fixture_command::write(&common::repo_root(), &self.0, name, body, mode).unwrap();
    }
    pub(crate) fn command(&self) -> Command {
        let mut command = Command::new(cli::fitctl_bin());
        command
            .env("PATH", &self.0)
            .env("SENSOR_COUNT", self.0.join("count"));
        command
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
