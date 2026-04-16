// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

//! Bootstrap-level errors returned before command-specific parsing or execution takes over.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootstrapErrorCode {
    UnknownCommand,
    NotImplemented,
}
