// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

//! Shared field-local diagnostic companion metadata.
//!
//! This module owns the reusable typed companion shape used by important reported values when
//! they need explicit source and probe-lineage detail beyond ordinary observed/missing state.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FieldDiagnosticSourceTierV1 {
    Primary,
    AdvisoryFallback,
}

impl FieldDiagnosticSourceTierV1 {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Primary => "primary",
            Self::AdvisoryFallback => "advisory_fallback",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FieldDiagnosticSourceKindV1 {
    CommandProbe,
    FileProbe,
    DynamicLibraryProbe,
    AdvisoryCommandProbe,
}

impl FieldDiagnosticSourceKindV1 {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CommandProbe => "command_probe",
            Self::FileProbe => "file_probe",
            Self::DynamicLibraryProbe => "dynamic_library_probe",
            Self::AdvisoryCommandProbe => "advisory_command_probe",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FieldDiagnosticProbeStatusV1 {
    Observed,
    SourceUnavailable,
    SourceUnreadable,
    ProbeFailed,
    LibraryUnavailable,
    SymbolUnavailable,
}

impl FieldDiagnosticProbeStatusV1 {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Observed => "observed",
            Self::SourceUnavailable => "source_unavailable",
            Self::SourceUnreadable => "source_unreadable",
            Self::ProbeFailed => "probe_failed",
            Self::LibraryUnavailable => "library_unavailable",
            Self::SymbolUnavailable => "symbol_unavailable",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FieldDiagnosticV1 {
    pub source_tier: FieldDiagnosticSourceTierV1,
    pub source_kind: FieldDiagnosticSourceKindV1,
    pub source_ref: String,
    #[serde(rename = "probe_status", alias = "status")]
    pub status: FieldDiagnosticProbeStatusV1,
}
