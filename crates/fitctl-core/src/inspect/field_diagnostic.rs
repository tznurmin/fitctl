// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

//! Shared inspect helpers for field-local diagnostics.

use crate::artifacts::field_diagnostic_v1::FieldDiagnosticV1;

pub fn format_missing_field_diagnostic_for_inspect(diagnostic: &FieldDiagnosticV1) -> String {
    format!(
        "missing; {} {}; {} via {}",
        diagnostic.source_tier.as_str(),
        diagnostic.source_kind.as_str(),
        diagnostic.status.as_str(),
        diagnostic.source_ref
    )
}
