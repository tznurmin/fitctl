// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

//! Typed top-level artifact families and shared artifact plumbing.
//!
//! This module owns the stable document shapes that the rest of the tool reads, emits, signs,
//! diffs, redacts, and inspects.

pub mod batch_classification_report_v1;
pub mod config_bundle_v1;
pub mod contract_v1;
pub mod decision_bundle_v1;
pub mod envelope_v1;
pub mod metadata_v1;
pub mod recommendation_report_v1;
pub mod record_v1;
pub mod schema_ids_v1;
pub mod semantic_hash_v1;
pub mod service_profile_v1;
pub mod state_v1;
pub mod survey_v1;
pub mod validation_report_v1;
pub mod validation_v1;
