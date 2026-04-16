// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

//! Pinned verdict and reason-code registries for validation reports.

use crate::artifacts::validation_report_v1::{ValidationReasonCodeV1, ValidationVerdictV1};

pub const VALIDATION_VERDICTS_V1: [ValidationVerdictV1; 4] = [
    ValidationVerdictV1::Fit,
    ValidationVerdictV1::FitWithDegradation,
    ValidationVerdictV1::Unfit,
    ValidationVerdictV1::Indeterminate,
];

pub const VALIDATION_REASON_CODES_V1: [ValidationReasonCodeV1; 16] = [
    ValidationReasonCodeV1::RequirementsSatisfied,
    ValidationReasonCodeV1::RequirementUnsatisfied,
    ValidationReasonCodeV1::CapabilityUnknown,
    ValidationReasonCodeV1::StateMissing,
    ValidationReasonCodeV1::StateStale,
    ValidationReasonCodeV1::AssurancePredicateUnresolved,
    ValidationReasonCodeV1::AssuranceSourceNotAccepted,
    ValidationReasonCodeV1::AssuranceDerivationStageNotAccepted,
    ValidationReasonCodeV1::PolicyNotAdmissible,
    ValidationReasonCodeV1::NetworkMismatch,
    ValidationReasonCodeV1::TopologyMismatch,
    ValidationReasonCodeV1::CapabilityDegraded,
    ValidationReasonCodeV1::DegradationPathRequired,
    ValidationReasonCodeV1::DegradationPathUnavailable,
    ValidationReasonCodeV1::EvidenceIncomplete,
    ValidationReasonCodeV1::ValidationBlocked,
];
