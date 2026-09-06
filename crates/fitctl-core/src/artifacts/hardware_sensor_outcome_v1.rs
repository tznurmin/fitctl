// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

//! One outcome basis for emitted and imported sensor evidence.

use super::hardware_sensor_resources_v1::*;
use super::state_v1::StateEvidenceProviderOutcomeV1 as Outcome;

pub(crate) fn reading_complete(r: &HardwareSensorReadingV1) -> bool {
    r.value_state == HardwareSensorValueStateV1::Observed
        && r.limits
            .iter()
            .all(|l| l.value_state == HardwareSensorValueStateV1::Observed)
        && r.flags.iter().all(|f| {
            matches!(
                f.state,
                HardwareSensorFlagStateV1::Clear | HardwareSensorFlagStateV1::Asserted
            )
        })
}

pub(crate) fn projection_outcome(
    readings: &[&HardwareSensorReadingV1],
) -> (Outcome, Option<HardwareSensorReasonV1>) {
    use HardwareSensorReasonV1::*;
    if readings.is_empty() {
        return (Outcome::Partial, Some(HardwareSensorNoSupportedReadings));
    }
    if readings.iter().all(|r| reading_complete(r)) {
        return (Outcome::Success, None);
    }
    let any_useful = readings.iter().any(|r| {
        r.value.is_some()
            || r.limits.iter().any(|l| l.value.is_some())
            || r.flags.iter().any(|f| {
                matches!(
                    f.state,
                    HardwareSensorFlagStateV1::Clear | HardwareSensorFlagStateV1::Asserted
                )
            })
    });
    let malformed = !any_useful
        && readings
            .iter()
            .all(|r| r.value_state == HardwareSensorValueStateV1::Malformed);
    // Selection must survive reordered inputs and redacted sensor identities.
    let reason = readings
        .iter()
        .flat_map(|r| {
            r.reason_code
                .into_iter()
                .chain(r.limits.iter().filter_map(|v| v.reason_code))
                .chain(r.flags.iter().filter_map(|v| v.reason_code))
        })
        .min_by_key(|reason| format!("{reason:?}"));
    (
        if malformed {
            Outcome::Malformed
        } else {
            Outcome::Partial
        },
        reason,
    )
}

pub(crate) fn provider_consistent(
    p: &HardwareSensorProviderV1,
    rs: &[&HardwareSensorReadingV1],
) -> bool {
    use HardwareSensorReasonV1::*;
    if !rs.is_empty() || p.outcome == Outcome::Partial {
        return (p.outcome, p.reason_code) == projection_outcome(rs);
    }
    matches!(
        (p.outcome, p.reason_code),
        (Outcome::Unavailable, Some(HardwareSensorSourceUnavailable))
            | (
                Outcome::PermissionDenied,
                Some(HardwareSensorPermissionDenied)
            )
            | (
                Outcome::CommandFailed,
                Some(
                    HardwareSensorCommandFailed | HardwareSensorTimeout | HardwareSensorOutputLimit
                )
            )
            | (
                Outcome::Malformed,
                Some(
                    HardwareSensorJsonMalformed
                        | HardwareSensorDuplicateKey
                        | HardwareSensorStructureLimit
                        | HardwareSensorIdentityMismatch
                        | HardwareSensorSchemaInvalid
                        | HardwareSensorOutputLimit
                )
            )
    )
}
