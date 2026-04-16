// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

//! Shared execution-context and observation-state types used by survey and state artifacts.

use serde::de::{self, Deserializer};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservationStateV1 {
    Observed,
    Missing,
    Unknown,
    PartiallyObserved,
    HiddenByPrivilegeOrVisibility,
    NotApplicable,
}

impl ObservationStateV1 {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Observed => "observed",
            Self::Missing => "missing",
            Self::Unknown => "unknown",
            Self::PartiallyObserved => "partially_observed",
            Self::HiddenByPrivilegeOrVisibility => "hidden_by_privilege_or_visibility",
            Self::NotApplicable => "not_applicable",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservationLimitationReasonV1 {
    CollectorLimitation,
    PrivilegeOrVisibilityLimit,
    ParserLimitation,
    UnsupportedHardware,
    SourceUnavailable,
    SourceError,
}

impl ObservationLimitationReasonV1 {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CollectorLimitation => "collector_limitation",
            Self::PrivilegeOrVisibilityLimit => "privilege_or_visibility_limit",
            Self::ParserLimitation => "parser_limitation",
            Self::UnsupportedHardware => "unsupported_hardware",
            Self::SourceUnavailable => "source_unavailable",
            Self::SourceError => "source_error",
        }
    }
}

pub fn deserialize_observation_limitation_reason_opt_v1<'de, D>(
    deserializer: D,
) -> Result<Option<ObservationLimitationReasonV1>, D::Error>
where
    D: Deserializer<'de>,
{
    match serde_json::Value::deserialize(deserializer)? {
        serde_json::Value::Null => Err(de::Error::custom(
            "limitation_reason must be omitted rather than null",
        )),
        value => ObservationLimitationReasonV1::deserialize(value)
            .map(Some)
            .map_err(de::Error::custom),
    }
}

pub fn validate_observation_field_coherence_v1<T>(
    state: &ObservationStateV1,
    limitation_reason: Option<&ObservationLimitationReasonV1>,
    value: Option<&T>,
    validate_value: impl FnOnce(&T) -> bool,
) -> Result<(), &'static str> {
    match state {
        ObservationStateV1::Observed => {
            if limitation_reason.is_some() {
                return Err("is observed but still carries a limitation reason");
            }
            match value {
                Some(value) if validate_value(value) => Ok(()),
                Some(_) => Err("contains an invalid observed value"),
                None => Err("is observed but has no value"),
            }
        }
        ObservationStateV1::PartiallyObserved => match value {
            Some(value) if validate_value(value) => Ok(()),
            Some(_) => Err("contains an invalid observed value"),
            None => Ok(()),
        },
        ObservationStateV1::Missing | ObservationStateV1::Unknown => {
            if value.is_some() {
                Err("is incomplete but still carries a concrete value")
            } else {
                Ok(())
            }
        }
        ObservationStateV1::HiddenByPrivilegeOrVisibility => {
            if value.is_some() {
                return Err(
                    "is hidden by privilege or visibility but still carries a concrete value",
                );
            }
            if limitation_reason.is_some_and(|reason| {
                *reason != ObservationLimitationReasonV1::PrivilegeOrVisibilityLimit
            }) {
                return Err(
                    "is hidden by privilege or visibility but carries a non-visibility limitation reason",
                );
            }
            Ok(())
        }
        ObservationStateV1::NotApplicable => {
            if value.is_some() {
                return Err("is not_applicable but still carries a concrete value");
            }
            if limitation_reason.is_some() {
                return Err("is not_applicable but still carries a limitation reason");
            }
            Ok(())
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VisibilityScopeV1 {
    BareMetalLike,
    VmLike,
    ContainerRestricted,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivilegeLevelV1 {
    Full,
    Limited,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionContextV1 {
    pub visibility_scope: VisibilityScopeV1,
    pub privilege_level: PrivilegeLevelV1,
    pub container_runtime: Option<String>,
    #[serde(default)]
    pub notes: Vec<String>,
}
