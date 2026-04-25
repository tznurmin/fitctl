// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

//! Replay fixture loading for host-survey snapshots.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::fixtures::FixtureCoverageTagV1;
use crate::identity::{fixture_identity_input_v2, select_live_linux_identity_input_v2};
use crate::survey::execution_context_v1::VisibilityScopeV1;
use crate::survey::live_v1::{CollectedHostSnapshotV1, SnapshotSourceKindV1, SurveyObservationsV1};
use crate::survey::{ExecutionContextV1, SurveyError, SurveyErrorCode};

pub const FIXTURE_CORPUS_SCHEMA_ID: &str = "fitctl.fixture.host_survey.corpus.v1";
pub const FIXTURE_SNAPSHOT_SCHEMA_ID: &str = "fitctl.fixture.host_survey.snapshot.v1";
pub const FIXTURE_MANIFEST_FILE_NAME: &str = "manifest.v1.json";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FixtureCorpusManifestV1 {
    pub schema_id: String,
    pub schema_version: u32,
    pub corpus_id: String,
    pub fixtures: Vec<FixtureCorpusEntryV1>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FixtureCorpusEntryV1 {
    pub fixture_id: String,
    pub path: String,
    pub execution_context: VisibilityScopeV1,
    #[serde(default)]
    pub coverage_tags: Vec<FixtureCoverageTagV1>,
    #[serde(default)]
    pub related_state_fixtures: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SurveyFixtureSnapshotV1 {
    pub schema_id: String,
    pub schema_version: u32,
    pub fixture_id: String,
    pub collected_at: String,
    pub host_alias: String,
    pub execution_context: ExecutionContextV1,
    pub collectors: Vec<String>,
    #[serde(default)]
    pub local_stable_identity_inputs_v2: Option<ReplayLocalStableIdentityInputsV1>,
    #[serde(default)]
    pub identity_summary: Option<serde_json::Value>,
    pub observations: SurveyObservationsV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplayLocalStableIdentityInputsV1 {
    #[serde(default)]
    pub etc_machine_id: Option<String>,
    #[serde(default)]
    pub dbus_machine_id: Option<String>,
    #[serde(default)]
    pub dmi_product_uuid: Option<String>,
    #[serde(default)]
    pub kernel_hostname: Option<String>,
}

/// Load the host-survey replay corpus manifest rooted at the given fixtures directory.
pub fn load_fixture_corpus_manifest(
    fixtures_root: &Path,
) -> Result<FixtureCorpusManifestV1, SurveyError> {
    let manifest_path = fixtures_root.join(FIXTURE_MANIFEST_FILE_NAME);
    let text = fs::read_to_string(&manifest_path).map_err(|error| {
        SurveyError::new(
            SurveyErrorCode::FixtureCorpusInvalid,
            "fixture_load",
            format!(
                "failed to read fixture manifest {}: {error}",
                manifest_path.display()
            ),
        )
    })?;

    let manifest: FixtureCorpusManifestV1 = serde_json::from_str(&text).map_err(|error| {
        SurveyError::new(
            SurveyErrorCode::FixtureCorpusInvalid,
            "fixture_load",
            format!(
                "failed to decode fixture manifest {}: {error}",
                manifest_path.display()
            ),
        )
    })?;

    validate_manifest(&manifest)?;
    Ok(manifest)
}

pub(crate) fn load_snapshot_from_corpus(
    fixtures_root: &Path,
    fixture_id: &str,
) -> Result<CollectedHostSnapshotV1, SurveyError> {
    let manifest = load_fixture_corpus_manifest(fixtures_root)?;
    let entry = manifest
        .fixtures
        .iter()
        .find(|entry| entry.fixture_id == fixture_id)
        .ok_or_else(|| {
            SurveyError::new(
                SurveyErrorCode::FixtureCorpusInvalid,
                "fixture_load",
                format!("fixture id {fixture_id} is not present in the selected corpus"),
            )
        })?;

    let fixture_path = resolve_fixture_path(fixtures_root, &entry.path)?;
    let text = fs::read_to_string(&fixture_path).map_err(|error| {
        SurveyError::new(
            SurveyErrorCode::CollectorPayloadMalformed,
            "fixture_load",
            format!("failed to read fixture {}: {error}", fixture_path.display()),
        )
    })?;
    let snapshot: SurveyFixtureSnapshotV1 = serde_json::from_str(&text).map_err(|error| {
        SurveyError::new(
            SurveyErrorCode::CollectorPayloadMalformed,
            "collector_parse",
            format!(
                "failed to decode fixture {}: {error}",
                fixture_path.display()
            ),
        )
    })?;

    validate_snapshot(&snapshot, entry)?;

    let mut execution_context = snapshot.execution_context.clone();
    let local_stable_identity_input =
        if let Some(identity_inputs) = snapshot.local_stable_identity_inputs_v2.as_ref() {
            let selection = select_live_linux_identity_input_v2(
                identity_inputs.etc_machine_id.as_deref(),
                identity_inputs.dbus_machine_id.as_deref(),
                identity_inputs.dmi_product_uuid.as_deref(),
                identity_inputs.kernel_hostname.as_deref(),
            );
            execution_context.notes.extend(selection.notes);
            selection.input
        } else {
            fixture_identity_input_v2(&manifest.corpus_id, &snapshot.host_alias)
        };

    Ok(CollectedHostSnapshotV1 {
        source_kind: SnapshotSourceKindV1::Replay {
            corpus_id: manifest.corpus_id.clone(),
        },
        provenance_source: format!("fixture_corpus:{}", manifest.corpus_id),
        snapshot_id: snapshot.fixture_id.clone(),
        collected_at: snapshot.collected_at.clone(),
        host_alias: snapshot.host_alias.clone(),
        local_stable_identity_input,
        execution_context,
        collectors: snapshot.collectors.clone(),
        observations: snapshot.observations.clone(),
    })
}

fn validate_manifest(manifest: &FixtureCorpusManifestV1) -> Result<(), SurveyError> {
    if manifest.schema_id != FIXTURE_CORPUS_SCHEMA_ID
        || manifest.schema_version != 1
        || manifest.corpus_id.trim().is_empty()
        || manifest.fixtures.is_empty()
    {
        return Err(SurveyError::new(
            SurveyErrorCode::FixtureCorpusInvalid,
            "fixture_load",
            "fixture corpus manifest must declare the supported schema and at least one fixture",
        ));
    }

    let mut ids = BTreeSet::new();
    for fixture in &manifest.fixtures {
        if fixture.fixture_id.trim().is_empty()
            || fixture.path.trim().is_empty()
            || Path::new(&fixture.path).is_absolute()
            || !ids.insert(fixture.fixture_id.clone())
        {
            return Err(SurveyError::new(
                SurveyErrorCode::FixtureCorpusInvalid,
                "fixture_load",
                "fixture manifest contains duplicate ids or invalid paths",
            ));
        }

        let mut coverage_tags = BTreeSet::new();
        for tag in &fixture.coverage_tags {
            if !coverage_tags.insert(*tag) {
                return Err(SurveyError::new(
                    SurveyErrorCode::FixtureCorpusInvalid,
                    "fixture_load",
                    "fixture manifest contains duplicate coverage tags",
                ));
            }
        }

        let mut related_state_fixtures = BTreeSet::new();
        for related_fixture_id in &fixture.related_state_fixtures {
            if related_fixture_id.trim().is_empty()
                || !related_state_fixtures.insert(related_fixture_id.clone())
            {
                return Err(SurveyError::new(
                    SurveyErrorCode::FixtureCorpusInvalid,
                    "fixture_load",
                    "fixture manifest contains invalid related state fixture ids",
                ));
            }
        }
    }

    Ok(())
}

fn validate_snapshot(
    snapshot: &SurveyFixtureSnapshotV1,
    entry: &FixtureCorpusEntryV1,
) -> Result<(), SurveyError> {
    if snapshot.schema_id != FIXTURE_SNAPSHOT_SCHEMA_ID
        || snapshot.schema_version != 1
        || snapshot.fixture_id != entry.fixture_id
        || snapshot.host_alias.trim().is_empty()
        || snapshot.collected_at.trim().is_empty()
        || snapshot.collectors.is_empty()
    {
        return Err(SurveyError::new(
            SurveyErrorCode::CollectorPayloadMalformed,
            "collector_parse",
            "fixture snapshot must declare the supported schema and required fields",
        ));
    }

    if snapshot.execution_context.visibility_scope != entry.execution_context {
        return Err(SurveyError::new(
            SurveyErrorCode::CollectorPayloadMalformed,
            "collector_parse",
            "fixture execution context must match the manifest entry",
        ));
    }

    Ok(())
}

fn resolve_fixture_path(fixtures_root: &Path, relative_path: &str) -> Result<PathBuf, SurveyError> {
    let canonical_root = fs::canonicalize(fixtures_root).map_err(|error| {
        SurveyError::new(
            SurveyErrorCode::FixtureCorpusInvalid,
            "fixture_resolve",
            format!(
                "failed to resolve fixture corpus root {}: {error}",
                fixtures_root.display()
            ),
        )
    })?;

    let candidate = canonical_root.join(relative_path);
    let canonical_candidate = fs::canonicalize(&candidate).map_err(|error| {
        SurveyError::new(
            SurveyErrorCode::FixturePathInvalid,
            "fixture_resolve",
            format!(
                "failed to resolve fixture path {}: {error}",
                candidate.display()
            ),
        )
    })?;

    if !canonical_candidate.starts_with(&canonical_root) {
        return Err(SurveyError::new(
            SurveyErrorCode::FixturePathInvalid,
            "fixture_resolve",
            "fixture path escapes the selected corpus root",
        ));
    }

    Ok(canonical_candidate)
}
