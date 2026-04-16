// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

//! Replay fixture loading for host-state snapshots.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::artifacts::state_v1::{
    HostRuntimeResourcesV1, HostStateExecutionBoundariesV1, HostStateOperabilityV1,
    HostStateTopologyV1, StateFreshnessV1,
};
use crate::fixtures::FixtureCoverageTagV1;
use crate::state::live_v1::{CollectedHostStateSnapshotV1, SnapshotSourceKindV1};
use crate::state::{StateError, StateErrorCode};

pub const FIXTURE_CORPUS_SCHEMA_ID: &str = "fitctl.fixture.host_state.corpus.v1";
pub const FIXTURE_SNAPSHOT_SCHEMA_ID: &str = "fitctl.fixture.host_state.snapshot.v1";
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
    #[serde(default)]
    pub coverage_tags: Vec<FixtureCoverageTagV1>,
    #[serde(default)]
    pub related_survey_fixtures: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostStateFixtureSnapshotV1 {
    pub schema_id: String,
    pub schema_version: u32,
    pub fixture_id: String,
    pub collected_at: String,
    pub host_alias: String,
    pub collectors: Vec<String>,
    pub freshness: StateFreshnessV1,
    pub resources: HostRuntimeResourcesV1,
    #[serde(default)]
    pub boundaries: HostStateExecutionBoundariesV1,
    #[serde(default)]
    pub topology: HostStateTopologyV1,
    #[serde(default)]
    pub operability: HostStateOperabilityV1,
}

/// Load the host-state replay corpus manifest rooted at the given fixtures directory.
pub fn load_fixture_corpus_manifest(
    fixtures_root: &Path,
) -> Result<FixtureCorpusManifestV1, StateError> {
    let manifest_path = fixtures_root.join(FIXTURE_MANIFEST_FILE_NAME);
    let text = fs::read_to_string(&manifest_path).map_err(|error| {
        StateError::new(
            StateErrorCode::FixtureCorpusInvalid,
            "fixture_load",
            format!(
                "failed to read state fixture manifest {}: {error}",
                manifest_path.display()
            ),
        )
    })?;

    let manifest: FixtureCorpusManifestV1 = serde_json::from_str(&text).map_err(|error| {
        StateError::new(
            StateErrorCode::FixtureCorpusInvalid,
            "fixture_load",
            format!(
                "failed to decode state fixture manifest {}: {error}",
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
) -> Result<CollectedHostStateSnapshotV1, StateError> {
    let manifest = load_fixture_corpus_manifest(fixtures_root)?;
    let entry = manifest
        .fixtures
        .iter()
        .find(|entry| entry.fixture_id == fixture_id)
        .ok_or_else(|| {
            StateError::new(
                StateErrorCode::FixtureCorpusInvalid,
                "fixture_load",
                format!("fixture id {fixture_id} is not present in the selected corpus"),
            )
        })?;

    let fixture_path = resolve_fixture_path(fixtures_root, &entry.path)?;
    let text = fs::read_to_string(&fixture_path).map_err(|error| {
        StateError::new(
            StateErrorCode::StatePayloadMalformed,
            "fixture_load",
            format!(
                "failed to read state fixture {}: {error}",
                fixture_path.display()
            ),
        )
    })?;
    let snapshot: HostStateFixtureSnapshotV1 = serde_json::from_str(&text).map_err(|error| {
        StateError::new(
            StateErrorCode::StatePayloadMalformed,
            "state_parse",
            format!(
                "failed to decode state fixture {}: {error}",
                fixture_path.display()
            ),
        )
    })?;

    validate_snapshot(&snapshot, entry)?;

    Ok(CollectedHostStateSnapshotV1 {
        source_kind: SnapshotSourceKindV1::Replay {
            corpus_id: manifest.corpus_id.clone(),
        },
        provenance_source: format!("fixture_corpus:{}", manifest.corpus_id),
        snapshot_id: snapshot.fixture_id.clone(),
        collected_at: snapshot.collected_at.clone(),
        host_alias: snapshot.host_alias.clone(),
        collectors: snapshot.collectors.clone(),
        freshness: snapshot.freshness.clone(),
        resources: snapshot.resources.clone(),
        boundaries: snapshot.boundaries.clone(),
        topology: snapshot.topology.clone(),
        operability: snapshot.operability.clone(),
    })
}

fn validate_manifest(manifest: &FixtureCorpusManifestV1) -> Result<(), StateError> {
    if manifest.schema_id != FIXTURE_CORPUS_SCHEMA_ID
        || manifest.schema_version != 1
        || manifest.corpus_id.trim().is_empty()
        || manifest.fixtures.is_empty()
    {
        return Err(StateError::new(
            StateErrorCode::FixtureCorpusInvalid,
            "fixture_load",
            "state fixture corpus manifest must declare the supported schema and at least one fixture",
        ));
    }

    let mut ids = BTreeSet::new();
    for fixture in &manifest.fixtures {
        if fixture.fixture_id.trim().is_empty()
            || fixture.path.trim().is_empty()
            || Path::new(&fixture.path).is_absolute()
            || !ids.insert(fixture.fixture_id.clone())
        {
            return Err(StateError::new(
                StateErrorCode::FixtureCorpusInvalid,
                "fixture_load",
                "state fixture manifest contains duplicate ids or invalid paths",
            ));
        }

        let mut coverage_tags = BTreeSet::new();
        for tag in &fixture.coverage_tags {
            if !coverage_tags.insert(*tag) {
                return Err(StateError::new(
                    StateErrorCode::FixtureCorpusInvalid,
                    "fixture_load",
                    "state fixture manifest contains duplicate coverage tags",
                ));
            }
        }

        let mut related_survey_fixtures = BTreeSet::new();
        for related_fixture_id in &fixture.related_survey_fixtures {
            if related_fixture_id.trim().is_empty()
                || !related_survey_fixtures.insert(related_fixture_id.clone())
            {
                return Err(StateError::new(
                    StateErrorCode::FixtureCorpusInvalid,
                    "fixture_load",
                    "state fixture manifest contains invalid related survey fixture ids",
                ));
            }
        }
    }

    Ok(())
}

fn validate_snapshot(
    snapshot: &HostStateFixtureSnapshotV1,
    entry: &FixtureCorpusEntryV1,
) -> Result<(), StateError> {
    if snapshot.schema_id != FIXTURE_SNAPSHOT_SCHEMA_ID
        || snapshot.schema_version != 1
        || snapshot.fixture_id != entry.fixture_id
        || snapshot.host_alias.trim().is_empty()
        || snapshot.collected_at.trim().is_empty()
        || snapshot.collectors.is_empty()
    {
        return Err(StateError::new(
            StateErrorCode::StatePayloadMalformed,
            "state_parse",
            "state fixture snapshot must declare the supported schema and required fields",
        ));
    }

    Ok(())
}

fn resolve_fixture_path(fixtures_root: &Path, relative_path: &str) -> Result<PathBuf, StateError> {
    let canonical_root = fs::canonicalize(fixtures_root).map_err(|error| {
        StateError::new(
            StateErrorCode::FixtureCorpusInvalid,
            "fixture_resolve",
            format!(
                "failed to resolve state fixture corpus root {}: {error}",
                fixtures_root.display()
            ),
        )
    })?;

    let candidate = canonical_root.join(relative_path);
    let canonical_candidate = fs::canonicalize(&candidate).map_err(|error| {
        StateError::new(
            StateErrorCode::FixturePathInvalid,
            "fixture_resolve",
            format!(
                "failed to resolve state fixture path {}: {error}",
                candidate.display()
            ),
        )
    })?;

    if !canonical_candidate.starts_with(&canonical_root) {
        return Err(StateError::new(
            StateErrorCode::FixturePathInvalid,
            "fixture_resolve",
            "state fixture path escapes the selected corpus root",
        ));
    }

    Ok(canonical_candidate)
}
