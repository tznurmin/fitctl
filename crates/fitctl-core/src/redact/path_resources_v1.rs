// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

//! Relationship-preserving identifiers and typed path-resource sharing views.

use std::collections::{BTreeMap, BTreeSet};

use crate::artifacts::path_probe_cleanup_v1::HostStatePathProbeCleanupV1;
use crate::artifacts::state_v1::{HostStatePathResourcesV1, StateFieldV1};
use crate::redact::profile_v1::BuiltInRedactionProfileV1;

pub(crate) fn deterministic_identifier_map<'a>(
    values: impl Iterator<Item = &'a str>,
    profile: BuiltInRedactionProfileV1,
    class: &str,
) -> BTreeMap<String, String> {
    values
        .map(ToOwned::to_owned)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .enumerate()
        .map(|(index, value)| (value, profile.indexed_placeholder(class, index)))
        .collect()
}

pub(crate) fn mapped_identifier(value: &str, replacements: &BTreeMap<String, String>) -> String {
    replacements
        .get(value)
        .cloned()
        .unwrap_or_else(|| value.to_string())
}

pub(crate) fn redact_state_path_resources_v1(
    resources: &mut HostStatePathResourcesV1,
    profile: BuiltInRedactionProfileV1,
) {
    let path_ids = deterministic_identifier_map(
        resources
            .paths
            .iter()
            .map(|path| path.path_id.as_str())
            .chain(
                resources
                    .link_pairs
                    .iter()
                    .flat_map(|pair| [pair.from_path_id.as_str(), pair.to_path_id.as_str()]),
            ),
        profile,
        "path_id",
    );

    for (index, path) in resources.paths.iter_mut().enumerate() {
        path.path_id = mapped_identifier(&path.path_id, &path_ids);
        let mount_placeholder = format!("{}:{index}", profile.mount_path_placeholder());
        path.path = mount_placeholder.clone();
        path.requested_path = Some(mount_placeholder.clone());
        replace_observed_string(&mut path.canonical_path, &mount_placeholder);
        replace_observed_string(&mut path.containing_mount_point, &mount_placeholder);
        replace_observed_string(
            &mut path.mount_source,
            &format!("{}:{index}", profile.block_device_placeholder()),
        );
        replace_observed_strings(&mut path.mount_options, profile, "mount_option");
        let storage_placeholder = format!("{}:{index}", profile.storage_identity_placeholder());
        replace_observed_string(&mut path.mount_device_major_minor, &storage_placeholder);
        replace_observed_string(&mut path.filesystem_uuid, &storage_placeholder);
        replace_observed_string(&mut path.partition_uuid, &storage_placeholder);
        replace_observed_strings_with_base(&mut path.persistent_device_links, &storage_placeholder);
        if !path.media_class_evidence.is_empty() {
            path.media_class_evidence = vec![storage_placeholder.clone()];
        }
        if !path.storage_identity_evidence.is_empty() {
            path.storage_identity_evidence = vec![storage_placeholder.clone()];
        }
        if let Some(link_capabilities) = path.link_capabilities.as_mut() {
            redact_cleanup(link_capabilities.cleanup.as_deref_mut(), &mount_placeholder);
            link_capabilities.probe_root = Some(mount_placeholder);
            replace_optional_indexed(
                &mut link_capabilities.probe_method,
                profile,
                "path_probe_method",
                index,
            );
            replace_optional(&mut link_capabilities.probe_error, "redacted:probe_error");
        }
        if let Some(storage_health) = path.storage_health.as_mut() {
            if storage_health.source.is_some() {
                storage_health.source = Some(format!(
                    "{}:{index}",
                    profile.storage_health_source_placeholder()
                ));
            }
            replace_optional_indexed(
                &mut storage_health.probe_method,
                profile,
                "storage_health_probe_method",
                index,
            );
            replace_optional(&mut storage_health.probe_error, "redacted:probe_error");
        }
    }

    for (index, pair) in resources.link_pairs.iter_mut().enumerate() {
        pair.pair_id = profile.indexed_placeholder("path_pair", index);
        pair.from_path_id = mapped_identifier(&pair.from_path_id, &path_ids);
        pair.to_path_id = mapped_identifier(&pair.to_path_id, &path_ids);
        replace_optional_indexed(
            &mut pair.probe_method,
            profile,
            "path_pair_probe_method",
            index,
        );
        replace_optional(&mut pair.probe_error, "redacted:probe_error");
        redact_cleanup(
            pair.cleanup.as_deref_mut(),
            &format!("{}:pair:{index}", profile.mount_path_placeholder()),
        );
    }
}

fn redact_cleanup(cleanup: Option<&mut [HostStatePathProbeCleanupV1]>, base: &str) {
    if let Some(cleanup) = cleanup {
        for (index, entry) in cleanup.iter_mut().enumerate() {
            entry.probe_root = format!("{base}:probe:{index}");
            replace_optional(&mut entry.error, "redacted:cleanup_error");
        }
    }
}

fn replace_observed_string(field: &mut StateFieldV1<String>, replacement: &str) {
    if field.value.is_some() {
        field.value = Some(replacement.to_string());
    }
}

fn replace_observed_strings(
    field: &mut StateFieldV1<Vec<String>>,
    profile: BuiltInRedactionProfileV1,
    class: &str,
) {
    if let Some(values) = field.value.as_mut() {
        replace_strings(values, profile, class);
    }
}

fn replace_observed_strings_with_base(field: &mut StateFieldV1<Vec<String>>, base: &str) {
    if let Some(values) = field.value.as_mut() {
        for (index, value) in values.iter_mut().enumerate() {
            *value = format!("{base}:{index}");
        }
    }
}

fn replace_strings(values: &mut [String], profile: BuiltInRedactionProfileV1, class: &str) {
    for (index, value) in values.iter_mut().enumerate() {
        *value = profile.indexed_placeholder(class, index);
    }
}

fn replace_optional(value: &mut Option<String>, replacement: &str) {
    if value.is_some() {
        *value = Some(replacement.to_string());
    }
}

fn replace_optional_indexed(
    value: &mut Option<String>,
    profile: BuiltInRedactionProfileV1,
    class: &str,
    index: usize,
) {
    if value.is_some() {
        *value = Some(profile.indexed_placeholder(class, index));
    }
}
