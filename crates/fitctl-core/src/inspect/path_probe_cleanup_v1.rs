// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

use crate::artifacts::path_probe_cleanup_v1::HostStatePathProbeCleanupV1;

pub(super) fn summary(cleanup: Option<&[HostStatePathProbeCleanupV1]>, verbose: bool) -> String {
    let Some(cleanup) = cleanup else {
        return "cleanup not_recorded".into();
    };
    if cleanup.is_empty() {
        return "cleanup not_needed".into();
    }
    let mut text = format!(
        "cleanup {}",
        cleanup
            .iter()
            .map(|entry| entry.outcome.as_str())
            .collect::<Vec<_>>()
            .join(",")
    );
    if verbose {
        for entry in cleanup {
            text.push_str(&format!(
                "; {} {}",
                entry.probe_root,
                entry.outcome.as_str()
            ));
            if let Some(error) = &entry.error {
                text.push_str(&format!(" ({error})"));
            }
        }
    }
    text
}
