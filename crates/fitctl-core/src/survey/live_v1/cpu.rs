// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

//! Live CPU inventory collection from procfs and sysfs topology/cache views.

use super::*;

pub(super) fn read_cpu() -> SurveyFieldV1<CpuDetailsV1> {
    let cpuinfo = match fs::read_to_string("/proc/cpuinfo") {
        Ok(text) => text,
        Err(_) => return unknown(),
    };

    let logical_cores = cpuinfo
        .lines()
        .filter(|line| line.starts_with("processor"))
        .count() as u32;
    let (model, model_basis) = read_cpu_model(&cpuinfo)
        .map(|(model, basis)| (model, Some(basis)))
        .unwrap_or_default();

    if logical_cores == 0 || model.is_empty() {
        return unknown();
    }

    let physical_cores =
        read_physical_core_count().or_else(|| read_cpu_core_hint_from_cpuinfo(&cpuinfo));
    let threads_per_core = physical_cores.and_then(|physical_cores| {
        (physical_cores > 0
            && logical_cores >= physical_cores
            && logical_cores.is_multiple_of(physical_cores))
        .then_some(logical_cores / physical_cores)
        .filter(|threads| *threads > 0)
    });
    let feature_flags = read_cpu_feature_flags(&cpuinfo);
    let cache_summary = read_cpu_cache_summary();

    let supporting_detail_missing = physical_cores.is_none()
        || threads_per_core.is_none()
        || feature_flags.is_empty()
        || cache_summary.is_none();

    SurveyFieldV1 {
        state: if supporting_detail_missing {
            ObservationStateV1::PartiallyObserved
        } else {
            ObservationStateV1::Observed
        },
        limitation_reason: supporting_detail_missing
            .then_some(ObservationLimitationReasonV1::CollectorLimitation),
        value: Some(CpuDetailsV1 {
            architecture: std::env::consts::ARCH.to_string(),
            logical_cores,
            model,
            model_basis,
            physical_cores,
            threads_per_core,
            feature_flags,
            cache_summary,
        }),
    }
}

pub(super) fn read_cpuinfo_value(cpuinfo: &str, keys: &[&str]) -> Option<String> {
    cpuinfo.lines().find_map(|line| {
        let (key, value) = line.split_once(':')?;
        keys.iter()
            .any(|candidate| key.trim() == *candidate)
            .then_some(value.trim().to_string())
            .filter(|value| !value.is_empty())
    })
}

pub(super) fn read_cpu_model(cpuinfo: &str) -> Option<(String, CpuModelBasisV1)> {
    if let Some(model) = read_cpuinfo_value(cpuinfo, &["model name"]) {
        return Some((model, CpuModelBasisV1::DirectCpuModel));
    }
    if let Some(model) = read_arm_cpu_model(cpuinfo) {
        return Some((model, CpuModelBasisV1::ArmPartLookup));
    }
    read_cpuinfo_value(cpuinfo, &["Hardware", "Processor", "Model"])
        .map(|model| (model, CpuModelBasisV1::CpuinfoLabelFallback))
}

pub(super) fn read_arm_cpu_model(cpuinfo: &str) -> Option<String> {
    let implementer = read_cpuinfo_hex_value(cpuinfo, "CPU implementer")?;
    let part = read_cpuinfo_hex_value(cpuinfo, "CPU part")?;

    match (implementer, part) {
        (0x41, 0xd03) => Some("Arm Cortex-A53".to_string()),
        (0x41, 0xd07) => Some("Arm Cortex-A57".to_string()),
        (0x41, 0xd08) => Some("Arm Cortex-A72".to_string()),
        (0x41, 0xd09) => Some("Arm Cortex-A73".to_string()),
        (0x41, 0xd0a) => Some("Arm Cortex-A75".to_string()),
        (0x41, 0xd0b) => Some("Arm Cortex-A76".to_string()),
        (0x41, 0xd0d) => Some("Arm Cortex-A77".to_string()),
        (0x41, 0xd41) => Some("Arm Cortex-A78".to_string()),
        _ => Some(format!(
            "CPU implementer 0x{implementer:02x} part 0x{part:03x}"
        )),
    }
}

pub(super) fn read_cpuinfo_hex_value(cpuinfo: &str, key: &str) -> Option<u32> {
    let raw = read_cpuinfo_value(cpuinfo, &[key])?;
    let raw = raw.strip_prefix("0x").unwrap_or(raw.as_str());
    u32::from_str_radix(raw, 16).ok()
}

pub(super) fn read_cpu_core_hint_from_cpuinfo(cpuinfo: &str) -> Option<u32> {
    read_cpuinfo_value(cpuinfo, &["cpu cores"])?
        .parse::<u32>()
        .ok()
        .filter(|value| *value > 0)
}

pub(super) fn read_cpu_feature_flags(cpuinfo: &str) -> Vec<String> {
    let mut flags = read_cpuinfo_value(cpuinfo, &["flags", "Features"])
        .map(|value| {
            value
                .split_whitespace()
                .map(|flag| flag.trim().to_ascii_lowercase())
                .filter(|flag| !flag.is_empty())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    flags.sort();
    flags.dedup();
    flags
}

pub(super) fn read_physical_core_count() -> Option<u32> {
    let entries = fs::read_dir("/sys/devices/system/cpu").ok()?;
    let mut cores = std::collections::BTreeSet::new();

    for entry in entries.filter_map(|entry| entry.ok()) {
        let name = entry.file_name().into_string().ok()?;
        if !name.starts_with("cpu")
            || !name[3..]
                .chars()
                .all(|character| character.is_ascii_digit())
        {
            continue;
        }

        let package_id = read_trimmed(entry.path().join("topology/physical_package_id").to_str()?);
        let core_id = read_trimmed(entry.path().join("topology/core_id").to_str()?);

        match (package_id, core_id) {
            (Some(package_id), Some(core_id)) => {
                cores.insert((package_id, core_id));
            }
            _ => continue,
        }
    }

    (!cores.is_empty()).then_some(u32::try_from(cores.len()).ok()?)
}

pub(super) fn read_cpu_cache_summary() -> Option<CpuCacheSummaryV1> {
    let entries = fs::read_dir("/sys/devices/system/cpu/cpu0/cache").ok()?;
    let mut summary = CpuCacheSummaryV1 {
        summary_basis: CpuCacheSummaryBasisV1::RepresentativeInstanceSizes,
        l1_data_bytes: None,
        l1_instruction_bytes: None,
        l2_bytes: None,
        l3_bytes: None,
    };
    let mut found_any = false;

    for entry in entries.filter_map(|entry| entry.ok()) {
        let level = read_trimmed(entry.path().join("level").to_str()?)
            .and_then(|value| value.parse::<u32>().ok());
        let cache_type = read_trimmed(entry.path().join("type").to_str()?);
        let size_bytes = read_trimmed(entry.path().join("size").to_str()?)
            .and_then(|value| parse_sysfs_size_to_bytes(&value));

        let (Some(level), Some(cache_type), Some(size_bytes)) = (level, cache_type, size_bytes)
        else {
            continue;
        };

        found_any = true;
        match (level, cache_type.as_str()) {
            (1, "Data") => update_optional_max(&mut summary.l1_data_bytes, size_bytes),
            (1, "Instruction") => {
                update_optional_max(&mut summary.l1_instruction_bytes, size_bytes)
            }
            (2, _) => update_optional_max(&mut summary.l2_bytes, size_bytes),
            (3, _) => update_optional_max(&mut summary.l3_bytes, size_bytes),
            _ => {}
        }
    }

    found_any.then_some(summary)
}

pub(super) fn update_optional_max(slot: &mut Option<u64>, candidate: u64) {
    match slot {
        Some(current) if *current >= candidate => {}
        _ => *slot = Some(candidate),
    }
}

pub(super) fn parse_sysfs_size_to_bytes(raw: &str) -> Option<u64> {
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }
    let unit = raw.chars().last()?;
    let digits = raw[..raw.len().saturating_sub(1)].trim();
    let value = digits.parse::<u64>().ok()?;
    match unit {
        'K' | 'k' => value.checked_mul(1024),
        'M' | 'm' => value.checked_mul(1024 * 1024),
        'G' | 'g' => value.checked_mul(1024 * 1024 * 1024),
        _ => raw.parse::<u64>().ok(),
    }
}
