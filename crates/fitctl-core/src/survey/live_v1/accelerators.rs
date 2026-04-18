// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

//! Live accelerator inventory collection from PCI, DRM, and visible device-node evidence.

use super::*;

pub(super) fn read_accelerators() -> SurveyFieldV1<AcceleratorDetailsV1> {
    let (mut devices, mut supporting_detail_missing, pci_permission_denied) =
        read_pci_accelerators();
    let known_pci_addresses = devices
        .iter()
        .filter_map(|device| device.pci_address.clone())
        .collect::<std::collections::BTreeSet<_>>();
    let (mut drm_platform_devices, drm_supporting_detail_missing) =
        read_drm_platform_accelerators(&known_pci_addresses);
    devices.append(&mut drm_platform_devices);
    supporting_detail_missing |= drm_supporting_detail_missing;

    let visible_device_nodes = read_visible_accelerator_device_nodes();
    devices.sort_by(|left, right| {
        left.kind
            .cmp(&right.kind)
            .then_with(|| left.discovery_source.cmp(&right.discovery_source))
            .then_with(|| left.vendor.cmp(&right.vendor))
            .then_with(|| left.family.cmp(&right.family))
            .then_with(|| left.model.cmp(&right.model))
            .then_with(|| left.vendor_id.cmp(&right.vendor_id))
            .then_with(|| left.device_id.cmp(&right.device_id))
            .then_with(|| left.integration.cmp(&right.integration))
            .then_with(|| left.memory_bytes.cmp(&right.memory_bytes))
            .then_with(|| left.pci_address.cmp(&right.pci_address))
            .then_with(|| left.driver.cmp(&right.driver))
            .then_with(|| left.numa_node.cmp(&right.numa_node))
    });
    let operability = derive_accelerator_operability_summary(&devices, visible_device_nodes);

    if devices.is_empty() && pci_permission_denied {
        return SurveyFieldV1 {
            state: ObservationStateV1::HiddenByPrivilegeOrVisibility,
            limitation_reason: Some(ObservationLimitationReasonV1::PrivilegeOrVisibilityLimit),
            value: None,
        };
    }

    SurveyFieldV1 {
        state: if !devices.is_empty() && supporting_detail_missing {
            ObservationStateV1::PartiallyObserved
        } else {
            ObservationStateV1::Observed
        },
        limitation_reason: (!devices.is_empty() && supporting_detail_missing)
            .then_some(ObservationLimitationReasonV1::CollectorLimitation),
        value: Some(AcceleratorDetailsV1 {
            devices,
            operability,
        }),
    }
}

fn read_pci_accelerators() -> (Vec<AcceleratorDeviceV1>, bool, bool) {
    match fs::read_dir("/sys/bus/pci/devices") {
        Ok(entries) => {
            let mut devices = Vec::new();
            let mut supporting_detail_missing = false;

            for entry in entries.filter_map(|entry| entry.ok()) {
                let class_path = entry.path().join("class");
                let Some(class_code) = read_trimmed(class_path.to_str().unwrap_or_default()) else {
                    continue;
                };
                let Some(kind) = classify_pci_accelerator_kind(&class_code) else {
                    continue;
                };

                let vendor_id = normalize_pci_hex_id(read_trimmed(
                    entry.path().join("vendor").to_str().unwrap_or_default(),
                ));
                let device_id = normalize_pci_hex_id(read_trimmed(
                    entry.path().join("device").to_str().unwrap_or_default(),
                ));
                let vendor = vendor_id.as_deref().and_then(map_pci_vendor_summary);
                let pci_address = entry.file_name().into_string().ok();
                let driver = read_driver_binding(entry.path().as_path());
                let model = read_pci_accelerator_model(
                    entry.path().as_path(),
                    pci_address.as_deref(),
                    driver.as_deref(),
                );
                let family = derive_accelerator_family(
                    vendor.as_deref(),
                    model.as_deref(),
                    driver.as_deref(),
                );
                let memory_bytes = read_accelerator_memory_bytes(entry.path().as_path());
                let numa_node = read_accelerator_numa_node(entry.path().as_path());

                supporting_detail_missing |= vendor_id.is_none()
                    || device_id.is_none()
                    || pci_address.is_none()
                    || driver.is_none();

                devices.push(AcceleratorDeviceV1 {
                    kind,
                    discovery_source: AcceleratorDiscoverySourceV1::Pci,
                    vendor,
                    family,
                    model,
                    vendor_id,
                    device_id,
                    integration: None,
                    memory_bytes,
                    pci_address,
                    driver,
                    numa_node,
                });
            }

            (devices, supporting_detail_missing, false)
        }
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
            (Vec::new(), false, true)
        }
        Err(_) => (Vec::new(), false, false),
    }
}

fn read_drm_platform_accelerators(
    known_pci_addresses: &std::collections::BTreeSet<String>,
) -> (Vec<AcceleratorDeviceV1>, bool) {
    let Ok(entries) = fs::read_dir("/sys/class/drm") else {
        return (Vec::new(), false);
    };

    let mut devices = Vec::new();
    let mut supporting_detail_missing = false;

    for entry in entries.filter_map(|entry| entry.ok()) {
        let Some(name) = entry.file_name().to_str().map(str::to_string) else {
            continue;
        };
        if !is_primary_drm_card(&name) {
            continue;
        }

        let device_symlink = entry.path().join("device");
        let Ok(device_path) = fs::canonicalize(&device_symlink) else {
            continue;
        };
        if find_pci_address_in_path(&device_path)
            .is_some_and(|value| known_pci_addresses.contains(&value))
        {
            continue;
        }
        if !looks_like_platform_integrated_gpu(&device_path) {
            continue;
        }

        let driver = read_driver_binding(device_path.as_path());
        if matches!(
            driver.as_deref(),
            Some("simpledrm" | "efi-framebuffer" | "simple-framebuffer")
        ) {
            continue;
        }
        let (vendor, family, model) =
            read_platform_accelerator_identity(device_path.as_path(), driver.as_deref());
        let memory_bytes = read_accelerator_memory_bytes(device_path.as_path());
        let numa_node = read_accelerator_numa_node(device_path.as_path());
        supporting_detail_missing |=
            vendor.is_none() || family.is_none() || model.is_none() || driver.is_none();

        devices.push(AcceleratorDeviceV1 {
            kind: AcceleratorKindV1::Gpu,
            discovery_source: AcceleratorDiscoverySourceV1::DrmPlatform,
            vendor,
            family,
            model,
            vendor_id: None,
            device_id: None,
            integration: Some(AcceleratorIntegrationV1::Integrated),
            memory_bytes,
            pci_address: None,
            driver,
            numa_node,
        });
    }

    (devices, supporting_detail_missing)
}

pub(super) fn classify_pci_accelerator_kind(class_code: &str) -> Option<AcceleratorKindV1> {
    let class_code = class_code.trim().trim_start_matches("0x");
    if class_code.starts_with("03") {
        Some(AcceleratorKindV1::Gpu)
    } else if class_code.starts_with("12") {
        Some(AcceleratorKindV1::Other)
    } else {
        None
    }
}

pub(super) fn normalize_pci_hex_id(raw: Option<String>) -> Option<String> {
    let normalized = raw?.trim().trim_start_matches("0x").to_ascii_lowercase();
    (normalized.len() == 4 && normalized.chars().all(|value| value.is_ascii_hexdigit()))
        .then_some(normalized)
}

pub(super) fn read_driver_binding(device_path: &Path) -> Option<String> {
    let link = fs::read_link(device_path.join("driver")).ok()?;
    let name = link.file_name()?.to_str()?.trim();
    (!name.is_empty()).then_some(name.to_string())
}

fn is_primary_drm_card(name: &str) -> bool {
    name.starts_with("card")
        && name.len() > 4
        && name[4..].chars().all(|value| value.is_ascii_digit())
}

fn find_pci_address_in_path(path: &Path) -> Option<String> {
    path.components().find_map(|component| {
        let value = component.as_os_str().to_str()?;
        is_valid_pci_address_component(value).then(|| value.to_string())
    })
}

fn is_valid_pci_address_component(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() != 12 || bytes[4] != b':' || bytes[7] != b':' || bytes[10] != b'.' {
        return false;
    }

    bytes.iter().enumerate().all(|(index, byte)| match index {
        4 | 7 | 10 => true,
        _ => (*byte as char).is_ascii_hexdigit(),
    })
}

fn looks_like_platform_integrated_gpu(path: &Path) -> bool {
    path.join("of_node").exists()
        || path
            .components()
            .any(|component| component.as_os_str() == "platform")
}

fn read_platform_accelerator_identity(
    device_path: &Path,
    driver: Option<&str>,
) -> (Option<String>, Option<String>, Option<String>) {
    let compatibles = read_device_tree_compatible_strings(device_path);
    for compatible in compatibles {
        let normalized = compatible.to_ascii_lowercase();
        if normalized.contains("brcm,") || normalized.contains("bcm27") {
            return (
                Some("broadcom".to_string()),
                Some("videocore".to_string()),
                Some(platform_model_from_compatible(&normalized, "v3d")),
            );
        }
        if normalized.contains("rockchip,") {
            return (
                Some("rockchip".to_string()),
                Some("mali".to_string()),
                Some(platform_model_from_compatible(&normalized, "mali")),
            );
        }
        if normalized.contains("amlogic,") {
            return (
                Some("amlogic".to_string()),
                Some("mali".to_string()),
                Some(platform_model_from_compatible(&normalized, "mali")),
            );
        }
        if normalized.contains("allwinner,") {
            return (
                Some("allwinner".to_string()),
                Some("mali".to_string()),
                Some(platform_model_from_compatible(&normalized, "mali")),
            );
        }
        if normalized.contains("apple,") {
            return (
                Some("apple".to_string()),
                Some("apple_gpu".to_string()),
                Some("apple-gpu".to_string()),
            );
        }
        if normalized.contains("mediatek,") {
            return (
                Some("mediatek".to_string()),
                Some("mali".to_string()),
                Some(platform_model_from_compatible(&normalized, "mali")),
            );
        }
        if normalized.contains("qcom,") || normalized.contains("qualcomm,") {
            return (
                Some("qualcomm".to_string()),
                Some("adreno".to_string()),
                Some(platform_model_from_compatible(&normalized, "adreno")),
            );
        }
        if normalized.contains("arm,mali") {
            return (
                Some("arm".to_string()),
                Some("mali".to_string()),
                Some(platform_model_from_compatible(&normalized, "mali")),
            );
        }
    }

    if let Some(driver) = driver {
        (
            map_platform_driver_vendor_summary(driver),
            map_platform_driver_family(driver),
            map_platform_driver_model(driver),
        )
    } else {
        (None, None, None)
    }
}

fn read_device_tree_compatible_strings(device_path: &Path) -> Vec<String> {
    let Ok(bytes) = fs::read(device_path.join("of_node").join("compatible")) else {
        return Vec::new();
    };

    bytes
        .split(|byte| *byte == 0)
        .filter_map(|value| {
            let text = String::from_utf8_lossy(value).trim().to_string();
            (!text.is_empty()).then_some(text)
        })
        .collect()
}

fn map_platform_driver_vendor_summary(driver: &str) -> Option<String> {
    Some(match driver.trim() {
        "vc4" | "v3d" => "broadcom".to_string(),
        "panfrost" | "lima" => "arm".to_string(),
        "etnaviv" => "vivante".to_string(),
        "msm" => "qualcomm".to_string(),
        "aspeed_gfx" | "ast" => "aspeed".to_string(),
        _ => return None,
    })
}

fn map_platform_driver_family(driver: &str) -> Option<String> {
    Some(match driver.trim() {
        "vc4" | "v3d" => "videocore".to_string(),
        "panfrost" | "lima" => "mali".to_string(),
        "etnaviv" => "gc".to_string(),
        "msm" => "adreno".to_string(),
        "aspeed_gfx" | "ast" => "ast".to_string(),
        _ => return None,
    })
}

fn map_platform_driver_model(driver: &str) -> Option<String> {
    Some(match driver.trim() {
        "vc4" => "vc4".to_string(),
        "v3d" => "v3d".to_string(),
        "panfrost" | "lima" => "mali".to_string(),
        "etnaviv" => "gc".to_string(),
        "msm" => "adreno".to_string(),
        "aspeed_gfx" | "ast" => "ast".to_string(),
        _ => return None,
    })
}

fn platform_model_from_compatible(compatible: &str, fallback: &str) -> String {
    compatible
        .split(',')
        .nth(1)
        .map(|value| value.replace('_', "-"))
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| fallback.to_string())
}

fn read_pci_accelerator_model(
    device_path: &Path,
    pci_address: Option<&str>,
    driver: Option<&str>,
) -> Option<String> {
    if matches!(driver, Some("nvidia")) {
        if let Some(pci_address) = pci_address {
            if let Some(model) = read_nvidia_gpu_information_value(pci_address, "Model") {
                return Some(model);
            }
        }
    }

    read_trimmed(device_path.join("label").to_str().unwrap_or_default())
}

fn read_nvidia_gpu_information_value(pci_address: &str, key: &str) -> Option<String> {
    let text = fs::read_to_string(format!(
        "/proc/driver/nvidia/gpus/{pci_address}/information"
    ))
    .ok()?;
    text.lines().find_map(|line| {
        let (left, right) = line.split_once(':')?;
        (left.trim() == key)
            .then(|| right.trim().to_string())
            .filter(|value| !value.is_empty())
    })
}

fn derive_accelerator_family(
    vendor: Option<&str>,
    model: Option<&str>,
    driver: Option<&str>,
) -> Option<String> {
    let normalized_model = model.map(|value| value.to_ascii_lowercase());
    if let Some(model) = normalized_model.as_deref() {
        if model.contains("rtx") {
            return Some("rtx".to_string());
        }
        if model.contains("gtx") {
            return Some("gtx".to_string());
        }
        if model.contains("quadro") {
            return Some("quadro".to_string());
        }
        if model.contains("tesla") {
            return Some("tesla".to_string());
        }
        if model.contains("videocore") || model == "v3d" || model == "vc4" {
            return Some("videocore".to_string());
        }
        if model.contains("mali") {
            return Some("mali".to_string());
        }
        if model.contains("adreno") {
            return Some("adreno".to_string());
        }
    }

    match (vendor, driver) {
        (Some("broadcom"), _) | (_, Some("vc4" | "v3d")) => Some("videocore".to_string()),
        (Some("arm"), _) | (_, Some("panfrost" | "lima")) => Some("mali".to_string()),
        (Some("qualcomm"), _) | (_, Some("msm")) => Some("adreno".to_string()),
        _ => None,
    }
}

fn read_accelerator_memory_bytes(device_path: &Path) -> Option<u64> {
    for candidate in [
        "mem_info_vram_total",
        "mem_info_vram_vendor_total",
        "mem_info_vis_vram_total",
    ] {
        let Some(raw) = read_trimmed(device_path.join(candidate).to_str().unwrap_or_default())
        else {
            continue;
        };
        if let Ok(value) = raw.parse::<u64>() {
            if value > 0 {
                return Some(value);
            }
        }
    }
    None
}

fn read_accelerator_numa_node(device_path: &Path) -> Option<u32> {
    let raw = read_trimmed(device_path.join("numa_node").to_str()?)?;
    let value = raw.parse::<i64>().ok()?;
    (value >= 0).then_some(value as u32)
}

pub(super) fn read_visible_accelerator_device_nodes() -> Vec<String> {
    let mut nodes = Vec::new();
    collect_named_device_nodes(
        Path::new("/dev/dri"),
        &mut nodes,
        |name| name.starts_with("card") || name.starts_with("renderD"),
        "/dev/dri",
    );
    collect_named_device_nodes(
        Path::new("/dev"),
        &mut nodes,
        |name| name.starts_with("nvidia") || name == "kfd",
        "/dev",
    );
    nodes.sort();
    nodes.dedup();
    nodes
}

pub(super) fn collect_named_device_nodes(
    root: &Path,
    nodes: &mut Vec<String>,
    keep: impl Fn(&str) -> bool,
    prefix: &str,
) {
    let Ok(entries) = fs::read_dir(root) else {
        return;
    };

    for entry in entries.filter_map(|entry| entry.ok()) {
        let Some(name) = entry.file_name().to_str().map(str::to_string) else {
            continue;
        };
        if keep(&name) {
            nodes.push(format!("{prefix}/{name}"));
        }
    }
}

pub(super) fn derive_accelerator_operability_summary(
    devices: &[AcceleratorDeviceV1],
    mut visible_device_nodes: Vec<String>,
) -> Option<AcceleratorOperabilityV1> {
    if devices.is_empty() {
        return None;
    }

    visible_device_nodes.sort();
    visible_device_nodes.dedup();
    let visible_render_nodes = collect_visible_render_nodes(&visible_device_nodes);
    let driver_bound_devices = u32::try_from(
        devices
            .iter()
            .filter(|device| device.driver.is_some())
            .count(),
    )
    .ok()?;

    let static_operability = if driver_bound_devices == 0 || visible_device_nodes.is_empty() {
        StaticOperabilityV1::NotOperable
    } else if usize::try_from(driver_bound_devices).ok() == Some(devices.len())
        && !visible_device_nodes.is_empty()
    {
        StaticOperabilityV1::Operable
    } else {
        StaticOperabilityV1::Indeterminate
    };

    Some(AcceleratorOperabilityV1 {
        static_operability,
        driver_bound_devices,
        visible_device_nodes,
        visible_render_nodes,
    })
}

fn collect_visible_render_nodes(visible_device_nodes: &[String]) -> Vec<String> {
    visible_device_nodes
        .iter()
        .filter(|node| node.starts_with("/dev/dri/renderD"))
        .cloned()
        .collect()
}

pub(super) fn map_pci_vendor_summary(raw: &str) -> Option<String> {
    let normalized = raw.trim().trim_start_matches("0x").to_ascii_lowercase();
    if normalized.is_empty() {
        return None;
    }

    Some(match normalized.as_str() {
        "10de" => "nvidia".to_string(),
        "1002" | "1022" => "amd".to_string(),
        "8086" => "intel".to_string(),
        "1a03" => "aspeed".to_string(),
        other => format!("pci_vendor_{other}"),
    })
}
