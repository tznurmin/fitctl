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
            .then_with(|| left.vendor_id.cmp(&right.vendor_id))
            .then_with(|| left.device_id.cmp(&right.device_id))
            .then_with(|| left.pci_address.cmp(&right.pci_address))
            .then_with(|| left.driver.cmp(&right.driver))
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

                supporting_detail_missing |= vendor_id.is_none()
                    || device_id.is_none()
                    || pci_address.is_none()
                    || driver.is_none();

                devices.push(AcceleratorDeviceV1 {
                    kind,
                    discovery_source: AcceleratorDiscoverySourceV1::Pci,
                    vendor,
                    vendor_id,
                    device_id,
                    pci_address,
                    driver,
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
        let vendor = read_platform_vendor_summary(device_path.as_path(), driver.as_deref());
        supporting_detail_missing |= vendor.is_none() || driver.is_none();

        devices.push(AcceleratorDeviceV1 {
            kind: AcceleratorKindV1::Gpu,
            discovery_source: AcceleratorDiscoverySourceV1::DrmPlatform,
            vendor,
            vendor_id: None,
            device_id: None,
            pci_address: None,
            driver,
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

fn read_platform_vendor_summary(device_path: &Path, driver: Option<&str>) -> Option<String> {
    let compatibles = read_device_tree_compatible_strings(device_path);
    for compatible in compatibles {
        let normalized = compatible.to_ascii_lowercase();
        if normalized.contains("brcm,") || normalized.contains("bcm27") {
            return Some("broadcom".to_string());
        }
        if normalized.contains("rockchip,") {
            return Some("rockchip".to_string());
        }
        if normalized.contains("amlogic,") {
            return Some("amlogic".to_string());
        }
        if normalized.contains("allwinner,") {
            return Some("allwinner".to_string());
        }
        if normalized.contains("apple,") {
            return Some("apple".to_string());
        }
        if normalized.contains("mediatek,") {
            return Some("mediatek".to_string());
        }
        if normalized.contains("qcom,") || normalized.contains("qualcomm,") {
            return Some("qualcomm".to_string());
        }
        if normalized.contains("arm,mali") {
            return Some("arm".to_string());
        }
    }

    driver.and_then(map_platform_driver_vendor_summary)
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
    let driver_bound_devices = u32::try_from(
        devices
            .iter()
            .filter(|device| device.driver.is_some())
            .count(),
    )
    .ok()?;

    let static_operability = if driver_bound_devices == 0 {
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
    })
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
