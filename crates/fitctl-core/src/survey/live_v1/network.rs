// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

//! Live network inventory and addressability collection.

use super::*;

pub(super) fn read_network() -> NetworkCollectionV1 {
    let address_map = read_network_address_map();
    let default_route_families = read_default_route_families();
    let mut collectors = vec!["netdev".to_string()];
    if address_map.is_some() {
        collectors.push("iproute2_addr".to_string());
    }
    if default_route_families.is_some() {
        collectors.push("iproute2_route".to_string());
    }

    match fs::read_dir("/sys/class/net") {
        Ok(entries) => {
            let mut interfaces = Vec::new();
            let mut interface_details = Vec::new();
            let address_map_ref = address_map.as_ref();

            for entry in entries.filter_map(|entry| entry.ok()) {
                let Some(interface_name) = entry.file_name().into_string().ok() else {
                    continue;
                };
                let addresses = address_map_ref.and_then(|map| map.get(&interface_name));
                interfaces.push(interface_name.clone());
                interface_details.push(read_network_interface_details(
                    &entry.path(),
                    interface_name,
                    addresses,
                ));
            }

            interfaces.sort();
            interfaces.dedup();
            interface_details.sort_by(|left, right| left.name.cmp(&right.name));

            if interfaces.is_empty() {
                NetworkCollectionV1 {
                    field: unknown(),
                    collectors,
                }
            } else {
                let addressability_summary = derive_addressability_summary(
                    &interface_details,
                    address_map.is_some(),
                    default_route_families,
                );
                NetworkCollectionV1 {
                    field: observed(NetworkDetailsV1 {
                        interfaces,
                        interface_details,
                        addressability_summary,
                    }),
                    collectors,
                }
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => NetworkCollectionV1 {
            field: SurveyFieldV1 {
                state: ObservationStateV1::HiddenByPrivilegeOrVisibility,
                limitation_reason: Some(ObservationLimitationReasonV1::PrivilegeOrVisibilityLimit),
                value: None,
            },
            collectors,
        },
        Err(_) => NetworkCollectionV1 {
            field: unknown(),
            collectors,
        },
    }
}

pub(super) fn read_network_interface_details(
    interface_path: &Path,
    interface_name: String,
    addresses: Option<&Vec<NetworkAddressV1>>,
) -> NetworkInterfaceV1 {
    let mut addresses = addresses.cloned().unwrap_or_default();
    addresses.sort_by(|left, right| {
        left.family
            .cmp(&right.family)
            .then_with(|| left.address.cmp(&right.address))
            .then_with(|| left.prefix_len.cmp(&right.prefix_len))
    });
    addresses.dedup();

    let classification = classify_network_interface(interface_path, &interface_name);

    NetworkInterfaceV1 {
        name: interface_name.clone(),
        interface_kind: classification.kind,
        interface_virtuality: classification.virtuality,
        link_state: read_link_state(interface_path),
        carrier_state: read_carrier_state(interface_path),
        duplex: read_duplex(interface_path),
        mtu: read_positive_u32(interface_path.join("mtu")),
        speed_mbps: read_positive_u64(interface_path.join("speed")),
        mac_address: read_trimmed(interface_path.join("address").to_str().unwrap_or_default()),
        addresses,
    }
}

pub(super) fn derive_addressability_summary(
    interface_details: &[NetworkInterfaceV1],
    address_map_collected: bool,
    default_route_families: Option<Vec<IpAddressFamilyV1>>,
) -> Option<NetworkAddressabilitySummaryV1> {
    let non_loopback_address_families = address_map_collected.then(|| {
        let mut families = interface_details
            .iter()
            .filter(|detail| detail.interface_kind != NetworkInterfaceKindV1::Loopback)
            .flat_map(|detail| detail.addresses.iter().map(|address| address.family))
            .collect::<Vec<_>>();
        families.sort();
        families.dedup();
        families
    });

    if non_loopback_address_families.is_none() && default_route_families.is_none() {
        return None;
    }

    Some(NetworkAddressabilitySummaryV1 {
        non_loopback_address_families,
        default_route_families,
    })
}

pub(super) fn read_network_address_map() -> Option<BTreeMap<String, Vec<NetworkAddressV1>>> {
    let output = Command::new("ip")
        .args(["-json", "addr", "show"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }

    let raw: Value = serde_json::from_slice(&output.stdout).ok()?;
    let interfaces = raw.as_array()?;
    let mut address_map = BTreeMap::new();

    for interface in interfaces {
        let Some(interface_name) = interface.get("ifname").and_then(Value::as_str) else {
            continue;
        };
        let mut addresses = Vec::new();
        if let Some(addr_info) = interface.get("addr_info").and_then(Value::as_array) {
            for address_info in addr_info {
                let Some(address_family) =
                    parse_ip_address_family(address_info.get("family").and_then(Value::as_str))
                else {
                    continue;
                };
                let Some(address) = address_info.get("local").and_then(Value::as_str) else {
                    continue;
                };
                let Some(prefix_len) = address_info.get("prefixlen").and_then(Value::as_u64) else {
                    continue;
                };
                if !is_valid_ip_address(address_family, address, prefix_len) {
                    continue;
                }
                let Ok(prefix_len) = u8::try_from(prefix_len) else {
                    continue;
                };
                addresses.push(NetworkAddressV1 {
                    family: address_family,
                    address: address.to_string(),
                    prefix_len,
                });
            }
        }
        if !addresses.is_empty() {
            address_map.insert(interface_name.to_string(), addresses);
        }
    }

    Some(address_map)
}

pub(super) fn read_default_route_families() -> Option<Vec<IpAddressFamilyV1>> {
    let mut families = Vec::new();
    let mut command_succeeded = false;

    for (family, args) in [
        (
            IpAddressFamilyV1::Ipv4,
            ["-4", "-json", "route", "show", "default"],
        ),
        (
            IpAddressFamilyV1::Ipv6,
            ["-6", "-json", "route", "show", "default"],
        ),
    ] {
        let Some(has_default_route) = read_default_route_presence(args) else {
            continue;
        };
        command_succeeded = true;
        if has_default_route {
            families.push(family);
        }
    }

    command_succeeded.then_some(families)
}

fn read_default_route_presence(args: [&str; 5]) -> Option<bool> {
    let output = Command::new("ip").args(args).output().ok()?;
    if !output.status.success() {
        return None;
    }

    let raw: Value = serde_json::from_slice(&output.stdout).ok()?;
    Some(raw.as_array().is_some_and(|routes| !routes.is_empty()))
}

pub(super) fn parse_ip_address_family(raw: Option<&str>) -> Option<IpAddressFamilyV1> {
    match raw? {
        "inet" => Some(IpAddressFamilyV1::Ipv4),
        "inet6" => Some(IpAddressFamilyV1::Ipv6),
        _ => None,
    }
}

pub(super) fn is_valid_ip_address(
    family: IpAddressFamilyV1,
    address: &str,
    prefix_len: u64,
) -> bool {
    match family {
        IpAddressFamilyV1::Ipv4 => address.parse::<Ipv4Addr>().is_ok() && prefix_len <= 32,
        IpAddressFamilyV1::Ipv6 => address.parse::<Ipv6Addr>().is_ok() && prefix_len <= 128,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct NetworkInterfaceClassificationV1 {
    kind: NetworkInterfaceKindV1,
    virtuality: NetworkInterfaceVirtualityV1,
}

pub(super) fn classify_network_interface(
    interface_path: &Path,
    interface_name: &str,
) -> NetworkInterfaceClassificationV1 {
    let type_text = read_trimmed(interface_path.join("type").to_str().unwrap_or_default());
    let virtuality = detect_interface_virtuality(interface_path, interface_name);
    let kind = detect_interface_kind(
        interface_path,
        interface_name,
        type_text.as_deref(),
        virtuality,
    );

    NetworkInterfaceClassificationV1 { kind, virtuality }
}

pub(super) fn detect_interface_kind(
    interface_path: &Path,
    interface_name: &str,
    type_text: Option<&str>,
    virtuality: NetworkInterfaceVirtualityV1,
) -> NetworkInterfaceKindV1 {
    if interface_name == "lo" || type_text == Some("772") {
        return NetworkInterfaceKindV1::Loopback;
    }
    if interface_path.join("wireless").exists() || interface_path.join("phy80211").exists() {
        return NetworkInterfaceKindV1::Wireless;
    }
    if interface_path.join("bridge").exists() {
        return NetworkInterfaceKindV1::Bridge;
    }
    if matches!(virtuality, NetworkInterfaceVirtualityV1::Virtual)
        && interface_name.starts_with("veth")
    {
        return NetworkInterfaceKindV1::Veth;
    }

    match type_text {
        Some("1") => NetworkInterfaceKindV1::Ethernet,
        Some("65534") => NetworkInterfaceKindV1::Tunnel,
        _ => NetworkInterfaceKindV1::Other,
    }
}

pub(super) fn detect_interface_virtuality(
    interface_path: &Path,
    interface_name: &str,
) -> NetworkInterfaceVirtualityV1 {
    if interface_name == "lo" {
        return NetworkInterfaceVirtualityV1::Virtual;
    }

    if is_virtual_interface(interface_path) {
        return NetworkInterfaceVirtualityV1::Virtual;
    }

    if interface_path.join("device").exists() {
        return NetworkInterfaceVirtualityV1::Physical;
    }

    NetworkInterfaceVirtualityV1::Indeterminate
}

pub(super) fn is_virtual_interface(interface_path: &Path) -> bool {
    fs::canonicalize(interface_path)
        .ok()
        .is_some_and(|path| path.starts_with(Path::new("/sys/devices/virtual/net")))
}

pub(super) fn read_link_state(interface_path: &Path) -> NetworkLinkStateV1 {
    match read_trimmed(
        interface_path
            .join("operstate")
            .to_str()
            .unwrap_or_default(),
    )
    .as_deref()
    {
        Some("up") => NetworkLinkStateV1::Up,
        Some("down") => NetworkLinkStateV1::Down,
        Some("dormant") => NetworkLinkStateV1::Dormant,
        _ => NetworkLinkStateV1::Unknown,
    }
}

pub(super) fn read_carrier_state(interface_path: &Path) -> NetworkCarrierStateV1 {
    match read_trimmed(interface_path.join("carrier").to_str().unwrap_or_default()).as_deref() {
        Some("1") => NetworkCarrierStateV1::Up,
        Some("0") => NetworkCarrierStateV1::Down,
        _ => NetworkCarrierStateV1::Unknown,
    }
}

pub(super) fn read_duplex(interface_path: &Path) -> NetworkDuplexV1 {
    match read_trimmed(interface_path.join("duplex").to_str().unwrap_or_default()).as_deref() {
        Some("full") => NetworkDuplexV1::Full,
        Some("half") => NetworkDuplexV1::Half,
        _ => NetworkDuplexV1::Unknown,
    }
}

pub(super) fn read_positive_u32(path: impl AsRef<Path>) -> Option<u32> {
    read_trimmed(path.as_ref().to_str()?)?
        .parse::<u32>()
        .ok()
        .filter(|value| *value > 0)
}

pub(super) fn read_positive_u64(path: impl AsRef<Path>) -> Option<u64> {
    let raw = read_trimmed(path.as_ref().to_str()?)?;
    let value = raw.parse::<i64>().ok()?;
    (value > 0).then_some(value as u64)
}
