// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

//! Registry of the supported core Linux collector families and their visibility caveats.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CollectorFamilyV1 {
    pub id: &'static str,
    pub summary: &'static str,
    pub visibility_caveat: &'static str,
}

pub const CORE_LINUX_COLLECTOR_FAMILIES: [CollectorFamilyV1; 7] = [
    CollectorFamilyV1 {
        id: "procfs",
        summary: "Processor, memory, and process-visible kernel evidence",
        visibility_caveat: "Container and privilege limits may hide host-wide state.",
    },
    CollectorFamilyV1 {
        id: "sysfs",
        summary: "Kernel device and topology views",
        visibility_caveat: "Restricted mounts may hide device classes or host topology.",
    },
    CollectorFamilyV1 {
        id: "cgroupfs",
        summary: "Execution-context and resource-controller restrictions",
        visibility_caveat: "Nested runtimes may expose only delegated cgroup state.",
    },
    CollectorFamilyV1 {
        id: "mountinfo",
        summary: "Mount, namespace, and filesystem visibility",
        visibility_caveat: "Namespace boundaries may present only a partial mount graph.",
    },
    CollectorFamilyV1 {
        id: "netdev",
        summary: "Network-interface inventory",
        visibility_caveat: "Network namespaces may hide host interfaces and addresses.",
    },
    CollectorFamilyV1 {
        id: "block_and_filesystem",
        summary: "Block-device and filesystem visibility",
        visibility_caveat: "Privileges and container binds may hide block ownership or topology.",
    },
    CollectorFamilyV1 {
        id: "devfs",
        summary: "Device-node visibility for hardware interfaces",
        visibility_caveat: "Namespace, cgroup, or privilege limits may hide usable device nodes.",
    },
];

pub fn is_supported_collector_family(id: &str) -> bool {
    CORE_LINUX_COLLECTOR_FAMILIES
        .iter()
        .any(|family| family.id == id)
}
