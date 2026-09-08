// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

use fitctl_core::{config, contract, policy, service_profile};
use serde_json::Value;

pub fn policy() -> Value {
    serde_json::from_str(include_str!(
        "../../../../configs/policy/general_compute_default.v1.json"
    ))
    .unwrap()
}

pub fn profile() -> Value {
    serde_json::from_str(include_str!(
        "../../../../configs/service_profiles/general_compute_contract_only.v2.json"
    ))
    .unwrap()
}

pub fn pack() -> Value {
    serde_json::from_str(include_str!(
        "../../../../configs/extensions/fitctl_runtime_cuda.v1.json"
    ))
    .unwrap()
}

pub fn context() -> Value {
    serde_json::from_str(include_str!(
        "../../../../configs/invocation_contexts/core_default.v1.json"
    ))
    .unwrap()
}

#[derive(Debug, PartialEq, Eq)]
pub struct Fault {
    pub model: &'static str,
    pub version: u32,
    pub code: &'static str,
    pub checkpoint: &'static str,
    pub message: String,
}

macro_rules! fault_from {
    ($error:ty) => {
        impl From<$error> for Fault {
            fn from(error: $error) -> Self {
                Self {
                    model: error.error_model_id,
                    version: error.error_model_version,
                    code: error.code.as_str(),
                    checkpoint: error.checkpoint_id,
                    message: error.message,
                }
            }
        }
    };
}
fault_from!(contract::ContractDerivationError);
fault_from!(service_profile::ServiceProfileError);
fault_from!(config::ConfigError);

#[derive(Debug, Clone, Copy)]
pub enum Family {
    Policy,
    Profile,
    Pack,
    Context,
}

impl Family {
    pub fn value(self, raw: Value) -> Result<Value, Fault> {
        match self {
            Self::Policy => policy::load_policy_document_from_value(raw)
                .map(|value| serde_json::to_value(value).unwrap())
                .map_err(Fault::from),
            Self::Profile => service_profile::load_service_profile_from_value(raw)
                .map(|value| serde_json::to_value(value).unwrap())
                .map_err(Fault::from),
            Self::Pack => config::load_extension_pack_from_value(raw)
                .map(|value| serde_json::to_value(value).unwrap())
                .map_err(Fault::from),
            Self::Context => config::load_invocation_context_from_value(raw)
                .map(|value| serde_json::to_value(value).unwrap())
                .map_err(Fault::from),
        }
    }

    pub fn path(self, path: &Path) -> Result<Value, Fault> {
        match self {
            Self::Policy => policy::load_policy_document_from_path(path)
                .map(|value| serde_json::to_value(value).unwrap())
                .map_err(Fault::from),
            Self::Profile => service_profile::load_service_profile_from_path(path)
                .map(|value| serde_json::to_value(value).unwrap())
                .map_err(Fault::from),
            Self::Pack => config::load_extension_pack_from_path(path)
                .map(|value| serde_json::to_value(value).unwrap())
                .map_err(Fault::from),
            Self::Context => config::load_invocation_context_from_path(path)
                .map(|value| serde_json::to_value(value).unwrap())
                .map_err(Fault::from),
        }
    }

    pub fn model(self) -> &'static str {
        match self {
            Self::Policy => "fitctl.contract_derivation.v1",
            Self::Profile => "fitctl.service_profile.v1",
            Self::Pack | Self::Context => "fitctl.config.v1",
        }
    }
}

pub struct TestRoot(PathBuf);

impl TestRoot {
    pub fn new() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let path = std::env::temp_dir().join(format!(
            "fitctl-value-loaders-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }

    pub fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for TestRoot {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).expect("remove owned path-parity fixtures");
    }
}

pub fn assert_case(family: Family, name: &str, raw: Value, expected: Option<(&str, &str)>) {
    let root = TestRoot::new();
    let path = root.path("document.json");
    fs::write(&path, serde_json::to_vec(&raw).unwrap()).unwrap();
    let memory = family.value(raw);
    let disk = family.path(&path);
    match expected {
        None => assert_eq!(memory.unwrap(), disk.unwrap(), "{family:?}/{name}"),
        Some((code, checkpoint)) => {
            let memory = memory.unwrap_err();
            let disk = disk.unwrap_err();
            assert_eq!(
                (memory.model, memory.version, memory.code, memory.checkpoint),
                (family.model(), 1, code, checkpoint),
                "{family:?}/{name}: {memory:?}"
            );
            assert_eq!(
                (disk.model, disk.version, disk.code, disk.checkpoint),
                (memory.model, memory.version, memory.code, memory.checkpoint),
                "{family:?}/{name}"
            );
            assert!(!memory.message.contains(path.to_str().unwrap()));
            // Only typed-decode diagnostics add the actual path in file ingress.
            let normalized = disk.message.replace(&format!(" {}:", path.display()), ":");
            assert_eq!(memory.message, normalized, "{family:?}/{name}");
        }
    }
}

#[test]
fn path_io_errors_keep_real_paths() {
    let root = TestRoot::new();
    for family in [
        Family::Policy,
        Family::Profile,
        Family::Pack,
        Family::Context,
    ] {
        for (name, bytes, read_error) in [
            ("absent.json", None, true),
            ("invalid.json", Some(b"{".as_slice()), false),
            ("invalid-utf8.json", Some(b"\xff".as_slice()), true),
        ] {
            let path = root.path(name);
            if let Some(bytes) = bytes {
                fs::write(&path, bytes).unwrap();
            }
            let fault = family.path(&path).unwrap_err();
            assert_eq!((fault.model, fault.version), (family.model(), 1));
            let (code, checkpoint) = match family {
                Family::Policy => ("policy_document_invalid", "policy_load"),
                Family::Profile => (
                    "service_profile_document_invalid",
                    if read_error {
                        "profile_load"
                    } else {
                        "profile_decode"
                    },
                ),
                _ => ("config_input_invalid", "config_load"),
            };
            assert_eq!((fault.code, fault.checkpoint), (code, checkpoint));
            assert!(fault.message.contains(path.to_str().unwrap()), "{fault:?}");
            assert!(
                fault.message.starts_with(if read_error {
                    "failed to read "
                } else {
                    "failed to decode "
                }),
                "{fault:?}"
            );
        }
    }
}
