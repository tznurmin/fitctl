// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

use super::*;
use serde_json::Value;
use std::cell::{Cell, RefCell};
use std::path::PathBuf;

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(LocalProbeIo.suffix("fitctl-cleanup-test-"));
        fs::create_dir(&root).unwrap();
        fs::create_dir(root.join("from")).unwrap();
        fs::create_dir(root.join("to")).unwrap();
        fs::write(root.join("keep"), b"unrelated").unwrap();
        Self(root)
    }

    fn run(&self, pair: bool, io: &Faults) -> Value {
        if pair {
            serde_json::to_value(probe_pair(
                "source",
                &self.0.join("from"),
                "destination",
                &self.0.join("to"),
                "unix:1",
                io,
            ))
            .unwrap()
        } else {
            serde_json::to_value(probe_single(&self.0.join("from"), "unix:1", io)).unwrap()
        }
    }

    fn kept(&self) {
        assert_eq!(fs::read(self.0.join("keep")).unwrap(), b"unrelated");
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).expect("remove only owned fixture root");
    }
}

#[derive(Default)]
struct Faults {
    fail_create: Option<usize>,
    fail_write: bool,
    fail_remove: Vec<usize>,
    creates: Cell<usize>,
    removals: RefCell<Vec<PathBuf>>,
}

fn injected(phase: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        format!("injected {phase} failure"),
    )
}

impl ProbeIo for Faults {
    fn suffix(&self, prefix: &str) -> String {
        format!("{prefix}owned")
    }
    fn create_dir(&self, path: &Path) -> io::Result<()> {
        let index = self.creates.get();
        self.creates.set(index + 1);
        if self.fail_create == Some(index) {
            Err(injected("create"))
        } else {
            fs::create_dir(path)
        }
    }
    fn write(&self, path: &Path, bytes: &[u8]) -> io::Result<()> {
        if self.fail_write {
            Err(injected("write"))
        } else {
            fs::write(path, bytes)
        }
    }
    fn remove_dir_all(&self, path: &Path) -> io::Result<()> {
        let index = self.removals.borrow().len();
        self.removals.borrow_mut().push(path.into());
        if self.fail_remove.contains(&index) {
            Err(injected("remove"))
        } else {
            fs::remove_dir_all(path)
        }
    }
}

fn rows(value: &Value) -> &Vec<Value> {
    value["cleanup"]
        .as_array()
        .expect("cleanup must be explicit even when primary probe fails")
}

fn check_rows(value: &Value, expected: &[&str]) {
    let rows = rows(value);
    assert_eq!(rows.len(), expected.len());
    for (row, outcome) in rows.iter().zip(expected) {
        assert_eq!(row["outcome"], *outcome);
        let path = Path::new(row["probe_root"].as_str().unwrap());
        if *outcome == "remove_failed" {
            assert!(path.exists());
            assert!(row["error"].as_str().unwrap().contains("injected remove"));
        } else {
            assert!(row.get("error").is_none());
            if *outcome == "removed" {
                assert!(!path.exists());
            }
        }
    }
}

#[test]
fn path_link_cleanup_normal_success_and_fault_seam_controls() {
    for pair in [false, true] {
        let fixture = Fixture::new();
        let io = Faults::default();
        let value = fixture.run(pair, &io);
        assert_eq!(value["copy_possible"]["value"], true);
        assert!(value.get("probe_error").is_none());
        assert_eq!(io.removals.borrow().len(), if pair { 2 } else { 1 });
        for root in io.removals.borrow().iter() {
            assert!(!root.exists());
        }
        fixture.kept();
        check_rows(
            &value,
            if pair {
                &["removed", "removed"]
            } else {
                &["removed"]
            },
        );
    }
}

#[test]
fn path_link_cleanup_failures_preserve_link_observations() {
    for (pair, failures, expected) in [
        (false, vec![0], vec!["remove_failed"]),
        (true, vec![0], vec!["remove_failed", "removed"]),
        (true, vec![1], vec!["removed", "remove_failed"]),
        (true, vec![0, 1], vec!["remove_failed", "remove_failed"]),
    ] {
        let fixture = Fixture::new();
        let io = Faults {
            fail_remove: failures,
            ..Default::default()
        };
        let value = fixture.run(pair, &io);
        assert_eq!(value["copy_possible"]["value"], true);
        assert_eq!(value["hardlink_supported"]["value"], true);
        assert!(value.get("probe_error").is_none());
        fixture.kept();
        check_rows(&value, &expected);
        assert_eq!(io.removals.borrow().len(), expected.len());
    }
}

#[test]
fn path_link_cleanup_partial_setup_keeps_primary_failure() {
    for pair in [false, true] {
        for fail_cleanup in [false, true] {
            let fixture = Fixture::new();
            let io = Faults {
                fail_write: true,
                fail_remove: if fail_cleanup { vec![0, 1] } else { vec![] },
                ..Default::default()
            };
            let value = fixture.run(pair, &io);
            assert!(value["probe_error"]
                .as_str()
                .unwrap()
                .contains("injected write"));
            assert_eq!(value["copy_possible"]["value"], false);
            let outcome = if fail_cleanup {
                "remove_failed"
            } else {
                "removed"
            };
            check_rows(&value, &vec![outcome; if pair { 2 } else { 1 }]);
            fixture.kept();
        }
        for fail_create in 0..if pair { 2 } else { 1 } {
            for fail_cleanup in [false, true] {
                let fixture = Fixture::new();
                let io = Faults {
                    fail_create: Some(fail_create),
                    fail_remove: if fail_cleanup { vec![0] } else { vec![] },
                    ..Default::default()
                };
                let value = fixture.run(pair, &io);
                assert!(value["probe_error"]
                    .as_str()
                    .unwrap()
                    .contains("injected create"));
                let mut expected = vec!["not_created"; if pair { 2 } else { 1 }];
                if fail_create == 1 {
                    expected[0] = if fail_cleanup {
                        "remove_failed"
                    } else {
                        "removed"
                    };
                }
                check_rows(&value, &expected);
                assert_eq!(io.removals.borrow().len(), fail_create);
                fixture.kept();
            }
        }
    }
}

#[test]
fn path_link_cleanup_collision_never_removes_unowned_content() {
    for pair in [false, true] {
        let fixture = Fixture::new();
        let prefix = if pair {
            ".fitctl-link-pair-probe-owned-source"
        } else {
            ".fitctl-link-probe-owned"
        };
        let root = fixture.0.join("from").join(prefix);
        fs::create_dir(&root).unwrap();
        fs::write(root.join("other"), b"do not remove").unwrap();
        let io = Faults::default();
        let value = fixture.run(pair, &io);
        assert!(value["probe_error"]
            .as_str()
            .unwrap()
            .contains("failed to create"));
        assert!(io.removals.borrow().is_empty());
        assert_eq!(fs::read(root.join("other")).unwrap(), b"do not remove");
        check_rows(
            &value,
            if pair {
                &["not_created", "not_created"]
            } else {
                &["not_created"]
            },
        );
    }
}

#[test]
fn path_link_cleanup_nonexistent_paths_have_no_owned_roots() {
    let fixture = Fixture::new();
    let missing = fixture.0.join("missing");
    let io = Faults::default();
    let single = serde_json::to_value(probe_single(&missing, "unix:1", &io)).unwrap();
    let pair = serde_json::to_value(probe_pair(
        "from",
        &fixture.0.join("from"),
        "to",
        &missing,
        "unix:1",
        &io,
    ))
    .unwrap();
    assert_eq!(io.creates.get(), 0);
    assert!(io.removals.borrow().is_empty());
    check_rows(&single, &[]);
    check_rows(&pair, &[]);
}

#[test]
fn path_link_cleanup_pair_aliases_have_distinct_owned_roots() {
    let fixture = Fixture::new();
    let io = Faults::default();
    let path = fixture.0.join("from");
    let value = serde_json::to_value(probe_pair("a", &path, "b", &path, "unix:1", &io)).unwrap();
    assert_eq!(value["copy_possible"]["value"], true);
    assert_ne!(rows(&value)[0]["probe_root"], rows(&value)[1]["probe_root"]);
    check_rows(&value, &["removed", "removed"]);
    fixture.kept();
}
