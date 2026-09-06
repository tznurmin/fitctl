// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

use crate::cli;
use std::io::Write;
use std::process::{Command, Stdio};

#[test]
pub(crate) fn completion_execution_bash_dispatches_collect_for_state_and_validate() {
    let generated = Command::new(cli::fitctl_bin())
        .args(["completion", "bash"])
        .output()
        .unwrap();
    assert!(generated.status.success());
    let mut script = String::from_utf8(generated.stdout).unwrap();
    script.push_str(
        r#"
for cmd in state validate; do
  COMP_WORDS=(fitctl "$cmd" --collect '')
  COMP_CWORD=3
  COMPREPLY=()
  _fitctl_completion
  printf '%s\n' "${COMPREPLY[@]}" | sort
done
"#,
    );
    script.push_str(
        r#"
for cmd in validate classify; do
  COMP_WORDS=(fitctl "$cmd" --validation-mode '')
  COMP_CWORD=3
  COMPREPLY=()
  _fitctl_completion
  [[ " ${COMPREPLY[*]} " == *" state_required "* ]] || exit 31
done
COMP_WORDS=(fitctl config export ''); COMP_CWORD=3; _fitctl_completion
[[ " ${COMPREPLY[*]} " == *" --out-dir "* ]] || exit 32
COMP_WORDS=(fitctl storage profile init ''); COMP_CWORD=4; _fitctl_completion
[[ " ${COMPREPLY[*]} " == *" --min-available-bytes "* ]] || exit 33
COMP_WORDS=(fitctl thermal collect ''); COMP_CWORD=3; _fitctl_completion
[[ " ${COMPREPLY[*]} " == *" --require-target-host-id "* ]] || exit 34
COMP_WORDS=(fitctl resolve-config ''); COMP_CWORD=2; _fitctl_completion
[[ " ${COMPREPLY[*]} " == *" --profile-id "* ]] || exit 35
COMP_WORDS=(fitctl survey --collect ''); COMP_CWORD=3; COMPREPLY=(); _fitctl_completion
[[ " ${COMPREPLY[*]} " != *" hardware-sensors "* ]] || exit 36
"#,
    );
    let shell = std::env::var_os("FITCTL_TEST_BASH").unwrap_or_else(|| "bash".into());
    let mut child = Command::new(shell)
        .args(["--noprofile", "--norc"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(script.as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(
        out.status.success(),
        "status={}; stderr={}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
    let text = String::from_utf8(out.stdout).unwrap();
    for collector in [
        "thermal",
        "memory-reliability",
        "gpu-reliability",
        "cuda-runtime",
        "hardware-sensors",
    ] {
        assert_eq!(
            text.lines().filter(|line| *line == collector).count(),
            2,
            "{collector}: {text}; {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
}
