// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

use std::os::unix::process::ExitStatusExt;
use std::process::{Command, ExitStatus, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

const CHILD_MODE: &str = "FITCTL_TEST_THREAD_EFFECT_CHILD";

pub fn selected_mode() -> Option<String> {
    std::env::var(CHILD_MODE).ok()
}

pub fn exercise(test: &str, mode: &str, action: impl Fn() + Send + Sync + 'static) -> ExitStatus {
    if std::env::var(CHILD_MODE).as_deref() == Ok(mode) {
        let limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // Expected SIGSYS controls must not generate persistent core dumps.
        assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_CORE, &limit) }, 0);
        assert_eq!(unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0) }, 0);
        let action = Arc::new(action);
        let threads: Vec<_> = (0..2)
            .map(|_| {
                let action = Arc::clone(&action);
                std::thread::spawn(move || {
                    trap_external_acquisition();
                    action();
                })
            })
            .collect();
        for thread in threads {
            thread.join().expect("guarded caller should finish");
        }
        std::process::exit(0);
    }
    let mut child = Command::new(std::env::current_exe().expect("test executable"))
        .args(["--exact", test, "--nocapture", "--test-threads=1"])
        .env(CHILD_MODE, mode)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("owned effect probe should start");
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return status,
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(5)),
            result => {
                let _ = child.kill();
                let _ = child.wait();
                panic!("owned effect probe failed or exceeded deadline: {result:?}");
            }
        }
    }
}

pub fn expect_trap(status: ExitStatus) {
    assert_eq!(
        status.signal(),
        Some(libc::SIGSYS),
        "guard control: {status}"
    );
}

fn trap_external_acquisition() {
    let mut filter = vec![libc::sock_filter {
        code: (libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16,
        jt: 0,
        jf: 0,
        k: 0, // seccomp_data.nr
    }];
    let syscalls = [
        libc::SYS_getrandom,
        libc::SYS_openat,
        libc::SYS_openat2,
        libc::SYS_socket,
        libc::SYS_connect,
        libc::SYS_execve,
        libc::SYS_execveat,
        libc::SYS_clone,
        libc::SYS_clone3,
    ];
    #[cfg(target_arch = "x86_64")]
    let legacy = &[
        libc::SYS_open,
        libc::SYS_creat,
        libc::SYS_fork,
        libc::SYS_vfork,
    ];
    #[cfg(not(target_arch = "x86_64"))]
    let legacy: &[libc::c_long] = &[];
    for syscall in syscalls.into_iter().chain(legacy.iter().copied()) {
        filter.push(libc::sock_filter {
            code: (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16,
            jt: 0,
            jf: 1,
            k: syscall as u32,
        });
        filter.push(libc::sock_filter {
            code: (libc::BPF_RET | libc::BPF_K) as u16,
            jt: 0,
            jf: 0,
            k: libc::SECCOMP_RET_TRAP,
        });
    }
    filter.push(libc::sock_filter {
        code: (libc::BPF_RET | libc::BPF_K) as u16,
        jt: 0,
        jf: 0,
        k: libc::SECCOMP_RET_ALLOW,
    });
    let program = libc::sock_fprog {
        len: filter.len() as u16,
        filter: filter.as_mut_ptr(),
    };
    // No TSYNC: the irreversible filter affects this fresh test thread only.
    assert_eq!(
        unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) },
        0
    );
    assert_eq!(
        unsafe { libc::prctl(libc::PR_SET_SECCOMP, libc::SECCOMP_MODE_FILTER, &program) },
        0
    );
}
