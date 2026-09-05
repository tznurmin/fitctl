// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

use super::*;

#[test]
fn capture_keeps_bounded_prefix_but_drains_all_bytes() {
    for limit in [MAX_PROVIDER_OUTPUT_BYTES + 1, MAX_PROVIDER_STDERR_BYTES] {
        let mut input = io::repeat(b'x').take((limit * 4) as u64);
        let mut capture = BoundedCapture::new(limit);
        while !capture.eof {
            capture.drain_available(&mut input).expect("drain input");
            assert!(capture.bytes.len() <= limit);
            assert_eq!(capture.bytes.capacity(), limit);
        }
        assert_eq!(capture.bytes, vec![b'x'; limit]);
        assert_eq!(input.limit(), 0);
    }
}

#[test]
fn continuous_output_is_budgeted_per_turn() {
    let mut input = CountingReader(0);
    let mut capture = BoundedCapture::new(1);
    assert!(capture
        .drain_available(&mut input)
        .expect("budgeted read must return"));
    assert_eq!(capture.bytes, [b'x']);
    assert!(!capture.eof);
    assert_eq!(input.0, 8);
}

#[test]
fn interrupted_and_would_block_reads_do_not_claim_eof() {
    for kind in [io::ErrorKind::Interrupted, io::ErrorKind::WouldBlock] {
        let mut capture = BoundedCapture::new(16);
        assert!(!capture
            .drain_available(&mut ErrorReader(kind))
            .expect("bounded retry"));
        assert!(!capture.eof);
        assert!(capture.bytes.is_empty());
    }
}

#[test]
fn read_error_remains_a_typed_command_failure() {
    let mut capture = BoundedCapture::new(16);
    let error = capture
        .drain_available(&mut ErrorReader(io::ErrorKind::BrokenPipe))
        .expect_err("reader failure");
    let failure = capture_error(error);
    assert_eq!(failure.outcome, ThermalProviderOutcomeV1::CommandFailed);
    assert_eq!(failure.error_code, THERMAL_PROVIDER_COMMAND_FAILED);
    assert!(!capture.eof);
}

struct ErrorReader(io::ErrorKind);

struct CountingReader(usize);

impl Read for CountingReader {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.0 += 1;
        assert!(self.0 <= 8, "one stream exceeded its per-turn read budget");
        buffer.fill(b'x');
        Ok(buffer.len())
    }
}

impl Read for ErrorReader {
    fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
        Err(io::Error::from(self.0))
    }
}
