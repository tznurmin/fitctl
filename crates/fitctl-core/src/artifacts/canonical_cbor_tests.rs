// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

use super::*;
use serde_json::json;

fn encoded(value: Value) -> Vec<u8> {
    let mut encoder = Encoder::new(Vec::new());
    encode_value(&value, &mut encoder).unwrap();
    encoder.into_writer()
}

#[test]
fn semantic_encoding_literal_numbers_and_null() {
    for (value, expected) in [
        (json!(null), vec![0xf6]),
        (json!([]), vec![0x80]),
        (json!({}), vec![0xa0]),
        (json!(23), vec![0x17]),
        (json!(24), vec![0x18, 0x18]),
        (json!(256), vec![0x19, 0x01, 0x00]),
        (json!(-25), vec![0x38, 0x18]),
        (
            json!(u64::MAX),
            vec![0x1b, 255, 255, 255, 255, 255, 255, 255, 255],
        ),
        (
            json!(i64::MIN),
            vec![0x3b, 127, 255, 255, 255, 255, 255, 255, 255],
        ),
        (json!(1.5), vec![0xf9, 0x3e, 0x00]),
        (json!(-0.0), vec![0xf9, 0x80, 0x00]),
        (json!(0.0), vec![0xf9, 0x00, 0x00]),
        (json!(100000.0), vec![0xfa, 0x47, 0xc3, 0x50, 0x00]),
        (
            json!(1.1),
            vec![0xfb, 0x3f, 0xf1, 0x99, 0x99, 0x99, 0x99, 0x99, 0x9a],
        ),
    ] {
        assert_eq!(encoded(value), expected);
    }
}

#[test]
fn semantic_encoding_all_maps_are_length_first_including_unicode() {
    let value = json!({"aa": {"zz": 1, "b": 2}, "z": null, "\u{e9}": true});
    assert_eq!(
        encoded(value),
        vec![
            0xa3, 0x61, b'z', 0xf6, 0x62, b'a', b'a', 0xa2, 0x61, b'b', 2, 0x62, b'z', b'z', 1,
            0x62, 0xc3, 0xa9, 0xf5,
        ]
    );
    assert_ne!(encoded(json!([1, 2])), encoded(json!([2, 1])));
}

#[test]
fn semantic_encoding_has_explicit_domain_and_preserves_optional_values() {
    #[derive(Serialize)]
    struct Projection {
        #[serde(skip_serializing_if = "Option::is_none")]
        absent: Option<u8>,
        null: Option<u8>,
        empty: Vec<u8>,
    }
    let bytes = to_vec(&Projection {
        absent: None,
        null: None,
        empty: vec![],
    })
    .unwrap();
    let mut decoder = minicbor::Decoder::new(&bytes);
    assert_eq!(decoder.array().unwrap(), Some(2));
    assert_eq!(decoder.str().unwrap(), SEMANTIC_ENCODING);
    assert_eq!(
        &bytes[decoder.position()..],
        &[0xa2, 0x64, b'n', b'u', b'l', b'l', 0xf6, 0x65, b'e', b'm', b'p', b't', b'y', 0x80]
    );
    assert_ne!(
        to_vec(&json!(null)).unwrap(),
        policy_lock_bytes(&json!(null)).unwrap()
    );
}

#[test]
fn semantic_encoding_projection_errors_are_not_success() {
    struct Invalid;
    impl Serialize for Invalid {
        fn serialize<S: serde::Serializer>(&self, _: S) -> Result<S::Ok, S::Error> {
            Err(serde::ser::Error::custom("invalid projection"))
        }
    }
    assert!(to_vec(&Invalid).unwrap_err().contains("invalid projection"));
    assert!(encode_float(f64::NAN, &mut Encoder::new(Vec::new())).is_err());
}
