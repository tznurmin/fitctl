// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

//! Length-first deterministic CBOR over validated JSON-shaped semantic projections.

use std::convert::Infallible;

use minicbor::{encode::Error, Encoder};
use serde::Serialize;
use serde_json::Value;

pub(crate) const SEMANTIC_ENCODING: &str = "fitctl.semantic_cbor.v2";
pub(crate) const POLICY_LOCK_ENCODING: &str = "fitctl.policy-pack-lock.semantic_cbor.v2";

pub(crate) fn to_vec<T: Serialize>(projection: &T) -> Result<Vec<u8>, String> {
    encode_projection(projection, SEMANTIC_ENCODING)
}

pub(crate) fn policy_lock_bytes<T: Serialize>(projection: &T) -> Result<Vec<u8>, String> {
    encode_projection(projection, POLICY_LOCK_ENCODING)
}

fn encode_projection<T: Serialize>(projection: &T, encoding: &str) -> Result<Vec<u8>, String> {
    let content = serde_json::to_value(projection).map_err(|error| error.to_string())?;
    let mut encoder = Encoder::new(Vec::new());
    encoder
        .array(2)
        .and_then(|e| e.str(encoding))
        .map_err(|error| error.to_string())?;
    encode_value(&content, &mut encoder).map_err(|error| error.to_string())?;
    Ok(encoder.into_writer())
}

fn encode_value(value: &Value, encoder: &mut Encoder<Vec<u8>>) -> Result<(), Error<Infallible>> {
    match value {
        Value::Null => {
            encoder.null()?;
        }
        Value::Bool(value) => {
            encoder.bool(*value)?;
        }
        Value::String(value) => {
            encoder.str(value)?;
        }
        Value::Number(value) => {
            if let Some(value) = value.as_u64() {
                encoder.u64(value)?;
            } else if let Some(value) = value.as_i64() {
                encoder.i64(value)?;
            } else {
                let value = value
                    .as_f64()
                    .ok_or_else(|| Error::message("invalid JSON number"))?;
                encode_float(value, encoder)?;
            }
        }
        Value::Array(values) => {
            encoder.array(values.len() as u64)?;
            for value in values {
                encode_value(value, encoder)?;
            }
        }
        Value::Object(values) => {
            let mut entries: Vec<_> = values.iter().collect();
            entries.sort_by(|(a, _), (b, _)| {
                a.len()
                    .cmp(&b.len())
                    .then_with(|| a.as_bytes().cmp(b.as_bytes()))
            });
            encoder.map(entries.len() as u64)?;
            for (key, value) in entries {
                encoder.str(key)?;
                encode_value(value, encoder)?;
            }
        }
    }
    Ok(())
}

fn encode_float(value: f64, encoder: &mut Encoder<Vec<u8>>) -> Result<(), Error<Infallible>> {
    if !value.is_finite() {
        return Err(Error::message("non-finite semantic number"));
    }
    let narrow = value as f32;
    if f64::from(narrow).to_bits() != value.to_bits() {
        encoder.f64(value)?;
        return Ok(());
    }
    // Use the maintained codec's half conversion, but accept it only when lossless.
    let mut half = [0_u8; 3];
    Encoder::new(half.as_mut_slice())
        .f16(narrow)
        .map_err(|_| Error::message("half encoding failed"))?;
    let decoded = minicbor::Decoder::new(&half)
        .f16()
        .map_err(|_| Error::message("half decoding failed"))?;
    if decoded.to_bits() == narrow.to_bits() {
        encoder.f16(narrow)?;
    } else {
        encoder.f32(narrow)?;
    }
    Ok(())
}

#[cfg(test)]
#[path = "canonical_cbor_tests.rs"]
mod tests;
