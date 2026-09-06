// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

//! Duplicate-rejecting classic sensors JSON decoder; bounded bytes are checked before entry.

use serde::{
    de::{Error, MapAccess, SeqAccess, Visitor},
    Deserialize, Deserializer,
};
use serde_json::{Map, Number, Value};

struct Unique(Value);
impl<'de> Deserialize<'de> for Unique {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        d.deserialize_any(UniqueVisitor)
    }
}
struct UniqueVisitor;
impl<'de> Visitor<'de> for UniqueVisitor {
    type Value = Unique;
    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("JSON with unique object keys")
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Unique, A::Error> {
        let mut out = Map::new();
        while let Some(key) = map.next_key::<String>()? {
            if out.contains_key(&key) {
                return Err(A::Error::custom("hardware_sensor_duplicate_key"));
            }
            out.insert(key, map.next_value::<Unique>()?.0);
        }
        Ok(Unique(Value::Object(out)))
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Unique, A::Error> {
        let mut out = Vec::new();
        while let Some(item) = seq.next_element::<Unique>()? {
            out.push(item.0);
        }
        Ok(Unique(Value::Array(out)))
    }
    fn visit_bool<E: Error>(self, v: bool) -> Result<Unique, E> {
        Ok(Unique(Value::Bool(v)))
    }
    fn visit_i64<E: Error>(self, v: i64) -> Result<Unique, E> {
        Ok(Unique(Value::Number(v.into())))
    }
    fn visit_u64<E: Error>(self, v: u64) -> Result<Unique, E> {
        Ok(Unique(Value::Number(v.into())))
    }
    fn visit_f64<E: Error>(self, v: f64) -> Result<Unique, E> {
        Number::from_f64(v)
            .map(|n| Unique(Value::Number(n)))
            .ok_or_else(|| E::custom("nonfinite number"))
    }
    fn visit_str<E: Error>(self, v: &str) -> Result<Unique, E> {
        Ok(Unique(Value::String(v.to_owned())))
    }
    fn visit_unit<E: Error>(self) -> Result<Unique, E> {
        Ok(Unique(Value::Null))
    }
}

pub(super) fn decode(text: &str) -> Result<Value, super::hardware_sensors_v1::SensorError> {
    use crate::artifacts::hardware_sensor_resources_v1::HardwareSensorReasonV1::*;
    serde_json::from_str::<Unique>(text)
        .map(|v| v.0)
        .map_err(|e| {
            super::hardware_sensors_v1::SensorError::new(
                if e.to_string().contains("hardware_sensor_duplicate_key") {
                    HardwareSensorDuplicateKey
                } else {
                    HardwareSensorJsonMalformed
                },
                "hardware_sensor_decode",
            )
        })
}
