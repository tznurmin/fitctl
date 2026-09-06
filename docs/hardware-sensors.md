# Hardware Sensors

`hardware-sensors` is an opt-in collector added in `0.7.0`. It records local electrical and cooling
observations, not a health verdict.

```bash
fitctl state --live --collect hardware-sensors > host.state.json
fitctl inspect --input host.state.json
```

Add `--collect thermal` to collect temperatures too. The identical built-in local provider shares
one bounded `sensors -j` capture per invocation; NVIDIA and configured thermal providers retain
their separate collection paths. There is no persistent cache or background polling.

## Quantities

Values come from classic `lm-sensors` JSON, which already uses libsensors conversion and labels.
They are not raw sysfs integers. fitctl does not require a device catalogue or per-board mapping.

| Channel | Quantity | Stored integer unit |
|---|---|---|
| `inN_input` (`N >= 0`) | voltage | microvolts |
| `currN_input` | current | microamperes |
| `powerN_input`, `powerN_average` | input or average power | microwatts |
| `fanN_input` | fan speed | millirevolutions per minute |
| `energyN_input` | cumulative energy | microjoules |
| `humidityN_input` | relative humidity | millipercent |

Other indexes start at one; leading zeros and unknown channel families are not accepted as
measurements. Only `tempN_input` is temperature evidence. Display labels never select units.
Finite JSON numbers are scaled and rounded to the nearest integer, with ties away from zero;
overflow is rejected. Voltage, current and power may be signed. Fan speed and energy cannot be
negative; humidity must be between 0 and 100 percent. Zero is an observed value, not missing data.

Supported provider-reported limits and alarm/fault flags are retained separately. An asserted fan
fault makes its numeric reading `faulted`, not usable `observed` evidence. Limits are not fitctl
threshold recommendations, and no alarm is calculated by comparing a value with a reported limit.
PWM, setpoints, controls, history and inferred rail/component identities are outside this collector.

The channel convention and JSON boundary follow the [Linux hwmon interface](https://docs.kernel.org/hwmon/sysfs-interface.html)
and [lm-sensors JSON emitter](https://github.com/lm-sensors/lm-sensors/blob/master/prog/sensors/chips.c).
The alternative `sensors -J` layout is not supported.

## Evidence and failure

The optional `state.core_state.hardware_sensor_resources` section contains its observation time,
collector identity, providers and readings. Every reading carries provider/chip/channel identity,
target, quantity, unit, measurement kind, nullable integer value, value state, reported limits and
flags. Provider outcomes distinguish success, partial, malformed, unavailable, permission denied
and command failure. Reason codes identify timeout, output limits, invalid values and missing data.

Valid sibling values survive individual malformed fields as partial evidence. Duplicate raw keys,
corrupt/unsupported JSON, more than 4096 readings or an identifier/label over 1024 UTF-8 bytes reject
the provider projection. Capture uses the existing five-second timeout, 1 MiB stdout cap and
4096-byte retained stderr bound. Raw command dumps are not retained. Command success means an
artifact was emitted, not that all sensors succeeded or the host is fit.

Linux and `sensors` are required for live collection. Missing tools or unsupported platforms are
explicitly unavailable. A machine need not expose every quantity. Replay uses only its supplied
snapshot and time, never a live fallback.

`fitctl validate --live-state --collect hardware-sensors --state-out host.state.json` can retain
this evidence with an otherwise valid contract/profile invocation. Existing validation requirements
and exit semantics are unchanged; these measurements satisfy no new host-fit or thermal requirement.

## Consumers and compatibility

Inspect, hashing, diff, signing and redaction validate the typed section. Hashes ignore observation
times, diagnostics and display labels, but retain quantities, validity, targets, limits and flags.
`auditor` and `external` replace hardware provider/chip/sensor/host identities, labels and diagnostics;
`local` and `fleet` retain them. Numeric facts and valid observation times stay visible. Sharing
profiles reject arbitrary text in section, provider or reading timestamps, even when those values
match each other. See the [timestamp grammar](./artifacts.md). Direct Rust sharing calls also reject
invalid hardware sections before replacing identities, including undeclared providers, rather than
panicking. Redaction clears signatures; inspect the entire artifact before sharing it.

Old state documents without the optional section remain readable and keep their semantic projection.
Old strict readers are not promised to accept a newly populated section. Public Rust additions are
`HardwareSensorResourcesV1` and its typed components, the parser/validator APIs, the opt-in live probe
builder, and an optional field on `HostStateCoreV1`, `CollectedHostStateSnapshotV1` and
`HostStateFixtureSnapshotV1`. Exhaustive Rust struct literals must supply the new field. This is why
the feature uses the `0.7.0` minor release, not an API-compatible `0.6.1` patch.
