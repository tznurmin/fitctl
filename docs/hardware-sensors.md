# Hardware Sensors

Use `hardware-sensors` to record voltage, current, power and fan speed from a Linux host. Energy
counters and humidity readings are included when the hardware exposes them.

These are measurements, not a health verdict. Temperatures belong to the separate `thermal`
collector.

## Collect readings

Live collection requires `lm-sensors`, with the `sensors` command available. To collect hardware
readings and temperatures together:

```bash
fitctl state --live --collect hardware-sensors --collect thermal > host.state.json
fitctl inspect --input host.state.json
```

Omit `--collect thermal` if you only want the non-temperature readings. `inspect` displays the two
groups separately, using units such as volts, watts, RPM and degrees Celsius.

Each invocation takes one snapshot; it does not start a background monitor. The built-in collectors
share one local `sensors -j` capture. GPU temperatures and configured thermal providers use their
own collection paths.

To try the output without reading live hardware, use the bundled fixture:

```bash
fitctl state --fixture linux-hardware-sensors-v1 | fitctl inspect
```

## Read the values

The channel type determines the quantity. A power reading stays a power reading even if its label
contains a temperature or voltage name. fitctl does not need a separate configuration for each
device, and it does not infer which physical rail or component a label represents.

| Reading | Display unit | Example interpretation |
|---|---|---|
| Voltage | V | An observed rail voltage, not a statement that it is within a safe range |
| Current | A | Current reported by the sensor |
| Power | W | Input or average power, kept as distinct measurements |
| Fan speed | RPM | Zero means an observed stationary fan, not a missing reading |
| Energy | J | A cumulative counter, not power or per-workload energy use |
| Relative humidity | %RH | A reading between 0 and 100 percent |

Provider-reported limits, alarms and faults appear alongside the reading. They are not thresholds
chosen by fitctl, and fitctl does not calculate an alarm by comparing a value with a reported limit.
An asserted fan fault makes that reading `faulted`, even if the provider also supplied a number.

## Missing or faulty readings

A host need not expose every quantity. Missing tools, unsupported platforms, access failures and
invalid values remain explicit in the artifact; they are not replaced with zero or a healthy status.

If an individual field is malformed, valid sibling readings can remain as partial evidence.
Malformed structure or exceeded collection limits reject the provider's readings instead.
Provider outcomes and reason codes distinguish these cases from a sensor reporting a fault.

Successful command execution means fitctl emitted an artifact. Check its provider outcomes and
reading validity before using the numbers; command success does not mean every sensor succeeded.

## Use the JSON

Automation should read `state.core_state.hardware_sensor_resources`, not parse `inspect` output:

```bash
jq '.state.core_state.hardware_sensor_resources' host.state.json
```

The section contains observation time, collector identity, provider results and individual readings.
Each reading includes its source and target, quantity, unit, measurement kind, value and validity.
Read `value_state` together with `value`; a stored number can still be marked invalid or faulted.

Hardware readings can accompany a [validation](./validation.md) request, including collection through
`--live-state --collect hardware-sensors --state-out host.state.json`. They do not satisfy thermal
requirements or add voltage, fan-speed or other admission thresholds.

Replay uses only the supplied snapshot and time. It never falls back to live collection.

## Units and collection limits

JSON stores scaled integers; `inspect` converts them to the display units above. For example,
`12000000` microvolts represents `12 V`.

| Source channel | Stored integer unit |
|---|---|
| `inN_input` | microvolts |
| `currN_input` | microamperes |
| `powerN_input`, `powerN_average` | microwatts |
| `fanN_input` | millirevolutions per minute |
| `energyN_input` | microjoules |
| `humidityN_input` | millipercent |

Values come from classic `sensors -j` JSON after libsensors conversion, not raw sysfs integers.
Index zero is allowed for `inN`; the other families start at one. Leading zeros, unknown channel
families and the alternative `sensors -J` layout are not supported. Only `tempN_input` supplies
temperature evidence. PWM controls, setpoints and history are not collected.

Finite numbers are rounded to the nearest stored integer, with ties away from zero; overflow is
rejected. Voltage, current and power may be signed. Fan speed and energy cannot be negative.

| Collection bound | Limit |
|---|---|
| Provider command | 5 seconds |
| Standard output | 1 MiB |
| Retained error output | 4096 bytes |
| Readings | 4096 |
| Identifier or label | 1024 UTF-8 bytes |

Duplicate JSON keys and unsupported structure cause the provider's readings to be rejected. Raw
command dumps are not retained. Channel conventions follow the [Linux hwmon interface](https://docs.kernel.org/hwmon/sysfs-interface.html)
and [lm-sensors JSON emitter](https://github.com/lm-sensors/lm-sensors/blob/master/prog/sensors/chips.c).

## Share a snapshot

The `external` and `auditor` profiles replace hardware identities, labels and diagnostics while
keeping numeric facts and valid observation times. `local` and `fleet` retain more identifying
detail. Redaction validates the section and its timestamps, and clears signatures.

Review the whole JSON before sharing it. See [Share a redacted artifact](../README.md#share-a-redacted-artifact)
and the [artifact reference](./artifacts.md#common-envelope) for the disclosure boundary.

## Compatibility

This optional section was added in `0.7.0`. State documents without it remain readable and keep the
same semantic projection; older strict readers may reject documents that include it.

Inspect, diff, hashing, signing and redaction validate the section. Semantic hashes retain the
quantities, validity, targets, limits and flags, but exclude observation times, diagnostics and
display labels.

Rust callers using exhaustive `HostStateCoreV1`, `CollectedHostStateSnapshotV1` or
`HostStateFixtureSnapshotV1` literals must supply the optional `hardware_sensor_resources` field.
The public API also includes `HardwareSensorResourcesV1`, its component types and collection and
validation entry points.
