# Changelog

All notable changes to this project will be documented in this file.

The format follows Keep a Changelog and the project uses Semantic Versioning for public release
tags.

## [0.7.0] - 2026-09-05

- opt-in typed voltage, current, power, fan-speed, energy and humidity evidence from lm-sensors,
  including reported limits, flags, value validity, inspect, hash, signing, redaction and replay
- one bounded local capture shared by thermal and hardware-sensor collection
- thermal channel selection excludes voltage, current, power and other non-temperature fields
- corrected Bash, Zsh and Fish collector completion
- sharing profiles reject malformed retained observation and report timestamps without partial output
- direct Rust sharing calls reject invalid hardware sensor relationships before identity replacement
- public Rust snapshot/state structs add `hardware_sensor_resources`; exhaustive struct literals
  must supply it, while old state JSON without the optional section remains readable

## [0.6.0] - 2026-09-05

- target-bound thermal evidence collection, bounded concurrent provider output capture,
  normalized provider diagnostics, and thermal profile generation
- opt-in memory and GPU reliability evidence in live host-state artifacts
- stable storage identity, link capability, and storage-health evidence for checked paths
- service-profile requirements for thermal, reliability, storage, and path admission evidence
- explicit CUDA runtime collection and correct handling of idle GPUs with zero used memory
- typed sharing-profile redaction for provenance, known extension payloads, nested validation data,
  core claim metadata, identity summaries, state paths, service profiles, accelerator topology,
  bundles, recommendation reports, and batch reports, with omitted state identity metadata,
  canonicalized engine provenance, authenticated extension payload/basis coherence, sanitized
  imported core and auxiliary provenance, paired recommendation-pack identity redaction, fail-closed
  unknown-extension handling, and closed-category validation
- compiler-controlled opt-in VCS build provenance, including untracked-file dirty state and
  warm-build freshness

## [0.5.0] - 2026-06-12

- installed configuration listing and export through `fitctl config list` and `fitctl config export --out-dir <dir>`
- bundled configuration assets shipped with the installed binary
- repository-free examples using exported `configs/...` paths
- path-capacity state collection through `fitctl state --path-check <id>=<path>`
- live path checks during validation through `fitctl validate --live-state --path-check <id>=<path>`
- `required_paths` service-profile requirements for minimum available filesystem capacity
- storage-aware validation for model caches, output directories, scratch paths, and similar workload paths
- workload report guidance for attaching `survey`, `contract`, `state`, and `validation` artifacts to external run reports
- state semantic hashes include path-resource evidence
- auditor and external redaction profiles redact checked path strings from state artifacts

## [0.4.0] - 2026-06-11

- direct validation gate flags for workload pre-flight: `--fail-on-unfit` and `--require-fit`
- validation gate behavior preserves the JSON report on stdout while process exit status carries the gate result
- batch `rows_csv` export includes host aliases and display labels for host-selection automation
- GitHub Actions self-hosted GPU runner example for CUDA runtime pre-flight
- host matrix selection example for state-aware candidate-host comparison
- built-in runtime extension packs for `fitctl.runtime.cuda`, `fitctl.runtime.python`, and `fitctl.runtime.node`
- public issue template for artifact-driven host reports
- canonical Apache-2.0 license text plus project `NOTICE`

## [0.3.0] - 2026-04-24

- richer GPU inspection in the normal operator flow, including CUDA driver/toolkit/runtime detail
- runtime-aware GPU admission from live host state
- multi-GPU and qualifying-device memory validation
- machine-id-first local stable identity for stateful correlation and container-visible OS-instance semantics
- compact inspect tightening for survey/state accelerator and memory summaries plus the new `inspect --view coverage` surface
- explicit CUDA `used_memory_bytes` collection so inspect no longer infers GPU used memory from allocatable/total arithmetic
- optional build provenance fields kept separate from the release-line `fitctl_version`

## [0.2.0] - 2026-04-18

- typed host decision flow: `survey`, `contract`, `validate`, and `inspect`
- policy and service-profile configuration for contract derivation and fit decisions
- batch classification and matrix inspect view for comparing hosts against workload profiles
- host-state artifacts and state-aware validation for runtime-sensitive checks
- signing, verification, redaction, bundle, export, and recommendation report surfaces
- public documentation set for configuration, contracts, validation, and artifacts
