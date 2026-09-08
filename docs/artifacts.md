# Artifacts

Artifacts are typed JSON records emitted at each step of the decision flow. They are the stable
handoff format between collection, contract derivation, validation, inspection, and automation.

Common artifacts in the local decision flow:

| Artifact | Produced by | Contains |
|---|---|---|
| `host-survey.v2` | `fitctl survey` | observed host evidence |
| `host-contract.v2` | `fitctl contract` | policy-shaped claim |
| `host-state.v2` | `fitctl state` | current runtime-sensitive facts |
| `fitctl.thermal-evidence.v1` | `fitctl thermal collect` | target-bound thermal evidence |
| `validation-report.v2` | `fitctl validate` | verdict, posture, reason codes, evidence |
| `fitctl.batch-classification-report.v3` | `fitctl classify` | multi-contract, multi-profile comparison |

Artifacts are JSON. `fitctl inspect` can print text views, and automation can read the JSON
directly.

Opt-in typed [hardware sensor evidence](./hardware-sensors.md) can be added to
`host-state.v2`; it is separate from temperature and admission policy.

Read any supported artifact with `inspect`:

```bash
fitctl inspect --input <artifact.json>
```

Other inspectable top-level artifacts include service profiles, config bundles, decision bundles,
batch classification reports, and recommendation reports.

For grouped coverage detail on survey, contract, and state artifacts, use:

```bash
fitctl inspect --input <artifact.json> --view coverage
```

Example shapes are under
[fixtures/schema_shapes/core_extension_split/valid](../fixtures/schema_shapes/core_extension_split/valid).
Conformance examples are under [fixtures/conformance/valid](../fixtures/conformance/valid).
Some conformance fixtures intentionally preserve older `fitctl_version` provenance values to
exercise compatibility with artifacts produced by earlier release lines.

[Contracts](./contracts.md) covers contract meaning. [Configuration](./configuration.md) covers
policies and service profiles. [Validation](./validation.md) covers the decision flow.

Namespaced runtime examples in this repository use `fitctl.runtime.*` extension identifiers.

## Semantic encoding

Version 0.8.0 uses `fitctl.semantic_cbor.v2`: one CBOR array containing the encoding
identifier and the validated semantic projection. Maps use UTF-8 text keys in length-first order;
collections have definite lengths and numbers use their shortest lossless widths. JSON formatting
is not hashed. Policy-pack locks use `fitctl.policy-pack-lock.semantic_cbor.v2`.

This replaces the 0.7 encoding, including incorrect optional-map lengths. Old signatures are not
accepted under the new encoding. Regenerate hashes, policy locks, derived artifacts and reference
chains together, then sign them again. Changing a version label does not update a stored hash.
Unsigned JSON shapes are unchanged; a raw SHA-256 digest does not identify its encoding version.

## Common envelope

Every supported artifact contains an `envelope` section.

`envelope` records schema identity, artifact identity, provenance, and optional redaction and
signatures.

It carries:

- `schema_id`
- `schema_version`
- `artifact_id`
- `provenance`
- optional `redaction`
- optional `signatures`

`schema_version` is the shared top-level envelope version. The artifact family version is encoded
in `schema_id`; these values can differ, as with `fitctl.batch-classification-report.v3` using
envelope schema version 2.

`envelope.provenance` keeps the release-line field `fitctl_version` separate from optional build
provenance. When available, build provenance may also include:

- `fitctl_vcs_revision`
- `fitctl_vcs_describe`
- `fitctl_build_dirty`

Source builds omit these VCS fields by default. Set `FITCTL_EMBED_VCS=1` only when building from
the fitctl workspace root and intentionally recording that checkout's revision. The build script is
the sole authority for these values; ambient `FITCTL_VCS_*` variables are not read by product code.
Untracked files count toward `fitctl_build_dirty` when VCS embedding is enabled.
Opted-in builds refresh the snapshot on every Cargo invocation, including builds reusing an
existing target directory. This may cause additional rebuild work; default builds do not collect
VCS metadata.

`fitctl redact` accepts the core decision artifacts, configuration and decision bundles, and
standalone recommendation and batch-classification reports. Every non-local profile replaces
`correlation_id` with the final redacted artifact id. The `auditor` and `external` profiles replace
`source` and remove all three optional VCS fields; `local` and `fleet` retain source and VCS values.
The same rule applies recursively to envelopes nested in bundles.

For `auditor` and `external`, each populated extension section must have a registered,
section-specific typed redactor. Unknown namespaces and known namespaces used in unsupported
sections fail closed instead of passing through unchanged. In host contracts, enabled
extension-basis namespaces must match semantic-hash keys, payload namespaces must be a subset of
the enabled basis, and non-empty extension payloads require a basis. Retained extension semantic
hashes must be 64 lowercase hexadecimal characters. This permits an enabled extension with no
observed payload to remain a valid evidence-incomplete input.

Every core and auxiliary envelope receives the same collection timestamp/version check at the
`auditor`/`external` sharing boundary, including supported nested bundle envelopes. Collection
timestamps must be `epoch:<seconds>`, `unix:<seconds>` (unsigned 64-bit seconds), or whole-second
UTC `YYYY-MM-DDTHH:MM:SSZ` with valid calendar/time fields. Malformed timestamps fail redaction
without an output artifact; no replacement time is invented. Plain numeric `major.minor.patch`
fitctl versions remain available; custom/prerelease/build suffixes are replaced with deterministic
profile-scoped placeholders. This checks version syntax, not publication status. Recognized core
command names are preserved; auxiliary command names use the existing placeholder rule.
Ordinary artifact loading and `local`/`fleet` provenance compatibility are unchanged.

The same grammar applies to retained typed payload times: state freshness, thermal and hardware
sensor observations, memory/GPU reliability, path/link/storage-health checks, contract derivation,
validation-basis state observations, recommendation freshness and batch validation/matched-state
times. Supported decision-bundle members and the supplied redaction time are checked too.
Invalid payload times fail at `sharing_timestamp_validate`, without echoing rejected text or
emitting a partial artifact. Valid timestamps and optional absence remain unchanged; syntax checks
do not establish freshness or require independently collected sections to share a timestamp.

Those profiles also transform typed core claim metadata, free-form labels and notes, state path and
relationship identifiers, service-profile identifiers and selectors, storage identities, and
accelerator PCI/device-node topology. Survey and contract identity summaries use
`identity_class = redacted`, fixed placeholders, and no local-anchor derivation metadata. The
`redacted` enum value is additive in v0.6.0; exhaustive readers must handle it. State-local
identity is absent from auditor and external views, and flexible engine identities are replaced
with profile-scoped values.

Redacted artifacts can retain semantic hashes so consumers can verify lineage. Those hashes are
stable, linkable fingerprints: a recipient with a candidate original can test whether it matches,
and can correlate separate disclosures carrying the same hash. They are not anonymity tokens.

Some diagnostic software, driver, collector, and runtime versions remain available where they are
needed to interpret evidence. Custom prerelease or build suffixes in those fields can disclose
site-specific text; inspect the complete serialized artifact before sharing it.

Configuration and decision bundle views retain configuration, trust-policy, signer,
external-evidence, and lineage identities that form part of the bundle's audit meaning. Treat those
views as structurally valid retained disclosures requiring manual review, not an anonymity
boundary or generally publication-safe exports. Prefer narrower survey, state, and validation
artifacts for host reports.

Numeric resource facts, timestamps, freshness, typed enums, coarse CPU/accelerator facts,
filesystem types, requirement thresholds, verdicts, typed reason codes, and closed provider
error-code values remain available where needed to interpret the artifact. Redaction reduces
identifying disclosure; it does not promise anonymity or unlinkability.

Compact inspect continues to show `fitctl version`. Verbose inspect may show the optional build
provenance fields separately when they are present.

## host-survey.v2

Produced by `fitctl survey`.

Top-level shape:

```text
{
  "envelope": { ... },
  "survey": { ... }
}
```

A survey records observed host evidence.

The `survey` section combines collection metadata with `core_evidence`.

It contains:

- `collection_mode`
- `host_alias`
- `snapshot_id`
- `source_ref`
- `core_evidence`
- optional `extension_evidence`

`collection_mode` is a closed compatibility string: only `live` and `replay` are valid.

`core_evidence` combines collector metadata, execution context, identity summary, section metadata,
and recorded observations.

It contains:

- `collectors`
- `execution_context`
- `identity_summary`
- `section_metadata`
- `observations`

`identity_summary` records the local correlation identity, including identity class, local stable
ID and version, anchor family and source, stability class, degradation flags, composition digest,
and provenance fingerprint.

Canonical host evidence uses `local_stable`; trust-domain export identities use
`export_pseudonym`; auditor/external sharing views use `redacted`. The `redacted` form contains
fixed placeholders and omits local-anchor derivation metadata.

`observations` carries the recorded host sections, including:

- `cpu`
- `memory`
- `storage`
- `network`
- `topology`
- `accelerators`
- `hostname`

## host-contract.v2

Produced by `fitctl contract`.

Top-level shape:

```text
{
  "envelope": { ... },
  "contract_basis": { ... },
  "contract": { ... }
}
```

A contract records what the host may claim under a selected policy.

`contract_basis` records how the contract was derived. It links the artifact back to the source
survey, the selected policy, the derivation engine, and the selected policy layers.

It contains:

- `core_semantic_basis`
- optional `extension_basis`
- `derivation_provenance`

`core_semantic_basis` records:

- `source_survey_semantic_hash`
- `policy_semantic_hash`
- `derivation_engine_id`
- `derivation_engine_version`
- `contract_schema_version`
- `selected_policy_layers`

The `contract` section contains `core_contract` and may also carry optional
`extension_contract`.

When `extension_basis` is present, it records enabled extension namespaces and their semantic
hashes. Ordinary validation and auditor/external sharing require its namespace list and hash keys
to match. Populated `extension_contract` namespaces must be a subset of that enabled set, and a
non-empty extension payload without a basis is invalid. Registered namespace strings and canonical
hashes remain unchanged as linkable lineage.

`core_contract` carries:

- `capability_classes`
- `execution_constraints`
- `identity_summary`
- `network_summary`
- `storage_summary`
- `accelerator_summary`
- `topology_summary`

When accelerator scope filters are active, `accelerator_summary` separates the
full accelerator inventory from the policy-scoped accelerator inventory used for the claim.

Count-sensitive validation uses the confirmed policy-scoped accelerator count and completeness
signals from that summary, not the full observed inventory. Inspect may therefore show both `full
accelerator inventory incomplete` and `policy-scoped accelerator inventory complete` on the same
host without contradiction.

Inspect prints policy-scoped inventory detail with `confirmed in-scope` and `unresolved in-scope`
counts so resolved out-of-scope devices do not inflate workload GPU floors.

`capability_classes` is the map of policy-bound claims, such as `general_compute` or
`gpu_accelerated`. Each claim records whether it is admissible and which evidence and rules support
it.

## host-state.v2

Produced by `fitctl state`.

Top-level shape:

```text
{
  "envelope": { ... },
  "state": { ... }
}
```

Host state records current runtime-sensitive facts separately from the stable contract.

The `state` section combines collection metadata with `core_state` and may also carry optional
`extension_state`.

It contains:

- `collection_mode`
- `host_alias`
- `snapshot_id`
- `source_ref`
- optional `local_identity`
- `core_state`
- optional `extension_state`

`local_identity` remains available for local and Fleet correlation. Auditor and external sharing
views omit the entire optional object rather than retaining its anchor or degradation metadata.

`core_state` captures current runtime-sensitive sections.

It contains:

- `collectors`
- `section_metadata`
- `freshness`
- `resources`
- `path_resources`
- optional `thermal_resources`
- optional `memory_reliability`
- optional `gpu_reliability`
- `boundaries`
- `topology`
- `operability`

`path_resources` records explicit path checks requested during live state collection. Each entry
contains:

- `path_id`
- `path`
- optional `requested_path`
- `exists`
- `filesystem_available_bytes`
- `filesystem_total_bytes`
- `canonical_path`
- `containing_mount_point`
- `filesystem_type`
- `mount_source`
- `mount_options`
- `mount_device_major_minor`
- `filesystem_uuid`
- `partition_uuid`
- `persistent_device_links`
- `storage_identity_evidence`
- `media_class`
- `media_class_confidence`
- `media_class_evidence`
- `durability_class`
- optional `observed_at`
- optional `link_capabilities`
- optional `storage_health`

`path_resources.link_pairs` records optional pairwise probes requested with
`--probe-path-link-pair <from-id>:<to-id>`. Each pair entry names the source and destination path
ids, records whether they were on the same filesystem from the current process view, and reports
hardlink, reflink, symlink, and copy probe results.

`media_class` is one of `tmpfs`, `nvme`, `ssd`, `hdd`, `network`, or `unknown`.
`durability_class` is one of `ephemeral`, `durable`, or `unknown`.

Storage identity fields are evidence about the currently mounted path. They can include the
mount major:minor value from mountinfo, filesystem UUIDs, partition UUIDs, and persistent
`/dev/disk/by-id` links when visible. Device names such as `nvme0n1` are evidence labels only;
they are not durable identity by themselves.

`link_capabilities` is emitted only when the caller explicitly asks for link probes with
`--probe-path-links <path-id>`. It can report hardlink, reflink, symlink, and copy fallback support
for the checked path. These are filesystem facts only; they do not select a DVC cache policy.

Pairwise link probes are also evidence only. They answer whether the observed source path can link
or copy into the observed destination path; they do not decide which cache policy a downstream
tool should select.

Both link evidence shapes may include `cleanup`, independent of link support and `probe_error`.
Current probes record an ordered list of `{probe_root, outcome, error?}` entries: one root for
a single-path probe, or source then destination for a pair. `not_created` means this invocation
did not create that root; `removed` means its removal succeeded; `remove_failed` retains a
nonblank removal error. Only roots actually created by this invocation are removed. Cleanup
failure does not overwrite successful link observations or the original setup failure.

An empty `cleanup` list means no roots were attempted. Absent or null cleanup is historical
evidence with cleanup not recorded, not proof that files were removed. Outcomes participate in
semantic hashing and signatures. Auditor/external views mask paths and diagnostics while keeping
the outcomes. Cleanup evidence is not authorization to delete paths named in an imported artifact.

`storage_health` is emitted only when requested with `--probe-path-health <path-id>`. It can record
health state, probe source, probe method, temperature, used percentage, available spare percentage,
probe errors, and observation time. Health evidence is included in the state semantic hash and is
redacted under auditor/external redaction profiles where it can expose device identity.

The current live path-health probe reads temperature from a safe sysfs source when available.
It does not run SMART utilities or infer health state, wear or spare capacity from temperature;
those fields remain unknown without evidence. A successful collection is not an SSD health verdict.

`memory_reliability` is emitted only when requested with `--collect memory-reliability`. It records
safe local memory reliability provider outcomes and aggregate counters such as corrected and
uncorrected error counts when the host exposes them. It is evidence only; fitctl does not change
memory-controller configuration. Provider error codes use a closed fitctl-emitted vocabulary;
unknown imported values fail artifact validation.

`gpu_reliability` is emitted only when requested with `--collect gpu-reliability`. It records
read-only GPU reliability provider outcomes and per-device evidence such as ECC mode, volatile ECC
error counts, retired-page state, and row-remapper state when available. It is evidence only; fitctl
does not enable ECC, change power limits, or modify GPU persistence settings. Provider error codes
use a closed fitctl-emitted vocabulary; unknown imported values fail artifact validation.

`thermal_resources` is emitted only when the caller supplies one or more thermal provider configs
with `--thermal-provider-config <path>`. It records provider outcomes and normalized temperature
readings from exact-argv providers such as `sensors -j`, `nvidia-smi` query output, or
`ipmitool sensor`.

Provider collection drains stdout and stderr within the configured timeout. Successful stdout
larger than one MiB is rejected as `thermal_provider_output_too_large`, never parsed as truncated
evidence. Stderr capture and failure diagnostics are bounded. Inherited output pipes remain subject
to the same deadline; timeout cleanup kills and reaps the direct provider child, not a separate
process group. Wrappers remain responsible for their own descendants.

`thermal_resources` keeps collector and target identity separate. `collector_host` describes the
host that ran the provider command. Each provider and reading also carries `evidence_target`, which
may identify the current host or a different host observed through an out-of-band path such as a
BMC. Provider kind never implies target identity.

Provider outcomes are `success`, `unavailable`, `permission_denied`, `command_failed`,
`malformed`, or `partial`. Sensor roles are normalized to `cpu`, `gpu`, `board`, `network_chip`,
`storage_drive`, `nvme`, `ssd`, `inlet`, `exhaust`, `vrm`, `bmc`, or `unknown`. Provider configs
may map raw labels to site-local `sensor_alias` values. Raw provider labels and aliases are
evidence and may be redacted under auditor/external redaction profiles. Provider error codes use a
closed fitctl-emitted vocabulary; unknown imported values fail artifact validation.

`extension_state` carries namespaced runtime facts that do not belong in the stable contract. CUDA
runtime replay and live state appear under
`extension_state.fitctl.runtime.cuda`.

CUDA extension payloads may also carry selected CUDA environment fields as additive observations.
They do not redefine the default CUDA view.

CUDA runtime device entries may include optional `compute_capability` and `mig_mode` state fields
when the live probe can observe them. Older replay artifacts and hosts that cannot expose those
facts remain valid with the fields missing or unknown.

This separation is deliberate: `contract` records what the host may claim in principle, while
`state` records what is true in the current execution context now.

## fitctl.thermal-evidence.v1

Produced by `fitctl thermal collect`.

Top-level shape:

```text
{
  "envelope": { ... },
  "thermal_evidence": { ... }
}
```

Standalone thermal evidence records provider outcomes and normalized temperature readings without
embedding a full `host-state.v2` runtime state artifact. It is useful when temperature evidence is
collected out of band, such as from a BMC/IPMI command run on one host for another host.

`thermal_evidence` has the same schema shape as `state.core_state.thermal_resources`:

- `observed_at`
- `collector_host`
- `providers`
- `readings`

Collector identity and evidence target identity remain separate. Validation compares
`evidence_target` against the contract host identity before using the evidence. A thermal evidence
artifact for one host must not satisfy requirements for another host.

Standalone thermal evidence can satisfy `core_requirements.required_thermal_sensors`, but it does
not satisfy non-thermal runtime requirements such as allocatable memory, path capacity, topology,
or CUDA runtime state. Those still require `host-state.v2`.

State-aware validation can also consume:

- `state.core_state.path_resources.paths[].storage_health` for
  `core_requirements.required_paths[<path-id>].storage_health`
- `state.core_state.memory_reliability` for
  `core_requirements.required_memory_reliability`
- `state.core_state.gpu_reliability` for `core_requirements.required_gpu_reliability`

## validation-report.v2

Produced by `fitctl validate`.

Top-level shape:

```text
{
  "envelope": { ... },
  "validation_basis": { ... },
  "report": { ... }
}
```

A validation report records the result of checking a contract against a service profile.

`validation_basis` records which inputs participated in the decision.

It contains:

- `validation_mode`
- `contract_artifact_id`
- `service_profile_artifact_id`
- `contract_semantic_hash`
- `service_profile_semantic_hash`
- optional `state_artifact_id`
- optional `state_semantic_hash`
- optional `state_observed_at`
- optional `state_freshness_state`
- optional `max_state_age_seconds`
- optional `thermal_evidence_artifact_ids`
- optional `thermal_evidence_semantic_hashes`
- `validation_engine_id`
- `validation_engine_version`

When state participates in validation, the optional state fields preserve the extra runtime and
freshness context.

When standalone thermal evidence participates in validation, the thermal evidence artifact ids and
semantic hashes preserve the evidence basis. They are paired lists; each id has a corresponding
semantic hash at the same index.

The `report` section carries the decision itself.

Key fields include:

- `verdict`
- `primary_reason_code`
- `matched_requirements`
- `failed_requirements`
- `evidence_refs`
- `policy_refs`
- `assurance_mismatches`
- `selected_degradation_tier`
- `warnings`
- `extension_diagnostics`
- `path_diagnostics`
- `explanations`
- `remediation_hints`
- `summary`

Count-sensitive and runtime-sensitive validation reuse these normal report fields. Scoped
accelerator floors and runtime admission still surface through `matched_requirements`,
`failed_requirements`, `primary_reason_code`, `summary`, and optional `extension_diagnostics`.

`path_diagnostics` is emitted when path relationship or pairwise link checks need structured
machine-readable detail. It records the requirement key, involved path ids, check id, status,
reason code, expected values, observed values, and evidence refs.

CUDA runtime detail is recorded under
`report.extension_diagnostics.fitctl.runtime.cuda`.

For multi-GPU CUDA admission, those diagnostics may also record qualifying-device counts and
allocatable-memory thresholds and observations. That lets validation explain how the static
policy-scoped accelerator floor was reused for runtime admission and how the
qualifying-device subset was evaluated.

Relevant CUDA diagnostic fields include `required_qualifying_device_count`,
`observed_qualifying_device_count`, `required_device_allocatable_memory_bytes`,
and `observed_device_allocatable_memory_bytes`.

## Other supported reports

`fitctl classify` emits `fitctl.batch-classification-report.v3`.

Use:

```bash
fitctl inspect --input batch.json --view matrix
```

to print that report as a shortlist table.

[Validation](./validation.md) covers batch comparison and matrix views.
