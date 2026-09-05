# Workload Reports

`fitctl` produces host-fit artifacts. It does not run workloads.

External workload runners can attach `fitctl` artifacts to their own reports so later analysis can
join workload results with the environment and fit decision used at launch time.

A report should store references to the artifacts it used:

```json
{
  "fitctl": {
    "survey_artifact": "host.survey.json",
    "contract_artifact": "host.contract.json",
    "state_artifact": "host.state.json",
    "thermal_evidence_artifacts": ["host.thermal.json"],
    "validation_artifact": "validation.json",
    "verdict": "fit",
    "primary_reason_code": "requirements_satisfied"
  }
}
```

For automation, read the verdict directly from the validation artifact:

```bash
jq -r '.report.verdict' validation.json
jq -r '.report.primary_reason_code' validation.json
```

## Admission Evidence For Runners

Downstream runners should consume validation JSON, not `fitctl inspect` output. A runner can record:

- `.validation_basis.validation_mode`
- `.validation_basis.state_artifact_id`
- `.validation_basis.state_freshness_state`
- `.validation_basis.thermal_evidence_artifact_ids`
- `.validation_basis.thermal_evidence_semantic_hashes`
- `.report.verdict`
- `.report.primary_reason_code`
- `.report.matched_requirements`
- `.report.failed_requirements`
- `.report.evidence_refs`

Prefer evidence-producing validation when another tool needs to preserve an unfit verdict:

```bash
fitctl validate \
  --contract host.contract.json \
  --profile fitctl-config/configs/service_profiles/cpu_large_state_required.v2.json \
  --state host.state.json \
  --validation-mode state_required \
  --validated-at 2025-04-21T14:37:19Z \
  > validation.json
```

Use process-gate flags only when shell exit status is the desired interface:

```bash
fitctl validate \
  --contract host.contract.json \
  --profile fitctl-config/configs/service_profiles/cpu_large_state_required.v2.json \
  --state host.state.json \
  --validation-mode state_required \
  --require-fit \
  > validation.json
```

If a runner needs both nonzero process failure and structured unfit evidence, test that it captures
stdout JSON from nonzero exits before relying on process-gate mode.

Fixture-backed state examples for admission testing include:

- CPU/RAM: `linux-bare-metal-like-fresh-v1`
- storage paths: `linux-gpu-workstation-like-path-resources-fit-v1`
- CUDA runtime: `linux-gpu-workstation-like-cuda-runtime-fit-v1`
- thermal state: [host-state.thermal-resources.v2.json](../fixtures/conformance/valid/host-state.thermal-resources.v2.json)
- standalone thermal evidence: [thermal-evidence.out-of-band-bmc.v1.json](../fixtures/conformance/valid/thermal-evidence.out-of-band-bmc.v1.json)
- stale state: `linux-gpu-workstation-like-cuda-runtime-stale-v1`

For workload measurements such as token generation speed, image generation time, peak RAM pressure,
or GPU utilization, record those measurements in the workload runner's own report and keep `fitctl`
artifacts as the standardized host and decision evidence.

That separation keeps the boundary explicit:

- `survey` records host inventory and local evidence
- `contract` records the policy-shaped host claim
- `state` records live runtime facts such as memory, CUDA, checked path capacity, storage class, thermal readings, and optional link capability evidence
- `thermal_evidence` can record target-bound thermal readings without embedding full host state
- `validation` records the fit decision
- the workload report records workload-specific measurements
