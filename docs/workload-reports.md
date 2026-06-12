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

For workload measurements such as token generation speed, image generation time, peak RAM pressure,
or GPU utilization, record those measurements in the workload runner's own report and keep `fitctl`
artifacts as the standardized host and decision evidence.

That separation keeps the boundary explicit:

- `survey` records host inventory and local evidence
- `contract` records the policy-shaped host claim
- `state` records live runtime facts such as memory, CUDA, and checked path capacity
- `validation` records the fit decision
- the workload report records workload-specific measurements
