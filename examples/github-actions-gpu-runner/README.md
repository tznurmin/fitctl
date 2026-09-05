# GitHub Actions GPU Runner Gate

GitHub Actions runner labels route jobs to candidate machines. They do not prove that CUDA is
visible, that the current runtime has enough allocatable GPU memory, or that the host still matches
the workload profile.

This example gates GPU-bound work on a self-hosted Linux runner before GPU-dependent steps run. The
gate emits the normal `validation-report.v2` artifact and uses `--require-fit` so the process exit
status can stop the job.

## Workflow

Use [workflow.yaml](./workflow.yaml) as the copyable GitHub Actions shape.

The workflow runs:

1. `fitctl config export` to materialize bundled policies and profiles
2. `fitctl survey` to collect host facts
3. `fitctl contract` to derive the policy-shaped host claim
4. `fitctl state` to capture live CUDA runtime detail
5. `fitctl validate --require-fit` to produce the decision and gate the job
6. `fitctl inspect` to print the validation artifact for logs

The CUDA runtime extension is enabled with the built-in `fitctl.runtime.cuda` extension pack:

```text
--enable-extension fitctl.runtime.cuda
```

## Local fixture run

The same flow can be replayed locally without a GPU by using bundled fixtures:

```bash
fitctl config export --out-dir fitctl-config

fitctl survey \
  --fixture linux-gpu-workstation-like-v1 \
  --enable-extension fitctl.runtime.cuda \
  > gpu.survey.json

fitctl contract \
  --survey gpu.survey.json \
  --policy fitctl-config/configs/policy/general_compute_default.v1.json \
  --enable-extension fitctl.runtime.cuda \
  > gpu.contract.json

fitctl state \
  --fixture linux-gpu-workstation-like-cuda-runtime-fit-v1 \
  --enable-extension fitctl.runtime.cuda \
  > gpu.state.json

fitctl validate \
  --contract gpu.contract.json \
  --profile fitctl-config/configs/service_profiles/general_compute_cuda_runtime_allocatable_memory_required.v2.json \
  --state gpu.state.json \
  --validation-mode state_required \
  --validated-at 2025-06-17T10:00:00Z \
  --require-fit \
  > validation.json

fitctl inspect --input validation.json
```

Expected decision:

```text
Summary
  Validation mode: state_required
  Verdict: fit
  Operator posture: proceed
  Primary reason code: requirements_satisfied
```

## Failure path

The validation artifact is still written when `--require-fit` rejects the host. That keeps the
machine-readable decision available for logs and post-run automation.

For example, replay the same flow with
`linux-gpu-workstation-like-cuda-runtime-insufficient-v1` as the state fixture. The gate exits with
policy rejection and `fitctl inspect --input validation.json` reports:

```text
Summary
  Validation mode: state_required
  Verdict: unfit
  Operator posture: stop
  Primary reason code: requirement_unsatisfied
  Failed requirements: extension_requirements.fitctl.runtime.cuda.minimum_allocatable_memory_bytes
```

The report also contains the CUDA memory diagnostic and remediation hint.
