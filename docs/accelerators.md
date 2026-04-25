# Accelerators

Accelerator data is split across two surfaces: `survey` and `state`.

A `survey` records hardware inventory, local visibility, local operability, and coarse locality. It
describes what accelerator hardware, such as GPUs, the host can observe in principle.

A `state` record captures live runtime detail. It describes what the current execution context can
use now, such as visible CUDA devices, allocatable memory, and the default CUDA driver, toolkit,
driver-supported CUDA level, and runtime view.

`validation` uses the survey-derived contract when a workload depends on accelerator inventory. It
also uses `state` when the decision depends on current runtime visibility, allocatable memory, or
other live runtime detail.

## Survey

A `survey` may report:

- observed accelerator kind, vendor, model, and family
- integrated versus discrete classification when that can be inferred conservatively
- conservative memory or VRAM detail when it is directly observable
- local visibility and local operability
- coarse locality facts, such as NUMA attachment

Additional hardware observations may include:

- PCI or DRM identity when the host exposes it
- driver binding and driver-bound device counts
- local device-node or render-node presence
- coarse NUMA attachment for locality-sensitive fit checks

If more than one GPU is visible, `inspect` renders them separately. The bundled GPU workstation
fixture renders:

```bash
fitctl survey \
  --fixture linux-gpu-workstation-like-v1 \
  | fitctl inspect
```

```text
Accelerators
  Observed GPUs: 2
  GPU 0000:65:00.0: nvidia-gpu-2206; driver nvidia; operable
  GPU 0000:b3:00.0: nvidia-gpu-2230; driver nvidia; operable
```

Coarse locality facts let service profiles require a known NUMA attachment or reject unknown
locality when placement matters.

## State

A `state` record models runtime detail separately from hardware inventory.

For CUDA, `state` may report:

- visible CUDA devices
- per-device allocatable memory
- per-device total memory
- the default CUDA driver, toolkit, driver-supported CUDA level, and runtime view

This detail affects the fit decision only when `state` is supplied during validation.

To collect CUDA runtime detail in the examples below:

- `--extension-pack configs/extensions/fitctl_runtime_cuda.v1.json` loads the extension definition
- `--enable-extension fitctl.runtime.cuda` enables that namespace during collection

The bundled CUDA examples use the extension namespace `fitctl.runtime.cuda`.

This example uses the bundled CUDA runtime extension and a two-device state fixture:

```bash
fitctl state \
  --fixture linux-gpu-dual-numa-like-cuda-runtime-fit-v1 \
  --extension-pack configs/extensions/fitctl_runtime_cuda.v1.json \
  --enable-extension fitctl.runtime.cuda \
  > gpu.state.json

fitctl inspect --input gpu.state.json
```

```text
Accelerators
  Observed CUDA devices: 2
  CUDA device GPU-1111...11111111: 20.00 GiB allocatable (24.00 GiB total)
  CUDA device GPU-2222...22222222: 18.00 GiB allocatable (24.00 GiB total)
```

## Validation

Use the contract alone when a decision depends only on accelerator inventory or on runtime
capabilities already captured in the survey-derived contract, such as CUDA presence or version
constraints.

Add `state` when the same decision also depends on live runtime conditions, such as:

- whether CUDA devices are visible in the current execution context
- whether allocatable memory is sufficient
- whether runtime state is present and fresh enough for `state_required` validation

## Example: validate with runtime state

This example uses the same CUDA extension settings during survey, contract derivation, and state
collection. That keeps the contract, the runtime observation, and the validation path aligned.

```bash
fitctl survey \
  --fixture linux-gpu-workstation-like-v1 \
  --extension-pack configs/extensions/fitctl_runtime_cuda.v1.json \
  --enable-extension fitctl.runtime.cuda \
  > gpu.survey.json

fitctl contract \
  --survey gpu.survey.json \
  --policy configs/policy/general_compute_default.v1.json \
  --extension-pack configs/extensions/fitctl_runtime_cuda.v1.json \
  --enable-extension fitctl.runtime.cuda \
  > gpu.contract.json

fitctl state \
  --fixture linux-gpu-workstation-like-cuda-runtime-fit-v1 \
  --extension-pack configs/extensions/fitctl_runtime_cuda.v1.json \
  --enable-extension fitctl.runtime.cuda \
  > gpu.state.json

fitctl validate \
  --contract gpu.contract.json \
  --profile configs/service_profiles/general_compute_cuda_runtime_allocatable_memory_required.v2.json \
  --state gpu.state.json \
  --validation-mode state_required \
  --validated-at 2025-04-21T14:37:19Z \
  > validation.json

fitctl inspect --input validation.json
```

```text
Summary
  Validation mode: state_required
  Verdict: fit
  Operator posture: proceed
  Primary reason code: requirements_satisfied
  Summary: service profile fits the general_compute capability baseline
```

The generated validation artifact stores the decision under `.report.verdict`. Extract it with
`jq` for shell automation:

```bash
if jq -e '.report.verdict == "fit"' validation.json >/dev/null; then
  echo "launch GPU workload"
else
  echo "do not launch"
fi

jq -r '.report.primary_reason_code' validation.json
```

## Visibility and operability

Hardware presence, local visibility, and local operability are separate states:

- present: the device is part of the observed hardware inventory
- visible: the current execution context exposes local device nodes or runtime handles
- operable: the visible device can be used locally

An accelerator may exist physically but still be unusable for a local decision because of:

- container or namespace masking
- missing device-node access
- control group (cgroup) or device restrictions
- partial visibility
- other local operability limits

## Where to look

- `fitctl survey | fitctl inspect` shows observed accelerator inventory
- `fitctl state ... | fitctl inspect` shows live accelerator runtime detail
- `fitctl contract ... | fitctl inspect` shows the policy-shaped accelerator claim the host may make
- `fitctl validate ... | fitctl inspect` shows why an accelerator-backed profile fits, degrades, or fails

Use those artifacts when you need typed local evidence, the derived contract claim, and the final
fit decision.
