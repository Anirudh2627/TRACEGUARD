# TraceGuard Kaggle Execution Readiness & Deployment Checklist

**Project:** TraceGuard — Multi-Turn Indirect Prompt Injection Auditing and Defense for AI Agents  
**Date:** November 2026  
**Auditor:** Senior AI Security Researcher & Deployment Engineer  

---

## 1. Local vs. Kaggle Execution Boundary

To preserve strict scientific integrity, **no local execution or weight download of Cohere models was attempted during this audit**. The local environment has validated all code, tools, gateways, datasets, parsers, and evaluation mechanics using deterministic simulation backends.

The real model inference and intervention sweeps are cleanly packaged and prepared for execution on a GPU-enabled Kaggle notebook.

---

## 2. Model & Generation Specification Verification

All parameters required by Phase 14 and Phase 16 were inspected and verified in [`traceguard/models/config.py`](traceguard/models/config.py) and [`traceguard/configs/model_config.yaml`](traceguard/configs/model_config.yaml):

| Parameter / Requirement | Specification | Verification Status | Implementation File |
| :--- | :--- | :---: | :--- |
| **Primary Model ID** | `CohereLabs/tiny-aya-global` | **PINNED** | `traceguard/configs/model_config.yaml:17` |
| **Primary Model Revision** | `af89d219b53ed9b13b8a4645f9c8028973510324` | **PINNED** | `traceguard/configs/model_config.yaml:18` |
| **Fallback Model ID** | `CohereLabs/aya-expanse-8b` | **PINNED** | `traceguard/configs/model_config.yaml:20` |
| **Fallback Model Revision** | `5062468bf9bc0c6035fd64e06274333ec127d980` | **PINNED** | `traceguard/configs/model_config.yaml:21` |
| **Decoding Strategy** | Greedy decoding (`do_sample: false`) | **ENFORCED** | `GenerationSettings.do_sample = False` |
| **Sampling Temperature** | `temperature: null`, `top_p: null` | **ENFORCED** | Enforced by `GenerationSettings` dataclass |
| **Context Limit Protection** | `max_new_tokens: 512`, context check | **ENFORCED** | Rejects prompts exceeding context without truncation |
| **Hardware Dtype Selection** | `dtype: auto` (bfloat16 on Ampere+, fp16 on T4) | **ENFORCED** | `traceguard/models/loader.py:resolve_loading_plan` |
| **Strict JSON Parsing** | Zero repair; exact type and schema check | **ENFORCED** | `traceguard/models/json_parser.py:parse_model_output` |
| **Raw Output Preservation** | Raw generation text preserved verbatim | **ENFORCED** | `TurnExecutionRecord.model_raw_output` |
| **Untrusted Model Provenance**| Model text never elevates trust | **ENFORCED** | Runtime assigns provenance independently of model claims |
| **JSONL Output Export** | Deterministic line-by-line persistence | **ENFORCED** | `traceguard/experiments/reporting.py` |

---

## 3. Step-by-Step Kaggle Execution Protocol

Follow these exact steps when executing on Kaggle:

### Step 1: Kaggle Runtime Configuration
- **Hardware Accelerator:** GPU (NVIDIA T4 x2 or A100).
- **Internet:** **ON** (Required for initial Hugging Face checkpoint download).
- **Kaggle Secrets:** Add `HF_TOKEN` with access to gated Cohere Aya checkpoints.

### Step 2: Environment Bootstrap
```bash
# Verify Python version and GPU
python -V
nvidia-smi

# Install required dependencies
pip install -r requirements/requirements-base.txt
```

### Step 3: Run the 10-Task Model Acceptance Smoke Test
The acceptance gate verifies that the model can adhere to the strict JSON tool-call protocol before running multi-turn benchmarks:
```bash
python -m traceguard.experiments.smoke_test \
    --model primary \
    --config traceguard/configs/model_config.yaml \
    --out results/smoke/tiny-aya-global/
```
*Acceptance Criteria:*
- At least 8/10 tasks must pass (`min_pass: 8`).
- Zero critical protocol failures allowed (`critical_failures_allowed: 0`).
- If primary model fails, rerun with `--model fallback` (`aya-expanse-8b`).

### Step 4: Run SafeTune Calibration Sweep (Optional Track B)
If executing SafeTune representation steering:
```bash
# In Python >= 3.12 environment with safetune installed:
python -m traceguard.experiments.safetune_calibration \
    --model primary \
    --strengths 1,5,10,20 \
    --max-new-tokens 128 \
    --out results/safetune/calibration-tiny-aya-global/
```

### Step 5: Run Full Real-Model Evaluation
Once the smoke test passes:
```bash
python scripts/run_traceguard.py \
    --mode model \
    --model primary \
    --split both \
    --auditkit \
    --output-dir results/evaluation_model/
```
