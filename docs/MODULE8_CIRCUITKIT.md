# TraceGuard Module 8: CircuitKIT Interpretability Infrastructure

**Role:** Member 2 — Data & Interpretability Lead  
**Package:** `traceguard.experiments` / `traceguard.data.circuit`  
**CircuitKIT Version:** 0.2.0  
**Status:** Completed & Validated  

---

## 1. Executive Summary

Module 8 implements the **CircuitKIT Interpretability Infrastructure** for TraceGuard. It provides the mechanistic interpretability layer required to investigate the internal circuits governing indirect prompt injection, attention routing over untrusted retrieved content, and safety-critical tool-call generation.

### Primary Objectives
1. **Contrastive Data Formulation:** Establish clean vs. corrupt paired prompt datasets across all three TraceGuard threat families (Family A, B, and C).
2. **Template-Disjoint Split Guarding:** Guarantee zero contamination between development and test splits ($T_{\text{dev}} \cap T_{\text{test}} = \emptyset$) with cryptographic SHA-256 fingerprinting.
3. **CircuitKIT 0.2.0 Pipeline Adapter:** Provide native adapter and CSV conversion conforming to `circuitkit.Pipeline.from_custom_data(...)`.
4. **Transparent Status Reporting:** Strictly prohibit fabricated scores (`NOT_RUN` when awaiting real-model weights from Member 1; all unmeasured metrics remain `None`/`null`).
5. **Offline Verifiability:** Full mock execution harness (`MockCircuitPipeline`) enabling complete CI/CD verification without GPU or external network access.

---

## 2. Contrastive Dataset Architecture

Circuit discovery algorithms (such as EAP-IG, EAP, and ACDC) require contrastive pairs to identify edges and nodes whose activations causally drive the behavior of interest.

### Contrastive Pair Formulation

| Field | Description | Clean Condition | Corrupt Condition |
| :--- | :--- | :--- | :--- |
| `prompt` | User request + retrieved context | User task over benign retrieved data | Identical user task over data containing indirect prompt injection |
| `answer` | Expected completion / action | Legitimate task summary (no tool call) | Malicious action (unauthorized tool call or data exfiltration) |

### Dataset Files

The canonical datasets are stored in JSONL format:

- **Development Split:** `traceguard/data/circuit/contrastive_dev.jsonl` (12 contrastive pairs)
- **Held-out Test Split:** `traceguard/data/circuit/contrastive_test.jsonl` (12 contrastive pairs)

```text
traceguard/data/circuit/
├── contrastive_dev.jsonl
└── contrastive_test.jsonl
```

### Threat Family Coverage & Template Disjointness

| Attack Family | Dev Templates | Test Templates | Disjoint? |
| :--- | :--- | :--- | :---: |
| **Family A: Document & Email** | `CIRCUIT_DEV_TPL_DOC_01`<br>`CIRCUIT_DEV_TPL_DOC_02`<br>`CIRCUIT_DEV_TPL_EMAIL_01`<br>`CIRCUIT_DEV_TPL_EMAIL_02` | `CIRCUIT_TEST_TPL_DOC_01`<br>`CIRCUIT_TEST_TPL_DOC_02`<br>`CIRCUIT_TEST_TPL_EMAIL_01`<br>`CIRCUIT_TEST_TPL_EMAIL_02` | ✅ $T_{\text{dev}} \cap T_{\text{test}} = \emptyset$ |
| **Family B: Search & Tool Outputs** | `CIRCUIT_DEV_TPL_SEARCH_01`<br>`CIRCUIT_DEV_TPL_SEARCH_02`<br>`CIRCUIT_DEV_TPL_TOOL_01`<br>`CIRCUIT_DEV_TPL_TOOL_02` | `CIRCUIT_TEST_TPL_SEARCH_01`<br>`CIRCUIT_TEST_TPL_SEARCH_02`<br>`CIRCUIT_TEST_TPL_TOOL_01`<br>`CIRCUIT_TEST_TPL_TOOL_02` | ✅ $T_{\text{dev}} \cap T_{\text{test}} = \emptyset$ |
| **Family C: Stored & Cross-Turn** | `CIRCUIT_DEV_TPL_STORED_01`<br>`CIRCUIT_DEV_TPL_STORED_02`<br>`CIRCUIT_DEV_TPL_CROSSTURN_01`<br>`CIRCUIT_DEV_TPL_CROSSTURN_02` | `CIRCUIT_TEST_TPL_STORED_01`<br>`CIRCUIT_TEST_TPL_STORED_02`<br>`CIRCUIT_TEST_TPL_MEMORY_01`<br>`CIRCUIT_TEST_TPL_MEMORY_02` | ✅ $T_{\text{dev}} \cap T_{\text{test}} = \emptyset$ |

### Cryptographic Hashes (SHA-256)

- **DEV Split Hash:** `eba65622de033b87f886f46337b6dd1a12deeded064e5f9e3a275204df3201bd`
- **TEST Split Hash:** `9f259b6a44e76274f728225b95331b72fd6b8ee62c33a8ff950e60dfaa08b160`

---

## 3. Configuration Specification

`CircuitExperimentConfig` in `traceguard/experiments/circuit_config.py` enforces parameter validation and prevents runtime misconfigurations.

### Configuration Schema

| Parameter | Type | Default | Valid Range / Options | Description |
| :--- | :--- | :--- | :--- | :--- |
| `algorithm` | `str` | `"eap-ig"` | `{"eap-ig", "eap", "acdc", "act-patch", "edge-pruning", "integrated-gradients"}` | Discovery attribution algorithm |
| `level` | `str` | `"node"` | `{"node", "neuron"}` | Granularity of circuit nodes |
| `sparsity` | `float` | `0.15` | $0.0 < s < 1.0$ | Target pruning sparsity fraction |
| `scope` | `str` | `"both"` | `{"heads", "mlp", "both"}` | Attention heads, MLPs, or both |
| `pillars` | `list[str]` | `["patching", "ablation"]` | Subset of 6 pillars: `patching`, `ablation`, `stability`, `robustness`, `baselines`, `generalization` | CircuitKIT evaluation pillars |
| `split` | `str` | `"dev"` | `{"dev", "test"}` | Target evaluation split |
| `allow_intervention`| `bool`| `False` | `True` / `False` | Whether to test circuit ablation intervention |
| `output_dir` | `str` | `"results/circuit"` | Non-empty path | Artifact destination directory |

---

## 4. Structured Results & Transparency

In compliance with AI safety research ethics and hackathon competition requirements, TraceGuard enforces strict transparency regarding unexecuted runs:

1. **No Synthetic Zeros:** Unexecuted metrics are stored as `None` / `null`, never `0.0`.
2. **Explicit Status Codes:** Results distinguish between:
   - `NOT_RUN`: Experiment intentionally unexecuted (e.g. awaiting Member 1's real model weights).
   - `SUCCESS`: Experiment executed and validated.
   - `FAILED`: Experiment encountered an execution error (detailed in `error_message`).
   - `UNAVAILABLE`: Capability not supported by the underlying pipeline.
3. **Self-Auditing Verification:** `CircuitExperimentSummary.verify_no_fabricated_scores()` raises an exception if numeric scores exist on unexecuted results.

### Generated Artifacts (`results/circuit/`)

When an experiment or dry-run is executed, four JSON artifacts are generated:
- `discovery.json`: Discovered nodes, edges, execution time, and algorithm metadata.
- `faithfulness.json`: Faithfulness metrics across patching, ablation, and other active pillars.
- `intervention.json`: Pre/post safety scores, accuracy, and utility deltas.
- `summary.json`: Top-level consolidation including split, dataset hash, configuration, and notes.

---

## 5. CLI Execution Guide

The CLI harness `scripts/run_circuit_experiment.py` provides operations for development, auditing, and execution.

### Environment Audit
```bash
python scripts/run_circuit_experiment.py --validate-env
```
*Output: Platform, Python version, CircuitKIT version (0.2.0), PyTorch version, and CUDA/CPU device status.*

### Dataset & Split Guard Validation
```bash
python scripts/run_circuit_experiment.py --validate-data
```
*Output: Validates both `contrastive_dev.jsonl` and `contrastive_test.jsonl`, counts samples by family, checks schema conformity, and verifies template disjointness.*

### Honest Dry-Run (Awaiting Model Integration)
```bash
python scripts/run_circuit_experiment.py --split dev --dry-run
```
*Output: Performs split checks and writes an honest `NOT_RUN` report with dataset hashes to `results/circuit/`.*

### Mock Pipeline Integration Test
```bash
python scripts/run_circuit_experiment.py --split dev --mock --intervention
```
*Output: Runs the complete end-to-end pipeline with mock discovery and faithfulness evaluation to verify reporting and serialization.*

---

## 6. Integration Contract for Member 1 (Real Model Lead)

When Member 1 has initialized the real model (e.g. Tiny Aya or Aya Expanse) in an environment with sufficient accelerator resources:

1. Provide model identifier: `config = CircuitExperimentConfig(model_name="CohereForAI/aya-expanse-8b", split="dev")`
2. Pass initialized pipeline directly:
   ```python
   from traceguard.experiments.circuit_config import CircuitExperimentConfig
   from traceguard.experiments.circuit_experiment import CircuitExperimentRunner, CircuitKITAdapter

   runner = CircuitExperimentRunner()
   cfg = CircuitExperimentConfig(model_name="your_model_path", split="dev")

   # CircuitKITAdapter will automatically convert contrastive JSONL to CSV
   # and call circuitkit.Pipeline.from_custom_data(...)
   summary = runner.run(cfg)
   ```
3. Artifacts will be populated in `results/circuit/` with status `SUCCESS` and verified nodes and faithfulness scores.

---

## 7. Verification & Regression Metrics

- **New Circuit Tests:** 35 passed (`tests/test_circuit_config.py`, `tests/test_circuit_split_guard.py`, `tests/test_circuit_results.py`, `tests/test_circuit_experiment.py`)
- **Full Project Regression:** **338 passed, 1 skipped** (`pytest tests/ --ignore=tests/test_generation_tiny.py -q`)
- **Core Dataset Validation:** **60/60 episodes validated** (`python scripts/validate_dataset.py`)
- **Leakage Status:** **Zero template overlap** ($T_{\text{dev}} \cap T_{\text{test}} = \emptyset$)
