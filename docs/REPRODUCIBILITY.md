# TraceGuard — Reproducibility & Replication Guide

**Project:** TraceGuard — Multi-Turn Indirect Prompt Injection Auditing and Defense for AI Agents
**Hackathon:** Lexsi Labs AI Safety and Alignment Hackathon 2026 (Track: AI Safety and Red Teaming, PS3)
**Target:** 100% Deterministic Offline Replication

---

## 1. System Requirements & Environment

- **Python:** Python 3.11 to 3.13 (tested on Python 3.13.14 AMD64 Windows and Python 3.11.2 Linux x86_64).
- **Hardware:** CPU execution only is required for deterministic evaluation, dataset curation, quality gating, and security testing. No GPU or CUDA hardware is required for replication.
- **Network:** Fully offline capable. No internet access or live Hugging Face token is needed to execute deterministic benchmarks, ablation experiments, or the interactive demo.

---

## 2. Dependency Installation

```powershell
# 1. Base requirements (PyTorch CPU, Transformers, PyYAML, PyTest)
pip install -r requirements/requirements-base.txt

# 2. Official Lexsi Labs ecosystem packages
pip install curatorkit==0.1.22 circuitkit==0.2.0 auditkit==1.1.3
```

---

## 3. Dataset Integrity Verification

TraceGuard enforces strict cryptographic hashes and schema validity across all 60 benchmark episodes.

```powershell
# 1. Validate original source datasets (60 episodes, 30 attack, 30 benign, 0 template overlap)
python scripts/validate_dataset.py

# 2. Validate curated dataset outputs, quality gates, and SHA-256 checksums
python scripts/validate_curated_dataset.py
```

### Reference SHA-256 Source Hashes
| File Path | SHA-256 Digest |
| :--- | :--- |
| `traceguard/data/episodes_attack_dev.jsonl` | `9b996ed210bd5f2e5efb6fc8e71c2d801bcf45471c8442eeace1884d07dac575` |
| `traceguard/data/episodes_attack_test.jsonl` | `5d99c5ed25fc28fb9b16a233500663f0c6aa1a08bfa2d4a7c167b21089797b35` |
| `traceguard/data/episodes_benign_dev.jsonl` | `65ebc2fe1c7cbd15e75a3c1675ff9cf5c716d57d32ace481dfde90978f9d615b` |
| `traceguard/data/episodes_benign_test.jsonl` | `f90777c460af02d39fe5ed411c75c3856556c1056ab859fbca51f669a7b6a70b` |

---

## 4. Full Test Suite Execution

Run the complete regression suite across all 10 modules:

```powershell
pytest tests/
```
*Expected Result:* **546 passed, 1 skipped** (`collected 546 items / 1 skipped`: 546 passed, 0 runtime skipped, 1 collection skipped).
*(Skipped tests are NOT executed. Totals depend on the machine: tests needing Hugging Face network access or the Python 3.12 SafeTune environment skip when those are unavailable. Use `pytest tests/ -ra` to see exactly what ran. Details: `reports/final_audit/TEST_RESULTS.md`.)*

---

## 5. End-to-End Evaluation Reproduction

Run the unified evaluation CLI across all experimental configurations:

### 5.1. Development Split Evaluation (with AuditKIT Export)
```powershell
python scripts/run_traceguard.py --mode mock --split dev --auditkit
```
- Evaluates configurations: `E0`, `E1`, `E2a`, `E2b`, `E3`, `E4`.
- Emits execution logs under `results/evaluation/`.
- Exports Lexsi Labs AuditKIT representations under `results/auditkit/`.
- Writes master run metadata to `results/evaluation/traceguard_master_summary.json`.

### 5.2. Held-Out Test Split Evaluation
```powershell
python scripts/run_traceguard.py --mode mock --split test
```
- Strictly held-out test evaluation.

### 5.3. Model-Backed Execution (Optional)
If live Hugging Face credentials and network access are configured:
```powershell
$env:HF_TOKEN="your_huggingface_token"
python scripts/run_traceguard.py --mode model --model-id CohereLabs/aya-expanse-8b --split dev
```
*(If offline or without token, the system safely reports `NOT_RUN` with diagnostic steps without failing).*

---

## 6. CuratorKIT Curation Pipeline Reproduction

```powershell
# Run the complete CuratorKIT curation and export pipeline
python scripts/run_curator.py --input-dir traceguard/data --output-dir traceguard/data/curated
```
Produces:
- Canonical full-fidelity datasets (`traceguard/data/curated/*.jsonl`)
- Trainer-ready conversational projections (`trainer_ready_*.jsonl`)
- 5 cryptographic manifests (`traceguard/data/curated/manifests/`)
- 5 dataset cards (`traceguard/data/curated/dataset_cards/`)
- Verified `checksums.txt`

---

## 7. CircuitKIT Interpretability Reproduction

```powershell
# Run contrastive circuit discovery and faithfulness evaluation
python scripts/run_circuit_experiment.py
```
Produces:
- `results/circuit/discovery.json`
- `results/circuit/faithfulness.json`
- `results/circuit/summary.json`

---

## 8. Interactive Demonstration

To run the offline judge-facing demonstration:
```powershell
python scripts/run_demo.py
```
Outputs:
- Blocked invoice document injection attempt and canary defense.
- Multi-turn benign business task executing with 100% utility.
- Analytical breakdown of turn-local (E2a) versus persistent (E2b) provenance tracking.
