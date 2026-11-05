# TraceGuard Toolkit Interoperability & Integration Status

**Project:** TraceGuard — Multi-Turn Indirect Prompt Injection Auditing and Defense for AI Agents  
**Date:** November 2026  
**Auditor:** Senior Tooling & Ecosystem Integration Auditor  

---

## 1. Executive Toolkit Status Matrix

| Toolkit | Package Version | Integration Status | Local Execution Status | Scope & Output Artifacts |
| :--- | :--- | :---: | :---: | :--- |
| **CuratorKIT** | `0.1.22` | **Fully Integrated** | **EVALUATED (PASS)** | 60 episodes curated; 65 quality gates passed; 18 SHA-256 checksums verified in [`traceguard/data/curated/`](traceguard/data/curated). |
| **CircuitKIT** | `0.2.0` | **Fully Integrated** | **MOCK EVALUATED** | Contrastive prompt dataset generated from DEV; discovery and faithfulness evaluated on mock activations. Real model weights *NOT_RUN*. |
| **AuditKIT** | `1.1.3` | **Fully Integrated** | **SERIALIZED** | Native adapter maps logs to `AgentEpisode`, `AgentEvent`, and `RunResult`; 10 JSON artifacts exported in [`results/auditkit/`](results/auditkit/). No external server upload. |
| **SafeTune** | N/A (Requires Py 3.12) | **Partially Integrated** | **NOT_RUN (Unvalidated)** | Isolated requirements specified; DEV split guards tested; uncalibrated architectural stub. Awaiting Kaggle Python 3.12 GPU run. |

---

## 2. Detailed Toolkit Audits

### 2.1. CuratorKIT (v0.1.22)
- **Implementation:** [`traceguard/data/curator/`](traceguard/data/curator) and [`scripts/run_curator.py`](scripts/run_curator.py).
- **Execution & Validation:**
  - Ingestion: 60 episodes (30 attack, 30 benign) across DEV and TEST splits.
  - Cleaning: Text normalization, whitespace trimming, and canary preservation.
  - Deduplication: MinHash LSH similarity scan (threshold 0.85); verified zero duplicates across splits.
  - Quality Gating: 65 automated tests executed (structural, family balance, template disjointness, outcome integrity).
  - Persistence: 4 full-fidelity JSONL exports, 4 trainer-ready conversational projections, 5 cryptographic manifests, 5 dataset cards, and verified `checksums.txt`.
- **Verdict:** **COMPLETE & LOCALLY VALIDATED**.

---

### 2.2. CircuitKIT (v0.2.0)
- **Implementation:** [`traceguard/experiments/circuit_experiment.py`](traceguard/experiments/circuit_experiment.py) and [`scripts/run_circuit_experiment.py`](scripts/run_circuit_experiment.py).
- **Execution & Validation:**
  - Contrastive Dataset: Built from development split episodes (`results/circuit/contrastive_dev.csv`).
  - Split Hygiene: Hard check raises `HeldOutDataError` if test episodes are supplied.
  - Discovery & Faithfulness: Evaluated against synthetic mock model activation traces.
  - Hardware Boundary: Real transformer weight activation tracing was *NOT_RUN* locally due to CPU-only execution without live model weights.
- **Verdict:** **INFRASTRUCTURE VALIDATED (Model execution pending Kaggle)**.

---

### 2.3. AuditKIT (v1.1.3)
- **Implementation:** [`traceguard/experiments/auditkit_adapter.py`](traceguard/experiments/auditkit_adapter.py) and [`tests/test_auditkit_integration.py`](tests/test_auditkit_integration.py).
- **Execution & Validation:**
  - Native Schema Compliance: Direct integration with `auditkit.AgentEpisode`, `AgentEvent`, `RunResult`, and `Stat`.
  - Export Artifacts:
    - 5 JSONL trajectory files (`auditkit_episodes_{E0,E1,E2a,E2b,E4}_{dev,test}.jsonl`).
    - 5 JSON run summary files (`auditkit_run_result_{E0,E1,E2a,E2b,E4}_{dev,test}.json`).
  - Ground Truth Primacy: TraceGuard deterministic scoring remains authoritative; AuditKIT serves as the standardized evaluation exchange format.
- **Verdict:** **COMPLETE & SERIALIZED**.

---

### 2.4. SafeTune
- **Implementation:** [`traceguard/experiments/safetune_calibration.py`](traceguard/experiments/safetune_calibration.py) and [`traceguard/models/steered_backend.py`](traceguard/models/steered_backend.py).
- **Execution & Validation:**
  - Environment Isolation: Documented in [`requirements/requirements-safetune-py312.txt`](requirements/requirements-safetune-py312.txt).
  - Split Guard: `tests/test_safetune_split_guard.py` verifies that calibration strictly rejects test data (`HeldOutDataError`).
  - Offline Safety: `SteeredBackend` explicitly raises `ImportError` if called without the SafeTune package; it never silently falls back or fabricates steering results.
- **Verdict:** **SCAFFOLD & SPLIT GUARDS VALIDATED (Steering sweep pending Kaggle)**.
