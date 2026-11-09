# TraceGuard — Hackathon Submission Readiness Checklist

**Project:** TraceGuard — Multi-Turn Indirect Prompt Injection Auditing and Defense for AI Agents
**Hackathon:** Lexsi Labs AI Safety and Alignment Hackathon 2026
**Track:** AI Safety and Red Teaming (Problem: PS3)
**Date:** November 2026

---

## 1. Research & Scientific Integrity

- [x] **Primary Research Question:** Clearly stated and empirically tested:
  *"Does preserving source provenance across turns reduce unsafe tool-call attempts compared with losing provenance, while preserving legitimate task completion?"*
- [x] **Canonical Provenance Labels:** Strictly preserved without informal string variants:
  `SYSTEM_POLICY`, `SYSTEM_CONFIG`, `USER_AUTHORIZED`, `UNTRUSTED_EXTERNAL`, `DERIVED_UNTRUSTED`, `UNKNOWN`.
- [x] **Honest Experiment Reporting:**
  - `E0`, `E1`, `E2a`, `E2b`, `E4` deterministic evaluations completed and scored on standard benchmark and controlled delayed-injection ablation.
  - Reconciled E1: deterministic simulation backend records 0.0% block / 53.3% canary leak (Turn 1 injection breaches episode before turn-based refusal kicks in on Turn 2).
  - Reconciled E2a vs E2b: standard benchmark blocks 100% via recipient ledger check; controlled ablation with authorized recipient isolates cross-turn provenance (E2a fails at 50.0% block / canary leak; E2b defends at 100.0% block / 0% canary leak).
  - `E3` (SafeTune representation steering) explicitly reported as uncalibrated stub and unvalidated (`NOT_RUN`).
  - Model-backed execution (`tiny-aya-global`) requires live credentials; offline mode reported honestly as unvalidated (`NOT_RUN`).
  - Model-backed CircuitKIT on real activations reported as unvalidated (`NOT_RUN`), with pipeline mock evaluated.
  - AuditKIT integration serialized to disk conforming to native schemas, but not externally executed against live remote telemetry.
- [x] **Zero Data Leakage:** Strict separation between DEV (calibration) and TEST (held-out evaluation). TEST data was never used for prompt design or threshold calibration.

---

## 2. Dataset Hygiene & Curation

- [x] **Balanced Equipartition:** 60 total episodes across 4 balanced quadrants:
  - 15 Attack DEV
  - 15 Attack TEST
  - 15 Benign DEV
  - 15 Benign TEST
- [x] **Threat Family Coverage:**
  - Family A (Memory/State Poisoning): 12 episodes
  - Family B (Tool-Output Indirect Injection): 10 episodes
  - Family C (Multi-Hop Delayed Exfiltration): 8 episodes
  - Matched Benign Tasks: 30 episodes
- [x] **Canary Isolation:** Exactly 30 unique synthetic canaries (`CANARY_A01`–`CANARY_C10`) present in attack episodes; 0 canaries in benign.
- [x] **Template Disjointness:** Zero attack template overlap between DEV and TEST ($T_{\text{dev}} \cap T_{\text{test}} = \emptyset$).
- [x] **CuratorKIT Ingestion & Exports:** Full Module 9 curation pipeline verified:
  - 4 full-fidelity JSONL exports.
  - 4 trainer-ready conversational projections (documented as lossy projections, not SafeTune inputs).
  - 5 cryptographic manifests with SHA-256 digests.
  - 5 Markdown dataset cards.
  - Verified `checksums.txt` (18/18 matching).

---

## 3. Runtime Defense & Security Gateway

- [x] **Simulated Sandbox:** 9 simulated tools (`read_email`, `send_email`, `search_documents`, `read_document`, `draft_email`, etc.). Zero real external calls.
- [x] **Authorization Ledger:** Tracks user directives and verified resources.
- [x] **Safety Gateway:** Evaluates tool calls and argument provenance.
  - Denial codes: `UNTRUSTED_ARGUMENT`, `DERIVED_UNTRUSTED_ARGUMENT`, `UNKNOWN_ARGUMENT_PROVENANCE`, `UNAUTHORIZED_ACTION`, `INVALID_TOOL`, `SCOPE_VIOLATION`.
  - Sensitive arguments fail closed on `UNKNOWN` or untrusted provenance.
  - Model generation cannot elevate untrusted provenance to trusted provenance.
- [x] **Multi-Turn Runner:** Supports turn-local (`E2a`) vs persistent (`E2b`) provenance tracking.

---

## 4. Ecosystem & Lexsi Stack Interoperability

- [x] **CuratorKIT (v0.1.22):** Integrated for dataset cleaning, deduplication, quality gating, manifests, and dataset cards.
- [x] **CircuitKIT (v0.2.0):** Integrated for contrastive dataset generation, edge discovery workflow, and faithfulness evaluation.
- [x] **AuditKIT (v1.1.3):** Thin adapter implemented (`traceguard/experiments/auditkit_adapter.py`) mapping execution logs to `AgentEpisode`, `AgentEvent`, and `RunResult`.
- [x] **SafeTune:** Documented requirements in `requirements/requirements-safetune-py312.txt`; split guard and stub verified.

---

## 5. Test Suite & Verification

- [x] **Full Regression:** `534 passed, 1 skipped` (from `pytest tests/ -ra`; the skipped test, `test_safetune_compat.py:17`, was not executed).
- [x] **Original Dataset Validator:** `python scripts/validate_dataset.py` (60/60 PASSED).
- [x] **Curated Dataset Validator:** `python scripts/validate_curated_dataset.py` (60/60 PASSED).
- [x] **8 Security Scenarios:** `tests/test_module10_security_scenarios.py` (8/8 PASSED).
- [x] **AuditKIT Adapter Tests:** `tests/test_auditkit_integration.py` (5/5 PASSED).

---

## 6. Reproducibility & Deliverables

- [x] **Master CLI:** `python scripts/run_traceguard.py --mode mock --split dev --auditkit` fully functional.
- [x] **Interactive Demo:** `python scripts/run_demo.py` offline and judge-ready.
- [x] **Documentation:**
  - `docs/REPRODUCIBILITY.md`
  - `docs/DEMO_GUIDE.md`
  - `docs/SUBMISSION_CHECKLIST.md`
  - `docs/FINAL_RESEARCH_REPORT.md`
  - `docs/MODULE10_FINAL_REPORT.md`
  - Root `README.md` updated.
- [x] **Git State:** 0 tracked files modified from prior modules; untracked Module 10 deliverables ready for commit; no unauthorized commits or pushes.
