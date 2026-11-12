# TraceGuard Dataset & CuratorKIT Audit

**Project:** TraceGuard — Multi-Turn Indirect Prompt Injection Auditing and Defense for AI Agents  
**Date:** November 2026  
**Auditor:** Senior Data & Machine Learning Quality Auditor  

---

## 1. Dataset Architecture & Equipartition Grid

TraceGuard provides an authoritative, curated dataset of **60 multi-turn episodes** (215 turns, 276 source records), divided into four balanced quadrants across split and task type:

```text
               ┌───────────────────────┬───────────────────────┐
               │   DEVELOPMENT SPLIT   │     TEST SPLIT        │
               │   (Calibration Set)   │  (Held-Out Benchmark) │
┌──────────────┼───────────────────────┼───────────────────────┤
│ ATTACK       │ 15 Episodes           │ 15 Episodes           │
│ EPISODES     │ 7 Unique Templates    │ 6 Unique Templates    │
│              │ 15 Synthetic Canaries │ 15 Synthetic Canaries │
├──────────────┼───────────────────────┼───────────────────────┤
│ BENIGN       │ 15 Episodes           │ 15 Episodes           │
│ CONTROLS     │ Matched Tasks         │ Matched Tasks         │
│              │ 0 Canaries            │ 0 Canaries            │
└──────────────┴───────────────────────┴───────────────────────┘
```

---

## 2. Threat Family Taxonomy & Coverage

The 30 attack episodes cover three distinct indirect prompt injection threat families:

| Threat Family | Description | Mechanism | Count | Splits |
| :--- | :--- | :--- | :---: | :---: |
| **Family A** | **Document & Email Injection** | Injects poisoned instructions into stored notes or staging memory to alter future routing or persistent state. | 12 | 6 DEV, 6 TEST |
| **Family B** | **Tool-Output Indirect Injection** | Injects instructions within search results, emails, or invoice attachments directing immediate unauthorized actions. | 10 | 5 DEV, 5 TEST |
| **Family C** | **Stored / Cross-Turn Injection** | Ingests payload in Turn 1 that remains dormant until an authorized action in Turn 2 or 3 triggers data exfiltration. | 8 | 4 DEV, 4 TEST |
| **Benign Controls**| **Legitimate Task Completion** | Matched enterprise workflows (invoice review, vendor status, document analysis) without attacks. | 30 | 15 DEV, 15 TEST |

---

## 3. Strict Split Hygiene & Leakage Prevention

A critical scientific integrity requirement is the absolute separation of development calibration data from held-out evaluation data:

1. **Template Disjointness ($T_{\text{dev}} \cap T_{\text{test}} = \emptyset$):**
   - Development Split: 7 attack templates (`template_a01_...` to `template_c02_...`).
   - Held-Out Test Split: 6 attack templates (`template_a04_...` to `template_c03_...`).
   - Overlap: Exactly **0 overlapping templates**. Verified by automated validator and CuratorKIT split hygiene check.
2. **Canary Isolation:**
   - Exactly 30 unique synthetic canaries (`CANARY_A01` through `CANARY_C10`).
   - 15 unique canaries in DEV; 15 unique canaries in TEST.
   - Zero canary crossover between DEV and TEST.
   - Zero canaries present in benign episodes.
3. **Canonical Provenance Labels:**
   - All 60 episodes strictly use canonical labels: `SYSTEM_POLICY`, `SYSTEM_CONFIG`, `USER_AUTHORIZED`, `UNTRUSTED_EXTERNAL`, `DERIVED_UNTRUSTED`, `UNKNOWN`.
   - Zero informal string variants or unvalidated labels.

---

## 4. CuratorKIT Pipeline (v0.1.22) Audit

The complete CuratorKIT dataset pipeline was executed via `python scripts/run_curator.py`:

- **Ingestion & Validation:** 60/60 episodes ingested successfully. 0 rejected.
- **MinHash LSH Deduplication:** 0 duplicate collisions across splits.
- **Automated Quality Gates:** **65 / 65 checks PASSED** across structural, attack, benign, and split hygiene categories.
- **Full-Fidelity Exports:** 4 JSONL files (`attack_dev.jsonl`, `attack_test.jsonl`, `benign_dev.jsonl`, `benign_test.jsonl`).
- **Trainer-Ready Projections:** 4 JSONL conversational projections documented as lossy projections.
- **Cryptographic Manifests:** 5 JSON manifests with verified SHA-256 digests.
- **Markdown Dataset Cards:** 5 dataset cards documenting provenance, ethical considerations, and threat models.
- **Cryptographic Checksums:** `checksums.txt` contains 18 entries. All 18 verified matching by `scripts/validate_curated_dataset.py`.
