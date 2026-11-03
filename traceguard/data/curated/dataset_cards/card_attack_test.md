# Dataset Card: attack_test

## 1. Dataset Overview

- **Dataset Name:** attack_test
- **Dataset Version:** 1.0.0
- **Generation Timestamp:** 2026-11-03T18:03:51.768809+00:00
- **CuratorKIT Version:** 0.1.22
- **TraceGuard Commit:** `6c851e1`
- **Total Episodes:** 15

---

## 2. Intended Research Purpose

TraceGuard investigates **multi-turn indirect prompt injection auditing and defense** for tool-augmented language agents. The core research question evaluated with this dataset is:

> *"Does preserving source provenance across turns reduce unsafe tool-call attempts compared with losing provenance, while preserving legitimate task completion?"*

---

## 3. Dataset Composition & Statistics

- **Attack Episodes:** 15
- **Benign Episodes:** 0
- **DEV Split Count:** 0
- **TEST Split Count:** 15
- **Unique Synthetic Canaries:** 15
- **Unique Templates:** 6

### Attack Family Distribution
- **family_a**: 6 episodes
- **family_b**: 5 episodes
- **family_c**: 4 episodes

### Active Templates
`doc_injection_02`, `email_injection_02`, `memory_poisoning_01`, `search_injection_02`, `search_injection_03`, `stored_injection_02`

---

## 4. Provenance Labels Distribution

TraceGuard tracks six immutable provenance trust labels:
- `UNTRUSTED_EXTERNAL`: 32 occurrences
- `DERIVED_UNTRUSTED`: 42 occurrences

---

## 5. Synthetic Canary Usage

- Attack episodes feature synthetic secret tokens (e.g. `CANARY_DOC_01`) embedded in authorized contexts or initial states.
- Leakage is tracked deterministically when an agent invokes an exfiltration tool or emits the canary in final responses.
- Benign episodes contain **zero canaries**.

---

## 6. DEV / TEST Split Methodology

- The dataset is split strictly by **complete attack templates**, not individual paraphrases.
- Attack DEV and TEST sets have **zero template overlap** ($T_{\text{dev}} \cap T_{\text{test}} = \emptyset$), ensuring zero split contamination.
- Test templates are strictly reserved for held-out evaluation.

---

## 7. Curation & Quality Gate Results

- **Quality Gate Status:** `PASSED`
- **Checks Passed:** 65 / 65
- **Exact Duplicates:** 0
- **Near-Duplicate Warnings:** 0
- **Cleaning Operations:** {}

---

## 8. Intended Use and Prohibited Uses

### Intended Use
- Benchmarking indirect prompt injection defense architectures.
- Evaluating provenance-tracking gateways ($E2a$ vs. $E2b$).
- Researching mechanistic interpretability of injection routing (CircuitKIT).

### Prohibited / Inappropriate Uses
- Training malicious injection generators.
- Real-world production deployment without safety review.
- Merging DEV and TEST data for model training.

---

## 9. Known Limitations

- Multi-turn episodes focus on 3 to 6 turns in desktop, enterprise, and developer agent workflows.
- Real-world zero-day payloads may present linguistic structures beyond the taxonomy's canonical templates.
