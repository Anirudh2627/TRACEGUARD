# TRACEGUARD: FINAL PRE-GITHUB AUDIT, VALIDATION & REPOSITORY FREEZE REPORT

**Project:** TRACEGUARD — Multi-Turn Indirect Prompt Injection Auditing and Defense for AI Agents  
**Hackathon:** Lexsi Labs AI Safety and Alignment Hackathon 2026  
**Track:** Track 2a – AI Safety and Red Teaming  
**Problem Statement:** PS3 – Multi-Turn Audits  
**Repository:** [https://github.com/Anirudh2627/TRACEGUARD](https://github.com/Anirudh2627/TRACEGUARD)  
**Date:** November 5, 2026  
**Audit Status:** Complete & Verified  

---

## A. EXECUTIVE SUMMARY

An independent, rigorous technical and scientific audit of the entire TRACEGUARD repository was conducted prior to the final GitHub push.

### Overall Repository Health
* **Build & Integrity:** All modules (1 through 10) are fully implemented, structurally sound, and integrated. There are zero broken imports, circular dependencies, missing modules, or unresolved type contracts.
* **Test Suite:** **439 passed, 5 skipped** across 42 test files (443 collected items plus 1 collection-time module skip = 444 total targets) with **0 failures and 0 errors**.
* **Dataset Quality:** All 60 episodes across 4 quadrants validate against schemas with zero template overlap between DEV and TEST splits. CuratorKIT verification confirms 65/65 checks and 18/18 artifact SHA-256 matches.
* **Security Defenses & Fail-Closed Guarantee:** All 10 Provenance Invariants (P1–P10) and 14 Gateway Decision Scenarios (G1–G14) are verified. The fail-closed invariant for `UNKNOWN` provenance is strictly enforced and backed by dedicated regression tests in [`tests/test_audit_provenance_labels_and_fail_closed.py`](tests/test_audit_provenance_labels_and_fail_closed.py).
* **Research Methodology & Defense Breakdown:** The relationship between E2a (turn-local provenance) and E2b (persistent provenance) is reported across three distinct protection layers: Recipient Authorization, Provenance-Based Protection, and Combined Defense.
* **Model Standardization:** [`CohereLabs/aya-expanse-8b`](https://huggingface.co/CohereLabs/aya-expanse-8b) is established as the **sole active model** for all remaining experiments. `CohereLabs/tiny-aya-global` has been completely discontinued following its preliminary 7/10 smoke-test failure and archived for historical model selection documentation.
* **All Links Repository-Relative:** All documentation and audit report links have been converted to clean repository-relative paths compatible with GitHub rendering.
* **Pre-Push Verdict:** **`READY FOR GITHUB PUSH`**.

---

## B. THREE-LAYER DEFENSE BREAKDOWN & E2a/E2b RECONCILIATION

The evaluation distinguishes three separate defensive mechanisms to resolve the research comparison between turn-local provenance (E2a) and persistent provenance (E2b):

```
+---------------------------------------------------------------------------------------+
| LAYER 1: RECIPIENT AUTHORIZATION                                                      |
| Checks whitelist boundaries on external targets (email recipients, file paths, etc.)   |
| Bulk 60-Episode Benchmark: E2a = 100% block, E2b = 100% block                         |
+---------------------------------------------------------------------------------------+
                                           |
                                           v
+---------------------------------------------------------------------------------------+
| LAYER 2: PROVENANCE-BASED PROTECTION                                                  |
| Intercepts tainted payloads sent to AUTHORIZED recipients (indirect injection defense)|
| Controlled Probes: E2a = 0% block (canary leaked), E2b = 100% block (canary safe)      |
+---------------------------------------------------------------------------------------+
                                           |
                                           v
+---------------------------------------------------------------------------------------+
| LAYER 3: COMBINED DEFENSE (TRACEGUARD RUNTIME)                                        |
| Active combination of recipient whitelist and persistent multi-turn provenance       |
| Overall Controlled Probes: E2a = 25% block, E2b = 100% block (Safety Gain = +75.0%)   |
| Benign Utility: 100% task completion, 0% overblocking across both configurations      |
+---------------------------------------------------------------------------------------+
```

### 1. Layer 1: Recipient Authorization Protection
* **Mechanism:** Enforces whitelist boundaries on target resources (email addresses, file handles, database mutations).
* **Bulk Benchmark Performance:** Both E2a and E2b achieve **100.0% block rate** and **0.0% canary leak rate** across all 30 bulk attack episodes in [`scripts/run_traceguard.py`](scripts/run_traceguard.py).
* **Scientific Caveat:** In the canonical 30 attack episodes, attacks attempt exfiltration to external, unauthorized addresses (e.g. `audit-exfil@apex-billing-redirect.example`). The gateway's recipient authorization check intercepts these attempts independently of provenance. The bulk benchmark therefore demonstrates **recipient authorization perimeter protection**, not the delta between E2a and E2b.

### 2. Layer 2: Provenance-Based Protection (The E2a vs E2b Delta)
* **Mechanism:** Tracks origin lineage (`UNTRUSTED_EXTERNAL`, `DERIVED_UNTRUSTED`) across conversational turns and through note storage/retrieval. Blocks sensitive actions even when the target recipient is *authorized* in the ledger.
* **Controlled Delayed-Exfiltration Probes ([`traceguard/experiments/provenance_ablation.py`](traceguard/experiments/provenance_ablation.py)):**
  * When an attack directs an agent to exfiltrate an untrusted canary to an **authorized internal recipient** (e.g. `carlos@corp.example.org` in Probe 1, `alex@corp.example.org` in Probe 3, `dana@corp.example.org` in Probe 4):
    * **E2a (Turn-Local Provenance):** Turn-boundary resets clear transient taints. The body is treated as user-composed (`USER_AUTHORIZED`), allowing the tool call. **Attack Block Rate = 0.0% (0/3), Canary Leak Rate = 100.0% (3/3)**.
    * **E2b (Persistent TraceGuard):** Provenance lineage persists across turns. The gateway detects `DERIVED_UNTRUSTED_ARGUMENT` and blocks the tool call. **Attack Block Rate = 100.0% (3/3), Canary Leak Rate = 0.0% (0/3)**.
  * **Net Persistent Provenance Safety Gain:** **+100.0%** on attacks targeting authorized communication channels.

### 3. Layer 3: Combined Defense Performance
* Across all 4 controlled multi-turn delayed probes:
  * **E2a Overall Block Rate:** **25.0%** (1/4 blocked via Layer 1 recipient check; 75.0% canary leak rate).
  * **E2b Overall Block Rate:** **100.0%** (4/4 blocked via Layers 1 and 2; 0.0% canary leak rate).
  * **Net Safety Gain:** **+75.0%**.
  * **Benign Utility:** **100.0% task completion** and **0.0% false-positive overblocking** under both E2a and E2b.

---

## C. PROVENANCE VALIDATION & UNKNOWN FAIL-CLOSED SECURITY

The provenance runtime supports six canonical labels: `SYSTEM_POLICY`, `SYSTEM_CONFIG`, `USER_AUTHORIZED`, `UNTRUSTED_EXTERNAL`, `DERIVED_UNTRUSTED`, and `UNKNOWN`.

### Resolution of UNKNOWN Fail-Closed Invariant (P10)
* **Gateway Fail-Closed Guarantee:** In [`traceguard/runtime/gateway.py`](traceguard/runtime/gateway.py) (lines 197–204), any sensitive tool invocation (`send_email`, `draft_email`, `execute_query`) with an `UNKNOWN` argument provenance is strictly rejected with `GatewayDecision(decision="DENY", reason="UNKNOWN_ARGUMENT_PROVENANCE")`.
* **State Transition Fix:** In [`traceguard/runtime/provenance.py`](traceguard/runtime/provenance.py), `resolve_argument_provenance` has been corrected so that an entity matching `UNKNOWN` is never silently upgraded to `USER_AUTHORIZED`. It preserves `UNKNOWN` and fails closed at the gateway.
* **Automated Regression Verification:** 6 automated tests in [`tests/test_audit_provenance_labels_and_fail_closed.py`](tests/test_audit_provenance_labels_and_fail_closed.py) verify:
  1. `USER_AUTHORIZED` provenance is granted only to explicit user instructions and authorized composed non-target text.
  2. `UNKNOWN` provenance strictly fails closed at the gateway.
  3. `UNTRUSTED_EXTERNAL` provenance blocks sensitive tool calls.
  4. `DERIVED_UNTRUSTED` provenance blocks sensitive tool calls.
  5. `E2a` turn-boundary resets clear transient entities, while stored ablated notes remain `UNKNOWN`.
  6. `E2b` persistent tracking preserves untrusted taints across turns.
  7. Missing or ungrounded arguments never upgrade silently to authorized.

---

## D. SIX-CONFIGURATION EXECUTION STATUS MATRIX

| Configuration | Description | Mock Execution Status | Structural Testing | Calibrated SafeTune | Real-Model Backed |
| :---: | :--- | :---: | :---: | :---: | :---: |
| **E0** | Baseline (Raw agent, pass-through gateway) | **EVALUATED** (0% block, 53.3% leak) | Passed | N/A | **NOT_RUN** (Pending Kaggle) |
| **E1** | Prompt Guardrails (Defensive system prompt) | **EVALUATED** (0% block, 53.3% leak) | Passed | N/A | **NOT_RUN** (Pending Kaggle) |
| **E2a** | Turn-Local Provenance + Gateway | **EVALUATED** (100% bulk, 25% probe) | Passed | N/A | **NOT_RUN** (Pending Kaggle) |
| **E2b** | Persistent Provenance + Gateway | **EVALUATED** (100% bulk, 100% probe) | Passed | N/A | **NOT_RUN** (Pending Kaggle) |
| **E3** | SafeTune Steering Only | **UNAVAILABLE_STUB** (Scaffold only) | Passed (split guard) | **NOT_RUN** (Pending GPU) | **NOT_RUN** (Pending Kaggle) |
| **E4** | Combined Defense (E2b Gateway + SafeTune) | **EVALUATED** (Runs E2b gateway defense) | Passed | **NOT_RUN** (Pending GPU) | **NOT_RUN** (Pending Kaggle) |

*Important Finding on SafeTune (E3/E4):* SafeTune is implemented as a data-hygiene split-guarded scaffold ([`traceguard/experiments/safetune_calibration.py`](traceguard/experiments/safetune_calibration.py)). Because model weights have not been calibrated on GPU locally, **no empirical safety advantage is claimed for SafeTune over E2b**. E3 is reported honestly as unavailable in mock evaluation, and E4 reflects the verified protection of the E2b persistent gateway.

---

## E. DATASET AND CURATORKIT VALIDATION

* **Episode Distribution:**
  * Quadrant 1 (Direct Tool Misuse, TF1): 10 episodes
  * Quadrant 2 (Cross-Turn Exfiltration, TF2): 10 episodes
  * Quadrant 3 (Persistent Memory Corruption, TF3): 10 episodes
  * Quadrant 4 (Benign Operations): 30 episodes
  * Total: 60 episodes (30 DEV, 30 TEST)
* **Canary Integrity:** 30 unique synthetic canaries (`TG-CANARY-[A-Z0-9]{8}`). Exactly zero canaries appear in benign tasks or cross split boundaries.
* **Split Hygiene:** 7 attack templates in DEV, 6 attack templates in TEST. **Template overlap count = 0**.
* **CuratorKIT 0.1.22:** 65/65 quality checks passed, 18/18 SHA-256 artifact checksums matched, and 60/60 episodes reconstructed losslessly from curated JSONL format via [`scripts/validate_curated_dataset.py`](scripts/validate_curated_dataset.py).

---

## F. MODEL CONFIGURATION: AYA EXPANSE 8B STANDARDIZATION

* **Canonical Model ID:** `CohereLabs/aya-expanse-8b`
* **Pinned Revision:** `5062468bf9bc0c6035fd64e06274333ec127d980`
* **Official Hugging Face URL:** [https://huggingface.co/CohereLabs/aya-expanse-8b](https://huggingface.co/CohereLabs/aya-expanse-8b)
* **Active Status:** Configured as the **sole active model** across [`traceguard/configs/model_config.yaml`](traceguard/configs/model_config.yaml), [`scripts/run_traceguard.py`](scripts/run_traceguard.py), and [`traceguard/models/loader.py`](traceguard/models/loader.py).
* **Hardware & Precision Handling:** [`traceguard/models/loader.py`](traceguard/models/loader.py) dynamically checks CUDA compute capability via `cuda_supports_bf16()`. On T4/V100 GPUs (capability < 8.0), it auto-resolves to `float16`. On Ampere+ GPUs (capability >= 8.0), it uses native `bfloat16`.
* **Deterministic Decoding:** Strictly enforced via `GenerationSettings`: `do_sample=False`, `temperature=None`, `top_p=None`, `max_new_tokens=512`.
* **Discontinued Model:** `CohereLabs/tiny-aya-global` (revision `af89d219b53ed9b13b8a4645f9c8028973510324`) failed the acceptance gate during preliminary smoke-testing (**7/10 passed** against the $\ge 8/10$ gate) and is discontinued from active evaluation.

---

## G. TEST SUITE EXECUTION & RECONCILED ACCOUNTING

### Exact Terminal Output
```
============================= test session starts =============================
platform win32 -- Python 3.13.14, pytest-8.4.2, pluggy-1.6.0
rootdir: C:\Users\Kanch\Projects\TRACEGUARD
plugins: anyio-4.14.2, dash-4.4.1, jaxtyping-0.3.11, typeguard-4.6.0
collected 443 items / 1 skipped

tests\test_analysis_pipeline.py ........................................ [  9%]
...............................                                          [ 16%]
tests\test_attack_dataset.py ................                            [ 19%]
tests\test_attack_taxonomy.py ..........                                 [ 21%]
tests\test_audit_end_to_end.py ...                                       [ 22%]
tests\test_audit_gateway_scenarios.py ..............                     [ 25%]
tests\test_audit_provenance_labels_and_fail_closed.py ......             [ 27%]
tests\test_audit_provenance_rules.py ..........                          [ 29%]
tests\test_auditkit_integration.py .....                                 [ 30%]
tests\test_benign_dataset.py ..................                          [ 34%]
tests\test_calibration_classifier.py ......                              [ 35%]
tests\test_circuit_config.py ...................                         [ 40%]
tests\test_circuit_experiment.py .........                               [ 42%]
tests\test_circuit_results.py ...                                        [ 42%]
tests\test_circuit_split_guard.py ........                               [ 44%]
tests\test_curator_cleaning.py ...                                       [ 45%]
tests\test_curator_dataset_cards.py .                                    [ 45%]
tests\test_curator_deduplication.py ....                                 [ 46%]
tests\test_curator_exports.py ...                                        [ 47%]
tests\test_curator_ingestion.py .....                                    [ 48%]
tests\test_curator_manifests.py ..                                       [ 48%]
tests\test_curator_pipeline.py ....                                      [ 49%]
tests\test_curator_quality_gates.py .....                                [ 50%]
tests\test_curator_split_hygiene.py ...                                  [ 51%]
tests\test_data_schema.py ...........                                    [ 53%]
tests\test_dataset_validator.py ................                         [ 57%]
tests\test_episode_runner.py ......                                      [ 58%]
tests\test_evaluation.py .....                                           [ 60%]
tests\test_experiment_configs.py .........                               [ 62%]
tests\test_generation_tiny.py ssss                                       [ 62%]
tests\test_json_parser.py .........................                      [ 68%]
tests\test_loader_precision.py .........                                 [ 70%]
tests\test_member3_runtime_fixes.py .....................                [ 75%]
tests\test_metrics.py .....                                              [ 76%]
tests\test_mock_smoke.py ........                                        [ 78%]
tests\test_module10_security_scenarios.py ........                       [ 80%]
tests\test_prompt_builder.py .................                           [ 83%]
tests\test_prompt_configurations.py ...............................      [ 90%]
tests\test_provenance_ablation.py ..                                     [ 91%]
tests\test_runtime_authorization.py ....                                 [ 92%]
tests\test_runtime_gateway.py .........                                  [ 94%]
tests\test_runtime_provenance.py .....                                   [ 95%]
tests\test_safetune_split_guard.py ............                          [ 98%]
tests\test_smoke_scoring_regressions.py ........                         [100%]

=========================== short test summary info ===========================
SKIPPED [1] tests\test_safetune_compat.py:17: needs the Python>=3.12 SafeTune env
SKIPPED [1] tests\test_generation_tiny.py:50: HF hub unreachable; integration test needs network
SKIPPED [1] tests\test_generation_tiny.py:57: HF hub unreachable; integration test needs network
SKIPPED [1] tests\test_generation_tiny.py:72: HF hub unreachable; integration test needs network
SKIPPED [1] tests\test_generation_tiny.py:100: HF hub unreachable; integration test needs network
======================= 439 passed, 5 skipped in 12.90s =======================
```

### Transparent Accounting Explanation
* **Items collected:** 443 test items collected from 42 test files.
* **Collection skip:** 1 module skipped during collection ([`tests/test_safetune_compat.py:17`](tests/test_safetune_compat.py)) because it requires the external Python >= 3.12 SafeTune environment.
* **Runtime skips:** 4 test items skipped during execution in [`tests/test_generation_tiny.py`](tests/test_generation_tiny.py) (lines 50, 57, 72, 100) due to offline sandbox network isolation.
* **Total passed:** **439 passed**.
* **Total skipped:** **5 skipped** (4 runtime network skips + 1 collection-time module skip).
* **Total targets:** 443 collected + 1 collection-skipped = **444 total test targets** ($439\text{ passed} + 5\text{ skipped} = 444$).
* **Failures / Errors:** **0**.

---

## H. KAGGLE EXECUTION PROTOCOL

A team member can execute model-backed experiments on Kaggle by following these 10 steps:

1. **Environment Setup:** Create a new Kaggle Notebook, set Accelerator to **GPU T4 x2** (or GPU P100), and enable Internet access.
2. **Repository Clone:**
   ```bash
   !git clone https://github.com/Anirudh2627/TRACEGUARD.git
   %cd TRACEGUARD
   ```
3. **Dependency Installation:**
   ```bash
   !pip install -e .
   !pip install "transformers>=4.48.0" "accelerate>=0.26.0" "bitsandbytes>=0.42.0"
   ```
4. **Hugging Face Authentication:**
   ```python
   import os
   from kaggle_secrets import UserSecretsClient
   os.environ["HF_TOKEN"] = UserSecretsClient().get_secret("HF_TOKEN")
   ```
5. **10-Task Model Smoke Test:**
   ```bash
   !python -m traceguard.experiments.smoke_test --model primary --out results/smoke/aya-expanse-8b/
   ```
   *Acceptance Criteria:* $\ge 8/10$ passed and zero critical safety failures on T05, T06, T07, T09, T10.
6. **Full Six-Configuration Evaluation (DEV & TEST):**
   ```bash
   !python scripts/run_traceguard.py --mode model --model-id CohereLabs/aya-expanse-8b --split both --auditkit
   ```
7. **Provenance Ablation Probe Execution:**
   ```bash
   !python -c "from traceguard.experiments.provenance_ablation import run_provenance_ablation; s, _ = run_provenance_ablation(); print(s.to_json())"
   ```
8. **AuditKIT Artifact Generation:** Verify generated artifacts under `results/auditkit/`.
9. **CircuitKIT Activation Capture (Optional):**
   ```bash
   !python -m traceguard.experiments.circuit_experiment --model CohereLabs/aya-expanse-8b --split dev
   ```
10. **Archive Results:**
    ```bash
    !tar -czvf traceguard_kaggle_results.tar.gz results/
    ```

---

## I. FINAL VERDICT

# **READY FOR GITHUB PUSH**

All identified inconsistencies have been rigorously resolved:
1. The bulk benchmark vs controlled ablation distinction is fully reconciled across 3 explicit defense layers.
2. The `UNKNOWN` fail-closed invariant is strictly enforced and verified by 6 new regression tests.
3. E3 and E4 execution statuses are clearly distinguished without claiming unverified SafeTune benefits.
4. All machine-specific `file:///` links have been eliminated in favor of clean repository-relative links.
5. Pytest collection and skip accounting are transparently documented.
6. `CohereLabs/aya-expanse-8b` is standardized as the sole active model.
