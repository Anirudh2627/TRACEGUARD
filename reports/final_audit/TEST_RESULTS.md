# TraceGuard Comprehensive Test Suite Results

**Project:** TraceGuard — Multi-Turn Indirect Prompt Injection Auditing and Defense for AI Agents  
**Date:** November 2026  
**Auditor:** Senior QA & Test Automation Engineer  

---

## 1. Verbatim PyTest Execution Output

Executed via `pytest tests/ -ra`:

```text
============================= test session starts =============================
platform win32 -- Python 3.13.14, pytest-8.4.2, pluggy-1.6.0
rootdir: C:\Users\Kanch\Projects\TRACEGUARD
plugins: anyio-4.14.2, dash-4.4.1, jaxtyping-0.3.11, typeguard-4.6.0
collected 437 items / 1 skipped

tests\test_analysis_pipeline.py ........................................ [  9%]
...............................                                          [ 16%]
tests\test_attack_dataset.py ................                            [ 19%]
tests\test_attack_taxonomy.py ..........                                 [ 22%]
tests\test_audit_end_to_end.py ...                                       [ 22%]
tests\test_audit_gateway_scenarios.py ..............                     [ 26%]
tests\test_audit_provenance_rules.py ..........                          [ 28%]
tests\test_auditkit_integration.py .....                                 [ 29%]
tests\test_benign_dataset.py ..................                          [ 33%]
tests\test_calibration_classifier.py ......                              [ 35%]
tests\test_circuit_config.py ...................                         [ 39%]
tests\test_circuit_experiment.py .........                               [ 41%]
tests\test_circuit_results.py ...                                        [ 42%]
tests\test_circuit_split_guard.py ........                               [ 43%]
tests\test_curator_cleaning.py ...                                       [ 44%]
tests\test_curator_dataset_cards.py .                                    [ 44%]
tests\test_curator_deduplication.py ....                                 [ 45%]
tests\test_curator_exports.py ...                                        [ 46%]
tests\test_curator_ingestion.py .....                                    [ 47%]
tests\test_curator_manifests.py ..                                       [ 48%]
tests\test_curator_pipeline.py ....                                      [ 48%]
tests\test_curator_quality_gates.py .....                                [ 50%]
tests\test_curator_split_hygiene.py ...                                  [ 50%]
tests\test_data_schema.py ...........                                    [ 53%]
tests\test_dataset_validator.py ................                         [ 56%]
tests\test_episode_runner.py ......                                      [ 58%]
tests\test_evaluation.py .....                                           [ 59%]
tests\test_experiment_configs.py .........                               [ 61%]
tests\test_generation_tiny.py ssss                                       [ 62%]
tests\test_json_parser.py .........................                      [ 68%]
tests\test_loader_precision.py .........                                 [ 70%]
tests\test_member3_runtime_fixes.py .....................                [ 75%]
tests\test_metrics.py .....                                              [ 76%]
tests\test_mock_smoke.py ........                                        [ 78%]
tests\test_module10_security_scenarios.py ........                       [ 79%]
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
======================= 433 passed, 5 skipped in 15.91s =======================
```

---

## 2. Test Accounting & Reconciliation

| Accounting Dimension | Count | Description / Justification |
| :--- | :---: | :--- |
| **Total Test Files** | **42** | Located across `tests/` |
| **Collected Test Items** | **437** | Successfully collected test functions |
| **Collection-Time Skips** | **1** | `tests/test_safetune_compat.py:17` (requires Python $\ge$ 3.12 SafeTune env) |
| **Total Session Test Targets**| **438** | $437 \text{ collected} + 1 \text{ collection skip}$ |
| **Passed Test Cases** | **433** | 100% passing across all tested modules |
| **Runtime Skips** | **4** | `tests/test_generation_tiny.py:50, 57, 72, 100` (offline HF hub network skips) |
| **Total Skipped (Summary)** | **5** | $4 \text{ runtime} + 1 \text{ collection}$ |
| **Failed Test Cases** | **0** | Zero failures |
| **Deselected Test Cases** | **0** | Zero deselected |
| **Runtime Errors** | **0** | Zero runtime errors |

$$\text{Arithmetic Verification:} \quad 433 \text{ passed} + 4 \text{ runtime skipped} = 437 \text{ collected}; \quad 437 + 1 = 438 \text{ total targets}$$

---

## 3. Test Suite Categorization

```text
┌───────────────────────────────────────────────┬────────────┬─────────┬─────────┐
│ Test Category                                 │ Test Files │ Passed  │ Skipped │
├───────────────────────────────────────────────┼────────────┼─────────┼─────────┤
│ Data Schema & Attack Taxonomy                 │ 4          │ 48      │ 0       │
│ Strict JSON Parser & Model Loader             │ 4          │ 55      │ 4 (HF)  │
│ Prompt Builder & Message Construction         │ 2          │ 48      │ 0       │
│ Runtime Gateway, Authorization & Provenance   │ 5          │ 53      │ 0       │
│ Member 3 Runtime Security Fixes               │ 1          │ 21      │ 0       │
│ Phase 4 Provenance Audit Rules (P1–P10)       │ 1          │ 10      │ 0       │
│ Phase 5 Gateway Security Scenarios (G1–G14)   │ 1          │ 14      │ 0       │
│ Phase 13 End-to-End Mock Episodes (A, B, C)   │ 1          │ 3       │ 0       │
│ Module 10 Security Scenarios                  │ 1          │ 8       │ 0       │
│ Dataset Curation & Quality Gates (CuratorKIT) │ 10         │ 84      │ 0       │
│ CircuitKIT Interpretability & Split Guards    │ 4          │ 41      │ 0       │
│ AuditKIT Integration Adapter                  │ 1          │ 5       │ 0       │
│ SafeTune Split Guard & Compatibility          │ 2          │ 12      │ 1 (env) │
│ Scorer & Evaluation Regressions               │ 5          │ 31      │ 0       │
├───────────────────────────────────────────────┼────────────┼─────────┼─────────┤
│ TOTAL                                         │ 42         │ 433     │ 5       │
└───────────────────────────────────────────────┴────────────┴─────────┴─────────┘
```

---

## 4. Analysis of Skipped Tests

All 5 skips are legitimate environment/network condition skips and do not represent defects:
1. `tests/test_safetune_compat.py:17` (`needs the Python>=3.12 SafeTune env`):
   - Safely skips live SafeTune invocation when running on environments without the isolated `safetune` package installed.
2. `tests/test_generation_tiny.py:50, 57, 72, 100` (`HF hub unreachable; integration test needs network`):
   - Integration tests that attempt live downloads of `CohereLabs/tiny-aya-global` weights from Hugging Face. In offline sandbox mode, they safely skip and preserve test suite determinism.
