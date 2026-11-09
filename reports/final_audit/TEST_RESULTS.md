# TraceGuard Comprehensive Test Suite Results

**Project:** TraceGuard — Multi-Turn Indirect Prompt Injection Auditing and Defense for AI Agents  
**Date:** November 2026  
**Auditor:** Senior QA & Test Automation Engineer  

---

## 1. Verbatim PyTest Execution Output

Executed via `pytest tests/ -ra`:

```text
============================= test session starts =============================
platform win32 -- Python 3.13.14, pytest-9.2.0, pluggy-1.6.0
rootdir: C:\Users\yerag\Desktop\TRACEGUARD
plugins: anyio-4.15.1, platformdirs-4.12.3
collected 534 items / 1 skipped

tests\test_analysis_pipeline.py ........................................ [  7%]
...............................                                          [ 13%]
tests\test_attack_dataset.py ................                            [ 16%]
tests\test_attack_taxonomy.py ..........                                 [ 18%]
tests\test_audit_end_to_end.py ...                                       [ 18%]
tests\test_audit_gateway_scenarios.py ..............                     [ 21%]
tests\test_audit_provenance_labels_and_fail_closed.py ......             [ 22%]
tests\test_audit_provenance_rules.py ..........                          [ 24%]
tests\test_auditkit_agent_eval.py ....                                   [ 25%]
tests\test_auditkit_coverage.py ............                             [ 27%]
tests\test_auditkit_integration.py .....                                 [ 28%]
tests\test_benign_dataset.py ..................                          [ 31%]
tests\test_calibration_classifier.py ......                              [ 32%]
tests\test_circuit_config.py ...................                         [ 36%]
tests\test_circuit_experiment.py .........                               [ 38%]
tests\test_circuit_results.py ...                                        [ 38%]
tests\test_circuit_split_guard.py ........                               [ 40%]
tests\test_curator_cleaning.py ...                                       [ 40%]
tests\test_curator_dataset_cards.py .                                    [ 40%]
tests\test_curator_deduplication.py ....                                 [ 41%]
tests\test_curator_exports.py ...                                        [ 42%]
tests\test_curator_ingestion.py .....                                    [ 43%]
tests\test_curator_manifests.py ..                                       [ 43%]
tests\test_curator_pipeline.py ....                                      [ 44%]
tests\test_curator_quality_gates.py .....                                [ 45%]
tests\test_curator_split_hygiene.py ...                                  [ 45%]
tests\test_data_schema.py ...........                                    [ 47%]
tests\test_dataset_validator.py ................                         [ 50%]
tests\test_episode_runner.py ......                                      [ 51%]
tests\test_evaluation.py .....                                           [ 52%]
tests\test_experiment_configs.py .........                               [ 54%]
tests\test_generation_tiny.py ....                                       [ 55%]
tests\test_json_parser.py .........................                      [ 59%]
tests\test_loader_precision.py .........                                 [ 61%]
tests\test_member3_log_fields.py ......                                  [ 62%]
tests\test_member3_runtime_fixes.py .....................                [ 66%]
tests\test_member3_runtime_robustness.py ............................... [ 72%]
...........                                                              [ 74%]
tests\test_member3_user_merge.py .......                                 [ 75%]
tests\test_metrics.py .....                                              [ 76%]
tests\test_mock_smoke.py ........                                        [ 78%]
tests\test_module10_security_scenarios.py ........                       [ 79%]
tests\test_phase4_analysis_integration.py ..........                     [ 81%]
tests\test_prompt_builder.py .................                           [ 84%]
tests\test_prompt_configurations.py ...............................      [ 90%]
tests\test_provenance_ablation.py ..                                     [ 91%]
tests\test_provenance_canonical_taxonomy.py ......                       [ 92%]
tests\test_role_alternation.py ....                                      [ 92%]
tests\test_runtime_authorization.py ....                                 [ 93%]
tests\test_runtime_gateway.py .........                                  [ 95%]
tests\test_runtime_provenance.py .....                                   [ 96%]
tests\test_safetune_split_guard.py ............                          [ 98%]
tests\test_smoke_scoring_regressions.py ........                         [100%]

=========================== short test summary info ===========================
SKIPPED [1] tests\test_safetune_compat.py:17: needs the Python>=3.12 SafeTune env
======================= 534 passed, 1 skipped in 16.76s =======================
```

---

## 2. Test Accounting & Reconciliation

| Accounting Dimension | Count |
| :--- | :---: |
| Total test files | 52 |
| Collected test items | 534 |
| Collection-time skips | 1 |
| Passed | 534 |
| Runtime skips | 0 |
| Failed / deselected | 0 / 0 |

Arithmetic: 534 passed + 0 runtime skipped = 534 collected; 534 + 1 collection skip = 535 targets.

---

## 3. Per-File Breakdown

| Test file | Collected | Passed | Skipped |
| :--- | :---: | :---: | :---: |
| `tests/test_analysis_pipeline.py` | 71 | 71 | 0 |
| `tests/test_attack_dataset.py` | 16 | 16 | 0 |
| `tests/test_attack_taxonomy.py` | 10 | 10 | 0 |
| `tests/test_audit_end_to_end.py` | 3 | 3 | 0 |
| `tests/test_audit_gateway_scenarios.py` | 14 | 14 | 0 |
| `tests/test_audit_provenance_labels_and_fail_closed.py` | 6 | 6 | 0 |
| `tests/test_audit_provenance_rules.py` | 10 | 10 | 0 |
| `tests/test_auditkit_agent_eval.py` | 4 | 4 | 0 |
| `tests/test_auditkit_coverage.py` | 12 | 12 | 0 |
| `tests/test_auditkit_integration.py` | 5 | 5 | 0 |
| `tests/test_benign_dataset.py` | 18 | 18 | 0 |
| `tests/test_calibration_classifier.py` | 6 | 6 | 0 |
| `tests/test_circuit_config.py` | 19 | 19 | 0 |
| `tests/test_circuit_experiment.py` | 9 | 9 | 0 |
| `tests/test_circuit_results.py` | 3 | 3 | 0 |
| `tests/test_circuit_split_guard.py` | 8 | 8 | 0 |
| `tests/test_curator_cleaning.py` | 3 | 3 | 0 |
| `tests/test_curator_dataset_cards.py` | 1 | 1 | 0 |
| `tests/test_curator_deduplication.py` | 4 | 4 | 0 |
| `tests/test_curator_exports.py` | 3 | 3 | 0 |
| `tests/test_curator_ingestion.py` | 5 | 5 | 0 |
| `tests/test_curator_manifests.py` | 2 | 2 | 0 |
| `tests/test_curator_pipeline.py` | 4 | 4 | 0 |
| `tests/test_curator_quality_gates.py` | 5 | 5 | 0 |
| `tests/test_curator_split_hygiene.py` | 3 | 3 | 0 |
| `tests/test_data_schema.py` | 11 | 11 | 0 |
| `tests/test_dataset_validator.py` | 16 | 16 | 0 |
| `tests/test_episode_runner.py` | 6 | 6 | 0 |
| `tests/test_evaluation.py` | 5 | 5 | 0 |
| `tests/test_experiment_configs.py` | 9 | 9 | 0 |
| `tests/test_generation_tiny.py` | 4 | 4 | 0 |
| `tests/test_json_parser.py` | 25 | 25 | 0 |
| `tests/test_loader_precision.py` | 9 | 9 | 0 |
| `tests/test_member3_log_fields.py` | 6 | 6 | 0 |
| `tests/test_member3_runtime_fixes.py` | 21 | 21 | 0 |
| `tests/test_member3_runtime_robustness.py` | 42 | 42 | 0 |
| `tests/test_member3_user_merge.py` | 7 | 7 | 0 |
| `tests/test_metrics.py` | 5 | 5 | 0 |
| `tests/test_mock_smoke.py` | 8 | 8 | 0 |
| `tests/test_module10_security_scenarios.py` | 8 | 8 | 0 |
| `tests/test_phase4_analysis_integration.py` | 10 | 10 | 0 |
| `tests/test_prompt_builder.py` | 17 | 17 | 0 |
| `tests/test_prompt_configurations.py` | 31 | 31 | 0 |
| `tests/test_provenance_ablation.py` | 2 | 2 | 0 |
| `tests/test_provenance_canonical_taxonomy.py` | 6 | 6 | 0 |
| `tests/test_role_alternation.py` | 4 | 4 | 0 |
| `tests/test_runtime_authorization.py` | 4 | 4 | 0 |
| `tests/test_runtime_gateway.py` | 9 | 9 | 0 |
| `tests/test_runtime_provenance.py` | 5 | 5 | 0 |
| `tests/test_safetune_split_guard.py` | 12 | 12 | 0 |
| `tests/test_smoke_scoring_regressions.py` | 8 | 8 | 0 |
| `tests/test_safetune_compat.py` | (skipped at collection) | 0 | 1 |

---

## 4. Skipped Tests

Skipped tests were **not executed** and are not counted as passing:
- `tests\test_safetune_compat.py:17` (needs the Python>=3.12 SafeTune env)

Mock-backend results are not real-model evidence; real-model E0-E4 runs are NOT_RUN. Counts depend on the machine; re-run `pytest tests/ -ra` to confirm.
