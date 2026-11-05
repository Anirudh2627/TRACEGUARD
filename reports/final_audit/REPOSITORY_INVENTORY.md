# TraceGuard Repository Inventory & Architecture Audit

**Project:** TraceGuard — Multi-Turn Indirect Prompt Injection Auditing and Defense for AI Agents  
**Hackathon:** Lexsi Labs AI Safety and Alignment Hackathon 2026 (Track 2a – AI Safety and Red Teaming, PS3)  
**Date:** November 2026  
**Auditor:** Senior Integration Auditor & AI Security Researcher  

---

## 1. Executive Layout & Structural Summary

The TraceGuard repository is structured into modular layers spanning data schema/curation, model interface/parsing, runtime security enforcement, evaluation/metrics, and external safety toolkit integrations (CuratorKIT, CircuitKIT, AuditKIT, SafeTune).

```text
TRACEGUARD/
├── traceguard/
│   ├── configs/                  # Tool specifications, model pins, smoke definitions
│   │   ├── model_config.yaml     # Pinned models (tiny-aya-global, aya-expanse-8b), device/generation settings
│   │   ├── smoke_tasks.jsonl     # 10 acceptance smoke tasks for model protocol
│   │   └── tools.yaml            # 9 synthetic tool schemas (read/search/draft/send/notes/private)
│   ├── data/                     # Authoritative multi-turn episode dataset
│   │   ├── schema.py             # Shared episode, turn, source record, and provenance schemas
│   │   ├── taxonomy.py           # Formal definitions for Threat Families A, B, and C
│   │   ├── dataset_validator.py  # 10-check structural and split-hygiene quality validator
│   │   ├── episodes_attack_dev.jsonl  # 15 Attack episodes (Calibration)
│   │   ├── episodes_attack_test.jsonl # 15 Attack episodes (Held-out Test)
│   │   ├── episodes_benign_dev.jsonl  # 15 Benign episodes (Calibration)
│   │   ├── episodes_benign_test.jsonl # 15 Benign episodes (Held-out Test)
│   │   ├── curated/              # CuratorKIT exports, dataset cards, manifests, and checksums.txt
│   │   └── curator/              # CuratorKIT ingestion, deduplication, quality gates, and export pipeline
│   ├── experiments/              # Evaluation engine, ablation probes, and toolkit adapters
│   │   ├── auditkit_adapter.py   # Native Lexsi Labs AuditKIT 1.1.3+ adapter
│   │   ├── canary.py             # Deterministic canary matching (exact, normalized, partial, base64)
│   │   ├── circuit_config.py     # CircuitKIT experiment configuration
│   │   ├── circuit_experiment.py # CircuitKIT contrastive pipeline, discovery, and faithfulness
│   │   ├── circuit_results.py    # CircuitKIT results schemas
│   │   ├── episode_scoring.py    # Deterministic episode scoring engine
│   │   ├── evaluation.py         # EvaluationRunner for multi-turn configurations (E0-E4)
│   │   ├── metrics.py            # Aggregate metrics, numerators/denominators, and confidence intervals
│   │   ├── provenance_ablation.py# Controlled E2a vs E2b delayed injection ablation experiment
│   │   ├── safetune_calibration.py # SafeTune calibration loader with hard split-guards
│   │   └── safetune_compat.py    # SafeTune compatibility verification
│   ├── models/                   # Model loader, prompt templates, and strict protocol parser
│   │   ├── config.py             # Dataclasses for model and smoke configs
│   │   ├── generation.py         # Abstract GenerationBackend and greedy GenerationSettings
│   │   ├── json_parser.py        # Strict zero-repair JSON parser for tool calls and final responses
│   │   ├── loader.py             # Hardware-aware loader plan resolution
│   │   ├── mock_backend.py       # Deterministic ScriptedMockBackend and SimulationAuditBackend
│   │   ├── prompt_builder.py     # Prompt rendering with configuration-specific history
│   │   └── steered_backend.py    # SafeTune representation steering execution backend
│   └── runtime/                  # Runtime defense, authorization, and gateway
│       ├── authorization.py      # AuthorizationLedger, sensitive tools, and single-use permissions
│       ├── gateway.py            # SafetyGateway mediating all tool invocations
│       ├── logging.py            # EpisodeExecutionLog and TurnExecutionRecord schemas
│       ├── provenance.py         # ProvenanceTracker for turn-local (E2a) and persistent (E2b) lineage
│       ├── runner.py             # EpisodeRunner sequencing multi-turn execution
│       ├── tools.py              # MockToolExecutor simulating 9 safe, sandboxed offline tools
│       └── userinput.py          # Isolation of quoted/pasted text from user directives
├── scripts/                      # CLI entry points
│   ├── run_traceguard.py         # Master evaluation CLI (--mode mock/model, --split, --auditkit)
│   ├── run_demo.py               # Interactive judge demonstration CLI (< 1s offline)
│   ├── run_curator.py            # CuratorKIT curation execution CLI
│   ├── run_circuit_experiment.py # CircuitKIT interpretability execution CLI
│   ├── validate_dataset.py       # Source dataset validator CLI
│   └── validate_curated_dataset.py # Curated dataset and checksum validator CLI
├── tests/                        # 42 test files (438 test items accounted for)
├── docs/                         # Research reports, reproducibility guides, and taxonomy specs
├── results/                      # Serialized evaluation summaries, CircuitKIT, and AuditKIT artifacts
└── reports/                      # Full technical audit documentation
```

---

## 2. Team Member Ownership & Deliverable Mapping

| Team Member | Subtree & Components Owned | File Mapping | Status |
| :--- | :--- | :--- | :---: |
| **Member 1** *(AI & Research Lead)* | Model loader, generation settings, strict JSON parser, prompt builder, SafeTune calibration, model smoke test | `traceguard/models/`<br>`traceguard/experiments/safetune_*`<br>`traceguard/configs/model_config.yaml` | Implemented; real model inference pending Kaggle execution |
| **Member 2** *(Data & Interpretability Lead)* | Attack/benign datasets, schema, taxonomy, CuratorKIT pipeline, CircuitKIT experiments, AuditKIT adapter, evaluation CLI | `traceguard/data/`<br>`traceguard/data/curator/`<br>`traceguard/experiments/circuit_*`<br>`traceguard/experiments/auditkit_*`<br>`scripts/run_traceguard.py` | Complete; 60 episodes validated; CuratorKIT and AuditKIT serialized |
| **Member 3** *(Runtime & Security Gateway Lead)* | Sandbox tools, ProvenanceTracker, AuthorizationLedger, SafetyGateway, EpisodeRunner, userinput isolation, demo | `traceguard/runtime/`<br>`scripts/run_demo.py`<br>`docs/MEMBER3_RUNTIME_FIXES.md` | Complete; all 4 runtime fixes and 21 regression tests verified |

---

## 3. CLI Entry Points & Execution Surface

1. **Master Evaluation CLI:**
   - Command: `python scripts/run_traceguard.py --mode mock --split both --auditkit`
   - Purpose: Evaluates all 6 configurations across DEV and TEST splits; outputs `results/evaluation/traceguard_master_summary.json` and AuditKIT exports.
2. **Interactive Judge Demonstration:**
   - Command: `python scripts/run_demo.py`
   - Purpose: 3-act offline walkthrough in < 1 second demonstrating attack interception, benign utility preservation, and the E2a vs E2b provenance difference.
3. **Dataset Quality Gate CLI:**
   - Command: `python scripts/validate_dataset.py`
   - Purpose: Validates all 60 original episodes across 10 structural and split-hygiene checks.
4. **Curated Dataset & Checksum Validator:**
   - Command: `python scripts/validate_curated_dataset.py`
   - Purpose: Validates 60 curated episodes and 18 cryptographic SHA-256 digests in `checksums.txt`.
5. **CuratorKIT Pipeline Runner:**
   - Command: `python scripts/run_curator.py`
   - Purpose: Runs deduplication, quality gating, manifests, and dataset cards.
6. **CircuitKIT Interpretability Runner:**
   - Command: `python scripts/run_circuit_experiment.py`
   - Purpose: Runs contrastive prompt processing, discovery, and faithfulness evaluation.

---

## 4. Interface Compatibility & Gap Audit

- **Tool Name Aliasing:** The team brief mentioned `search_notes`/`read_note`/`write_note` while the registry implemented `retrieve_notes`/`save_note`. `MockToolExecutor` now provides backwards-compatible aliases so either invocation works seamlessly.
- **Argument Parameter Aliasing:** Supported aliases include `doc_id` / `document_id`, `path` / `file_handle`, and `to` / `recipient`.
- **Recipient Security:** Added explicit checking for additional recipients (`cc`, `bcc`) in the Safety Gateway to enforce Scenario G10.
- **No Orphaned or Conflicting Code:** All modules compile and import cleanly without circular dependencies.
