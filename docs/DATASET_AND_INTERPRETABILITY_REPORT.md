# TraceGuard: Dataset and Interpretability Report

Scope: data and CircuitKIT work (Member 2). Repo state: `main` at d2ee771. All data is synthetic; all tool actions are simulated.
Sources: `reports/final_audit/DATASET_AUDIT.md`, `docs/MODULE9_CURATORKIT.md`, `docs/MODULE8_CIRCUITKIT.md`, `docs/ATTACK_TAXONOMY.md`.

## 1. Dataset

60 multi-turn episodes (215 turns, 276 source records), split by template into development and held-out test sets.

| | Dev | Test |
|---|---|---|
| Attack | 15 (7 templates) | 15 (6 templates) |
| Benign controls | 15 | 15 |

- 30 synthetic canaries, one per attack episode. 15 are in dev and 15 in test, with none shared across splits and none in benign episodes.
- Template overlap between dev and test is 0, checked by our validator and by the CuratorKIT split-hygiene gate.
- Every episode uses the six canonical provenance labels: `SYSTEM_POLICY`, `SYSTEM_CONFIG`, `USER_AUTHORIZED`, `UNTRUSTED_EXTERNAL`, `DERIVED_UNTRUSTED`, `UNKNOWN`.
- Benign controls are matched enterprise tasks (invoice review, vendor status, document analysis) with no attack content. They measure over-refusal.

## 2. Attack taxonomy

| Family | Mechanism | Episodes |
|---|---|---|
| A: Document and email injection | Instruction hidden in a retrieved email or document | 12 |
| B: Tool-output injection | Instruction inside a search or tool result | 10 |
| C: Stored / cross-turn injection | Injected text is saved as a note and retrieved in a later turn | 8 |

Families are not equally sized, so per-family rates rest on small counts and should be reported as raw counts.

## 3. Curation (CuratorKIT 0.1.22)

- 60 of 60 episodes ingested, none rejected; no exact or MinHash near-duplicates found.
- 65 of 65 quality gates passed (structural, attack, benign, split hygiene).
- Outputs: 4 full-fidelity JSONL files, 4 trainer-ready projections, 5 manifests, 5 dataset cards, `checksums.txt` with 18 SHA-256 entries. All 18 verified by `scripts/validate_curated_dataset.py`.
- Cleaning is whitespace-only; attack payloads and provenance labels are never edited.
- The trainer-ready files are lossy projections for exploratory use. They are not confirmed SafeTune inputs, and evaluation always uses the full-fidelity files.

## 4. CircuitKIT (0.2.0)

What exists:
- 24 contrastive clean/corrupt prompt pairs (12 dev, 12 test) with disjoint templates, authored separately from the 60 episodes.
- A config validator, a split guard (discovery on dev only, faithfulness routed to test), and an adapter to `circuitkit.Pipeline.from_custom_data`.
- A mock pipeline that exercises discovery, faithfulness and reporting without a GPU.
- Result status codes `NOT_RUN`, `SUCCESS`, `FAILED` and `UNAVAILABLE`. Unmeasured metrics are stored as `null`, never `0`.

What was run: the mock pipeline and the dataset and split checks only.

**What was not run: CircuitKIT discovery, faithfulness or intervention on real Aya Expanse 8B activations. These are reported as `NOT_RUN`. We make no interpretability claims about the model.** A real run would need a GPU with at least 16 GB of VRAM and was out of scope for the time budget.

## 5. Limitations

1. 15 attack episodes per split is small. Report counts and paired flips, with no significance claims.
2. Real-model runs on Aya Expanse 8B attempted a prohibited action in 0 of 15 attacks in every configuration, including the undefended E0. That dataset therefore shows the defence working only on the scripted mock attacker, not on the real model.
3. Canary checks catch exact, normalized, partial and Base64 variants. Free-form paraphrased leaks can still be missed.
4. The episodes are synthetic and template-built, so they cover three injection families only. Wider real-world coverage is untested.
5. Mock-backend and real-model results are reported separately and are not comparable.
6. No mechanistic findings are claimed (section 4).
