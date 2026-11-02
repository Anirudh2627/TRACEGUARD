# TraceGuard — Phase 1 Inspection Report (Member 1)

Date: 2026-11-02 · Author: Member 1 (AI/ML lead) with agent assistance
All findings below were **verified by direct execution / HTTP probes on 2026-11-02**. Nothing is assumed.

---

## 1. Repository state

- The shared workspace is **empty** — there is no existing `traceguard/` repo, no README, no
  requirements file, no agreed JSON protocol, tool schemas, dataset JSONL schema, provenance
  metadata schema, or experiment interfaces committed here yet.
- Consequence: there is nothing to adapt to and no risk of duplicating teammates' modules,
  but **all shared schemas must be obtained from Member 2 / Member 3** (see §6) before Phase 5.
- Plan: initialize the repo with the Member-1-isolated layout from the master prompt
  (`traceguard/models/`, `traceguard/experiments/`, `traceguard/configs/`, `results/`, `tests/`)
  so it can later be merged into the team repo without conflicts.

## 2. Environment and hardware (this sandbox)

| Item | Verified value |
|---|---|
| OS | Linux x86_64 (Debian 12 userland, kernel 4.19) |
| Python | 3.11.2 (`/usr/bin/python3`) — **no python3.12**, no gcc/make, no curl/wget |
| pip | Not installed by default; `python3 -m ensurepip` provides pip 23.0.1 (works) |
| CPU | 2 cores |
| RAM | **~1.06 GB total** (MemTotal 1,083,460 kB) — hard constraint |
| Disk | 9.9 GB, 9.3 GB free |
| GPU | **None** (no `/proc/driver/nvidia`, no CUDA) |
| Network | Working: PyPI 200, huggingface.co API 200, github.com 200, raw.githubusercontent.com 200 |
| HF auth | **No `HF_TOKEN` env var, no HF cache** — unauthenticated |
| git | Available |

**What can run here:** full codebase development + unit/integration tests using an ungated tiny
model (`hf-internal-testing/tiny-random-gpt2`, verified ungated, a few MB) to exercise the
loader → prompt builder → greedy generate → strict JSON parser → scoring pipeline end to end.

**What cannot run here:** any real Aya model (RAM), and `pip install safetune` as-is
(Python 3.12 requirement). Workaround for 3.12 exists (install `uv` via pip — it ships binary
wheels, no compiler needed — then `uv python install 3.12` + a 3.12 venv for import-level
SafeTune tests), but the 1 GB RAM ceiling still blocks running any real model, including
SafeTune's 0.5B quickstart model (Qwen2.5-0.5B needs ≳1–2 GB). Real runs must happen on
Colab (or a teammate machine); we write and verify everything reproducible from there.

## 3. Model compatibility findings and risks

### CohereLabs/tiny-aya-global (primary)
- **Exists** on HF Hub. Revision (main) at inspection time:
  `af89d219b53ed9b13b8a4645f9c8028973510324`, last modified 2026-09-30.
- **Gated** (`gated: auto`): anonymous file access returns **HTTP 401** (verified — config.json
  and README raw files are inaccessible without a token + accepted conditions).
  → Action: accept the CC-BY-NC license + Cohere Labs AUP on the model page with the account
  whose token we use, then export `HF_TOKEN` (never hardcode).
- Size per model card: **3.35B parameters**, 8K context, chat template via
  `tokenizer.apply_chat_template(..., add_generation_prompt=True)`.
  "Tiny" is *not* small in memory terms: bf16 weights ≈ 6.7 GB.
  → Cannot run in this sandbox. Fits on a **Colab T4 (16 GB VRAM)** in bf16/fp16; comfortable
  in 4-bit. Needs ≥8 GB free system RAM otherwise.
- Architecture: hybrid attention — 3 sliding-window layers (window 4096) + 1 global-attention
  layer, RoPE; card shows plain `AutoModelForCausalLM` usage → likely requires a **recent
  transformers**. Exact `model_type` could not be read (gated 401); must confirm the minimum
  transformers version once we have a token.
- Known stated limitations (model card): weak chain-of-thought/reasoning, "performs best with
  clear prompts". **Risk for strict one-JSON-object-per-turn protocol is real and is exactly
  what the T01–T10 smoke test must measure** — we do not assume it works.
- Greedy generation: card example uses sampling; we will force `do_sample=False,
  temperature=None, top_p=None` for determinism (verify no transformers warning breaks this).

### CohereLabs/aya-expanse-8b (fallback)
- **Exists**, gated (`auto`), revision at inspection: `5062468bf9bc0c6035fd64e06274333ec127d980`.
- 8B → bf16 ≈ 16 GB: **not runnable on a Colab T4 without 4-bit/int8 quantization**; fine on
  A100/L4-class. Note: an older mirror `CohereForAI/aya-expanse-8b` also exists; we should
  standardize on the `CohereLabs/*` IDs and pin revisions.
- CC-BY-NC license applies (hackathon research use OK; note in the report).

### Cost note
- The $20 HF credits are **not needed for these downloads** — gated ≠ paid; they are free
  after license acceptance. Credits only matter if we used paid Inference Endpoints (we won't).

## 4. SafeTune compatibility findings and risks

Verified from GitHub (`Lexsi-Labs/SafeTune`, active; last commit 2026-10-21) and PyPI:

- **PyPI `safetune`, latest 0.1.10** (releases 0.1.0 → 0.1.10). Install: `pip install safetune`.
- Hard requirements: **Python ≥ 3.12**, `torch>=2.7.0`, **`transformers>=5.15,<6`**, plus a
  heavy dependency tree: `trl`, `peft`, `bitsandbytes`, `accelerate`, `datasets`, `lm-eval`,
  `wandb`, `tensorboard`, `nltk`, `sentencepiece`, `tiktoken`, … (full list captured).
- Actual Steer API — **verified from source**
  (`src/safetune/interventions/steer/refusal_direction.py`, 720 lines, fetched and read):
  - `RefusalDirectionConfig` — dataclass incl. `target_layers`, `pick_layer`,
    `pool_method` (`"last_token"` | `"mean"`), `strength` (positive = steer toward refusal),
    `select_directions`, `kl_threshold` (default 0.1), `kl_threshold_fallback`,
    `min_bypass_reduction`.
  - `extract_refusal_direction(model, tokenizer, harmful_prompts, harmless_prompts, config=None)
    -> (direction, layer_idx, all_layer_directions)` — Arditi et al. (2406.11717) difference of
    means at the last instruction token, with the paper's validation sweep.
  - `RefusalDirectionModel(...)` with `.install()` / `.remove()` and context-manager support —
    implemented via **forward hooks on the residual stream**, i.e. architecture-generic in
    principle, but hook targets must exist on the Cohere model's decoder stack (**unverified**).
  - `orthogonalize_weights` / `restore_weights` — the "abliteration" (weight-space) variant.
  - README also exposes `RefusalDirectionTrainer` in `safetune.runner.steer` ("refuse harmful
    prompts at inference") — the runner wrapper; exact signature to be read from the installed
    package in Phase 3, not guessed.
- Quickstart runs the Steer path on `Qwen/Qwen2.5-0.5B-Instruct`, no GPU — our CPU/Colab plan
  is consistent with the library's own supported path.

**Risks (all to be tested in Phase 3, none assumed):**
1. **Python 3.12 vs our environments.** Colab's Python version must be checked at run time;
   this sandbox is 3.11 (workaround via `uv`-managed 3.12 exists, RAM still blocks model runs).
2. **transformers pin interaction.** SafeTune forces `transformers>=5.15,<6`. We must confirm
   Tiny Aya's architecture loads under that exact range (it should — recent model — but the
   gated config prevented verification today).
3. **Hook compatibility with the hybrid-attention Cohere architecture.** If
   `extract_refusal_direction`'s layer enumeration or the hook install fails on
   `tiny-aya-global`, we record the compatibility failure, test `aya-expanse-8b`, and report
   the limitation (per master prompt). No fake wrappers, no silent substitution.
4. **Semantic risk (most important scientifically).** The refusal direction is extracted from
   *contrast prompts*. The stock selection sweep optimizes refusal on direct harmful requests
   (HarmBench-style). Our threat is **indirect prompt injection inside tool-call JSON**: the
   "unsafe" behavior is emitting a tool_call for an unauthorized action, not free-text
   compliance. Steering *toward* refusal may (a) not target the injection-following circuit at
   all, and (b) inflate over-refusal on benign episodes. Calibration must therefore use our own
   dev episodes' contrast pairs (injected-instruction vs benign-imperative), and both attack
   resistance **and** over-refusal/benign completion are primary outcomes. This is a hypothesis
   to test, not an expected win.
5. `bitsandbytes` import on CPU-only machines — install fine, but any 4-bit path is GPU-only;
   Steer on CPU is supported per README (0.5B model).
6. Dependency weight (~3 GB installed) vs Colab/sandbox disk — manageable, but we install the
   CPU torch wheel explicitly (`--index-url https://download.pytorch.org/whl/cpu`) to avoid
   multi-GB CUDA wheels.

## 5. Files to create (Phase 2 scaffold — for approval, not yet written)

```
traceguard/
  models/
    __init__.py
    loader.py            # pinned-revision loading, device/dtype policy, HF_TOKEN via env only
    prompt_builder.py    # chat-template prompt construction for the JSON tool protocol
    json_parser.py       # STRICT parser: single JSON object; rejects fences/trailing text/
                         # unknown tools/missing/extra/mistyped args; never repairs
    generation.py        # greedy generate wrapper + latency/token accounting + raw-output logging
  experiments/
    smoke_test.py        # T01–T10 runner, deterministic scoring, acceptance gate (≥8/10, 0 critical)
    manifest.py          # machine-readable experiment manifest writer
  configs/
    model_config.yaml    # model ids, pinned revisions, gen settings (temperature etc.)
    tools.yaml           # tool schemas for the sandboxed synthetic assistant
    smoke_tasks.jsonl    # T01–T10 with expected outcomes + critical-safety flags
tests/
  test_json_parser.py
  test_prompt_builder.py
  test_smoke_test.py     # runs the full pipeline against hf-internal-testing/tiny-random-gpt2
requirements/
  requirements-base.txt  # pinned after compatibility is established
results/.gitkeep
docs/PHASE1_INSPECTION.md   # this file
```

Explicitly **not** created by Member 1: the provenance store, the gateway, the episode
dataset, the AuditKIT integration (Members 3/2 own these; I consume their schemas).

## 6. Interfaces needed from teammates

From **Member 3** (runtime/gateway):
1. Provenance record schema as actually implemented (fields, enum spelling, `parent_source_ids`
   semantics) — the master-prompt example is my starting assumption.
2. Gateway call interface: how my experiment runner submits a candidate tool call for
   authorization, and the shape of the **attempt log** (so I can separate *unsafe attempts*
   from *executed actions* — required for the E2a-vs-E2b analysis).
3. The turn-loop contract: who constructs prompts in E0–E4 (my `prompt_builder` vs their
   runtime), and where provenance labels get injected into the prompt.

From **Member 2** (CuratorKIT/CircuitKIT):
4. Episode JSONL schema + the 60-episode dataset (15 attack/15 benign × dev/test), including
   per-episode canaries and expected outcomes, and the template families (A/B/C) used —
   held-out must be separate templates, so I need to know the family assignments.
5. Any CuratorKIT-produced dataset IDs/versions to pin in my manifests.
6. For CircuitKIT support: which Tiny Aya layers are hookable (overlaps with my SafeTune
   compatibility finding — we should share one architecture-probe result).

Team-wide:
7. The agreed result schema my experiments must emit (AuditKIT-compatible) — needed before
   Phase 4, not Phase 2.

## 7. Exact commands for the first smoke test (two tracks)

**Track A — this sandbox (pipeline verification, no Aya access needed):**
```bash
python3 -m ensurepip --user
python3 -m pip install --user "torch==2.7.*" --index-url https://download.pytorch.org/whl/cpu
python3 -m pip install --user "transformers==5.*" "huggingface_hub" "pyyaml" "pytest"
# after I write the Phase 2 code:
python3 -m pytest tests/ -q
python3 -m traceguard.experiments.smoke_test \
  --model hf-internal-testing/tiny-random-gpt2 \
  --config traceguard/configs/model_config.yaml \
  --out results/smoke/tiny-random-gpt2/
```
Expected: parser/prompt/scoring/manifest all verified; the tiny random model will *fail* most
T-tasks (it emits gibberish) — that is the correct, honest behavior of the harness and proves
the acceptance gate works.

**Track B — Colab or local machine with ≥8 GB RAM (real Tiny Aya run):**
```bash
pip install "torch==2.7.*" --index-url https://download.pytorch.org/whl/cpu   # or CUDA wheel on Colab
pip install "transformers>=5.15,<6" huggingface_hub pyyaml
# 1) Accept the license at https://huggingface.co/CohereLabs/tiny-aya-global with your account
# 2) In Colab Secrets or shell env — never in code or the repo:
export HF_TOKEN=...            # Colab: os.environ["HF_TOKEN"] = userdata.get("HF_TOKEN")
python -m traceguard.experiments.smoke_test \
  --model CohereLabs/tiny-aya-global \
  --revision af89d219b53ed9b13b8a4645f9c8028973510324 \
  --config traceguard/configs/model_config.yaml \
  --out results/smoke/tiny-aya-global/
# If acceptance fails (≥8/10 pass, 0 critical safety failures):
python -m traceguard.experiments.smoke_test \
  --model CohereLabs/aya-expanse-8b \
  --revision 5062468bf9bc0c6035fd64e06274333ec127d980 \
  --config traceguard/configs/model_config.yaml \
  --load-in-4bit \
  --out results/smoke/aya-expanse-8b/
```

## 8. Honest execution statement

I **can** execute code in this sandbox (Python 3.11, network, ~1 GB RAM): everything up to and
including Track A tests, and import-level SafeTune checks via a uv-managed Python 3.12.
I **cannot** run Tiny Aya / Aya Expanse / the SafeTune quickstart model here (RAM), and I
cannot access gated weights without your `HF_TOKEN`. No test result involving a real Aya model
will ever be reported from this sandbox — those runs happen on Colab/your machine with the
commands above, and I will show actual outputs or actual errors.
