# TraceGuard — Member 1 components (Phase 2)

Model integration and smoke testing for the Lexsi Labs AI Safety & Alignment
Hackathon entry **TraceGuard**. This subtree is Member-1-owned; the provenance
runtime/gateway (Member 3) and dataset curation (Member 2) live elsewhere.

## Layout

```
traceguard/
  models/            loader, prompt builder, STRICT JSON parser, generation, mock backend
  experiments/       T01-T10 smoke runner, deterministic scoring, manifests
  configs/           model pins, tool schemas, smoke tasks, experiment stub
tests/               unit + deterministic mock + tiny-model integration tests
results/             experiment artifacts (raw outputs / results / manifests / logs)
docs/                Phase 1 inspection report, Phase 2 report
```

## Setup (Python ≥ 3.10; SafeTune in Phase 3 will need ≥ 3.12)

```bash
python3 -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements/requirements-base.txt
# CPU-only torch:
pip install "torch==2.7.1" --index-url https://download.pytorch.org/whl/cpu
```

## Track A — sandbox/CI infrastructure check (no GPU, no gated access)

```bash
python -m pytest tests/ -q                              # 56 tests
python -m traceguard.experiments.smoke_test --backend mock \
  --mock-script tests/fixtures/mock_script_valid.jsonl \
  --out results/smoke/mock-valid/                       # exit 0 = harness OK
python -m traceguard.experiments.smoke_test --model sandbox_probe \
  --out results/smoke/tiny-random-gpt2/                 # exit 2 expected (random weights)
```

Track A validates the harness only. It is never counted as model success.

## Track B — real Tiny Aya smoke test (Colab or ≥8 GB RAM machine)

1. Accept the license at <https://huggingface.co/CohereLabs/tiny-aya-global>
   (gated, CC-BY-NC) with your HF account.
2. Provide the token via environment/Colab Secrets — **never commit it**:
   ```bash
   export HF_TOKEN=...          # Colab: userdata.get("HF_TOKEN")
   ```
3. Run (revisions are pinned in `traceguard/configs/model_config.yaml`):
   ```bash
   python -m traceguard.experiments.smoke_test --model primary \
     --out results/smoke/tiny-aya-global/
   # only if the gate fails (<8/10 or any critical safety failure):
   python -m traceguard.experiments.smoke_test --model fallback --load-in-4bit \
     --out results/smoke/aya-expanse-8b/
   ```
   Dtype `auto` is hardware-aware (review patch P1): FP16 on T4-class GPUs
   (compute capability < 8.0, incl. the 4-bit compute dtype), BF16 only where
   natively supported (Ampere+), FP32 on CPU. The resolved choice is recorded
   in each run's `manifest.json`.

Acceptance gate (fixed in config, not CLI-overridable): **≥ 8/10 tasks passed
AND zero critical safety failures**. Exit codes: 0 accepted, 2 not accepted,
1 infrastructure error. Artifacts per run: `raw_outputs.jsonl`,
`results.json`, `manifest.json`, `errors.log`.

## Phase 3 — SafeTune (isolated Python 3.12 environment)

SafeTune requires Python ≥ 3.12; Phase 2 runs on 3.11. Keep the environments
separate (pinned lists in `requirements/`):

```bash
pip install uv && uv python install 3.12
uv venv --python 3.12 .venv-safetune
uv pip install --python .venv-safetune/bin/python "torch==2.7.1" \
    --index-url https://download.pytorch.org/whl/cpu
uv pip install --python .venv-safetune/bin/python -r requirements/requirements-safetune-py312.txt
```

Track A (sandbox mechanics, ungated tiny model — no behavioral claims):

```bash
.venv-safetune/bin/python scripts/inspect_safetune_api.py --out results/safetune/api_report.json
.venv-safetune/bin/python -m pytest tests/ -q        # incl. tests/test_safetune_compat.py
WANDB_MODE=disabled .venv-safetune/bin/python -m traceguard.experiments.safetune_compat \
    --model sandbox_probe --quick --out results/safetune/probe-tiny-random-gpt2/
```

Track C (Colab, REAL Tiny Aya — run separately from Track B, keep artifacts apart):

```bash
pip install safetune==0.1.10            # Colab ships Python 3.12; verify with python -V
# requires license acceptance + HF_TOKEN (same as Track B)
WANDB_MODE=disabled python -m traceguard.experiments.safetune_compat \
    --model primary --out results/safetune/probe-tiny-aya-global/
# only after the probe is compatible AND Track B results are in:
WANDB_MODE=disabled python -m traceguard.experiments.safetune_calibration \
    --model primary --strengths 1,5,10,20 --max-new-tokens 128 \
    --out results/safetune/calibration-tiny-aya-global/
```

Calibration data hygiene is enforced in code: every input line must carry
`"split": "dev"`; anything else raises `HeldOutDataError`. The current
contrast/eval files are Member-1 scaffold placeholders
(`provenance: member1_scaffold_v1`) until Member 2's CuratorKIT dev episodes
replace them.

## Integrity rules encoded here

- Greedy decoding only (`do_sample=False` enforced by `GenerationSettings`).
- The parser never repairs invalid output; failures are recorded verbatim.
- Parse failures are scored as task failures, never as critical safety failures.
- Prompts longer than the model context fail explicitly (`prompt_exceeds_context`);
  inputs are never silently truncated.
- Results are measured, never fabricated; a failing model is reported as failing.
- `SteeredBackend` refuses to run (raises) when safetune is missing — it never
  silently substitutes unsteered generation.
- SafeTune calibration reads development data only; the loader rejects any
  non-dev split with `HeldOutDataError`.
- SafeTune API usage is verified against the installed package
  (`results/safetune/api_report.json`), not the README.
