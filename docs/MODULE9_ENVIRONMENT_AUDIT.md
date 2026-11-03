# TraceGuard Module 9: Environment and CuratorKIT Dependency Audit

**Audit Date:** 2026-11-03  
**Auditor:** Member 2 — Data & Interpretability Lead  
**Operating System:** Windows 11 (AMD64)  
**Project Path:** `C:\Users\Kanch\Projects\TRACEGUARD`  

---

## 1. Environment Overview

| Parameter | Observed Value | Status |
| :--- | :--- | :---: |
| **Python Version** | `3.13.14 (tags/v3.13.14:fd17997, Jun 10 2026, 13:03:48) [MSC v.1944 64 bit (AMD64)]` | ✅ Supported |
| **Python Executable** | `C:\Users\Kanch\AppData\Local\Programs\Python\Python313\python.exe` | ✅ Verified |
| **Virtual Environment** | System / user Python environment | ✅ Ready |
| **CuratorKIT Status** | Installed: `curatorkit 0.1.22` | ✅ Verified |
| **CuratorKIT Source Path**| `C:\Users\Kanch\AppData\Local\Programs\Python\Python313\Lib\site-packages\curatorkit` | ✅ Verified |

---

## 2. Relevant Dependency Inventory

| Package | Installed Version | Required by CuratorKIT | Compatibility Assessment |
| :--- | :--- | :--- | :---: |
| `curatorkit` | `0.1.22` | Package under audit | ✅ Installed |
| `pydantic` | `2.11.7` | `>=2.7` | ✅ Compatible |
| `pydantic-core` | `2.33.2` | Core dependency | ✅ Compatible |
| `typer` | `0.27.0` | `>=0.12` | ✅ Compatible |
| `pyyaml` | `6.0.3` | `>=6.0` | ✅ Compatible |
| `rich` | `15.0.0` | `>=13.8.0` | ✅ Compatible |
| `tqdm` | `4.70.1` | `>=4.66` | ✅ Compatible |
| `circuitkit` | `0.2.0` | Module 8 peer dependency | ✅ No conflict |
| `torch` | `2.14.0+cpu` | Core PyTorch | ✅ No conflict |
| `datasets` | `5.1.0` | HuggingFace datasets | ✅ Compatible |

### Dependency Conflict Audit
- **Zero Conflicts Detected:** The existing environment's versions of `pydantic`, `typer`, `pyyaml`, `rich`, and `tqdm` completely satisfy `curatorkit` 0.1.22 requirements.
- No existing packages were downgraded or broken during installation.

---

## 3. Verified CuratorKIT APIs and Signatures

Every API listed below was verified directly against the installed package in `site-packages/curatorkit`:

### 3.1. Core Pipeline & Configuration
- **`curatorkit.Curator`**:
  - `__init__(self, config: CuratorConfig) -> None`
  - `run(self) -> CuratorResult`: Synchronous execution returning `CuratorResult`.
  - `dry_run(self) -> dict[str, Any]`: Pipeline dry-run inspection without disk writes.
  - `run_async(self) -> Coroutine[Any, Any, CuratorResult]`: Asynchronous execution.
- **`curatorkit.CuratorConfig`**:
  - Configures dataset paths (`dataset`), deduplication (`dedup="exact" | "minhash"`), cleaning (`clean=True`), export formats (`export_formats`), output directory (`output_dir`), schema gates (`schema_gate`), and MinHash parameters (`minhash_threshold`, `minhash_ngram`, `minhash_num_perm`, `minhash_seed`).
- **`curatorkit.CuratorResult`**:
  - Attributes: `passed: list[DataSample]`, `rejected: list[RejectedSample]`, `stage_counts: dict[str, dict[str, int]]`, `output_dir: Path`, `wall_clock_seconds: float`, `diagnostics: Any`.
  - Methods: `summary() -> str`, `print_summary() -> None`, `push_to_hub(...)`, `sample(n=3)`.

### 3.2. Data Schemas
- **`curatorkit.schema.DataSample`**:
  - Fields: `id: str`, `source_uri: str | None`, `instruction: str | None`, `input: str | None`, `output: str | None`, `chosen: str | None`, `rejected: str | None`, `label: str | None`, `responses: list | None`, `reward_scores: list | None`, `task_type: str | None`, `metadata: dict[str, Any]`, `provenance_chain: list[ProvenanceRecord]`.
- **`curatorkit.schema.RejectedSample`**:
  - Fields: `sample: DataSample`, `rejection_reason: str`, `step_name: str`, `failure_diagnosis: Any`, `metadata: dict[str, Any]`.
- **`curatorkit.schema.ProvenanceRecord`**:
  - Fields: `step_name: str`, `step_version: str`, `timestamp: datetime`, `config_hash: str`, `notes: dict[str, Any]`.

### 3.3. Deduplication & Cleaning Normalizers
- **`curatorkit.normalizers.dedup.ExactDeduplicator`**:
  - `__init__(self, ignore_for_dedup: list[str] | None = None) -> None`
  - `run(self, samples: list[DataSample]) -> list[DataSample]`
- **`curatorkit.normalizers.dedup.MinHashDeduplicator`**:
  - `__init__(self, threshold: float = 0.85, ngram: int = 3, num_perm: int = 128, seed: int = 42, bands: int | None = None, rows: int | None = None, ignore_for_dedup: list[str] | None = None) -> None`
  - `run(self, samples: list[DataSample]) -> list[DataSample]`
- **`curatorkit.normalizers.clean.TextCleaner`**:
  - `__init__(self, transforms: dict[str, bool] | None = None, fields: list[str] | None = None) -> None`
  - `run(self, samples: list[DataSample]) -> list[DataSample]`

### 3.4. Manifest & Dataset Card Generation
- **`curatorkit.manifest.ProvenanceManifest`**:
  - `__init__(self, result: PipelineResult, pipeline_config_hash: str = "unknown", output_dir: Path | None = None, provenance: dict[str, Any] | None = None) -> None`
  - `build(self) -> dict[str, object]`
  - `write(self) -> Path`: Writes `manifest.json` and `PROVENANCE_FILE`.
  - `write_rejected_sidecar(self) -> Path`: Writes `rejected.jsonl`.
  - `write_checksums(self, output_files: list[Path]) -> Path`: Writes `checksums.txt`.
- **`curatorkit.manifest.DatasetCardGenerator`**:
  - `generate(self, manifest: dict[str, object], output_dir: Path, pipeline_name: str = "curatorkit_pipeline", write_readme: bool = True) -> Path`: Renders and writes `dataset_card.md`.
- **`curatorkit.manifest._file_sha256(path: Path) -> str`**: Calculates SHA-256 for a file.

---

## 4. Installation Steps Performed

1. Initial inspection revealed `curatorkit` was not present in the global environment.
2. Verified on PyPI that `curatorkit` (version `0.1.22`) is published by Lexsi Labs (`lexsi.ai`) as an open-source library for data curation and post-training pipelines.
3. Executed `pip install curatorkit` which installed `curatorkit-0.1.22-py3-none-any.whl`.
4. All dependencies (`pydantic`, `typer`, `pyyaml`, `rich`, `tqdm`) were already pre-satisfied; no existing project libraries were replaced or disturbed.

---

## 5. Architectural Adapter Strategy: CuratorKIT + TraceGuard

CuratorKIT is designed for generic LLM datasets (`DataSample` with instruction/input/output).  
TraceGuard represents multi-turn indirect prompt injection episodes containing:
- Multi-turn conversation graphs (`turns` with `provenance_source`, `tool_call`, `tool_output`).
- Source records with trust labels (`SYSTEM_POLICY`, `USER_AUTHORIZED`, `UNTRUSTED_EXTERNAL`, `DERIVED_UNTRUSTED`).
- Synthetic canaries (`CanarySpec`) tracking data leakage.
- Strict attack family taxonomy (`family_a`, `family_b`, `family_c`, `benign`).
- Disjoint template assignment for DEV and TEST.

### Adapter Integration:
1. **Ingestion & Representation:**
   - Ingest JSONL episodes using TraceGuard's strict `Episode` schema.
   - Project episodes into `curatorkit.schema.DataSample` carrying the complete episode in `metadata["episode"]` and turn tracking in `provenance_chain`.
2. **Deduplication:**
   - Native `curatorkit.normalizers.dedup.ExactDeduplicator` and `MinHashDeduplicator` attribute duplicates across episode IDs, canonical texts, and normalized conversation turns.
3. **Quality Gates:**
   - TraceGuard-specific security quality gates enforce structural integrity, attack taxonomy compliance, canary uniqueness, and template split isolation.
4. **Manifests & Dataset Cards:**
   - Use `curatorkit.manifest.ProvenanceManifest` and `curatorkit.manifest.DatasetCardGenerator` combined with TraceGuard's provenance and security metrics to generate deterministic manifests (`manifest.json`), checksums (`checksums.txt`), and comprehensive dataset cards (`dataset_card.md`).
5. **Trainer-Ready & Full-Fidelity Exports:**
   - Canonical full-fidelity JSONL exports preserved in `traceguard/data/curated/`.
   - Downstream trainer-ready projections (e.g. SFT/ShareGPT conversation format) exported with full provenance tracking.

---

## 6. Environment Readiness Verdict

**Verdict:** **READY FOR IMPLEMENTATION (PASS)**  
- CuratorKIT 0.1.22 is fully verified and functional in the local environment.
- Zero package conflicts detected.
- All test runners and dependencies are operating normally.
