# TraceGuard Environment & Dependency Audit

**Project:** TraceGuard — Multi-Turn Indirect Prompt Injection Auditing and Defense for AI Agents  
**Date:** November 2026  
**Auditor:** Senior Python & Systems Auditor  

---

## 1. Environment Overview

| System Attribute | Verified Value | Operational Status |
| :--- | :--- | :---: |
| **Operating System** | Windows 11 Home AMD64 (build 10.0.26300) | Validated |
| **Python Runtime** | Python 3.13.14 (v3.13.14:824b70c) | Validated |
| **PyTorch Version** | 2.14.0+cpu (CPU execution, no GPU required locally) | Validated |
| **Transformers** | 5.22.1 (satisfies SafeTune pin `>=5.15,<6`) | Validated |
| **CuratorKIT** | 0.1.22 (Lexsi Labs Data Curation Toolkit) | Validated |
| **CircuitKIT** | 0.2.0 (Lexsi Labs Mechanistic Interpretability) | Validated |
| **AuditKIT** | 1.1.3 (Lexsi Labs Agent Evaluation Platform) | Validated |
| **Accelerate** | 1.15.0 (Hugging Face Model Acceleration) | Validated |
| **Datasets** | 5.1.0 (Hugging Face Datasets) | Validated |
| **PyTest** | 8.4.2 (Automated Test Runner) | Validated |

---

## 2. Dependency Specification Files

The repository maintains two explicit dependency files:

### A. Base Runtime Requirements (`requirements/requirements-base.txt`)
- Pinned from Member 1 baseline: `torch==2.7.1` (or local CPU equivalent), `transformers==5.22.1`, `tokenizers==0.23.3`, `huggingface-hub==2.4.0`, `safetensors==0.8.0`, `accelerate==1.15.0`, `numpy==2.4.6`, `PyYAML==6.0.3`, `regex==2026.9.29`, `pytest==9.2.0`.
- All base imports execute cleanly under Python 3.13 without deprecation errors or syntax warnings.

### B. SafeTune Requirements (`requirements/requirements-safetune-py312.txt`)
- Requires isolated environment with `Python >= 3.12`.
- Pins: `safetune==0.1.10`, `torch==2.7.1`, `transformers==5.22.1`, `peft==0.21.2`, `trl==1.14.2`, `bitsandbytes==0.50.2`, `datasets==5.1.0`, `lm-eval==0.4.13`, `wandb==0.31.0`.
- Runtime isolation: The SafeTune split guard and compatibility test correctly detect the active runtime and skip live execution if SafeTune is not installed, preventing crashes.

---

## 3. Circular Import & Syntax Compilation Audit

All Python source files across `traceguard/`, `scripts/`, and `tests/` were compiled and imported systematically:
```powershell
python -m compileall traceguard/ scripts/ tests/
```
**Result:** 100% of files compiled cleanly with exit code 0. Zero syntax errors, zero circular imports, and zero missing module errors.

---

## 4. Platform-Specific Assumptions & Sandboxing

1. **Path Resolution:** All path resolutions use `pathlib.Path` with `REPO_ROOT` resolution, eliminating hardcoded POSIX or Windows slash issues.
2. **Deterministic Offline Execution:** All local tests and evaluation runs execute against simulated in-memory mock handlers without requiring network access, external API keys, or GPU hardware.
3. **Line Endings:** Curated dataset files and manifests use normalized line endings verified by cryptographic SHA-256 checksums.
