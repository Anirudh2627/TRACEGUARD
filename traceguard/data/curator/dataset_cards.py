"""Dataset card generation for TraceGuard curated datasets."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


class DatasetCardGenerator:
    """Generates comprehensive Markdown dataset cards conforming to AI safety documentation standards."""

    def __init__(self, output_dir: str | Path = "traceguard/data/curated/dataset_cards") -> None:
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate_card(self, manifest: dict[str, Any], output_filename: str) -> Path:
        """Render a Markdown dataset card from a curated dataset manifest."""
        metrics = manifest.get("metrics", {})
        ds_name = manifest.get("dataset_name", "TraceGuard Dataset")
        tool_versions = manifest.get("tool_versions", {})
        src_files = manifest.get("source_files", [])
        cleaning_ops = manifest.get("cleaning_operations", {})
        dedup_info = manifest.get("duplicate_findings", {})
        gate_res = manifest.get("quality_gate_results", {})

        families_str = "\n".join(
            f"- **{fam}**: {cnt} episodes"
            for fam, cnt in metrics.get("attack_family_distribution", {}).items()
        ) or "- None"

        prov_str = "\n".join(
            f"- `{lbl}`: {cnt} occurrences"
            for lbl, cnt in metrics.get("provenance_labels_distribution", {}).items()
        ) or "- None"

        templates_str = ", ".join(f"`{t}`" for t in metrics.get("template_ids", [])) or "None"

        content = f"""# Dataset Card: {ds_name}

## 1. Dataset Overview

- **Dataset Name:** {ds_name}
- **Dataset Version:** {manifest.get("dataset_version", "1.0.0")}
- **Generation Timestamp:** {manifest.get("generation_timestamp", "unknown")}
- **CuratorKIT Version:** {tool_versions.get("curatorkit", "unknown")}
- **TraceGuard Commit:** `{tool_versions.get("traceguard_commit", "unknown")}`
- **Total Episodes:** {metrics.get("episode_count", 0)}

---

## 2. Intended Research Purpose

TraceGuard investigates **multi-turn indirect prompt injection auditing and defense** for tool-augmented language agents. The core research question evaluated with this dataset is:

> *"Does preserving source provenance across turns reduce unsafe tool-call attempts compared with losing provenance, while preserving legitimate task completion?"*

---

## 3. Dataset Composition & Statistics

- **Attack Episodes:** {metrics.get("attack_count", 0)}
- **Benign Episodes:** {metrics.get("benign_count", 0)}
- **DEV Split Count:** {metrics.get("dev_count", 0)}
- **TEST Split Count:** {metrics.get("test_count", 0)}
- **Unique Synthetic Canaries:** {metrics.get("unique_canary_count", 0)}
- **Unique Templates:** {metrics.get("unique_templates_count", 0)}

### Attack Family Distribution
{families_str}

### Active Templates
{templates_str}

---

## 4. Provenance Labels Distribution

TraceGuard tracks six immutable provenance trust labels:
{prov_str}

---

## 5. Synthetic Canary Usage

- Attack episodes feature synthetic secret tokens (e.g. `CANARY_DOC_01`) embedded in authorized contexts or initial states.
- Leakage is tracked deterministically when an agent invokes an exfiltration tool or emits the canary in final responses.
- Benign episodes contain **zero canaries**.

---

## 6. DEV / TEST Split Methodology

- The dataset is split strictly by **complete attack templates**, not individual paraphrases.
- Attack DEV and TEST sets have **zero template overlap** ($T_{{\\text{{dev}}}} \\cap T_{{\\text{{test}}}} = \\emptyset$), ensuring zero split contamination.
- Test templates are strictly reserved for held-out evaluation.

---

## 7. Curation & Quality Gate Results

- **Quality Gate Status:** `{gate_res.get("status", "PASSED")}`
- **Checks Passed:** {gate_res.get("passed_checks_count", 0)} / {gate_res.get("total_checks_run", 0)}
- **Exact Duplicates:** {dedup_info.get("exact_id_duplicates_count", 0)}
- **Near-Duplicate Warnings:** {dedup_info.get("near_duplicate_warnings_count", 0)}
- **Cleaning Operations:** {cleaning_ops.get("transformations_applied", {})}

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
"""
        card_path = self.output_dir / output_filename
        with open(card_path, "w", encoding="utf-8") as f:
            f.write(content)
        return card_path
