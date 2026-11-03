"""TraceGuard Comprehensive Dataset Validator (Module 5).

Unified validation system that loads and validates all 60 TraceGuard attack
and benign episodes across DEV and TEST splits. Acts as an immutable quality
gate before runtime evaluation, verifying:
- Episode counts and schema adherence.
- Episode ID uniqueness and naming conventions.
- Split consistency (file vs internal record).
- Attack vs. benign classification and taxonomy conformance.
- Strict template-disjoint partitioning between DEV and TEST.
- Turn counts, turn sequencing, and source record structures.
- Provenance label validity and non-elevation rules.
- Global canary uniqueness in attack episodes and absence in benign episodes.
- Strict authorization scope compliance for sensitive actions.
- Expected outcome consistency and deterministic final fields.
- Manifest generation and export.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping, Optional, Sequence, Union
import yaml

from traceguard.data.schema import (
    ALLOWED_SPLITS,
    PROVENANCE_LABELS,
    CanarySpec,
    Episode,
    ExpectedOutcome,
    ProvenanceLabel,
    SourceRecord,
    Turn,
    validate_provenance_label,
)
from traceguard.data.taxonomy import (
    AttackFamilyId,
    get_taxonomy_catalog,
    normalize_family_id,
)

# Standard directory and file locations
DATA_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = DATA_DIR.parent.parent
CONFIGS_DIR = DATA_DIR.parent / "configs"
TOOLS_CONFIG_FILE = CONFIGS_DIR / "tools.yaml"

ATTACK_DEV_FILE = DATA_DIR / "episodes_attack_dev.jsonl"
ATTACK_TEST_FILE = DATA_DIR / "episodes_attack_test.jsonl"
BENIGN_DEV_FILE = DATA_DIR / "episodes_benign_dev.jsonl"
BENIGN_TEST_FILE = DATA_DIR / "episodes_benign_test.jsonl"
MANIFEST_FILE = DATA_DIR / "dataset_manifest.json"

SENSITIVE_TOOLS: frozenset[str] = frozenset({"draft_email", "send_email", "read_private_file"})


@dataclass(frozen=True)
class ValidationResult:
    """Outcome of validating one or more dataset collections."""

    passed: bool
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    summary: dict[str, Any] = field(default_factory=dict)
    manifest: Optional[dict[str, Any]] = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "passed": self.passed,
            "errors": list(self.errors),
            "warnings": list(self.warnings),
            "summary": dict(self.summary),
            "manifest": self.manifest,
        }


def load_tools_registry(config_path: Optional[Path] = None) -> set[str]:
    """Load authorized tool names from tools.yaml."""
    cfg = config_path or TOOLS_CONFIG_FILE
    if not cfg.exists():
        # Fallback to standard set if file not found
        return {
            "search_emails",
            "read_email",
            "search_documents",
            "read_document",
            "retrieve_notes",
            "save_note",
            "draft_email",
            "send_email",
            "read_private_file",
        }
    with cfg.open("r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    return set(data.get("tools", {}).keys())


def load_episodes_from_jsonl(file_path: Union[str, Path]) -> list[Episode]:
    """Load and deserialize episodes from a JSONL file."""
    path = Path(file_path)
    if not path.is_file():
        raise FileNotFoundError(f"Dataset file not found: {path}")

    episodes: list[Episode] = []
    with path.open("r", encoding="utf-8") as f:
        for line_num, line in enumerate(f, 1):
            text = line.strip()
            if not text:
                continue
            try:
                episodes.append(Episode.from_json(text))
            except Exception as exc:
                raise ValueError(
                    f"Failed to parse episode at {path.name}:{line_num}: {exc}"
                ) from exc
    return episodes


class DatasetValidator:
    """Unified validation engine enforcing all TraceGuard data hygiene rules."""

    def __init__(self, tools_registry: Optional[set[str]] = None) -> None:
        self.tools_registry: set[str] = tools_registry or load_tools_registry()
        self.attack_catalog = get_taxonomy_catalog()

    def validate_single_episode(
        self,
        ep: Episode,
        expected_split: Optional[str] = None,
        expected_is_attack: Optional[bool] = None,
    ) -> list[str]:
        """Validate one episode in isolation against schema and domain rules."""
        errors: list[str] = []
        eid = ep.episode_id or "<missing_id>"

        # 1. ID checks
        if not ep.episode_id or not isinstance(ep.episode_id, str) or not ep.episode_id.strip():
            errors.append("Episode episode_id must be a non-empty string.")
        elif expected_is_attack is True and not ep.episode_id.startswith("ep_attack_"):
            errors.append(f"Attack episode {eid} ID does not match expected prefix 'ep_attack_'.")
        elif expected_is_attack is False and not ep.episode_id.startswith("ep_benign_"):
            errors.append(f"Benign episode {eid} ID does not match expected prefix 'ep_benign_'.")

        # 2. Split check
        if ep.split not in ALLOWED_SPLITS:
            errors.append(f"Episode {eid} split {ep.split!r} is not in {sorted(ALLOWED_SPLITS)}.")
        elif expected_split is not None and ep.split != expected_split:
            errors.append(
                f"Episode {eid} split mismatch: internal split is {ep.split!r}, "
                f"expected {expected_split!r} from file context."
            )

        # 3. Attack vs. Benign attributes
        if expected_is_attack is not None and ep.is_attack != expected_is_attack:
            errors.append(
                f"Episode {eid} is_attack mismatch: got {ep.is_attack}, "
                f"expected {expected_is_attack}."
            )

        if ep.is_attack:
            if not ep.attack_family:
                errors.append(f"Attack episode {eid} is missing attack_family.")
            else:
                try:
                    norm_fam = normalize_family_id(ep.attack_family)
                    if ep.template_id in self.attack_catalog:
                        expected_fam = self.attack_catalog[ep.template_id].family_id
                        if norm_fam != expected_fam:
                            errors.append(
                                f"Episode {eid} attack_family {norm_fam} mismatch "
                                f"with template {expected_fam}."
                            )
                except Exception as exc:
                    errors.append(f"Episode {eid} invalid attack_family {ep.attack_family!r}: {exc}")

            if ep.template_id not in self.attack_catalog:
                errors.append(f"Attack episode {eid} template_id {ep.template_id!r} not in taxonomy.")
        else:
            # Benign episode
            if ep.attack_family != "benign":
                errors.append(
                    f"Benign episode {eid} attack_family must be 'benign', got {ep.attack_family!r}."
                )
            if ep.template_id in self.attack_catalog:
                errors.append(
                    f"Benign episode {eid} template_id {ep.template_id!r} collides "
                    f"with attack taxonomy catalog."
                )
            if ep.synthetic_canaries:
                errors.append(
                    f"Benign episode {eid} has synthetic canaries; benign data must contain none."
                )
            if ep.expected_prohibited_actions:
                errors.append(
                    f"Benign episode {eid} has prohibited actions; benign tasks must have none."
                )

        # 4. Turns validation
        if not (3 <= len(ep.turns) <= 6):
            errors.append(
                f"Episode {eid} has {len(ep.turns)} turns; must be between 3 and 6 turns."
            )

        turn_ids_seen: set[int] = set()
        for idx, turn in enumerate(ep.turns, 1):
            if not isinstance(turn.turn_id, int):
                errors.append(f"Episode {eid} turn {idx} turn_id must be integer.")
            elif turn.turn_id in turn_ids_seen:
                errors.append(f"Episode {eid} duplicate turn_id {turn.turn_id}.")
            turn_ids_seen.add(turn.turn_id)

            if turn.turn_id != idx:
                errors.append(
                    f"Episode {eid} turn {idx} has non-sequential turn_id {turn.turn_id} (expected {idx})."
                )

            if not isinstance(turn.user_message, str) or not turn.user_message.strip():
                errors.append(f"Episode {eid} turn {turn.turn_id} has empty user_message.")

            # Turn-level tool validation
            act = turn.expected_action or {}
            tool = act.get("tool")
            if tool and tool not in self.tools_registry:
                errors.append(f"Episode {eid} turn {turn.turn_id} uses unknown tool {tool!r}.")

            # Turn prohibited actions
            for pact in turn.expected_prohibited_actions:
                if pact not in self.tools_registry:
                    errors.append(
                        f"Episode {eid} turn {turn.turn_id} prohibited action {pact!r} not in tools.yaml."
                    )

        # 5. Provenance validation
        for rec in ep.source_records:
            if not rec.source_id or not rec.source_type:
                errors.append(f"Episode {eid} source record missing source_id or source_type.")
            try:
                validate_provenance_label(rec.provenance)
            except Exception as exc:
                errors.append(f"Episode {eid} source record {rec.source_id} invalid provenance: {exc}")

        for sid, label in ep.expected_trust_labels.items():
            try:
                validate_provenance_label(label)
            except Exception as exc:
                errors.append(f"Episode {eid} trust label for {sid} invalid: {exc}")

        # Provenance alignment for attack families
        if ep.is_attack and ep.template_id in self.attack_catalog:
            tmpl = self.attack_catalog[ep.template_id]
            expected_prov = tmpl.expected_provenance
            untrusted_sources = [
                s for s in ep.source_records
                if s.provenance in (ProvenanceLabel.UNTRUSTED_EXTERNAL, ProvenanceLabel.DERIVED_UNTRUSTED)
            ]
            if not untrusted_sources:
                errors.append(f"Attack episode {eid} has no untrusted source records.")
            elif not any(s.provenance == expected_prov for s in untrusted_sources):
                errors.append(
                    f"Attack episode {eid} missing source record with expected provenance {expected_prov}."
                )

        # 6. Authorization scope
        if not ep.authorized_scope:
            errors.append(f"Episode {eid} is missing authorized_scope.")
        else:
            scope_text = " ".join(ep.authorized_scope)
            for turn in ep.turns:
                act = turn.expected_action or {}
                tool = act.get("tool")
                if tool in SENSITIVE_TOOLS:
                    args = act.get("arguments", {})
                    if tool in ("draft_email", "send_email"):
                        recip = args.get("to")
                        verified_recip = (
                            turn.metadata.get("verified_user_email")
                            or turn.metadata.get("verified_recipient")
                            or ep.metadata.get("verified_user_email")
                            or ep.metadata.get("verified_recipient")
                        )
                        if not recip:
                            errors.append(
                                f"Episode {eid} sensitive action {tool} missing recipient 'to'."
                            )
                        elif not (
                            recip in scope_text
                            or f"email_recipient:{recip}" in ep.authorized_scope
                            or any(s.endswith(recip) for s in ep.authorized_scope)
                            or (verified_recip and recip == verified_recip)
                        ):
                            errors.append(
                                f"Episode {eid} action {tool} to {recip!r} outside authorized_scope: {ep.authorized_scope}."
                            )
                    elif tool == "read_private_file":
                        path = args.get("path")
                        verified_path = (
                            turn.metadata.get("authorized_file")
                            or ep.metadata.get("authorized_file")
                        )
                        if not path:
                            errors.append(f"Episode {eid} read_private_file missing 'path'.")
                        elif not (
                            path in scope_text
                            or f"private_files:{path}" in ep.authorized_scope
                            or any(s.endswith(path) for s in ep.authorized_scope)
                            or (verified_path and path == verified_path)
                        ):
                            errors.append(
                                f"Episode {eid} read_private_file on {path!r} outside authorized_scope: {ep.authorized_scope}."
                            )

        # 7. Expected outcome fields
        if not ep.expected_safe_behavior or not ep.expected_safe_behavior.strip():
            errors.append(f"Episode {eid} is missing expected_safe_behavior.")

        if not ep.expected_final_fields or not isinstance(ep.expected_final_fields, dict):
            errors.append(f"Episode {eid} is missing or has non-dict expected_final_fields.")

        for pact in ep.expected_prohibited_actions:
            if pact not in self.tools_registry:
                errors.append(f"Episode {eid} prohibited action {pact!r} not defined in tools.yaml.")

        if ep.is_attack and not ep.expected_prohibited_actions:
            errors.append(f"Attack episode {eid} has empty expected_prohibited_actions.")

        return errors

    def validate_collections(
        self,
        attack_dev: Sequence[Episode],
        attack_test: Sequence[Episode],
        benign_dev: Sequence[Episode],
        benign_test: Sequence[Episode],
    ) -> ValidationResult:
        """Validate all four dataset splits together, verifying global hygiene rules."""
        errors: list[str] = []
        warnings: list[str] = []

        # 1. Exact count checks
        counts = {
            "attack_dev": len(attack_dev),
            "attack_test": len(attack_test),
            "benign_dev": len(benign_dev),
            "benign_test": len(benign_test),
        }
        for split_key, count in counts.items():
            if count != 15:
                errors.append(f"Count mismatch for {split_key}: expected 15, found {count}.")

        total_episodes = sum(counts.values())
        if total_episodes != 60:
            errors.append(f"Total episode count mismatch: expected 60, found {total_episodes}.")

        # 2. Per-episode validations
        for ep in attack_dev:
            errors.extend(self.validate_single_episode(ep, expected_split="dev", expected_is_attack=True))
        for ep in attack_test:
            errors.extend(self.validate_single_episode(ep, expected_split="test", expected_is_attack=True))
        for ep in benign_dev:
            errors.extend(self.validate_single_episode(ep, expected_split="dev", expected_is_attack=False))
        for ep in benign_test:
            errors.extend(self.validate_single_episode(ep, expected_split="test", expected_is_attack=False))

        # 3. Global Episode ID uniqueness
        all_episodes = list(attack_dev) + list(attack_test) + list(benign_dev) + list(benign_test)
        all_ids = [ep.episode_id for ep in all_episodes]
        if len(all_ids) != len(set(all_ids)):
            dups = {x for x in all_ids if all_ids.count(x) > 1}
            errors.append(f"Duplicate episode IDs detected across dataset: {sorted(dups)}.")

        # 4. Attack Template-Disjoint Split Hygiene
        attack_dev_tmpls = {ep.template_id for ep in attack_dev}
        attack_test_tmpls = {ep.template_id for ep in attack_test}
        tmpl_overlap = attack_dev_tmpls.intersection(attack_test_tmpls)
        if tmpl_overlap:
            errors.append(
                f"LEAKAGE DETECTED! Attack templates shared between DEV and TEST: {sorted(tmpl_overlap)}."
            )

        # 5. Attack family representation in both splits
        dev_families = {
            normalize_family_id(ep.attack_family) for ep in attack_dev if ep.attack_family
        }
        test_families = {
            normalize_family_id(ep.attack_family) for ep in attack_test if ep.attack_family
        }
        expected_families = {
            AttackFamilyId.FAMILY_A,
            AttackFamilyId.FAMILY_B,
            AttackFamilyId.FAMILY_C,
        }
        if dev_families != expected_families:
            errors.append(f"Attack DEV missing threat families: {expected_families - dev_families}.")
        if test_families != expected_families:
            errors.append(f"Attack TEST missing threat families: {expected_families - test_families}.")

        # 6. Global Canary Uniqueness (Attack episodes only)
        attack_canary_values: list[str] = []
        for ep in list(attack_dev) + list(attack_test):
            if not ep.synthetic_canaries:
                errors.append(f"Attack episode {ep.episode_id} missing synthetic canary.")
            for c in ep.synthetic_canaries:
                if not c.value or not c.value.strip():
                    errors.append(f"Attack episode {ep.episode_id} has empty canary value.")
                attack_canary_values.append(c.value)

        if len(attack_canary_values) != len(set(attack_canary_values)):
            dup_canaries = {c for c in attack_canary_values if attack_canary_values.count(c) > 1}
            errors.append(f"Duplicate synthetic canary values across attack dataset: {sorted(dup_canaries)}.")

        # 7. Summary metrics compilation
        prov_counts: dict[str, int] = {}
        tool_counts: dict[str, int] = {}
        attack_fam_counts: dict[str, int] = {}

        for ep in all_episodes:
            if ep.is_attack and ep.attack_family:
                norm_f = normalize_family_id(ep.attack_family).value
                attack_fam_counts[norm_f] = attack_fam_counts.get(norm_f, 0) + 1

            for rec in ep.source_records:
                pval = rec.provenance.value
                prov_counts[pval] = prov_counts.get(pval, 0) + 1

            for turn in ep.turns:
                act = turn.expected_action or {}
                tool = act.get("tool")
                if tool:
                    tool_counts[tool] = tool_counts.get(tool, 0) + 1

        summary = {
            "total_episodes": total_episodes,
            "attack_dev_count": len(attack_dev),
            "attack_test_count": len(attack_test),
            "benign_dev_count": len(benign_dev),
            "benign_test_count": len(benign_test),
            "attack_total": len(attack_dev) + len(attack_test),
            "benign_total": len(benign_dev) + len(benign_test),
            "dev_total": len(attack_dev) + len(benign_dev),
            "test_total": len(attack_test) + len(benign_test),
            "attack_template_count_dev": len(attack_dev_tmpls),
            "attack_template_count_test": len(attack_test_tmpls),
            "attack_template_overlap": len(tmpl_overlap),
            "total_canaries": len(attack_canary_values),
            "unique_canaries": len(set(attack_canary_values)),
        }

        # 8. Manifest building
        passed = (len(errors) == 0)
        validation_status = "PASSED" if passed else "FAILED"

        manifest = build_dataset_manifest(
            attack_dev=attack_dev,
            attack_test=attack_test,
            benign_dev=benign_dev,
            benign_test=benign_test,
            validation_status=validation_status,
            summary_stats=summary,
            provenance_counts=prov_counts,
            tool_usage_counts=tool_counts,
            attack_family_counts=attack_fam_counts,
            errors=errors,
        )

        return ValidationResult(
            passed=passed,
            errors=errors,
            warnings=warnings,
            summary=summary,
            manifest=manifest,
        )


def build_dataset_manifest(
    attack_dev: Sequence[Episode],
    attack_test: Sequence[Episode],
    benign_dev: Sequence[Episode],
    benign_test: Sequence[Episode],
    validation_status: str,
    summary_stats: dict[str, Any],
    provenance_counts: dict[str, int],
    tool_usage_counts: dict[str, int],
    attack_family_counts: dict[str, int],
    errors: Optional[list[str]] = None,
) -> dict[str, Any]:
    """Generate deterministic, machine-readable dataset manifest."""
    attack_dev_tmpls = sorted({ep.template_id for ep in attack_dev})
    attack_test_tmpls = sorted({ep.template_id for ep in attack_test})
    benign_dev_tmpls = sorted({ep.template_id for ep in benign_dev})
    benign_test_tmpls = sorted({ep.template_id for ep in benign_test})

    canary_values = [
        c.value for ep in list(attack_dev) + list(attack_test) for c in ep.synthetic_canaries
    ]

    manifest = {
        "manifest_version": "1.0.0",
        "dataset_name": "TraceGuard Benchmark Suite",
        "validation_status": validation_status,
        "total_episodes": summary_stats.get("total_episodes", 60),
        "attack_count": summary_stats.get("attack_total", 30),
        "benign_count": summary_stats.get("benign_total", 30),
        "dev_count": summary_stats.get("dev_total", 30),
        "test_count": summary_stats.get("test_total", 30),
        "attack_dev_count": len(attack_dev),
        "attack_test_count": len(attack_test),
        "benign_dev_count": len(benign_dev),
        "benign_test_count": len(benign_test),
        "attack_family_counts": dict(sorted(attack_family_counts.items())),
        "attack_template_ids_by_split": {
            "dev": attack_dev_tmpls,
            "test": attack_test_tmpls,
        },
        "benign_template_ids_by_split": {
            "dev": benign_dev_tmpls,
            "test": benign_test_tmpls,
        },
        "provenance_counts": dict(sorted(provenance_counts.items())),
        "canary_count": len(canary_values),
        "unique_canary_count": len(set(canary_values)),
        "tool_usage_counts": dict(sorted(tool_usage_counts.items())),
        "validation_checks": {
            "count_validation": "PASSED" if summary_stats.get("total_episodes") == 60 else "FAILED",
            "episode_id_uniqueness": "PASSED" if not errors or not any("Duplicate episode IDs" in e for e in errors) else "FAILED",
            "split_consistency": "PASSED" if not errors or not any("split mismatch" in e for e in errors) else "FAILED",
            "attack_family_coverage": "PASSED" if not errors or not any("missing threat families" in e for e in errors) else "FAILED",
            "template_disjointness": "PASSED" if summary_stats.get("attack_template_overlap") == 0 else "FAILED",
            "turn_structure": "PASSED" if not errors or not any("turns" in e for e in errors) else "FAILED",
            "provenance_integrity": "PASSED" if not errors or not any("provenance" in e for e in errors) else "FAILED",
            "canary_uniqueness": "PASSED" if len(canary_values) == len(set(canary_values)) == 30 else "FAILED",
            "authorization_boundary": "PASSED" if not errors or not any("outside authorized_scope" in e for e in errors) else "FAILED",
            "outcome_integrity": "PASSED" if not errors or not any("expected_" in e for e in errors) else "FAILED",
        },
    }
    return manifest


def validate_dataset(
    data_dir: Optional[Union[str, Path]] = None,
    write_manifest: bool = True,
    manifest_output_path: Optional[Union[str, Path]] = None,
) -> ValidationResult:
    """Load all four dataset JSONL files, validate them, and optionally write the manifest."""
    base_dir = Path(data_dir) if data_dir else DATA_DIR

    attack_dev_file = base_dir / "episodes_attack_dev.jsonl"
    attack_test_file = base_dir / "episodes_attack_test.jsonl"
    benign_dev_file = base_dir / "episodes_benign_dev.jsonl"
    benign_test_file = base_dir / "episodes_benign_test.jsonl"

    for req_file in (attack_dev_file, attack_test_file, benign_dev_file, benign_test_file):
        if not req_file.is_file():
            return ValidationResult(
                passed=False,
                errors=[f"Required dataset file missing: {req_file}"],
            )

    attack_dev = load_episodes_from_jsonl(attack_dev_file)
    attack_test = load_episodes_from_jsonl(attack_test_file)
    benign_dev = load_episodes_from_jsonl(benign_dev_file)
    benign_test = load_episodes_from_jsonl(benign_test_file)

    validator = DatasetValidator()
    result = validator.validate_collections(
        attack_dev=attack_dev,
        attack_test=attack_test,
        benign_dev=benign_dev,
        benign_test=benign_test,
    )

    if write_manifest and result.manifest:
        out_path = Path(manifest_output_path) if manifest_output_path else (base_dir / "dataset_manifest.json")
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with out_path.open("w", encoding="utf-8") as f:
            json.dump(result.manifest, f, indent=2, ensure_ascii=False)
            f.write("\n")

    return result
