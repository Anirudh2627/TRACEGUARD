"""Comprehensive Quality Gate system for TraceGuard datasets."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from traceguard.data.schema import (
    ALLOWED_SPLITS,
    PROVENANCE_LABELS,
    Episode,
)

logger = logging.getLogger(__name__)

VALID_ATTACK_FAMILIES = {"family_a", "family_b", "family_c"}


@dataclass
class QualityGateViolation:
    """Detailed record of a failed quality check."""

    category: str  # "structural", "attack", "benign", "split_hygiene", "dataset_level"
    check_name: str
    episode_id: str
    message: str
    severity: str = "CRITICAL"  # "CRITICAL", "WARNING"

    def to_dict(self) -> dict[str, Any]:
        return {
            "category": self.category,
            "check_name": self.check_name,
            "episode_id": self.episode_id,
            "message": self.message,
            "severity": self.severity,
        }


@dataclass
class QualityGateReport:
    """Summary of all executed quality gate checks and overall gate pass/fail status."""

    passed: bool = True
    total_checks_run: int = 0
    passed_checks_count: int = 0
    failed_checks_count: int = 0
    warning_count: int = 0
    violations: list[QualityGateViolation] = field(default_factory=list)
    metrics: dict[str, Any] = field(default_factory=dict)

    def record_violation(self, violation: QualityGateViolation) -> None:
        self.violations.append(violation)
        self.failed_checks_count += 1
        if violation.severity == "CRITICAL":
            self.passed = False
        elif violation.severity == "WARNING":
            self.warning_count += 1

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": "PASSED" if self.passed else "FAILED",
            "passed": self.passed,
            "total_checks_run": self.total_checks_run,
            "passed_checks_count": self.passed_checks_count,
            "failed_checks_count": self.failed_checks_count,
            "warning_count": self.warning_count,
            "violations": [v.to_dict() for v in self.violations],
            "metrics": self.metrics,
        }


class QualityGateRunner:
    """Executes structural, attack, benign, split hygiene, and dataset-level gates."""

    def evaluate_episode(self, ep: Episode) -> list[QualityGateViolation]:
        """Run structural and role-specific quality checks on a single episode."""
        violations: list[QualityGateViolation] = []

        # 1. Structural Checks
        if not ep.episode_id or not isinstance(ep.episode_id, str) or not ep.episode_id.strip():
            violations.append(
                QualityGateViolation(
                    category="structural",
                    check_name="valid_episode_id",
                    episode_id=str(getattr(ep, "episode_id", "UNKNOWN")),
                    message="episode_id must be a non-empty string.",
                )
            )

        if not ep.template_id or not isinstance(ep.template_id, str) or not ep.template_id.strip():
            violations.append(
                QualityGateViolation(
                    category="structural",
                    check_name="valid_template_id",
                    episode_id=ep.episode_id,
                    message="template_id must be a non-empty string.",
                )
            )

        if ep.split not in ALLOWED_SPLITS:
            violations.append(
                QualityGateViolation(
                    category="structural",
                    check_name="valid_split",
                    episode_id=ep.episode_id,
                    message=f"Invalid split {ep.split!r}; must be in {sorted(ALLOWED_SPLITS)}.",
                )
            )

        if not ep.turns or len(ep.turns) == 0:
            violations.append(
                QualityGateViolation(
                    category="structural",
                    check_name="turns_present",
                    episode_id=ep.episode_id,
                    message="Episode must contain at least one turn.",
                )
            )

        for idx, t in enumerate(ep.turns):
            if not t.user_message or not isinstance(t.user_message, str):
                violations.append(
                    QualityGateViolation(
                        category="structural",
                        check_name="turn_content_valid",
                        episode_id=ep.episode_id,
                        message=f"Turn {idx} has empty or non-string user_message.",
                    )
                )
            for s in t.source_records:
                lbl = s.provenance.value if hasattr(s.provenance, "value") else str(s.provenance)
                if lbl not in PROVENANCE_LABELS:
                    violations.append(
                        QualityGateViolation(
                            category="structural",
                            check_name="valid_turn_source_provenance",
                            episode_id=ep.episode_id,
                            message=f"Turn {idx} source {s.source_id} has invalid provenance {lbl!r}.",
                        )
                    )

        for s in ep.source_records:
            lbl = s.provenance.value if hasattr(s.provenance, "value") else str(s.provenance)
            if lbl not in PROVENANCE_LABELS:
                violations.append(
                    QualityGateViolation(
                        category="structural",
                        check_name="valid_source_provenance",
                        episode_id=ep.episode_id,
                        message=f"Source record {s.source_id} has invalid provenance {lbl!r}.",
                    )
                )

        # 2. Attack vs. Benign role checks
        if ep.is_attack:
            if ep.attack_family not in VALID_ATTACK_FAMILIES:
                violations.append(
                    QualityGateViolation(
                        category="attack",
                        check_name="valid_attack_family",
                        episode_id=ep.episode_id,
                        message=f"Attack episode has invalid attack_family {ep.attack_family!r}.",
                    )
                )

            if not ep.synthetic_canaries or len(ep.synthetic_canaries) == 0:
                violations.append(
                    QualityGateViolation(
                        category="attack",
                        check_name="canaries_present",
                        episode_id=ep.episode_id,
                        message="Attack episode must contain synthetic canaries.",
                    )
                )

            if not ep.expected_safe_behavior or not ep.expected_safe_behavior.strip():
                violations.append(
                    QualityGateViolation(
                        category="attack",
                        check_name="expected_safe_behavior_defined",
                        episode_id=ep.episode_id,
                        message="Attack episode must define expected_safe_behavior.",
                    )
                )

            if not ep.expected_prohibited_actions or len(ep.expected_prohibited_actions) == 0:
                violations.append(
                    QualityGateViolation(
                        category="attack",
                        check_name="prohibited_actions_defined",
                        episode_id=ep.episode_id,
                        message="Attack episode must specify expected_prohibited_actions.",
                    )
                )
        else:
            if ep.attack_family != "benign":
                violations.append(
                    QualityGateViolation(
                        category="benign",
                        check_name="benign_family_label",
                        episode_id=ep.episode_id,
                        message=f"Benign episode must have attack_family='benign', got {ep.attack_family!r}.",
                    )
                )

            if ep.synthetic_canaries and len(ep.synthetic_canaries) > 0:
                violations.append(
                    QualityGateViolation(
                        category="benign",
                        check_name="no_canaries_in_benign",
                        episode_id=ep.episode_id,
                        message="Benign episode must not contain synthetic canaries.",
                    )
                )

        return violations

    def evaluate_collection(
        self, datasets: dict[str, list[Episode]]
    ) -> QualityGateReport:
        """Evaluate complete dataset collection across all quality gate categories."""
        report = QualityGateReport()

        all_episodes: list[Episode] = []
        for name, eps in datasets.items():
            all_episodes.extend(eps)

        report.total_checks_run += len(all_episodes)

        # 1. Episode-level structural, attack, and benign checks
        for ep in all_episodes:
            viols = self.evaluate_episode(ep)
            if viols:
                for v in viols:
                    report.record_violation(v)
            else:
                report.passed_checks_count += 1

        # 2. Canary uniqueness across attack episodes
        attack_canaries: dict[str, list[str]] = {}
        for ep in all_episodes:
            if ep.is_attack:
                for c in ep.synthetic_canaries:
                    attack_canaries.setdefault(c.value, []).append(ep.episode_id)

        for canary_val, ep_ids in attack_canaries.items():
            if len(ep_ids) > 1:
                report.record_violation(
                    QualityGateViolation(
                        category="dataset_level",
                        check_name="canary_uniqueness",
                        episode_id=str(ep_ids),
                        message=f"Canary {canary_val!r} is duplicated across episodes: {ep_ids}",
                    )
                )

        # 3. Split hygiene: Template Disjointness between DEV and TEST
        attack_dev_templates = {
            ep.template_id for ep in datasets.get("attack_dev", []) if ep.is_attack
        }
        attack_test_templates = {
            ep.template_id for ep in datasets.get("attack_test", []) if ep.is_attack
        }
        template_overlap = attack_dev_templates.intersection(attack_test_templates)

        report.total_checks_run += 1
        if len(template_overlap) > 0:
            report.record_violation(
                QualityGateViolation(
                    category="split_hygiene",
                    check_name="attack_template_disjointness",
                    episode_id="COLLECTION",
                    message=f"Attack template leakage detected across DEV and TEST: {template_overlap}",
                )
            )
        else:
            report.passed_checks_count += 1

        # 4. Dataset counts and family distributions
        attack_eps = [ep for ep in all_episodes if ep.is_attack]
        benign_eps = [ep for ep in all_episodes if not ep.is_attack]

        dev_eps = [ep for ep in all_episodes if ep.split == "dev"]
        test_eps = [ep for ep in all_episodes if ep.split == "test"]

        family_counts = {
            "family_a": sum(1 for ep in attack_eps if ep.attack_family == "family_a"),
            "family_b": sum(1 for ep in attack_eps if ep.attack_family == "family_b"),
            "family_c": sum(1 for ep in attack_eps if ep.attack_family == "family_c"),
            "benign": len(benign_eps),
        }

        report.metrics = {
            "total_episodes": len(all_episodes),
            "attack_episodes_total": len(attack_eps),
            "benign_episodes_total": len(benign_eps),
            "dev_episodes_total": len(dev_eps),
            "test_episodes_total": len(test_eps),
            "attack_dev_count": len(datasets.get("attack_dev", [])),
            "attack_test_count": len(datasets.get("attack_test", [])),
            "benign_dev_count": len(datasets.get("benign_dev", [])),
            "benign_test_count": len(datasets.get("benign_test", [])),
            "family_distribution": family_counts,
            "unique_canaries_count": len(attack_canaries),
            "attack_dev_templates_count": len(attack_dev_templates),
            "attack_test_templates_count": len(attack_test_templates),
            "template_overlap_count": len(template_overlap),
        }

        # Expected baseline verification (run only when evaluating full 4 datasets)
        if len(datasets) == 4 and "attack_dev" in datasets and "attack_test" in datasets:
            report.total_checks_run += 4
            if len(all_episodes) == 60:
                report.passed_checks_count += 1
            else:
                report.record_violation(
                    QualityGateViolation(
                        category="dataset_level",
                        check_name="expected_total_count",
                        episode_id="COLLECTION",
                        message=f"Expected 60 total episodes, found {len(all_episodes)}.",
                    )
                )

            if len(attack_eps) == 30 and len(benign_eps) == 30:
                report.passed_checks_count += 1
            else:
                report.record_violation(
                    QualityGateViolation(
                        category="dataset_level",
                        check_name="attack_benign_parity",
                        episode_id="COLLECTION",
                        message=f"Expected 30 attack and 30 benign episodes, found {len(attack_eps)} and {len(benign_eps)}.",
                    )
                )

            if family_counts["family_a"] == 12 and family_counts["family_b"] == 10 and family_counts["family_c"] == 8:
                report.passed_checks_count += 1
            else:
                report.record_violation(
                    QualityGateViolation(
                        category="dataset_level",
                        check_name="attack_family_distribution",
                        episode_id="COLLECTION",
                        message=f"Expected Family A=12, B=10, C=8. Got: {family_counts}",
                    )
                )

            if len(attack_canaries) == 30:
                report.passed_checks_count += 1
            else:
                report.record_violation(
                    QualityGateViolation(
                        category="dataset_level",
                        check_name="expected_canaries_count",
                        episode_id="COLLECTION",
                        message=f"Expected 30 unique canaries, found {len(attack_canaries)}.",
                    )
                )

        return report
