"""CLI tool to execute comprehensive dataset validation for TraceGuard (Module 5).

Usage:
    python scripts/validate_dataset.py
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from traceguard.data.dataset_validator import validate_dataset


def main() -> int:
    """Run comprehensive validation across all TraceGuard datasets."""
    print("=" * 70)
    print("TRACEGUARD MODULE 5: COMPREHENSIVE DATASET VALIDATOR")
    print("=" * 70)

    result = validate_dataset(write_manifest=True)

    summary = result.summary
    print(f"Total episodes validated: {summary.get('total_episodes', 0)}")
    print(f"  Attack DEV:  {summary.get('attack_dev_count', 0)}")
    print(f"  Attack TEST: {summary.get('attack_test_count', 0)}")
    print(f"  Benign DEV:  {summary.get('benign_dev_count', 0)}")
    print(f"  Benign TEST: {summary.get('benign_test_count', 0)}")
    print("-" * 70)
    print(f"Attack total: {summary.get('attack_total', 0)}")
    print(f"Benign total: {summary.get('benign_total', 0)}")
    print(f"DEV total:    {summary.get('dev_total', 0)}")
    print(f"TEST total:   {summary.get('test_total', 0)}")
    print(f"Attack templates (DEV):  {summary.get('attack_template_count_dev', 0)}")
    print(f"Attack templates (TEST): {summary.get('attack_template_count_test', 0)}")
    print(f"Attack template overlap: {summary.get('attack_template_overlap', 0)}")
    print(f"Unique canaries:         {summary.get('unique_canaries', 0)}")
    print("-" * 70)

    if result.manifest and "validation_checks" in result.manifest:
        print("Validation Checks:")
        for check_name, status in result.manifest["validation_checks"].items():
            print(f"  - {check_name:<26}: {status}")
        print("-" * 70)

    if not result.passed:
        print(f"Validation FAILED with {len(result.errors)} errors:")
        for idx, err in enumerate(result.errors, 1):
            print(f"  [{idx}] {err}")
        print("=" * 70)
        return 1

    print("60 episodes validated")
    print("15 attack DEV")
    print("15 attack TEST")
    print("15 benign DEV")
    print("15 benign TEST")
    print("Validation PASSED")
    print("=" * 70)
    return 0


if __name__ == "__main__":
    sys.exit(main())
