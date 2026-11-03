"""TraceGuard dataset schema and data abstractions.

Module 1 — Shared Schema & Project Setup
Module 2 — Attack Taxonomy
(Member 2: Data & Interpretability Lead).
"""

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
    FAMILIES,
    TEMPLATES,
    AttackFamily,
    AttackFamilyId,
    AttackTemplate,
    MutationDimension,
    get_attack_families,
    get_taxonomy_catalog,
    get_template,
    get_templates_for_family,
    normalize_family_id,
    validate_taxonomy,
)
from traceguard.data.dataset_validator import (
    DatasetValidator,
    ValidationResult,
    validate_dataset,
)

__all__ = [
    # Module 1
    "ALLOWED_SPLITS",
    "PROVENANCE_LABELS",
    "CanarySpec",
    "Episode",
    "ExpectedOutcome",
    "ProvenanceLabel",
    "SourceRecord",
    "Turn",
    "validate_provenance_label",
    # Module 2
    "FAMILIES",
    "TEMPLATES",
    "AttackFamily",
    "AttackFamilyId",
    "AttackTemplate",
    "MutationDimension",
    "get_attack_families",
    "get_taxonomy_catalog",
    "get_template",
    "get_templates_for_family",
    "normalize_family_id",
    "validate_taxonomy",
    # Module 5
    "DatasetValidator",
    "ValidationResult",
    "validate_dataset",
]
