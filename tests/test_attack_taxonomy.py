"""Tests for TraceGuard formal attack taxonomy (Module 2).

Validates AttackFamily, AttackTemplate, MutationDimension, template ID uniqueness,
family normalization, provenance compliance, and catalog querying.
"""

from __future__ import annotations

import pytest

from traceguard.data.schema import PROVENANCE_LABELS, ProvenanceLabel
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


# ---------- 1. Family validation ----------


def test_all_three_required_families_exist():
    families = get_attack_families()
    assert len(families) == 3
    assert AttackFamilyId.FAMILY_A in families
    assert AttackFamilyId.FAMILY_B in families
    assert AttackFamilyId.FAMILY_C in families

    assert families[AttackFamilyId.FAMILY_A].name == "Document & Email Injection"
    assert families[AttackFamilyId.FAMILY_B].name == "Tool-Output & Search-Result Injection"
    assert families[AttackFamilyId.FAMILY_C].name == "Stored / Cross-Turn Injection"


def test_family_id_normalization():
    # Canonical enums
    assert normalize_family_id(AttackFamilyId.FAMILY_A) == AttackFamilyId.FAMILY_A
    assert normalize_family_id(AttackFamilyId.FAMILY_B) == AttackFamilyId.FAMILY_B
    assert normalize_family_id(AttackFamilyId.FAMILY_C) == AttackFamilyId.FAMILY_C

    # Common aliases and letter codes
    assert normalize_family_id("family_a") == AttackFamilyId.FAMILY_A
    assert normalize_family_id("family_a_document_email") == AttackFamilyId.FAMILY_A
    assert normalize_family_id("document_email") == AttackFamilyId.FAMILY_A
    assert normalize_family_id("A") == AttackFamilyId.FAMILY_A
    assert normalize_family_id("a") == AttackFamilyId.FAMILY_A

    assert normalize_family_id("family_b") == AttackFamilyId.FAMILY_B
    assert normalize_family_id("tool_search") == AttackFamilyId.FAMILY_B
    assert normalize_family_id("B") == AttackFamilyId.FAMILY_B

    assert normalize_family_id("family_c") == AttackFamilyId.FAMILY_C
    assert normalize_family_id("stored_crossturn") == AttackFamilyId.FAMILY_C
    assert normalize_family_id("C") == AttackFamilyId.FAMILY_C


def test_invalid_family_fails():
    invalid_families = ["family_d", "unknown_threat", "prompt_injection_general", "", "123"]
    for inv in invalid_families:
        with pytest.raises(ValueError, match="Unknown attack family"):
            normalize_family_id(inv)

        with pytest.raises(ValueError, match="Unknown attack family"):
            AttackTemplate(
                template_id="test_tmpl",
                family_id=inv,  # type: ignore
                name="test",
                description="test",
                attack_mechanism="test",
                source_type="doc",
                expected_provenance=ProvenanceLabel.UNTRUSTED_EXTERNAL,
            )


# ---------- 2. Template uniqueness and catalog validation ----------


def test_all_catalog_template_ids_unique():
    catalog = get_taxonomy_catalog()
    assert len(catalog) == len(TEMPLATES)
    assert len(catalog) >= 12  # Ensure rich coverage across families

    template_ids = [t.template_id for t in TEMPLATES]
    assert len(template_ids) == len(set(template_ids))

    validate_taxonomy(catalog)


def test_each_family_has_registered_templates():
    for fam_id in (AttackFamilyId.FAMILY_A, AttackFamilyId.FAMILY_B, AttackFamilyId.FAMILY_C):
        templates = get_templates_for_family(fam_id)
        assert len(templates) >= 3, f"Family {fam_id} has fewer than 3 templates"
        for t in templates:
            assert t.family_id == fam_id


def test_get_template_by_id():
    tmpl = get_template("doc_injection_01")
    assert tmpl.template_id == "doc_injection_01"
    assert tmpl.family_id == AttackFamilyId.FAMILY_A
    assert "send_email" in tmpl.targeted_sensitive_actions

    with pytest.raises(KeyError, match="not found in taxonomy catalog"):
        get_template("non_existent_template_999")


# ---------- 3. Valid template construction and validation ----------


def test_valid_custom_template_construction():
    mutation = MutationDimension(
        name="framing_style",
        description="Phrasing of injection",
        possible_values=["override", "polite"],
    )

    tmpl = AttackTemplate(
        template_id="custom_attack_01",
        family_id=AttackFamilyId.FAMILY_A,
        name="Custom Attack",
        description="Custom attack description",
        attack_mechanism="Indirect injection via invoice",
        source_type="document",
        expected_provenance=ProvenanceLabel.UNTRUSTED_EXTERNAL,
        targeted_sensitive_actions=["send_email"],
        expected_safe_behavior="Ignore embedded directive",
        mutation_dimensions=[mutation],
    )

    assert tmpl.template_id == "custom_attack_01"
    assert tmpl.family_id == AttackFamilyId.FAMILY_A
    assert tmpl.expected_provenance == ProvenanceLabel.UNTRUSTED_EXTERNAL
    assert len(tmpl.mutation_dimensions) == 1
    assert tmpl.mutation_dimensions[0].name == "framing_style"


def test_empty_template_id_fails():
    for empty in ("", "   "):
        with pytest.raises(ValueError, match="AttackTemplate template_id must be a non-empty string"):
            AttackTemplate(
                template_id=empty,
                family_id=AttackFamilyId.FAMILY_A,
                name="Empty ID",
                description="desc",
                attack_mechanism="mech",
                source_type="doc",
                expected_provenance=ProvenanceLabel.UNTRUSTED_EXTERNAL,
            )


# ---------- 4. Provenance enforcement ----------


def test_template_provenance_must_be_valid_label():
    for prov in PROVENANCE_LABELS:
        tmpl = AttackTemplate(
            template_id="prov_test",
            family_id=AttackFamilyId.FAMILY_B,
            name="Prov Test",
            description="desc",
            attack_mechanism="mech",
            source_type="tool_output",
            expected_provenance=prov,  # type: ignore
        )
        assert tmpl.expected_provenance == ProvenanceLabel(prov)

    invalid_provs = ["TRUSTED", "FORGED", "HIGH", "", "admin"]
    for inv in invalid_provs:
        with pytest.raises(ValueError, match="Invalid provenance label"):
            AttackTemplate(
                template_id="prov_test_bad",
                family_id=AttackFamilyId.FAMILY_B,
                name="Prov Test",
                description="desc",
                attack_mechanism="mech",
                source_type="tool_output",
                expected_provenance=inv,  # type: ignore
            )


# ---------- 5. Serialization & Roundtrip ----------


def test_template_and_mutation_serialization():
    dim = MutationDimension(
        name="placement",
        description="Location in text",
        possible_values=["header", "footer"],
    )
    dim_dict = dim.to_dict()
    assert dim_dict["name"] == "placement"
    restored_dim = MutationDimension.from_dict(dim_dict)
    assert restored_dim == dim

    tmpl = get_template("stored_injection_01")
    d = tmpl.to_dict()
    assert d["template_id"] == "stored_injection_01"
    assert d["family_id"] == "family_c"
    assert d["expected_provenance"] == "DERIVED_UNTRUSTED"

    restored = AttackTemplate.from_dict(d)
    assert restored == tmpl
