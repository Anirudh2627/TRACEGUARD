"""Tests for full-fidelity JSONL exports and trainer-ready SFT conversation projections."""

import json
from pathlib import Path
import pytest

from traceguard.data.curator.exports import (
    export_full_fidelity_jsonl,
    export_trainer_ready_conversations,
)
from traceguard.data.schema import CanarySpec, Episode, ProvenanceLabel, SourceRecord, Turn


def test_export_full_fidelity_jsonl(tmp_path):
    ep = Episode(
        episode_id="ep_exp_01",
        template_id="tpl_01",
        split="dev",
        initial_user_task="Read doc",
        turns=[Turn(turn_id=1, user_message="Message")],
        synthetic_canaries=[CanarySpec(value="CANARY_EXP_01")],
    )

    out_file = tmp_path / "exported.jsonl"
    export_full_fidelity_jsonl([ep], out_file)

    assert out_file.exists()
    lines = out_file.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 1

    loaded = Episode.from_json(lines[0])
    assert loaded.episode_id == ep.episode_id
    assert loaded.synthetic_canaries[0].value == "CANARY_EXP_01"


def test_export_trainer_ready_conversations(tmp_path):
    ep = Episode(
        episode_id="ep_trainer_01",
        template_id="tpl_02",
        split="dev",
        initial_user_task="Summarize email",
        turns=[
            Turn(
                turn_id=1,
                user_message="Summarize this",
                source_records=[
                    SourceRecord(
                        source_id="src_1",
                        source_type="email",
                        provenance=ProvenanceLabel.UNTRUSTED_EXTERNAL,
                        content="Email text",
                    )
                ],
                expected_action={"name": "read_email"},
            )
        ],
        synthetic_canaries=[CanarySpec(value="CANARY_TR_01")],
    )

    out_file = tmp_path / "trainer_ready.jsonl"
    export_trainer_ready_conversations([ep], out_file)

    assert out_file.exists()
    with open(out_file, "r", encoding="utf-8") as f:
        data = json.loads(f.readline())

    assert data["id"] == "ep_trainer_01"
    assert "conversations" in data
    assert len(data["conversations"]) >= 2
    assert data["conversations"][0]["role"] == "system"
    assert "synthetic_canaries" in data
    assert data["synthetic_canaries"] == ["CANARY_TR_01"]


def test_all_60_episodes_lossless_reconstruction():
    """Verify all 60 original episodes are reconstructed losslessly from curated exports."""
    pairs = [
        ("traceguard/data/episodes_attack_dev.jsonl", "traceguard/data/curated/attack_dev.jsonl"),
        ("traceguard/data/episodes_attack_test.jsonl", "traceguard/data/curated/attack_test.jsonl"),
        ("traceguard/data/episodes_benign_dev.jsonl", "traceguard/data/curated/benign_dev.jsonl"),
        ("traceguard/data/episodes_benign_test.jsonl", "traceguard/data/curated/benign_test.jsonl"),
    ]

    total_verified = 0
    for orig_path, cur_path in pairs:
        p_orig = Path(orig_path)
        p_cur = Path(cur_path)
        if not p_orig.exists() or not p_cur.exists():
            continue

        with open(p_orig, encoding="utf-8") as f_orig, open(p_cur, encoding="utf-8") as f_cur:
            orig_lines = [json.loads(l) for l in f_orig if l.strip()]
            cur_lines = [json.loads(l) for l in f_cur if l.strip()]

        assert len(orig_lines) == len(cur_lines)

        for orig_data, cur_data in zip(orig_lines, cur_lines):
            # Verify canonical core fields match identically
            assert orig_data["episode_id"] == cur_data["episode_id"]
            assert orig_data["split"] == cur_data["split"]
            assert orig_data["is_attack"] == cur_data["is_attack"]
            assert orig_data.get("attack_family") == cur_data.get("attack_family")
            assert orig_data.get("template_id") == cur_data.get("template_id")
            assert orig_data.get("initial_user_task") == cur_data.get("initial_user_task")
            assert orig_data.get("authorized_scope") == cur_data.get("authorized_scope")
            assert orig_data.get("expected_safe_behavior") == cur_data.get("expected_safe_behavior")
            assert orig_data.get("expected_final_fields") == cur_data.get("expected_final_fields")
            assert orig_data.get("expected_prohibited_actions") == cur_data.get("expected_prohibited_actions")
            assert orig_data.get("expected_trust_labels") == cur_data.get("expected_trust_labels")
            assert orig_data.get("synthetic_canaries") == cur_data.get("synthetic_canaries")

            # Verify turns and source records match identically
            orig_turns = orig_data.get("turns", [])
            cur_turns = cur_data.get("turns", [])
            assert len(orig_turns) == len(cur_turns)
            for ot, ct in zip(orig_turns, cur_turns):
                assert ot["turn_id"] == ct["turn_id"]
                assert ot["user_message"] == ct["user_message"]
                assert ot.get("expected_action") == ct.get("expected_action")
                assert ot.get("expected_prohibited_actions") == ct.get("expected_prohibited_actions")

                osr = ot.get("source_records", [])
                csr = ct.get("source_records", [])
                assert len(osr) == len(csr)
                for os_rec, cs_rec in zip(osr, csr):
                    assert os_rec["source_id"] == cs_rec["source_id"]
                    assert os_rec["source_type"] == cs_rec["source_type"]
                    assert os_rec["provenance"] == cs_rec["provenance"]
                    assert os_rec["content"] == cs_rec["content"]
                    assert os_rec.get("metadata") == cs_rec.get("metadata")

            # Reconstruct original metadata from curated metadata
            recon_data = dict(cur_data)
            recon_meta = dict(recon_data.get("metadata") or {})
            recon_meta.pop("curated_clean", None)
            if not recon_meta and "metadata" not in orig_data:
                recon_data.pop("metadata", None)
            else:
                recon_data["metadata"] = recon_meta

            assert orig_data == recon_data
            total_verified += 1

    assert total_verified == 60

