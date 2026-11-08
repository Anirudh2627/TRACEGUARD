"""Regression tests for multi-turn role alternation and chat template rendering."""

from __future__ import annotations

from typing import Any, Sequence

import pytest

from traceguard.models.prompt_builder import (
    normalize_conversation_roles,
    render_prompt,
)


class StrictAlternatingTokenizer:
    """Mock tokenizer that strictly enforces role alternation (like Cohere Aya / LLaMA Jinja templates)."""

    chat_template = "{% for m in messages %}...{% endfor %}"

    def apply_chat_template(
        self,
        messages: Sequence[dict[str, str]],
        tokenize: bool = False,
        add_generation_prompt: bool = True,
    ) -> str:
        assert tokenize is False
        # Jinja template strict alternation check
        prev_role: str | None = None
        for idx, msg in enumerate(messages):
            role = msg["role"]
            if role == "system" and idx == 0:
                prev_role = "system"
                continue
            if prev_role is not None and prev_role == role:
                raise ValueError(
                    f"TemplateError: Conversation roles must alternate user/assistant/user/assistant/... "
                    f"Found consecutive '{role}' at index {idx}."
                )
            prev_role = role

        rendered = "\n".join(f"[{m['role']}] {m['content']}" for m in messages)
        if add_generation_prompt:
            rendered += "\n[assistant]\n"
        return rendered


def test_strict_tokenizer_raises_on_raw_consecutive_user_messages():
    """Verify that a strict alternating tokenizer raises an error on consecutive user messages."""
    strict_tok = StrictAlternatingTokenizer()
    unnormalized_messages = [
        {"role": "system", "content": "System prompt instructions"},
        {"role": "user", "content": "Search documents for invoice INV-8821"},
        {"role": "assistant", "content": '{"tool": "search_documents", "arguments": {"query": "INV-8821"}}'},
        {"role": "user", "content": "Tool search_documents returned: doc_inv_8821 found."},
        {"role": "user", "content": "Please read doc_inv_8821."},
    ]

    with pytest.raises(ValueError, match="TemplateError: Conversation roles must alternate"):
        strict_tok.apply_chat_template(unnormalized_messages, tokenize=False, add_generation_prompt=True)


def test_normalize_conversation_roles_merges_consecutive_user_turns():
    """Verify normalize_conversation_roles consolidates consecutive user messages without data loss."""
    raw_messages = [
        {"role": "system", "content": "System prompt instructions"},
        {"role": "user", "content": "Search documents for invoice INV-8821"},
        {"role": "assistant", "content": '{"tool": "search_documents"}'},
        {"role": "user", "content": "Tool output: doc_inv_8821 found."},
        {"role": "user", "content": "Please read doc_inv_8821."},
    ]

    normalized = normalize_conversation_roles(raw_messages)
    assert len(normalized) == 4
    assert [m["role"] for m in normalized] == ["system", "user", "assistant", "user"]

    # Verify both tool output and subsequent user instruction are preserved verbatim
    last_user_turn = normalized[3]
    assert "Tool output: doc_inv_8821 found." in last_user_turn["content"]
    assert "Please read doc_inv_8821." in last_user_turn["content"]
    assert (
        last_user_turn["content"]
        == "Tool output: doc_inv_8821 found.\n\nPlease read doc_inv_8821."
    )


def test_normalize_conversation_roles_edge_cases():
    """Verify normalize_conversation_roles handles empty, single, and already alternating sequences."""
    assert normalize_conversation_roles([]) == []

    single = [{"role": "user", "content": "Hello"}]
    assert normalize_conversation_roles(single) == single

    alternating = [
        {"role": "user", "content": "Hello"},
        {"role": "assistant", "content": "Hi"},
        {"role": "user", "content": "Help me"},
    ]
    assert normalize_conversation_roles(alternating) == alternating

    triple_user = [
        {"role": "user", "content": "A"},
        {"role": "user", "content": "B"},
        {"role": "user", "content": "C"},
    ]
    norm_triple = normalize_conversation_roles(triple_user)
    assert len(norm_triple) == 1
    assert norm_triple[0]["content"] == "A\n\nB\n\nC"


def test_render_prompt_succeeds_with_strict_tokenizer():
    """Verify render_prompt automatically normalizes roles when calling apply_chat_template."""
    strict_tok = StrictAlternatingTokenizer()
    multi_turn_messages = [
        {"role": "system", "content": "You are a secure assistant."},
        {"role": "user", "content": "Search mailbox for invoice."},
        {"role": "assistant", "content": '{"tool": "search_emails", "query": "invoice"}'},
        {"role": "user", "content": "Tool search_emails returned: email_7712."},
        {"role": "user", "content": "What is the total due in email_7712?"},
    ]

    rendered = render_prompt(multi_turn_messages, tokenizer=strict_tok)
    assert rendered.renderer == "chat_template"
    assert "You are a secure assistant." in rendered.text
    assert "Tool search_emails returned: email_7712." in rendered.text
    assert "What is the total due in email_7712?" in rendered.text
    assert rendered.text.endswith("\n[assistant]\n")
