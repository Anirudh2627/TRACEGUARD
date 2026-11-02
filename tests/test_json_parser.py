"""Unit tests for the strict JSON parser (traceguard.models.json_parser).

Every rejection mode required by the master prompt is covered:
markdown fences, trailing text, invalid JSON, unknown tools, missing
arguments, extra arguments, wrong argument types — plus duplicate keys,
bool/int confusion and top-level field violations.
"""

from __future__ import annotations

import pytest

from traceguard.models.json_parser import (
    ParseFailure,
    ParsedOutput,
    load_tool_registry,
    parse_model_output,
)
from traceguard.models.config import CONFIG_DIR

REGISTRY = load_tool_registry(CONFIG_DIR / "tools.yaml")


def parse(raw: str):
    return parse_model_output(raw, REGISTRY)


# ---------- valid outputs ----------

def test_valid_tool_call():
    out = parse('{"type": "tool_call", "tool": "search_emails", "arguments": {"query": "ABC invoice", "limit": 5}}')
    assert isinstance(out, ParsedOutput)
    assert out.kind == "tool_call" and out.tool == "search_emails"
    assert out.arguments == {"query": "ABC invoice", "limit": 5}


def test_valid_final_and_clarify():
    fin = parse('{"type": "final", "answer": "Done."}')
    cla = parse('{"type": "clarify", "question": "Which one?"}')
    assert isinstance(fin, ParsedOutput) and fin.answer == "Done."
    assert isinstance(cla, ParsedOutput) and cla.question == "Which one?"


def test_surrounding_whitespace_is_tolerated():
    out = parse('  \n {"type": "final", "answer": "ok"} \n ')
    assert isinstance(out, ParsedOutput)


def test_optional_argument_may_be_omitted():
    out = parse('{"type": "tool_call", "tool": "search_emails", "arguments": {"query": "x"}}')
    assert isinstance(out, ParsedOutput)


# ---------- rejections (never repaired) ----------

def test_reject_markdown_fence():
    raw = '```json\n{"type": "final", "answer": "ok"}\n```'
    out = parse(raw)
    assert isinstance(out, ParseFailure)
    assert out.reason_code == "markdown_fence"
    assert out.raw_text == raw  # verbatim preserved for logging


def test_reject_trailing_text():
    out = parse('{"type": "final", "answer": "ok"} hope this helps!')
    assert isinstance(out, ParseFailure)
    assert out.reason_code == "leading_trailing_text"


def test_reject_leading_text():
    out = parse('Sure! {"type": "final", "answer": "ok"}')
    assert isinstance(out, ParseFailure)
    assert out.reason_code == "leading_trailing_text"


def test_reject_invalid_json():
    out = parse('{"type": "final", "answer": ')
    assert isinstance(out, ParseFailure)
    assert out.reason_code == "invalid_json"


def test_reject_empty_output():
    out = parse("   ")
    assert isinstance(out, ParseFailure)
    assert out.reason_code == "empty_output"


def test_reject_top_level_array():
    out = parse('[{"type": "final", "answer": "ok"}]')
    assert isinstance(out, ParseFailure)
    assert out.reason_code == "not_an_object"


def test_reject_duplicate_keys():
    out = parse('{"type": "final", "answer": "a", "answer": "b"}')
    assert isinstance(out, ParseFailure)
    assert out.reason_code == "duplicate_keys"


def test_reject_missing_type():
    out = parse('{"answer": "ok"}')
    assert isinstance(out, ParseFailure)
    assert out.reason_code == "missing_field"


def test_reject_unknown_type_value():
    out = parse('{"type": "toolcall", "tool": "x", "arguments": {}}')
    assert isinstance(out, ParseFailure)
    assert out.reason_code == "unknown_type_value"


def test_reject_extra_top_level_field():
    out = parse('{"type": "final", "answer": "ok", "confidence": 0.9}')
    assert isinstance(out, ParseFailure)
    assert out.reason_code == "extra_field"


def test_reject_missing_required_field():
    out = parse('{"type": "tool_call", "tool": "search_emails"}')
    assert isinstance(out, ParseFailure)
    assert out.reason_code == "missing_field"


def test_reject_unknown_tool():
    out = parse('{"type": "tool_call", "tool": "delete_everything", "arguments": {}}')
    assert isinstance(out, ParseFailure)
    assert out.reason_code == "unknown_tool"


def test_reject_missing_required_argument():
    out = parse('{"type": "tool_call", "tool": "read_email", "arguments": {}}')
    assert isinstance(out, ParseFailure)
    assert out.reason_code == "missing_argument"


def test_reject_extra_argument():
    out = parse('{"type": "tool_call", "tool": "read_email", "arguments": {"email_id": "e1", "sudo": true}}')
    assert isinstance(out, ParseFailure)
    assert out.reason_code == "extra_argument"


def test_reject_wrong_argument_type():
    out = parse('{"type": "tool_call", "tool": "search_emails", "arguments": {"query": 42}}')
    assert isinstance(out, ParseFailure)
    assert out.reason_code == "wrong_argument_type"


def test_reject_bool_as_integer():
    out = parse('{"type": "tool_call", "tool": "search_emails", "arguments": {"query": "x", "limit": true}}')
    assert isinstance(out, ParseFailure)
    assert out.reason_code == "wrong_argument_type"


def test_reject_integer_as_boolean():
    out = parse('{"type": "tool_call", "tool": "send_email", "arguments": {"to": "a@b.c", "subject": true, "body": "x"}}')
    assert isinstance(out, ParseFailure)


def test_reject_non_string_answer():
    out = parse('{"type": "final", "answer": 42}')
    assert isinstance(out, ParseFailure)
    assert out.reason_code == "wrong_field_type"


def test_reject_non_object_arguments():
    out = parse('{"type": "tool_call", "tool": "search_emails", "arguments": "query=x"}')
    assert isinstance(out, ParseFailure)
    assert out.reason_code == "wrong_field_type"


# ---------- registry loading ----------

def test_registry_contents_and_sensitivity():
    names = REGISTRY.names()
    assert "search_emails" in names and "send_email" in names and "read_private_file" in names
    assert REGISTRY.get("send_email").sensitive is True
    assert REGISTRY.get("search_emails").sensitive is False


def test_registry_rejects_unknown_arg_type(tmp_path):
    bad = tmp_path / "tools.yaml"
    bad.write_text("tools:\n  t:\n    description: x\n    arguments:\n      a: {type: object}\n")
    with pytest.raises(ValueError, match="Unsupported argument type"):
        load_tool_registry(bad)
