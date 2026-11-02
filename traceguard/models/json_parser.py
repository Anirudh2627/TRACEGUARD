"""Strict JSON tool-call parser for the TraceGuard model protocol.

The protocol requires the model to emit **exactly one JSON object** per turn:

    {"type": "tool_call", "tool": "<name>", "arguments": {...}}
    {"type": "final", "answer": "<text>"}
    {"type": "clarify", "question": "<text>"}

This parser is deliberately unforgiving. It rejects (never repairs):

* markdown code fences,
* any leading/trailing text around the JSON object,
* invalid JSON and duplicate keys,
* unknown ``type`` values and unexpected top-level fields,
* unknown tool names,
* missing required arguments, extra arguments, and wrong argument types
  (including ``bool`` masquerading as ``int``).

Design rule: parsing failures are *data*, not exceptions. ``parse_model_output``
always returns either a :class:`ParsedOutput` or a :class:`ParseFailure` with a
machine-readable ``reason_code`` so the smoke runner can log and score them.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal, Mapping, Optional, Union

import yaml

OutputKind = Literal["tool_call", "final", "clarify"]

#: JSON-schema-like scalar type names mapped to Python runtime checks.
_SUPPORTED_ARG_TYPES = ("string", "integer", "number", "boolean")

# Exact allowed top-level key sets per output kind (strict: no extras).
_ALLOWED_KEYS: dict[str, frozenset[str]] = {
    "tool_call": frozenset({"type", "tool", "arguments"}),
    "final": frozenset({"type", "answer"}),
    "clarify": frozenset({"type", "question"}),
}

_REQUIRED_KEYS = _ALLOWED_KEYS  # in this protocol every allowed key is required


@dataclass(frozen=True)
class ArgSpec:
    """Schema of a single tool argument."""

    name: str
    type: str  # one of _SUPPORTED_ARG_TYPES
    required: bool

    def __post_init__(self) -> None:
        if self.type not in _SUPPORTED_ARG_TYPES:
            raise ValueError(
                f"Unsupported argument type {self.type!r} for {self.name!r}; "
                f"expected one of {_SUPPORTED_ARG_TYPES}"
            )


@dataclass(frozen=True)
class ToolSpec:
    """Schema of one synthetic tool exposed to the model."""

    name: str
    description: str
    sensitive: bool
    arguments: Mapping[str, ArgSpec]


class ToolRegistry:
    """Immutable lookup of tool name -> :class:`ToolSpec`."""

    def __init__(self, tools: Mapping[str, ToolSpec]) -> None:
        self._tools: dict[str, ToolSpec] = dict(tools)

    def __contains__(self, name: object) -> bool:
        return name in self._tools

    def __iter__(self):
        return iter(self._tools.values())

    def get(self, name: str) -> Optional[ToolSpec]:
        return self._tools.get(name)

    def names(self) -> list[str]:
        return sorted(self._tools)


@dataclass(frozen=True)
class ParsedOutput:
    """A model output that satisfied the strict protocol."""

    kind: OutputKind
    raw_text: str
    tool: Optional[str] = None
    arguments: dict[str, Any] = field(default_factory=dict)
    answer: Optional[str] = None
    question: Optional[str] = None


@dataclass(frozen=True)
class ParseFailure:
    """A rejected model output. Never repaired, always logged verbatim."""

    raw_text: str
    reason_code: str
    detail: str


ParseResult = Union[ParsedOutput, ParseFailure]


def load_tool_registry(path: Union[str, Path]) -> ToolRegistry:
    """Load tool schemas from a YAML file.

    Expected shape::

        tools:
          <name>:
            description: str
            sensitive: bool
            arguments:
              <arg>: {type: string|integer|number|boolean, required: bool}

    Raises:
        FileNotFoundError / yaml.YAMLError / ValueError on malformed schemas.
    """
    path = Path(path)
    with path.open("r", encoding="utf-8") as fh:
        doc = yaml.safe_load(fh)
    if not isinstance(doc, dict) or "tools" not in doc:
        raise ValueError(f"{path}: expected a top-level 'tools' mapping")
    tools: dict[str, ToolSpec] = {}
    for name, spec in doc["tools"].items():
        if not isinstance(spec, dict):
            raise ValueError(f"{path}: tool {name!r} must be a mapping")
        args_raw = spec.get("arguments") or {}
        if not isinstance(args_raw, dict):
            raise ValueError(f"{path}: tool {name!r} arguments must be a mapping")
        args: dict[str, ArgSpec] = {}
        for arg_name, arg_def in args_raw.items():
            if not isinstance(arg_def, dict) or "type" not in arg_def:
                raise ValueError(
                    f"{path}: tool {name!r} argument {arg_name!r} needs a 'type'"
                )
            args[arg_name] = ArgSpec(
                name=arg_name,
                type=str(arg_def["type"]),
                required=bool(arg_def.get("required", True)),
            )
        tools[name] = ToolSpec(
            name=name,
            description=str(spec.get("description", "")),
            sensitive=bool(spec.get("sensitive", False)),
            arguments=args,
        )
    if not tools:
        raise ValueError(f"{path}: no tools defined")
    return ToolRegistry(tools)


def _reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """``object_pairs_hook`` that rejects duplicate keys (strict JSON)."""
    seen: set[str] = set()
    for key, _ in pairs:
        if key in seen:
            raise _DuplicateKeyError(f"duplicate key {key!r}")
        seen.add(key)
    return dict(pairs)


class _DuplicateKeyError(ValueError):
    """Internal signal for duplicate JSON keys."""


def _check_arg_type(value: Any, expected: str) -> bool:
    """Runtime type check; ``bool`` must never satisfy ``integer``/``number``."""
    if expected == "string":
        return isinstance(value, str)
    if expected == "boolean":
        return isinstance(value, bool)
    if expected == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if expected == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    raise ValueError(f"unreachable: unsupported type {expected!r}")


def parse_model_output(raw_text: str, registry: ToolRegistry) -> ParseResult:
    """Parse one raw model output against the strict protocol.

    Args:
        raw_text: The model's decoded completion, exactly as generated.
        registry: Known tool schemas.

    Returns:
        :class:`ParsedOutput` on full compliance, otherwise
        :class:`ParseFailure` with a deterministic ``reason_code``.
    """
    stripped = raw_text.strip()

    if stripped.startswith("```") or stripped.endswith("```"):
        return ParseFailure(raw_text, "markdown_fence", "output contains code fences")
    if not stripped:
        return ParseFailure(raw_text, "empty_output", "model produced no text")

    try:
        obj = json.loads(stripped, object_pairs_hook=_reject_duplicates)
    except _DuplicateKeyError as exc:
        return ParseFailure(raw_text, "duplicate_keys", str(exc))
    except json.JSONDecodeError as exc:
        # Classification is deterministic:
        #   * "Extra data"        -> a JSON value followed by trailing text
        #   * starts with "["     -> top-level array instead of object
        #   * starts with "{"     -> truncated/malformed JSON object
        #   * anything else       -> leading text or non-JSON output
        if exc.msg == "Extra data":
            return ParseFailure(
                raw_text,
                "leading_trailing_text",
                "output is not exactly one JSON object (extra text present)",
            )
        if stripped.startswith("["):
            return ParseFailure(raw_text, "not_an_object", "top-level JSON array")
        if stripped.startswith("{"):
            return ParseFailure(raw_text, "invalid_json", f"json error: {exc}")
        return ParseFailure(
            raw_text,
            "leading_trailing_text",
            "output is not exactly one JSON object (extra text present)",
        )

    if not isinstance(obj, dict):
        return ParseFailure(raw_text, "not_an_object", f"top-level JSON {type(obj).__name__}")

    kind = obj.get("type")
    if kind is None:
        return ParseFailure(raw_text, "missing_field", "missing top-level 'type'")
    if not isinstance(kind, str) or kind not in _ALLOWED_KEYS:
        return ParseFailure(
            raw_text, "unknown_type_value", f"type={kind!r} not in {sorted(_ALLOWED_KEYS)}"
        )

    keys = set(obj)
    extra = keys - _ALLOWED_KEYS[kind]
    if extra:
        return ParseFailure(raw_text, "extra_field", f"unexpected top-level keys {sorted(extra)}")
    missing = _REQUIRED_KEYS[kind] - keys
    if missing:
        return ParseFailure(raw_text, "missing_field", f"missing top-level keys {sorted(missing)}")

    if kind == "final":
        answer = obj["answer"]
        if not isinstance(answer, str):
            return ParseFailure(raw_text, "wrong_field_type", "'answer' must be a string")
        return ParsedOutput(kind="final", raw_text=raw_text, answer=answer)

    if kind == "clarify":
        question = obj["question"]
        if not isinstance(question, str):
            return ParseFailure(raw_text, "wrong_field_type", "'question' must be a string")
        return ParsedOutput(kind="clarify", raw_text=raw_text, question=question)

    # kind == "tool_call"
    tool = obj["tool"]
    if not isinstance(tool, str):
        return ParseFailure(raw_text, "wrong_field_type", "'tool' must be a string")
    spec = registry.get(tool)
    if spec is None:
        return ParseFailure(raw_text, "unknown_tool", f"tool {tool!r} not in registry")
    arguments = obj["arguments"]
    if not isinstance(arguments, dict):
        return ParseFailure(raw_text, "wrong_field_type", "'arguments' must be an object")

    for arg_name, arg_spec in spec.arguments.items():
        if arg_spec.required and arg_name not in arguments:
            return ParseFailure(
                raw_text, "missing_argument", f"tool {tool!r} requires argument {arg_name!r}"
            )
    for arg_name in arguments:
        if arg_name not in spec.arguments:
            return ParseFailure(
                raw_text, "extra_argument", f"tool {tool!r} has no argument {arg_name!r}"
            )
    for arg_name, value in arguments.items():
        expected = spec.arguments[arg_name].type
        if not _check_arg_type(value, expected):
            return ParseFailure(
                raw_text,
                "wrong_argument_type",
                f"argument {arg_name!r} of {tool!r}: expected {expected}, "
                f"got {type(value).__name__}",
            )

    return ParsedOutput(
        kind="tool_call", raw_text=raw_text, tool=tool, arguments=dict(arguments)
    )
