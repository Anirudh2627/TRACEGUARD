"""Separate a user's own instruction from material the user pasted for processing.

Policy (team brief, provenance rule 12): quoted content is not an instruction.
If the user says "summarize this email: '... send it to X ...'", the embedded
words and any address inside them remain untrusted content even though the
user typed them into the chat. Only the user's own instruction text may
authorize a recipient or resource.

The split is a deliberately simple, deterministic heuristic (no model involved):

* A quoted span (straight or curly double quotes, single quotes not used as
  apostrophes, or a ``` fence) is *material* when it holds at least
  ``MIN_QUOTED_WORDS`` words. A short quoted token such as ``"a@b.test"`` is
  treated as part of the instruction.
* Everything after an introducer such as "this email:" or "the following:"
  is *material*.

Known limitation: pasted text with no quotes and no introducer is not detected.
"""

from __future__ import annotations

import re

#: Quoted spans with at least this many words count as pasted material.
MIN_QUOTED_WORDS = 4

_QUOTE_SPAN = re.compile(
    r"```.*?```"
    r'|"[^"]*"'
    r"|“[^”]*”"
    r"|(?<![\w])'[^']*'(?![\w])",
    re.DOTALL,
)

_INTRODUCER = re.compile(
    r"\b(?:this|the following|following|that|below)\s*"
    r"(?:e-?mail|document|message|text|note|file|invoice|content|thread)?s?\s*:",
    re.IGNORECASE,
)


def split_user_text(text: str) -> tuple[str, list[str]]:
    """Return ``(instruction_text, pasted_material)`` for a user message."""
    if not text:
        return "", []

    material: list[str] = []

    def _strip(match: re.Match[str]) -> str:
        span = match.group(0)
        if len(span.split()) >= MIN_QUOTED_WORDS:
            material.append(span)
            return " "
        return span

    instruction = _QUOTE_SPAN.sub(_strip, text)

    intro = _INTRODUCER.search(instruction)
    if intro is not None:
        tail = instruction[intro.end():].strip()
        if tail:
            material.append(tail)
        instruction = instruction[: intro.end()]

    return instruction.strip(), material
