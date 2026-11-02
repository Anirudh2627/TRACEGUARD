"""Deterministic scripted mock backend.

Replays predefined raw completion strings so the full pipeline
(prompt building -> "generation" -> strict parsing -> scoring -> artifacts)
can be tested end-to-end without any model weights. This is the primary
vehicle for validating parser/scoring behavior (valid AND invalid outputs);
``tiny-random-gpt2`` only proves the transformers integration works, since a
random-weight model cannot produce protocol-valid JSON.

The mock never repairs or transforms the script: whatever string is scripted
is what the "model" emits, byte for byte.
"""

from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path
from typing import Any, Optional, Sequence, Union

from traceguard.models.generation import GenerationRecord, GenerationSettings


class ScriptedMockBackend:
    """Backend that returns scripted raw strings, one per generate() call."""

    name = "scripted_mock"

    def __init__(
        self,
        script: Sequence[str],
        settings: Optional[GenerationSettings] = None,
        simulated_latency: float = 0.0,
    ) -> None:
        if not script:
            raise ValueError("script must contain at least one response")
        self._script = list(script)
        self._index = 0
        self._settings = settings or GenerationSettings()
        self._latency = simulated_latency

    @classmethod
    def from_jsonl(
        cls,
        path: Union[str, Path],
        task_order: Sequence[str],
        settings: Optional[GenerationSettings] = None,
    ) -> "ScriptedMockBackend":
        """Load a script from JSONL: {"task_id": ..., "response": "<raw string>"}.

        Responses are ordered to match ``task_order``; every task must have an
        entry (missing entries are a hard error, not a silent skip).
        """
        by_task: dict[str, str] = {}
        with Path(path).open("r", encoding="utf-8") as fh:
            for line_no, line in enumerate(fh, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise ValueError(f"{path}:{line_no}: invalid JSON ({exc})") from exc
                if "task_id" not in entry or "response" not in entry:
                    raise ValueError(f"{path}:{line_no}: needs 'task_id' and 'response'")
                by_task[entry["task_id"]] = entry["response"]
        missing = [t for t in task_order if t not in by_task]
        if missing:
            raise ValueError(f"{path}: no scripted response for tasks {missing}")
        return cls([by_task[t] for t in task_order], settings=settings)

    def describe(self) -> dict[str, Any]:
        return {
            "backend": self.name,
            "model_id": None,
            "revision": None,
            "scripted_responses": len(self._script),
            "settings": asdict(self._settings),
        }

    def generate(self, messages: Sequence[dict[str, str]]) -> GenerationRecord:
        if self._index >= len(self._script):
            raise IndexError(
                f"ScriptedMockBackend exhausted after {len(self._script)} responses; "
                "the script must cover every task exactly once"
            )
        raw = self._script[self._index]
        self._index += 1
        return GenerationRecord(
            backend_name=self.name,
            model_id=None,
            revision=None,
            raw_text=raw,
            latency_seconds=self._latency,
            prompt_tokens=None,
            completion_tokens=None,
            renderer="mock",
            settings=asdict(self._settings),
            error=None,
        )
