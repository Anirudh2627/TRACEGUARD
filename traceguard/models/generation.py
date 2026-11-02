"""Generation backends and the :class:`GenerationRecord` measurement wrapper.

A backend turns a chat-message list into one raw completion plus measurement
metadata (latency, token counts). Two implementations:

* :class:`TransformersBackend` — real greedy decoding (``do_sample=False``)
  with ``torch.no_grad`` and ``model.eval()``; deterministic settings are
  pinned by construction, callers cannot silently enable sampling.
* :class:`ScriptedMockBackend` (see ``mock_backend.py``) — replays predefined
  raw strings for deterministic testing of the parser/scoring pipeline.

Errors are captured into the record (``error`` field), never swallowed and
never converted into fake successes.
"""

from __future__ import annotations

import logging
import time
from dataclasses import asdict, dataclass, field
from typing import Any, Optional, Protocol, Sequence

from traceguard.models.prompt_builder import RenderedPrompt, render_prompt

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class GenerationSettings:
    """Deterministic generation configuration recorded in every manifest."""

    max_new_tokens: int = 512
    do_sample: bool = False
    temperature: Optional[float] = None
    top_p: Optional[float] = None
    seed: int = 1234

    def __post_init__(self) -> None:
        if self.do_sample:
            raise ValueError(
                "TraceGuard smoke/experiment runs require greedy decoding "
                "(do_sample=False) for determinism"
            )
        if self.temperature is not None or self.top_p is not None:
            raise ValueError("temperature/top_p must be None with greedy decoding")


@dataclass(frozen=True)
class GenerationRecord:
    """One raw model output plus measurement metadata."""

    backend_name: str
    model_id: Optional[str]
    revision: Optional[str]
    raw_text: str
    latency_seconds: float
    prompt_tokens: Optional[int]
    completion_tokens: Optional[int]
    renderer: Optional[str]
    settings: dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class GenerationBackend(Protocol):
    """Interface every backend must satisfy (mock and real alike)."""

    name: str

    def generate(self, messages: Sequence[dict[str, str]]) -> GenerationRecord:
        """Produce one completion for the given chat messages."""
        ...

    def describe(self) -> dict[str, Any]:
        """Manifest-friendly description (model id, revision, device, dtype)."""
        ...


class TransformersBackend:
    """Greedy Hugging Face Transformers backend.

    Construction takes an already-loaded ``(model, tokenizer)`` pair so that
    loading policy (device/dtype/quantization/token) stays in ``loader.py``.
    """

    name = "transformers"

    def __init__(
        self,
        model: Any,
        tokenizer: Any,
        model_id: str,
        revision: Optional[str],
        settings: GenerationSettings,
        device: str,
        dtype: str,
        prompt_truncation: Optional[int] = None,
    ) -> None:
        self._model = model
        self._tokenizer = tokenizer
        self._model_id = model_id
        self._revision = revision
        self._settings = settings
        self._device = device
        self._dtype = dtype
        self._prompt_truncation = prompt_truncation
        self._context_limit = self._resolve_context_limit(model, tokenizer)
        self._model.eval()

    @staticmethod
    def _resolve_context_limit(model: Any, tokenizer: Any) -> Optional[int]:
        """Best-effort context window from the model config (None if unknown)."""
        config = getattr(model, "config", None)
        for attr in ("max_position_embeddings", "n_positions"):
            value = getattr(config, attr, None)
            if isinstance(value, int) and value > 0:
                return value
        limit = getattr(tokenizer, "model_max_length", None)
        if isinstance(limit, int) and 0 < limit < 10**8:
            return limit
        return None

    @property
    def tokenizer(self) -> Any:
        return self._tokenizer

    @property
    def model(self) -> Any:
        """The underlying nn.Module (needed e.g. for SafeTune hook installation)."""
        return self._model

    def describe(self) -> dict[str, Any]:
        return {
            "backend": self.name,
            "model_id": self._model_id,
            "revision": self._revision,
            "device": self._device,
            "dtype": self._dtype,
            "has_chat_template": bool(getattr(self._tokenizer, "chat_template", None)),
            "context_limit": self._context_limit,
            "settings": asdict(self._settings),
        }

    def generate(self, messages: Sequence[dict[str, str]]) -> GenerationRecord:
        import torch  # local import: keeps mock-only runs torch-free

        rendered: RenderedPrompt = render_prompt(messages, self._tokenizer)
        base: dict[str, Any] = dict(
            backend_name=self.name,
            model_id=self._model_id,
            revision=self._revision,
            renderer=rendered.renderer,
            settings=asdict(self._settings),
        )
        try:
            inputs = self._tokenizer(rendered.text, return_tensors="pt")
            input_ids = inputs["input_ids"].to(self._model.device)
            prompt_tokens = int(input_ids.shape[1])
            if (
                self._prompt_truncation is not None
                and prompt_tokens > self._prompt_truncation
            ):
                # EXPLICIT, opt-in, logged truncation for small-context probe
                # models only (keeps the first N tokens). Off by default; real
                # runs must never need it. Recorded in the output settings.
                logger.warning(
                    "truncating prompt from %d to %d tokens (prompt_truncation "
                    "enabled; model=%s)",
                    prompt_tokens,
                    self._prompt_truncation,
                    self._model_id,
                )
                input_ids = input_ids[:, : self._prompt_truncation]
                prompt_tokens = int(input_ids.shape[1])
                base["settings"] = {
                    **base["settings"],
                    "prompt_truncation": self._prompt_truncation,
                }
            if self._context_limit is not None and prompt_tokens > self._context_limit:
                # Explicit, auditable failure — never silently truncate inputs.
                error = (
                    f"prompt_exceeds_context: {prompt_tokens} prompt tokens > "
                    f"{self._context_limit} model context"
                )
                logger.error("%s (model=%s)", error, self._model_id)
                return GenerationRecord(
                    raw_text="",
                    latency_seconds=0.0,
                    prompt_tokens=prompt_tokens,
                    completion_tokens=0,
                    error=error,
                    **base,
                )
            gen_kwargs: dict[str, Any] = dict(
                max_new_tokens=self._settings.max_new_tokens,
                do_sample=False,
                pad_token_id=self._tokenizer.pad_token_id
                if self._tokenizer.pad_token_id is not None
                else self._tokenizer.eos_token_id,
            )
            start = time.perf_counter()
            with torch.no_grad():
                output_ids = self._model.generate(input_ids, **gen_kwargs)
            latency = time.perf_counter() - start
            new_tokens = output_ids[0][prompt_tokens:]
            raw_text = self._tokenizer.decode(new_tokens, skip_special_tokens=True)
            return GenerationRecord(
                raw_text=raw_text,
                latency_seconds=round(latency, 4),
                prompt_tokens=prompt_tokens,
                completion_tokens=int(new_tokens.shape[0]),
                error=None,
                **base,
            )
        except Exception as exc:  # captured, logged, surfaced — never faked
            logger.exception("generation failed for model=%s", self._model_id)
            return GenerationRecord(
                raw_text="",
                latency_seconds=0.0,
                prompt_tokens=None,
                completion_tokens=None,
                error=f"{type(exc).__name__}: {exc}",
                **base,
            )
