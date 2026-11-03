"""Episode-result schema (DRAFT v0) — the logging contract for E0-E4 runs.

Status: **draft, pending Member-3 coordination** (see docs/GATEWAY_CONTRACT.md).
Field names mirror the provenance policy enum of the master prompt (§4) so
Member 3's runtime can emit these records with minimal mapping. Nothing here
fabricates outcomes: a record is a LOG (turns, gateway decisions, transcript);
deterministic episode outcomes are DERIVED from it by ``episode_scoring.py``.

Hard rules enforced at load time:
* ``schema_version`` must match exactly (no silent migration).
* ``placeholder`` is a REQUIRED field and must be an actual JSON boolean
  (missing/null/"false"/0/1 are rejected) so a malformed record can never be
  coerced past the placeholder banner; ``placeholder: true`` propagates into
  every downstream artifact.
* Gateway entries require the runtime-emitted ``sensitive_action`` boolean;
  the unauthorized-execution metric is scoped to sensitive actions (review R1).
* Benign ``expected`` structures (incl. every check object and kind) are
  fully validated at load time (review R3) — malformed checks are rejected,
  never silently treated as passing.
* ``split`` must be "dev" or "test"; loading a test split requires an
  explicit ``allow_test_split=True`` (held-out data is never touched by
  calibration; analysis of test results happens only after config freeze).
* All six configurations E0-E4 are valid; anything else is rejected.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional, Sequence, Union

SCHEMA_VERSION = "traceguard-episode-result@draft-v0"
VALID_CONFIGURATIONS = ("E0", "E1", "E2a", "E2b", "E3", "E4")
VALID_SPLITS = ("dev", "test")
VALID_EPISODE_KINDS = ("attack", "benign")
VALID_ATTACK_FAMILIES = ("A", "B", "C")
VALID_DECISIONS = ("ALLOWED", "BLOCKED", "NOT_ENFORCED")
#: Authorization bases per the provenance policy; a sensitive action is
#: authorized ONLY by these (master prompt §4 rules 8-9: the model cannot
#: authorize itself; UNKNOWN is never trusted).
TRUSTED_AUTHORIZATION_BASES = ("USER_AUTHORIZED", "SYSTEM_CONFIG", "SYSTEM_POLICY")
PROVENANCE_ENUM = (
    "SYSTEM_POLICY",
    "SYSTEM_CONFIG",
    "USER_AUTHORIZED",
    "UNTRUSTED_EXTERNAL",
    "DERIVED_UNTRUSTED",
    "UNKNOWN",
)


class SchemaError(ValueError):
    """A record violates the episode-result schema (never coerced silently)."""


class HeldOutDataError(ValueError):
    """Test-split data loaded without the explicit post-freeze flag."""


@dataclass(frozen=True)
class EpisodeResult:
    """One validated episode-result record (a LOG, not a verdict)."""

    schema_version: str
    experiment_id: str
    configuration: str
    model_id: str
    model_revision: Optional[str]
    split: str
    dataset_version: str
    prompt_mode: str
    episode_id: str
    episode_kind: str
    attack_family: Optional[str]
    placeholder: bool
    turns: tuple[dict[str, Any], ...]
    gateway_log: tuple[dict[str, Any], ...]
    transcript: tuple[dict[str, Any], ...]
    canaries: tuple[dict[str, Any], ...] = ()
    prohibited_actions: tuple[dict[str, Any], ...] = ()
    expected: Optional[dict[str, Any]] = None
    latency_seconds: float = 0.0
    prompt_tokens: Optional[int] = None
    completion_tokens: Optional[int] = None
    safetune: Optional[dict[str, Any]] = None
    provenance_events: tuple[dict[str, Any], ...] = ()
    raw: dict[str, Any] = field(default_factory=dict, repr=False)


def _require(doc: dict[str, Any], key: str, episode_id: str) -> Any:
    if key not in doc:
        raise SchemaError(f"episode {episode_id!r}: missing required field {key!r}")
    return doc[key]


def _as_tuple(value: Any, key: str, episode_id: str) -> tuple[dict[str, Any], ...]:
    if value is None:
        return ()
    if not isinstance(value, list):
        raise SchemaError(f"episode {episode_id!r}: field {key!r} must be a list")
    for i, item in enumerate(value):
        if not isinstance(item, dict):
            raise SchemaError(f"episode {episode_id!r}: {key}[{i}] must be an object")
    return tuple(value)


def validate_gateway_entry(entry: dict[str, Any], episode_id: str, index: int) -> None:
    """Validate one gateway/authorization-ledger entry (the Member-3 surface)."""
    where = f"episode {episode_id!r} gateway_log[{index}]"
    for key in ("tool", "decision", "executed", "authorization_basis", "sensitive_action"):
        if key not in entry:
            raise SchemaError(f"{where}: missing required field {key!r}")
    if entry["decision"] not in VALID_DECISIONS:
        raise SchemaError(
            f"{where}: decision {entry['decision']!r} not in {VALID_DECISIONS}"
        )
    if not isinstance(entry["executed"], bool):
        raise SchemaError(f"{where}: 'executed' must be a boolean")
    if not isinstance(entry["sensitive_action"], bool):
        raise SchemaError(
            f"{where}: 'sensitive_action' must be a JSON boolean "
            "(emitted by the runtime from the tool registry; a read/search tool "
            "is False, an action requiring authorization is True)"
        )
    basis = entry["authorization_basis"]
    if basis is not None and basis not in PROVENANCE_ENUM:
        raise SchemaError(f"{where}: authorization_basis {basis!r} not in policy enum")
    for label in entry.get("argument_provenance", {}).values():
        if label not in PROVENANCE_ENUM:
            raise SchemaError(f"{where}: argument_provenance label {label!r} invalid")
    # Consistency: E0 has no gateway, so its entries must be NOT_ENFORCED.
    # (Cross-checked against configuration at record level.)


#: Deterministic check kinds supported by episode_scoring (contract §4).
CHECK_KIND_REQUIRED_FIELDS = {
    "tool_executed": ("tool",),
    "no_tool_executed": (),
    "assistant_text_contains": ("text",),
}


def validate_expected(expected: Any, episode_id: str) -> None:
    """Validate the full benign ``expected`` structure at load time.

    Malformed structures are REJECTED here — episode_scoring must never see an
    invalid check (and therefore can never silently treat one as passing).
    """
    where = f"episode {episode_id!r} 'expected'"
    if not isinstance(expected, dict):
        raise SchemaError(f"{where}: must be an object")
    tool = expected.get("expected_tool")
    if tool is not None and not isinstance(tool, str):
        raise SchemaError(f"{where}: 'expected_tool' must be a string or null")
    if "checks" not in expected:
        return
    checks = expected["checks"]
    if not isinstance(checks, list):
        raise SchemaError(f"{where}: 'checks' must be a list when supplied")
    for i, check in enumerate(checks):
        cwhere = f"{where}.checks[{i}]"
        if not isinstance(check, dict):
            raise SchemaError(f"{cwhere}: must be an object")
        kind = check.get("kind")
        if kind not in CHECK_KIND_REQUIRED_FIELDS:
            raise SchemaError(
                f"{cwhere}: kind {kind!r} not in "
                f"{sorted(CHECK_KIND_REQUIRED_FIELDS)}"
            )
        for field_name in CHECK_KIND_REQUIRED_FIELDS[kind]:
            if field_name not in check or not isinstance(check[field_name], str):
                raise SchemaError(
                    f"{cwhere}: kind {kind!r} requires string field {field_name!r}"
                )
        unknown = set(check) - {"kind", *CHECK_KIND_REQUIRED_FIELDS[kind]}
        if unknown:
            raise SchemaError(f"{cwhere}: unexpected fields {sorted(unknown)}")


def validate_record(doc: dict[str, Any], allow_test_split: bool = False) -> EpisodeResult:
    """Validate one episode-result dict; return the typed record or raise."""
    if not isinstance(doc, dict):
        raise SchemaError(f"record must be an object, got {type(doc).__name__}")

    episode_id = str(doc.get("episode_id", "<missing>"))
    version = _require(doc, "schema_version", episode_id)
    if version != SCHEMA_VERSION:
        raise SchemaError(
            f"episode {episode_id!r}: schema_version {version!r} != {SCHEMA_VERSION!r} "
            "(no silent migration — regenerate the record)"
        )

    configuration = str(_require(doc, "configuration", episode_id))
    if configuration not in VALID_CONFIGURATIONS:
        raise SchemaError(
            f"episode {episode_id!r}: configuration {configuration!r} not in {VALID_CONFIGURATIONS}"
        )
    split = str(_require(doc, "split", episode_id))
    if split not in VALID_SPLITS:
        raise SchemaError(f"episode {episode_id!r}: split {split!r} not in {VALID_SPLITS}")
    if split == "test" and not allow_test_split:
        raise HeldOutDataError(
            f"episode {episode_id!r}: refusing to load split='test' without "
            "allow_test_split=True (held-out data is analyzed only after the "
            "configuration freeze; calibration must never see it)"
        )
    kind = str(_require(doc, "episode_kind", episode_id))
    if kind not in VALID_EPISODE_KINDS:
        raise SchemaError(f"episode {episode_id!r}: episode_kind {kind!r} invalid")

    family = doc.get("attack_family")
    if kind == "attack":
        if family not in VALID_ATTACK_FAMILIES:
            raise SchemaError(
                f"episode {episode_id!r}: attack episodes require attack_family in {VALID_ATTACK_FAMILIES}"
            )
    elif family is not None:
        raise SchemaError(f"episode {episode_id!r}: benign episodes must not carry attack_family")

    # placeholder is REQUIRED and must be an actual JSON boolean: missing,
    # null, "false" (string), or 0/1 (numeric) are all rejected so a malformed
    # record can never slip past the placeholder banner by coercion.
    if "placeholder" not in doc:
        raise SchemaError(
            f"episode {episode_id!r}: missing required field 'placeholder' "
            "(explicit true/false JSON boolean required — no default)"
        )
    if not isinstance(doc["placeholder"], bool):
        raise SchemaError(
            f"episode {episode_id!r}: 'placeholder' must be a JSON boolean, "
            f"got {type(doc['placeholder']).__name__} ({doc['placeholder']!r})"
        )
    placeholder = doc["placeholder"]
    prompt_mode = str(_require(doc, "prompt_mode", episode_id))

    turns = _as_tuple(_require(doc, "turns", episode_id), "turns", episode_id)
    gateway_log = _as_tuple(doc.get("gateway_log"), "gateway_log", episode_id)
    for i, entry in enumerate(gateway_log):
        validate_gateway_entry(entry, episode_id, i)
    # E0 consistency: baseline has NO gateway; any entry must be NOT_ENFORCED.
    if configuration == "E0":
        for i, entry in enumerate(gateway_log):
            if entry["decision"] != "NOT_ENFORCED":
                raise SchemaError(
                    f"episode {episode_id!r} gateway_log[{i}]: E0 has no gateway; "
                    f"decision must be NOT_ENFORCED, got {entry['decision']!r}"
                )
    # Gateway configurations must record decisions for sensitive attempts.
    transcript = _as_tuple(doc.get("transcript"), "transcript", episode_id)
    canaries = _as_tuple(doc.get("canaries"), "canaries", episode_id)
    for i, canary in enumerate(canaries):
        if "value" not in canary:
            raise SchemaError(f"episode {episode_id!r}: canaries[{i}] missing 'value'")
    prohibited = _as_tuple(doc.get("prohibited_actions"), "prohibited_actions", episode_id)
    provenance_events = _as_tuple(
        doc.get("provenance_events"), "provenance_events", episode_id
    )
    if kind == "benign" and doc.get("expected") is None:
        raise SchemaError(
            f"episode {episode_id!r}: benign episodes require deterministic 'expected'"
        )
    if doc.get("expected") is not None:
        validate_expected(doc["expected"], episode_id)

    return EpisodeResult(
        schema_version=version,
        experiment_id=str(_require(doc, "experiment_id", episode_id)),
        configuration=configuration,
        model_id=str(_require(doc, "model_id", episode_id)),
        model_revision=doc.get("model_revision"),
        split=split,
        dataset_version=str(_require(doc, "dataset_version", episode_id)),
        prompt_mode=prompt_mode,
        episode_id=episode_id,
        episode_kind=kind,
        attack_family=family,
        placeholder=placeholder,
        turns=turns,
        gateway_log=gateway_log,
        transcript=transcript,
        canaries=canaries,
        prohibited_actions=prohibited,
        expected=doc.get("expected"),
        latency_seconds=float(doc.get("latency_seconds", 0.0)),
        prompt_tokens=doc.get("prompt_tokens"),
        completion_tokens=doc.get("completion_tokens"),
        safetune=doc.get("safetune"),
        provenance_events=provenance_events,
        raw=doc,
    )


def load_episode_results(
    path: Union[str, Path],
    allow_test_split: bool = False,
) -> list[EpisodeResult]:
    """Load and validate a JSONL file of episode results."""
    path = Path(path)
    records: list[EpisodeResult] = []
    with path.open("r", encoding="utf-8") as fh:
        for line_no, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            try:
                doc = json.loads(line)
            except json.JSONDecodeError as exc:
                raise SchemaError(f"{path}:{line_no}: invalid JSON ({exc})") from exc
            records.append(validate_record(doc, allow_test_split=allow_test_split))
    if not records:
        raise SchemaError(f"{path}: no records")
    return records


def check_homogeneous(
    records: Sequence[EpisodeResult], context: str
) -> dict[str, Any]:
    """Enforce that one analysis input varies nothing but the configuration.

    Returns the common identity dict. Raises SchemaError on any mixture
    (splits, dataset versions, models, schema versions) — comparisons across
    mixed inputs would be meaningless.
    """
    first = records[0]
    identity = {
        "schema_version": first.schema_version,
        "split": first.split,
        "dataset_version": first.dataset_version,
        "model_id": first.model_id,
        "model_revision": first.model_revision,
    }
    for rec in records[1:]:
        for key, want in identity.items():
            got = getattr(rec, key)
            if got != want:
                raise SchemaError(
                    f"{context}: mixed {key} ({want!r} vs {got!r} in episode "
                    f"{rec.episode_id!r}) — one analysis input must hold "
                    "everything constant except the configuration"
                )
    return identity
