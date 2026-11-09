"""CircuitKIT interpretability experiment execution harness for TraceGuard.

Implements contrastive dataset loading, strict split guarding, CSV conversion for
CircuitKIT, pipeline adapter management, and transparent results reporting.
"""

from __future__ import annotations

import csv
import dataclasses
import hashlib
import json
import logging
import platform
import time
from pathlib import Path
from typing import Any, Optional

from traceguard.experiments.circuit_config import CircuitExperimentConfig
from traceguard.experiments.circuit_results import (
    CircuitExperimentSummary,
    CircuitStatus,
    DiscoveryResult,
    FaithfulnessResult,
    InterventionResult,
)

logger = logging.getLogger(__name__)

DEFAULT_DEV_PATH = Path("traceguard/data/circuit/contrastive_dev.jsonl")
DEFAULT_TEST_PATH = Path("traceguard/data/circuit/contrastive_test.jsonl")

REQUIRED_CONTRASTIVE_FIELDS = [
    "example_id",
    "template_id",
    "split",
    "attack_family",
    "clean_prompt",
    "clean_answer",
    "corrupt_prompt",
    "corrupt_answer",
]

CANONICAL_PROVENANCE_LABELS = frozenset(
    {
        "SYSTEM_POLICY",
        "SYSTEM_CONFIG",
        "USER_AUTHORIZED",
        "UNTRUSTED_EXTERNAL",
        "DERIVED_UNTRUSTED",
        "UNKNOWN",
    }
)


def compute_dataset_hash(records_or_path: list[dict[str, Any]] | str | Path) -> str:
    """Compute a deterministic SHA-256 hash for a contrastive dataset."""
    if isinstance(records_or_path, (str, Path)):
        p = Path(records_or_path)
        if not p.exists():
            raise FileNotFoundError(f"Dataset file not found: {p}")
        records = load_contrastive_dataset(p)
    else:
        records = records_or_path

    canonical_reprs = []
    for r in records:
        canonical_dict = {k: r.get(k) for k in sorted(r.keys())}
        canonical_reprs.append(json.dumps(canonical_dict, sort_keys=True))

    combined = "\n".join(canonical_reprs).encode("utf-8")
    return hashlib.sha256(combined).hexdigest()


def verify_template_disjointness(
    dev_records: list[dict[str, Any]], test_records: list[dict[str, Any]]
) -> tuple[bool, set[str]]:
    """Verify that dev and test datasets share zero template IDs.

    Returns:
        (is_disjoint, overlapping_templates_set)
    """
    dev_templates = {str(r.get("template_id")) for r in dev_records if r.get("template_id")}
    test_templates = {str(r.get("template_id")) for r in test_records if r.get("template_id")}
    overlap = dev_templates.intersection(test_templates)
    return len(overlap) == 0, overlap


def load_contrastive_dataset(
    path: str | Path, expected_split: Optional[str] = None
) -> list[dict[str, Any]]:
    """Load a contrastive JSONL dataset and validate required fields and split."""
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Contrastive dataset not found at {p}")

    records: list[dict[str, Any]] = []
    with open(p, "r", encoding="utf-8") as f:
        for line_idx, line in enumerate(f, 1):
            line_str = line.strip()
            if not line_str:
                continue
            try:
                data = json.loads(line_str)
            except json.JSONDecodeError as e:
                raise ValueError(f"Invalid JSON at line {line_idx} in {p}: {e}")

            for field_name in REQUIRED_CONTRASTIVE_FIELDS:
                if field_name not in data or data[field_name] is None:
                    raise ValueError(
                        f"Missing required field '{field_name}' at line {line_idx} in {p}"
                    )

            if expected_split and data.get("split") != expected_split:
                raise ValueError(
                    f"Record split mismatch at line {line_idx} in {p}: "
                    f"expected '{expected_split}', found '{data.get('split')}'"
                )

            # Validate canonical provenance labels
            if "expected_provenance" in data and isinstance(data["expected_provenance"], dict):
                for src_key, prov_val in data["expected_provenance"].items():
                    if prov_val not in CANONICAL_PROVENANCE_LABELS:
                        raise ValueError(
                            f"Invalid provenance label '{prov_val}' for source '{src_key}' at line {line_idx} in {p}. "
                            f"Canonical labels are: {sorted(CANONICAL_PROVENANCE_LABELS)}"
                        )

            records.append(data)

    if not records:
        raise ValueError(f"Contrastive dataset at {p} contains zero valid records")

    return records


def export_contrastive_to_csv(
    records: list[dict[str, Any]], csv_path: str | Path
) -> Path:
    """Export contrastive records to a CSV file suitable for CircuitKIT Pipeline.from_custom_data."""
    out_path = Path(csv_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    fieldnames = [
        "clean_prompt",
        "clean_answer",
        "corrupt_prompt",
        "corrupt_answer",
        "example_id",
        "template_id",
        "split",
        "attack_family",
    ]

    with open(out_path, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for r in records:
            writer.writerow(r)

    return out_path


def resolve_circuit_precision(
    requested_precision: Optional[str] = "auto",
    device: Optional[str] = None,
) -> tuple[str, str, dict[str, Any]]:
    """Resolve hardware device and precision dtype for CircuitKIT experiments.

    Args:
        requested_precision: 'auto' (default), 'bfloat16', 'float16', or 'float32'.
        device: 'auto' (or None), 'cuda', or 'cpu'.

    Returns:
        (resolved_device, resolved_precision, hardware_info_dict)
    """
    import torch
    from traceguard.models.loader import cuda_supports_bf16

    cuda_avail = torch.cuda.is_available()
    if device is None or device == "auto":
        target_device = "cuda" if cuda_avail else "cpu"
    else:
        target_device = device.lower()

    if target_device not in ("cuda", "cpu"):
        raise ValueError(f"Unsupported device '{device}'. Must be 'auto', 'cuda', or 'cpu'")

    bf16_supported = cuda_supports_bf16() if cuda_avail else False
    device_name = torch.cuda.get_device_name(0) if cuda_avail and target_device == "cuda" else "CPU"
    device_capability = None
    if cuda_avail and target_device == "cuda":
        try:
            device_capability = torch.cuda.get_device_capability()
        except Exception:
            device_capability = None

    req = (requested_precision or "auto").lower()

    if target_device == "cuda":
        if not cuda_avail:
            raise RuntimeError("CUDA device requested but torch.cuda.is_available() is False")

        if req == "auto":
            resolved_precision = "bfloat16" if bf16_supported else "float16"
        elif req == "bfloat16":
            if not bf16_supported:
                raise ValueError(
                    f"Explicit precision 'bfloat16' is not supported on CUDA device '{device_name}' "
                    f"(compute capability {device_capability} < 8.0). Use 'float16' or 'auto'."
                )
            resolved_precision = "bfloat16"
        elif req in ("float16", "float32"):
            resolved_precision = req
        else:
            raise ValueError(f"Unsupported precision '{requested_precision}' for CUDA device")

    else:  # CPU
        if req == "auto":
            resolved_precision = "float32"
        elif req == "float32":
            resolved_precision = "float32"
        elif req == "bfloat16":
            resolved_precision = "bfloat16"
        elif req == "float16":
            raise ValueError("Explicit precision 'float16' is not supported for CPU execution in PyTorch")
        else:
            raise ValueError(f"Unsupported precision '{requested_precision}' for CPU device")

    hardware_info = {
        "device": target_device,
        "device_name": device_name,
        "cuda_available": cuda_avail,
        "cuda_supports_bf16": bf16_supported,
        "device_capability": device_capability,
        "selected_precision": resolved_precision,
        "requested_precision": requested_precision,
    }

    return target_device, resolved_precision, hardware_info


class CircuitKITAdapter:
    """Adapter for inspecting environment capabilities and wrapping CircuitKIT APIs."""

    @staticmethod
    def is_circuitkit_available() -> bool:
        """Check if circuitkit is installed and exposes Pipeline."""
        try:
            import circuitkit
            return hasattr(circuitkit, "Pipeline")
        except ImportError:
            return False

    @staticmethod
    def check_environment() -> dict[str, Any]:
        """Inspect and return runtime environment information."""
        info: dict[str, Any] = {
            "platform": platform.platform(),
            "python_version": platform.python_version(),
            "circuitkit_available": False,
            "circuitkit_version": None,
            "torch_available": False,
            "torch_version": None,
            "cuda_available": False,
            "cuda_supports_bf16": False,
            "cuda_capability": None,
            "device": "cpu",
        }

        try:
            import circuitkit
            info["circuitkit_available"] = True
            info["circuitkit_version"] = getattr(circuitkit, "__version__", "unknown")
        except ImportError:
            pass

        try:
            import torch
            from traceguard.models.loader import cuda_supports_bf16

            info["torch_available"] = True
            info["torch_version"] = torch.__version__
            info["cuda_available"] = torch.cuda.is_available()
            info["cuda_supports_bf16"] = cuda_supports_bf16() if torch.cuda.is_available() else False
            if torch.cuda.is_available():
                info["device"] = f"cuda ({torch.cuda.get_device_name(0)})"
                try:
                    info["cuda_capability"] = torch.cuda.get_device_capability()
                except Exception:
                    info["cuda_capability"] = None
        except ImportError:
            pass

        return info

    @staticmethod
    def build_pipeline_from_csv(
        model_name: str,
        csv_path: str | Path,
        output_dir: str = "results/circuit",
        precision: str = "bfloat16",
        device: Optional[str] = None,
        task_name: Optional[str] = None,
        model_revision: Optional[str] = None,
    ) -> Any:
        """Construct a CircuitKIT Pipeline from a contrastive CSV file with exact revision pinning."""
        from circuitkit import Pipeline

        pipe = Pipeline.from_custom_data(
            model_name=model_name,
            data_path=str(csv_path),
            clean_prompt="{clean_prompt}",
            clean_answer="{clean_answer}",
            corrupt_prompt="{corrupt_prompt}",
            corrupt_answer="{corrupt_answer}",
            task_name=task_name or f"traceguard_contrastive_{Path(csv_path).stem}",
            precision=precision,
            device=device,
            output_dir=output_dir,
        )
        pipe.model_revision = model_revision

        # Propagate exact revision into CircuitKIT model loader
        if model_revision:
            orig_ensure = pipe._ensure_model

            def pinned_ensure_model() -> Any:
                if pipe._model is None:
                    from circuitkit import quick

                    pipe._model = quick.load_model(
                        pipe.model_name,
                        dtype=pipe.precision,
                        device=pipe._device,
                        revision=model_revision,
                    )
                return pipe._model

            pipe._ensure_model = pinned_ensure_model

        return pipe

    @staticmethod
    def register_custom_task(
        model: Any,
        csv_path: str | Path,
        task_name: Optional[str] = None,
        algorithm: str = "eap-ig",
    ) -> str:
        """Register a custom CSV dataset as a CircuitKIT task using CircuitKIT's prepare_custom_task."""
        from circuitkit.api import prepare_custom_task

        csv_p = Path(csv_path)
        if not csv_p.exists():
            raise FileNotFoundError(f"Custom task CSV not found at {csv_p}")

        derived_name = task_name or f"traceguard_contrastive_{csv_p.stem}"
        cfg = {
            "data": {
                "type": "template",
                "path": str(csv_p),
                "template": {
                    "clean_prompt": "{clean_prompt}",
                    "clean_answer": "{clean_answer}",
                    "corrupt_prompt": "{corrupt_prompt}",
                    "corrupt_answer": "{corrupt_answer}",
                },
            },
            "discovery": {
                "algorithm": algorithm,
            },
        }

        registered_name = prepare_custom_task(cfg, model, task_name=derived_name)
        return registered_name


class CircuitExperimentRunner:
    """Executes circuit discovery, faithfulness evaluations, and interventions."""

    def __init__(
        self,
        dev_dataset_path: Optional[str | Path] = None,
        test_dataset_path: Optional[str | Path] = None,
    ) -> None:
        self.dev_path = Path(dev_dataset_path or DEFAULT_DEV_PATH)
        self.test_path = Path(test_dataset_path or DEFAULT_TEST_PATH)

    def validate_datasets(self) -> dict[str, Any]:
        """Validate both dev and test contrastive datasets and verify split disjointness."""
        dev_records = load_contrastive_dataset(self.dev_path, expected_split="dev")
        test_records = load_contrastive_dataset(self.test_path, expected_split="test")

        dev_hash = compute_dataset_hash(dev_records)
        test_hash = compute_dataset_hash(test_records)

        is_disjoint, overlap = verify_template_disjointness(dev_records, test_records)
        if not is_disjoint:
            raise ValueError(
                f"Split leakage detected! Overlapping template IDs between dev and test: {overlap}"
            )

        dev_families = {}
        for r in dev_records:
            fam = r.get("attack_family", "unknown")
            dev_families[fam] = dev_families.get(fam, 0) + 1

        test_families = {}
        for r in test_records:
            fam = r.get("attack_family", "unknown")
            test_families[fam] = test_families.get(fam, 0) + 1

        return {
            "status": "PASSED",
            "dev_path": str(self.dev_path),
            "test_path": str(self.test_path),
            "dev_count": len(dev_records),
            "test_count": len(test_records),
            "dev_hash": dev_hash,
            "test_hash": test_hash,
            "dev_families": dev_families,
            "test_families": test_families,
            "template_disjoint": True,
            "overlapping_templates": [],
        }

    def run(
        self,
        config: CircuitExperimentConfig,
        pipeline: Optional[Any] = None,
    ) -> CircuitExperimentSummary:
        """Run the circuit experiment according to configuration.

        If pipeline is None (no model connected), produces an honest NOT_RUN summary.
        If pipeline or mock pipeline is provided, executes discovery and faithfulness.
        """
        # Validate datasets and ensure split guard is intact
        self.validate_datasets()

        # Resolve hardware device and precision
        resolved_device, resolved_precision, hw_info = resolve_circuit_precision(
            requested_precision=config.precision,
            device=config.device,
        )
        config.precision = resolved_precision
        config.device = resolved_device

        # Split guard rule: Circuit discovery MUST strictly and exclusively consume development data.
        # Held-out test data is reserved exclusively for post-discovery evaluation.
        dev_records = load_contrastive_dataset(self.dev_path, expected_split="dev")
        dev_hash = compute_dataset_hash(dev_records)

        output_dir = Path(config.output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        dev_csv_file = output_dir / "contrastive_dev.csv"
        export_contrastive_to_csv(dev_records, dev_csv_file)

        # Target evaluation records (dev or test)
        if config.split == "test":
            if not self.test_path.exists():
                raise FileNotFoundError(f"Held-out test dataset not found at {self.test_path}")
            eval_records = load_contrastive_dataset(self.test_path, expected_split="test")
            if len(eval_records) == 0:
                raise ValueError(f"Held-out test dataset at {self.test_path} contains 0 records")
            eval_hash = compute_dataset_hash(eval_records)
            eval_csv_file = output_dir / "contrastive_test.csv"
            export_contrastive_to_csv(eval_records, eval_csv_file)
        else:
            eval_records = dev_records
            eval_hash = dev_hash
            eval_csv_file = dev_csv_file

        target_records = eval_records
        dataset_hash = eval_hash

        # Case 1: No pipeline / model supplied (Member 1 awaiting integration / offline CPU)
        is_mock = isinstance(pipeline, MockCircuitPipeline) or getattr(pipeline, "_is_mock", False)
        is_cpu_offline = not hw_info["cuda_available"]
        no_model_supplied = not config.model_name or config.model_name.strip() == ""

        if pipeline is None and (no_model_supplied or config.dry_run or is_cpu_offline):
            notes_reason = (
                "Real model not supplied; awaiting Member 1 model connection on GPU (Track B)"
                if not no_model_supplied
                else "Real model not supplied; awaiting Member 1 model connection"
            )
            discovery_result = DiscoveryResult(
                status=CircuitStatus.NOT_RUN.value,
                algorithm=config.algorithm,
                level=config.level,
                target_sparsity=config.sparsity,
                error_message=notes_reason,
                metadata={
                    "split": config.split,
                    "dataset_hash": dataset_hash,
                    "discovery_dataset": "contrastive_dev",
                    "discovery_hash": dev_hash,
                    "test_data_in_discovery": False,
                    "model_name": config.model_name,
                    "model_revision": config.model_revision,
                    "hardware": hw_info,
                },
            )

            faithfulness_result = FaithfulnessResult(
                status=CircuitStatus.NOT_RUN.value,
                pillars_evaluated=list(config.pillars),
                error_message=notes_reason,
                pillar_details={
                    "evaluated_split": config.split,
                    "evaluated_dataset_hash": dataset_hash,
                    "model_name": config.model_name,
                    "model_revision": config.model_revision,
                },
            )

            intervention_result = InterventionResult(
                status=CircuitStatus.NOT_RUN.value,
                intervention_type="circuit_pruning",
                applied=False,
                error_message="Intervention unexecuted; awaiting model connection",
            )

            summary = CircuitExperimentSummary(
                status=CircuitStatus.NOT_RUN.value,
                split=config.split,
                config=config.to_dict(),
                dataset_hash=dataset_hash,
                n_examples=len(target_records),
                discovery=discovery_result,
                faithfulness=faithfulness_result,
                intervention=intervention_result,
                notes=notes_reason,
            )

            summary.verify_no_fabricated_scores()
            summary.save(output_dir)
            return summary

        # Case 2: Pipeline or mock pipeline supplied
        # Discovery pipeline is always constructed from dev_csv_file (ensures test data never enters discovery)
        if pipeline is None:
            if not CircuitKITAdapter.is_circuitkit_available():
                raise RuntimeError("CircuitKIT is required to run live experiments")
            pipeline = CircuitKITAdapter.build_pipeline_from_csv(
                model_name=config.model_name,
                model_revision=config.model_revision,
                csv_path=dev_csv_file,
                output_dir=str(output_dir),
                precision=config.precision,
                device=config.device,
                task_name=config.task_name,
            )

        # Execute discovery strictly over development records
        t_disc_start = time.time()
        try:
            n_ex = min(config.n_examples, len(dev_records))
            pipeline.discover(
                algorithm=config.algorithm,
                level=config.level,
                sparsity=config.sparsity,
                n_examples=n_ex,
                batch_size=config.batch_size,
                scope=config.scope,
                seed=config.seed,
            )
            disc_duration = time.time() - t_disc_start

            # Extract discovered circuit details
            circuit_obj = getattr(pipeline, "_circuit", None)
            nodes = []
            n_nodes = None
            n_edges = None
            if circuit_obj is not None:
                if hasattr(circuit_obj, "nodes"):
                    raw_nodes = circuit_obj.nodes
                    if isinstance(raw_nodes, (list, tuple)):
                        nodes = [str(n) for n in raw_nodes]
                        n_nodes = len(nodes)
                    elif isinstance(raw_nodes, dict):
                        nodes = [str(k) for k in raw_nodes.keys()]
                        n_nodes = len(nodes)
                if hasattr(circuit_obj, "edges") and circuit_obj.edges is not None:
                    n_edges = len(circuit_obj.edges)
                elif hasattr(circuit_obj, "__len__") and n_nodes is None:
                    n_nodes = len(circuit_obj)

            discovery_result = DiscoveryResult(
                status=CircuitStatus.SUCCESS.value,
                algorithm=config.algorithm,
                level=config.level,
                target_sparsity=config.sparsity,
                actual_sparsity=config.sparsity,
                n_nodes=n_nodes if n_nodes is not None else len(nodes),
                n_edges=n_edges,
                node_names=nodes[:50] if nodes else [],
                artifact_path=str(getattr(pipeline, "_artifact_path", None)),
                execution_time_seconds=round(disc_duration, 4),
                metadata={
                    "split": config.split,
                    "dataset_hash": dataset_hash,
                    "discovery_dataset": "contrastive_dev",
                    "discovery_hash": dev_hash,
                    "test_data_in_discovery": False,
                    "is_mock": is_mock,
                    "model_name": config.model_name,
                    "model_revision": config.model_revision,
                    "device": config.device,
                    "precision": config.precision,
                    "hardware": hw_info,
                },
            )
        except Exception as e:
            logger.error(f"Circuit discovery failed: {e}", exc_info=True)
            discovery_result = DiscoveryResult(
                status=CircuitStatus.FAILED.value,
                algorithm=config.algorithm,
                level=config.level,
                target_sparsity=config.sparsity,
                error_message=str(e),
                execution_time_seconds=round(time.time() - t_disc_start, 4),
            )
            summary = CircuitExperimentSummary(
                status=CircuitStatus.FAILED.value,
                split=config.split,
                config=config.to_dict(),
                dataset_hash=dataset_hash,
                n_examples=len(target_records),
                discovery=discovery_result,
                faithfulness=FaithfulnessResult(
                    status=CircuitStatus.NOT_RUN.value,
                    error_message="Skipped due to discovery failure",
                ),
                intervention=InterventionResult(
                    status=CircuitStatus.NOT_RUN.value,
                    error_message="Skipped due to discovery failure",
                ),
                notes=f"Discovery failed: {e}",
            )
            summary.save(output_dir)
            return summary

        # Execute faithfulness evaluation
        t_eval_start = time.time()
        try:
            n_eval = min(config.n_eval_examples, len(target_records))
            eval_kwargs: dict[str, Any] = {
                "pillars": config.pillars,
                "n_examples": n_eval,
                "n_stability_runs": config.n_stability_runs,
            }

            if is_mock:
                eval_kwargs["target_records"] = target_records
                eval_kwargs["split"] = config.split
            elif config.split == "test":
                # Explicitly register held-out TEST task into CircuitKIT
                test_task_name = f"traceguard_contrastive_{eval_csv_file.stem}"
                registered_name = CircuitKITAdapter.register_custom_task(
                    model=pipeline._ensure_model(),
                    csv_path=eval_csv_file,
                    task_name=test_task_name,
                    algorithm=config.algorithm,
                )
                from circuitkit.tasks.registry import is_task_registered

                if not is_task_registered(registered_name):
                    raise RuntimeError(
                        f"Failed to register TEST task '{registered_name}' in CircuitKIT registry. "
                        "Aborting evaluation to prevent silent fallback to DEV data."
                    )
                # Route evaluation explicitly to the held-out TEST task
                eval_discovery_cfg = dict(pipeline._discovery_cfg["discovery"])
                eval_discovery_cfg["task"] = registered_name
                eval_kwargs["discovery"] = eval_discovery_cfg
                pipeline._discovery_cfg["discovery"]["task"] = registered_name

            pipeline.evaluate(**eval_kwargs)
            eval_duration = time.time() - t_eval_start

            report = getattr(pipeline, "report", None)
            patching_score = None
            ablation_score = None
            stability_score = None
            robustness_score = None
            generalization_score = None
            pillar_details = {}

            if report is not None:
                patching_score = getattr(report, "patching_score", None)
                ablation_score = getattr(report, "ablation_score", None)
                stability_score = getattr(report, "stability", None)
                robustness_score = getattr(report, "robustness", None)
                generalization_score = getattr(report, "generalization", None)
                if hasattr(report, "to_dict"):
                    pillar_details = report.to_dict()
                elif dataclasses.is_dataclass(report):
                    pillar_details = dataclasses.asdict(report)

            # Record evaluation metadata
            pillar_details.update(
                {
                    "evaluated_split": config.split,
                    "evaluated_dataset_hash": dataset_hash,
                    "n_evaluated": n_eval,
                    "model_name": config.model_name,
                    "model_revision": config.model_revision,
                    "selected_precision": config.precision,
                }
            )

            scores = [s for s in (patching_score, ablation_score) if s is not None]
            overall_faith = round(sum(scores) / len(scores), 4) if scores else None

            faithfulness_result = FaithfulnessResult(
                status=CircuitStatus.SUCCESS.value,
                pillars_evaluated=list(config.pillars),
                patching_score=patching_score,
                ablation_score=ablation_score,
                stability_score=stability_score,
                robustness_score=robustness_score,
                generalization_score=generalization_score,
                overall_faithfulness=overall_faith,
                pillar_details=pillar_details,
                execution_time_seconds=round(eval_duration, 4),
            )
        except Exception as e:
            logger.error(f"Faithfulness evaluation failed: {e}", exc_info=True)
            faithfulness_result = FaithfulnessResult(
                status=CircuitStatus.FAILED.value,
                pillars_evaluated=list(config.pillars),
                error_message=str(e),
                execution_time_seconds=round(time.time() - t_eval_start, 4),
            )

        # Optional intervention evaluation
        if config.allow_intervention:
            if hasattr(pipeline, "intervene"):
                try:
                    inter_res = pipeline.intervene()
                    intervention_result = InterventionResult(
                        status=CircuitStatus.SUCCESS.value,
                        intervention_type="circuit_pruning",
                        applied=True,
                        clean_accuracy_pre=inter_res.get("clean_accuracy_pre"),
                        clean_accuracy_post=inter_res.get("clean_accuracy_post"),
                        safety_score_pre=inter_res.get("safety_score_pre"),
                        safety_score_post=inter_res.get("safety_score_post"),
                        delta_safety=inter_res.get("delta_safety"),
                        delta_clean_utility=inter_res.get("delta_clean_utility"),
                        details=inter_res,
                    )
                except Exception as e:
                    intervention_result = InterventionResult(
                        status=CircuitStatus.FAILED.value,
                        intervention_type="circuit_pruning",
                        error_message=str(e),
                    )
            else:
                intervention_result = InterventionResult(
                    status=CircuitStatus.UNAVAILABLE.value,
                    intervention_type="circuit_pruning",
                    error_message="Pipeline does not support direct intervention method",
                )
        else:
            intervention_result = InterventionResult(
                status=CircuitStatus.NOT_RUN.value,
                intervention_type="circuit_pruning",
                applied=False,
                error_message="Intervention evaluation not enabled in config",
            )

        overall_status = (
            CircuitStatus.SUCCESS.value
            if discovery_result.status == CircuitStatus.SUCCESS.value
            and faithfulness_result.status == CircuitStatus.SUCCESS.value
            else CircuitStatus.FAILED.value
        )

        cfg_dict = config.to_dict()
        if is_mock:
            cfg_dict["is_mock"] = True
            faithfulness_result.pillar_details["is_mock"] = True
            intervention_result.details["is_mock"] = True

        summary = CircuitExperimentSummary(
            status=overall_status,
            split=config.split,
            config=cfg_dict,
            dataset_hash=dataset_hash,
            n_examples=len(target_records),
            discovery=discovery_result,
            faithfulness=faithfulness_result,
            intervention=intervention_result,
            notes=(
                "[MOCK MODE] Results generated using synthetic MockCircuitPipeline; not real model discovery."
                if is_mock
                else None
            ),
        )

        summary.save(output_dir)
        return summary


class MockFaithfulnessReport:
    """Mock faithfulness report matching CircuitKIT FaithfulnessReport interface."""

    def __init__(
        self,
        patching_score: float = 0.8842,
        ablation_score: float = 0.8215,
        stability: float = 0.9100,
        robustness: float = 0.8540,
        generalization: float = 0.7920,
        metadata: Optional[dict[str, Any]] = None,
    ) -> None:
        self.patching_score = patching_score
        self.ablation_score = ablation_score
        self.stability = stability
        self.robustness = robustness
        self.generalization = generalization
        self.metadata = metadata or {}

    def to_dict(self) -> dict[str, Any]:
        data = {
            "patching_score": self.patching_score,
            "ablation_score": self.ablation_score,
            "stability": self.stability,
            "robustness": self.robustness,
            "generalization": self.generalization,
        }
        data.update(self.metadata)
        return data


class MockCircuit:
    """Mock circuit representation with nodes and edges."""

    def __init__(self, nodes: list[str]) -> None:
        self.nodes = nodes
        self.edges = [(nodes[i], nodes[i + 1]) for i in range(len(nodes) - 1)]

    def __len__(self) -> int:
        return len(self.nodes)


class MockCircuitPipeline:
    """Mock CircuitKIT Pipeline for offline CPU testing and test harness verification."""

    _is_mock: bool = True

    def __init__(
        self,
        output_dir: str = "results/circuit",
        fail_discovery: bool = False,
        fail_evaluation: bool = False,
    ) -> None:
        self.output_dir = output_dir
        self.fail_discovery = fail_discovery
        self.fail_evaluation = fail_evaluation
        self._circuit: Optional[MockCircuit] = None
        self._artifact_path: Optional[str] = None
        self.report: Optional[MockFaithfulnessReport] = None
        self.evaluated_records: list[dict[str, Any]] = []
        self.evaluated_split: Optional[str] = None

    def discover(self, **kwargs: Any) -> MockCircuitPipeline:
        if self.fail_discovery:
            raise RuntimeError("Simulated discovery failure in MockCircuitPipeline")
        self._circuit = MockCircuit(["L10H4", "L10H7", "L11H2", "L11H9", "L12H1", "L12H8"])
        self._artifact_path = f"{self.output_dir}/mock_circuit.pt"
        return self

    def evaluate(
        self,
        target_records: Optional[list[dict[str, Any]]] = None,
        split: Optional[str] = None,
        pillars: Optional[list[str]] = None,
        n_examples: Optional[int] = None,
        **kwargs: Any,
    ) -> MockCircuitPipeline:
        if self.fail_evaluation:
            raise RuntimeError("Simulated evaluation failure in MockCircuitPipeline")

        if target_records is not None:
            if not isinstance(target_records, list) or len(target_records) == 0:
                raise ValueError("target_records must be a non-empty list of contrastive records")
            self.evaluated_records = target_records
            self.evaluated_split = split or target_records[0].get("split", "unknown")
        elif "discovery" in kwargs and isinstance(kwargs["discovery"], dict):
            task_name = kwargs["discovery"].get("task", "")
            self.evaluated_split = "test" if "test" in task_name else "dev"

        # Deterministically derive mock scores based on actual records consumed
        if self.evaluated_records:
            split_hash = compute_dataset_hash(self.evaluated_records)
            int_hash = int(split_hash[:8], 16)
            offset = ((int_hash % 500) / 500.0 - 0.5) * 0.04

            if self.evaluated_split == "test":
                # Distinct scores for held-out TEST evaluation
                patching = round(0.8450 + offset, 4)
                ablation = round(0.7890 + offset, 4)
                stability = round(0.8800 + offset * 0.5, 4)
                robustness = round(0.8250 + offset * 0.5, 4)
                generalization = round(0.7680 + offset * 0.5, 4)
            else:
                # DEV evaluation baseline
                patching = 0.8842
                ablation = 0.8215
                stability = 0.9100
                robustness = 0.8540
                generalization = 0.7920
        else:
            patching = 0.8842
            ablation = 0.8215
            stability = 0.9100
            robustness = 0.8540
            generalization = 0.7920

        self.report = MockFaithfulnessReport(
            patching_score=patching,
            ablation_score=ablation,
            stability=stability,
            robustness=robustness,
            generalization=generalization,
            metadata={
                "evaluated_split": self.evaluated_split or split or "dev",
                "n_evaluated": len(self.evaluated_records) if self.evaluated_records else (n_examples or 0),
                "is_mock": True,
            },
        )
        return self

    def intervene(self) -> dict[str, Any]:
        return {
            "clean_accuracy_pre": 0.95,
            "clean_accuracy_post": 0.94,
            "safety_score_pre": 0.20,
            "safety_score_post": 0.85,
            "delta_safety": 0.65,
            "delta_clean_utility": -0.01,
        }

