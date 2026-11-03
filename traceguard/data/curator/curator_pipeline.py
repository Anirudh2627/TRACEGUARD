"""End-to-end CuratorKIT dataset curation pipeline for TraceGuard."""

from __future__ import annotations

import logging
import time
from pathlib import Path
from typing import Optional

from traceguard.data.curator.cleaning import CleaningReport, EpisodeCleaner
from traceguard.data.curator.curator_config import CuratorPipelineConfig
from traceguard.data.curator.dataset_cards import DatasetCardGenerator
from traceguard.data.curator.deduplication import DeduplicationReport, EpisodeDeduplicator
from traceguard.data.curator.exports import (
    export_full_fidelity_jsonl,
    export_trainer_ready_conversations,
)
from traceguard.data.curator.ingestion import DatasetIngester, IngestionReport
from traceguard.data.curator.manifests import ManifestBuilder
from traceguard.data.curator.quality_gates import QualityGateReport, QualityGateRunner
from traceguard.data.schema import Episode
from traceguard.experiments.curator_results import CuratorExecutionSummary

logger = logging.getLogger(__name__)


class CuratorPipeline:
    """Executes the complete CuratorKIT ingestion, cleaning, deduplication, quality gating, and export lifecycle."""

    def __init__(self, config: Optional[CuratorPipelineConfig] = None) -> None:
        self.config = config or CuratorPipelineConfig()
        self.ingester = DatasetIngester()
        self.cleaner = EpisodeCleaner(normalize_whitespace=self.config.clean_whitespace)
        self.deduplicator = EpisodeDeduplicator(
            similarity_threshold=self.config.similarity_threshold,
            minhash_ngram=self.config.minhash_ngram,
            minhash_num_perm=self.config.minhash_num_perm,
            minhash_seed=self.config.minhash_seed,
        )
        self.gate_runner = QualityGateRunner()
        self.manifest_builder = ManifestBuilder(
            output_dir=Path(self.config.output_dir) / "manifests"
        )
        self.card_generator = DatasetCardGenerator(
            output_dir=Path(self.config.output_dir) / "dataset_cards"
        )

    def run(self) -> CuratorExecutionSummary:
        """Run the dataset curation pipeline."""
        t0 = time.time()
        in_dir = Path(self.config.input_dir)
        out_dir = Path(self.config.output_dir)
        out_dir.mkdir(parents=True, exist_ok=True)

        target_names = self.config.target_datasets or list(self.config.dataset_files.keys())

        ingestion_reports: dict[str, IngestionReport] = {}
        cleaning_reports: dict[str, CleaningReport] = {}
        dedup_reports: dict[str, DeduplicationReport] = {}
        curated_datasets: dict[str, list[Episode]] = {}

        manifest_paths: list[str] = []
        card_paths: list[str] = []
        curated_file_paths: list[str] = []

        total_ingested = 0
        total_curated = 0
        total_rejected = 0

        # Step 1: Ingestion, Cleaning, and Deduplication per dataset
        for name in target_names:
            filename = self.config.dataset_files[name]
            file_path = in_dir / filename

            # Ingestion
            episodes, ing_rep = self.ingester.ingest_file(file_path, dataset_name=name)
            ingestion_reports[name] = ing_rep
            total_ingested += ing_rep.total_lines
            total_rejected += ing_rep.rejected_count

            # Cleaning
            cleaned_eps, clean_rep = self.cleaner.clean_dataset(episodes, dataset_name=name)
            cleaning_reports[name] = clean_rep

            # Deduplication
            surviving_eps, dedup_rep = self.deduplicator.analyze(cleaned_eps, dataset_name=name)
            dedup_reports[name] = dedup_rep
            total_rejected += (
                dedup_rep.exact_id_duplicates_count + dedup_rep.exact_record_duplicates_count
            )

            curated_datasets[name] = surviving_eps
            total_curated += len(surviving_eps)

        # Step 2: Quality Gates across the entire curated collection
        quality_report = self.gate_runner.evaluate_collection(curated_datasets)

        # Step 3: Exports and Artifacts
        if not self.config.dry_run and not self.config.validation_only:
            output_paths_for_checksum: list[Path] = []

            for name, eps in curated_datasets.items():
                out_name = f"{name}.jsonl"
                out_file = out_dir / out_name
                export_full_fidelity_jsonl(eps, out_file)
                curated_file_paths.append(str(out_file))
                output_paths_for_checksum.append(out_file)

                if self.config.generate_trainer_exports:
                    trainer_file = out_dir / f"trainer_ready_{name}.jsonl"
                    export_trainer_ready_conversations(eps, trainer_file)
                    output_paths_for_checksum.append(trainer_file)

                # Step 4: Manifests
                if self.config.generate_manifests:
                    manifest_dict = self.manifest_builder.build_dataset_manifest(
                        dataset_name=name,
                        episodes=eps,
                        source_path=in_dir / self.config.dataset_files[name],
                        curated_path=out_file,
                        cleaning_report=cleaning_reports[name],
                        dedup_report=dedup_reports[name],
                        gate_report=quality_report,
                    )
                    man_path = self.manifest_builder.write_manifest(
                        manifest_dict, f"manifest_{name}.json"
                    )
                    manifest_paths.append(str(man_path))
                    output_paths_for_checksum.append(man_path)

                    # Step 5: Dataset Cards
                    if self.config.generate_dataset_cards:
                        card_p = self.card_generator.generate_card(
                            manifest_dict, f"card_{name}.md"
                        )
                        card_paths.append(str(card_p))
                        output_paths_for_checksum.append(card_p)

            # Collection-level manifest and card
            if self.config.generate_manifests and len(curated_datasets) == 4:
                all_eps = []
                for eps in curated_datasets.values():
                    all_eps.extend(eps)
                coll_manifest = self.manifest_builder.build_dataset_manifest(
                    dataset_name="traceguard_curated_collection",
                    episodes=all_eps,
                    source_path=in_dir,
                    curated_path=out_dir,
                    cleaning_report=None,
                    dedup_report=None,
                    gate_report=quality_report,
                )
                coll_man_path = self.manifest_builder.write_manifest(
                    coll_manifest, "manifest_collection.json"
                )
                manifest_paths.append(str(coll_man_path))
                output_paths_for_checksum.append(coll_man_path)

                if self.config.generate_dataset_cards:
                    coll_card_p = self.card_generator.generate_card(
                        coll_manifest, "card_collection.md"
                    )
                    card_paths.append(str(coll_card_p))
                    output_paths_for_checksum.append(coll_card_p)

            # Checksums
            checksums_file = out_dir / "checksums.txt"
            self.manifest_builder.write_checksums(output_paths_for_checksum, checksums_file)
            checksums_path_str = str(checksums_file)
        else:
            checksums_path_str = None

        wall_clock = time.time() - t0
        status = "PASSED" if quality_report.passed else "FAILED"

        summary = CuratorExecutionSummary(
            status=status,
            config=self.config.to_dict(),
            datasets_processed=target_names,
            total_episodes_ingested=total_ingested,
            total_episodes_curated=total_curated,
            total_episodes_rejected=total_rejected,
            ingestion_reports={k: v.to_dict() for k, v in ingestion_reports.items()},
            cleaning_reports={k: v.to_dict() for k, v in cleaning_reports.items()},
            deduplication_reports={k: v.to_dict() for k, v in dedup_reports.items()},
            quality_gate_report=quality_report.to_dict(),
            manifest_paths=manifest_paths,
            dataset_card_paths=card_paths,
            curated_file_paths=curated_file_paths,
            checksums_path=checksums_path_str,
            wall_clock_seconds=round(wall_clock, 4),
        )

        # Save summary to results/curator/
        summary.save("results/curator")
        return summary
