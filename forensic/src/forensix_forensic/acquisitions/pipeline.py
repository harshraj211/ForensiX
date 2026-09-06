"""Forensic Acquisition Pipeline Orchestrator.

Orchestrates execution of selected acquisition vectors and passes extracted
data to the Forensic Evidence Packager for container sealing.
"""

import json
import logging
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from forensix_forensic.adb import AdbClient
from forensix_forensic.capabilities.decision_engine import (
    AcquisitionPlanRecommendation,
    AcquisitionVector,
)
from forensix_forensic.extractors.agent_apk import AgentCollector

from .models import (
    AcquisitionExecutionState,
    AcquisitionPipelineResult,
)
from .packager import ForensicEvidencePackager

logger = logging.getLogger(__name__)


class AcquisitionPipelineOrchestrator:
    """Orchestrates capability-gated acquisition vector execution and evidence packaging."""

    def __init__(self, packager: ForensicEvidencePackager | None = None) -> None:
        self._packager = packager or ForensicEvidencePackager()

    async def execute_plan(
        self,
        recommendation: AcquisitionPlanRecommendation,
        adb_client: AdbClient,
        case_id: str,
        output_base_dir: Path,
    ) -> AcquisitionPipelineResult:
        acquisition_id = str(uuid4())[:8]
        started_at = datetime.now(UTC)
        serial = recommendation.assessed_serial

        raw_dir = output_base_dir / "raw" / acquisition_id
        archives_dir = output_base_dir / "sealed"
        raw_dir.mkdir(parents=True, exist_ok=True)

        # Try Primary Vector, fallback to viable vectors on error
        vectors_to_try = [
            recommendation.primary_vector,
            *recommendation.fallback_vectors,
        ]

        last_error: str | None = None

        for vector in vectors_to_try:
            try:
                logger.info("Executing acquisition vector: %s for device %s", vector, serial)

                if vector in (AcquisitionVector.AGENT_LOGICAL, AcquisitionVector.ROOTED_LOGICAL):
                    from forensix_forensic.extractors.agent_apk.agent_collector import (
                        CollectorConfig,
                    )

                    collector = AgentCollector(
                        adb=adb_client,
                        config=CollectorConfig(poll_interval_seconds=0.1, max_wait_seconds=5),
                        output_dir=raw_dir,
                    )
                    result = await collector.collect(
                        serial=serial,
                        case_id=case_id,
                        extraction_id=acquisition_id,
                    )
                    if not result.success:
                        last_error = (
                            result.error_message or f"Agent collection failed for vector {vector}"
                        )
                        continue

                elif vector == AcquisitionVector.METADATA_ONLY:
                    # Write basic metadata fallback file
                    metadata_file = raw_dir / "device_metadata.json"
                    meta_payload = {
                        "serial": serial,
                        "vector": "METADATA_ONLY",
                        "collected_at": started_at.isoformat(),
                    }
                    metadata_file.write_text(json.dumps(meta_payload), encoding="utf-8")

                else:
                    logger.warning(
                        "Vector %s not natively executable via ADB agent; recording vector log.",
                        vector,
                    )
                    log_file = raw_dir / "vector_notice.json"
                    notice_payload = {
                        "serial": serial,
                        "vector": str(vector),
                        "notice": "Requires external protocol harness",
                    }
                    log_file.write_text(json.dumps(notice_payload), encoding="utf-8")

                finished_at = datetime.now(UTC)
                eval_info = recommendation.vector_evaluations.get(vector.value)
                yield_score = eval_info.yield_score if eval_info else 10

                return self._packager.package(
                    acquisition_id=acquisition_id,
                    case_id=case_id,
                    device_serial=serial,
                    vector_used=vector,
                    yield_score=yield_score,
                    started_at=started_at,
                    finished_at=finished_at,
                    raw_extraction_dir=raw_dir,
                    output_archive_dir=archives_dir,
                    limitations=recommendation.limitations,
                )

            except Exception as exc:
                logger.error("Error executing vector %s: %s", vector, exc)
                last_error = str(exc)

        return AcquisitionPipelineResult(
            acquisition_id=acquisition_id,
            success=False,
            state=AcquisitionExecutionState.FAILED,
            vector_used=recommendation.primary_vector,
            output_dir=str(raw_dir),
            error_message=last_error or "All acquisition vectors failed to execute.",
        )
