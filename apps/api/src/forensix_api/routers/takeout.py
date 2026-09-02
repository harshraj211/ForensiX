"""Google Takeout import endpoints."""

# mypy: ignore-errors

# ruff: noqa: E501, SIM105

import hashlib
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, UploadFile, status

from forensix_api.dependencies import get_authenticated_session, get_database, get_settings
from forensix_server.acquisitions.takeout_import import TakeoutImporter
from forensix_server.auth import AuthenticatedSession
from forensix_server.config import Settings
from forensix_server.db import Database, TimelineEventRecord
from forensix_server.evidence.timeline import TIMELINE_BUILDER_VERSION, _canonical_json

router = APIRouter(prefix="/api/v1/cases", tags=["takeout"])


@router.post("/{case_id}/takeout/import")
async def import_takeout(
    case_id: str,
    file: UploadFile,
    authenticated: Annotated[AuthenticatedSession, Depends(get_authenticated_session)],
    settings: Annotated[Settings, Depends(get_settings)],
    database: Annotated[Database, Depends(get_database)],
) -> dict:
    """Import a Google Takeout ZIP and add extracted events to the timeline."""
    if not file.filename or not file.filename.endswith(".zip"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="File must be a ZIP archive",
        )

    temp_dir = settings.resolved_data_dir / "tmp"
    temp_dir.mkdir(parents=True, exist_ok=True)
    temp_path = temp_dir / f"{case_id}_{file.filename}"

    imported_count = 0

    try:
        content = await file.read()
        temp_path.write_bytes(content)

        importer = TakeoutImporter(temp_path)

        with database.session() as session:
            for item in importer.process():
                event_time = item["event_time"]
                payload = {
                    "builder_version": TIMELINE_BUILDER_VERSION,
                    "case_id": case_id,
                    "category": item["category"],
                    "confidence": item["confidence"],
                    "event_time": event_time.isoformat(),
                    "summary": item["summary"],
                    "timestamp_type": "google_takeout_import",
                    "timezone_basis": "UTC parsed from Google Takeout",
                }
                event_hash = hashlib.sha256(_canonical_json(payload).encode("utf-8")).hexdigest()

                # Check for duplicates using the generated hash
                existing = (
                    session.query(TimelineEventRecord).filter_by(event_hash=event_hash).first()
                )
                if not existing:
                    # Persist imported Takeout event into case timeline
                    record = TimelineEventRecord(
                        case_id=case_id,
                        artifact_id=case_id,
                        job_id=case_id,
                        category=item["category"],
                        timestamp_type="google_takeout_import",
                        event_time=event_time,
                        original_time=event_time.isoformat(),
                        timezone_basis="UTC parsed from Google Takeout",
                        precision="second",
                        confidence=item["confidence"],
                        summary=item["summary"],
                        builder_version=TIMELINE_BUILDER_VERSION,
                        event_hash=event_hash,
                    )
                    session.add(record)
                    imported_count += 1

            session.commit()

        return {"imported_events": imported_count}
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to import Takeout: {str(exc)}",
        ) from exc
    finally:
        if temp_path.exists():
            try:
                temp_path.unlink()
            except OSError:
                pass
