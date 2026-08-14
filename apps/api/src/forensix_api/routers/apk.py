"""APK analysis endpoints."""

from dataclasses import asdict
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, UploadFile, status

from forensix_api.dependencies import get_authenticated_session, get_settings
from forensix_server.auth import AuthenticatedSession
from forensix_server.config import Settings
from forensix_forensic.apk_analysis import ApkAnalyzer

router = APIRouter(prefix="/api/v1/cases", tags=["apk"])


@router.post("/{case_id}/apk/analyze")
async def analyze_apk(
    case_id: str,
    file: UploadFile,
    authenticated: Annotated[AuthenticatedSession, Depends(get_authenticated_session)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> dict:
    """Analyze an uploaded APK file and return metadata."""
    if not file.filename or not file.filename.endswith(".apk"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="File must be an APK",
        )

    temp_dir = settings.resolved_data_dir / "tmp"
    temp_dir.mkdir(parents=True, exist_ok=True)
    temp_path = temp_dir / f"{case_id}_{file.filename}"

    try:
        content = await file.read()
        temp_path.write_bytes(content)

        analyzer = ApkAnalyzer()
        result = analyzer.analyze(temp_path)
        return asdict(result)
    except RuntimeError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=str(exc),
        ) from exc
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to analyze APK: {str(exc)}",
        ) from exc
    finally:
        if temp_path.exists():
            try:
                temp_path.unlink()
            except OSError:
                pass
