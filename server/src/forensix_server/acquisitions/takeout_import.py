"""Google Takeout archive importer."""

import json
import zipfile
from datetime import datetime, UTC
from pathlib import Path
from typing import Any, Iterator


def _parse_takeout_timestamp(ms_val: Any) -> datetime | None:
    try:
        dt = datetime.fromtimestamp(int(ms_val) / 1000.0, tz=UTC)
        if 1990 <= dt.year <= 2200:
            return dt
        return None
    except (ValueError, TypeError, OverflowError):
        return None


class TakeoutImporter:
    """Parses Google Takeout archives to extract timeline events."""

    def __init__(self, archive_path: Path) -> None:
        self.archive_path = archive_path

    def process(self) -> Iterator[dict[str, Any]]:
        """Yields extracted artifacts from known Takeout files."""
        if not zipfile.is_zipfile(self.archive_path):
            raise ValueError("Not a valid ZIP archive")

        with zipfile.ZipFile(self.archive_path, "r") as zf:
            for name in zf.namelist():
                if name.endswith("Location History/Records.json") or "Semantic Location History" in name:
                    yield from self._parse_location(zf, name)
                elif name.endswith("Chrome/BrowserHistory.json"):
                    yield from self._parse_chrome(zf, name)

    def _parse_location(self, zf: zipfile.ZipFile, filename: str) -> Iterator[dict[str, Any]]:
        try:
            with zf.open(filename) as f:
                data = json.load(f)
                locations = data.get("locations", [])
                for loc in locations:
                    timestamp_ms = loc.get("timestampMs") or loc.get("timestamp", {}).get("epoch_ms")
                    if not timestamp_ms:
                        continue
                    dt = _parse_takeout_timestamp(timestamp_ms)
                    if not dt:
                        continue
                        
                    lat = loc.get("latitudeE7", 0) / 1e7
                    lng = loc.get("longitudeE7", 0) / 1e7
                    
                    yield {
                        "category": "location",
                        "title": "Google Takeout Location",
                        "summary": f"Location ({lat}, {lng}) from Takeout",
                        "event_time": dt,
                        "confidence": "high"
                    }
        except Exception:
            pass

    def _parse_chrome(self, zf: zipfile.ZipFile, filename: str) -> Iterator[dict[str, Any]]:
        try:
            with zf.open(filename) as f:
                data = json.load(f)
                history = data.get("Browser History", [])
                for visit in history:
                    timestamp_usec = visit.get("time_usec")
                    if not timestamp_usec:
                        continue
                    dt = _parse_takeout_timestamp(int(timestamp_usec) / 1000)
                    if not dt:
                        continue
                        
                    yield {
                        "category": "application",
                        "title": visit.get("title", "Unknown Title"),
                        "summary": visit.get("url", "Unknown URL"),
                        "event_time": dt,
                        "confidence": "high"
                    }
        except Exception:
            pass
