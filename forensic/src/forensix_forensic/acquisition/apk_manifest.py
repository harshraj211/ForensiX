"""APK Downgrade Manifest — thin re-export from the canonical extractor module.

The canonical 46-profile manifest lives in
``forensix_forensic.extractors.apk_downgrade.APK_DOWNGRADE_PROFILES``.

This module exposes it under a stable, short-form import path for use by
the server-side handler and any API endpoints that need the profile list
without importing the full extractor.
"""

from __future__ import annotations

from forensix_forensic.extractors.apk_downgrade import APK_DOWNGRADE_PROFILES

__all__ = [
    "APK_DOWNGRADE_PROFILES",
    "list_profiles",
    "resolve_legacy_apk_filename",
]


def list_profiles() -> list[dict[str, object]]:
    """Return a JSON-serialisable list of all 46 downgrade profiles.

    Each entry exposes:
      * ``package_name``  — Android package identifier
      * ``display_name``  — Human-readable app name
      * ``profile_id``    — Unique profile key (same as package name)
      * ``min_downgrade_version`` — Lowest legacy APK version accepted
    """
    return [
        {
            "profile_id": profile.profile_id,
            "package_name": profile.package_name,
            "display_name": profile.display_name,
            "min_api": profile.min_api,
            "max_api": profile.max_api,
        }
        for profile in APK_DOWNGRADE_PROFILES.values()
    ]


def resolve_legacy_apk_filename(package_name: str) -> str | None:
    """Return the legacy APK filename for *package_name*, or None if unknown.

    Checks the canonical APK_DOWNGRADE_PROFILES first; falls back to the
    server-side handler manifest.
    """
    profile = next(
        (item for item in APK_DOWNGRADE_PROFILES.values() if item.package_name == package_name),
        None,
    )
    if profile is None:
        return None

    # Legacy filenames are maintained by the server-side execution manifest.
    from forensix_server.jobs.handlers.generic_downgrade_handler import (
        APK_DOWNGRADE_MANIFEST,
    )

    return APK_DOWNGRADE_MANIFEST.get(package_name)
