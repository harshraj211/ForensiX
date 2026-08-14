"""APK analysis using Androguard."""

import pathlib
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class ApkAnalysisResult:
    package_name: str
    version_name: str
    version_code: str
    min_sdk_version: str
    target_sdk_version: str
    permissions: list[str]
    activities: list[str]
    services: list[str]
    receivers: list[str]
    providers: list[str]
    certificates: list[dict[str, Any]]


class ApkAnalyzer:
    """Analyze an APK file."""

    def analyze(self, apk_path: pathlib.Path) -> ApkAnalysisResult:
        try:
            from androguard.core.bytecodes.apk import APK
        except ImportError as exc:
            raise RuntimeError("Androguard is not installed.") from exc

        apk = APK(str(apk_path))

        certs: list[dict[str, Any]] = []
        if apk.is_signed():
            try:
                # Basic certificate extraction; exact API depends on Androguard version
                for cert in apk.get_certificates():
                    cert_dict = {}
                    if hasattr(cert, "issuer") and hasattr(cert.issuer, "human_friendly"):
                        cert_dict["issuer"] = cert.issuer.human_friendly
                    if hasattr(cert, "subject") and hasattr(cert.subject, "human_friendly"):
                        cert_dict["subject"] = cert.subject.human_friendly
                    if hasattr(cert, "serial_number"):
                        cert_dict["serial_number"] = hex(cert.serial_number)
                    if hasattr(cert, "sha1_fingerprint"):
                        cert_dict["hash_sha1"] = cert.sha1_fingerprint
                    elif hasattr(cert, "sha1"):
                        cert_dict["hash_sha1"] = cert.sha1
                    if hasattr(cert, "sha256_fingerprint"):
                        cert_dict["hash_sha256"] = cert.sha256_fingerprint
                    elif hasattr(cert, "sha256"):
                        cert_dict["hash_sha256"] = cert.sha256
                    
                    if not cert_dict:
                        cert_dict["raw"] = "Certificate parsed but attributes not accessible"
                    
                    certs.append(cert_dict)
            except Exception as e:
                certs.append({"error": f"Failed to parse certificate: {e}"})

        return ApkAnalysisResult(
            package_name=apk.get_package() or "",
            version_name=apk.get_androidversion_name() or "",
            version_code=str(apk.get_androidversion_code() or ""),
            min_sdk_version=str(apk.get_min_sdk_version() or ""),
            target_sdk_version=str(apk.get_target_sdk_version() or ""),
            permissions=sorted(apk.get_permissions() or []),
            activities=sorted(apk.get_activities() or []),
            services=sorted(apk.get_services() or []),
            receivers=sorted(apk.get_receivers() or []),
            providers=sorted(apk.get_providers() or []),
            certificates=certs,
        )
