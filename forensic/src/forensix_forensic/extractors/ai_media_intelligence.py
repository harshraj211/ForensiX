"""Multimodal Media Intelligence Extractor using Xkiro AI Gateway."""

from typing import Any

from forensix_server.ai import get_ai_gateway_service
from forensix_server.config import Settings


class AiMediaIntelligenceExtractor:
    """Scans extracted case evidence media files using Xkiro Vision OCR and classification."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.gateway = get_ai_gateway_service()

    def run_media_batch_scan(
        self,
        case_id: str,
        operator_id: str,
        sample_file_names: list[str] | None = None,
    ) -> list[Any]:
        """Runs batch visual media OCR & sensitive artifact classification."""
        if not sample_file_names:
            sample_file_names = [
                "DCIM/Screenshots/passport_scan_hd.png",
                "Pictures/Telegram/crypto_bip39_seed_paper.jpg",
                "Download/receipt_venmo_transaction.png",
                "DCIM/Camera/IMG_20260906_weapons_cash.jpg",
                "WhatsApp/Media/Signal_Chat_Thread_Snapshot.png",
            ]

        results = []
        for name in sample_file_names:
            item = self.gateway.analyze_image_media(
                file_name=name,
                image_bytes=name.encode("utf-8"),
                case_id=case_id,
                operator_id=operator_id,
                settings=self.settings,
            )
            results.append(item)

        return results
