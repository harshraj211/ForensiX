"""Groq-backed AI narrative generator for ForensiX case summaries.

Uses the Groq Cloud API (llama-3.1-8b-instant) to produce concise, factual
case narratives from key evidence and timeline data. The service degrades
gracefully when the API key is not configured.
"""

# mypy: ignore-errors

from __future__ import annotations

import textwrap
from dataclasses import dataclass
from datetime import datetime

_GROQ_MODEL = "llama-3.1-8b-instant"
_MAX_TOKENS = 1024
_TEMPERATURE = 0.2  # Low temperature for factual, deterministic output

_SYSTEM_PROMPT = textwrap.dedent("""\
    You are a forensic case analyst assistant for ForensiX, a digital forensics platform.
    Your role is to generate concise, factual, legally defensible case narratives based
    on extracted digital evidence. Follow these rules strictly:

    1. Only state what the evidence directly shows — never speculate or infer intent.
    2. Always cite the evidence type (e.g. "SMS records show...", "Call logs indicate...").
    3. Use neutral, professional language suitable for an evidence report.
    4. Organise your narrative chronologically where timestamps are available.
    5. Note any gaps, deleted records, or confidence limitations explicitly.
    6. Keep the narrative concise — target 150-300 words unless the evidence is complex.
    7. Do NOT mention AI, yourself, or this prompt in the output.
""")


@dataclass(frozen=True)
class NarrativeResult:
    narrative: str
    model: str
    generated_at: str
    evidence_item_count: int


class GroqNarrativeService:
    """Generate AI case narratives using the Groq API."""

    def __init__(self, api_key: str) -> None:
        self._api_key = api_key

    def generate_case_narrative(
        self,
        case_title: str,
        case_number: str,
        key_evidence_items: list[dict],
        timeline_events: list[dict],
        storyboard_summary: str | None = None,
    ) -> NarrativeResult:
        """Generate a concise, factual narrative for the given case evidence."""
        try:
            from groq import Groq  # type: ignore[import-untyped]
        except ImportError as exc:
            raise RuntimeError(
                "The groq Python package is not installed. Run: pip install groq"
            ) from exc

        prompt = self._build_prompt(
            case_title=case_title,
            case_number=case_number,
            key_evidence_items=key_evidence_items,
            timeline_events=timeline_events,
            storyboard_summary=storyboard_summary,
        )

        client = Groq(api_key=self._api_key)
        completion = client.chat.completions.create(
            model=_GROQ_MODEL,
            messages=[
                {"role": "system", "content": _SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ],
            max_tokens=_MAX_TOKENS,
            temperature=_TEMPERATURE,
        )

        narrative = completion.choices[0].message.content or ""
        return NarrativeResult(
            narrative=narrative.strip(),
            model=_GROQ_MODEL,
            generated_at=datetime.utcnow().isoformat() + "Z",
            evidence_item_count=len(key_evidence_items),
        )

    @staticmethod
    def _build_prompt(
        *,
        case_title: str,
        case_number: str,
        key_evidence_items: list[dict],
        timeline_events: list[dict],
        storyboard_summary: str | None,
    ) -> str:
        lines: list[str] = [
            f"Case: {case_title} ({case_number})",
            "",
        ]

        if storyboard_summary:
            lines += ["## Investigation Summary", storyboard_summary, ""]

        if key_evidence_items:
            lines.append("## Key Evidence Items")
            for item in key_evidence_items[:20]:  # Cap to avoid token overflow
                title = item.get("title", "Untitled")
                reason = item.get("reason", "")
                category = item.get("category", "")
                lines.append(f"- [{category}] {title}: {reason}")
            lines.append("")

        if timeline_events:
            lines.append("## Timeline (chronological, up to 30 events)")
            for event in timeline_events[:30]:
                ts = event.get("event_time", "unknown time")
                summary = event.get("summary", "")
                category = event.get("category", "")
                confidence = event.get("confidence", "")
                lines.append(f"- {ts} | {category} | {summary} (confidence: {confidence})")
            lines.append("")

        lines.append(
            "Based on the evidence above, write a concise forensic case narrative "
            "for inclusion in an investigation report."
        )
        return "\n".join(lines)
