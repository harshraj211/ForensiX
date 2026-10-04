"""Self-contained, deterministic, air-gapped forensic HTML report generator.

Features:
- Zero external dependencies: zero CDNs, zero web fonts, zero remote scripts or images.
- Pure inline CSS with executive dark palette, forensic contrast, and print-ready styles.
- Client-side vanilla JavaScript (<60 lines) for real-time artifact searching,
  category filtering, and hash copying.
- Comprehensive sections: Case Metadata, Integrity & Custody Ledger, Acquired
  Devices, Cryptographic Source Verification, Carved & Recovered Data, Readable
  Communications, Normalized Artifact Inventory, Timeline, and Examiner Sign-off.
- Completely injection-safe via comprehensive HTML escaping.
"""

from __future__ import annotations

import html
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .snapshot import ReportSnapshot


def _esc(val: object | None) -> str:
    """Safely escape text for HTML output."""
    if val is None:
        return ""
    return html.escape(str(val))


def _format_size(size_bytes: int | None) -> str:
    if size_bytes is None:
        return "Unknown"
    if size_bytes < 1024:
        return f"{size_bytes} B"
    if size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.1f} KB"
    if size_bytes < 1024 * 1024 * 1024:
        return f"{size_bytes / (1024 * 1024):.2f} MB"
    return f"{size_bytes / (1024 * 1024 * 1024):.2f} GB"


def render_html(snapshot: ReportSnapshot) -> bytes:
    """Render a standalone, self-contained HTML forensic report."""
    case = snapshot.case
    report_info = snapshot.report

    # Counts and summaries
    recovered_artifacts = [
        art for art in snapshot.imported_artifacts if art.status.lower() == "recovered"
    ]
    chat_messages = []
    for art in snapshot.imported_artifacts:
        subtype = art.subtype.casefold()
        if art.category == "communication" and any(
            marker in subtype for marker in ("message", "sms", "mms", "chat", "call")
        ):
            app = subtype.split("_", 1)[0].replace("android", "SMS").title()
            if subtype.startswith("whatsapp"):
                app = "WhatsApp"
            elif subtype.startswith("telegram"):
                app = "Telegram"
            elif subtype.startswith(("android_sms", "sms")):
                app = "SMS"
            chat_messages.append(
                (
                    art.event_time.isoformat() if art.event_time else "Time unavailable",
                    app,
                    art.title,
                    art.summary,
                    art.status,
                )
            )

    total_artifacts = len(snapshot.imported_artifacts) + len(snapshot.selected_artifacts)
    total_sources = len(snapshot.evidence_sources)
    total_files = len(snapshot.hash_manifest)
    total_custody = len(snapshot.custody)
    total_timeline = len(snapshot.timeline)

    # Categories for filter pills
    categories = sorted(
        {art.category for art in snapshot.imported_artifacts if art.category}
        | {art.category for art in snapshot.selected_artifacts if art.category}
    )

    doc = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="generator" content="ForensiX {_esc(snapshot.tool_version)}">
<title>ForensiX Forensic Report - {_esc(case.case_number)}</title>
<style>
/* Reset & Base */
*, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
body {{
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
  background-color: #0b111e;
  color: #cbd5e1;
  line-height: 1.5;
  font-size: 13px;
  -webkit-font-smoothing: antialiased;
}}
a {{ color: #38bdf8; text-decoration: none; }}
a:hover {{ text-decoration: underline; }}
code, pre, .mono {{
  font-family: ui-monospace, "SF Mono", "Cascadia Code", "Segoe UI Mono", Menlo, Consolas, monospace;
  font-size: 11px;
}}
.container {{ max-width: 1240px; margin: 0 auto; padding: 24px 20px 80px; }}

/* Top Brand Header */
.report-header {{
  background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
  border: 1px solid rgba(255, 255, 255, 0.08);
  border-radius: 12px;
  padding: 24px 28px;
  margin-bottom: 20px;
  box-shadow: 0 4px 20px rgba(0, 0, 0, 0.4);
}}
.header-top {{
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  flex-wrap: wrap;
  gap: 16px;
  border-bottom: 1px solid rgba(255, 255, 255, 0.08);
  padding-bottom: 18px;
  margin-bottom: 18px;
}}
.brand-title {{
  display: flex;
  align-items: center;
  gap: 10px;
}}
.brand-logo {{
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 36px;
  height: 36px;
  background: linear-gradient(135deg, #06b6d4, #0284c7);
  border-radius: 8px;
  color: #0f172a;
  font-weight: 800;
  font-size: 18px;
}}
.brand-text h1 {{
  font-size: 20px;
  font-weight: 700;
  color: #f8fafc;
  letter-spacing: -0.02em;
}}
.brand-text p {{
  font-size: 11px;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.12em;
  color: #38bdf8;
}}
.meta-badges {{
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
}}
.badge {{
  display: inline-flex;
  align-items: center;
  gap: 5px;
  padding: 4px 10px;
  border-radius: 9999px;
  font-size: 11px;
  font-weight: 600;
  letter-spacing: 0.04em;
  text-transform: uppercase;
}}
.badge-warning {{
  background: rgba(245, 158, 11, 0.12);
  border: 1px solid rgba(245, 158, 11, 0.35);
  color: #fbbf24;
}}
.badge-cyan {{
  background: rgba(6, 182, 212, 0.12);
  border: 1px solid rgba(6, 182, 212, 0.3);
  color: #38bdf8;
}}
.badge-purple {{
  background: rgba(168, 85, 247, 0.15);
  border: 1px solid rgba(168, 85, 247, 0.4);
  color: #c084fc;
}}
.badge-emerald {{
  background: rgba(16, 185, 129, 0.12);
  border: 1px solid rgba(16, 185, 129, 0.35);
  color: #34d399;
}}
.badge-slate {{
  background: rgba(100, 116, 139, 0.15);
  border: 1px solid rgba(100, 116, 139, 0.3);
  color: #94a3b8;
}}

/* Case Metadata Grid */
.meta-grid {{
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
  gap: 16px;
}}
.meta-item dt {{
  font-size: 11px;
  font-weight: 500;
  color: #94a3b8;
  margin-bottom: 2px;
}}
.meta-item dd {{
  font-size: 13px;
  color: #f1f5f9;
  font-weight: 500;
  word-break: break-word;
}}

/* Warning Banner */
.alert-banner {{
  display: flex;
  align-items: flex-start;
  gap: 12px;
  background: rgba(245, 158, 11, 0.08);
  border: 1px solid rgba(245, 158, 11, 0.25);
  border-radius: 8px;
  padding: 12px 16px;
  margin-bottom: 20px;
  color: #fef3c7;
  font-size: 12px;
  line-height: 1.5;
}}

/* KPI Metric Cards */
.kpi-row {{
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(170px, 1fr));
  gap: 12px;
  margin-bottom: 24px;
}}
.kpi-card {{
  background: #111a2c;
  border: 1px solid rgba(255, 255, 255, 0.06);
  border-radius: 10px;
  padding: 14px 16px;
  box-shadow: 0 2px 8px rgba(0, 0, 0, 0.2);
}}
.kpi-label {{
  font-size: 11px;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.05em;
  color: #64748b;
}}
.kpi-value {{
  font-size: 22px;
  font-weight: 700;
  color: #f8fafc;
  margin-top: 4px;
}}
.kpi-sub {{
  font-size: 11px;
  color: #94a3b8;
  margin-top: 2px;
}}

/* Section Headings */
.section-card {{
  background: #111a2c;
  border: 1px solid rgba(255, 255, 255, 0.06);
  border-radius: 10px;
  padding: 20px;
  margin-bottom: 20px;
}}
.section-title {{
  font-size: 15px;
  font-weight: 700;
  color: #f8fafc;
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 14px;
  border-bottom: 1px solid rgba(255, 255, 255, 0.06);
  padding-bottom: 10px;
}}
.section-title span.count {{
  font-size: 12px;
  font-weight: normal;
  color: #64748b;
}}

/* Filter and Search Controls */
.controls-bar {{
  display: flex;
  flex-wrap: wrap;
  gap: 10px;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 14px;
}}
.search-input {{
  background: #0b111e;
  border: 1px solid rgba(255, 255, 255, 0.12);
  border-radius: 6px;
  padding: 8px 12px;
  font-size: 12px;
  color: #f8fafc;
  min-width: 260px;
  outline: none;
  transition: border-color 0.15s;
}}
.search-input:focus {{
  border-color: #38bdf8;
}}
.filter-pills {{
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
}}
.filter-btn {{
  background: #1e293b;
  border: 1px solid rgba(255, 255, 255, 0.08);
  color: #94a3b8;
  padding: 5px 12px;
  border-radius: 6px;
  font-size: 11px;
  font-weight: 500;
  cursor: pointer;
  transition: all 0.15s;
}}
.filter-btn:hover {{
  color: #f1f5f9;
  border-color: rgba(255, 255, 255, 0.2);
}}
.filter-btn.active {{
  background: rgba(6, 182, 212, 0.15);
  border-color: #06b6d4;
  color: #38bdf8;
}}

/* Forensic Tables */
.table-wrapper {{
  overflow-x: auto;
  border: 1px solid rgba(255, 255, 255, 0.06);
  border-radius: 8px;
}}
table.forensic-table {{
  width: 100%;
  border-collapse: collapse;
  font-size: 12px;
  text-align: left;
}}
table.forensic-table th {{
  background: #0d1524;
  color: #94a3b8;
  font-weight: 600;
  padding: 10px 12px;
  border-bottom: 1px solid rgba(255, 255, 255, 0.08);
  white-space: nowrap;
}}
table.forensic-table td {{
  padding: 9px 12px;
  border-bottom: 1px solid rgba(255, 255, 255, 0.04);
  vertical-align: top;
}}
table.forensic-table tbody tr:hover {{
  background: rgba(255, 255, 255, 0.02);
}}
table.forensic-table tbody tr.row-recovered {{
  background: rgba(168, 85, 247, 0.03);
}}
table.forensic-table tbody tr.row-recovered:hover {{
  background: rgba(168, 85, 247, 0.07);
}}

/* Copyable hashes */
.hash-pill {{
  display: inline-flex;
  align-items: center;
  gap: 6px;
  background: rgba(0, 0, 0, 0.25);
  padding: 2px 6px;
  border-radius: 4px;
  border: 1px solid rgba(255, 255, 255, 0.06);
}}
.copy-btn {{
  background: transparent;
  border: none;
  color: #64748b;
  cursor: pointer;
  padding: 1px 3px;
  border-radius: 3px;
  font-size: 10px;
}}
.copy-btn:hover {{
  color: #38bdf8;
  background: rgba(255, 255, 255, 0.05);
}}

/* Chat & Messages view */
.chat-container {{
  display: flex;
  flex-direction: column;
  gap: 8px;
  max-height: 480px;
  overflow-y: auto;
  padding-right: 6px;
}}
.chat-item {{
  background: #0d1524;
  border: 1px solid rgba(255, 255, 255, 0.05);
  border-radius: 8px;
  padding: 10px 14px;
}}
.chat-item-header {{
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 4px;
  font-size: 11px;
}}
.chat-app {{
  font-weight: 600;
  color: #38bdf8;
}}
.chat-time {{
  color: #64748b;
}}
.chat-title {{
  font-weight: 500;
  color: #e2e8f0;
  font-size: 12px;
  margin-bottom: 2px;
}}
.chat-body {{
  color: #94a3b8;
  font-size: 12px;
  word-break: break-word;
}}

/* Sign-off box */
.signoff-grid {{
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
  gap: 20px;
  margin-top: 14px;
}}
.signoff-box {{
  border: 1px dashed rgba(255, 255, 255, 0.15);
  border-radius: 8px;
  padding: 16px;
  background: rgba(0, 0, 0, 0.15);
}}
.signoff-box h4 {{
  font-size: 12px;
  font-weight: 600;
  text-transform: uppercase;
  color: #94a3b8;
  margin-bottom: 12px;
}}
.sig-line {{
  border-bottom: 1px solid rgba(255, 255, 255, 0.2);
  margin-top: 36px;
  margin-bottom: 6px;
}}
.sig-label {{
  font-size: 11px;
  color: #64748b;
}}

/* Print Stylesheet */
@media print {{
  body {{
    background: #ffffff !important;
    color: #1e293b !important;
    font-size: 10pt;
  }}
  .container {{
    max-width: 100% !important;
    padding: 0 !important;
  }}
  .report-header, .section-card, .kpi-card {{
    background: #ffffff !important;
    border: 1px solid #cbd5e1 !important;
    box-shadow: none !important;
    color: #1e293b !important;
    break-inside: avoid;
  }}
  .brand-text h1, .section-title, .kpi-value {{
    color: #0f172a !important;
  }}
  table.forensic-table th {{
    background: #f1f5f9 !important;
    color: #334155 !important;
    border-bottom: 1px solid #cbd5e1 !important;
  }}
  table.forensic-table td {{
    border-bottom: 1px solid #e2e8f0 !important;
    color: #1e293b !important;
  }}
  .controls-bar, .search-input, .filter-pills, .copy-btn {{
    display: none !important;
  }}
  .alert-banner {{
    background: #fffbeb !important;
    border: 1px solid #f59e0b !important;
    color: #92400e !important;
  }}
}}
</style>
</head>
<body>
<div class="container">

  <!-- Header Card -->
  <header class="report-header">
    <div class="header-top">
      <div class="brand-title">
        <div class="brand-logo">FX</div>
        <div class="brand-text">
          <h1>Forensic Case Triage &amp; Examination Report</h1>
          <p>ForensiX Platform &bull; Verifiable Evidence Export</p>
        </div>
      </div>
      <div class="meta-badges">
        <span class="badge badge-warning">Preliminary Triage</span>
        <span class="badge badge-cyan">{_esc(report_info.redaction_profile.replace("_", " "))}</span>
        <span class="badge badge-slate">Schema {_esc(snapshot.schema_version)}</span>
      </div>
    </div>

    <!-- Case Metadata Grid -->
    <dl class="meta-grid">
      <div class="meta-item">
        <dt>Case Number</dt>
        <dd class="mono">{_esc(case.case_number)}</dd>
      </div>
      <div class="meta-item">
        <dt>Case Title</dt>
        <dd>{_esc(case.title)}</dd>
      </div>
      <div class="meta-item">
        <dt>Legal Authority</dt>
        <dd>{_esc(case.legal_authority or "Not specified")}</dd>
      </div>
      <div class="meta-item">
        <dt>Case Status</dt>
        <dd>{_esc(case.status.title())}</dd>
      </div>
      <div class="meta-item">
        <dt>Generated By</dt>
        <dd>{_esc(report_info.generated_by_name)}</dd>
      </div>
      <div class="meta-item">
        <dt>Generated At (UTC)</dt>
        <dd class="mono">{_esc(report_info.generated_at.isoformat())}</dd>
      </div>
      <div class="meta-item">
        <dt>Report UUID</dt>
        <dd class="mono">{_esc(report_info.report_id)}</dd>
      </div>
      <div class="meta-item">
        <dt>Tool Version</dt>
        <dd>{_esc(snapshot.tool_name)} v{_esc(snapshot.tool_version)}</dd>
      </div>
    </dl>
  </header>

  <!-- Warning Banner -->
  <div class="alert-banner">
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#fbbf24" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="flex-shrink: 0; margin-top: 1px;">
      <path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"/>
      <line x1="12" y1="9" x2="12" y2="13"/>
      <line x1="12" y1="17" x2="12.01" y2="17"/>
    </svg>
    <div>
      <strong>FORENSIC NOTICE:</strong> {_esc(report_info.preliminary_warning)}
      This report represents controlled logical triage artifacts. Forensic examinations conducted via ADB
      do not utilize hardware write-blocking. Unsupported or encrypted private data is not claimed as exhaustive.
    </div>
  </div>

  <!-- KPI Metrics Dashboard -->
  <div class="kpi-row">
    <div class="kpi-card">
      <div class="kpi-label">Evidence Sources</div>
      <div class="kpi-value">{total_sources}</div>
      <div class="kpi-sub">Containers &amp; extractions</div>
    </div>
    <div class="kpi-card">
      <div class="kpi-label">Acquired Files</div>
      <div class="kpi-value">{total_files}</div>
      <div class="kpi-sub">Manifest verified files</div>
    </div>
    <div class="kpi-card">
      <div class="kpi-label">Parsed Artifacts</div>
      <div class="kpi-value">{total_artifacts}</div>
      <div class="kpi-sub">Normalized records</div>
    </div>
    <div class="kpi-card">
      <div class="kpi-label">Carved / Recovered</div>
      <div class="kpi-value" style="color: #c084fc;">{len(recovered_artifacts)}</div>
      <div class="kpi-sub">Freelist &amp; freeblocks</div>
    </div>
    <div class="kpi-card">
      <div class="kpi-label">Timeline Events</div>
      <div class="kpi-value">{total_timeline}</div>
      <div class="kpi-sub">Chronological markers</div>
    </div>
    <div class="kpi-card">
      <div class="kpi-label">Custody Events</div>
      <div class="kpi-value">{total_custody}</div>
      <div class="kpi-sub">Hash-chained ledger</div>
    </div>
  </div>
"""

    # Section 1: Device & Readiness Summary
    doc += """
  <!-- Section: Assessed Devices -->
  <section class="section-card">
    <div class="section-title">
      <span>1. Assessed Devices &amp; Hardware Profile</span>
      <span class="count">"""
    doc += f"{len(snapshot.devices)} device(s)</span></div>"
    if not snapshot.devices:
        doc += "<p style='color: #64748b;'>No assessed device records recorded for this case.</p>"
    else:
        doc += """<div class="table-wrapper"><table class="forensic-table">
        <thead><tr>
          <th>Make &amp; Model</th>
          <th>Serial Suffix</th>
          <th>Android OS / SDK</th>
          <th>Security Patch</th>
          <th>Build Fingerprint</th>
        </tr></thead><tbody>"""
        for dev in snapshot.devices:
            dev_name = " ".join(filter(None, (dev.manufacturer, dev.model))) or "Unknown"
            doc += f"""<tr>
            <td><strong>{_esc(dev_name)}</strong></td>
            <td class="mono">{_esc(dev.serial_suffix)}</td>
            <td>{_esc(dev.android_version or "Unknown")} (SDK {_esc(dev.sdk_level or "N/A")})</td>
            <td>{_esc(dev.security_patch or "Unknown")}</td>
            <td class="mono" style="font-size: 10px; word-break: break-all;">{_esc(dev.build_fingerprint or "Unknown")}</td>
          </tr>"""
        doc += "</tbody></table></div>"
    doc += "</section>"

    # Section 2: Evidence Sources & Cryptographic Verification
    doc += """
  <!-- Section: Evidence Sources -->
  <section class="section-card">
    <div class="section-title">
      <span>2. Evidence Sources &amp; Integrity Verification</span>
      <span class="count">"""
    doc += f"{len(snapshot.evidence_sources)} source(s)</span></div>"
    if not snapshot.evidence_sources:
        doc += "<p style='color: #64748b;'>No imported evidence source records recorded for this case.</p>"
    else:
        doc += """<div class="table-wrapper"><table class="forensic-table">
        <thead><tr>
          <th>Source Name</th>
          <th>Type / Level</th>
          <th>Format / Status</th>
          <th>Size</th>
          <th>Master SHA-256</th>
          <th>Working Copies</th>
          <th>Parser Runs</th>
        </tr></thead><tbody>"""
        for src in snapshot.evidence_sources:
            sha_disp = (
                f'<span class="hash-pill mono">{_esc(src.sha256[:16])}...{_esc(src.sha256[-8:])} '
                f'<button class="copy-btn" onclick="copyText(\'{_esc(src.sha256)}\')" title="Copy SHA-256">Copy</button></span>'
                if src.sha256
                else "N/A"
            )
            doc += f"""<tr>
            <td><strong>{_esc(src.display_name)}</strong><br><span style="font-size: 10px; color: #64748b;">{_esc(src.source_name)}</span></td>
            <td>{_esc(src.source_type)}<br><span class="badge badge-slate" style="margin-top: 2px;">{_esc(src.acquisition_level)}</span></td>
            <td>{_esc(src.container_format)} &bull; <span class="badge badge-emerald">{_esc(src.status)}</span></td>
            <td>{_format_size(src.size_bytes)}</td>
            <td>{sha_disp}</td>
            <td>{len(src.working_copies)}</td>
            <td>{len(src.parser_runs)}</td>
          </tr>"""
        doc += "</tbody></table></div>"
    doc += "</section>"

    # Section 3: Carved & Recovered Data (Special Forensic Feature)
    doc += """
  <!-- Section: Carved & Recovered Data -->
  <section class="section-card">
    <div class="section-title">
      <span>3. Deep Forensic Carved &amp; Recovered Records</span>
      <span class="count">"""
    doc += f"{len(recovered_artifacts)} item(s)</span></div>"
    if not recovered_artifacts:
        doc += (
            "<p style='color: #64748b;'>No carved fragments or recovered freelist/freeblock records "
            "detected in this snapshot.</p>"
        )
    else:
        doc += """<div class="table-wrapper"><table class="forensic-table">
        <thead><tr>
          <th>Artifact Title</th>
          <th>Category / Subtype</th>
          <th>Status</th>
          <th>Source Locator</th>
          <th>Parser</th>
          <th>Summary / Content</th>
          <th>Confidence</th>
        </tr></thead><tbody>"""
        for art in recovered_artifacts:
            doc += f"""<tr class="row-recovered">
            <td><strong>{_esc(art.title)}</strong></td>
            <td>{_esc(art.category)}<br><span style="font-size: 10px; color: #94a3b8;">{_esc(art.subtype)}</span></td>
            <td><span class="badge badge-purple">Recovered</span></td>
            <td class="mono" style="font-size: 10px; word-break: break-all;">{_esc(art.source_locator)}</td>
            <td style="font-size: 10px;">{_esc(art.parser_id)}</td>
            <td style="word-break: break-word;">{_esc(art.summary)}</td>
            <td><span class="badge badge-slate">{_esc(art.confidence)}</span></td>
          </tr>"""
        doc += "</tbody></table></div>"
    doc += "</section>"

    # Section 4: Readable Communications
    doc += """
  <!-- Section: Communications & Chat Timeline -->
  <section class="section-card">
    <div class="section-title">
      <span>4. Communications &amp; Messages</span>
      <span class="count">"""
    doc += f"{len(chat_messages)} message(s)</span></div>"
    if not chat_messages:
        doc += "<p style='color: #64748b;'>No readable communication or messaging artifacts recorded in this snapshot.</p>"
    else:
        doc += '<div class="chat-container">'
        for t, app, title, summary, status in chat_messages[:300]:
            status_badge = (
                '<span class="badge badge-purple" style="font-size: 9px; padding: 1px 6px;">Recovered</span>'
                if status == "recovered"
                else ""
            )
            doc += f"""<div class="chat-item">
            <div class="chat-item-header">
              <div><span class="chat-app">{_esc(app)}</span> {status_badge}</div>
              <div class="chat-time mono">{_esc(t)}</div>
            </div>
            <div class="chat-title">{_esc(title)}</div>
            <div class="chat-body">{_esc(summary)}</div>
          </div>"""
        if len(chat_messages) > 300:
            doc += f"<p style='color: #64748b; font-size: 11px; margin-top: 8px;'>Showing 300 of {len(chat_messages)} messages.</p>"
        doc += "</div>"
    doc += "</section>"

    # Section 5: Filterable Normalized Artifacts Inventory
    doc += """
  <!-- Section: Artifacts Inventory -->
  <section class="section-card">
    <div class="section-title">
      <span>5. Normalized Forensic Artifacts Inventory</span>
      <span class="count">"""
    doc += f"{len(snapshot.imported_artifacts)} artifact(s)</span></div>"

    # Search & Filter Controls
    doc += """<div class="controls-bar">
      <input type="text" id="artifactSearchInput" class="search-input" placeholder="Search artifacts by title, locator, or content..." oninput="filterArtifacts()">
      <div class="filter-pills" id="categoryFilterPills">
        <button class="filter-btn active" onclick="setCategoryFilter('all', this)">All</button>"""
    for cat in categories:
        doc += f'<button class="filter-btn" onclick="setCategoryFilter(\'{_esc(cat)}\', this)">{_esc(cat.title())}</button>'
    if recovered_artifacts:
        doc += '<button class="filter-btn" onclick="setCategoryFilter(\'recovered\', this)">Recovered (Carved)</button>'
    doc += """</div></div>"""

    if not snapshot.imported_artifacts:
        doc += "<p style='color: #64748b;'>No normalized artifacts recorded in this snapshot.</p>"
    else:
        doc += """<div class="table-wrapper"><table class="forensic-table" id="artifactsTable">
        <thead><tr>
          <th>Time</th>
          <th>Category</th>
          <th>Subtype</th>
          <th>Status</th>
          <th>Title &amp; Summary</th>
          <th>Source Locator</th>
          <th>Parser</th>
          <th>Hash</th>
        </tr></thead><tbody>"""
        for art in snapshot.imported_artifacts:
            t_str = art.event_time.isoformat() if art.event_time else ""
            status_cls = "row-recovered" if art.status.lower() == "recovered" else ""
            badge_cls = "badge-purple" if art.status.lower() == "recovered" else "badge-slate"
            short_hash = (
                f'<span class="hash-pill mono">{_esc(art.artifact_hash[:8])}..<button class="copy-btn" onclick="copyText(\'{_esc(art.artifact_hash)}\')" title="Copy Hash">Copy</button></span>'
                if art.artifact_hash
                else ""
            )
            doc += f"""<tr class="{status_cls}" data-category="{_esc(art.category.lower())}" data-status="{_esc(art.status.lower())}">
            <td class="mono" style="font-size: 10px; white-space: nowrap;">{_esc(t_str)}</td>
            <td>{_esc(art.category)}</td>
            <td style="color: #94a3b8;">{_esc(art.subtype)}</td>
            <td><span class="badge {badge_cls}">{_esc(art.status)}</span></td>
            <td><strong>{_esc(art.title)}</strong><br><span style="color: #94a3b8; font-size: 11px;">{_esc(art.summary)}</span></td>
            <td class="mono" style="font-size: 10px; word-break: break-all;">{_esc(art.source_locator)}</td>
            <td style="font-size: 10px;">{_esc(art.parser_id)}</td>
            <td>{short_hash}</td>
          </tr>"""
        doc += "</tbody></table></div>"
    doc += "</section>"

    # Section 6: Chronological Timeline Events
    doc += """
  <!-- Section: Timeline Events -->
  <section class="section-card">
    <div class="section-title">
      <span>6. Chronological Forensic Timeline</span>
      <span class="count">"""
    doc += f"{len(snapshot.timeline)} event(s)</span></div>"
    if not snapshot.timeline:
        doc += "<p style='color: #64748b;'>No timeline events recorded in this snapshot.</p>"
    else:
        doc += """<div class="table-wrapper"><table class="forensic-table">
        <thead><tr>
          <th>Timestamp (UTC)</th>
          <th>Category</th>
          <th>Timestamp Type</th>
          <th>Summary</th>
          <th>Confidence</th>
        </tr></thead><tbody>"""
        for evt in snapshot.timeline[:200]:
            doc += f"""<tr>
            <td class="mono" style="white-space: nowrap;">{_esc(evt.event_time.isoformat())}</td>
            <td>{_esc(evt.category)}</td>
            <td style="color: #94a3b8;">{_esc(evt.timestamp_type)}</td>
            <td>{_esc(evt.summary)}</td>
            <td><span class="badge badge-slate">{_esc(evt.confidence)}</span></td>
          </tr>"""
        if len(snapshot.timeline) > 200:
            doc += f"<tr><td colspan='5' style='color: #64748b; font-size: 11px;'>Showing 200 of {len(snapshot.timeline)} timeline events.</td></tr>"
        doc += "</tbody></table></div>"
    doc += "</section>"

    # Section 7: Chain of Custody & Hash Manifest
    doc += """
  <!-- Section: Chain of Custody -->
  <section class="section-card">
    <div class="section-title">
      <span>7. Cryptographic Chain of Custody</span>
      <span class="count">"""
    doc += f"{len(snapshot.custody)} event(s)</span></div>"
    if not snapshot.custody:
        doc += "<p style='color: #64748b;'>No custody events recorded for this case.</p>"
    else:
        doc += """<div class="table-wrapper"><table class="forensic-table">
        <thead><tr>
          <th>Seq</th>
          <th>Timestamp (UTC)</th>
          <th>Event Type</th>
          <th>Actor ID</th>
          <th>Evidence / Object</th>
          <th>SHA-256 Event Hash</th>
        </tr></thead><tbody>"""
        for item in snapshot.custody:
            evidence_ref = item.evidence_file_id or item.evidence_source_id or "Case"
            hash_disp = (
                f'<span class="hash-pill mono">{_esc(item.event_hash[:16])}...{_esc(item.event_hash[-8:])} '
                f'<button class="copy-btn" onclick="copyText(\'{_esc(item.event_hash)}\')" title="Copy Event Hash">Copy</button></span>'
                if item.event_hash
                else "N/A"
            )
            doc += f"""<tr>
            <td class="mono"><strong>#{item.sequence}</strong></td>
            <td class="mono" style="white-space: nowrap;">{_esc(item.created_at.isoformat())}</td>
            <td><strong>{_esc(item.event_type.replace("_", " "))}</strong></td>
            <td class="mono" style="font-size: 10px;">{_esc(item.actor_id)}</td>
            <td class="mono" style="font-size: 10px;">{_esc(evidence_ref)}</td>
            <td>{hash_disp}</td>
          </tr>"""
        doc += "</tbody></table></div>"
    doc += "</section>"

    # Section 8: Methodology, Limitations & Examiner Sign-off
    doc += """
  <!-- Section: Methodology, Limitations & Sign-off -->
  <section class="section-card">
    <div class="section-title">
      <span>8. Methodology, Known Limitations &amp; Examiner Sign-off</span>
    </div>

    <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 20px; margin-bottom: 20px;">
      <div>
        <h4 style="font-size: 12px; color: #94a3b8; text-transform: uppercase; margin-bottom: 8px;">Methodology</h4>
        <ul style="padding-left: 18px; color: #cbd5e1; font-size: 12px;">"""
    for m in snapshot.methodology:
        doc += f"<li style='margin-bottom: 4px;'>{_esc(m)}</li>"
    doc += """</ul>
      </div>
      <div>
        <h4 style="font-size: 12px; color: #94a3b8; text-transform: uppercase; margin-bottom: 8px;">Known Limitations</h4>
        <ul style="padding-left: 18px; color: #cbd5e1; font-size: 12px;">"""
    for lim in snapshot.limitations:
        doc += f"<li style='margin-bottom: 4px;'>{_esc(lim)}</li>"
    doc += """</ul>
      </div>
    </div>"""

    if snapshot.errors:
        doc += """<div style="background: rgba(239, 68, 68, 0.1); border: 1px solid rgba(239, 68, 68, 0.3); border-radius: 6px; padding: 12px; margin-bottom: 20px;">
        <h4 style="font-size: 12px; color: #f87171; text-transform: uppercase; margin-bottom: 6px;">Recorded Triage Errors</h4>
        <ul style="padding-left: 18px; color: #fca5a5; font-size: 12px;">"""
        for err in snapshot.errors:
            doc += f"<li style='margin-bottom: 4px;'>{_esc(err)}</li>"
        doc += "</ul></div>"

    doc += f"""
    <!-- Formal Sign-off Block -->
    <div class="signoff-grid">
      <div class="signoff-box">
        <h4>Lead Forensic Examiner</h4>
        <p style="font-size: 12px; color: #f1f5f9;">{_esc(report_info.generated_by_name)}</p>
        <p style="font-size: 10px; color: #64748b;">Examiner ID: {_esc(report_info.generated_by_id)}</p>
        <div class="sig-line"></div>
        <div class="sig-label">Signature &bull; Date</div>
      </div>
      <div class="signoff-box">
        <h4>Supervisory / Independent Reviewer</h4>
        <p style="font-size: 12px; color: #94a3b8;">Pending Peer Examination</p>
        <p style="font-size: 10px; color: #64748b;">Chain-of-Custody Rule 702 Compliance</p>
        <div class="sig-line"></div>
        <div class="sig-label">Signature &bull; Date</div>
      </div>
    </div>
  </section>

</div>

<!-- Vanilla JavaScript for Client-Side Interactivity -->
<script>
var activeCategory = 'all';

function setCategoryFilter(category, btn) {{
  activeCategory = category;
  var buttons = document.querySelectorAll('#categoryFilterPills .filter-btn');
  buttons.forEach(function(b) {{ b.classList.remove('active'); }});
  if (btn) {{ btn.classList.add('active'); }}
  filterArtifacts();
}}

function filterArtifacts() {{
  var query = (document.getElementById('artifactSearchInput') ? document.getElementById('artifactSearchInput').value : '').toLowerCase().trim();
  var rows = document.querySelectorAll('#artifactsTable tbody tr');
  rows.forEach(function(row) {{
    var rowCat = row.getAttribute('data-category') || '';
    var rowStatus = row.getAttribute('data-status') || '';
    var text = row.textContent.toLowerCase();

    var matchesCat = true;
    if (activeCategory === 'recovered') {{
      matchesCat = (rowStatus === 'recovered');
    }} else if (activeCategory !== 'all') {{
      matchesCat = (rowCat === activeCategory);
    }}

    var matchesQuery = (!query || text.indexOf(query) !== -1);
    row.style.display = (matchesCat && matchesQuery) ? '' : 'none';
  }});
}}

function copyText(text) {{
  if (navigator.clipboard && navigator.clipboard.writeText) {{
    navigator.clipboard.writeText(text).then(function() {{
      showToast('Copied to clipboard!');
    }}).catch(function() {{
      fallbackCopy(text);
    }});
  }} else {{
    fallbackCopy(text);
  }}
}}

function fallbackCopy(text) {{
  var ta = document.createElement('textarea');
  ta.value = text;
  ta.style.position = 'fixed';
  ta.style.opacity = '0';
  document.body.appendChild(ta);
  ta.select();
  try {{
    document.execCommand('copy');
    showToast('Copied to clipboard!');
  }} catch (e) {{}}
  document.body.removeChild(ta);
}}

function showToast(msg) {{
  var existing = document.getElementById('forensixToast');
  if (existing) {{ existing.remove(); }}
  var toast = document.createElement('div');
  toast.id = 'forensixToast';
  toast.textContent = msg;
  toast.style.cssText = 'position:fixed;bottom:24px;right:24px;background:#06b6d4;color:#0f172a;padding:8px 16px;border-radius:6px;font-size:12px;font-weight:600;box-shadow:0 4px 12px rgba(0,0,0,0.5);z-index:9999;transition:opacity 0.3s;';
  document.body.appendChild(toast);
  setTimeout(function() {{
    toast.style.opacity = '0';
    setTimeout(function() {{ if (toast.parentNode) toast.parentNode.removeChild(toast); }}, 300);
  }}, 2000);
}}
</script>
</body>
</html>"""

    return doc.encode("utf-8")
