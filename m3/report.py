"""PDF and JSON report generation for M3.

The report is assembled only from the run summary, merged findings, the health
payload, the remediation bundle and the PR summary. Nothing is invented; when a
section was not generated the report says so.

PDF output uses reportlab (added to requirements.txt). The JSON payload is the
canonical, complete export; the PDF is a human-readable rendering of it.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from io import BytesIO
from pathlib import Path

from m3.config import MAX_REPORT_FINDINGS
from m3.health import compute_health

SCHEMA_VERSION = "m3.1"


def _get(item, name, default=None):
    if isinstance(item, dict):
        return item.get(name, default)
    return getattr(item, name, default)


def _finding_dict(finding) -> dict:
    """Structured finding for the JSON export (never a str() rendering)."""
    if isinstance(finding, dict):
        return finding
    to_dict = getattr(finding, "to_dict", None)
    if callable(to_dict):
        return to_dict()
    data = getattr(finding, "__dict__", None)
    if isinstance(data, dict):
        return {k: v for k, v in data.items() if not k.startswith("_")}
    return {"value": str(finding)}


def build_json_report(run: dict, findings: list, remediation: dict | None,
                      summary: dict | None) -> dict:
    findings = list(findings or [])
    health = compute_health(run.get("status"), findings)
    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "run": run,
        "health": health,
        # Findings may arrive as Finding dataclasses (pipeline) or dicts (tests);
        # the JSON export must contain structured objects, never str() renderings.
        "findings": [_finding_dict(f) for f in findings[:MAX_REPORT_FINDINGS]],
        "finding_count": len(findings),
        "findings_truncated": len(findings) > MAX_REPORT_FINDINGS,
        "summary": summary,
        "remediation": remediation,
        "disclaimer": (
            "Static analysis report. Submitted code was not executed. The health score is derived "
            "from severity-weighted findings and is not a security guarantee. Remediation examples "
            "are suggestions and were not applied."
        ),
    }


# --------------------------------------------------------------------------
# PDF rendering
# --------------------------------------------------------------------------

def _pdf_text(text, mono: bool = False) -> str:
    """Preserve non-WinAnsi characters when a Unicode TTF is registered.

    A registered TTF still has a finite glyph repertoire (Segoe UI/Arial/DejaVu
    contain no CJK or emoji), and reportlab draws missing glyphs as blanks. Those
    characters are replaced with '?' so the reader can tell the character is
    unsupported instead of silently losing text.
    """
    value = str(text or "").replace("\r\n", "\n")
    value = "".join(ch for ch in value if ch in "\n\t" or ord(ch) >= 32)
    fonts = _register_fonts()
    if fonts["unicode"]:
        supported = fonts["code_cmap"] if mono else fonts["body_cmap"]
        if supported:
            value = "".join(
                ch if ch in "\n\t" or ord(ch) in supported else "?"
                for ch in value
            )
        return value
    # Built-in fonts only cover WinAnsi: transliterate rather than lose the page.
    return value.encode("cp1252", "replace").decode("cp1252")


_FONTS = {
    "ready": False,
    "body": "Helvetica",
    "bold": "Helvetica-Bold",
    "code": "Courier",
    "unicode": False,
    "source": None,
    "body_cmap": None,
    "code_cmap": None,
}

_FONT_DIRS = (
    Path(__file__).resolve().parents[1] / "assets" / "fonts",
    Path("C:/Windows/Fonts"),
    Path("/usr/share/fonts/truetype/dejavu"),
    Path("/usr/share/fonts/truetype/liberation"),
    Path("/usr/share/fonts/truetype/noto"),
    Path("/System/Library/Fonts/Supplemental"),
    Path("/Library/Fonts"),
)

# (regular, bold, monospace) per family. DejaVu first: broadest Unicode coverage
# among fonts commonly installed; Arial/Segoe UI cover Latin, Greek and Cyrillic.
_FONT_FAMILIES = (
    ("DejaVuSans.ttf", "DejaVuSans-Bold.ttf", "DejaVuSansMono.ttf"),
    ("segoeui.ttf", "segoeuib.ttf", "consola.ttf"),
    ("arial.ttf", "arialbd.ttf", "consola.ttf"),
    ("LiberationSans-Regular.ttf", "LiberationSans-Bold.ttf", "LiberationMono-Regular.ttf"),
)


def _font_cmap(font_name: str):
    """Codepoints the embedded font can actually draw, or None if unknown."""
    try:
        from reportlab.pdfbase import pdfmetrics

        face = pdfmetrics.getFont(font_name).face
        return frozenset(face.charToGlyph)
    except Exception:
        return None


def _register_fonts() -> dict:
    """Embed a system TrueType font when one exists; else keep the built-ins.

    No font is bundled and no dependency is added. If registration fails for any
    reason the report still renders with Helvetica, exactly as before.
    """
    if _FONTS["ready"]:
        return _FONTS
    _FONTS["ready"] = True
    try:
        from reportlab.pdfbase import pdfmetrics
        from reportlab.pdfbase.pdfmetrics import registerFontFamily
        from reportlab.pdfbase.ttfonts import TTFont
    except Exception:  # pragma: no cover - reportlab present in requirements
        return _FONTS

    for directory in _FONT_DIRS:
        try:
            exists = directory.is_dir()
        except OSError:
            exists = False
        if not exists:
            continue
        for regular_name, bold_name, mono_name in _FONT_FAMILIES:
            regular = directory / regular_name
            bold = directory / bold_name
            if not (regular.is_file() and bold.is_file()):
                continue
            try:
                pdfmetrics.registerFont(TTFont("ReportBody", str(regular)))
                pdfmetrics.registerFont(TTFont("ReportBody-Bold", str(bold)))
                registerFontFamily(
                    "ReportBody",
                    normal="ReportBody",
                    bold="ReportBody-Bold",
                    italic="ReportBody",
                    boldItalic="ReportBody-Bold",
                )
                code_font = "ReportBody"
                mono = directory / mono_name
                if mono.is_file():
                    try:
                        pdfmetrics.registerFont(TTFont("ReportCode", str(mono)))
                        code_font = "ReportCode"
                    except Exception:
                        code_font = "ReportBody"
                _FONTS.update(
                    body="ReportBody",
                    bold="ReportBody-Bold",
                    code=code_font,
                    unicode=True,
                    source=regular.name,
                    body_cmap=_font_cmap("ReportBody"),
                    code_cmap=_font_cmap(code_font),
                )
                return _FONTS
            except Exception:
                continue
    return _FONTS


def _esc(text, mono: bool = False) -> str:
    return (
        _pdf_text(text, mono=mono)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )


# Usable text width of a code block: page width minus both margins and padding.
CODE_LIMIT_PT = (210 - 2 * 18) * 72 / 25.4 - 14


def _wrap_code(code: str, mono: bool = True) -> list[str]:
    """Hard-wrap code by measured width so no line can overflow the page."""
    raw_lines = str(code or "").replace("\r\n", "\n").replace("\t", "    ").split("\n")
    try:
        from reportlab.pdfbase import pdfmetrics

        font_name = _register_fonts()["code"] if mono else _register_fonts()["body"]

        def measure(candidate: str) -> float:
            return pdfmetrics.stringWidth(candidate, font_name, 7.2)
    except Exception:
        measure = None

    lines = []
    for raw_line in raw_lines:
        if measure is None:
            remaining = raw_line
            while len(remaining) > 100:
                lines.append(remaining[:100])
                remaining = remaining[100:]
            lines.append(remaining)
            continue
        remaining = raw_line
        while remaining and measure(remaining) > CODE_LIMIT_PT:
            low, high = 1, len(remaining)
            while low < high:
                mid = (low + high + 1) // 2
                if measure(remaining[:mid]) <= CODE_LIMIT_PT:
                    low = mid
                else:
                    high = mid - 1
            lines.append(remaining[:low])
            remaining = remaining[low:]
        lines.append(remaining)
    return lines


def build_pdf_report(run: dict, findings: list, remediation: dict | None,
                     summary: dict | None) -> bytes:
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_LEFT
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.platypus import (
        KeepTogether,
        PageBreak,
        Paragraph,
        SimpleDocTemplate,
        Spacer,
        Table,
        TableStyle,
    )

    findings = list(findings or [])
    health = compute_health(run.get("status"), findings)
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    styles = getSampleStyleSheet()
    fonts = _register_fonts()
    title_style = ParagraphStyle(
        "ReportTitle", parent=styles["Title"], fontName=fonts["bold"],
        fontSize=20, leading=24, textColor=colors.HexColor("#0f172a"), spaceAfter=4,
    )
    h1 = ParagraphStyle(
        "H1", parent=styles["Heading1"], fontName=fonts["bold"],
        fontSize=13, leading=16, textColor=colors.HexColor("#312e81"),
        spaceBefore=10, spaceAfter=5,
    )
    h2 = ParagraphStyle(
        "H2", parent=styles["Heading2"], fontName=fonts["bold"],
        fontSize=10.5, leading=13, textColor=colors.HexColor("#0f172a"),
        spaceBefore=8, spaceAfter=3,
    )
    body = ParagraphStyle(
        "Body", parent=styles["BodyText"], fontName=fonts["body"],
        fontSize=8.8, leading=12, alignment=TA_LEFT, spaceAfter=3,
    )
    small = ParagraphStyle(
        "Small", parent=body, fontSize=7.6, leading=10, textColor=colors.HexColor("#475569"),
    )
    code_style = ParagraphStyle(
        "Code", parent=body, fontName=fonts["code"], fontSize=7.2, leading=9.2,
        backColor=colors.HexColor("#f1f5f9"), borderPadding=4, spaceBefore=2, spaceAfter=4,
    )
    status_style = ParagraphStyle(
        "Status", parent=body, fontName=fonts["bold"], fontSize=11, leading=14,
    )

    story = []
    story.append(Paragraph("AI Code Review Report", title_style))
    story.append(Paragraph(
        _esc(f"{run.get('filename') or 'submitted source'} \u00b7 {run.get('language') or 'unknown'} "
             f"\u00b7 run {run.get('run_id')}"),
        small,
    ))
    story.append(Paragraph(_esc(f"Generated {generated}"), small))
    story.append(Paragraph(_esc(
        "PDF font: " + (fonts["source"] or "built-in Helvetica (WinAnsi)")
        + (" \u2014 Unicode text; characters this font lacks are shown as '?'"
           if fonts["unicode"] else " \u2014 non-Latin characters are transliterated")
    ), small))
    story.append(Spacer(1, 6 * mm))

    review = (summary or {}).get("review_status") or {}
    review_label = review.get("label") or "Review status unavailable"
    story.append(Paragraph("Review status", h1))
    story.append(Paragraph(_esc(review_label), status_style))
    if review.get("rationale"):
        story.append(Paragraph(_esc(review["rationale"]), body))

    run_meta = [
        ["Analysis status", str(run.get("status") or "unknown")],
        ["Findings", str(len(findings))],
        ["Health score", f"{health['score']}/100 ({health['label']})" if health.get("available")
         else f"Withheld — {health.get('reason')}"],
        ["Language", str(run.get("language") or "unknown")],
        ["File", str(run.get("filename") or "submitted source")],
    ]
    meta_table = Table(
        [[Paragraph(_esc(k), small), Paragraph(_esc(v), small)] for k, v in run_meta],
        colWidths=[38 * mm, 128 * mm],
        hAlign="LEFT",
    )
    meta_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#eef2ff")),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#cbd5e1")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(Spacer(1, 3 * mm))
    story.append(meta_table)

    story.append(Paragraph("Executive overview", h1))
    overview = (summary or {}).get("executive_overview") or (
        f"The run analysed {len(findings)} finding(s) with status {run.get('status')}."
    )
    story.append(Paragraph(_esc(overview), body))

    story.append(Paragraph("Health score", h1))
    if health.get("available"):
        story.append(Paragraph(_esc(
            f"{health['score']}/100 — {health['label']}. {health.get('explanation', '')}"
        ), body))
        weight_rows = [["Severity", "Count", "Weight each", "Deduction"]]
        for component in health["components"]:
            weight_rows.append([
                component["severity"], str(component["count"]),
                str(component["weight_each"]), str(component["deduction"]),
            ])
        weight_table = Table(
            weight_rows, colWidths=[35 * mm, 28 * mm, 40 * mm, 40 * mm], hAlign="LEFT"
        )
        weight_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e2e8f0")),
            ("FONTNAME", (0, 0), (-1, 0), fonts["bold"]),
            ("FONTNAME", (0, 1), (-1, -1), fonts["body"]),
            ("FONTSIZE", (0, 0), (-1, -1), 7.8),
            ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#cbd5e1")),
        ]))
        story.append(weight_table)
        story.append(Paragraph(_esc(health.get("caveat") or ""), small))
    else:
        story.append(Paragraph(_esc(health.get("reason") or "Score unavailable."), body))
        story.append(Paragraph(
            "No numeric score is shown for an incomplete run because it would be misleading.",
            small,
        ))

    story.append(Paragraph("Severity breakdown", h1))
    severity_counts = (summary or {}).get("severity_counts") or health.get("counts") or {}
    severity_rows = [["Severity", "Findings"]]
    for severity in ("critical", "high", "medium", "low", "info"):
        severity_rows.append([severity, str(severity_counts.get(severity, 0))])
    severity_table = Table(severity_rows, colWidths=[50 * mm, 35 * mm], hAlign="LEFT")
    severity_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e2e8f0")),
        ("FONTNAME", (0, 0), (-1, 0), fonts["bold"]),
        ("FONTNAME", (0, 1), (-1, -1), fonts["body"]),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#cbd5e1")),
    ]))
    story.append(severity_table)

    story.append(Paragraph("Prioritized actions", h1))
    priorities = (summary or {}).get("prioritized_fixes") or []
    if priorities:
        for item in priorities:
            location = item.get("location") or {}
            story.append(Paragraph(
                _esc(f"{item.get('priority')}. [{item.get('severity')}] {item.get('title')} "
                     f"({item.get('rule_id')}) — line {location.get('line_start')}"),
                body,
            ))
            story.append(Paragraph(_esc(f"Action: {item.get('action')}"), small))
    else:
        story.append(Paragraph(
            "No prioritized actions were generated. This is not proof that the code is secure.",
            body,
        ))

    story.append(Paragraph("Findings and remediation", h1))
    remediation_by_id = {}
    if remediation:
        remediation_by_id = {
            item.get("finding_id"): item for item in remediation.get("findings") or []
        }
    if not findings:
        story.append(Paragraph("No findings were reported by the implemented rules.", body))
    for index, finding in enumerate(findings[:MAX_REPORT_FINDINGS], start=1):
        # Title and metadata are separate paragraphs so a long title cannot push a
        # dangling dash/rule id onto its own line.
        heading = f"{index}. {_get(finding, 'title')}"
        location = (
            f"{_get(finding, 'file_path') or 'file'}:{_get(finding, 'line_start')}"
            + (f"-{_get(finding, 'line_end')}" if _get(finding, "line_end") not in (None, _get(finding, "line_start")) else "")
        )
        meta = f"{_get(finding, 'rule_id')} \u00b7 {_get(finding, 'severity')} \u00b7 {location}"
        item = remediation_by_id.get(_get(finding, "id"))
        block = [
            Paragraph(_esc(heading), h2),
            Paragraph(_esc(meta), small),
            Paragraph(_esc(_get(finding, "description") or ""), body),
        ]
        snippet = _get(finding, "code_snippet")
        if snippet:
            block.append(Paragraph("Code snippet", small))
            block.append(Paragraph(
                "<br/>".join(_esc(line, mono=True) for line in _wrap_code(snippet[:2500])),
                code_style,
            ))
        if not item:
            block.append(Paragraph(
                "No remediation bundle item exists for this finding in the report.", small
            ))
        story.append(KeepTogether(block))

        # Remediation is its own group: keeping it with the finding above would
        # leave large blank areas whenever the pair does not fit on one page.
        remedy = []
        if item:
            # Naming the finding keeps the block meaningful if it starts a new page.
            remedy.append(Paragraph(
                _esc(f"Finding {index} \u2014 remediation ({item.get('remediation_status')}): "
                     f"{item.get('recommended_fix')}"),
                body,
            ))
            remedy.append(Paragraph(_esc(f"Why: {item.get('reason_for_fix')}"), small))
            remedy.append(Paragraph(_esc(f"Best practice: {item.get('best_practice')}"), small))
            if item.get("corrected_code"):
                remedy.append(Paragraph("Illustrative corrected code", small))
                remedy.append(Paragraph(
                    "<br/>".join(
                        _esc(line, mono=True) for line in _wrap_code(item["corrected_code"][:3500])
                    ),
                    code_style,
                ))
            story.append(KeepTogether(remedy))
        story.append(Spacer(1, 2.5 * mm))

    caveats = (summary or {}).get("caveats") or []
    caveat_items = [Paragraph("• " + _esc(caveat), small) for caveat in caveats] or [
        Paragraph("No additional caveats were recorded.", small)
    ]
    # Keep the heading with its first line so it cannot sit alone at a page foot.
    story.append(KeepTogether([Paragraph("Caveats and limitations", h1), caveat_items[0]]))
    story.extend(caveat_items[1:])

    # No forced page break: a short disclaimer used to occupy a page of its own.
    scope = [
        Paragraph("Scope and disclaimer", h1),
        Paragraph(_esc(
            "This report was generated by a static analysis pipeline. Submitted code was never executed. "
            "Detections are limited to the implemented Python/Java rules; absence of a finding is not "
            "proof of safety. Remediation text and corrected-code examples are suggestions only and have "
            "not been applied or verified. Do not treat the health score as a security certification."
        ), body),
    ]
    if remediation is None:
        scope.append(Paragraph("No remediation bundle was generated for this run.", body))
    else:
        scope.append(Paragraph(_esc(
            f"Remediation mode: {remediation.get('mode')}; findings remediated: "
            f"{remediation.get('finding_count')}; LLM used: "
            f"{bool((remediation.get('llm') or {}).get('used'))}."
        ), body))
    story.append(KeepTogether(scope[:2]))
    story.extend(scope[2:])

    buffer = BytesIO()
    document = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        leftMargin=18 * mm,
        rightMargin=18 * mm,
        topMargin=16 * mm,
        bottomMargin=16 * mm,
        title=f"AI Code Review Report {run.get('run_id')}",
        author="AI Code Review Platform",
    )

    def footer(canvas, doc):
        canvas.saveState()
        canvas.setFont(fonts["body"], 7)
        canvas.setFillColor(colors.HexColor("#64748b"))
        canvas.drawString(18 * mm, 9 * mm, f"AI Code Review Report — {run.get('run_id')}")
        canvas.drawRightString(A4[0] - 18 * mm, 9 * mm, f"Page {doc.page}")
        canvas.restoreState()

    document.build(story, onFirstPage=footer, onLaterPages=footer)
    return buffer.getvalue()


def build_report_bytes(fmt: str, run: dict, findings: list, remediation: dict | None,
                       summary: dict | None) -> tuple[bytes, str, str]:
    """Return (payload, content_type, filename)."""
    if fmt == "pdf":
        payload = build_pdf_report(run, findings, remediation, summary)
        return payload, "application/pdf", f"code-review-{run.get('run_id')}.pdf"
    payload = json.dumps(
        build_json_report(run, findings, remediation, summary),
        indent=2,
        default=str,
    ).encode("utf-8")
    return payload, "application/json", f"code-review-{run.get('run_id')}.json"
