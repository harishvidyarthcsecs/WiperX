# wiperx/core/report_generator.py
"""
Report Generator
----------------
Generates wipe reports in two formats:
  1. JSON  : Machine-readable, stored in /reports/ directory.
  2. PDF   : Human-readable certificate of destruction.

Reports include:
  - Timestamp (UTC)
  - Hostname and OS
  - Disk model and serial number
  - Wipe method/strategy used
  - Verification result
  - Log excerpt
  - Operator name (if provided)
"""

import json
import logging
import os
from datetime import datetime
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# Reports output directory
REPORTS_DIR = Path(__file__).parent.parent / "reports"
REPORTS_DIR.mkdir(exist_ok=True)


class ReportGenerator:
    """
    Generates JSON and PDF wipe reports after a wipe operation completes.
    """

    def build_report_dict(
        self,
        wipe_result,
        verification_result: Optional[dict] = None,
        operator: str = "System",
    ) -> dict:
        """
        Assemble the machine-readable wipe report dict (pre-signature).

        Args:
            wipe_result         : WipeResult dataclass from ExecutionManager.
            verification_result : Optional dict from WipeVerifier. Falls back to
                                  wipe_result.verification, then a "not performed"
                                  stub.
            operator            : Name of the person/system that initiated the wipe.

        Returns:
            dict
        """
        verification = (
            verification_result
            or getattr(wipe_result, "verification", None)
            or {
                "verified": None,
                "method": "none",
                "details": "Verification not performed.",
            }
        )
        return {
            "wiperx_report": {
                "schema_version": "1.1",
                "generated_at": datetime.utcnow().isoformat() + "Z",
                "operator": operator,
            },
            "operation": {
                "timestamp": wipe_result.timestamp,
                "success": wipe_result.success,
                "error": wipe_result.error,
            },
            "target": {
                "hostname": wipe_result.hostname,
                "os_detected": wipe_result.os_detected,
                "disk_identifier": wipe_result.disk_identifier,
                "disk_model": wipe_result.disk_model,
                "disk_serial": wipe_result.disk_serial,
            },
            "wipe": {
                "strategy_used": wipe_result.strategy_name,
                "method": getattr(wipe_result, "method", "auto"),
                "pass_count": getattr(wipe_result, "pass_count", 0),
                "log_lines": wipe_result.log_lines,
            },
            "verification": verification,
            "compliance": {
                "standard": "NIST SP 800-88 Rev.1 (Guidelines for Media Sanitization)",
                "note": (
                    "This report documents a software-based sanitization operation. "
                    "For certified destruction, engage a NIST-compliant service provider."
                ),
            },
        }

    def generate_json_report(
        self,
        wipe_result,
        verification_result: Optional[dict] = None,
        operator: str = "System",
    ) -> Path:
        """
        Generate a JSON wipe report (unsigned).

        Returns:
            Path: Path to the generated JSON report file.
        """
        report_data = self.build_report_dict(wipe_result, verification_result, operator)

        safe_ts = wipe_result.timestamp.replace(":", "-").replace(".", "-")
        safe_disk = wipe_result.disk_identifier.replace("/", "_")
        report_path = REPORTS_DIR / f"wipe_report_{safe_disk}_{safe_ts}.json"

        with open(report_path, "w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=2)

        logger.info(f"[ReportGenerator] JSON report saved: {report_path}")
        return report_path

    def generate_signed_json_report(
        self,
        wipe_result,
        verification_result: Optional[dict] = None,
        operator: str = "System",
    ) -> Optional[Path]:
        """
        Generate an Ed25519-signed JSON wipe certificate.

        Returns:
            Path to the signed certificate, or None if signing is unavailable.
        """
        report_data = self.build_report_dict(wipe_result, verification_result, operator)

        safe_ts = wipe_result.timestamp.replace(":", "-").replace(".", "-")
        safe_disk = wipe_result.disk_identifier.replace("/", "_")
        cert_path = REPORTS_DIR / f"wipe_cert_{safe_disk}_{safe_ts}.json"

        try:
            from core.report_signer import write_signed_json

            write_signed_json(report_data, cert_path)
            logger.info(f"[ReportGenerator] Signed certificate saved: {cert_path}")
            return cert_path
        except Exception as exc:  # noqa: BLE001 - signing is best-effort
            logger.warning(f"[ReportGenerator] Could not sign certificate: {exc}")
            return None

    def generate_pdf_report(
        self,
        wipe_result,
        verification_result: Optional[dict] = None,
        operator: str = "System",
    ) -> Optional[Path]:
        """
        Generate a PDF certificate of data destruction.

        Requires reportlab to be installed.

        Args:
            wipe_result         : WipeResult dataclass.
            verification_result : Optional dict from WipeVerifier.
            operator            : Operator name.

        Returns:
            Path: Path to generated PDF, or None if reportlab unavailable.
        """
        try:
            from reportlab.lib.pagesizes import A4
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.lib.units import cm
            from reportlab.lib import colors
            from reportlab.platypus import (
                SimpleDocTemplate, Paragraph, Spacer, Table,
                TableStyle, HRFlowable
            )
            from reportlab.lib.enums import TA_CENTER, TA_LEFT
        except ImportError:
            logger.warning(
                "[ReportGenerator] reportlab not installed. PDF generation skipped. "
                "Install with: pip install reportlab"
            )
            return None

        safe_ts = wipe_result.timestamp.replace(":", "-").replace(".", "-")
        safe_disk = wipe_result.disk_identifier.replace("/", "_")
        filename = f"wipe_certificate_{safe_disk}_{safe_ts}.pdf"
        report_path = REPORTS_DIR / filename

        doc = SimpleDocTemplate(
            str(report_path),
            pagesize=A4,
            rightMargin=2 * cm,
            leftMargin=2 * cm,
            topMargin=2 * cm,
            bottomMargin=2 * cm,
        )

        styles = getSampleStyleSheet()
        elements = []

        # ── Header ──
        header_style = ParagraphStyle(
            "Header",
            parent=styles["Title"],
            fontSize=22,
            textColor=colors.HexColor("#1a1a2e"),
            spaceAfter=6,
            alignment=TA_CENTER,
        )
        sub_style = ParagraphStyle(
            "Sub",
            parent=styles["Normal"],
            fontSize=11,
            textColor=colors.HexColor("#555555"),
            alignment=TA_CENTER,
            spaceAfter=4,
        )
        label_style = ParagraphStyle(
            "Label",
            parent=styles["Normal"],
            fontSize=10,
            textColor=colors.HexColor("#1a1a2e"),
            fontName="Helvetica-Bold",
        )
        value_style = ParagraphStyle(
            "Value",
            parent=styles["Normal"],
            fontSize=10,
            textColor=colors.HexColor("#333333"),
        )

        elements.append(Paragraph("WiperX", header_style))
        elements.append(Paragraph("Certificate of Data Destruction", sub_style))
        elements.append(Paragraph(
            f"Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}",
            sub_style
        ))
        elements.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor("#e74c3c")))
        elements.append(Spacer(1, 0.4 * cm))

        # ── Status Banner ──
        status_text = "✓ WIPE SUCCESSFUL" if wipe_result.success else "✗ WIPE FAILED"
        status_color = colors.HexColor("#27ae60") if wipe_result.success else colors.HexColor("#e74c3c")
        status_style = ParagraphStyle(
            "Status",
            parent=styles["Normal"],
            fontSize=16,
            textColor=status_color,
            fontName="Helvetica-Bold",
            alignment=TA_CENTER,
            spaceAfter=12,
        )
        elements.append(Paragraph(status_text, status_style))

        # ── Details Table ──
        verification = verification_result or {}
        verified_str = (
            "✓ VERIFIED" if verification.get("verified") else
            "✗ NOT VERIFIED" if verification.get("verified") is False else
            "N/A"
        )

        table_data = [
            ["Field", "Value"],
            ["Operator", operator],
            ["Wipe Timestamp (UTC)", wipe_result.timestamp],
            ["Target Hostname", wipe_result.hostname],
            ["OS Detected", wipe_result.os_detected],
            ["Disk Identifier", wipe_result.disk_identifier],
            ["Disk Model", wipe_result.disk_model or "Unknown"],
            ["Disk Serial", wipe_result.disk_serial or "Unknown"],
            ["Wipe Strategy", wipe_result.strategy_name],
            ["Post-Wipe Verification", verified_str],
            ["Verification Method", verification.get("method", "none")],
            ["Compliance Reference", "NIST SP 800-88 Rev.1"],
        ]

        table = Table(table_data, colWidths=[6 * cm, 12 * cm])
        table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1a1a2e")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, 0), 11),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#f8f9fa"), colors.white]),
            ("FONTNAME", (0, 1), (0, -1), "Helvetica-Bold"),
            ("FONTSIZE", (0, 1), (-1, -1), 9),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#dddddd")),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ]))

        elements.append(table)
        elements.append(Spacer(1, 0.5 * cm))

        # ── Log Excerpt ──
        elements.append(Paragraph("Operation Log (last 20 lines)", label_style))
        elements.append(Spacer(1, 0.2 * cm))

        log_lines = wipe_result.log_lines[-20:] if wipe_result.log_lines else ["No log available"]
        log_text = "<br/>".join(
            f"<font name='Courier' size='7'>{line}</font>"
            for line in log_lines
        )
        elements.append(Paragraph(log_text, value_style))

        # ── Footer ──
        elements.append(Spacer(1, 0.5 * cm))
        elements.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#cccccc")))
        footer_style = ParagraphStyle(
            "Footer",
            parent=styles["Normal"],
            fontSize=8,
            textColor=colors.HexColor("#888888"),
            alignment=TA_CENTER,
        )
        elements.append(Paragraph(
            "This certificate is generated by WiperX. "
            "For legally binding data destruction certification, "
            "engage a certified data destruction service.",
            footer_style
        ))

        doc.build(elements)
        logger.info(f"[ReportGenerator] PDF certificate saved: {report_path}")
        return report_path
