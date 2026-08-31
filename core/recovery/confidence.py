# wiperx/core/recovery/confidence.py
"""
Recovery Confidence Scoring
---------------------------
Turn the evidence gathered about a recovered file into a single 0..1
confidence score plus a band (high / medium / low). The score is meant to
predict "is this byte-for-byte the original file", so the demo can show a
confidence-vs-correctness table.

Inputs, by recovery path:
  carving : end-detection method, footer presence, validator result, size
            sanity, structural refinement.
  fs      : filename present, timestamps present, data blocks readable,
            validator result.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Optional

_METHOD_WEIGHT = {
    "structure": 0.45,
    "bifragment": 0.40,   # validated two-fragment reassembly
    "footer": 0.35,
    "max-size": 0.15,
}
_VALIDATION_DELTA = {"intact": 0.40, "partial": 0.18, "unchecked": 0.05, "corrupt": -0.25}


@dataclass
class ConfidenceScore:
    """A recovery-confidence verdict."""

    score: float
    band: str            # "high" | "medium" | "low"
    factors: Dict[str, float] = field(default_factory=dict)


def _band(score: float) -> str:
    if score >= 0.75:
        return "high"
    if score >= 0.45:
        return "medium"
    return "low"


def _finalise(factors: Dict[str, float]) -> ConfidenceScore:
    score = max(0.0, min(1.0, round(sum(factors.values()), 4)))
    return ConfidenceScore(score=score, band=_band(score), factors=factors)


def score_carve(
    *,
    method: str,
    footer_found: bool,
    validation_state: str,
    size: int,
    sig_min: int,
    sig_max: int,
) -> ConfidenceScore:
    """
    Confidence for a signature-carved file.

    Args:
        method           : "structure" | "footer" | "max-size".
        footer_found     : a footer / structural end was located.
        validation_state : "intact" | "partial" | "corrupt" | "unchecked".
        size             : carved byte length.
        sig_min, sig_max : the signature's size bounds.
    """
    factors = {
        "method": _METHOD_WEIGHT.get(method, 0.15),
        "footer": 0.10 if footer_found else 0.0,
        "validation": _VALIDATION_DELTA.get(validation_state, 0.0),
    }
    if sig_min <= size <= int(sig_max * 0.9):
        factors["size_sane"] = 0.05
    else:
        factors["size_sane"] = -0.10
    return _finalise(factors)


def score_fs(
    *,
    has_name: bool,
    has_timestamps: bool,
    data_readable: bool,
    validation_state: str = "unchecked",
) -> ConfidenceScore:
    """
    Confidence for a filesystem-metadata (undelete) recovery.

    Metadata-based recovery is inherently high-confidence: the inode / MFT
    record still points at the real data blocks.
    """
    factors = {
        "base": 0.60,
        "name": 0.15 if has_name else 0.0,
        "timestamps": 0.10 if has_timestamps else 0.0,
        "data_readable": 0.10 if data_readable else -0.30,
        "validation": _VALIDATION_DELTA.get(validation_state, 0.0) * 0.5,
    }
    return _finalise(factors)


def score_from_record(record: dict, validation_state: Optional[str] = None) -> ConfidenceScore:
    """Convenience: score a pipeline record dict from either path."""
    vstate = validation_state or record.get("validation", {}).get("state", "unchecked")
    if record.get("source_method") == "fs":
        return score_fs(
            has_name=bool(record.get("original_name")),
            has_timestamps=bool(record.get("timestamps")),
            data_readable=record.get("data_readable", True),
            validation_state=vstate,
        )
    return score_carve(
        method=record.get("carve_method", "max-size"),
        footer_found=bool(record.get("footer_found")),
        validation_state=vstate,
        size=int(record.get("size", 0)),
        sig_min=int(record.get("sig_min", 0)),
        sig_max=int(record.get("sig_max", 1 << 40)),
    )
