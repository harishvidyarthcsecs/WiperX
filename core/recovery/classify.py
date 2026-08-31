# wiperx/core/recovery/classify.py
"""
Recovered-File Classification
-----------------------------
Assign a content category and a best MIME / extension to each recovered
file. Uses libmagic when available, else falls back to signature sniffing
plus ZIP-container inspection (docx / xlsx / pptx).

NOTE: Claude reference implementation. Codex builds an independent version.
"""

from __future__ import annotations

import logging
import zipfile
from dataclasses import dataclass
from typing import Optional

from core.recovery.signatures import match_at

logger = logging.getLogger(__name__)

try:
    import magic  # python-magic

    _MAGIC_OK = True
except Exception:  # pragma: no cover - libmagic missing or import error
    _MAGIC_OK = False

CATEGORIES = (
    "image", "document", "archive", "video", "audio", "database", "source", "other"
)

_MIME_CATEGORY = {
    "image": "image", "video": "video", "audio": "audio",
    "text": "document", "application/pdf": "document",
    "application/zip": "archive", "application/x-7z-compressed": "archive",
    "application/x-rar": "archive", "application/gzip": "archive",
    "application/x-sqlite3": "database", "application/vnd.sqlite3": "database",
}

_OOXML = {
    "word/": ("document", "docx"),
    "xl/": ("document", "xlsx"),
    "ppt/": ("document", "pptx"),
    "META-INF/": ("document", "odt"),
}


@dataclass
class Classification:
    """Content classification of a recovered file."""

    category: str
    ext: str
    mime: str
    source: str      # "libmagic" | "signature" | "zip-container" | "fallback"


def _category_for_mime(mime: str) -> str:
    top = mime.split("/", 1)[0]
    if mime in _MIME_CATEGORY:
        return _MIME_CATEGORY[mime]
    if top in _MIME_CATEGORY:
        return _MIME_CATEGORY[top]
    return "other"


def _inspect_zip(path: str) -> Optional[Classification]:
    try:
        with zipfile.ZipFile(path) as zf:
            names = zf.namelist()
    except Exception:  # noqa: BLE001
        return None
    for prefix, (cat, ext) in _OOXML.items():
        if any(n.startswith(prefix) for n in names):
            return Classification(cat, ext, f"application/{ext}", "zip-container")
    return Classification("archive", "zip", "application/zip", "zip-container")


def classify(
    path: str, fallback_sig: str = "", fallback_category: str = "other"
) -> Classification:
    """
    Classify a recovered file.

    Args:
        path              : file to classify.
        fallback_sig      : signature name from the carver (e.g. "jpeg").
        fallback_category : category from the carver's Signature.

    Returns:
        Classification
    """
    try:
        with open(path, "rb") as fh:
            head = fh.read(64)
    except OSError:
        head = b""

    if head[:4] == b"PK\x03\x04":
        zc = _inspect_zip(path)
        if zc is not None:
            return zc

    if _MAGIC_OK:
        try:
            mime = magic.from_file(path, mime=True)
            cat = _category_for_mime(mime)
            ext = mime.split("/")[-1].split(".")[-1][:8] or fallback_sig or "bin"
            return Classification(cat, ext, mime, "libmagic")
        except Exception as exc:  # noqa: BLE001
            logger.debug("[classify] libmagic failed on %s: %s", path, exc)

    sig = match_at(head, 0)
    if sig is not None:
        return Classification(sig.category, sig.ext, f"application/{sig.ext}", "signature")

    ext = fallback_sig or "bin"
    return Classification(
        fallback_category or "other", ext, "application/octet-stream", "fallback"
    )
