# wiperx/core/recovery/validate.py
"""
Recovered-File Validators
-------------------------
Open each recovered file with a type-specific parser and report whether it
is intact, partially readable, or corrupt. Missing optional libraries
degrade to "unchecked" rather than failing.

NOTE: Claude reference implementation. Codex builds an independent version.
"""

from __future__ import annotations

import logging
import sqlite3
import zipfile
from dataclasses import dataclass

logger = logging.getLogger(__name__)

try:
    from PIL import Image, ImageFile

    _PIL_OK = True
except ImportError:  # pragma: no cover
    _PIL_OK = False

try:
    import pypdf

    _PYPDF_OK = True
except ImportError:  # pragma: no cover
    _PYPDF_OK = False

try:
    import mutagen

    _MUTAGEN_OK = True
except ImportError:  # pragma: no cover
    _MUTAGEN_OK = False

_IMAGE_TYPES = {"jpeg", "png", "gif", "bmp", "tiff"}


@dataclass
class ValidationResult:
    """Outcome of validating one recovered file."""

    state: str        # "intact" | "partial" | "corrupt" | "unchecked"
    validator: str    # "pillow" | "pypdf" | "zipfile" | "sqlite" | "mutagen" | "none"
    detail: str = ""

    @property
    def ok(self) -> bool:
        return self.state in ("intact", "partial")


def _validate_image(path: str) -> ValidationResult:
    if not _PIL_OK:
        return ValidationResult("unchecked", "none", "Pillow not installed")
    try:
        with Image.open(path) as img:
            img.verify()
        return ValidationResult("intact", "pillow", "verify() passed")
    except Exception as exc:  # noqa: BLE001 - Pillow raises many types
        prev = ImageFile.LOAD_TRUNCATED_IMAGES
        ImageFile.LOAD_TRUNCATED_IMAGES = True
        try:
            with Image.open(path) as img:
                img.load()
            return ValidationResult("partial", "pillow", f"loads truncated ({exc})")
        except Exception as exc2:  # noqa: BLE001
            return ValidationResult("corrupt", "pillow", str(exc2))
        finally:
            ImageFile.LOAD_TRUNCATED_IMAGES = prev


def _validate_pdf(path: str) -> ValidationResult:
    if not _PYPDF_OK:
        return ValidationResult("unchecked", "none", "pypdf not installed")
    try:
        reader = pypdf.PdfReader(path, strict=False)
        pages = len(reader.pages)
        if pages > 0:
            return ValidationResult("intact", "pypdf", f"{pages} page(s)")
        return ValidationResult("partial", "pypdf", "0 pages parsed")
    except Exception as exc:  # noqa: BLE001
        return ValidationResult("corrupt", "pypdf", str(exc))


def _validate_zip(path: str) -> ValidationResult:
    try:
        with zipfile.ZipFile(path) as zf:
            bad = zf.testzip()
            names = zf.namelist()
        if bad is None:
            return ValidationResult("intact", "zipfile", f"{len(names)} entries")
        return ValidationResult("partial", "zipfile", f"first bad entry: {bad}")
    except zipfile.BadZipFile as exc:
        return ValidationResult("corrupt", "zipfile", str(exc))
    except Exception as exc:  # noqa: BLE001
        return ValidationResult("corrupt", "zipfile", str(exc))


def _validate_sqlite(path: str) -> ValidationResult:
    try:
        con = sqlite3.connect(path)
        try:
            row = con.execute("PRAGMA integrity_check").fetchone()
        finally:
            con.close()
        if row and row[0] == "ok":
            return ValidationResult("intact", "sqlite", "integrity_check ok")
        return ValidationResult("corrupt", "sqlite", str(row))
    except Exception as exc:  # noqa: BLE001
        return ValidationResult("corrupt", "sqlite", str(exc))


def _validate_media(path: str) -> ValidationResult:
    if not _MUTAGEN_OK:
        return ValidationResult("unchecked", "none", "mutagen not installed")
    try:
        meta = mutagen.File(path)
        if meta is None:
            return ValidationResult("corrupt", "mutagen", "unrecognised container")
        length = getattr(getattr(meta, "info", None), "length", None)
        return ValidationResult("intact", "mutagen", f"length={length}")
    except Exception as exc:  # noqa: BLE001
        return ValidationResult("corrupt", "mutagen", str(exc))


def validate(path: str, sig_name: str, category: str) -> ValidationResult:
    """
    Validate a recovered file.

    Args:
        path     : file to validate.
        sig_name : signature name ("jpeg", "pdf", "zip", ...).
        category : "image" | "document" | "archive" | "video" | "audio" | ...

    Returns:
        ValidationResult
    """
    name = (sig_name or "").lower()
    if name in _IMAGE_TYPES or category == "image":
        return _validate_image(path)
    if name == "pdf":
        return _validate_pdf(path)
    if name == "zip" or (category == "archive" and name not in ("gzip", "7z", "rar")):
        return _validate_zip(path)
    if name == "sqlite":
        return _validate_sqlite(path)
    if category in ("audio", "video"):
        return _validate_media(path)
    return ValidationResult("unchecked", "none", f"no validator for {name or category}")
