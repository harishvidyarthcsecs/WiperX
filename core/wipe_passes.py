# wiperx/core/wipe_passes.py
"""
Wipe Pass Tables
----------------
Overwrite-pattern definitions for the Secure Drive Eraser. Pure data +
lookup: no I/O, no device access. The strategy layer consumes the pass
list and executes one device-wide overwrite per PassSpec.

Methods (case-insensitive):
  clear / auto : 1 random + 1 zero pass            (NIST SP 800-88 Clear)
  zero         : single 0x00 pass
  random       : single random pass
  dod / dod-3  : 0x00, 0xFF, random                (DoD 5220.22-M (E))
  dod-7        : 0x00,0xFF,random,random,0x00,0xFF,random  (DoD 5220.22-M ECE)
  gutmann      : 4 random + 27 patterns + 4 random  (Gutmann, 35 passes)
  nist-purge   : random + verify

NOTE: Claude reference implementation. Codex builds an independent version;
keep whichever passes tests/test_wipe_passes.py cleanly.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class PassSpec:
    """
    One device-wide overwrite pass.

    Args:
        kind : "random" (CSPRNG bytes), "fixed" (repeat `byte`), or "verify"
               (read-back check, no write).
        byte : 0..255 fill value when kind == "fixed"; None otherwise.
    """

    kind: str
    byte: int | None = None

    def __post_init__(self) -> None:
        if self.kind not in ("random", "fixed", "verify"):
            raise ValueError(f"invalid PassSpec.kind: {self.kind!r}")
        if self.kind == "fixed" and not (isinstance(self.byte, int) and 0 <= self.byte <= 255):
            raise ValueError(f"fixed pass needs byte in 0..255, got {self.byte!r}")
        if self.kind != "fixed" and self.byte is not None:
            raise ValueError(f"{self.kind} pass must not set byte")


_R = PassSpec("random")
_V = PassSpec("verify")


def _fixed(value: int) -> PassSpec:
    return PassSpec("fixed", value)


# Gutmann passes 5-31: the 27 fixed / patterned passes. For the 3-byte
# repeating patterns only the first byte is used (documented simplification).
_GUTMANN_PATTERN_BYTES = [
    0x55, 0xAA, 0x92, 0x49, 0x24,
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
    0x92, 0x49, 0x24,
    0x6D, 0xB6, 0xDB,
]

_METHODS: dict[str, list[PassSpec]] = {
    "clear": [_R, _fixed(0x00)],
    "auto": [_R, _fixed(0x00)],
    "zero": [_fixed(0x00)],
    "random": [_R],
    "dod": [_fixed(0x00), _fixed(0xFF), _R],
    "dod-3": [_fixed(0x00), _fixed(0xFF), _R],
    "dod-7": [
        _fixed(0x00), _fixed(0xFF), _R, _R,
        _fixed(0x00), _fixed(0xFF), _R,
    ],
    "gutmann": (
        [_R, _R, _R, _R]
        + [_fixed(b) for b in _GUTMANN_PATTERN_BYTES]
        + [_R, _R, _R, _R]
    ),
    "nist-purge": [_R, _V],
}

_DESCRIPTIONS: dict[str, str] = {
    "clear": "NIST SP 800-88 Clear (1 random + 1 zero pass)",
    "auto": "NIST SP 800-88 Clear (1 random + 1 zero pass)",
    "zero": "Single zero-fill pass",
    "random": "Single random pass",
    "dod": "DoD 5220.22-M (E) (3-pass: 0x00, 0xFF, random)",
    "dod-3": "DoD 5220.22-M (E) (3-pass: 0x00, 0xFF, random)",
    "dod-7": "DoD 5220.22-M (ECE) (7-pass)",
    "gutmann": "Gutmann (35-pass: 4 random, 27 patterns, 4 random)",
    "nist-purge": "NIST SP 800-88 Purge (random pass + read-back verify)",
}


def methods() -> list[str]:
    """Sorted list of known method names."""
    return sorted(_METHODS)


def pass_spec(method: str) -> list[PassSpec]:
    """
    Return the overwrite pass list for a wipe method.

    Args:
        method : Method name (case-insensitive); see module docstring.

    Returns:
        list[PassSpec]: One entry per device-wide pass, in order.

    Raises:
        ValueError : Unknown method.
    """
    key = method.strip().lower()
    try:
        return list(_METHODS[key])
    except KeyError:
        raise ValueError(f"unknown wipe method: {method!r}") from None


def describe(method: str) -> str:
    """One-line human summary of a method. Raises ValueError if unknown."""
    key = method.strip().lower()
    if key not in _DESCRIPTIONS:
        raise ValueError(f"unknown wipe method: {method!r}")
    return _DESCRIPTIONS[key]
