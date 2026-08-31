# wiperx/core/entropy.py
"""
Sample Entropy
--------------
Judge a post-wipe disk/file sample. Pure: input is bytes, output is a
verdict. Used by the verifier to distinguish a genuinely overwritten
region from one that still holds live (high-entropy or structured) data.

  zeroed         : ~all bytes 0x00        -> wiped OK
  fixed-fill     : ~all bytes one value   -> wiped OK (e.g. 0xFF pass)
  low-entropy    : little variation       -> probably wiped / sparse
  random-or-live : high entropy           -> random pass OR untouched data

After a zero-final wipe pass, a "random-or-live" sample means the wipe did
not reach that region.

NOTE: Claude reference implementation. Codex builds an independent version;
keep whichever passes tests/test_entropy.py cleanly.
"""

from __future__ import annotations

import logging
import math
from collections import Counter
from dataclasses import dataclass

logger = logging.getLogger(__name__)


def shannon(buf: bytes) -> float:
    """
    Shannon entropy of a byte buffer in bits per byte.

    Args:
        buf : Bytes to measure.

    Returns:
        float: 0.0 for empty or single-valued input, up to 8.0 for a
        perfectly uniform byte distribution.
    """
    if not buf:
        return 0.0
    counts = Counter(buf)
    if len(counts) == 1:
        return 0.0
    total = len(buf)
    entropy = 0.0
    for count in counts.values():
        p = count / total
        entropy -= p * math.log2(p)
    return entropy


@dataclass
class SampleVerdict:
    """
    Classification of one sampled region.

    Args:
        verdict       : "zeroed" | "fixed-fill" | "low-entropy" | "random-or-live".
        entropy       : Shannon entropy in bits/byte.
        dominant_byte : Most common byte value, or None for empty input.
        fill_ratio    : Fraction of bytes equal to dominant_byte (1.0 if empty).
    """

    verdict: str
    entropy: float
    dominant_byte: int | None
    fill_ratio: float


def looks_wiped(
    buf: bytes,
    *,
    fixed_fill_ratio: float = 0.99,
    low_entropy_bits: float = 2.0,
) -> SampleVerdict:
    """
    Classify a sampled region as wiped or not.

    Args:
        buf              : Sampled bytes.
        fixed_fill_ratio : Dominant-byte fraction at/above which the sample
                           counts as a single-value fill.
        low_entropy_bits : Entropy below which a non-fill sample counts as
                           low-entropy (sparse / mostly wiped).

    Returns:
        SampleVerdict
    """
    if not buf:
        return SampleVerdict("zeroed", 0.0, None, 1.0)

    counts = Counter(buf)
    dominant_byte, dominant_count = counts.most_common(1)[0]
    fill_ratio = dominant_count / len(buf)
    entropy = shannon(buf)

    if fill_ratio >= fixed_fill_ratio:
        verdict = "zeroed" if dominant_byte == 0x00 else "fixed-fill"
    elif entropy < low_entropy_bits:
        verdict = "low-entropy"
    else:
        verdict = "random-or-live"

    return SampleVerdict(verdict, entropy, dominant_byte, fill_ratio)
