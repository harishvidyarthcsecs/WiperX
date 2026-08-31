# wiperx/core/recovery/carver_fragment.py
"""
Bifragment Gap Carving (JPEG)
----------------------------
Reassemble a baseline JPEG stored in exactly two fragments separated by a
gap of unrelated blocks - the common case when a filesystem could not
place the file contiguously.

Approach (Garfinkel-style bifragment gap carving):
  1. Parse the JPEG header (SOF0 / DHT / DRI / SOS) and note where the
     entropy-coded scan data begins. The prefix up to there is fragment
     one's known-good part.
  2. Decode the raw (un-spliced) region with a minimal baseline Huffman
     MCU decoder to estimate where the gap starts.
  3. Around that estimate, try block-aligned (cut, restart) pairs. For each
     splice ``region[:cut] + region[restart:]`` run the decoder over the
     entropy-coded segment. A wrong splice desynchronises the Huffman
     bitstream: the decoder hits an undefined code, over-runs a block, or
     fails to land on EOI after exactly ``mcus_x * mcus_y`` MCUs. Only the
     correct splice decodes cleanly.
  4. First splice that decodes cleanly wins.

Only two fragments and baseline (non-progressive, Huffman) JPEGs are
supported - a documented scope limit.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

_PROBE_CAP = 48 * 1024 * 1024
_MAX_CANDIDATES = 20_000
_MAX_MCUS = 4_000_000


@dataclass
class BifragmentResult:
    """Outcome of a bifragment JPEG reassembly attempt."""

    recovered: Optional[bytes]     # reassembled JPEG bytes, or None on failure
    frag1_len: int                 # bytes taken from the header fragment (== cut)
    gap_start: int                 # offset in `region` where fragment 1 ended
    frag2_start: int               # offset in `region` where fragment 2 resumed
    frag2_len: int                 # bytes taken from fragment 2 (up to and incl. EOI)
    validated: bool                # entropy-coded stream Huffman-decoded to EOI
    scan_candidates: int           # number of splices tried


class _DecodeError(Exception):
    """Raised when the Huffman bitstream desynchronises."""


# ---------------------------------------------------------------------------
# Header parsing
# ---------------------------------------------------------------------------

@dataclass
class _Header:
    scan_start: int
    width: int
    height: int
    components: List[Tuple[int, int, int]]        # (comp_id, h_samp, v_samp)
    scan_selectors: List[Tuple[int, int, int]]    # (comp_id, dc_table_id, ac_table_id)
    dc_tables: Dict[int, dict]
    ac_tables: Dict[int, dict]
    restart_interval: int


def _build_huffman(counts: bytes, symbols: bytes) -> dict:
    """Return {(length, code): symbol}."""
    table: dict = {}
    code = 0
    k = 0
    for length in range(1, 17):
        for _ in range(counts[length - 1]):
            table[(length, code)] = symbols[k]
            k += 1
            code += 1
        code <<= 1
    return table


def _parse_header(region: bytes) -> Optional[_Header]:
    if region[:2] != b"\xff\xd8":
        return None
    n = len(region)
    pos = 2
    width = height = 0
    components: List[Tuple[int, int, int]] = []
    dc_tables: Dict[int, dict] = {}
    ac_tables: Dict[int, dict] = {}
    restart_interval = 0

    while pos + 4 <= n:
        if region[pos] != 0xFF:
            pos += 1
            continue
        marker = region[pos + 1]
        if marker == 0xFF:
            pos += 1
            continue
        if marker == 0x00 or 0xD0 <= marker <= 0xD7:
            pos += 2
            continue
        if marker == 0xD9:
            return None
        seg_len = int.from_bytes(region[pos + 2:pos + 4], "big")
        if seg_len < 2 or pos + 2 + seg_len > n:
            return None
        body = region[pos + 4:pos + 2 + seg_len]

        if marker in (0xC0, 0xC1):  # baseline / extended sequential
            height = int.from_bytes(body[1:3], "big")
            width = int.from_bytes(body[3:5], "big")
            ncomp = body[5]
            for c in range(ncomp):
                cid = body[6 + c * 3]
                samp = body[7 + c * 3]
                components.append((cid, samp >> 4, samp & 0x0F))
        elif marker in (0xC2, 0xC3, 0xC5, 0xC6, 0xC7, 0xC9, 0xCA, 0xCB, 0xCD, 0xCE, 0xCF):
            return None  # progressive / arithmetic / lossless - out of scope
        elif marker == 0xC4:  # DHT
            off = 0
            while off + 17 <= len(body):
                tc_th = body[off]
                counts = body[off + 1:off + 17]
                nsym = sum(counts)
                symbols = body[off + 17:off + 17 + nsym]
                tbl = _build_huffman(counts, symbols)
                if tc_th >> 4 == 0:
                    dc_tables[tc_th & 0x0F] = tbl
                else:
                    ac_tables[tc_th & 0x0F] = tbl
                off += 17 + nsym
        elif marker == 0xDD:  # DRI
            restart_interval = int.from_bytes(body[0:2], "big")
        elif marker == 0xDA:  # SOS
            ns = body[0]
            selectors: List[Tuple[int, int, int]] = []
            for s in range(ns):
                cid = body[1 + s * 2]
                td_ta = body[2 + s * 2]
                selectors.append((cid, td_ta >> 4, td_ta & 0x0F))
            scan_start = pos + 2 + seg_len
            if not (components and selectors and dc_tables and ac_tables):
                return None
            return _Header(scan_start, width, height, components, selectors,
                           dc_tables, ac_tables, restart_interval)
        pos += 2 + seg_len
    return None


# ---------------------------------------------------------------------------
# Fast baseline Huffman MCU decoder (counts MCUs; does not reconstruct pixels)
# ---------------------------------------------------------------------------

_ZERO_RUN_LIMIT = 24  # raw 0x00 bytes in a row -> not JPEG entropy (a gap)


class _BitReader:
    """MSB-first bit reader over destuffed JPEG entropy data, int-accumulator."""

    __slots__ = ("data", "pos", "n", "acc", "cnt", "marker_at", "pad", "zrun")

    def __init__(self, data: bytes, start: int):
        self.data = data
        self.pos = start
        self.n = len(data)
        self.acc = 0
        self.cnt = 0
        self.marker_at = -1
        self.pad = 0
        self.zrun = 0

    def _fill(self) -> None:
        data = self.data
        n = self.n
        while self.cnt <= 48 and self.marker_at < 0:
            p = self.pos
            if p >= n:
                self.marker_at = n
                return
            byte = data[p]
            if byte == 0xFF:
                nxt = data[p + 1] if p + 1 < n else 0xD9
                if nxt == 0x00:
                    self.pos = p + 2
                else:
                    self.marker_at = p
                    return
                self.zrun = 0
            else:
                self.pos = p + 1
                if byte == 0x00:
                    self.zrun += 1
                    if self.zrun >= _ZERO_RUN_LIMIT:
                        self.marker_at = p - self.zrun + 1  # start of the zero run
                        return
                else:
                    self.zrun = 0
            self.acc = (self.acc << 8) | byte
            self.cnt += 8

    def peek16(self) -> int:
        if self.cnt < 16:
            self._fill()
        if self.cnt >= 16:
            return (self.acc >> (self.cnt - 16)) & 0xFFFF
        need = 16 - self.cnt
        return ((self.acc << need) | ((1 << need) - 1)) & 0xFFFF

    def consume(self, k: int) -> None:
        if self.cnt >= k:
            self.cnt -= k
            self.acc &= (1 << self.cnt) - 1
        else:
            self.pad += k - self.cnt
            self.acc = 0
            self.cnt = 0

    def take(self, s: int) -> None:
        """Consume s magnitude bits (value unused)."""
        if s == 0:
            return
        if self.cnt < s:
            self._fill()
        if self.cnt >= s:
            self.cnt -= s
            self.acc &= (1 << self.cnt) - 1
        else:
            self.pad += s - self.cnt
            self.acc = 0
            self.cnt = 0

    def marker(self) -> int:
        if self.marker_at < 0:
            self._fill()
        if 0 <= self.marker_at < self.n - 1:
            return self.data[self.marker_at + 1]
        return 0

    def skip_restart(self) -> None:
        m = self.marker()
        if not (0xD0 <= m <= 0xD7):
            raise _DecodeError("expected restart marker")
        self.pos = self.marker_at + 2
        self.acc = 0
        self.cnt = 0
        self.marker_at = -1
        self.zrun = 0


def _decode_huff(reader: _BitReader, table: dict) -> int:
    peek = reader.peek16()
    for length in range(1, 17):
        sym = table.get((length, peek >> (16 - length)))
        if sym is not None:
            reader.consume(length)
            return sym
    raise _DecodeError("undefined Huffman code")


def _decode_block(reader: _BitReader, dc_table: dict, ac_table: dict) -> None:
    s = _decode_huff(reader, dc_table)
    if s:
        reader.take(s)
    k = 1
    while k < 64:
        rs = _decode_huff(reader, ac_table)
        r, s = rs >> 4, rs & 0x0F
        if s == 0:
            if r != 15:
                break  # EOB
            k += 16
            continue
        k += r
        if k >= 64:
            raise _DecodeError("AC index overflow")
        reader.take(s)
        k += 1


def _plan(header: _Header):
    hmax = max(h for _, h, _ in header.components)
    vmax = max(v for _, _, v in header.components)
    if hmax == 0 or vmax == 0:
        return None
    mcus_x = -(-header.width // (8 * hmax))
    mcus_y = -(-header.height // (8 * vmax))
    total = mcus_x * mcus_y
    if not (0 < total <= _MAX_MCUS):
        return None
    samp = {cid: (h, v) for cid, h, v in header.components}
    order = []
    for cid, td, ta in header.scan_selectors:
        dc_t = header.dc_tables.get(td)
        ac_t = header.ac_tables.get(ta)
        if dc_t is None or ac_t is None:
            return None
        h, v = samp[cid]
        order.append((dc_t, ac_t, h * v))
    return total, order


def _run_decoder(data: bytes, header: _Header, plan) -> Tuple[bool, int, int]:
    """
    Returns (clean, mcus_done, stop_offset).
      clean = decoded exactly `total` MCUs and landed on EOI with little padding.
      stop_offset = byte offset where the decoder stopped / failed.
    """
    total, order = plan
    reader = _BitReader(data, header.scan_start)
    ri = header.restart_interval
    try:
        for m in range(total):
            if ri and m and m % ri == 0:
                reader.skip_restart()
            for dc_t, ac_t, nblk in order:
                for _ in range(nblk):
                    _decode_block(reader, dc_t, ac_t)
    except _DecodeError:
        return False, m, reader.marker_at if reader.marker_at >= 0 else reader.pos
    clean = reader.marker() == 0xD9 and reader.pad <= 16
    return clean, total, reader.marker_at if reader.marker_at >= 0 else reader.pos


# ---------------------------------------------------------------------------
# public entrypoint
# ---------------------------------------------------------------------------

def carve_bifragment_jpeg(
    region: bytes,
    *,
    block_size: int = 512,
    max_gap_blocks: int = 1024,
) -> BifragmentResult:
    """
    Recover a baseline JPEG split into two fragments with a gap.

    Args:
        region         : bytes starting at a JPEG SOI (FF D8); may contain
                         trailing unrelated data.
        block_size     : filesystem block size; cut / restart points are
                         aligned to this.
        max_gap_blocks : largest gap (in blocks) to search between fragments.

    Returns:
        BifragmentResult. `recovered` is None when no clean reassembly is
        found; the offsets then describe the best attempt and `validated`
        is False.
    """
    if len(region) > _PROBE_CAP:
        region = region[:_PROBE_CAP]

    header = _parse_header(region)
    if header is None:
        return BifragmentResult(None, 0, 0, 0, 0, False, 0)
    plan = _plan(header)
    if plan is None:
        return BifragmentResult(None, 0, 0, 0, 0, False, 0)

    n = len(region)
    scan_start = header.scan_start

    def _finish(data: bytes, cut: int, restart: int, cands: int) -> BifragmentResult:
        end = data.find(b"\xff\xd9", scan_start)
        end = end + 2 if end != -1 else len(data)
        return BifragmentResult(
            recovered=data[:end], frag1_len=cut, gap_start=cut,
            frag2_start=restart, frag2_len=max(0, end - cut),
            validated=True, scan_candidates=cands,
        )

    # 0. contiguous / already-intact
    clean, _done, _stop = _run_decoder(region, header, plan)
    if clean:
        eoi = region.find(b"\xff\xd9", scan_start) + 2
        return _finish(region, eoi, eoi, 1)

    # 1. estimate where the gap starts, then search block-aligned splices
    _c, _d, approx = _run_decoder(region, header, plan)
    approx = max(approx, scan_start + block_size)

    cut_lo = max(block_size, (approx // block_size - 3) * block_size)
    cut_hi = min(n, approx + 3 * block_size)
    candidates = 0

    cut = (cut_lo // block_size) * block_size
    while cut <= cut_hi and candidates < _MAX_CANDIDATES:
        if cut > scan_start:
            far = min(n, cut + max_gap_blocks * block_size)
            restart = cut + block_size
            while restart < far and candidates < _MAX_CANDIDATES:
                candidates += 1
                spliced = region[:cut] + region[restart:]
                if b"\xff\xd9" in spliced[scan_start:]:
                    clean, _dn, _st = _run_decoder(spliced, header, plan)
                    if clean:
                        return _finish(spliced, cut, restart, candidates)
                restart += block_size
        cut += block_size

    logger.debug("[carver_fragment] no clean reassembly after %d candidates", candidates)
    return BifragmentResult(None, 0, 0, 0, 0, False, candidates)
