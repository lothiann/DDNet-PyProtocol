"""Huffman codec — 1:1 port of DDNet engine/shared/huffman.cpp (DDNet 20.2).

The DDNet protocol compresses packet payloads with a fixed-frequency Huffman
tree. The table is part of the wire format: both sides must build the exact
same tree, so this is a faithful port, not a generic huffman implementation.
"""

from __future__ import annotations

HUFFMAN_EOF_SYMBOL = 256
HUFFMAN_MAX_SYMBOLS = HUFFMAN_EOF_SYMBOL + 1  # 257: bytes 0..255 + EOF
HUFFMAN_MAX_NODES = HUFFMAN_MAX_SYMBOLS * 2 - 1
HUFFMAN_LUTBITS = 10
HUFFMAN_LUTSIZE = 1 << HUFFMAN_LUTBITS
HUFFMAN_LUTMASK = HUFFMAN_LUTSIZE - 1

# Fixed frequency table from the reference; the last entry (index 256) is the
# EOF symbol frequency. Byte-exact wire compatibility depends on this table.
FREQ_TABLE: tuple[int, ...] = (
    1 << 30, 4545, 2657, 431, 1950, 919, 444, 482, 2244, 617, 838, 542, 715, 1814, 304, 240, 754, 212, 647, 186,
    283, 131, 146, 166, 543, 164, 167, 136, 179, 859, 363, 113, 157, 154, 204, 108, 137, 180, 202, 176,
    872, 404, 168, 134, 151, 111, 113, 109, 120, 126, 129, 100, 41, 20, 16, 22, 18, 18, 17, 19,
    16, 37, 13, 21, 362, 166, 99, 78, 95, 88, 81, 70, 83, 284, 91, 187, 77, 68, 52, 68,
    59, 66, 61, 638, 71, 157, 50, 46, 69, 43, 11, 24, 13, 19, 10, 12, 12, 20, 14, 9,
    20, 20, 10, 10, 15, 15, 12, 12, 7, 19, 15, 14, 13, 18, 35, 19, 17, 14, 8, 5,
    15, 17, 9, 15, 14, 18, 8, 10, 2173, 134, 157, 68, 188, 60, 170, 60, 194, 62, 175, 71,
    148, 67, 167, 78, 211, 67, 156, 69, 1674, 90, 174, 53, 147, 89, 181, 51, 174, 63, 163, 80,
    167, 94, 128, 122, 223, 153, 218, 77, 200, 110, 190, 73, 174, 69, 145, 66, 277, 143, 141, 60,
    136, 53, 180, 57, 142, 57, 158, 61, 166, 112, 152, 92, 26, 22, 21, 28, 20, 26, 30, 21,
    32, 27, 20, 17, 23, 21, 30, 22, 22, 21, 27, 25, 17, 27, 23, 18, 39, 26, 15, 21,
    12, 18, 18, 27, 20, 18, 15, 19, 11, 17, 33, 12, 18, 15, 19, 18, 16, 26, 17, 18,
    9, 10, 25, 22, 22, 17, 20, 16, 6, 16, 15, 20, 14, 18, 24, 335, 1,
)


class _Node:
    __slots__ = ("bits", "num_bits", "symbol", "leaves")

    def __init__(self) -> None:
        self.bits = 0
        self.num_bits = 0  # != 0 marks a leaf (matches the C code's sentinel)
        self.symbol = 0
        self.leaves = (-1, -1)  # 0xffff means "no child" in the reference


class Huffman:
    """Fixed-tree Huffman codec, wire-compatible with CHuffman."""

    def __init__(self, freq_table: tuple[int, ...] = FREQ_TABLE) -> None:
        self._nodes: list[_Node] = []
        self._decode_lut: list[_Node | None] = [None] * HUFFMAN_LUTSIZE
        self._start = 0
        self._build(freq_table)

    # -- tree construction --------------------------------------------------

    def _build(self, freq_table: tuple[int, ...]) -> None:
        nodes = self._nodes
        for i in range(HUFFMAN_MAX_SYMBOLS):
            node = _Node()
            node.num_bits = 0xFFFFFFFF  # leaf marker
            node.symbol = i
            nodes.append(node)

        # (frequency, node id), kept in a stable descending sort like the C code
        left: list[list[int]] = [[freq_table[i], i] for i in range(HUFFMAN_MAX_SYMBOLS)]
        num_nodes = HUFFMAN_MAX_SYMBOLS

        while len(left) > 1:
            left.sort(key=lambda item: -item[0])  # stable, descending
            low1, low2 = left[-1], left[-2]
            parent = _Node()
            parent.num_bits = 0  # internal node
            parent.leaves = (low1[1], low2[1])
            nodes.append(parent)
            left[-2] = [low1[0] + low2[0], num_nodes]
            del left[-1]
            num_nodes += 1

        self._start = num_nodes - 1
        self._set_bits(self._start, 0, 0)

        # decode LUT: for each 10-bit window, either the leaf it resolves to
        # or the deepest internal node reached (finished bit-by-bit afterwards)
        for i in range(HUFFMAN_LUTSIZE):
            bits = i
            node: _Node | None = nodes[self._start]
            for k in range(HUFFMAN_LUTBITS):
                assert node is not None
                node = nodes[node.leaves[bits & 1]]
                bits >>= 1
                if node.num_bits:
                    self._decode_lut[i] = node
                    break
            else:
                self._decode_lut[i] = node

    def _set_bits(self, node_id: int, bits: int, depth: int) -> None:
        node = self._nodes[node_id]
        if node.leaves[1] != -1:
            self._set_bits(node.leaves[1], bits | (1 << depth), depth + 1)
        if node.leaves[0] != -1:
            self._set_bits(node.leaves[0], bits, depth + 1)
        if node.num_bits:
            node.bits = bits
            node.num_bits = depth

    # -- codec ---------------------------------------------------------------

    def compress(self, data: bytes | bytearray | memoryview, max_output: int = 1 << 20) -> bytes | None:
        """Compress; returns None when the result does not fit max_output."""
        nodes = self._nodes
        out = bytearray()
        bits = 0
        bitcount = 0

        def write() -> bool:
            nonlocal bits, bitcount
            while bitcount >= 8:
                out.append(bits & 0xFF)
                if len(out) > max_output:
                    return False
                bits >>= 8
                bitcount -= 8
            return True

        for byte in data:
            sym = nodes[byte]
            bits |= sym.bits << bitcount
            bitcount += sym.num_bits
            if not write():
                return None

        eof = nodes[HUFFMAN_EOF_SYMBOL]
        bits |= eof.bits << bitcount
        bitcount += eof.num_bits
        if not write():
            return None

        if bitcount:  # 20.2.1: trailing byte only when there are leftover bits
            if len(out) >= max_output:
                return None
            out.append(bits & 0xFF)
        return bytes(out)

    def decompress(self, data: bytes | bytearray | memoryview, max_output: int = 1 << 20) -> bytes | None:
        """Decompress; returns None on malformed input or overrun."""
        nodes = self._nodes
        lut = self._decode_lut
        out = bytearray()
        bits = 0
        bitcount = 0
        src = 0
        src_end = len(data)

        while True:
            node: _Node | None = None
            if bitcount >= HUFFMAN_LUTBITS:
                node = lut[bits & HUFFMAN_LUTMASK]

            while bitcount < 24 and src != src_end:
                bits |= data[src] << bitcount
                src += 1
                bitcount += 8

            if node is None:
                node = lut[bits & HUFFMAN_LUTMASK]
            if node is None:
                return None

            if node.num_bits:
                if bitcount < node.num_bits:
                    return None
                bits >>= node.num_bits
                bitcount -= node.num_bits
            else:
                if bitcount < HUFFMAN_LUTBITS:
                    return None
                bits >>= HUFFMAN_LUTBITS
                bitcount -= HUFFMAN_LUTBITS
                while True:
                    node = nodes[node.leaves[bits & 1]]  # type: ignore[index]
                    bitcount -= 1
                    bits >>= 1
                    if node.num_bits:
                        break
                    if bitcount == 0:
                        return None

            if node.symbol == HUFFMAN_EOF_SYMBOL:
                break

            if len(out) == max_output:
                return None
            out.append(node.symbol)

        return bytes(out)
