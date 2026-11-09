"""Message packer — port of DDNet engine/shared/packer.cpp + compression.cpp.

`pack_int`/`unpack_int` implement CVariableInt (the wire's variable-length
int encoding); `compress_ints`/`decompress_ints` map int arrays to bytes.
`Packer`/`Unpacker` build and parse DDNet messages (ints, NUL-terminated
strings, raw data).
"""

from __future__ import annotations

import struct

PACKER_BUFFER_SIZE = 1024 * 2
MAX_BYTES_PACKED = 5

# sanitize flags (CUnpacker)
SANITIZE = 1
SANITIZE_CC = 2
SKIP_START_WHITESPACES = 4


def pack_int(value: int) -> bytes:
    """CVariableInt::Pack — format ESDDDDDD EDDDDDDD EDD..., sign in bit 6."""
    value = struct.unpack("<i", struct.pack("<I", value & 0xFFFFFFFF))[0]  # int32
    out = bytearray()
    byte = 0
    if value < 0:
        byte |= 0x40
        value = ~value & 0xFFFFFFFF  # C: i = ~i on int; equivalent for our shifts
        # ~i on a negative int in C is bitwise not of the int32 pattern
    byte |= value & 0x3F
    value >>= 6
    while value:
        byte |= 0x80
        out.append(byte)
        byte = value & 0x7F
        value >>= 7
    out.append(byte)
    return bytes(out)


def unpack_int(data: bytes | bytearray | memoryview, offset: int = 0) -> tuple[int, int] | None:
    """CVariableInt::Unpack — returns (value, new_offset) or None on error."""
    if offset >= len(data):
        return None
    sign = (data[offset] >> 6) & 1
    value = data[offset] & 0x3F
    masks = (0x7F, 0x7F, 0x7F, 0x0F)
    shifts = (6, 13, 20, 27)
    index = 0
    while True:
        if not (data[offset] & 0x80):
            break
        if index >= 4:
            # more than 4 extension bytes: the C loop just stops after 4
            break
        offset += 1
        if offset >= len(data):
            return None
        value |= (data[offset] & masks[index]) << shifts[index]
        index += 1
    offset += 1
    if sign:
        value = ~value
    return value, offset


def compress_ints(ints) -> bytes:
    """CVariableInt::Compress — pack an int array into bytes."""
    out = bytearray()
    for value in ints:
        out += pack_int(value)
    return bytes(out)


def decompress_ints(data: bytes | bytearray | memoryview, num_ints: int) -> list[int] | None:
    """CVariableInt::Decompress — unpack exactly num_ints ints or fail."""
    out: list[int] = []
    offset = 0
    size = len(data)
    while offset < size:
        if len(out) >= num_ints:
            return None
        res = unpack_int(data, offset)
        if res is None:
            return None
        value, offset = res
        out.append(value)
    if len(out) != num_ints:
        return None
    return out


def decompress_ints_stream(data: bytes | bytearray | memoryview) -> list[int] | None:
    """CVariableInt::Decompress — unpack until the source is exhausted."""
    out: list[int] = []
    offset = 0
    size = len(data)
    while offset < size:
        res = unpack_int(data, offset)
        if res is None:
            return None
        value, offset = res
        out.append(value)
    return out


def _sanitize_cc(text: str) -> str:
    """str_sanitize_cc — replace control characters with spaces."""
    return "".join(c if ord(c) >= 32 else " " for c in text)


def _sanitize(text: str) -> str:
    """str_sanitize — keep only printable chars plus \\r \\n \\t."""
    return "".join(c if ord(c) >= 32 or c in "\r\n\t" else " " for c in text)


def _skip_whitespaces(text: str) -> str:
    return text.lstrip(" \t\r\n")


class Packer:
    """CPacker — builds a message payload (ints, strings, raw data)."""

    def __init__(self, buffer_size: int = PACKER_BUFFER_SIZE) -> None:
        self._limit = buffer_size
        self._buf = bytearray()
        self.error = False

    def reset(self) -> None:
        self._buf.clear()
        self.error = False

    def add_int(self, value: int) -> None:
        if self.error:
            return
        packed = pack_int(value)
        if len(self._buf) + len(packed) > self._limit:
            self.error = True
            return
        self._buf += packed

    def add_string(self, text: str, limit: int = 0, allow_truncation: bool = True) -> None:
        """Append a NUL-terminated string; limit is a byte budget like in C
        (checked per UTF-8 codepoint so multi-byte chars are never split)."""
        if self.error:
            return
        start = len(self._buf)
        if limit <= 0:
            limit = self._limit
        for ch in text:
            encoded = ch.encode("utf-8", errors="replace")
            length = len(encoded)
            if limit < length:
                if allow_truncation:
                    break
                self.error = True
                del self._buf[start:]
                return
            if len(self._buf) + length + 1 > self._limit:
                self.error = True
                del self._buf[start:]
                return
            self._buf += encoded
            limit -= length
        self._buf.append(0)

    def add_raw(self, data: bytes | bytearray | memoryview) -> None:
        if self.error:
            return
        if len(self._buf) + len(data) > self._limit:
            self.error = True
            return
        self._buf += data

    def data(self) -> bytes:
        return bytes(self._buf)

    def size(self) -> int:
        return len(self._buf)


class Unpacker:
    """CUnpacker — parses a message payload."""

    def __init__(self, data: bytes | bytearray | memoryview) -> None:
        self._data = bytes(data)
        self._offset = 0
        self.error = False

    def get_int(self) -> int:
        if self.error:
            return 0
        res = unpack_int(self._data, self._offset)
        if res is None:
            self.error = True
            return 0
        value, self._offset = res
        return value

    def get_int_or_default(self, default: int) -> int:
        if self.error:
            return 0
        if self._offset == len(self._data):
            return default
        return self.get_int()

    def get_uncompressed_int(self) -> int:
        if self.error:
            return 0
        if self._offset + 4 > len(self._data):
            self.error = True
            return 0
        (value,) = struct.unpack_from("<i", self._data, self._offset)
        self._offset += 4
        return value

    def get_string(self, sanitize_type: int = SANITIZE) -> str:
        if self.error:
            return ""
        start = self._offset
        while True:
            if self._offset >= len(self._data):
                self.error = True
                return ""
            if self._data[self._offset] == 0:
                break
            self._offset += 1
        self._offset += 1
        raw = self._data[start:self._offset - 1]
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            self.error = True
            return ""
        if sanitize_type & SANITIZE:
            text = _sanitize(text)
        elif sanitize_type & SANITIZE_CC:
            text = _sanitize_cc(text)
        if sanitize_type & SKIP_START_WHITESPACES:
            text = _skip_whitespaces(text)
        return text

    def get_raw(self, size: int) -> bytes | None:
        if self.error:
            return None
        if size < 0 or self._offset + size > len(self._data):
            self.error = True
            return None
        raw = self._data[self._offset:self._offset + size]
        self._offset += size
        return raw

    def remaining(self) -> int:
        return len(self._data) - self._offset
