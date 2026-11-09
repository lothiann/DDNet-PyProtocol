"""Packet layer — port of DDNet engine/shared/network.cpp (CNetBase).

Handles the UDP wire format: 3-byte packet header (flags/ack/num_chunks),
optional huffman compression, trailing security token, chunk headers, and
control messages. Only the 0.6 protocol path is implemented (DDNet servers
speak 0.6 to clients).
"""

from __future__ import annotations

import socket
import struct

from .huffman import Huffman

# sizes / limits
NET_MAX_PACKETSIZE = 1400
NET_MAX_CHUNK_SIZE = 1023
NET_MAX_CHUNKHEADERSIZE = 3
NET_PACKETHEADERSIZE = 3
NET_CONNLESS_EXTRA_SIZE = 4
NET_MAX_SEQUENCE = 1 << 10
NET_MAX_PACKET_CHUNKS = 0xFF

# packet flags (0.6 bit layout: ORNCaaAA)
NET_PACKETFLAG_UNUSED = 1 << 0
NET_PACKETFLAG_TOKEN = 1 << 1
NET_PACKETFLAG_CONTROL = 1 << 2
NET_PACKETFLAG_CONNLESS = 1 << 3
NET_PACKETFLAG_RESEND = 1 << 4
NET_PACKETFLAG_COMPRESSION = 1 << 5
NET_PACKETFLAG_EXTENDED = 1 << 6  # not sent directly

# chunk flags
NET_CHUNKFLAG_VITAL = 1
NET_CHUNKFLAG_RESEND = 2

# control messages
NET_CTRLMSG_KEEPALIVE = 0
NET_CTRLMSG_CONNECT = 1
NET_CTRLMSG_CONNECTACCEPT = 2
NET_CTRLMSG_ACCEPT = 3
NET_CTRLMSG_CLOSE = 4

# security tokens (big-endian int32 appended to packets)
SECURITY_TOKEN_MAGIC = b"TKEN"
NET_SECURITY_TOKEN_UNKNOWN = -1
NET_SECURITY_TOKEN_UNSUPPORTED = 0

_NET_HEADER_EXTENDED = b"xe"
_CONNLESS_DATA_OFFSET = len(_NET_HEADER_EXTENDED) + NET_CONNLESS_EXTRA_SIZE


def to_security_token(data: bytes) -> int:
    """ToSecurityToken — big-endian uint32, signed view."""
    return struct.unpack(">i", data[:4])[0]


def write_security_token(token: int) -> bytes:
    """WriteSecurityToken — signed int32 as big-endian bytes."""
    return struct.pack(">i", token)


class ChunkHeader:
    """CNetChunkHeader — 2 bytes, 3 for vital chunks (0.6 Split = 4)."""

    __slots__ = ("flags", "size", "sequence")

    def __init__(self, flags: int = 0, size: int = 0, sequence: int = -1) -> None:
        self.flags = flags
        self.size = size
        self.sequence = sequence

    def pack(self, split: int = 4) -> bytes:
        assert 0 <= self.size < 1 << (split + 6), "invalid chunk size"
        b0 = ((self.flags & 3) << 6) | ((self.size >> split) & 0x3F)
        b1 = self.size & ((1 << split) - 1)
        if self.flags & NET_CHUNKFLAG_VITAL:
            b1 |= (self.sequence >> 2) & (~((1 << split) - 1) & 0xFF)
            b2 = self.sequence & 0xFF
            return bytes((b0, b1, b2))
        return bytes((b0, b1))

    @staticmethod
    def unpack(data: bytes | bytearray | memoryview, offset: int = 0, split: int = 4) -> tuple["ChunkHeader", int]:
        flags = (data[offset] >> 6) & 3
        size = ((data[offset] & 0x3F) << split) | (data[offset + 1] & ((1 << split) - 1))
        sequence = -1
        if flags & NET_CHUNKFLAG_VITAL:
            sequence = ((data[offset + 1] & (~((1 << split) - 1) & 0xFF)) << 2) | data[offset + 2]
            return ChunkHeader(flags, size, sequence), offset + 3
        return ChunkHeader(flags, size), offset + 2


class PacketConstruct:
    """CNetPacketConstruct — a packet being built/parsed.

    `response_token` is filled by unpack_packet for CONNECT control packets
    (the server's token we must use when replying).
    """

    __slots__ = ("flags", "ack", "num_chunks", "data_size", "chunk_data", "extra_data", "response_token")

    def __init__(self) -> None:
        self.flags = 0
        self.ack = 0
        self.num_chunks = 0
        self.data_size = 0
        self.chunk_data = bytearray(NET_MAX_PACKETSIZE)
        self.extra_data = bytearray(NET_CONNLESS_EXTRA_SIZE)
        self.response_token = NET_SECURITY_TOKEN_UNKNOWN

    def reset(self) -> None:
        self.flags = 0
        self.ack = 0
        self.num_chunks = 0
        self.data_size = 0
        self.response_token = NET_SECURITY_TOKEN_UNKNOWN


_huffman = Huffman()


def compress(data: bytes) -> bytes | None:
    return _huffman.compress(data, NET_MAX_PACKETSIZE)


def decompress(data: bytes) -> bytes | None:
    return _huffman.decompress(data, NET_MAX_PACKETSIZE - NET_PACKETHEADERSIZE)


def is_valid_connection_oriented_packet(packet: PacketConstruct) -> bool:
    if packet.flags & ~(NET_PACKETFLAG_CONTROL | NET_PACKETFLAG_RESEND | NET_PACKETFLAG_COMPRESSION):
        return False
    if packet.flags & NET_PACKETFLAG_CONTROL:
        # control packets: one control byte, no chunks, never compressed
        return packet.num_chunks == 0 and packet.data_size > 0 and not (packet.flags & NET_PACKETFLAG_COMPRESSION)
    min_chunks = 0 if packet.flags & NET_PACKETFLAG_RESEND else 1
    return min_chunks <= packet.num_chunks <= NET_MAX_PACKET_CHUNKS


def is_seq_in_backroom(seq: int, ack: int) -> bool:
    """True when seq was already acked (older than ack - NET_MAX_SEQUENCE/2)."""
    bottom = ack - NET_MAX_SEQUENCE // 2
    if bottom < 0:
        return seq <= ack or seq >= bottom + NET_MAX_SEQUENCE
    return ack >= seq >= bottom


def send_packet(sock: socket.socket, addr: tuple[str, int], packet: PacketConstruct, security_token: int) -> None:
    """CNetBase::SendPacket — header, optional huffman, trailing token.

    Does not mutate the packet: the token is appended to a local copy, the
    caller keeps building on the original construct (like the C code, which
    clears its construct after every flush).
    """
    assert is_valid_connection_oriented_packet(packet), "invalid packet to send"
    assert not packet.flags & NET_PACKETFLAG_COMPRESSION, "compression flag is set automatically"

    data = bytes(memoryview(packet.chunk_data)[:packet.data_size])
    if security_token != NET_SECURITY_TOKEN_UNSUPPORTED:
        # UNKNOWN (-1) is appended too, hoping to negotiate the token
        data += write_security_token(security_token)

    compressed: bytes | None = None
    if not packet.flags & NET_PACKETFLAG_CONTROL:
        compressed = _huffman.compress(data, NET_MAX_PACKETSIZE - NET_PACKETHEADERSIZE)

    if compressed is not None and len(compressed) < len(data):
        final = compressed
        flags = packet.flags | NET_PACKETFLAG_COMPRESSION
    else:
        final = data
        flags = packet.flags

    header = bytes((
        ((flags << 2) & 0xFC) | ((packet.ack >> 8) & 0x3),
        packet.ack & 0xFF,
        packet.num_chunks,
    ))
    sock.sendto(header + final, addr)


def unpack_packet_flags(buffer: bytes) -> int | None:
    """UnpackPacketFlags — None when the size is impossible."""
    if len(buffer) < NET_PACKETHEADERSIZE or len(buffer) > NET_MAX_PACKETSIZE:
        return None
    return buffer[0] >> 2


def unpack_packet(buffer: bytes) -> PacketConstruct | None:
    """CNetBase::UnpackPacket (0.6 path only).

    Returns a parsed PacketConstruct or None on malformed input.
    """
    flags = unpack_packet_flags(buffer)
    if flags is None:
        return None

    packet = PacketConstruct()
    packet.flags = flags

    if flags & NET_PACKETFLAG_CONNLESS:
        if len(buffer) < _CONNLESS_DATA_OFFSET:
            return None
        packet.flags = NET_PACKETFLAG_CONNLESS
        if buffer[:2] == _NET_HEADER_EXTENDED:
            packet.flags |= NET_PACKETFLAG_EXTENDED
            packet.extra_data[:] = buffer[2:2 + NET_CONNLESS_EXTRA_SIZE]
        packet.data_size = len(buffer) - _CONNLESS_DATA_OFFSET
        packet.chunk_data[:packet.data_size] = buffer[_CONNLESS_DATA_OFFSET:]
        return packet

    if flags & NET_PACKETFLAG_UNUSED:
        # 0.6.5 token flag, never supported by DDNet
        return None

    packet.ack = ((buffer[0] & 0x3) << 8) | buffer[1]
    packet.num_chunks = buffer[2]
    packet.data_size = len(buffer) - NET_PACKETHEADERSIZE

    if not is_valid_connection_oriented_packet(packet):
        return None

    if flags & NET_PACKETFLAG_COMPRESSION:
        decompressed = _huffman.decompress(
            buffer[NET_PACKETHEADERSIZE:], len(packet.chunk_data)
        )
        if decompressed is None:
            return None
        packet.data_size = len(decompressed)
        packet.chunk_data[:packet.data_size] = decompressed
    else:
        packet.chunk_data[:packet.data_size] = buffer[NET_PACKETHEADERSIZE:]

    if flags & NET_PACKETFLAG_CONTROL and packet.data_size >= 1 + 4:
        if packet.chunk_data[0] == NET_CTRLMSG_CONNECT:
            packet.response_token = to_security_token(packet.chunk_data[1:5])

    return packet


def send_control_msg(
    sock: socket.socket,
    addr: tuple[str, int],
    ack: int,
    control_msg: int,
    extra: bytes | None,
    security_token: int,
) -> None:
    """CNetBase::SendControlMsg."""
    packet = PacketConstruct()
    packet.flags = NET_PACKETFLAG_CONTROL
    packet.ack = ack
    packet.num_chunks = 0
    packet.chunk_data[0] = control_msg
    if extra:
        packet.chunk_data[1:1 + len(extra)] = extra
    packet.data_size = 1 + (len(extra) if extra else 0)
    send_packet(sock, addr, packet, security_token)


def send_packet_connless(
    sock: socket.socket,
    addr: tuple[str, int],
    data: bytes,
    extended: bool = False,
    extra: bytes = b"\x00" * NET_CONNLESS_EXTRA_SIZE,
) -> None:
    """CNetBase::SendPacketConnless (0.6 layout: FFFFFFFF filler or 'xe')."""
    if extended:
        prefix = _NET_HEADER_EXTENDED + extra[:NET_CONNLESS_EXTRA_SIZE]
    else:
        prefix = b"\xff" * _CONNLESS_DATA_OFFSET
    sock.sendto(prefix + data, addr)
