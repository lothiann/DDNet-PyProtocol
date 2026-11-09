"""Connection layer — port of DDNet network_conn.cpp + network_client.cpp.

Implements the client side of the connection-oriented UDP protocol:
state machine (OFFLINE -> CONNECT -> ONLINE), security token negotiation,
reliable (vital) chunks with resend, keepalives, and chunk extraction from
incoming packets. 0.6 protocol only.
"""

from __future__ import annotations

import enum
import socket
import time
from collections import deque
from dataclasses import dataclass

from . import netbase
from .netbase import (
    NET_CHUNKFLAG_RESEND,
    NET_CHUNKFLAG_VITAL,
    NET_CTRLMSG_ACCEPT,
    NET_CTRLMSG_CLOSE,
    NET_CTRLMSG_CONNECT,
    NET_CTRLMSG_CONNECTACCEPT,
    NET_CTRLMSG_KEEPALIVE,
    NET_MAX_SEQUENCE,
    NET_PACKETFLAG_CONTROL,
    NET_PACKETFLAG_CONNLESS,
    NET_PACKETFLAG_RESEND,
    NET_SECURITY_TOKEN_UNKNOWN,
    NET_SECURITY_TOKEN_UNSUPPORTED,
    PacketConstruct,
    ChunkHeader,
    is_seq_in_backroom,
    send_control_msg,
    send_packet,
    to_security_token,
    unpack_packet,
)

# tunables mirroring the default g_Config values of the reference
CONN_TIMEOUT = 10.0  # s without traffic before the connection errors out
CONN_RESEND_REQUESTS_PER_SECOND = 10.0
KEEPALIVE_INTERVAL = 1.0
FLUSH_INTERVAL = 0.5
CONNECT_INTERVAL = 0.5
RESEND_INTERVAL = 1.0
CONN_BUFFER_SIZE = 1024 * 32  # resend buffer bytes


class State(enum.Enum):
    OFFLINE = enum.auto()
    CONNECT = enum.auto()
    PENDING = enum.auto()
    ONLINE = enum.auto()
    ERROR = enum.auto()


# CNetClient::State() mapping
NETSTATE_OFFLINE = 0
NETSTATE_CONNECTING = 1
NETSTATE_ONLINE = 2


@dataclass
class ChunkResend:
    flags: int
    data: bytes
    sequence: int
    first_send_time: float
    last_send_time: float


@dataclass
class Chunk:
    """A chunk extracted from an incoming packet."""

    flags: int
    data: bytes
    sequence: int  # vital chunks only, -1 otherwise


def _now() -> float:
    return time.monotonic()


class NetConnection:
    """CNetConnection — one connection to the server (client side)."""

    def __init__(self, sock: socket.socket) -> None:
        self._sock = sock
        self.block_close_msg = False
        self.timeout_protected = False
        self.timeout_situation = False
        self._resend_buf: deque[ChunkResend] = deque()
        self._construct = PacketConstruct()
        self.reset()

    # -- lifecycle -----------------------------------------------------------

    def reset(self) -> None:
        self.sequence = 0
        self.ack = 0
        self.peer_ack = 0
        self.remote_closed = False
        self.timeout_protected = False
        self.timeout_situation = False
        self.state = State.OFFLINE
        self.security_token = NET_SECURITY_TOKEN_UNKNOWN
        self.last_send_time = 0.0
        self.last_recv_time = 0.0
        self.last_resend_time = 0.0
        self.last_update_time = 0.0
        self.resend_requested = False
        self.unknown_seq = False
        self.connect_addrs: list[tuple[str, int]] = []
        self.peer_addr: tuple[str, int] | None = None
        self._resend_buf.clear()
        self._construct.reset()
        self.error_string = ""

    def connect(self, addr: tuple[str, int]) -> None:
        """CNetConnection::Connect — start connecting (0.6, token negotiation)."""
        if self.state != State.OFFLINE:
            return
        self.reset()
        self.connect_addrs = [addr]
        self.peer_addr = None
        self.state = State.CONNECT
        self.send_connect()

    def disconnect(self, reason: str | None = None) -> None:
        if self.state == State.OFFLINE:
            return
        if not self.remote_closed and not self.timeout_situation:
            extra = None
            if reason:
                extra = reason.encode("utf-8") + b"\x00"
                send_control_msg(self._sock, self.peer_addr, self.ack, NET_CTRLMSG_CLOSE, extra, self.security_token)
            else:
                send_control_msg(self._sock, self.peer_addr, self.ack, NET_CTRLMSG_CLOSE, None, self.security_token)
        if reason:
            self.error_string = reason
        self.reset()

    # -- sending ---------------------------------------------------------------

    def send_connect(self) -> None:
        self.last_send_time = _now()
        for addr in self.connect_addrs:
            send_control_msg(
                self._sock, addr, self.ack, NET_CTRLMSG_CONNECT,
                netbase.SECURITY_TOKEN_MAGIC, self.security_token,
            )

    def send_control(self, control_msg: int, extra: bytes | None = None) -> None:
        self.last_send_time = _now()
        assert self.peer_addr is not None
        send_control_msg(self._sock, self.peer_addr, self.ack, control_msg, extra, self.security_token)

    def queue_chunk_ex(self, flags: int, data: bytes, sequence: int) -> int:
        """CNetConnection::QueueChunkEx — 0 on success, -1 when rejected."""
        if self.state in (State.OFFLINE, State.ERROR):
            return -1

        construct = self._construct
        if (
            construct.data_size + len(data) + netbase.NET_MAX_CHUNKHEADERSIZE
            > len(construct.chunk_data) - 4  # room for the security token
            or construct.num_chunks == netbase.NET_MAX_PACKET_CHUNKS
        ):
            self.flush()

        header = ChunkHeader(flags, len(data), sequence).pack()
        offset = construct.data_size
        construct.chunk_data[offset:offset + len(header) + len(data)] = header + data
        construct.num_chunks += 1
        construct.data_size = offset + len(header) + len(data)

        if flags & NET_CHUNKFLAG_VITAL and not flags & NET_CHUNKFLAG_RESEND:
            now = _now()
            budget = sum(len(r.data) + 16 for r in self._resend_buf)
            if budget + len(data) > CONN_BUFFER_SIZE:
                return -1  # out of resend buffer, hope nobody asks for it
            self._resend_buf.append(ChunkResend(flags, bytes(data), sequence, now, now))
        return 0

    def queue_chunk(self, flags: int, data: bytes) -> int:
        if flags & NET_CHUNKFLAG_VITAL:
            self.sequence = (self.sequence + 1) % NET_MAX_SEQUENCE
        return self.queue_chunk_ex(flags, data, self.sequence)

    def flush(self) -> int:
        """CNetConnection::Flush — send pending chunks; returns chunk count."""
        construct = self._construct
        num_chunks = construct.num_chunks
        if not num_chunks and not construct.flags & NET_PACKETFLAG_RESEND:
            return 0
        assert self.peer_addr is not None
        construct.ack = self.ack
        send_packet(self._sock, self.peer_addr, construct, self.security_token)
        self.last_send_time = _now()
        construct.reset()
        return num_chunks

    def _resend_chunk(self, resend: ChunkResend) -> None:
        self.queue_chunk_ex(resend.flags | netbase.NET_CHUNKFLAG_RESEND, resend.data, resend.sequence)
        resend.last_send_time = _now()

    def _resend(self) -> None:
        for resend in list(self._resend_buf):
            self._resend_chunk(resend)

    def signal_resend(self) -> None:
        self._construct.flags |= NET_PACKETFLAG_RESEND

    def _answer_resend_request(self, now: float) -> None:
        if not self.resend_requested:
            return
        if now - self.last_resend_time < 1.0 / CONN_RESEND_REQUESTS_PER_SECOND:
            return
        self.resend_requested = False
        self.last_resend_time = now
        self._resend()

    def _ack_chunks(self, ack: int) -> None:
        while self._resend_buf and is_seq_in_backroom(self._resend_buf[0].sequence, ack):
            self._resend_buf.popleft()

    # -- receiving ---------------------------------------------------------------

    def _is_peer_address(self, addr: tuple[str, int]) -> bool:
        if self.state != State.CONNECT:
            return self.peer_addr == addr
        return addr in self.connect_addrs

    def feed(
        self,
        packet: PacketConstruct,
        addr: tuple[str, int],
        security_token: int = NET_SECURITY_TOKEN_UNSUPPORTED,
        response_token: int = NET_SECURITY_TOKEN_UNKNOWN,
    ) -> int:
        """CNetConnection::Feed — returns 1 if the packet was accepted."""
        assert self.state != State.OFFLINE, "can't feed packets to offline connection"
        if not self._is_peer_address(addr):
            return 0

        if self.security_token not in (NET_SECURITY_TOKEN_UNKNOWN, NET_SECURITY_TOKEN_UNSUPPORTED):
            # supposed to have a valid token in this packet, check it
            if packet.data_size < 4:
                return 0
            packet.data_size -= 4
            got = to_security_token(packet.chunk_data[packet.data_size:packet.data_size + 4])
            if self.security_token != got:
                return 0

        # check if the ack value is valid (own sequence..latest peer ack)
        if self.sequence >= self.peer_ack:
            if self.peer_ack <= packet.ack <= self.sequence:
                pass
            else:
                return 0
        else:
            if packet.ack < self.peer_ack and packet.ack > self.sequence:
                return 0
        self.peer_ack = packet.ack

        now = _now()

        if packet.flags & NET_PACKETFLAG_RESEND:
            self.resend_requested = True
        self._answer_resend_request(now)

        if packet.flags & NET_PACKETFLAG_CONTROL:
            ctrl_msg = packet.chunk_data[0]
            if ctrl_msg == NET_CTRLMSG_CLOSE:
                self.state = State.ERROR
                self.remote_closed = True
                reason = ""
                if packet.data_size > 1:
                    raw = bytes(packet.chunk_data[1:packet.data_size]).split(b"\x00", 1)[0]
                    reason = raw.decode("utf-8", errors="replace")
                    reason = "".join(c if ord(c) >= 32 else " " for c in reason)
                if not self.block_close_msg:
                    self.error_string = reason
                return 0
            if self.state == State.CONNECT and ctrl_msg == NET_CTRLMSG_CONNECTACCEPT:
                self.peer_addr = addr
                if (
                    self.security_token == NET_SECURITY_TOKEN_UNKNOWN
                    and packet.data_size >= 1 + len(netbase.SECURITY_TOKEN_MAGIC) + 4
                    and bytes(packet.chunk_data[1:1 + len(netbase.SECURITY_TOKEN_MAGIC)]) == netbase.SECURITY_TOKEN_MAGIC
                ):
                    self.security_token = to_security_token(packet.chunk_data[5:9])
                else:
                    self.security_token = NET_SECURITY_TOKEN_UNSUPPORTED
                self.send_control(NET_CTRLMSG_ACCEPT)
                self.last_recv_time = now
                self.state = State.ONLINE
        else:
            if self.state == State.PENDING:
                self.last_recv_time = now
                self.state = State.ONLINE

        if self.state == State.ONLINE:
            self.last_recv_time = now
            self._ack_chunks(packet.ack)

        return 1

    def update(self) -> None:
        """CNetConnection::Update — resends, timeouts, keepalives."""
        now = _now()

        if self.state in (State.OFFLINE, State.ERROR):
            return

        self.timeout_situation = False
        self._answer_resend_request(now)

        if self.state != State.CONNECT and now - self.last_recv_time > CONN_TIMEOUT:
            self.state = State.ERROR
            self.error_string = "Timeout"
            self.timeout_situation = True

        if self._resend_buf:
            first = self._resend_buf[0]
            if now - first.first_send_time > CONN_TIMEOUT:
                self.state = State.ERROR
                self.error_string = f"Too weak connection (not acked for {CONN_TIMEOUT:.0f} seconds)"
                self.timeout_situation = True
            elif now - first.last_send_time > RESEND_INTERVAL:
                self._resend_chunk(first)

        if self.state == State.ONLINE:
            if now - self.last_send_time > FLUSH_INTERVAL:
                self.flush()
            if now - self.last_send_time > KEEPALIVE_INTERVAL:
                self.send_control(NET_CTRLMSG_KEEPALIVE)
        elif self.state == State.CONNECT:
            if now - self.last_send_time > CONNECT_INTERVAL:
                self.send_connect()
        elif self.state == State.PENDING:
            if now - self.last_send_time > CONNECT_INTERVAL:
                self.send_control(NET_CTRLMSG_CONNECTACCEPT, netbase.SECURITY_TOKEN_MAGIC)

    # -- chunk extraction (CPacketChunkUnpacker) ---------------------------------

    def unpack_next_chunk(self, packet: PacketConstruct, state: list[int]) -> Chunk | None:
        """Iterate chunks of one already-fed packet.

        `state` is a two-element list [offset, chunk_index] owned by the
        caller and advanced across calls (mirrors CPacketChunkUnpacker).
        """
        offset, chunk_index = state
        end = packet.data_size
        try:
            while True:
                if chunk_index >= packet.num_chunks or offset + 2 > end:
                    return None
                header, offset = ChunkHeader.unpack(packet.chunk_data, offset)
                chunk_index += 1
                if offset + header.size > end:
                    return None
                data = bytes(packet.chunk_data[offset:offset + header.size])
                offset += header.size

                if header.flags & NET_CHUNKFLAG_VITAL:
                    if header.sequence == (self.ack + 1) % NET_MAX_SEQUENCE or self.unknown_seq:
                        self.unknown_seq = False
                        self.ack = header.sequence
                    elif is_seq_in_backroom(header.sequence, self.ack):
                        continue  # old chunk we already had
                    else:
                        self.signal_resend()
                        continue  # out of sequence, request resend
                return Chunk(header.flags, data, header.sequence)
        finally:
            state[0], state[1] = offset, chunk_index


class NetClient:
    """CNetClient — UDP socket + connection, chunk-level send/recv."""

    def __init__(self, bind_addr: tuple[str, int] = ("0.0.0.0", 0)) -> None:
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(bind_addr)
        self.sock.setblocking(False)
        self.connection = NetConnection(self.sock)
        self._pending: PacketConstruct | None = None
        self._chunk_state = [0, 0]  # offset, chunk index of the pending packet

    def close(self) -> None:
        self.sock.close()

    def connect(self, addr: tuple[str, int]) -> None:
        self.connection.connect(addr)

    def disconnect(self, reason: str | None = None) -> None:
        self.connection.disconnect(reason)
        self._pending = None
        self._chunk_state = [0, 0]

    def state(self) -> int:
        if self.connection.state == State.ONLINE:
            return NETSTATE_ONLINE
        if self.connection.state == State.OFFLINE:
            return NETSTATE_OFFLINE
        return NETSTATE_CONNECTING

    def error_string(self) -> str:
        return self.connection.error_string

    def update(self) -> None:
        self.connection.update()
        if self.connection.state == State.ERROR:
            self.disconnect(self.connection.error_string)

    def flush(self) -> int:
        return self.connection.flush()

    def send_chunk(self, data: bytes, vital: bool = True, flush: bool = False) -> None:
        flags = NET_CHUNKFLAG_VITAL if vital else 0
        self.connection.queue_chunk(flags, data)
        if flush:
            self.connection.flush()

    def recv_chunk(self) -> Chunk | None:
        """CNetClient::Recv — next game chunk or None (drains the socket).

        Chunks of one packet are returned across successive calls until the
        packet is exhausted (mirrors CPacketChunkUnpacker).
        """
        while True:
            if self._pending is not None:
                chunk = self.connection.unpack_next_chunk(self._pending, self._chunk_state)
                if chunk is not None:
                    if self.connection.state != State.OFFLINE:
                        return chunk
                    self._pending = None
                else:
                    self._pending = None
                    self._chunk_state = [0, 0]

            try:
                data, addr = self.sock.recvfrom(netbase.NET_MAX_PACKETSIZE)
            except BlockingIOError:
                return None

            packet = unpack_packet(data)
            if packet is None:
                continue

            if packet.flags & NET_PACKETFLAG_CONNLESS:
                # surfaced as a chunk with sequence -1; connless handling
                # (master server comm) lives in higher layers
                return Chunk(netbase.NET_PACKETFLAG_CONNLESS, bytes(memoryview(packet.chunk_data)[:packet.data_size]), -1)

            was_control = bool(packet.flags & NET_PACKETFLAG_CONTROL)
            if self.connection.state not in (State.OFFLINE, State.ERROR):
                if self.connection.feed(packet, addr, NET_SECURITY_TOKEN_UNSUPPORTED, packet.response_token):
                    if not was_control and packet.data_size > 0 and packet.num_chunks > 0:
                        self._pending = packet
                        self._chunk_state = [0, 0]
