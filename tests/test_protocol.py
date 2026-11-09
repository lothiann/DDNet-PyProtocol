"""Protocol tests — mirror the vectors from DDNet's own gtest suites
(src/test/huffman_test.cpp, packer_test.cpp, compression_test.cpp)
plus wire-level roundtrips and a loopback connection handshake."""

import random
import socket
import threading
import time

import pytest

from ddnet_protocol import netbase
from ddnet_protocol.connection import (
    NETSTATE_OFFLINE,
    NETSTATE_ONLINE,
    NetClient,
    State,
)
from ddnet_protocol.packer import SANITIZE_CC
from ddnet_protocol.huffman import Huffman
from ddnet_protocol.packer import (
    Packer,
    Unpacker,
    compress_ints,
    decompress_ints,
    pack_int,
    unpack_int,
)


# -- huffman (vectors from huffman_test.cpp) ----------------------------------

@pytest.fixture(scope="module")
def huffman() -> Huffman:
    return Huffman()


def test_huffman_empty(huffman: Huffman):
    compressed = huffman.compress(b"")
    assert compressed == bytes([0x8A, 0x1B])
    assert huffman.decompress(compressed) == b""


def test_huffman_does_not_change_data(huffman: Huffman):
    for input_mod in range(0x10000):
        data = bytes([input_mod & 0xFF, (input_mod >> 8) & 0xFF]) + bytes(62)
        compressed = huffman.compress(data)
        assert compressed is not None
        max_size = 12 if input_mod <= 0xFF else 14
        assert 10 <= len(compressed) <= max_size
        assert huffman.decompress(compressed) == data


def test_huffman_compression_compatible(huffman: Huffman):
    data = bytes(range(8)) + bytes(56)
    compressed = huffman.compress(data)
    expected = bytes.fromhex("515878761BB7FFFFFFFFFFFF7FC50D")
    assert compressed == expected
    assert huffman.decompress(compressed) == data


def test_huffman_no_trailing_null(huffman: Huffman):
    data = bytes([0x15]) + bytes(63)
    compressed = huffman.compress(data)
    expected = bytes.fromhex("BEFDFFFF FFFFFFFF FF1537".replace(" ", ""))
    assert compressed == expected
    assert huffman.decompress(compressed) == data


def test_huffman_truncated(huffman: Huffman):
    data = bytes(range(8)) + bytes(56)
    for cap in range(1, 15):
        assert huffman.compress(data, max_output=cap) is None, cap
    for cap in range(15, 21):
        result = huffman.compress(data, max_output=cap)
        assert result is not None and len(result) == 15, cap


def test_huffman_decompress_garbage(huffman: Huffman):
    for garbage in (b"\x1a", b"\x62\x91\x62\xa9", b"\x4c\x04\xfe\x00\x68"):
        assert huffman.decompress(garbage) is None


def test_huffman_roundtrip_random(huffman: Huffman):
    rng = random.Random(1234)
    for _ in range(200):
        data = bytes(rng.randrange(256) for _ in range(rng.randrange(0, 512)))
        compressed = huffman.compress(data)
        assert compressed is not None
        assert huffman.decompress(compressed) == data


# -- packer / variable int (vectors from packer_test.cpp) ----------------------

def test_pack_int_single_byte():
    assert pack_int(1) == b"\x01"
    assert pack_int(2) == b"\x02"
    assert pack_int(-1) == b"\x40"
    assert pack_int(-2) == b"\x41"
    for i in range(63):
        assert pack_int(i) == bytes([i])


def test_pack_int_extended():
    assert pack_int(64) == b"\x80\x01"
    assert pack_int(65) == b"\x81\x01"
    assert pack_int(66) == b"\x82\x01"
    assert pack_int(-65) == b"\xc0\x01"
    assert pack_int(-66) == b"\xc1\x01"
    assert pack_int(-67) == b"\xc2\x01"
    assert pack_int(-68) == b"\xc3\x01"


@pytest.mark.parametrize("value", [0, 1, -1, 63, 64, -64, -65, 8191, 8192, -8192,
                                   65535, -65536, 2**31 - 1, -2**31])
def test_variable_int_roundtrip(value: int):
    packed = pack_int(value)
    assert len(packed) <= 5
    res = unpack_int(packed)
    assert res is not None
    got, offset = res
    assert got == value
    assert offset == len(packed)


def test_int_array_roundtrip():
    ints = [0, 1, -1, 123456, -123456, 2**31 - 1, -2**31, 42]
    blob = compress_ints(ints)
    assert decompress_ints(blob, len(ints)) == ints
    assert decompress_ints(blob, len(ints) + 1) is None


def test_packer_strings():
    p = Packer()
    p.add_string("hello")
    assert p.data() == b"hello\x00"
    u = Unpacker(p.data())
    assert u.get_string() == "hello"
    assert not u.error


def test_packer_string_limit_truncation():
    p = Packer()
    p.add_string("hello world", limit=5)
    assert p.data() == b"hello\x00"
    assert not p.error


def test_packer_string_multibyte_not_split():
    p = Packer()
    p.add_string("aбв", limit=3)  # "a" + 2-byte "б" fits, "в" does not
    assert p.data() == "aб".encode("utf-8") + b"\x00"
    assert Unpacker(p.data()).get_string() == "aб"


def test_packer_string_no_truncation_error():
    p = Packer()
    p.add_string("hello world", limit=5, allow_truncation=False)
    assert p.error


def test_packer_int_string_mixed():
    p = Packer()
    p.add_int(123456)
    p.add_string("клиент")
    p.add_raw(b"\xde\xad\xbe\xef")
    u = Unpacker(p.data())
    assert u.get_int() == 123456
    assert u.get_string() == "клиент"
    assert u.get_raw(4) == b"\xde\xad\xbe\xef"
    assert not u.error


def test_unpacker_overflow():
    u = Unpacker(b"\x01")
    assert u.get_int() == 1
    assert u.get_int() == 0
    assert u.error


def test_unpacker_bad_utf8():
    u = Unpacker(b"\xff\xff\x00")
    assert u.get_string() == ""
    assert u.error


def test_unpacker_sanitize():
    u = Unpacker(b"bo\x01t\x00")
    assert u.get_string(SANITIZE_CC) == "bo t"


# -- netbase -------------------------------------------------------------------

def test_chunk_header_roundtrip():
    for flags, seq in ((0, -1), (1, 0), (1, 1), (1, 1023), (1, 513)):
        header = netbase.ChunkHeader(flags, 123, seq)
        blob = header.pack()
        parsed, offset = netbase.ChunkHeader.unpack(blob)
        assert offset == len(blob)
        assert parsed.flags == flags
        assert parsed.size == 123
        assert parsed.sequence == (seq if flags & 1 else -1)


def test_security_token():
    blob = netbase.write_security_token(-1)
    assert blob == b"\xff\xff\xff\xff"
    assert netbase.to_security_token(blob) == -1
    assert netbase.to_security_token(netbase.write_security_token(123456)) == 123456


def test_is_seq_in_backroom():
    assert netbase.is_seq_in_backroom(5, 10)
    assert not netbase.is_seq_in_backroom(11, 10)
    # wrap-around at 1024
    assert netbase.is_seq_in_backroom(1023, 3)
    assert netbase.is_seq_in_backroom(100, 101)
    assert not netbase.is_seq_in_backroom(102, 101)


def test_packet_roundtrip_udp():
    """send_packet -> wire -> unpack_packet -> chunks, with token + huffman."""
    rx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    rx.bind(("127.0.0.1", 0))
    rx.settimeout(2.0)
    addr = rx.getsockname()

    packet = netbase.PacketConstruct()
    msg = bytes([5, 1, 42]) + b"\x00"  # would be NETMSG_INFO + version
    header = netbase.ChunkHeader(netbase.NET_CHUNKFLAG_VITAL, len(msg), 1).pack()
    packet.chunk_data[:len(header) + len(msg)] = header + msg
    packet.num_chunks = 1
    packet.data_size = len(header) + len(msg)
    netbase.send_packet(rx, addr, packet, 0x01020304)

    wire = rx.recv(4096)
    rx.close()
    parsed = netbase.unpack_packet(wire)
    assert parsed is not None
    # 4-byte payloads typically do not shrink; both paths must parse
    header2, offset = netbase.ChunkHeader.unpack(parsed.chunk_data)
    header2, offset = netbase.ChunkHeader.unpack(parsed.chunk_data)
    assert header2.flags == netbase.NET_CHUNKFLAG_VITAL
    assert header2.sequence == 1
    payload = bytes(parsed.chunk_data[offset:offset + header2.size])
    assert payload == msg
    # the token rides inside the (possibly compressed) chunk data like in C;
    # assert it directly only when the packet went out uncompressed
    if not parsed.flags & netbase.NET_PACKETFLAG_COMPRESSION:
        assert netbase.to_security_token(wire[-4:]) == 0x01020304


# -- connection handshake over loopback ----------------------------------------

class FakeServer:
    """Minimal 0.6 server side, enough to accept a NetClient."""

    def __init__(self) -> None:
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.settimeout(2.0)
        self.addr: tuple[str, int] | None = None
        self.token = netbase.NET_SECURITY_TOKEN_UNSUPPORTED
        self.ack = 0

    def port(self) -> int:
        return self.sock.getsockname()[1]

    def pump(self) -> None:
        try:
            wire, self.addr = self.sock.recvfrom(4096)
        except OSError:
            return
        packet = netbase.unpack_packet(wire)
        assert packet is not None
        if packet.flags & netbase.NET_PACKETFLAG_CONTROL:
            if packet.chunk_data[0] == netbase.NET_CTRLMSG_CONNECT:
                self.token = packet.response_token
                # CONNECTACCEPT: magic + token so the client upgrades
                extra = netbase.SECURITY_TOKEN_MAGIC + netbase.write_security_token(0x0BADF00D)
                netbase.send_control_msg(self.sock, self.addr, self.ack,
                                         netbase.NET_CTRLMSG_CONNECTACCEPT, extra,
                                         netbase.NET_SECURITY_TOKEN_UNSUPPORTED)
            elif packet.chunk_data[0] == netbase.NET_CTRLMSG_ACCEPT:
                self.ack = packet.ack
                # real servers pick up the client's token from the packet tail
                if packet.data_size >= 4:
                    self.token = netbase.to_security_token(
                        packet.chunk_data[packet.data_size - 4:packet.data_size]
                    )
        else:
            # any packet carries the peer's ack for our vital chunks
            self.ack = packet.ack

    def send_chunk(self, data: bytes, seq: int) -> None:
        packet = netbase.PacketConstruct()
        header = netbase.ChunkHeader(netbase.NET_CHUNKFLAG_VITAL, len(data), seq).pack()
        packet.chunk_data[:len(header) + len(data)] = header + data
        packet.num_chunks = 1
        packet.data_size = len(header) + len(data)
        assert self.addr is not None
        netbase.send_packet(self.sock, self.addr, packet, self.token)


def test_connection_handshake_and_chunks():
    server = FakeServer()
    stop = threading.Event()

    def serve() -> None:
        while not stop.is_set():
            server.pump()
            time.sleep(0.005)

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()

    client = NetClient(("127.0.0.1", 0))
    client.connect(("127.0.0.1", server.port()))

    deadline = time.monotonic() + 2.0
    while client.state() != NETSTATE_ONLINE and time.monotonic() < deadline:
        client.update()
        client.recv_chunk()
        time.sleep(0.005)
    assert client.state() == NETSTATE_ONLINE
    assert client.connection.security_token == 0x0BADF00D

    # server -> client vital chunk
    server.send_chunk(b"\x07\x01hello\x00", seq=1)
    deadline = time.monotonic() + 2.0
    chunk = None
    while time.monotonic() < deadline:
        chunk = client.recv_chunk()
        if chunk is not None:
            break
        time.sleep(0.005)
    assert chunk is not None
    assert chunk.flags & netbase.NET_CHUNKFLAG_VITAL
    assert chunk.data == b"\x07\x01hello\x00"
    assert client.connection.ack == 1

    # client -> server vital chunk lands and bumps the server's ack
    client.send_chunk(b"\x01\x02\x03")
    deadline = time.monotonic() + 2.0
    while server.ack != 1 and time.monotonic() < deadline:
        client.update()
        client.recv_chunk()
        time.sleep(0.005)
    assert server.ack == 1

    stop.set()
    thread.join(timeout=1)
    client.disconnect()
    client.close()
    server.sock.close()


def test_connection_close_reason():
    server = FakeServer()
    client = NetClient(("127.0.0.1", 0))
    client.connect(("127.0.0.1", server.port()))
    # force the client into ONLINE without the server's help
    client.connection.state = State.ONLINE
    client.connection.peer_addr = ("127.0.0.1", server.port())
    client.connection.security_token = netbase.NET_SECURITY_TOKEN_UNSUPPORTED

    netbase.send_control_msg(
        server.sock, client.sock.getsockname(), 0,
        netbase.NET_CTRLMSG_CLOSE, b"nope\x00",
        netbase.NET_SECURITY_TOKEN_UNSUPPORTED,
    )
    deadline = time.monotonic() + 2.0
    while time.monotonic() < deadline:
        client.recv_chunk()
        if client.connection.state == State.ERROR:
            break
        time.sleep(0.005)
    assert client.connection.state == State.ERROR
    assert client.connection.error_string == "nope"
    client.close()
    server.sock.close()
