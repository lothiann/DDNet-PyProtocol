"""Extended (uuid-addressed) messages — port of engine/shared/protocol_ex.cpp
and uuid_manager.cpp.

EX messages travel as NETMSG_EX (=0) followed by the message's 16-byte uuid
and the payload. Uuids are derived from the wire names by md5 over a fixed
namespace (RFC 4122 version 3).
"""

from __future__ import annotations

import hashlib

from . import proto_gen

TEEWORLDS_NAMESPACE = bytes.fromhex("e05ddaaac4e64cfbb6425d48e80c0029")

UUID_INVALID = -2
UUID_UNKNOWN = -1

# symbol -> wire name, straight from the generated headers
EX_UUIDS: dict[str, str] = dict(proto_gen.EX_UUIDS)
GAME_UUIDS: dict[str, str] = dict(proto_gen.GAME_UUIDS)


def calculate_uuid(name: str) -> bytes:
    """CalculateUuid — md5(namespace + name), RFC 4122 v3 bit twiddling."""
    digest = hashlib.md5(TEEWORLDS_NAMESPACE + name.encode("utf-8")).digest()
    data = bytearray(digest)
    data[6] = (data[6] & 0x0F) | 0x30  # version 3
    data[8] = (data[8] & 0x3F) | 0x80  # variant 1
    return bytes(data)


_SYMBOL_NAMES = {**EX_UUIDS, **GAME_UUIDS}
NAME_TO_SYMBOL = {name: sym for sym, name in _SYMBOL_NAMES.items()}
UUID_TO_SYMBOL = {calculate_uuid(name): sym for sym, name in _SYMBOL_NAMES.items()}
SYMBOL_TO_UUID = {sym: calculate_uuid(name) for sym, name in _SYMBOL_NAMES.items()}

# engine EX message symbols as numeric ids (registration order after 1<<16)
for _i, _sym in enumerate(EX_UUIDS):
    globals()[_sym] = (1 << 16) + _i
OFFSET_TEEHISTORIAN_UUID = (1 << 16) + len(EX_UUIDS)


def lookup_uuid(uuid: bytes) -> str | None:
    """UuidManager::LookupUuid — uuid bytes -> registered symbol."""
    return UUID_TO_SYMBOL.get(uuid)


def pack_ex(symbol: str, body: bytes = b"") -> bytes:
    """Pack an EX message chunk payload: id int + uuid + body."""
    from .packer import Packer

    p = Packer()
    p.add_int(0)  # NETMSG_EX / NETMSGTYPE_EX
    p.add_raw(SYMBOL_TO_UUID[symbol])
    p.add_raw(body)
    return p.data()


def unpack_ex(u):
    """Read the uuid of an EX message; returns (symbol, unpacker) or None."""
    raw = u.get_raw(16)
    if raw is None or u.error:
        return None
    return UUID_TO_SYMBOL.get(raw), u


def send_ex(client, symbol: str, body: bytes = b"", flush: bool = True) -> None:
    """Send an EX message through a HeadlessClient."""
    client._send_msg(0, system=True, body=pack_ex(symbol, body), flush=flush)
