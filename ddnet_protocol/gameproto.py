"""Game protocol constants — DDNet 0.6 wire ids.

System message ids from engine/shared/protocol.h, game message ids from the
generated game protocol (matches Kinetix 20.2's src/generated/protocol.h).
On the wire a message is one vital chunk starting with
`pack_int((id << 1) | system)`.
"""

from __future__ import annotations

from .packer import Packer, Unpacker

# -- system (engine) messages, sent by client and/or server -------------------
NETMSG_EX = 0
NETMSG_INFO = 1
NETMSG_MAP_CHANGE = 2
NETMSG_MAP_DATA = 3
NETMSG_CON_READY = 4
NETMSG_SNAP = 5
NETMSG_SNAPEMPTY = 6
NETMSG_SNAPSINGLE = 7
NETMSG_SNAPSMALL = 8
NETMSG_INPUTTIMING = 9
NETMSG_RCON_AUTH_STATUS = 10
NETMSG_RCON_LINE = 11
NETMSG_READY = 14
NETMSG_ENTERGAME = 15
NETMSG_INPUT = 16
NETMSG_RCON_CMD = 17
NETMSG_RCON_AUTH = 18
NETMSG_REQUEST_MAP_DATA = 19
NETMSG_PING = 22
NETMSG_PING_REPLY = 23
NETMSG_RCON_CMD_ADD = 25
NETMSG_RCON_CMD_REM = 26

# -- game messages (NETMSGTYPE_*, generated protocol) --------------------------
SV_MOTD = 1
SV_BROADCAST = 2
SV_CHAT = 3
SV_KILLMSG = 4
SV_READYTOENTER = 8
SV_WEAPONPICKUP = 9
SV_EMOTICON = 10
SV_VOTESET = 15
SV_VOTESTATUS = 16
CL_SAY = 17
CL_SETTEAM = 18
CL_SETSPECTATORMODE = 19
CL_STARTINFO = 20
CL_CHANGEINFO = 21
CL_KILL = 22
CL_EMOTICON = 23
CL_VOTE = 24
CL_CALLVOTE = 25
CL_ISDDNETLEGACY = 26

def pack_message(msg_id: int, system: bool, body: bytes = b"") -> bytes:
    """Full chunk payload: id int followed by the packed message body."""
    p = Packer()
    p.add_int((msg_id << 1) | (1 if system else 0))
    p.add_raw(body)
    return p.data()


def unpack_message(chunk_data: bytes) -> tuple[int, bool, Unpacker] | None:
    """Split a chunk payload into (id, system, unpacker) or None on error."""
    u = Unpacker(chunk_data)
    wire = u.get_int()
    if u.error:
        return None
    return wire >> 1, bool(wire & 1), u
