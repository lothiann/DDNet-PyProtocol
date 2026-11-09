"""Headless DDNet client — the complete 0.6 game-level protocol on top of
the transport layer (connection.py).

Flow: NETMSG_CLIENTVER + NETMSG_INFO -> NETMSG_MAP_CHANGE -> map download
(NETMSG_MAP_DATA / REQUEST_MAP_DATA, crc verified) -> NETMSG_READY ->
NETMSG_CON_READY -> CL_STARTINFO + NETMSG_ENTERGAME -> snapshots (delta
decoded, players extracted). All system, extended (uuid) and game messages
of the 0.6 protocol are handled.
"""

from __future__ import annotations

import os
import struct
import threading
import time
import uuid as _uuid
import zlib
from dataclasses import dataclass, field
from types import SimpleNamespace
from typing import Callable

from . import gameproto as gp
from . import netbase
from . import proto_gen
from . import protocol_ex as ex
from .connection import (
    NETSTATE_ONLINE,
    Chunk,
    NetClient,
    State,
)
from .packer import (
    Packer,
    SANITIZE_CC,
    SKIP_START_WHITESPACES,
    Unpacker,
    decompress_ints_stream,
)
from .snapshot import EMPTY_SNAPSHOT, Snapshot, SnapshotDelta

# client states
CLIENT_OFFLINE = 0
CLIENT_CONNECTING = 1
CLIENT_LOADING = 2
CLIENT_ONLINE = 3

GAME_NETVERSION = "0.6 626fce9a778df4d4"  # game/version.h
DDNET_VERSION_NUMBER = 20021  # 20.2.1
DDNET_VERSION_STR = "DDNet 20.2.1"

# SERVERCAP flags (protocol_ex.h)
SERVERCAP_DDNET = 1 << 0
SERVERCAP_CHATTIMEOUTCODE = 1 << 1
SERVERCAP_ANYPLAYERFLAG = 1 << 2
SERVERCAP_PINGEX = 1 << 3
SERVERCAP_ALLOWDUMMY = 1 << 4
SERVERCAP_SYNCWEAPONINPUT = 1 << 5

# DDNetPlayer flags
DDNETFLAG_SPEC = 1 << 0
DDNETFLAG_PAUSED = 1 << 1

WEAPON_GAME = -3

SNAPSHOT_STORAGE = 256

# numeric game msg id -> struct symbol (for generic unpacking)
_NETMSG_ID_TO_STRUCT: dict[int, str] = {}
for _cls, _id_symbol in proto_gen.MSG_IDS.items():
    if _cls in proto_gen.MESSAGES and _id_symbol in proto_gen.NETMSG_IDS:
        _NETMSG_ID_TO_STRUCT[proto_gen.NETMSG_IDS[_id_symbol]] = _cls


@dataclass
class PlayerState:
    """Merged view of CLIENTINFO/PLAYERINFO/CHARACTER/DDNETPLAYER items."""

    name: str = ""
    clan: str = ""
    skin: str = ""
    country: int = -1
    team: int = 0
    score: int = 0
    latency: int = 0
    local: bool = False
    x: int = 0
    y: int = 0
    health: int = 0
    armor: int = 0
    weapon: int = 0
    frozen: bool = False
    freeze_end: int = 0
    spec: bool = False
    auth_level: int = 0
    character: bool = False  # has a CHARACTER object in the current snapshot
    has_playerinfo: bool = False  # server-snapped a PLAYERINFO for this slot
    use_custom_color: bool = False
    color_body: int = 0  # packed HSL (h<<16 | s<<8 | l), DDNet format
    color_feet: int = 0

    @property
    def in_game(self) -> bool:
        """False for the server's fake " " client (chat relay, no PLAYERINFO)."""
        return self.has_playerinfo


@dataclass
class Client:
    """One independent bot client (a player; no dummy concept exists)."""

    name: str = "nameless tee"
    skin: str = "default"
    log_fn: Callable[[str, str], None] = field(default=lambda msg, level: None)
    on_state: Callable[[int], None] = field(default=lambda state: None)
    on_players: Callable[[dict[int, PlayerState]], None] = field(default=lambda players: None)
    maps_dir: str = ""

    def __post_init__(self) -> None:
        self._net = NetClient(("0.0.0.0", 0))
        self._state = CLIENT_OFFLINE

        self.game = SimpleNamespace(
            map_name="",
            map_crc=0,
            map_size=0,
            motd="",
            broadcast="",
            game_tick=-1,
            players={},
            teams={},
            tunings={},
            vote={},
        )

        self._connection_id = _uuid.uuid4().bytes
        self._server_capabilities = 0
        self._map_details_sha256: bytes | None = None
        self._map_details_url: str | None = None
        self._snap_count = 0
        self._sent_ddnet_legacy = False
        self._last_input_tick = -1

        # snapshot machinery
        self._delta = SnapshotDelta()
        self._snapshots: dict[int, Snapshot] = {}
        self._snap_tick = -1
        self._snap_parts = 0
        self._snap_buf = bytearray()
        self._snap_num_parts = 0
        self._last_decoded_tick = -1

        # map download
        self._map_file: bytearray | None = None
        self._map_chunk = 0

        # ping
        self._ping_ex_id: bytes | None = None
        self._ping_ex_time = 0.0

        self._thread: threading.Thread | None = None
        self._running = False

    # -- lifecycle -----------------------------------------------------------

    def connect(self, addr: tuple[str, int]) -> None:
        self._running = True
        self._net.connect(addr)
        self._set_state(CLIENT_CONNECTING)
        self._thread = threading.Thread(target=self._run, name=f"hc-{self.name}", daemon=True)
        self._thread.start()

    def disconnect(self, reason: str | None = None) -> None:
        self._running = False
        self._net.disconnect(reason)
        self._set_state(CLIENT_OFFLINE)

    def close(self) -> None:
        self.disconnect()
        self._net.close()

    def _set_state(self, state: int) -> None:
        self._state = state
        self.on_state(state)

    # -- sending ---------------------------------------------------------------

    def _send_msg(self, msg_id: int, system: bool, body: bytes = b"", flush: bool = True) -> None:
        self._net.send_chunk(gp.pack_message(msg_id, system, body), vital=True, flush=flush)

    def _send_ex(self, symbol: str, body: bytes = b"", flush: bool = True) -> None:
        self._send_msg(0, system=True, body=ex.pack_ex(symbol, body), flush=flush)

    def _send_struct(self, cls: str, values: list, flush: bool = True) -> None:
        """Pack and send any message from proto_gen.MESSAGES."""
        fields = proto_gen.MESSAGES[cls]
        msg_id = proto_gen.NETMSG_IDS[proto_gen.MSG_IDS[cls]]
        p = Packer()
        for (fname, kind, count), value in zip(fields, values):
            if kind == "i":
                p.add_int(value)
            elif kind == "s":
                p.add_string(value, -1)
            elif kind == "u":
                p.add_raw(value)
            elif kind == "x":
                for v in value:
                    p.add_int(v)
        self._send_msg(msg_id, system=False, body=p.data(), flush=flush)

    # -- lifecycle messages ------------------------------------------------------

    def _send_clientver_and_info(self) -> None:
        # CClient::SendInfo: NETMSG_CLIENTVER (uuid ext) then NETMSG_INFO
        p = Packer()
        p.add_raw(self._connection_id)
        p.add_int(DDNET_VERSION_NUMBER)
        p.add_string(DDNET_VERSION_STR, -1)
        self._send_ex("NETMSG_CLIENTVER", p.data())

        p = Packer()
        p.add_string(GAME_NETVERSION, 128)
        p.add_string("")  # password
        self.log("sending NETMSG_INFO", "debug")
        self._send_msg(gp.NETMSG_INFO, system=True, body=p.data())

    def _send_ready(self) -> None:
        self._send_msg(gp.NETMSG_READY, system=True)

    def _send_entergame(self) -> None:
        self._send_msg(gp.NETMSG_ENTERGAME, system=True)

    def _send_startinfo(self) -> None:
        self._send_struct("CNetMsg_Cl_StartInfo", [self.name, "", -1, self.skin, 0, 0, 0])

    def _request_map_chunk(self, chunk: int) -> None:
        p = Packer()
        p.add_int(chunk)
        self._send_msg(gp.NETMSG_REQUEST_MAP_DATA, system=True, body=p.data())

    def _send_input(self) -> None:
        """CNetObj_PlayerInput-shaped empty input (10 ints); real controls
        arrive with the physics integration."""
        if self._last_input_tick == self.game.game_tick:
            return
        self._last_input_tick = self.game.game_tick
        p = Packer()
        for _ in range(10):
            p.add_int(0)
        self._send_msg(gp.NETMSG_INPUT, system=True, body=p.data(), flush=False)

    # -- public game APIs --------------------------------------------------------

    def send_chat(self, message: str, team: bool = False) -> None:
        if self._state == CLIENT_ONLINE:
            self._send_struct("CNetMsg_Cl_Say", [1 if team else 0, -1, message])

    def send_kill(self) -> None:
        if self._state == CLIENT_ONLINE:
            self._send_struct("CNetMsg_Cl_Kill", [WEAPON_GAME])

    def set_team(self, team: int) -> None:
        if self._state == CLIENT_ONLINE:
            self._send_struct("CNetMsg_Cl_SetTeam", [team])

    def set_spectator(self, spec_mode: int) -> None:
        if self._state == CLIENT_ONLINE:
            self._send_struct("CNetMsg_Cl_SetSpectatorMode", [spec_mode])

    def send_emoticon(self, emoticon: int) -> None:
        if self._state == CLIENT_ONLINE:
            self._send_struct("CNetMsg_Cl_Emoticon", [emoticon])

    def vote(self, yes: bool) -> None:
        if self._state == CLIENT_ONLINE:
            self._send_struct("CNetMsg_Cl_Vote", [1 if yes else -1])

    def call_vote(self, vote_type: str, value: str, reason: str) -> None:
        if self._state == CLIENT_ONLINE:
            self._send_struct("CNetMsg_Cl_CallVote", [vote_type, value, reason])

    def rcon_auth(self, password: str) -> None:
        p = Packer()
        p.add_string("")  # username (unused by the 0.6 server)
        p.add_string(password)
        p.add_int(1)
        self._send_msg(gp.NETMSG_RCON_AUTH, system=True, body=p.data())

    def rcon_cmd(self, command: str) -> None:
        p = Packer()
        p.add_string(command)
        self._send_msg(gp.NETMSG_RCON_CMD, system=True, body=p.data())

    def ping(self) -> None:
        self._send_msg(gp.NETMSG_PING, system=True)

    def ping_ex(self) -> None:
        self._ping_ex_id = os.urandom(16)
        self._ping_ex_time = time.monotonic()
        self._send_ex("NETMSG_PINGEX", self._ping_ex_id)

    # -- main loop ---------------------------------------------------------------

    def _run(self) -> None:
        try:
            self._run_inner()
        except Exception:
            import traceback

            self.log("client thread crashed: " + traceback.format_exc(), "error")

    def _run_inner(self) -> None:
        last_input = 0.0
        while self._running:
            self._net.update()
            while True:
                chunk = self._net.recv_chunk()
                if chunk is None:
                    break
                self._on_chunk(chunk)

            if self._net.connection.state == State.ERROR:
                self.log(f"connection error: {self._net.error_string()}", "error")
                self._set_state(CLIENT_OFFLINE)
                break

            if self._state == CLIENT_CONNECTING and self._net.state() == NETSTATE_ONLINE:
                self._send_clientver_and_info()

            if self._state == CLIENT_ONLINE and time.monotonic() - last_input > 0.05:
                self._send_input()
                last_input = time.monotonic()
            time.sleep(0.005)

    # -- chunk dispatch --------------------------------------------------------------

    def _on_chunk(self, chunk: Chunk) -> None:
        if chunk.flags & netbase.NET_PACKETFLAG_CONNLESS:
            return
        parsed = gp.unpack_message(chunk.data)
        if parsed is None:
            return
        msg_id, system, u = parsed
        if system:
            self._on_system_msg(msg_id, u)
        else:
            self._on_game_msg(msg_id, u)

    # -- system messages ----------------------------------------------------------------

    def _on_system_msg(self, msg_id: int, u: Unpacker) -> None:
        if msg_id == gp.NETMSG_EX:
            self._on_ex_msg(u)
        elif msg_id == gp.NETMSG_MAP_CHANGE:
            self._on_map_change(u)
        elif msg_id == gp.NETMSG_MAP_DATA:
            self._on_map_data(u)
        elif msg_id == gp.NETMSG_CON_READY:
            self.log("connection ready", "ok")
            self._send_startinfo()
            self._send_entergame()
            self._set_state(CLIENT_ONLINE)
        elif msg_id in (gp.NETMSG_SNAP, gp.NETMSG_SNAPSINGLE, gp.NETMSG_SNAPEMPTY):
            self._on_snap(msg_id, u)
        elif msg_id == gp.NETMSG_PING:
            self._send_msg(gp.NETMSG_PING_REPLY, system=True)
        elif msg_id == gp.NETMSG_RCON_LINE:
            self.log(f"rcon: {u.get_string(SANITIZE_CC)}", "info")
        elif msg_id == gp.NETMSG_RCON_AUTH_STATUS:
            authed = u.get_int()
            level = u.get_int_or_default(0)
            self.log(f"rcon auth: authed={authed} level={level}", "info")
        elif msg_id == gp.NETMSG_INPUTTIMING:
            u.get_int()  # estimated offset, informational
        elif msg_id in (gp.NETMSG_RCON_CMD_ADD, gp.NETMSG_RCON_CMD_REM):
            pass  # rcon tab completion
        else:
            self.log(f"unhandled system msg {msg_id}", "debug")

    def _on_ex_msg(self, u: Unpacker) -> None:
        header = ex.unpack_ex(u)
        if header is None:
            return
        symbol, u = header

        if symbol == "NETMSG_PINGEX":
            ident = u.get_raw(16)
            if ident:
                self._send_ex("NETMSG_PONGEX", ident)
        elif symbol == "NETMSG_PONGEX":
            ident = u.get_raw(16)
            if ident and self._ping_ex_id == ident:
                latency = (time.monotonic() - self._ping_ex_time) * 1000
                self.log(f"ping: {latency:.0f}ms", "info")
        elif symbol == "NETMSG_WHATIS":
            queried = u.get_raw(16)
            if queried:
                if queried in ex.UUID_TO_SYMBOL:
                    self._send_ex("NETMSG_ITIS", queried)
                else:
                    self._send_ex("NETMSG_IDONTKNOW", queried)
        elif symbol == "NETMSG_CHECKSUM_REQUEST":
            ident = u.get_raw(16)
            if ident:
                # no executable to hash: report failure like C does on errors
                p = Packer()
                p.add_int(1)
                self._send_ex("NETMSG_CHECKSUM_ERROR", ident + p.data())
                self.log("checksum requested, answered with error", "debug")
        elif symbol == "NETMSG_MAP_DETAILS":
            u.get_string(SANITIZE_CC)  # name (also comes in MAP_CHANGE)
            self._map_details_sha256 = u.get_raw(32)
            self._map_details_url = u.get_string(SANITIZE_CC) or None
            self.log(f"map details: url={self._map_details_url!r}", "debug")
        elif symbol == "NETMSG_CAPABILITIES":
            version = u.get_int()
            flags = u.get_int()
            if version > 0:
                self._server_capabilities = flags
                self.log(f"server capabilities: {flags:#x}", "debug")
        elif symbol == "NETMSG_REDIRECT":
            self.log(f"server redirect: {u.get_string(SANITIZE_CC)!r}", "warn")
        elif symbol == "NETMSG_RECONNECT":
            self.log("server requested reconnect", "warn")
        elif symbol == "NETMSG_MAP_RELOAD":
            self.log("map reload", "info")
            if self._state == CLIENT_ONLINE:
                self._send_ready()
        elif symbol in (
            "NETMSG_RCONTYPE",
            "NETMSG_RCON_CMD_GROUP_START",
            "NETMSG_RCON_CMD_GROUP_END",
            "NETMSG_MAPLIST_ADD",
            "NETMSG_MAPLIST_GROUP_START",
            "NETMSG_MAPLIST_GROUP_END",
            "NETMSG_ITIS",
            "NETMSG_IDONTKNOW",
            "NETMSGTYPE_SV_COMMANDINFOGROUPSTART",
            "NETMSGTYPE_SV_COMMANDINFOGROUPEND",
            "NETMSGTYPE_SV_COMMANDINFO",
            "NETMSGTYPE_SV_COMMANDINFOREMOVE",
            "NETMSGTYPE_SV_VOTEOPTIONGROUPSTART",
            "NETMSGTYPE_SV_VOTEOPTIONGROUPEND",
            "NETMSGTYPE_SV_MAPINFO",
            "NETMSGTYPE_SV_TEAMSSTATE",
            "NETMSGTYPE_SV_RECORD",
            "NETMSGTYPE_SV_DDRACETIME",
            "NETMSGTYPE_SV_SERVERALERT",
        ):
            pass  # informational bulk
        else:
            self.log(f"unhandled ex msg {symbol}", "debug")

    # -- map download -------------------------------------------------------------------

    def _on_map_change(self, u: Unpacker) -> None:
        name = u.get_string(SANITIZE_CC | SKIP_START_WHITESPACES)
        crc = u.get_int() & 0xFFFFFFFF
        size = u.get_int()
        self.game.map_name, self.game.map_crc, self.game.map_size = name, crc, size
        self.log(f"map change: {name!r} crc={crc:08x} size={size}", "ok")

        cached = self._load_cached_map(name)
        if cached is not None:
            if zlib.crc32(cached) & 0xFFFFFFFF == crc:
                self.log("map already cached", "debug")
                self._send_ready()
                return
            self.log("cached map crc mismatch, downloading", "warn")

        # the client drives the download: request chunk 0 first (SendMapRequest)
        self._map_file = bytearray()
        self._map_chunk = 0
        self._set_state(CLIENT_LOADING)
        self._request_map_chunk(0)

    def _load_cached_map(self, name: str) -> bytes | None:
        if not self.maps_dir:
            return None
        path = os.path.join(self.maps_dir, name + ".map")
        if not os.path.isfile(path):
            return None
        with open(path, "rb") as f:
            return f.read()

    def _on_map_data(self, u: Unpacker) -> None:
        if self._map_file is None:
            return
        last = u.get_int()
        crc = u.get_int() & 0xFFFFFFFF
        chunk = u.get_int()
        size = u.get_int()
        data = u.get_raw(size)
        if u.error or size <= 0 or crc != self.game.map_crc or chunk != self._map_chunk:
            return
        self._map_file += data
        if last:
            blob = bytes(self._map_file)
            self._map_file = None
            actual_crc = zlib.crc32(blob) & 0xFFFFFFFF
            if actual_crc != self.game.map_crc:
                self.log(f"map download crc mismatch: got {actual_crc:08x}", "error")
                return
            self.log(f"map downloaded ({len(blob)} bytes)", "ok")
            self._save_map(blob)
            self._send_ready()
        else:
            self._map_chunk += 1
            self._request_map_chunk(self._map_chunk)

    def _save_map(self, blob: bytes) -> None:
        if not self.maps_dir:
            return
        try:
            os.makedirs(self.maps_dir, exist_ok=True)
            with open(os.path.join(self.maps_dir, self.game.map_name + ".map"), "wb") as f:
                f.write(blob)
        except OSError as exc:
            self.log(f"map save failed: {exc}", "warn")

    # -- snapshots -----------------------------------------------------------------------

    def _on_snap(self, msg_id: int, u: Unpacker) -> None:
        game_tick = u.get_int()
        delta_tick = game_tick - u.get_int()

        num_parts, part = 1, 0
        if msg_id == gp.NETMSG_SNAP:
            num_parts = u.get_int()
            part = u.get_int()

        crc = 0
        part_size = 0
        raw: bytes | None = b""
        if msg_id != gp.NETMSG_SNAPEMPTY:
            crc = u.get_int() & 0xFFFFFFFF
            part_size = u.get_int()
            raw = u.get_raw(part_size)
        if u.error or num_parts < 1 or num_parts > 64 or part < 0 or part >= num_parts:
            return

        if msg_id == gp.NETMSG_SNAPEMPTY:
            self.game.game_tick = max(self.game.game_tick, game_tick)
            return
        if game_tick <= self._last_decoded_tick and game_tick != self._snap_tick:
            return  # already decoded (a resent part would fail crc anyway)

        if game_tick != self._snap_tick:
            self._snap_tick = game_tick
            self._snap_parts = 0
            self._snap_buf = bytearray()

        self._snap_buf += raw or b""
        self._snap_parts |= 1 << part

        if self._snap_parts != (1 << num_parts) - 1:
            return  # more parts to come

        self._snap_parts = 0
        self.game.game_tick = game_tick
        self._snap_count += 1

        # the wire delta is variable-int compressed: expand to plain ints first
        delta_ints = decompress_ints_stream(bytes(self._snap_buf))
        if delta_ints is None:
            self.log("snapshot delta decompress failed", "warn")
            return
        delta_blob = struct.pack(f"<{len(delta_ints)}i", *delta_ints)

        if delta_tick >= 0 and delta_tick not in self._snapshots:
            # missing delta base: force an input packet so the server resyncs
            self._snap_tick = -1
            self._last_input_tick = -1
            return
        from_snap = self._snapshots.get(delta_tick, EMPTY_SNAPSHOT) if delta_tick >= 0 else EMPTY_SNAPSHOT
        new_snap = self._delta.unpack(from_snap, delta_blob)
        if new_snap is None:
            self.log("snapshot delta failed", "warn")
            return

        # the wire crc covers the DECODED snapshot (CSnapshot::Crc)
        if crc and new_snap.crc() != crc:
            self.log(f"snapshot crc mismatch: got {new_snap.crc():08x} want {crc:08x}", "warn")
            return

        self._last_decoded_tick = game_tick
        self._snapshots[game_tick] = new_snap
        if len(self._snapshots) > SNAPSHOT_STORAGE:
            del self._snapshots[min(self._snapshots)]
        self._interpret(new_snap)

    def _interpret(self, snap: Snapshot) -> None:
        """Build the player view from the CURRENT snapshot.

        A fresh dict per snapshot: the decoded delta carries every live item
        (unchanged items are carried over by unpack), so players who left are
        dropped instead of lingering as ghosts with stale/empty names.
        """
        players: dict[int, PlayerState] = {}
        self.game.players = players

        # uuid items: an EX item (type 0, id >= 0x4000) carries the uuid,
        # the real item with type >= 0x4000 carries the data
        ext_types: dict[int, str] = {}
        for item_type, item_id, ints in snap.items():
            if item_type == 0 and item_id >= 0x4000 and len(ints) == 4:
                uuid_bytes = struct.pack("<4I", *[v & 0xFFFFFFFF for v in ints])
                symbol = ex.lookup_uuid(uuid_bytes)
                if symbol:
                    ext_types[item_id] = symbol

        for item_type, item_id, ints in snap.items():
            if item_type == 0 and item_id >= 0x4000:
                continue  # type-definition item
            if item_type >= 0x4000:
                symbol = ext_types.get(item_type)
            else:
                symbol = proto_gen.NETOBJ_TYPES.get(item_type)
            if symbol is None:
                continue

            if symbol == "NETOBJTYPE_CLIENTINFO":
                if len(ints) >= 17:
                    player = players.setdefault(item_id, PlayerState())
                    player.name = self._ints_to_str(ints[0:4])
                    player.clan = self._ints_to_str(ints[4:7])
                    player.country = ints[7]
                    player.skin = self._ints_to_str(ints[8:14])
                    player.use_custom_color = bool(ints[14])
                    player.color_body = ints[15]
                    player.color_feet = ints[16]
            elif symbol == "NETOBJTYPE_PLAYERINFO":
                if len(ints) >= 5:
                    player = players.setdefault(item_id, PlayerState())
                    player.has_playerinfo = True
                    player.local = bool(ints[0])
                    player.team = ints[2]
                    player.score = ints[3]
                    player.latency = ints[4]
            elif symbol == "NETOBJTYPE_CHARACTER":
                if len(ints) >= 22:
                    player = players.setdefault(item_id, PlayerState())
                    player.character = True
                    player.x = ints[1]
                    player.y = ints[2]
                    player.health = ints[16]
                    player.armor = ints[17]
                    player.weapon = ints[19]
            elif symbol == "NETOBJTYPE_DDNETCHARACTER":
                if len(ints) >= 2:
                    player = players.setdefault(item_id, PlayerState())
                    player.freeze_end = ints[1]
                    player.frozen = ints[1] > 0
            elif symbol == "NETOBJTYPE_DDNETPLAYER":
                if len(ints) >= 2:
                    player = players.setdefault(item_id, PlayerState())
                    player.spec = bool(ints[0] & 1)
                    player.auth_level = ints[1]

        if not self._sent_ddnet_legacy and any(p.local for p in players.values()):
            self._sent_ddnet_legacy = True
            p = Packer()
            p.add_int(DDNET_VERSION_NUMBER)
            self._send_msg(
                proto_gen.NETMSG_IDS["NETMSGTYPE_CL_ISDDNETLEGACY"], system=False, body=p.data()
            )
        self.on_players(players)

    @staticmethod
    def _ints_to_str(ints: list[int]) -> str:
        """StrToInts/IntsToStr coding: string bytes big-endian within each
        int, every byte shifted by +0x80; NUL terminator and padding are 0x80."""
        raw = b"".join(struct.pack(">I", v & 0xFFFFFFFF) for v in ints)
        out = bytearray()
        for byte in raw:
            if byte <= 0x80:  # NUL terminator (0x80) or trailing garbage
                break
            out.append(byte - 0x80)
        return out.decode("utf-8", errors="replace")

    # -- game messages --------------------------------------------------------------------

    def _on_game_msg(self, msg_id: int, u: Unpacker) -> None:
        if msg_id == 0:
            self._on_ex_msg(u)
            return
        struct_symbol = _NETMSG_ID_TO_STRUCT.get(msg_id)
        if struct_symbol is None:
            self.log(f"unhandled game msg {msg_id}", "debug")
            return

        fields = proto_gen.MESSAGES[struct_symbol]
        values: list = []
        for _fname, kind, count in fields:
            if kind == "i":
                values.append(u.get_int())
            elif kind == "s":
                values.append(u.get_string(SANITIZE_CC))
            elif kind == "u":
                values.append(u.get_raw(16))
            elif kind == "x":
                values.append([u.get_int() for _ in range(count)])
        if u.error:
            return

        symbol = proto_gen.MSG_IDS[struct_symbol]
        if symbol == "NETMSGTYPE_SV_MOTD":
            self.game.motd = values[0]
            self.log(f"motd: {values[0][:64]!r}", "info")
        elif symbol == "NETMSGTYPE_SV_BROADCAST":
            self.game.broadcast = values[0]
        elif symbol == "NETMSGTYPE_SV_CHAT":
            self.log(f"chat[{values[1]}]: {values[2]!r}", "info")
        elif symbol == "NETMSGTYPE_SV_KILLMSG":
            self.log(f"kill: cid{values[0]} -> cid{values[1]} weapon={values[2]}", "debug")
        elif symbol == "NETMSGTYPE_SV_VOTESET":
            self.game.vote = dict(zip([f[0] for f in fields], values))
            self.log(f"voteset: {values[1]} {values[2]!r} ({values[3]!r})", "info")
        elif symbol == "NETMSGTYPE_SV_VOTESTATUS":
            self.log(f"vote: yes={values[0]} no={values[1]} pass={values[2]} total={values[3]}", "debug")
        elif symbol == "NETMSGTYPE_SV_TUNEPARAMS":
            self.game.tunings = values[0] if values and isinstance(values[0], list) else values
        elif symbol == "NETMSGTYPE_SV_TEAMSSTATELEGACY":
            teams = values[0] if values and isinstance(values[0], list) else []
            self.game.teams = {cid: team for cid, team in enumerate(teams)}
        # everything else (sounds, weapon pickups, vote options, race times,
        # ddrace teams...) is consumed; extend here as features need them

    # -- status ------------------------------------------------------------------------------

    @property
    def state(self) -> int:
        return self._state

    @property
    def snap_count(self) -> int:
        return self._snap_count

    def log(self, message: str, level: str = "info") -> None:
        self.log_fn(f"[{self.name}] {message}", level)
