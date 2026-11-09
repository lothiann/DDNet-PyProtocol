"""Snapshots — port of engine/shared/snapshot.cpp (CSnapshot,
CSnapshotDelta::UnpackDelta, CSnapshotBuilder).

A snapshot is a list of items `(internal_type, id, data_ints)`; the wire
carries delta-compressed updates against a previously stored snapshot.
All values are handled as int32 (signed), matching the C semantics.
"""

from __future__ import annotations

import struct

from . import proto_gen

OFFSET_UUID_TYPE = 0x4000
MAX_TYPE = 0x7FFF
MAX_ID = 0xFFFF
MAX_ITEMS = 1024
MAX_PARTS = 64
MAX_SIZE = MAX_PARTS * 1024

NETOBJTYPE_EX = 0


def _i32(value: int) -> int:
    """Normalize an unsigned 32-bit result to the signed int32 range."""
    value &= 0xFFFFFFFF
    return value - 0x100000000 if value >= 0x80000000 else value


class Snapshot:
    """CSnapshot — parsed item container."""

    __slots__ = ("data_size", "num_items", "_items")

    def __init__(self, items: list[tuple[int, int, list[int]]]) -> None:
        """Build from items; mirrors CSnapshotBuilder::Finish layout."""
        self._items = [
            (item_type, item_id, [_i32(v) for v in item_ints])
            for item_type, item_id, item_ints in items
        ]
        self.num_items = len(self._items)

    # -- parsing -----------------------------------------------------------

    @staticmethod
    def from_bytes(blob: bytes) -> "Snapshot | None":
        """CSnapshot::IsValid + item extraction; None when invalid."""
        if len(blob) < 8:
            return None
        data_size, num_items = struct.unpack_from("<ii", blob, 0)
        if (
            num_items < 0
            or num_items > MAX_ITEMS
            or data_size < 0
            or data_size % 4 != 0
            or len(blob) != 8 + 4 * num_items + data_size
        ):
            return None
        offsets = list(struct.unpack_from(f"<{num_items}i", blob, 8)) if num_items else []
        data = blob[8 + 4 * num_items:]
        for offset in offsets:
            if offset < 0 or offset > data_size or offset % 4 != 0:
                return None

        items: list[tuple[int, int, list[int]]] = []
        for index, offset in enumerate(offsets):
            end = data_size if index == num_items - 1 else offsets[index + 1]
            size = end - offset - 4  # minus the type_and_id header
            if size < 0 or size % 4 != 0:
                return None
            type_and_id = struct.unpack_from("<i", data, offset)[0]
            ints = list(struct.unpack_from(f"<{size // 4}i", data, offset + 4))
            items.append((type_and_id >> 16, type_and_id & 0xFFFF, ints))
        snap = Snapshot.__new__(Snapshot)
        snap._items = items
        snap.num_items = num_items
        snap.data_size = data_size
        return snap

    def to_bytes(self) -> bytes:
        """Serialize back into the CSnapshot wire/memory layout."""
        offsets: list[int] = []
        data = bytearray()
        for item_type, item_id, item_ints in self._items:
            offsets.append(len(data))
            data += struct.pack("<i", _i32((item_type << 16) | item_id))
            for value in item_ints:
                data += struct.pack("<i", _i32(value))
        out = struct.pack("<ii", len(data), self.num_items)
        if offsets:
            out += struct.pack(f"<{len(offsets)}i", *offsets)
        return out + bytes(data)

    # -- access ------------------------------------------------------------

    def items(self) -> list[tuple[int, int, list[int]]]:
        """(internal_type, id, data_ints) in wire order."""
        return self._items

    def find_item(self, key: int) -> list[int] | None:
        """GetItemIndex by full key (type << 16 | id)."""
        for item_type, item_id, item_ints in self._items:
            if (item_type << 16) | item_id == key:
                return item_ints
        return None

    def crc(self) -> int:
        """CSnapshot::Crc — plain 32-bit sum of all item data ints."""
        crc = 0
        for _t, _i, item_ints in self._items:
            for value in item_ints:
                crc = (crc + (value & 0xFFFFFFFF)) & 0xFFFFFFFF
        return crc


EMPTY_SNAPSHOT = Snapshot([])


class SnapshotDelta:
    """CSnapshotDelta — applies wire deltas onto a previous snapshot."""

    def __init__(self) -> None:
        # static item sizes in bytes per internal type (0.6 objects only);
        # mirrors SnapSetStaticsize(GetObjSize(i)) for i < NUM_NETOBJTYPES
        self.static_sizes: dict[int, int] = {}
        for type_id, symbol in proto_gen.NETOBJ_TYPES.items():
            if symbol in proto_gen.OBJ_SIZES:
                self.static_sizes[type_id] = proto_gen.OBJ_SIZES[symbol]

    def unpack(self, from_snapshot: Snapshot, delta: bytes) -> Snapshot | None:
        """CSnapshotDelta::UnpackDelta; returns the new snapshot or None."""
        if len(delta) < 12 or len(delta) % 4 != 0:
            return None
        # CData header: num_deleted, num_update_items, num_temp_items (unused)
        num_deleted, num_update_items = struct.unpack_from("<ii", delta, 0)
        if num_deleted < 0 or num_update_items < 0:
            return None
        ints = list(struct.unpack_from(f"<{(len(delta) - 12) // 4}i", delta, 12))
        pos = 0
        end = len(ints)

        if num_deleted > end - pos:
            return None
        deleted = {value & 0xFFFFFFFF for value in ints[pos:pos + num_deleted]}
        pos += num_deleted

        items: list[tuple[int, int, list[int]]] = []
        index_by_key: dict[int, int] = {}

        def new_item(item_type: int, item_id: int, item_ints: list[int]) -> bool:
            if len(items) >= MAX_ITEMS:
                return False
            items.append((item_type, item_id, list(item_ints)))
            index_by_key[(item_type << 16) | item_id] = len(items) - 1
            return True

        # copy all non-deleted items from the previous snapshot
        for from_type, from_id, from_ints in from_snapshot.items():
            if ((from_type << 16) | from_id) & 0xFFFFFFFF in deleted:
                continue
            if not new_item(from_type, from_id, from_ints):
                return None

        # unpack updated / new items
        for _ in range(num_update_items):
            if pos + 2 > end:
                return None
            item_type = ints[pos]
            item_id = ints[pos + 1]
            pos += 2
            if item_type < 0 or item_type > MAX_TYPE:
                return None
            if item_id < 0 or item_id > MAX_ID:
                return None

            if item_type in self.static_sizes:
                size = self.static_sizes[item_type]
            else:
                if pos + 1 > end:
                    return None
                size_field = ints[pos]
                if size_field < 0:
                    return None
                size = size_field * 4
                pos += 1

            if size < 0 or size % 4 != 0 or (end - pos) * 4 < size:
                return None
            count = size // 4
            diff_ints = ints[pos:pos + count]
            pos += count

            key = (item_type << 16) | item_id
            existing_index = index_by_key.get(key)
            if existing_index is not None:
                current = items[existing_index][2]
                if len(current) != count:
                    return None
                items[existing_index] = (
                    item_type,
                    item_id,
                    [_i32(past + diff) for past, diff in zip(current, diff_ints)],
                )
            else:
                if not new_item(item_type, item_id, diff_ints):
                    return None

        return Snapshot(items)
