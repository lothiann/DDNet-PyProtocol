# DDNet-PyProtocol

A complete implementation of the DDNet (DDraceNetwork) 0.6 network protocol in
pure Python — a headless client with not a single line of C++. Companion to
[DDNet-PyEngine](../DDNet-PyEngine) (a Python port of the DDNet physics).

Byte-compatible with DDNet servers: validated against the DDNet gtest vectors
(huffman, packer) and live against DDNet/Kinetix 20.2 servers.

## What's inside (`ddnet_protocol/`)

| module | contents |
|---|---|
| `huffman.py` | Huffman codec with the fixed DDNet frequency table (byte-exact, vectors from `src/test/huffman_test.cpp`) |
| `packer.py` | `CVariableInt` packing, `Packer`/`Unpacker` for messages, `StrToInts`-compatible strings (bytes shifted by +0x80) |
| `netbase.py` | UDP wire format: flags/ack header, chunks, security tokens, huffman compression |
| `connection.py` | `NetConnection`/`NetClient`: state machine, token negotiation, resend, keepalive |
| `snapshot.py` | `CSnapshot` + full `CSnapshotDelta::UnpackDelta` (delta decoding, static item sizes) |
| `gameproto.py` | system message ids + message pack/unpack helpers |
| `protocol_ex.py` | uuid-addressed (extended) messages: CLIENTVER, PINGEX/PONGEX, WHATIS/ITIS, CHECKSUM, MAP_DETAILS, CAPABILITIES, ... |
| `proto_gen.py` | generated tables: net object types/sizes, fields of every SV/CL message (generator in `tools/gen_protocol.py`) |
| `client.py` | `Client`: INFO → MAP_CHANGE → map download (CRC-verified) → READY → STARTINFO + ENTERGAME → delta-decoded snapshots with parsed players |

## Usage

```python
from ddnet_protocol import Client

client = Client(name="mybot", skin="default",
                        log_fn=lambda msg, level: print(msg))
client.connect(("127.0.0.1", 8303))
# the client runs the whole connect flow, downloads the map and
# decodes snapshots on its own worker thread
time.sleep(5)
for cid, player in client.game.players.items():
    print(cid, player.name, player.x, player.y, player.health)
client.close()
```

## Protocol notes (learned the hard way, from the C++ sources)

- The snapshot delta on the wire is additionally compressed with `CVariableInt`
  (`CVariableInt::Decompress`); the `CData` header is three ints.
- The CRC in SNAP messages covers the **decoded** snapshot, not the delta.
- `StrToInts` (DDNet 20.x): every string byte is shifted by **+0x80**, the
  first character lives in the **most significant byte** of each int, the NUL
  terminator and padding are `0x80`.
- The client drives the map download: it must request chunk 0 itself
  (`NETMSG_REQUEST_MAP_DATA`), the server then serves ~50 chunks/sec.
- Uuid snapshot items travel as a pair: an EX item (type 0) holding the uuid
  plus the actual item with type `0x4000+N`. Only types 0..20 have static
  sizes; everything else carries a size int in the delta.
- A message begins with `pack_int((id << 1) | system)`.
- `NETMSG_CLIENTVER` is not optional — the server logs the client version.
- If the delta base snapshot is missing, the client must NOT decode against an
  empty snapshot: it sends input to force the server into a full resync.

## Tests

```
pytest tests/
```

Covers the DDNet gtest vectors (huffman, packer), wire roundtrips, a loopback
connection handshake and snapshot decoding.

## Reference

Protocol reference: [ddnet/ddnet](https://github.com/ddnet/ddnet) @ `176fc2f9a`
(20.2.1). License follows DDNet's (zlib — see `LICENSE`).
