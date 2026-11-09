"""DDNet-PyProtocol — the DDNet (DDraceNetwork) 0.6 network protocol in pure Python.

A dependency-free port of the client-relevant parts of the DDNet C++ engine:
huffman codec, message packer, UDP connection layer, extended (uuid) messages,
snapshot delta decoding and the full client connect flow. Byte-compatible with
DDNet servers (tested against DDNet/Kinetix 20.2).
"""

from .client import Client

__version__ = "0.1.0"
