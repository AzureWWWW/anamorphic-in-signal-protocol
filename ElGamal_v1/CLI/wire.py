"""
wire.py — Framed-JSON wire protocol between clients and relay.

Each message on the wire is:
    [4 bytes big-endian length] [JSON bytes]

Message types (all are JSON objects with a "type" field):

  Client -> Relay:
    {"type": "register", "name": "alice", "identity_key": "<hex>"}
      - must be first message from a client; identity_key proves which
        account you are across reconnects
    {"type": "publish_bundle", "signal_bundle": {...}, "anamorphic_aPK": {...}}
      - posts this user's keys to the relay's directory
    {"type": "fetch_bundle", "peer": "bob"}
      - ask for bob's published bundles
    {"type": "send", "to": "bob", "wire": "<hex-encoded Signal ciphertext>"}
      - relay forwards to bob (or queues if bob is offline)

  Relay -> Client:
    {"type": "ok"}
      - generic acknowledgement
    {"type": "bundle", "peer": "bob", "signal_bundle": {...}, "anamorphic_aPK": {...}}
      - response to fetch_bundle
    {"type": "bundle_not_ready", "peer": "bob"}
      - bob hasn't published yet
    {"type": "deliver", "from": "alice", "wire": "<hex-encoded ciphertext>"}
      - an incoming message (real-time or drained from queue)
    {"type": "error", "message": "..."}
      - something went wrong on the relay side
"""

import asyncio
import json
import struct


LENGTH_PREFIX_BYTES = 4  # big-endian uint32


async def send_msg(writer: asyncio.StreamWriter, msg: dict) -> None:
    """Send a JSON message with a 4-byte length prefix."""
    data = json.dumps(msg).encode("utf-8")
    writer.write(struct.pack(">I", len(data)) + data)
    await writer.drain()


async def recv_msg(reader: asyncio.StreamReader) -> dict | None:
    """Receive one length-prefixed JSON message. Returns None on EOF."""
    try:
        prefix = await reader.readexactly(LENGTH_PREFIX_BYTES)
    except asyncio.IncompleteReadError:
        return None
    (length,) = struct.unpack(">I", prefix)
    data = await reader.readexactly(length)
    return json.loads(data.decode("utf-8"))