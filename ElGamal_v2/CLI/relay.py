"""
relay.py — Message relay for anamorphic CLI chat.

Protocol phases:
  A. Boot (every client does this on startup):
       register -> publish_bundle
     After this, the client is listed in the directory and visible to others.
  B. Start conversation (each user initiates separately for each peer):
       fetch_bundle -> send/receive messages
     The relay treats send/receive as opaque bytes — never sees plaintext.

Relay roles:
  - Directory: stores Signal pre-key bundles + anamorphic aPKs.
  - Router:    forwards "send" messages to the recipient (or queues).
  - Mailbox:   holds queued messages for offline recipients; flushes on reconnect.

The relay is fully untrusted by the crypto layer. It could drop, reorder, or
fabricate identity info, but it cannot read plaintext.

State is in-memory only. Restart = clear everything.
"""

import argparse
import asyncio
import logging
from collections import defaultdict

from ElGamal_v2.CLI.wire import send_msg, recv_msg


logger = logging.getLogger("relay")


class Relay:
    def __init__(self, max_queue_per_recipient: int = 100):
        # name -> {"signal_bundle": dict, "anamorphic_aPK": dict}
        self.bundles: dict[str, dict] = {}
        # name -> currently-active StreamWriter
        self.connections: dict[str, asyncio.StreamWriter] = {}
        # name -> list of pending {"from": sender, "wire": hex}
        self.queues: dict[str, list[dict]] = defaultdict(list)
        self.max_queue_per_recipient = max_queue_per_recipient

    def _enqueue(self, recipient: str, item: dict) -> None:
        q = self.queues[recipient]
        if len(q) >= self.max_queue_per_recipient:
            dropped = q.pop(0)
            logger.info(f"[{recipient}] queue full, dropped oldest from "
                        f"{dropped['from']!r}")
        q.append(item)

    async def handle_client(self, reader: asyncio.StreamReader,
                             writer: asyncio.StreamWriter):
        peer = writer.get_extra_info("peername")
        name: str | None = None
        try:
            msg = await recv_msg(reader)
            if msg is None or msg.get("type") != "register" or "name" not in msg:
                await send_msg(writer, {"type": "error",
                                        "message": "first message must be register"})
                return
            name = msg["name"]

            # Kick any existing connection under this name.
            if name in self.connections:
                old = self.connections[name]
                logger.info(f"[{name}] replacing existing connection")
                try:
                    await asyncio.wait_for(
                        send_msg(old, {"type": "error",
                                       "message": "replaced by newer connection"}),
                        timeout=0.5,
                    )
                except Exception:
                    pass
                try:
                    old.close()
                except Exception:
                    pass

            self.connections[name] = writer
            logger.info(f"[{name}] connected from {peer}")
            await send_msg(writer, {"type": "ok"})

            # Deliver any queued messages waiting for this user.
            if self.queues.get(name):
                pending = self.queues.pop(name)
                logger.info(f"[{name}] delivering {len(pending)} queued messages")
                for p in pending:
                    await send_msg(writer, {
                        "type": "deliver",
                        "from": p["from"],
                        "wire": p["wire"],
                    })

            while True:
                msg = await recv_msg(reader)
                if msg is None:
                    break
                await self.handle_message(name, msg, writer)

        except Exception as e:
            logger.exception(f"[{name or peer}] error: {e}")
        finally:
            if name and self.connections.get(name) is writer:
                del self.connections[name]
                logger.info(f"[{name}] disconnected")
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    async def handle_message(self, sender: str, msg: dict,
                              writer: asyncio.StreamWriter):
        t = msg.get("type")

        if t == "publish_bundle":
            self.bundles[sender] = {
                "signal_bundle": msg["signal_bundle"],
                "anamorphic_aPK": msg["anamorphic_aPK"],
            }
            logger.info(f"[{sender}] published bundle")
            await send_msg(writer, {"type": "ok"})

        elif t == "fetch_bundle":
            peer = msg["peer"]
            if peer in self.bundles:
                b = self.bundles[peer]
                await send_msg(writer, {
                    "type": "bundle",
                    "peer": peer,
                    "signal_bundle": b["signal_bundle"],
                    "anamorphic_aPK": b["anamorphic_aPK"],
                })
            else:
                await send_msg(writer, {"type": "bundle_not_ready", "peer": peer})

        elif t == "list_peers":
            # Return all registered names except the sender's own.
            peers = sorted(n for n in self.bundles.keys() if n != sender)
            await send_msg(writer, {"type": "peers", "peers": peers})

        elif t == "send":
            to = msg["to"]
            wire = msg["wire"]
            envelope = {"type": "deliver", "from": sender, "wire": wire}

            if to in self.connections:
                try:
                    await send_msg(self.connections[to], envelope)
                    logger.info(f"[{sender} -> {to}] forwarded "
                                f"({len(wire) // 2} bytes)")
                except Exception:
                    self._enqueue(to, {"from": sender, "wire": wire})
                    logger.info(f"[{sender} -> {to}] delivery failed, queued")
            else:
                self._enqueue(to, {"from": sender, "wire": wire})
                logger.info(f"[{sender} -> {to}] queued "
                            f"({len(wire) // 2} bytes, {to} offline)")

            await send_msg(writer, {"type": "ok"})

        else:
            await send_msg(writer, {"type": "error",
                                    "message": f"unknown message type: {t}"})


async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=5555)
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(name)s %(message)s",
                        datefmt="%H:%M:%S")

    relay = Relay()
    server = await asyncio.start_server(relay.handle_client, args.host, args.port)
    sockets = ", ".join(str(s.getsockname()) for s in server.sockets)
    logger.info(f"relay listening on {sockets}")
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass