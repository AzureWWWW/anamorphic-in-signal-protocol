"""
client.py — Anamorphic chat CLI.

Protocol:
  Phase A (boot, automatic on startup):
    connect -> register -> publish_bundle
  Phase B (peer selection, user-driven):
    prompt for peer name, fetch_bundle, establish session
  Phase C (chat):
    cover/hidden prompts, send and receive messages

Usage:
    python client.py <my_name> [--host H] [--port P]

Commands during chat:
    /peers        list other registered users
    /switch NAME  switch to chatting with a different peer
    /quit         exit

A blank line at the cover prompt is a no-op (just prompts again).
"""

import os
os.environ.setdefault("PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION", "python")

import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

import argparse
import asyncio

from ElGamal_v1.anamorphic_layer import AnamorphicSession
from ElGamal_v1.CLI.wire import send_msg, recv_msg
from ElGamal_v1.CLI.bundle_codec import (
    bundle_to_dict, bundle_from_dict, aPK_to_dict, aPK_from_dict,
)


def _flush_stdin() -> None:
    """Discard any unread bytes from stdin (POSIX only; silent no-op elsewhere)."""
    try:
        import termios
        termios.tcflush(sys.stdin.fileno(), termios.TCIFLUSH)
    except Exception:
        pass


class Client:
    def __init__(self, name: str, host: str, port: int):
        self.name = name
        self.host = host
        self.port = port
        self.session = AnamorphicSession(name)
        self.reader: asyncio.StreamReader | None = None
        self.writer: asyncio.StreamWriter | None = None
        self.stop = asyncio.Event()

        # Current chat peer (None until user picks one).
        self.peer: str | None = None

        # FIFO queues of pending responses, keyed by response type. When we
        # issue a request, we append a future to the corresponding list; when
        # a response of that type arrives in recv_loop, we pop the oldest
        # future and set it. This handles multiple in-flight requests cleanly.
        self._awaiting_bundle: list[asyncio.Future] = []
        self._awaiting_peers: list[asyncio.Future] = []

        # Deliveries that arrived before the user picked a peer — held here
        # until the chat loop is ready to display them.
        self._pending_deliveries: list[dict] = []
        self._in_chat = False

    # ---- Wire ----

    async def _send(self, msg: dict) -> None:
        assert self.writer is not None
        await send_msg(self.writer, msg)

    async def _recv(self) -> dict | None:
        assert self.reader is not None
        return await recv_msg(self.reader)

    # ---- Phase A: boot ----

    async def boot(self) -> None:
        """Connect, register, publish our bundle. Must succeed before chat."""
        self.reader, self.writer = await asyncio.open_connection(self.host, self.port)
        await self._send({"type": "register", "name": self.name})
        resp = await self._recv()
        if resp is None or resp.get("type") != "ok":
            raise RuntimeError(f"register failed: {resp}")
        print(f"[connected to relay as {self.name!r}]")

        # Publish bundle
        signal_bundle = self.session.publish_signal_bundle(
            pre_key_id=100 + (hash(self.name) & 0xFFF),
            signed_pre_key_id=5,
        )
        await self._send({
            "type": "publish_bundle",
            "signal_bundle": bundle_to_dict(signal_bundle),
            "anamorphic_aPK": aPK_to_dict(self.session.public_anamorphic()),
        })
        resp = await self._recv()
        if resp is None or resp.get("type") != "ok":
            raise RuntimeError(f"publish_bundle failed: {resp}")
        print(f"[bundle published; you are now visible to others as {self.name!r}]")

    # ---- Phase B: peer selection ----

    async def request_peer_list(self) -> list[str]:
        """Ask the relay for currently-registered users."""
        fut = asyncio.get_event_loop().create_future()
        self._awaiting_peers.append(fut)
        await self._send({"type": "list_peers"})
        return await fut

    async def request_peer_bundle(self, peer_name: str) -> dict | None:
        """Fetch peer's bundle. Returns None if peer isn't published yet."""
        fut = asyncio.get_event_loop().create_future()
        self._awaiting_bundle.append(fut)
        await self._send({"type": "fetch_bundle", "peer": peer_name})
        return await fut

    async def establish_session_with(self, peer_name: str) -> bool:
        """Fetch peer's bundle and build the Signal+anamorphic session.
        Returns True on success."""
        result = await self.request_peer_bundle(peer_name)
        if result is None:
            print(f"[{peer_name!r} has not registered yet]")
            return False
        signal_bundle = bundle_from_dict(result["signal_bundle"])
        aPK = aPK_from_dict(result["anamorphic_aPK"])
        self.session.start_signal_session(peer_name, signal_bundle)
        self.session.provision_peer(peer_name, aPK)
        self.peer = peer_name
        print(f"[session established with {peer_name!r}]")
        return True

    async def pick_peer_interactive(self) -> None:
        """Prompt user for peer name. Retries until a valid session exists."""
        while not self.stop.is_set():
            peers = await self.request_peer_list()
            if peers:
                print(f"[available peers: {', '.join(peers)}]")
            else:
                print(f"[no other peers registered yet]")

            try:
                choice = await asyncio.to_thread(input, "peer> ")
            except EOFError:
                self.stop.set()
                return
            choice = choice.strip()

            if not choice:
                continue
            if choice == "/quit":
                self.stop.set()
                return
            if choice == self.name:
                print(f"[you can't chat with yourself]")
                continue

            if await self.establish_session_with(choice):
                return

    # ---- Phase C: chat loop ----

    async def chat_loop(self) -> None:
        """Read cover+hidden pairs from stdin and send them."""
        self._in_chat = True
        print(f"[now chatting with {self.peer!r}. "
              f"commands: /peers  /switch NAME  /quit]")

        # If any deliveries came in during peer-selection, process them now.
        if self._pending_deliveries:
            pending = self._pending_deliveries
            self._pending_deliveries = []
            print(f"[processing {len(pending)} message(s) received earlier]")
            for m in pending:
                await self._process_delivery(m)

        while not self.stop.is_set() and self.peer is not None:
            try:
                cover = await asyncio.to_thread(input, f"[{self.peer}] cover> ")
            except EOFError:
                self.stop.set()
                return

            if cover == "":
                continue
            if cover.strip() == "/quit":
                self.stop.set()
                return
            if cover.strip() == "/peers":
                peers = await self.request_peer_list()
                print(f"[peers: {', '.join(peers) or '(none)'}]")
                continue
            if cover.startswith("/switch "):
                new_peer = cover[len("/switch "):].strip()
                if new_peer and new_peer != self.name:
                    if await self.establish_session_with(new_peer):
                        print(f"[switched to {new_peer!r}]")
                continue

            try:
                hidden = await asyncio.to_thread(input, f"[{self.peer}] hidden> ")
            except EOFError:
                self.stop.set()
                return

            try:
                wire_bytes = self.session.send_to(self.peer, cover=cover, hidden=hidden)
            except ValueError as e:
                print(f"[encrypt error: {e}]")
                continue

            await self._send({
                "type": "send",
                "to": self.peer,
                "wire": wire_bytes.hex(),
            })
            print(f"[sent {len(wire_bytes)} bytes]")

    # ---- Permanent recv loop ----

    async def recv_loop(self) -> None:
        """Dispatch incoming messages. Runs for the lifetime of the connection."""
        while not self.stop.is_set():
            try:
                msg = await self._recv()
            except Exception:
                msg = None
            if msg is None:
                print("\n[relay closed connection]")
                self.stop.set()
                return

            t = msg.get("type")

            if t == "deliver":
                await self._on_delivery(msg)
            elif t == "bundle":
                if self._awaiting_bundle:
                    fut = self._awaiting_bundle.pop(0)
                    if not fut.done():
                        fut.set_result(msg)
            elif t == "bundle_not_ready":
                if self._awaiting_bundle:
                    fut = self._awaiting_bundle.pop(0)
                    if not fut.done():
                        fut.set_result(None)
            elif t == "peers":
                if self._awaiting_peers:
                    fut = self._awaiting_peers.pop(0)
                    if not fut.done():
                        fut.set_result(msg.get("peers", []))
            elif t == "ok":
                pass
            elif t == "error":
                print(f"\n[relay error: {msg.get('message')}]")
            else:
                print(f"\n[unexpected: {msg}]")

    async def _on_delivery(self, msg: dict) -> None:
        if not self._in_chat:
            # Buffer for later. Just show a hint so the user isn't surprised.
            self._pending_deliveries.append(msg)
            sender = msg.get("from", "?")
            print(f"\n[new message from {sender!r} — "
                  f"pick a peer to read it]")
            return

        await self._process_delivery(msg)

    async def _process_delivery(self, msg: dict) -> None:
        sender = msg["from"]
        wire_bytes = bytes.fromhex(msg["wire"])

        # If we've never chatted with this sender, we need their aPK to
        # double-decrypt.
        if sender not in self.session._peer_aPKs:
            result = await self.request_peer_bundle(sender)
            if result is not None:
                signal_bundle = bundle_from_dict(result["signal_bundle"])
                aPK = aPK_from_dict(result["anamorphic_aPK"])
                try:
                    self.session.start_signal_session(sender, signal_bundle)
                except Exception:
                    pass  # session may already be implicitly built
                self.session.provision_peer(sender, aPK)

        try:
            cover, hidden = self.session.receive_from(sender, wire_bytes)
            print(f"\n[from {sender}]")
            print(f"  cover:  {cover!r}")
            print(f"  hidden: {hidden!r}")
            if self.peer is not None:
                print(f"[{self.peer}] cover> ", end="", flush=True)
        except Exception as e:
            print(f"\n[from {sender}] decrypt failed: {e}")

    # ---- Driver ----

    async def run(self) -> None:
        await self.boot()
        recv_task = asyncio.create_task(self.recv_loop())

        try:
            # Phase B: pick a peer.
            _flush_stdin()
            await self.pick_peer_interactive()
            if self.stop.is_set():
                return

            # Phase C: chat. Interleaves with recv_task.
            await self.chat_loop()

        finally:
            self.stop.set()
            recv_task.cancel()
            try:
                if self.writer is not None:
                    self.writer.close()
                    await self.writer.wait_closed()
            except Exception:
                pass


async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("name", help="your name (e.g. alice)")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=5555)
    args = parser.parse_args()

    client = Client(args.name, args.host, args.port)
    try:
        await client.run()
    except KeyboardInterrupt:
        pass
    print("[bye]")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass