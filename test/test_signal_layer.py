"""
test_phase1.py — Multi-message exchange demonstrating Signal's ratchet.

Uses the signal_layer module. Shows:
  - X3DH session setup via pre-key bundle
  - Multiple messages in one direction (sender chain advances)
  - Direction switch (DH ratchet step — root key changes)
  - Out-of-order delivery (library caches skipped message keys)
  - Longer back-and-forth (frequent DH ratchet steps)

Run:
    python test_phase1.py
"""

from signal_layer import SignalClient


def _print_state(label: str, client: SignalClient, peer: str) -> None:
    s = client.inspect_session(peer)
    idx = s["send_chain_idx"]
    idx_str = f"@ idx={idx}" if idx is not None else ""
    print(f"  [{label:28}] root={s['root_key']}  "
          f"send={s['send_chain']} {idx_str}  prev={s['prev_counter']}")


def demo():
    print("=" * 72)
    print("Testing Signal Protocol baseline — multi-message exchange")
    print("=" * 72)

    alice = SignalClient("alice")
    bob = SignalClient("bob")

    print(f"\nAlice identity: {alice.identity_public_key[:8].hex()}")
    print(f"Bob   identity: {bob.identity_public_key[:8].hex()}")

    # --- Setup ---
    print("\n[1] Bob publishes a pre-key bundle.")
    bob_bundle = bob.publish_bundle(pre_key_id=100, signed_pre_key_id=5)

    print("[2] Alice processes the bundle (X3DH).")
    alice.start_session("bob", bob_bundle)
    _print_state("Alice post-X3DH", alice, "bob")

    # --- First message (PreKey handshake) ---
    print("\n[3] Alice sends first message (PreKeyWhisperMessage).")
    wire = alice.encrypt("bob", b"Hi Bob, message 1.")
    print(f"    wire: {len(wire)} bytes")
    pt = bob.decrypt("alice", wire)
    print(f"    Bob got: {pt.decode()!r}")
    _print_state("Alice after send #1", alice, "bob")
    _print_state("Bob after recv #1", bob, "alice")

    # --- Multiple messages same direction (sender chain advances) ---
    print("\n[4] Alice sends 3 more messages without Bob replying.")
    for i in range(2, 5):
        wire = alice.encrypt("bob", f"Message {i} from Alice.".encode())
        pt = bob.decrypt("alice", wire)
        print(f"    [{i}] {len(wire)} bytes -> Bob got: {pt.decode()!r}")
    _print_state("Alice after send #4", alice, "bob")
    _print_state("Bob after recv #4", bob, "alice")

    # --- Bob replies: DH ratchet steps ---
    print("\n[5] Bob replies (DH ratchet step — watch Alice's root key change).")
    wire = bob.encrypt("alice", b"Got all your messages, Alice.")
    print(f"    wire: {len(wire)} bytes")
    pt = alice.decrypt("bob", wire)
    print(f"    Alice got: {pt.decode()!r}")
    _print_state("Alice after recv reply", alice, "bob")
    _print_state("Bob after send reply", bob, "alice")

    # --- Alice replies back ---
    print("\n[6] Alice sends after Bob's reply (new sending chain).")
    wire = alice.encrypt("bob", b"Great, glad you got them.")
    pt = bob.decrypt("alice", wire)
    print(f"    Bob got: {pt.decode()!r}")
    _print_state("Alice after send #5", alice, "bob")
    _print_state("Bob after recv #5", bob, "alice")

    # --- Out-of-order delivery ---
    print("\n[7] Out-of-order: Alice sends 3, Bob decrypts in order [3, 1, 2].")
    ooo = [
        alice.encrypt("bob", b"ooo-A (first sent)"),
        alice.encrypt("bob", b"ooo-B (second sent)"),
        alice.encrypt("bob", b"ooo-C (third sent)"),
    ]
    for idx in [2, 0, 1]:
        pt = bob.decrypt("alice", ooo[idx])
        print(f"    delivered: {pt.decode()!r}")
    _print_state("Alice after OOO", alice, "bob")
    _print_state("Bob after OOO", bob, "alice")

    # --- Back-and-forth: many DH ratchet steps ---
    print("\n[8] Ping-pong — root key should change every turn.")
    for turn in range(1, 4):
        a_wire = alice.encrypt("bob", f"turn {turn}: alice".encode())
        bob.decrypt("alice", a_wire)
        _print_state(f"after alice turn {turn}", alice, "bob")

        b_wire = bob.encrypt("alice", f"turn {turn}: bob".encode())
        alice.decrypt("bob", b_wire)
        _print_state(f"after bob turn {turn}", alice, "bob")

    print("\n" + "=" * 72)
    print("What you saw:")
    print("  - First message was PreKeyWhisperMessage; rest were WhisperMessages.")
    print("  - Sender chain index advanced with each send in same direction.")
    print("  - Root key changed on direction switches (DH ratchet steps).")
    print("  - Out-of-order messages decrypted correctly.")
    print("=" * 72)


if __name__ == "__main__":
    demo()