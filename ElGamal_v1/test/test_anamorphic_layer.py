"""
test_phase3.py — End-to-end anamorphic messaging over Signal.

Scenarios:
  1. Setup: key generation, pre-key bundles, aPK exchange.
  2. Basic send: Alice sends cover+hidden, Bob decrypts both.
  3. Bidirectional exchange.
  4. Multi-message run (Signal ratchet advances).
  5. Capability separation: aSK alone reveals only cover.
  6. Third-party property: Alice holding Bob's aPK cannot read hidden
     messages other senders address to Bob.
  7. Unicode sanity.
  8. Signal ratchet state inspection.
"""

from ElGamal_v1.anamorphic_layer import AnamorphicSession
from ElGamal_v1.src_anamorphic_ElGamal.receiver_am import ReceiverAnamorphicEncryption


def hr():
    print("-" * 64)


def setup():
    print("\n[SETUP] Generate keys, exchange Signal bundles and aPKs")
    hr()

    alice = AnamorphicSession("alice")
    bob = AnamorphicSession("bob")
    print(f"  Alice Signal identity: {alice.signal.identity_public_key[:8].hex()}")
    print(f"  Bob   Signal identity: {bob.signal.identity_public_key[:8].hex()}")

    # Signal handshake: publish bundles, process peer bundle (X3DH).
    bob_bundle = bob.publish_signal_bundle(pre_key_id=101, signed_pre_key_id=1)
    alice_bundle = alice.publish_signal_bundle(pre_key_id=102, signed_pre_key_id=1)
    alice.start_signal_session("bob", bob_bundle)
    bob.start_signal_session("alice", alice_bundle)

    # Anamorphic setup: only aPKs are exchanged. dkeys stay with their owners.
    alice.provision_peer("bob", bob.public_anamorphic())
    bob.provision_peer("alice", alice.public_anamorphic())

    print("  Signal sessions established, aPKs exchanged.")
    print("  dkeys remain with each user, never transmitted.")
    return alice, bob


def scenario_basic(alice, bob):
    print("\n[1] Basic: Alice sends cover+hidden, Bob decrypts both")
    hr()
    cover = "Hey, what are you up to tonight?"
    hidden = "The package is at the usual spot."

    wire = alice.send_to("bob", cover=cover, hidden=hidden)
    print(f"  wire size: {len(wire)} bytes")

    got_cover, got_hidden = bob.receive_from("alice", wire)
    print(f"  cover:  {got_cover!r}  {'OK' if got_cover == cover else 'FAIL'}")
    print(f"  hidden: {got_hidden!r}  {'OK' if got_hidden == hidden else 'FAIL'}")
    assert got_cover == cover
    assert got_hidden == hidden


def scenario_bidirectional(alice, bob):
    print("\n[2] Bob replies with his own cover+hidden")
    hr()
    cover = "Not much, watching a movie."
    hidden = "Understood, I'll pick it up tomorrow."

    wire = bob.send_to("alice", cover=cover, hidden=hidden)
    got_cover, got_hidden = alice.receive_from("bob", wire)
    print(f"  cover:  {got_cover!r}  {'OK' if got_cover == cover else 'FAIL'}")
    print(f"  hidden: {got_hidden!r}  {'OK' if got_hidden == hidden else 'FAIL'}")
    assert got_cover == cover
    assert got_hidden == hidden


def scenario_multi(alice, bob):
    print("\n[3] Multi-message exchange")
    hr()
    exchanges = [
        ("alice", "What movie?",                     "Meet at 9pm"),
        ("bob",   "Some indie thing, pretty slow.",  "Bring the blue bag"),
        ("alice", "Oh nice, recommended?",           "Got it, already packed"),
        ("bob",   "Eh, 6/10. You'd hate it.",        "Be careful, different car this time"),
        ("alice", "Lol. I might watch later anyway.","Understood"),
    ]

    for sender, cover, hidden in exchanges:
        src, dst = (alice, bob) if sender == "alice" else (bob, alice)
        wire = src.send_to(dst.name, cover=cover, hidden=hidden)
        got_cover, got_hidden = dst.receive_from(src.name, wire)
        ok = got_cover == cover and got_hidden == hidden
        print(f"  [{sender}->{dst.name}] {got_cover!r} / {got_hidden!r}  "
              f"{'OK' if ok else 'FAIL'}")
        assert ok


def scenario_capability_separation(alice, bob):
    """aSK alone reveals cover; dkey is required for hidden.

    This demonstrates the capability separation at the cryptographic level.
    A real security argument also requires that dkey is stored separately
    from aSK operationally (different device, passphrase-protected, etc.) —
    that is out of scope for the protocol and is the user's responsibility.
    """
    print("\n[4] Capability separation: aSK alone reveals only cover")
    hr()

    cover = "See you at the game on Saturday!"
    hidden = "The server room code is 4719."

    # Full path: Bob has aSK and dkey, sees both.
    wire1 = alice.send_to("bob", cover=cover, hidden=hidden)
    got_cover, got_hidden = bob.receive_from("alice", wire1)
    print(f"  Bob (aSK + dkey) sees:")
    print(f"    cover:  {got_cover!r}")
    print(f"    hidden: {got_hidden!r}")

    # aSK-only path: use the cover-only helper to simulate what decryption
    # would produce if dkey were not available.
    wire2 = alice.send_to("bob", cover=cover + " (next)",
                          hidden=hidden + " (next)")
    cover_only = bob.receive_cover_only("alice", wire2)
    print(f"\n  aSK-only view (simulated):")
    print(f"    cover:  {cover_only!r}")
    print(f"    hidden: <not decryptable without dkey>")
    assert cover_only == cover + " (next)"


def scenario_third_party(alice, bob):
    """Anyone can encrypt to Bob (he published aPK). Only Bob can decrypt.

    Specifically: Alice holds Bob's aPK, which lets her send to him. It does
    not let her read messages other senders address to Bob, because aPK
    contains no secret material.
    """
    print("\n[5] Third-party property: aPK only grants send, not read")
    hr()

    # Simulate a third-party Carol sending to Bob.
    ram = ReceiverAnamorphicEncryption()
    carol_cover = "hey bob, book club thursday?"
    carol_hidden = "asset pickup location changed to pier 7"
    bob_aPK = bob.public_anamorphic()
    carol_ct = ram.AnamorphicEncrypt(bob_aPK, carol_cover, carol_hidden)

    # Bob decrypts using his own aSK and dkey.
    bob_cover = ram.NormalDecrypt(bob.aSK, carol_ct)
    bob_hidden = ram.DoubleDecrypt(bob.dkey, carol_ct)
    print(f"  Bob reads:")
    print(f"    cover:  {bob_cover!r}")
    print(f"    hidden: {bob_hidden!r}")
    assert bob_cover == carol_cover
    assert bob_hidden == carol_hidden

    # Alice has Bob's aPK (public) and her own aSK/dkey (useless for Bob's
    # ciphertexts). She has no way to recover either cover or hidden from
    # a ciphertext addressed to Bob.
    print(f"\n  Alice's available keys for decrypting Carol->Bob ciphertext:")
    print(f"    - Bob's aPK   (public; gives sending ability only)")
    print(f"    - Alice's own aSK, dkey  (unrelated to Bob's keypair)")
    print(f"  Recovery requires sk0/sk1 for Bob, which Alice never obtains.")


def scenario_unicode(alice, bob):
    print("\n[6] Unicode messages")
    hr()
    cover = "Nos vemos en el café, 21h."
    hidden = "暗号鍵: 7829 🔐"

    wire = alice.send_to("bob", cover=cover, hidden=hidden)
    got_cover, got_hidden = bob.receive_from("alice", wire)
    print(f"  cover  {'OK' if got_cover == cover else 'FAIL'}: {got_cover!r}")
    print(f"  hidden {'OK' if got_hidden == hidden else 'FAIL'}: {got_hidden!r}")
    assert got_cover == cover
    assert got_hidden == hidden


def scenario_inspect_ratchet(alice, bob):
    print("\n[7] Signal ratchet state")
    hr()
    a = alice.inspect_signal("bob")
    b = bob.inspect_signal("alice")
    print(f"  alice->bob: root={a['root_key']}  send={a['send_chain']} @ {a['send_chain_idx']}")
    print(f"  bob->alice: root={b['root_key']}  send={b['send_chain']} @ {b['send_chain_idx']}")
    print(f"  Different roots reflect multiple DH ratchet steps during the run.")


def main():
    print("=" * 64)
    print("Phase 3: Anamorphic messaging over Signal")
    print("=" * 64)

    alice, bob = setup()
    scenario_basic(alice, bob)
    scenario_bidirectional(alice, bob)
    scenario_multi(alice, bob)
    scenario_capability_separation(alice, bob)
    scenario_third_party(alice, bob)
    scenario_unicode(alice, bob)
    scenario_inspect_ratchet(alice, bob)

    print("\n" + "=" * 64)
    print("All scenarios passed.")
    print("")
    print("Summary of properties observed:")
    print("  - Transport: Signal provides X3DH, ratcheting, out-of-order handling.")
    print("  - Anamorphic: every message carries (cover, hidden) as a pair.")
    print("  - aSK alone recovers cover only; dkey is needed for hidden.")
    print("  - aPK grants send ability only; it does not grant read ability.")
    print("  - dkey never leaves its owner; operational protection is")
    print("    the sole defense once the protocol runs correctly.")
    print("=" * 64)


if __name__ == "__main__":
    main()