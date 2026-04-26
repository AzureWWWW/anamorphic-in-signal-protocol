"""
anamorphic_session.py — Phase 3: Signal transport + receiver-anamorphic encryption.

Composes two layers:

  - SignalClient provides transport: X3DH handshake, Double Ratchet, session
    state. This gives forward secrecy and post-compromise security at the
    transport level, and hides the existence of anamorphic traffic — on the
    wire, everything looks like ordinary Signal messages.

  - ReceiverAnamorphicEncryption provides the dual-message property: each
    transmission carries both a cover (m0) and a hidden (m1) plaintext.
    Decrypting with aSK recovers the cover. Decrypting with dkey recovers
    the hidden.

Each user holds three pieces of anamorphic key material:
  - aPK  : public bundle. Published; anyone can encrypt to this user.
  - aSK  : the "normal" secret key. This is the key a coerced user hands
           over; doing so reveals cover messages only.
  - dkey : the dual secret. MUST remain secret — if it leaks, all hidden
           messages (past and future) become readable. The scheme's covert
           property rests entirely on dkey staying unknown to the adversary.
           dkey is held only by its owner; it is never transmitted.

Send path (Alice -> Bob):
  1. Alice fetches Bob's aPK (published).
  2. ReceiverAnamorphicEncryption.AnamorphicEncrypt(bob_aPK, cover, hidden)
     produces an anamorphic ciphertext dict.
  3. The dict is serialized to bytes.
  4. SignalClient.encrypt wraps those bytes as a normal Signal message.

Receive path (Bob):
  1. SignalClient.decrypt unwraps to the anamorphic ciphertext bytes.
  2. Bytes are deserialized back to the ciphertext dict.
  3. NormalDecrypt(bob_aSK, ct) recovers the cover message.
  4. DoubleDecrypt(bob_dkey, ct) recovers the hidden message.

Threat coverage summary:
  - Passive network observer: blocked by Signal's transport encryption.
  - Coerced user who reveals aSK: sees cover only. Cannot recover hidden
    without dkey. This is the anamorphic property.
  - Adversary who compromises Signal session state (but not dkey): can read
    current anamorphic ciphertexts as bytes but cannot decrypt the hidden
    channel. Signal's forward secrecy still protects past wire bytes.
  - Adversary who obtains dkey: game over. No protocol mechanism protects
    against dkey compromise — the scheme is deliberately designed this way.
    Security reduces to operational protection of dkey.
"""

import json

from ElGamal_v1.signal_layer import SignalClient
from ElGamal_v1.src_anamorphic_ElGamal.receiver_am import ReceiverAnamorphicEncryption


# 512 bits is fast enough for prototype iteration. Real deployment: >= 2048.
DEFAULT_LAMBDA_BITS = 512


# ----------------------------------------------------------------------
# Ciphertext serialization
# ----------------------------------------------------------------------
# An anamorphic ciphertext is a nested dict:
#   {
#     'ct0': {'c1': BigInt, 'c2': BigInt, 'y_used': BigInt},
#     'ct1': {'c1': BigInt, 'c2': BigInt, 'y_used': BigInt},
#     'pi':  bytes (NIZK proof; placeholder for now),
#   }
# We serialize to JSON with BigInts and bytes as hex strings so Signal can
# transport it.
#
# Note on y_used: the sender's randomness. Not needed for decryption; we
# keep it so the round-tripped dict is structurally identical to the
# pre-transmit one.
#
# Note on pi: placeholder for a Persiano-style NIZK proof that binds ct0
# and ct1. Currently inert (never verified on decrypt). Reserved in the
# wire format so swapping in a real NIZK does not require protocol changes.

def _serialize_ciphertext(ct: dict) -> bytes:
    def pack_elgamal(ec):
        return {
            'c1': hex(ec['c1']),
            'c2': hex(ec['c2']),
            'y_used': hex(ec['y_used']),
        }
    wire = {
        'ct0': pack_elgamal(ct['ct0']),
        'ct1': pack_elgamal(ct['ct1']),
        'pi': ct['pi'].hex(),
    }
    return json.dumps(wire).encode('utf-8')


def _deserialize_ciphertext(data: bytes) -> dict:
    wire = json.loads(data.decode('utf-8'))
    def unpack_elgamal(ec):
        return {
            'c1': int(ec['c1'], 16),
            'c2': int(ec['c2'], 16),
            'y_used': int(ec['y_used'], 16),
        }
    return {
        'ct0': unpack_elgamal(wire['ct0']),
        'ct1': unpack_elgamal(wire['ct1']),
        'pi': bytes.fromhex(wire['pi']),
    }


# ----------------------------------------------------------------------
# AnamorphicSession
# ----------------------------------------------------------------------

class AnamorphicSession:
    """One user's combined Signal + anamorphic state.

    Owns a SignalClient (transport) plus the user's own anamorphic keypair
    (aPK, aSK, dkey). Maintains a table of known peer aPKs so the user can
    encrypt outbound messages.
    """

    def __init__(self, name: str, lambda_bits: int = DEFAULT_LAMBDA_BITS):
        self.name = name
        self.signal = SignalClient(name)
        self._ram = ReceiverAnamorphicEncryption()

        # This user's anamorphic keypair. aPK will be published; aSK and
        # dkey are kept on this device.
        self.aPK, self.aSK, self.dkey = self._ram.AnamorphicKeyGen(lambda_bits)

        # peer_name -> peer's aPK. Populated via provision_peer().
        self._peer_aPKs: dict[str, dict] = {}

    # ---- Published material ----

    def publish_signal_bundle(self, pre_key_id: int, signed_pre_key_id: int):
        """Generate a Signal pre-key bundle for publication."""
        return self.signal.publish_bundle(pre_key_id, signed_pre_key_id)

    def public_anamorphic(self) -> dict:
        """The user's public anamorphic bundle (aPK). Safe to publish."""
        return self.aPK

    # ---- Learning about peers ----

    def provision_peer(self, peer_name: str, peer_aPK: dict) -> None:
        """Record a peer's aPK so we can send anamorphic messages to them.

        aPK is public material, typically fetched from a directory service or
        posted alongside the peer's Signal pre-key bundle. No secret is
        exchanged here — there is no dkey handoff in receiver-anamorphic.
        """
        self._peer_aPKs[peer_name] = peer_aPK

    def start_signal_session(self, peer_name: str, peer_bundle) -> None:
        """Run X3DH against a peer's Signal pre-key bundle."""
        self.signal.start_session(peer_name, peer_bundle)

    # ---- Sending ----

    def send_to(self, peer_name: str, cover: str, hidden: str) -> bytes:
        """Encrypt (cover, hidden) for peer and wrap in Signal. Returns wire bytes."""
        if peer_name not in self._peer_aPKs:
            raise ValueError(
                f"No aPK known for {peer_name!r}. Call provision_peer() first."
            )
        ciphertext = self._ram.AnamorphicEncrypt(
            self._peer_aPKs[peer_name], cover, hidden
        )
        ct_bytes = _serialize_ciphertext(ciphertext)
        return self.signal.encrypt(peer_name, ct_bytes)

    # ---- Receiving ----

    def receive_from(self, peer_name: str, wire: bytes) -> tuple[str, str]:
        """Decrypt a Signal-wrapped anamorphic message. Returns (cover, hidden).

        Both are recovered because this user holds their own aSK and dkey.
        """
        ct_bytes = self.signal.decrypt(peer_name, wire)
        ciphertext = _deserialize_ciphertext(ct_bytes)
        cover = self._ram.NormalDecrypt(self.aSK, ciphertext)
        hidden = self._ram.DoubleDecrypt(self.dkey, ciphertext)
        return cover, hidden

    def receive_cover_only(self, peer_name: str, wire: bytes) -> str:
        """Decrypt showing cover only.

        Illustrative helper: what would be recoverable from a message if one
        held only aSK, not dkey. This is the view a coercer would have after
        extracting the 'normal' key. Note: this method still holds dkey in
        this object and chooses not to use it — a real coercion scenario
        would involve a process that genuinely lacks dkey access.
        """
        ct_bytes = self.signal.decrypt(peer_name, wire)
        ciphertext = _deserialize_ciphertext(ct_bytes)
        return self._ram.NormalDecrypt(self.aSK, ciphertext)

    # ---- Inspection ----

    def inspect_signal(self, peer_name: str) -> dict:
        """Expose the underlying Signal ratchet state (for debugging)."""
        return self.signal.inspect_session(peer_name)