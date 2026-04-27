# Composes two layers: Signal transport + receiver-anamorphic encryption.

import json

from ElGamal_v1.signal_layer import SignalClient
from ElGamal_v1.src_anamorphic_ElGamal.receiver_am import ReceiverAnamorphicEncryption


# Change DEFAULT_LAMBDA_BITS affects the limit of allowed message.
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
        
        # Decrypt a Signal-wrapped anamorphic message. Returns (cover, hidden).

        ct_bytes = self.signal.decrypt(peer_name, wire)
        ciphertext = _deserialize_ciphertext(ct_bytes)
        cover = self._ram.NormalDecrypt(self.aSK, ciphertext)
        hidden = self._ram.DoubleDecrypt(self.dkey, ciphertext)
        return cover, hidden

    def receive_cover_only(self, peer_name: str, wire: bytes) -> str:
        """Decrypt showing cover only. This is the view a coercer would have after
        extracting the 'normal' key.
        """
        ct_bytes = self.signal.decrypt(peer_name, wire)
        ciphertext = _deserialize_ciphertext(ct_bytes)
        return self._ram.NormalDecrypt(self.aSK, ciphertext)

    # ---- Inspection ----

    def inspect_signal(self, peer_name: str) -> dict:
        """Expose the underlying Signal ratchet state (for debugging)."""
        return self.signal.inspect_session(peer_name)