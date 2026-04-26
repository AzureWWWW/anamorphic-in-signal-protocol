"""
anamorphic_session.py — v2 (Approach B): Signal session with anamorphic AEAD.

This is the v2 counterpart to phase2/anamorphic_session.py. The shape is
similar — an AnamorphicSession is one user's combined Signal + anamorphic
state — but the internals differ:

  v1 (Approach A): anamorphic encryption was a wrapper layer, applied to
                   plaintext before handing the bytes to a vanilla SignalClient
                   (which then did Signal's normal AES-CBC + HMAC).

  v2 (Approach B): anamorphic encryption replaces Signal's AES-CBC. The
                   AnamorphicSessionCipher subclass of python-axolotl's
                   SessionCipher does the anamorphic AEAD inline. There is
                   no double-wrapping — only one symmetric encryption per
                   message (AES-GCM, with keys derived from Signal's ratchet
                   IV via HKDF, encrypted under the anamorphic ElGamal
                   keypair).

Public API matches v1 closely so the existing CLI/relay stack drops in:

    session = AnamorphicSession(name)
    session.publish_signal_bundle(pre_key_id, signed_pre_key_id) -> PreKeyBundle
    session.public_anamorphic() -> aPK dict
    session.provision_peer(peer_name, peer_aPK)
    session.start_signal_session(peer_name, peer_signal_bundle)
    session.send_to(peer_name, cover, hidden) -> wire bytes
    session.receive_from(peer_name, wire_bytes) -> (cover, hidden)
    session.receive_cover_only(peer_name, wire_bytes) -> str  # demo helper

Key differences from v1:
  - send_to / receive_from operate on Signal message objects directly (we
    serialize/deserialize at this layer) rather than wrapping bytes through
    a separate Signal layer.
  - cover and hidden have no length cap — the AEAD layer's AES-GCM handles
    arbitrary-length plaintexts.
"""

import os
os.environ.setdefault("PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION", "python")

from axolotl.util.keyhelper import KeyHelper
from axolotl.state.prekeybundle import PreKeyBundle
from axolotl.sessionbuilder import SessionBuilder
from axolotl.protocol.prekeywhispermessage import PreKeyWhisperMessage
from axolotl.protocol.whispermessage import WhisperMessage
from axolotl.protocol.ciphertextmessage import CiphertextMessage
from axolotl.tests.inmemoryaxolotlstore import InMemoryAxolotlStore

from ElGamal_v2.anamorphic_session_cipher import AnamorphicSessionCipher
from ElGamal_v2.src_anamorphic_ElGamal.receiver_am import ReceiverAnamorphicEncryption


# Match the demo size used elsewhere; bump to >= 2048 for real deployment.
DEFAULT_LAMBDA_BITS = 512


class AnamorphicSession:
    """One user's combined Signal + anamorphic state (v2).

    Owns:
      - An InMemoryAxolotlStore (Signal's identity, pre-keys, sessions).
      - The user's anamorphic keypair (aPK, aSK, dkey).
      - Per-peer AnamorphicSessionCipher instances (lazily constructed).
      - A table of known peer aPKs.
    """

    DEVICE_ID = 1  # No multi-device support in this prototype.

    def __init__(self, name: str, lambda_bits: int = DEFAULT_LAMBDA_BITS,
                 store: InMemoryAxolotlStore | None = None):
        self.name = name
        self.store = store if store is not None else InMemoryAxolotlStore()

        # Anamorphic keypair: aPK is publishable; aSK and dkey stay on this device.
        ram = ReceiverAnamorphicEncryption()
        self.aPK, self.aSK, self.dkey = ram.AnamorphicKeyGen(lambda_bits)

        # peer_name -> peer's aPK. Required to send to that peer.
        self._peer_aPKs: dict[str, dict] = {}

        # peer_name -> AnamorphicSessionCipher for that peer. Cached.
        self._ciphers: dict[str, AnamorphicSessionCipher] = {}

    # ---- Published material ----

    @property
    def identity_public_key(self) -> bytes:
        return self.store.getIdentityKeyPair().getPublicKey().serialize()

    @property
    def registration_id(self) -> int:
        return self.store.getLocalRegistrationId()

    def publish_signal_bundle(self, pre_key_id: int,
                              signed_pre_key_id: int) -> PreKeyBundle:
        """Generate and store a one-time pre-key + signed pre-key; return the
        public bundle. Same structure as v1's SignalClient.publish_bundle."""
        identity = self.store.getIdentityKeyPair()
        one_time = KeyHelper.generatePreKeys(pre_key_id, 1)[0]
        signed = KeyHelper.generateSignedPreKey(identity, signed_pre_key_id)
        self.store.storePreKey(one_time.getId(), one_time)
        self.store.storeSignedPreKey(signed.getId(), signed)
        return PreKeyBundle(
            self.registration_id, self.DEVICE_ID,
            one_time.getId(), one_time.getKeyPair().getPublicKey(),
            signed.getId(), signed.getKeyPair().getPublicKey(),
            signed.getSignature(),
            identity.getPublicKey(),
        )

    def public_anamorphic(self) -> dict:
        """The user's public anamorphic bundle (aPK). Safe to publish."""
        return self.aPK

    # ---- Learning about peers ----

    def provision_peer(self, peer_name: str, peer_aPK: dict) -> None:
        """Record a peer's aPK so we can encrypt anamorphic messages to them.
        Discards any cached cipher for that peer so the next send/receive
        rebuilds with the new aPK.
        """
        self._peer_aPKs[peer_name] = peer_aPK
        # Drop the cached cipher (its peer_aPK reference may be stale).
        self._ciphers.pop(peer_name, None)

    def start_signal_session(self, peer_name: str, peer_bundle) -> None:
        """Run X3DH against a peer's Signal pre-key bundle."""
        builder = SessionBuilder(
            self.store, self.store, self.store, self.store,
            peer_name, self.DEVICE_ID,
        )
        builder.processPreKeyBundle(peer_bundle)

    # ---- Cipher lifecycle ----

    def _get_cipher(self, peer_name: str,
                    require_peer_aPK: bool) -> AnamorphicSessionCipher:
        """Get or build the AnamorphicSessionCipher for this peer.

        require_peer_aPK: True if we're about to encrypt; the cipher will be
        constructed in send-capable mode (or rebuilt if the cached one is
        receive-only). False if we're decrypting and any cipher will do.
        """
        cached = self._ciphers.get(peer_name)
        if cached is not None:
            if not require_peer_aPK or cached._peer_aPK is not None:
                return cached
            # Cache exists but is receive-only and we now need to send;
            # rebuild with peer_aPK below.

        peer_aPK = self._peer_aPKs.get(peer_name)
        if require_peer_aPK and peer_aPK is None:
            raise ValueError(
                f"No aPK known for peer {peer_name!r}; call provision_peer() "
                f"before sending."
            )

        cipher = AnamorphicSessionCipher(
            self.store, self.store, self.store, self.store,
            peer_name, self.DEVICE_ID,
            my_aSK=self.aSK,
            my_dkey=self.dkey,
            peer_aPK=peer_aPK,  # may be None for receive-only
        )
        self._ciphers[peer_name] = cipher
        return cipher

    # ---- Sending ----

    def send_to(self, peer_name: str, cover: str, hidden: str) -> bytes:
        """Encrypt (cover, hidden) for peer; return wire bytes ready to ship.

        Wire bytes are the serialized form of the Signal message object
        (PreKeyWhisperMessage on the first send to a new peer, WhisperMessage
        once the session is acknowledged).
        """
        cipher = self._get_cipher(peer_name, require_peer_aPK=True)
        signal_msg = cipher.encrypt_pair(cover, hidden)
        return signal_msg.serialize()

    # ---- Receiving ----

    def _decrypt_signal_msg(self, cipher: AnamorphicSessionCipher,
                             wire_bytes: bytes,
                             want_pair: bool) -> tuple[str, str] | str:
        """Common path: parse wire bytes as PreKey or regular WhisperMessage,
        run the appropriate decrypt method, return (cover, hidden) or just cover.
        """
        # Trial-parse: PreKeyWhisperMessage parsing fails cleanly on a regular
        # WhisperMessage; same approach v1 used.
        try:
            msg = PreKeyWhisperMessage(serialized=wire_bytes)
            if want_pair:
                return cipher.decrypt_pair_pkmsg(msg)
            cipher.decryptPkmsg(msg)
            cover, _ = cipher._last_decrypted
            cipher._last_decrypted = None
            return cover
        except Exception:
            msg = WhisperMessage(serialized=wire_bytes)
            if want_pair:
                return cipher.decrypt_pair_msg(msg)
            cipher.decryptMsg(msg)
            cover, _ = cipher._last_decrypted
            cipher._last_decrypted = None
            return cover

    def receive_from(self, peer_name: str, wire_bytes: bytes) -> tuple[str, str]:
        """Decrypt a Signal-wrapped anamorphic message. Returns (cover, hidden).

        Both halves are recovered because this user holds their own aSK and dkey.
        """
        # Decryption doesn't require peer_aPK (we use only our own keys for
        # the AES nonce derivation), so peer_aPK can be None.
        cipher = self._get_cipher(peer_name, require_peer_aPK=False)
        result = self._decrypt_signal_msg(cipher, wire_bytes, want_pair=True)
        return result  # type: ignore[return-value]

    def receive_cover_only(self, peer_name: str, wire_bytes: bytes) -> str:
        """Decrypt and return only the cover, discarding hidden.

        Illustrative helper: simulates what would be recoverable if dkey were
        not available. In v2 the cipher's getPlaintext decrypts both halves
        regardless (it has both keys), so this is purely a presentation choice
        — it's not a faithful coercion simulation. Same caveat as v1.
        """
        cipher = self._get_cipher(peer_name, require_peer_aPK=False)
        result = self._decrypt_signal_msg(cipher, wire_bytes, want_pair=False)
        return result  # type: ignore[return-value]

    # ---- Inspection ----

    def has_session_with(self, peer_name: str) -> bool:
        """Whether a Signal session exists for this peer."""
        return self.store.containsSession(peer_name, self.DEVICE_ID)

    def has_aPK_for(self, peer_name: str) -> bool:
        """Whether we know the peer's aPK (and so can send to them)."""
        return peer_name in self._peer_aPKs