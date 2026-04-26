"""
signal_layer.py — Reusable Signal Protocol wrappers over python-axolotl.

This module exposes a small, friendly API on top of python-axolotl so the rest
of the project (tests, CLI, anamorphic integration) doesn't have to know about
axolotl's four-store constructor calls or the PreKeyWhisperMessage/WhisperMessage
routing dance.

Public API:
    SignalClient            - holds one user's identity + stores.
    SignalClient.publish_bundle(pre_key_id, signed_pre_key_id) -> PreKeyBundle
    SignalClient.start_session(peer_name, peer_bundle, device_id=1)
    SignalClient.encrypt(peer_name, plaintext: bytes, device_id=1) -> bytes
    SignalClient.decrypt(peer_name, wire_bytes: bytes, device_id=1) -> bytes
    SignalClient.inspect_session(peer_name, device_id=1) -> dict

Note: the protobuf env var MUST be set before importing anything from axolotl.
We set it at module load so importers don't have to remember.
"""

import os
os.environ.setdefault("PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION", "python")

from axolotl.util.keyhelper import KeyHelper
from axolotl.state.prekeybundle import PreKeyBundle
from axolotl.sessionbuilder import SessionBuilder
from axolotl.sessioncipher import SessionCipher
from axolotl.protocol.prekeywhispermessage import PreKeyWhisperMessage
from axolotl.protocol.whispermessage import WhisperMessage
from axolotl.tests.inmemoryaxolotlstore import InMemoryAxolotlStore


class SignalClient:
    """One user's Signal state — identity keys, pre-keys, sessions with peers.

    Wraps a single InMemoryAxolotlStore that serves all four store roles
    (session, pre-key, signed-pre-key, identity). That's standard python-axolotl
    usage. For Phase 3+, subclass this or extend `store` with the anamorphic
    additions (dual keys, anamorphic keypairs, ratchet state).
    """

    def __init__(self, name: str, store: InMemoryAxolotlStore | None = None):
        self.name = name
        self.store = store if store is not None else InMemoryAxolotlStore()
        self._ciphers: dict[tuple[str, int], SessionCipher] = {}

    # ---- Identity ----

    @property
    def identity_public_key(self) -> bytes:
        return self.store.getIdentityKeyPair().getPublicKey().serialize()

    @property
    def registration_id(self) -> int:
        return self.store.getLocalRegistrationId()

    # ---- Bundle publishing (Bob side of the handshake) ----

    def publish_bundle(self, pre_key_id: int, signed_pre_key_id: int,
                       device_id: int = 1) -> PreKeyBundle:
        """Generate and store a one-time pre-key + signed pre-key, return the
        public bundle. In a real system the bundle goes to a directory server;
        here we just return it for the caller to pass around.
        """
        identity = self.store.getIdentityKeyPair()
        one_time = KeyHelper.generatePreKeys(pre_key_id, 1)[0]
        signed = KeyHelper.generateSignedPreKey(identity, signed_pre_key_id)

        self.store.storePreKey(one_time.getId(), one_time)
        self.store.storeSignedPreKey(signed.getId(), signed)

        return PreKeyBundle(
            self.registration_id,
            device_id,
            one_time.getId(),
            one_time.getKeyPair().getPublicKey(),
            signed.getId(),
            signed.getKeyPair().getPublicKey(),
            signed.getSignature(),
            identity.getPublicKey(),
        )

    # ---- Session setup (Alice side of the handshake) ----

    def start_session(self, peer_name: str, peer_bundle: PreKeyBundle,
                      device_id: int = 1) -> None:
        """Process a peer's pre-key bundle. Runs X3DH, establishes session state.
        After this, encrypt() to this peer will work.
        """
        builder = SessionBuilder(
            self.store, self.store, self.store, self.store,
            peer_name, device_id,
        )
        builder.processPreKeyBundle(peer_bundle)

    # ---- Messaging ----

    def _cipher(self, peer_name: str, device_id: int) -> SessionCipher:
        """Lazily construct and cache a SessionCipher per peer."""
        key = (peer_name, device_id)
        if key not in self._ciphers:
            self._ciphers[key] = SessionCipher(
                self.store, self.store, self.store, self.store,
                peer_name, device_id,
            )
        return self._ciphers[key]

    def encrypt(self, peer_name: str, plaintext: bytes,
                device_id: int = 1) -> bytes:
        """Encrypt plaintext for peer. Returns serialized wire bytes.
        The receiver doesn't need to know whether this is a PreKey or regular
        message — decrypt() figures it out from the wire format.
        """
        cipher = self._cipher(peer_name, device_id)
        message = cipher.encrypt(plaintext)
        return message.serialize()

    def decrypt(self, peer_name: str, wire_bytes: bytes,
                device_id: int = 1) -> bytes:
        """Decrypt wire bytes from peer. Auto-detects PreKeyWhisperMessage vs
        WhisperMessage. If this is the first message from a new peer, the
        session is built implicitly from the PreKey header.
        """
        cipher = self._cipher(peer_name, device_id)
        # Try as PreKeyWhisperMessage first (carries X3DH handshake).
        # If that fails because it's a regular message, fall through.
        try:
            msg = PreKeyWhisperMessage(serialized=wire_bytes)
            return cipher.decryptPkmsg(msg)
        except Exception:
            msg = WhisperMessage(serialized=wire_bytes)
            return cipher.decryptMsg(msg)

    # ---- State inspection (for tests/demos) ----

    def inspect_session(self, peer_name: str, device_id: int = 1) -> dict:
        """Pull ratchet state out of the session record, for visibility during
        testing. Returns fingerprint-style 8-byte hex prefixes of the root key
        and current sending chain key, plus the previous-chain counter.
        """
        record = self.store.loadSession(peer_name, device_id)
        state = record.getSessionState()

        info = {
            "root_key": _hex8(state.getRootKey().getKeyBytes()),
            "send_chain": "(none)",
            "send_chain_idx": None,
            "prev_counter": state.getPreviousCounter(),
        }

        try:
            sender_chain = state.getSenderChainKey()
            if sender_chain is not None:
                info["send_chain"] = _hex8(sender_chain.getKey())
                info["send_chain_idx"] = sender_chain.getIndex()
        except Exception:
            pass

        return info


def _hex8(b: bytes) -> str:
    """First 8 bytes as hex — short enough to eyeball, long enough to tell keys apart."""
    return b[:8].hex() if b else "(none)"