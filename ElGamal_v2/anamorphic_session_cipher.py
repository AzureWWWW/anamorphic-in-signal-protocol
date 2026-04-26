"""
anamorphic_session_cipher.py — Approach B: replace Signal's AEAD with anamorphic.

Subclasses python-axolotl's SessionCipher and overrides the two methods that
form the AEAD seam: getCiphertext (encrypt-bytes) and getPlaintext (decrypt-
bytes). Everything else inherited unchanged.

What we replace:
  Signal original:   ciphertext = AES-256-CBC(messageKey.cipherKey, plaintext)
  Anamorphic version: ciphertext = serialize(
                          AnamorphicElGamal(pk0, k_cover, y0_from_ratchet),
                          AnamorphicElGamal(pk1, k_hidden, y1_from_ratchet),
                          AES-GCM(k_cover, cover_plaintext, nonce_cover),
                          AES-GCM(k_hidden, hidden_plaintext, nonce_hidden))
    where k_cover, k_hidden, nonce_*, y0, y1 are all derived from the
    ratchet's per-message IV via HKDF — so the entire encryption is anchored
    in Signal's forward-secure key schedule.

What we keep:
  - HMAC-SHA256 MAC over the message (Signal's existing integrity).
  - Protobuf framing of WhisperMessage / PreKeyWhisperMessage.
  - Double Ratchet, X3DH, out-of-order handling, skipped-key cache.

API differences from parent SessionCipher:
  - encrypt_pair(cover, hidden) instead of encrypt(plaintext)
  - decrypt_pair_msg / decrypt_pair_pkmsg return (cover, hidden) tuples
  - The parent's encrypt() / decryptMsg() / decryptPkmsg() are no longer
    intended to be called directly.
"""

import json

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

from axolotl.sessioncipher import SessionCipher

from ElGamal_v2.src_anamorphic_ElGamal.receiver_am import ReceiverAnamorphicEncryption


_AES_KEY_BYTES = 32
_NONCE_BYTES = 12

# Format version on the wire so we can extend later without ambiguity.
_FORMAT_VERSION = b"\x01"


def _derive_inner_secrets(message_iv: bytes, p0_bits: int, p1_bits: int):
    """From the ratchet's per-message IV (16 bytes), deterministically derive
    everything the anamorphic-AEAD needs:
      - k_cover, k_hidden     (32 bytes each, AES-256 keys)
      - nonce_cover, nonce_hidden (12 bytes each, AES-GCM nonces)
      - y0, y1                (ElGamal exponents in [2, p-2] for each modulus)

    Tying it all to the ratcheted IV means each message's encryption is
    deterministic in ratchet state. Forward-secrecy of the ratchet propagates
    to forward-secrecy of the anamorphic layer.
    """
    # Pull a generous amount; we'll slice it.
    out = HKDF(
        algorithm=hashes.SHA256(),
        length=2 * _AES_KEY_BYTES + 2 * _NONCE_BYTES + 2 * 64,  # 64 bytes per ElGamal exponent
        salt=None,
        info=b"anamorphic-aead-v1",
    ).derive(message_iv)

    pos = 0
    k_cover = out[pos:pos + _AES_KEY_BYTES]; pos += _AES_KEY_BYTES
    k_hidden = out[pos:pos + _AES_KEY_BYTES]; pos += _AES_KEY_BYTES
    nonce_cover = out[pos:pos + _NONCE_BYTES]; pos += _NONCE_BYTES
    nonce_hidden = out[pos:pos + _NONCE_BYTES]; pos += _NONCE_BYTES
    y0_raw = out[pos:pos + 64]; pos += 64
    y1_raw = out[pos:pos + 64]

    # Map raw bytes to ElGamal exponents in [2, p-2]. We have plenty of bits.
    y0 = (int.from_bytes(y0_raw, "big") % ((1 << p0_bits) - 4)) + 2
    y1 = (int.from_bytes(y1_raw, "big") % ((1 << p1_bits) - 4)) + 2
    return k_cover, k_hidden, nonce_cover, nonce_hidden, y0, y1


def _serialize(anamorphic_ct: dict, cover_blob: bytes, hidden_blob: bytes) -> bytes:
    """Serialize the on-wire payload.

    anamorphic_ct: {ct0, ct1, pi} as returned by AnamorphicEncrypt.
    cover_blob, hidden_blob: AES-GCM ciphertexts (incl. tags).
    """
    ct0 = anamorphic_ct["ct0"]
    ct1 = anamorphic_ct["ct1"]
    body = {
        "ct0": {"c1": hex(ct0["c1"]), "c2": hex(ct0["c2"])},
        "ct1": {"c1": hex(ct1["c1"]), "c2": hex(ct1["c2"])},
        "pi": anamorphic_ct["pi"].hex(),
        "cover": cover_blob.hex(),
        "hidden": hidden_blob.hex(),
    }
    return _FORMAT_VERSION + json.dumps(body, separators=(",", ":")).encode("utf-8")


def _deserialize(data: bytes) -> tuple[dict, bytes, bytes]:
    """Inverse of _serialize.

    Returns (anamorphic_ct, cover_blob, hidden_blob), where anamorphic_ct has
    the same shape as AnamorphicEncrypt's output so it can be fed directly to
    NormalDecrypt / DoubleDecrypt.
    """
    if not data or data[:1] != _FORMAT_VERSION:
        raise ValueError("unrecognized anamorphic ciphertext format")
    body = json.loads(data[1:].decode("utf-8"))
    anamorphic_ct = {
        "ct0": {"c1": int(body["ct0"]["c1"], 16),
                "c2": int(body["ct0"]["c2"], 16)},
        "ct1": {"c1": int(body["ct1"]["c1"], 16),
                "c2": int(body["ct1"]["c2"], 16)},
        "pi": bytes.fromhex(body["pi"]),
    }
    return anamorphic_ct, bytes.fromhex(body["cover"]), bytes.fromhex(body["hidden"])


class AnamorphicSessionCipher(SessionCipher):
    """SessionCipher with anamorphic AEAD instead of AES-CBC."""

    def __init__(self, sessionStore, preKeyStore, signedPreKeyStore,
                 identityKeyStore, recipientId, deviceId,
                 my_aSK, my_dkey, peer_aPK=None):
        super().__init__(sessionStore, preKeyStore, signedPreKeyStore,
                         identityKeyStore, recipientId, deviceId)
        self._ram = ReceiverAnamorphicEncryption()
        self._my_aSK = my_aSK
        self._my_dkey = my_dkey
        # peer_aPK is only needed when *we* encrypt for the peer. Receive-only
        # ciphers can construct without it.
        self._peer_aPK = peer_aPK

        # Per-encrypt state (set by encrypt_pair, read by getCiphertext).
        self._pending_cover: str | None = None
        self._pending_hidden: str | None = None

        # Per-decrypt state (set by getPlaintext, read by decrypt_pair_*).
        self._last_decrypted: tuple[str, str] | None = None

    # ---- Encryption ----

    def encrypt_pair(self, cover: str, hidden: str):
        """Encrypt a (cover, hidden) pair. Returns the WhisperMessage or
        PreKeyWhisperMessage that the parent's encrypt() produces."""
        if self._peer_aPK is None:
            raise RuntimeError(
                "encrypt_pair requires peer_aPK; this cipher was constructed "
                "in receive-only mode."
            )
        if not isinstance(cover, str) or not isinstance(hidden, str):
            raise TypeError("cover and hidden must both be str")
        self._pending_cover = cover
        self._pending_hidden = hidden
        try:
            # The parent's encrypt() calls our overridden getCiphertext().
            # We pass empty bytes because getCiphertext ignores its argument
            # and uses self._pending_* instead.
            return self.encrypt(b"")
        finally:
            self._pending_cover = None
            self._pending_hidden = None

    def getCiphertext(self, version, messageKeys, plainText):
        """Override of SessionCipher.getCiphertext.
        Returns: anamorphic ciphertext bytes. Ignores plainText argument.
        """
        if self._pending_cover is None or self._pending_hidden is None:
            raise RuntimeError(
                "AnamorphicSessionCipher.encrypt() called directly. "
                "Use encrypt_pair(cover, hidden)."
            )

        cover_bytes = self._pending_cover.encode("utf-8")
        hidden_bytes = self._pending_hidden.encode("utf-8")

        pk0 = self._peer_aPK["pk0"]
        pk1 = self._peer_aPK["pk1"]
        k_cover, k_hidden, nonce_cover, nonce_hidden, y0, y1 = _derive_inner_secrets(
            messageKeys.getIv(), pk0["p"].bit_length(), pk1["p"].bit_length(),
        )

        # AES-GCM over the actual cover and hidden plaintexts.
        cover_blob = AESGCM(k_cover).encrypt(nonce_cover, cover_bytes, None)
        hidden_blob = AESGCM(k_hidden).encrypt(nonce_hidden, hidden_bytes, None)

        # Anamorphic ElGamal encrypts the two AES keys as integers. y0 and y1
        # are bound to the ratchet IV, so the ElGamal randomness is forward-
        # secure. Each AES key is 32 bytes = 256 bits, fits comfortably under
        # any modulus >= ~280 bits.
        k_cover_int = int.from_bytes(k_cover, "big")
        k_hidden_int = int.from_bytes(k_hidden, "big")
        anamorphic_ct = self._ram.AnamorphicEncrypt(
            self._peer_aPK, k_cover_int, k_hidden_int, y0=y0, y1=y1,
        )

        return _serialize(anamorphic_ct, cover_blob, hidden_blob)

    # ---- Decryption ----

    def decrypt_pair_msg(self, ciphertext) -> tuple[str, str]:
        """Decrypt a regular WhisperMessage. Returns (cover, hidden)."""
        # The parent's decryptMsg calls our getPlaintext, which stashes the
        # pair on self._last_decrypted.
        self.decryptMsg(ciphertext)
        result = self._last_decrypted
        self._last_decrypted = None
        if result is None:
            raise RuntimeError("decrypt did not produce a pair")
        return result

    def decrypt_pair_pkmsg(self, ciphertext) -> tuple[str, str]:
        """Decrypt a PreKeyWhisperMessage. Returns (cover, hidden)."""
        self.decryptPkmsg(ciphertext)
        result = self._last_decrypted
        self._last_decrypted = None
        if result is None:
            raise RuntimeError("decrypt did not produce a pair")
        return result

    def getPlaintext(self, version, messageKeys, cipherText):
        """Override: decrypt the anamorphic blob, stash (cover, hidden) pair.
        Returns plaintext bytes (cover) for compatibility with the parent's
        return path."""
        anamorphic_ct, cover_blob, hidden_blob = _deserialize(bytes(cipherText))

        # The receiver knows their own keys; bit lengths come from them, not
        # from the peer's aPK (which the receiver may not even hold).
        sk0 = self._my_aSK
        sk1 = self._my_dkey["sk1"] if isinstance(self._my_dkey, dict) else self._my_dkey

        k_cover_int = self._ram.NormalDecrypt(sk0, anamorphic_ct)
        k_hidden_int = self._ram.DoubleDecrypt(self._my_dkey, anamorphic_ct)
        k_cover = k_cover_int.to_bytes(_AES_KEY_BYTES, "big")
        k_hidden = k_hidden_int.to_bytes(_AES_KEY_BYTES, "big")

        # Re-derive nonces from the message IV using the receiver's own key
        # bit-lengths (which equal the sender's view of pk0.p / pk1.p, since
        # the sender used this user's own aPK to encrypt).
        _, _, nonce_cover, nonce_hidden, _, _ = _derive_inner_secrets(
            messageKeys.getIv(),
            sk0["p"].bit_length(), sk1["p"].bit_length(),
        )

        cover_bytes = AESGCM(k_cover).decrypt(nonce_cover, cover_blob, None)
        hidden_bytes = AESGCM(k_hidden).decrypt(nonce_hidden, hidden_blob, None)

        cover = cover_bytes.decode("utf-8")
        hidden = hidden_bytes.decode("utf-8")
        self._last_decrypted = (cover, hidden)
        return cover_bytes