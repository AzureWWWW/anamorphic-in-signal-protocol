"""base_pke.py — ElGamal public-key encryption, integer-mode only.

In v2, ElGamal is used as a primitive that the AEAD layer drives. It encrypts
short integers (specifically 256-bit AES keys cast as ints) under a public
key. All higher-level concerns — message framing, serialization, AES-GCM bulk
encryption, ratchet-derived randomness — live above this module in
anamorphic_session_cipher.py.

API:
  ElGamalPKE.KeyGen(bits)           -> (PK, SK)
  ElGamalPKE.EncryptInt(PK, m_int)  -> {c1, c2, y_used}
  ElGamalPKE.DecryptInt(SK, ct)     -> m_int
"""

from Crypto.Util import number

from ElGamal_v2.src_anamorphic_ElGamal.utils import pow_mod, generate_prime, get_random_int


class ElGamalPKE:

    def KeyGen(self, lambda_bits):
        """Generate (PK, SK) for a fresh ElGamal keypair over Z_p^*."""
        p = generate_prime(lambda_bits)
        g = 2
        while True:
            if g < p - 1:
                break
            g = get_random_int(2, p - 1)

        x = get_random_int(2, p - 2)
        h = pow_mod(g, x, p)

        PK = {'p': p, 'g': g, 'h': h}
        SK = {'x': x, 'p': p}
        return PK, SK

    def EncryptInt(self, PK, m: int, randomness=None) -> dict:
        """Encrypt an integer m in [0, p). Returns {c1, c2, y_used}.

        randomness, if provided, is the ElGamal exponent y. The AEAD layer
        passes a y derived from Signal's ratchet so the encryption is
        deterministic in ratchet state and inherits forward secrecy.
        """
        p = PK['p']
        g = PK['g']
        h = PK['h']

        if not isinstance(m, int):
            raise TypeError(f"m must be int, got {type(m).__name__}")
        if m < 0 or m >= p:
            raise ValueError(
                f"m must satisfy 0 <= m < p; got bit-length {m.bit_length()}, "
                f"p has {p.bit_length()} bits"
            )

        y = randomness if randomness is not None else get_random_int(2, p - 2)
        c1 = pow_mod(g, y, p)
        s = pow_mod(h, y, p)
        c2 = (m * s) % p
        return {'c1': c1, 'c2': c2, 'y_used': y}

    def DecryptInt(self, SK, ciphertext) -> int:
        """Decrypt to an integer in [0, p)."""
        p = SK['p']
        x = SK['x']
        c1 = ciphertext['c1']
        c2 = ciphertext['c2']
        s = pow_mod(c1, x, p)
        s_inv = number.inverse(s, p)
        return (c2 * s_inv) % p