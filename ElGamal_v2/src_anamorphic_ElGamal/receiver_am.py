from ElGamal_v2.src_anamorphic_ElGamal.base_pke import ElGamalPKE
from ElGamal_v2.src_anamorphic_ElGamal.utils import get_random_int


# 32-byte placeholder; size matches what a Fiat-Shamir-compiled NIZK proof
# would produce. Not verified anywhere; reserved field on the wire.
PLACEHOLDER_PI = b"\x00" * 32


class ReceiverAnamorphicEncryption:

    def __init__(self):
        self.pke = ElGamalPKE()

    def AnamorphicKeyGen(self, lambda_bits):
        pk0, sk0 = self.pke.KeyGen(lambda_bits)
        pk1, sk1 = self.pke.KeyGen(lambda_bits)
        aPK = {'pk0': pk0, 'pk1': pk1}
        aSK = sk0
        dkey = {'sk1': sk1}
        return aPK, aSK, dkey

    def AnamorphicEncrypt(self, aPK, m0: int, m1: int,
                          y0: int = None, y1: int = None) -> dict:
        """Encrypt cover m0 (under pk0) and hidden m1 (under pk1).

        m0 and m1 must be integers in [0, p) for their respective moduli.
        y0, y1 are optional explicit ElGamal exponents — the AEAD layer
        passes ratchet-derived values so encryption is forward-secure.
        Without them, fresh randomness is drawn per call.
        """
        pk0 = aPK['pk0']
        pk1 = aPK['pk1']

        if y0 is None:
            y0 = get_random_int(2, pk0['p'] - 2)
        if y1 is None:
            y1 = get_random_int(2, pk1['p'] - 2)

        ct0 = self.pke.EncryptInt(pk0, m0, randomness=y0)
        ct1 = self.pke.EncryptInt(pk1, m1, randomness=y1)
        return {'ct0': ct0, 'ct1': ct1, 'pi': PLACEHOLDER_PI}

    def NormalDecrypt(self, aSK, anamorphic_ciphertext) -> int:
        """Decrypt the cover (m0) using the normal secret key. Returns int."""
        return self.pke.DecryptInt(aSK, anamorphic_ciphertext['ct0'])

    def DoubleDecrypt(self, dkey, anamorphic_ciphertext) -> int:
        """Decrypt the hidden (m1) using the dual key. Returns int."""
        sk1 = dkey['sk1']
        return self.pke.DecryptInt(sk1, anamorphic_ciphertext['ct1'])