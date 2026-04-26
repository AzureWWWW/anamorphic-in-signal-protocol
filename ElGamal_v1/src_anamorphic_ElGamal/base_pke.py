from ElGamal_v1.src_anamorphic_ElGamal.utils import pow_mod, generate_prime, get_random_int
from Crypto.Util import number

LENGTH_PREFIX_BYTES = 2  # supports messages up to 65535 bytes


def _bytes_to_int(msg: bytes, p: int) -> int:
    """Encode bytes as a length-prefixed integer < p. Reversible."""
    if len(msg) > 2**(8 * LENGTH_PREFIX_BYTES) - 1:
        raise ValueError(f"message too long for {LENGTH_PREFIX_BYTES}-byte length prefix")
    framed = len(msg).to_bytes(LENGTH_PREFIX_BYTES, 'big') + msg
    n = int.from_bytes(framed, 'big')
    if n >= p:
        max_bytes = (p.bit_length() - 1) // 8 - LENGTH_PREFIX_BYTES
        raise ValueError(
            f"message too long: {len(msg)} bytes produces a {n.bit_length()}-bit "
            f"integer but modulus is only {p.bit_length()} bits. "
            f"Max payload for this key: {max_bytes} bytes."
        )
    return n


def _int_to_bytes(n: int) -> bytes:
    """Recover the original bytes from a length-prefixed integer."""
    if n == 0:
        return b""
    raw = n.to_bytes((n.bit_length() + 7) // 8, 'big')
    # int.to_bytes drops leading zero bytes; pad to recover the length prefix
    while True:
        if len(raw) < LENGTH_PREFIX_BYTES:
            raw = b"\x00" + raw
            continue
        declared = int.from_bytes(raw[:LENGTH_PREFIX_BYTES], 'big')
        expected_total = LENGTH_PREFIX_BYTES + declared
        if len(raw) == expected_total:
            return raw[LENGTH_PREFIX_BYTES:]
        if len(raw) > expected_total:
            raise ValueError("decode length mismatch — ciphertext corrupt?")
        raw = b"\x00" + raw


class ElGamalPKE:

    def __init__(self):
        pass

    def KeyGen(self, lambda_bits):
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

    def Encrypt(self, PK, message, randomness=None):
        """Encrypt a string message. Returns a ciphertext dict."""
        p = PK['p']
        g = PK['g']
        h = PK['h']

        if not isinstance(message, str):
            raise TypeError(f"message must be str, got {type(message).__name__}")

        # str -> UTF-8 bytes -> length-prefixed int
        message_int = _bytes_to_int(message.encode('utf-8'), p)

        if randomness is None:
            y = get_random_int(2, p - 2)
        else:
            y = randomness
        
        c1 = pow_mod(g, y, p)
        
        s = pow_mod(h, y, p)
        
        c2 = (message_int * s) % p
        
        ciphertext = {'c1': c1, 'c2': c2, 'y_used': y}
        return ciphertext

    def Decrypt(self, SK, ciphertext) -> str:
        """Decrypt to a string. Assumes the plaintext was valid UTF-8."""
        p = SK['p']
        x = SK['x']
        
        c1 = ciphertext['c1']
        c2 = ciphertext['c2']
        
        s = pow_mod(c1, x, p)
        
        s_inv = number.inverse(s, p)
        
        message_int = (c2 * s_inv) % p
        
        # int -> length-prefixed bytes -> UTF-8 str
        return _int_to_bytes(message_int).decode('utf-8')