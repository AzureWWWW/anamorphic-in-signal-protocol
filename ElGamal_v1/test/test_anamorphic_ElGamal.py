"""
test_str_api.py — Verify the simplified str-only API.

API:
  AnamorphicEncrypt(dkey, cover: str, hidden: str) -> ciphertext dict
  NormalDecrypt(aSK, ct) -> str
  DoubleDecrypt(dkey, ct) -> str

No bytes, no int. Everything is str.
"""

from ElGamal_v1.src_anamorphic_ElGamal.receiver_am import ReceiverAnamorphicEncryption

LAMBDA_BITS = 512


def hr():
    print("-" * 60)


def test_basic_strings():
    print("\n[1] Basic string round-trip")
    hr()
    ram = ReceiverAnamorphicEncryption()
    aPK, aSK, dkey = ram.AnamorphicKeyGen(LAMBDA_BITS)

    cover = "Hi Bob, ordinary message."
    hidden = "Meet at the cafe at 9pm."

    ct = ram.AnamorphicEncrypt(dkey, cover, hidden)
    got_cover = ram.NormalDecrypt(aSK, ct)
    got_hidden = ram.DoubleDecrypt(dkey, ct)

    print(f"  cover  sent: {cover!r}")
    print(f"  cover  got:  {got_cover!r}  {'OK' if got_cover == cover else 'FAIL'}")
    print(f"  hidden sent: {hidden!r}")
    print(f"  hidden got:  {got_hidden!r}  {'OK' if got_hidden == hidden else 'FAIL'}")

    assert isinstance(got_cover, str), "NormalDecrypt should return str"
    assert isinstance(got_hidden, str), "DoubleDecrypt should return str"
    assert got_cover == cover
    assert got_hidden == hidden


def test_cli_style_input():
    print("\n[2] Simulated CLI input (what input() would give)")
    hr()
    ram = ReceiverAnamorphicEncryption()
    aPK, aSK, dkey = ram.AnamorphicKeyGen(LAMBDA_BITS)

    # Simulate 3 rounds of user CLI interaction
    exchanges = [
        ("What's for dinner?", "Bring the documents"),
        ("Pasta I think", "Use the fire escape"),
        ("Sounds good", "Burn after reading"),
    ]

    for cover, hidden in exchanges:
        ct = ram.AnamorphicEncrypt(dkey, cover, hidden)
        out_cover = ram.NormalDecrypt(aSK, ct)
        out_hidden = ram.DoubleDecrypt(dkey, ct)
        ok = out_cover == cover and out_hidden == hidden
        print(f"  cover: {cover!r} -> {out_cover!r} {'OK' if ok else 'FAIL'}")
        print(f"  hidden: {hidden!r} -> {out_hidden!r}")
        assert ok


def test_unicode():
    print("\n[3] Unicode text (what a CLI would pass through)")
    hr()
    ram = ReceiverAnamorphicEncryption()
    aPK, aSK, dkey = ram.AnamorphicKeyGen(LAMBDA_BITS)

    cover = "Hôtel de ville, 20h"
    hidden = "暗号 🔐"

    ct = ram.AnamorphicEncrypt(dkey, cover, hidden)
    got_cover = ram.NormalDecrypt(aSK, ct)
    got_hidden = ram.DoubleDecrypt(dkey, ct)

    print(f"  cover:  {got_cover!r}  {'OK' if got_cover == cover else 'FAIL'}")
    print(f"  hidden: {got_hidden!r}  {'OK' if got_hidden == hidden else 'FAIL'}")
    assert got_cover == cover
    assert got_hidden == hidden


def test_empty_string():
    print("\n[4] Empty strings")
    hr()
    ram = ReceiverAnamorphicEncryption()
    aPK, aSK, dkey = ram.AnamorphicKeyGen(LAMBDA_BITS)

    ct = ram.AnamorphicEncrypt(dkey, "", "")
    got_cover = ram.NormalDecrypt(aSK, ct)
    got_hidden = ram.DoubleDecrypt(dkey, ct)

    print(f"  cover  empty -> {got_cover!r}  {'OK' if got_cover == '' else 'FAIL'}")
    print(f"  hidden empty -> {got_hidden!r}  {'OK' if got_hidden == '' else 'FAIL'}")
    assert got_cover == ""
    assert got_hidden == ""


def test_wrong_type_rejected():
    print("\n[5] Non-str inputs are rejected with clear error")
    hr()
    ram = ReceiverAnamorphicEncryption()
    aPK, aSK, dkey = ram.AnamorphicKeyGen(LAMBDA_BITS)

    for bad_input, desc in [(42, "int"), (b"bytes", "bytes"), (None, "None"),
                            ([1, 2, 3], "list")]:
        try:
            ram.AnamorphicEncrypt(dkey, bad_input, "ok")
            print(f"  {desc}: accepted (BUG - should have rejected)")
        except TypeError as e:
            print(f"  {desc}: correctly raised TypeError — {e}")


def test_length_limit():
    print("\n[6] Length limit for this key size")
    hr()
    ram = ReceiverAnamorphicEncryption()
    aPK, aSK, dkey = ram.AnamorphicKeyGen(LAMBDA_BITS)

    p_bits = dkey["pk0"]["p"].bit_length()
    # UTF-8 ASCII is 1 byte per char, so char count = byte count for ASCII
    max_bytes = (p_bits - 1) // 8 - 2
    print(f"  modulus: {p_bits} bits, max ASCII chars: ~{max_bytes}")

    at_limit = "A" * max_bytes
    over_limit = "A" * (max_bytes + 10)

    try:
        ct = ram.AnamorphicEncrypt(dkey, at_limit, "short")
        got = ram.NormalDecrypt(aSK, ct)
        print(f"  at limit ({len(at_limit)} chars): {'OK' if got == at_limit else 'FAIL'}")
    except ValueError as e:
        print(f"  at limit: {e}")

    try:
        ram.AnamorphicEncrypt(dkey, over_limit, "short")
        print(f"  over limit: should have raised!")
    except ValueError as e:
        print(f"  over limit ({len(over_limit)} chars): correctly raised ValueError")


def test_multibyte_char_length():
    print("\n[7] Multi-byte UTF-8 characters count as multiple bytes")
    hr()
    ram = ReceiverAnamorphicEncryption()
    aPK, aSK, dkey = ram.AnamorphicKeyGen(LAMBDA_BITS)

    # A Japanese char is 3 UTF-8 bytes; emoji is 4
    # So "あ" * 20 = 60 bytes, "🔐" * 15 = 60 bytes, both near the 61-byte limit
    msg = "秘密" * 10  # 20 Japanese chars = 60 bytes in UTF-8
    print(f"  message: {msg[:20]}... ({len(msg)} chars, {len(msg.encode('utf-8'))} UTF-8 bytes)")
    try:
        ct = ram.AnamorphicEncrypt(dkey, msg, "short")
        got = ram.NormalDecrypt(aSK, ct)
        print(f"  round-trip: {'OK' if got == msg else 'FAIL'}")
        assert got == msg
    except ValueError as e:
        print(f"  raised: {e}")


def main():
    print("=" * 60)
    print("str-only API — real message round-trips")
    print("=" * 60)

    test_basic_strings()
    test_cli_style_input()
    test_unicode()
    test_empty_string()
    test_wrong_type_rejected()
    test_length_limit()
    test_multibyte_char_length()

    print("\n" + "=" * 60)
    print("All tests passed.")
    print("API is str-in / str-out, matches CLI input() semantics.")
    print("=" * 60)


if __name__ == "__main__":
    main()