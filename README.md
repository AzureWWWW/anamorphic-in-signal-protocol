# Anamorphic Messenger over Signal

A messaging system that combines Signal Protocol's transport security with
anamorphic encryption to provide a covert channel inside otherwise
ordinary-looking conversations. Each message carries a **cover** plaintext
(the plausible public message) and a **hidden** plaintext (the covert payload).
A coerced user who reveals the "normal" key can decrypt cover messages only;
the hidden channel requires a separate dual key that never leaves the device.

This repository contains two complete implementations of the integration.

## The two versions

There are two viable ways to wire anamorphic encryption into Signal. We built
both, in separate folders, so the trade-offs are visible.

### Version 1 — Hybrid wrapper

Anamorphic encryption is applied as an **outer wrapper** above Signal:

```
plaintext (cover, hidden)
   │
   ▼ AnamorphicEncrypt(peer_aPK, cover, hidden)   [our layer]
   │
   ▼ JSON-serialize -> bytes
   │
   ▼ Signal SessionCipher.encrypt   [unchanged]
   │   ├── AES-CBC encrypt with ratcheted message key
   │   └── HMAC-SHA256 over result
   │
   ▼ wire bytes
```

**Two encryptions per message** — anamorphic on the inside, Signal's normal
AEAD on the outside. python-axolotl is used unmodified.

### Version 2 — Replaced AEAD

Anamorphic encryption **replaces** Signal's AES-CBC inside `SessionCipher`:

```
plaintext (cover, hidden)
   │
   ▼ ratchet derives messageKey (cipher_key, mac_key, iv, counter)
   │
   ▼ HKDF(iv) -> (k_cover, k_hidden, nonce_cover, nonce_hidden, y0, y1)
   │
   ▼ AES-GCM(k_cover, cover) -> cover_blob
   ▼ AES-GCM(k_hidden, hidden) -> hidden_blob
   ▼ ElGamal-encrypt(pk0, k_cover_int, y0) -> ct0
   ▼ ElGamal-encrypt(pk1, k_hidden_int, y1) -> ct1
   │
   ▼ serialize -> ciphertextBody
   │
   ▼ HMAC-SHA256 over framed message   [Signal's MAC unchanged]
   │
   ▼ wire bytes
```

**One symmetric encryption per message** (AES-GCM). The HMAC, ratchet, X3DH,
protobuf framing all stay. Only `SessionCipher.getCiphertext` and
`getPlaintext` are overridden — the rest is inherited.

### Functional differences
 
| | v1 | v2 |
|---|---|---|
| Message length cap | ~61 bytes per slot at 512-bit ElGamal keys, due to the str-API's UTF-8 + length-prefix encoding | None — AES-GCM handles arbitrary length |
| Encryption layers per message | 2 (anamorphic AES-GCM inside, Signal AES-CBC outside) | 1 (anamorphic AES-GCM, replacing Signal's AES-CBC) |
| Anamorphic randomness | `os.urandom`, independent of Signal | Derived from ratchet IV via HKDF |
| python-axolotl modifications | None | Subclass of `SessionCipher` overriding two methods |

## Running

See `README-v1.md` for the v1 CLI walkthrough, and `README-v2.md` for v2
test execution.

### Dependencies
 
- Python 3.10+
- `python-axolotl==0.2.3` (the Python port of libsignal-protocol)
- `pycryptodome` (for `Crypto.Util.number`)
- `cryptography` (for AES-GCM and HKDF in v2)

 
```bash
pip install -r requirements.txt
```
## Running the app
 
Open three terminals. All commands run from the `anamorphic-in-signal-protocol/` directory.

### Terminal 1: the relay

For version 1:
```bash
python -m ElGamal_v1.CLI.relay
```

For version 2:
```bash
python -m ElGamal_v2.CLI.relay
```

You'll see:
```
HH:MM:SS relay relay listening on ('127.0.0.1', 5555)
```

The relay is now accepting connections. It'll log every register, publish,
fetch, and forward. Leave it running.

You can override the host/port:
```bash
python -m ElGamal_v1.CLI.relay --host 0.0.0.0 --port 8080
```

### Terminal 2: Alice

For version 1:
```bash
python -m ElGamal_v1.CLI.client alice
```

For version 2:
```bash
python -m ElGamal_v2.CLI.client alice
```

You'll see:
```
[connected to relay as 'alice']
[bundle published; you are now visible to others as 'alice']
[no other peers registered yet]
peer>
```

Alice has booted (registered + published her bundle). She's now visible in
the relay's directory and waiting for you to choose a peer.

### Terminal 3: Bob

For version 1:
```bash
python -m ElGamal_v1.CLI.client bob
```

For version 2:
```bash
python -m ElGamal_v2.CLI.client bob
```

Bob boots the same way:
```
[connected to relay as 'bob']
[bundle published; you are now visible to others as 'bob']
[available peers: alice]
peer>
```

Now Bob sees Alice in the directory.