"""
bundle_codec.py — Serialize/deserialize python-axolotl PreKeyBundle to JSON-safe dicts.

PreKeyBundle objects contain ECPublicKey/IdentityKey instances that don't
serialize directly to JSON. We pull out the raw wire bytes (from .serialize()
on each key) as hex strings, then reconstruct the objects on the other side.
"""

import os
os.environ.setdefault("PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION", "python")

from axolotl.state.prekeybundle import PreKeyBundle
from axolotl.ecc.curve import Curve
from axolotl.identitykey import IdentityKey


def bundle_to_dict(bundle: PreKeyBundle) -> dict:
    return {
        "registration_id": bundle.getRegistrationId(),
        "device_id": bundle.getDeviceId(),
        "pre_key_id": bundle.getPreKeyId(),
        "pre_key_public": bundle.getPreKey().serialize().hex(),
        "signed_pre_key_id": bundle.getSignedPreKeyId(),
        "signed_pre_key_public": bundle.getSignedPreKey().serialize().hex(),
        "signed_pre_key_signature": bundle.getSignedPreKeySignature().hex(),
        "identity_key": bundle.getIdentityKey().serialize().hex(),
    }


def bundle_from_dict(d: dict) -> PreKeyBundle:
    pre_key_bytes = bytes.fromhex(d["pre_key_public"])
    signed_pre_key_bytes = bytes.fromhex(d["signed_pre_key_public"])
    identity_key_bytes = bytes.fromhex(d["identity_key"])

    pre_key_pub = Curve.decodePoint(pre_key_bytes, 0)
    signed_pre_key_pub = Curve.decodePoint(signed_pre_key_bytes, 0)
    identity_key = IdentityKey(identity_key_bytes, 0)

    return PreKeyBundle(
        d["registration_id"],
        d["device_id"],
        d["pre_key_id"],
        pre_key_pub,
        d["signed_pre_key_id"],
        signed_pre_key_pub,
        bytes.fromhex(d["signed_pre_key_signature"]),
        identity_key,
    )


# ---- Anamorphic aPK <-> dict ----
# aPK contains ElGamal public keys which are already dicts of Python ints.
# We just need to encode the ints as hex strings for JSON.

def aPK_to_dict(aPK: dict) -> dict:
    def pack_pk(pk):
        return {"p": hex(pk["p"]), "g": hex(pk["g"]), "h": hex(pk["h"])}
    return {
        "pk0": pack_pk(aPK["pk0"]),
        "pk1": pack_pk(aPK["pk1"]),
    }


def aPK_from_dict(d: dict) -> dict:
    def unpack_pk(pk):
        return {"p": int(pk["p"], 16), "g": int(pk["g"], 16), "h": int(pk["h"], 16)}
    return {
        "pk0": unpack_pk(d["pk0"]),
        "pk1": unpack_pk(d["pk1"]),
    }