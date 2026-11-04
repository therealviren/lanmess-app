import base64
import hashlib
import hmac
import json
import os
import struct
import time

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .config import (
    GROUP_SALT,
    LOGIN_CODE_DIGITS,
    LOGIN_CODE_PERIOD,
    LOOKUP_SALT,
    PBKDF2_ITERATIONS,
)


def derive_group_key(group_code):
    return hashlib.pbkdf2_hmac(
        "sha256",
        group_code.encode("utf-8"),
        GROUP_SALT,
        PBKDF2_ITERATIONS,
        32,
    )


def group_key_hash(key):
    return hashlib.sha256(key).hexdigest()


def derive_lookup_key(group_key):
    return hmac.new(
        group_key, LOOKUP_SALT, hashlib.sha256
    ).digest()


def compute_name_hash(lookup_key, name):
    return hmac.new(
        lookup_key, name.encode("utf-8"), hashlib.sha256
    ).hexdigest()


def compute_secure_code_tag(lookup_key, code):
    return hmac.new(
        lookup_key, code.encode("utf-8"), hashlib.sha256
    ).hexdigest()[:16]


def encrypt_json(key, data, aad):
    plaintext = json.dumps(
        data, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")
    nonce = os.urandom(12)
    ct = AESGCM(key).encrypt(nonce, plaintext, aad)
    return base64.b64encode(nonce + ct).decode("ascii")


def decrypt_json(key, blob, aad):
    raw = base64.b64decode(blob)
    nonce = raw[:12]
    ct = raw[12:]
    plaintext = AESGCM(key).decrypt(nonce, ct, aad)
    return json.loads(plaintext.decode("utf-8"))


def generate_ed25519_private():
    return Ed25519PrivateKey.generate()


def ed_private_to_bytes(sk):
    return sk.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )


def ed_public_to_bytes(pk):
    return pk.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def ed_private_from_bytes(raw):
    return Ed25519PrivateKey.from_private_bytes(raw)


def ed_public_from_bytes(raw):
    return Ed25519PublicKey.from_public_bytes(raw)


def sign_bytes(sk, data):
    return sk.sign(data)


def verify_bytes(pk, sig, data):
    try:
        pk.verify(sig, data)
        return True
    except InvalidSignature:
        return False


def x25519_generate():
    return X25519PrivateKey.generate()


def x25519_private_to_bytes(sk):
    return sk.private_bytes_raw()


def x25519_public_to_bytes(pk):
    return pk.public_bytes_raw()


def x25519_private_from_bytes(raw):
    return X25519PrivateKey.from_private_bytes(raw)


def x25519_public_from_bytes(raw):
    return X25519PublicKey.from_public_bytes(raw)


def _pairwise_key(
    my_static_pub_raw,
    their_static_pub_raw,
    ephemeral_pub_raw,
    shared_secret,
):
    salt = (
        b"".join(sorted([my_static_pub_raw, their_static_pub_raw]))
        + ephemeral_pub_raw
    )
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=b"lanmess-msg-v1",
    )
    return hkdf.derive(shared_secret)


def pairwise_encrypt(
    my_static_sk, their_static_pub, plaintext, aad
):
    ephemeral_sk = X25519PrivateKey.generate()
    ephemeral_pub = ephemeral_sk.public_key()
    shared = ephemeral_sk.exchange(their_static_pub)
    my_pub_raw = my_static_sk.public_key().public_bytes_raw()
    their_pub_raw = their_static_pub.public_bytes_raw()
    eph_pub_raw = ephemeral_pub.public_bytes_raw()
    key = _pairwise_key(
        my_pub_raw, their_pub_raw, eph_pub_raw, shared
    )
    nonce = os.urandom(12)
    ct = AESGCM(key).encrypt(nonce, plaintext, aad)
    return eph_pub_raw, nonce, ct


def pairwise_decrypt(
    my_static_sk,
    my_static_pub,
    their_static_pub,
    ephemeral_pub_raw,
    nonce,
    ct,
    aad,
):
    ephemeral_pub = X25519PublicKey.from_public_bytes(
        ephemeral_pub_raw
    )
    shared = my_static_sk.exchange(ephemeral_pub)
    my_pub_raw = my_static_pub.public_bytes_raw()
    their_pub_raw = their_static_pub.public_bytes_raw()
    key = _pairwise_key(
        my_pub_raw, their_pub_raw, ephemeral_pub_raw, shared
    )
    return AESGCM(key).decrypt(nonce, ct, aad)


def generate_totp_secret():
    return os.urandom(20)


def compute_totp(secret, offset=0):
    counter = int(time.time() // LOGIN_CODE_PERIOD) + offset
    msg = struct.pack(">Q", counter)
    digest = hmac.new(secret, msg, hashlib.sha256).digest()
    off = digest[-1] & 0x0F
    code = (
        struct.unpack(">I", digest[off:off + 4])[0] & 0x7FFFFFFF
    ) % (10 ** LOGIN_CODE_DIGITS)
    return f"{code:0{LOGIN_CODE_DIGITS}d}"


def verify_totp(secret, code):
    for offset in (0, -1):
        if hmac.compare_digest(
            compute_totp(secret, offset), code
        ):
            return True
    return False


def totp_remaining():
    return LOGIN_CODE_PERIOD - int(
        time.time() % LOGIN_CODE_PERIOD
    )