import hashlib
import hmac
import os
import struct
import time

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .config import (
    GROUP_SALT,
    LOGIN_CODE_DIGITS,
    LOGIN_CODE_PERIOD,
    PBKDF2_ITERATIONS,
)


def derive_group_key(group_code: str) -> bytes:
    return hashlib.pbkdf2_hmac(
        "sha256",
        group_code.encode("utf-8"),
        GROUP_SALT,
        PBKDF2_ITERATIONS,
        32,
    )


def group_key_hash(key: bytes) -> str:
    return hashlib.sha256(key).hexdigest()


def generate_ed25519_private() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


def ed_private_to_bytes(sk: Ed25519PrivateKey) -> bytes:
    return sk.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )


def ed_public_to_bytes(pk: Ed25519PublicKey) -> bytes:
    return pk.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def ed_private_from_bytes(raw: bytes) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(raw)


def ed_public_from_bytes(raw: bytes) -> Ed25519PublicKey:
    return Ed25519PublicKey.from_public_bytes(raw)


def sign_bytes(sk: Ed25519PrivateKey, data: bytes) -> bytes:
    return sk.sign(data)


def verify_bytes(pk: Ed25519PublicKey, sig: bytes, data: bytes) -> bool:
    try:
        pk.verify(sig, data)
        return True
    except InvalidSignature:
        return False


def encrypt_aes(key: bytes, plaintext: bytes, aad: bytes = b""):
    nonce = os.urandom(12)
    ct = AESGCM(key).encrypt(nonce, plaintext, aad)
    return nonce, ct


def decrypt_aes(key: bytes, nonce: bytes, ct: bytes, aad: bytes = b"") -> bytes:
    return AESGCM(key).decrypt(nonce, ct, aad)


def generate_totp_secret() -> bytes:
    return os.urandom(20)


def compute_totp(secret: bytes, offset: int = 0) -> str:
    counter = int(time.time() // LOGIN_CODE_PERIOD) + offset
    msg = struct.pack(">Q", counter)
    digest = hmac.new(secret, msg, hashlib.sha256).digest()
    off = digest[-1] & 0x0F
    code = (
        struct.unpack(">I", digest[off:off + 4])[0] & 0x7FFFFFFF
    ) % (10 ** LOGIN_CODE_DIGITS)
    return f"{code:0{LOGIN_CODE_DIGITS}d}"


def verify_totp(secret: bytes, code: str) -> bool:
    for offset in (0, -1):
        if hmac.compare_digest(compute_totp(secret, offset), code):
            return True
    return False


def totp_remaining() -> int:
    return LOGIN_CODE_PERIOD - int(time.time() % LOGIN_CODE_PERIOD)


def code_tag(code: str) -> str:
    return hashlib.sha256(code.encode("utf-8")).hexdigest()[:16]