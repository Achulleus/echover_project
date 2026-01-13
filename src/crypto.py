"""
Echover cryptographic primitives:

1) Symmetric encryption: AES in CTR mode
2) Integrity/authentication: HMAC-SHA256
3) Authenticated encryption composition: Encrypt-then-MAC (EtM)
4) Public-key crypto: RSA
   - Encryption: c = m^e mod N
   - Signature:  s = H(m)^d mod N
"""

from __future__ import annotations

import base64
from dataclasses import dataclass
from typing import Tuple

from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes


# -----------------
# Base64 helpers
# -----------------
def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))


# -----------------
# Randomness
# -----------------
def random_bytes(n: int) -> bytes:
    return get_random_bytes(n)


def random_group_key() -> bytes:
    # 32 bytes -> AES-256
    return random_bytes(32)


# -----------------
# Hash / KDF
# -----------------
def sha256(data: bytes) -> bytes:
    return SHA256.new(data).digest()


def derive_enc_mac_keys(group_key: bytes) -> Tuple[bytes, bytes]:
    if len(group_key) != 32:
        raise ValueError("group_key must be 32 bytes")
    k_enc = sha256(b"ENC|" + group_key)
    k_mac = sha256(b"MAC|" + group_key)
    return k_enc, k_mac


# -----------------
# AES-CTR + HMAC
# -----------------
@dataclass
class CtrParams:
    nonce_prefix: bytes  # 8 bytes
    counter: int         # 64-bit counter value

    def counter_bytes(self) -> bytes:
        return int(self.counter).to_bytes(8, "big")


def aes_ctr_encrypt(k_enc: bytes, params: CtrParams, plaintext: bytes) -> bytes:
    if len(k_enc) != 32:
        raise ValueError("AES-256 requires 32-byte key")
    if len(params.nonce_prefix) != 8:
        raise ValueError("CTR nonce_prefix must be 8 bytes")
    cipher = AES.new(k_enc, AES.MODE_CTR, nonce=params.nonce_prefix, initial_value=params.counter)
    return cipher.encrypt(plaintext)


def aes_ctr_decrypt(k_enc: bytes, params: CtrParams, ciphertext: bytes) -> bytes:
    if len(k_enc) != 32:
        raise ValueError("AES-256 requires 32-byte key")
    if len(params.nonce_prefix) != 8:
        raise ValueError("CTR nonce_prefix must be 8 bytes")
    cipher = AES.new(k_enc, AES.MODE_CTR, nonce=params.nonce_prefix, initial_value=params.counter)
    return cipher.decrypt(ciphertext)


def hmac_sha256(k_mac: bytes, data: bytes) -> bytes:
    h = HMAC.new(k_mac, digestmod=SHA256)
    h.update(data)
    return h.digest()


def hmac_verify(k_mac: bytes, data: bytes, tag: bytes) -> bool:
    try:
        h = HMAC.new(k_mac, digestmod=SHA256)
        h.update(data)
        h.verify(tag)
        return True
    except Exception:
        return False


def group_msg_mac_data(group_id: str, epoch: int, sender: str, params: CtrParams, ciphertext: bytes) -> bytes:
    return (
        b"GRPMSG|"
        + group_id.encode("utf-8")
        + b"|"
        + str(epoch).encode("ascii")
        + b"|"
        + sender.encode("utf-8")
        + b"|"
        + params.nonce_prefix
        + b"|"
        + params.counter_bytes()
        + b"|"
        + ciphertext
    )


def etm_encrypt(group_key: bytes, group_id: str, epoch: int, sender: str, params: CtrParams, plaintext: bytes) -> Tuple[bytes, bytes]:
    k_enc, k_mac = derive_enc_mac_keys(group_key)
    ct = aes_ctr_encrypt(k_enc, params, plaintext)
    mac_data = group_msg_mac_data(group_id, epoch, sender, params, ct)
    tag = hmac_sha256(k_mac, mac_data)
    return ct, tag


def etm_decrypt(group_key: bytes, group_id: str, epoch: int, sender: str, params: CtrParams, ciphertext: bytes, tag: bytes) -> bytes:
    k_enc, k_mac = derive_enc_mac_keys(group_key)
    mac_data = group_msg_mac_data(group_id, epoch, sender, params, ciphertext)
    if not hmac_verify(k_mac, mac_data, tag):
        raise ValueError("HMAC verification failed")
    return aes_ctr_decrypt(k_enc, params, ciphertext)


# -----------------
# Password-based wrapping
# -----------------
def password_master_key(password: str, salt: bytes) -> bytes:
    return sha256(password.encode("utf-8") + b"|" + salt)


def wrap_blob_with_password(password: str, blob: bytes, aad: bytes = b"PRIVKEY") -> dict:
    salt = random_bytes(16)
    master = password_master_key(password, salt)
    k_enc, k_mac = derive_enc_mac_keys(master)

    params = CtrParams(nonce_prefix=random_bytes(8), counter=int.from_bytes(random_bytes(8), "big"))
    ct = aes_ctr_encrypt(k_enc, params, blob)
    mac_data = b"BLOB|" + aad + b"|" + params.nonce_prefix + b"|" + params.counter_bytes() + b"|" + ct
    tag = hmac_sha256(k_mac, mac_data)
    return {
        "v": 1,
        "salt": b64e(salt),
        "nonce": b64e(params.nonce_prefix),
        "ctr": params.counter,
        "ct": b64e(ct),
        "tag": b64e(tag),
        "aad": b64e(aad),
    }


def unwrap_blob_with_password(password: str, wrapped: dict) -> bytes:
    if int(wrapped.get("v", 0)) != 1:
        raise ValueError("Unsupported wrapped blob version")
    salt = b64d(wrapped["salt"])
    nonce = b64d(wrapped["nonce"])
    ctr = int(wrapped["ctr"])
    ct = b64d(wrapped["ct"])
    tag = b64d(wrapped["tag"])
    aad = b64d(wrapped.get("aad", b64e(b"PRIVKEY")))

    master = password_master_key(password, salt)
    k_enc, k_mac = derive_enc_mac_keys(master)
    params = CtrParams(nonce_prefix=nonce, counter=ctr)
    mac_data = b"BLOB|" + aad + b"|" + params.nonce_prefix + b"|" + params.counter_bytes() + b"|" + ct
    if not hmac_verify(k_mac, mac_data, tag):
        raise ValueError("Wrong password or corrupted key file")
    return aes_ctr_decrypt(k_enc, params, ct)


# -----------------
# RSA
# -----------------
def generate_rsa_private_key(bits: int = 2048) -> RSA.RsaKey:
    return RSA.generate(bits)


def serialize_public_key_pem(priv: RSA.RsaKey) -> bytes:
    return priv.public_key().export_key(format="PEM")


def load_public_key_pem(pem: bytes) -> RSA.RsaKey:
    return RSA.import_key(pem)


def export_private_key_der(priv: RSA.RsaKey) -> bytes:
    return priv.export_key(format="DER", pkcs=8)


def import_private_key_der(der: bytes) -> RSA.RsaKey:
    return RSA.import_key(der)


def rsa_encrypt(pub_pem: bytes, plaintext: bytes) -> bytes:
    pub = load_public_key_pem(pub_pem)
    n = int(pub.n)
    e = int(pub.e)
    m = int.from_bytes(plaintext, "big")
    if m < 0 or m >= n:
        raise ValueError("Plaintext integer out of range for RSA modulus")
    c = pow(m, e, n)
    k = (pub.size_in_bits() + 7) // 8
    return int(c).to_bytes(k, "big")


def rsa_decrypt(priv: RSA.RsaKey, ciphertext: bytes, out_len: int) -> bytes:
    n = int(priv.n)
    d = int(priv.d)
    c = int.from_bytes(ciphertext, "big")
    if c < 0 or c >= n:
        raise ValueError("Ciphertext integer out of range for RSA modulus")
    m = pow(c, d, n)
    return int(m).to_bytes(out_len, "big")


def rsa_sign(priv: RSA.RsaKey, data: bytes) -> bytes:
    h = sha256(data)
    h_int = int.from_bytes(h, "big")
    s = pow(h_int, int(priv.d), int(priv.n))
    k = (priv.size_in_bits() + 7) // 8
    return int(s).to_bytes(k, "big")


def rsa_verify(pub_pem: bytes, signature: bytes, data: bytes) -> bool:
    pub = load_public_key_pem(pub_pem)
    h = sha256(data)
    h_int = int.from_bytes(h, "big")
    s = int.from_bytes(signature, "big")
    v = pow(s, int(pub.e), int(pub.n))
    return int(v) == int(h_int)


# -----------------
# Signature framing helpers
# -----------------
def key_update_sig_data(group_id: str, epoch: int, enc_key: bytes) -> bytes:
    return b"KEYUPDATE|" + group_id.encode("utf-8") + b"|" + str(epoch).encode("ascii") + b"|" + enc_key


def group_msg_sig_data(group_id: str, epoch: int, sender: str, params: CtrParams, ciphertext: bytes, tag: bytes) -> bytes:
    return (
        b"GROUPMSG|"
        + group_id.encode("utf-8")
        + b"|"
        + str(epoch).encode("ascii")
        + b"|"
        + sender.encode("utf-8")
        + b"|"
        + params.nonce_prefix
        + b"|"
        + params.counter_bytes()
        + b"|"
        + ciphertext
        + b"|"
        + tag
    )
