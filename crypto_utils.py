#crypto_utils.py

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA512, SHA256
from Crypto.Signature import pkcs1_15
from Crypto.Random import get_random_bytes



def load_rsa_public_key(path: str) -> RSA.RsaKey:
    with open(path, 'rb') as f:
        return RSA.import_key(f.read())


def verify_signature(pub_key: RSA.RsaKey, message: bytes, signature: bytes) -> bool:
    """
    Attempt to verify an RSA signature against the message.
    Try SHA-512 first, then SHA-256 for compatibility with potential server settings.
    """
    for hash_algo in (SHA512, SHA256):
        h = hash_algo.new(message)
        try:
            pkcs1_15.new(pub_key).verify(h, signature)
            return True
        except (ValueError, TypeError):
            continue
    return False


def hash_code(code: str) -> bytes:
    return SHA512.new(code.encode()).digest()


def generate_master_iv() -> tuple[bytes, bytes]:
    data = get_random_bytes(32)
    return data[:16], data[16:]


def encrypt_master_key(km: bytes, iv: bytes, pub_key: RSA.RsaKey) -> bytes:
    cipher = PKCS1_OAEP.new(pub_key)
    return cipher.encrypt(km + iv)