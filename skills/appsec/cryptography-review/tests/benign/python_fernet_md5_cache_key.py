import hashlib
from cryptography.fernet import Fernet


def encrypt_message(message: bytes, key: bytes) -> bytes:
    return Fernet(key).encrypt(message)


def cache_key(template_name: str, locale: str) -> str:
    digest = hashlib.md5(f"{template_name}:{locale}".encode(), usedforsecurity=False)
    return f"rendered:{digest.hexdigest()}"
