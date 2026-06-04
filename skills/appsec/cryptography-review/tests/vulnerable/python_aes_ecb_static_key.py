from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

KEY = b"0123456789abcdef"


def encrypt_profile(profile_json: bytes) -> bytes:
    cipher = AES.new(KEY, AES.MODE_ECB)
    return cipher.encrypt(pad(profile_json, AES.block_size))
