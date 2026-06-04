import hmac
import json


def load_signed_profile(raw_body: bytes, signature: str, secret: bytes) -> dict:
    expected = hmac.digest(secret, raw_body, "sha256").hex()
    if not hmac.compare_digest(expected, signature):
        raise ValueError("invalid signature")

    profile = json.loads(raw_body)
    if not isinstance(profile, dict) or not isinstance(profile.get("display_name"), str):
        raise ValueError("invalid profile")
    return profile
