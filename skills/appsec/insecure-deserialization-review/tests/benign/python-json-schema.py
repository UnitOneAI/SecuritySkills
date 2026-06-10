import json
from dataclasses import dataclass
from flask import Flask, request

app = Flask(__name__)


@dataclass(frozen=True)
class ProfileImport:
    display_name: str
    timezone: str


@app.post("/import-profile")
def import_profile():
    data = json.loads(request.get_data())
    profile = ProfileImport(
        display_name=validate_string(data["display_name"], 80),
        timezone=validate_string(data["timezone"], 64),
    )
    save_profile(profile)
    return ("", 204)


def validate_string(value, max_length):
    if not isinstance(value, str) or not value or len(value) > max_length:
        raise ValueError("invalid field")
    return value


def save_profile(profile):
    return profile
