import hashlib
import hmac
import os
from flask import Flask, request

app = Flask(__name__)


@app.post("/webhooks/idp")
def idp_webhook():
    raw = request.get_data(cache=False)
    signature = request.headers.get("X-Provider-Signature", "")
    expected = hmac.new(
        os.environ["WEBHOOK_SECRET"].encode(),
        raw,
        hashlib.sha256,
    ).hexdigest()

    if not hmac.compare_digest(signature, expected):
        return ("bad signature", 401)

    event = request.get_json()
    enable_user(event["user_id"])
    return ("", 204)


def enable_user(user_id):
    return user_id
