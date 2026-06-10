import hashlib
import hmac
import os
import time
from flask import Flask, request

app = Flask(__name__)
seen_events = set()


@app.post("/webhooks/idp")
def idp_webhook():
    raw = request.get_data(cache=False)
    timestamp = request.headers.get("X-Provider-Timestamp", "")
    event_id = request.headers.get("X-Provider-Event-Id", "")
    signature = request.headers.get("X-Provider-Signature", "")

    if not is_fresh(timestamp, 300) or not event_id or event_id in seen_events:
        return ("bad delivery", 401)

    signed_payload = timestamp.encode() + b"." + raw
    expected = hmac.new(
        os.environ["WEBHOOK_SECRET"].encode(),
        signed_payload,
        hashlib.sha256,
    ).hexdigest()

    if not hmac.compare_digest(signature, expected):
        return ("bad signature", 401)

    seen_events.add(event_id)
    event = request.get_json()
    enable_user(event["user_id"])
    return ("", 204)


def is_fresh(timestamp, tolerance_seconds):
    try:
        sent_at = int(timestamp)
    except ValueError:
        return False
    return abs(time.time() - sent_at) <= tolerance_seconds


def enable_user(user_id):
    return user_id
