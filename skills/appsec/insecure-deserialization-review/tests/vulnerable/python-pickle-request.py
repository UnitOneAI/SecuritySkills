import pickle
from flask import Flask, request

app = Flask(__name__)


@app.post("/import-profile")
def import_profile():
    profile = pickle.loads(request.get_data())
    save_profile(profile)
    return ("", 204)


def save_profile(profile):
    return profile
