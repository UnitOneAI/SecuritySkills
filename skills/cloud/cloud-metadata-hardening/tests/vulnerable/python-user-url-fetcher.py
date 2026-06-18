from flask import Flask, request
import requests

app = Flask(__name__)


@app.get("/preview")
def preview():
    url = request.args["url"]
    response = requests.get(url, timeout=5)
    return response.text[:500]
