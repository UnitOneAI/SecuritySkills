import yaml
from flask import Flask, request

app = Flask(__name__)


@app.post("/jobs")
def create_job():
    job = yaml.load(request.data, Loader=yaml.Loader)
    enqueue_job(job)
    return ("", 202)


def enqueue_job(job):
    return job
