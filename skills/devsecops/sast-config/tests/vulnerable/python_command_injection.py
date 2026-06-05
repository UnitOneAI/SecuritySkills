"""True-positive fixture: user input reaches a shell command sink."""

import subprocess
from flask import request


def export_report():
    report_id = request.args["id"]
    command = f"report-cli --id {report_id}"
    return subprocess.run(command, shell=True, check=False)
