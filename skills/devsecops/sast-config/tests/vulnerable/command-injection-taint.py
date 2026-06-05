from flask import request
import subprocess


def export_report():
    report_id = request.args["id"]
    subprocess.run(f"report-cli --id {report_id}", shell=True, check=True)
