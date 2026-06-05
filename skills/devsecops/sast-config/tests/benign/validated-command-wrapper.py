from flask import request
import subprocess


def validate_report_id(value: str) -> str:
    if not value.isdecimal():
        raise ValueError("invalid report id")
    return value


def export_report():
    report_id = validate_report_id(request.args["id"])
    subprocess.run(["report-cli", "--id", report_id], check=True)
