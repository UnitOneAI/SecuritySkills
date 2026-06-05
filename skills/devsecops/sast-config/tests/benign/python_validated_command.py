"""True-negative fixture: validated input uses an argument array, not a shell."""

import re
import subprocess
from flask import request


REPORT_ID_PATTERN = re.compile(r"^[0-9]{1,12}$")


def validate_report_id(value):
    if not REPORT_ID_PATTERN.fullmatch(value):
        raise ValueError("report id must be numeric")
    return value


def export_report():
    report_id = validate_report_id(request.args["id"])
    return subprocess.run(["report-cli", "--id", report_id], check=True)
