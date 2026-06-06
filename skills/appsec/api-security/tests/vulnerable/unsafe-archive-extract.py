"""Vulnerable fixture: archive extraction lacks bounds and path checks."""

import zipfile

from flask import Flask, request


app = Flask(__name__)


@app.post("/api/import")
def import_zip():
    archive = zipfile.ZipFile(request.files["archive"])
    archive.extractall("/srv/imports")
    return {"imported": len(archive.infolist())}


# Expected review outcome: High because extraction has no compression ratio,
# entry count, nesting depth, canonical path, or isolated workspace controls.
