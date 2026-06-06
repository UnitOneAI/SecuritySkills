# Vulnerable: archive import extracts untrusted entries without bounds

This fixture should trigger API4:2023 and API8:2023 concerns.

```python
import zipfile
from flask import request

@app.post('/api/import')
def import_zip():
    archive = zipfile.ZipFile(request.files['archive'])
    archive.extractall('/srv/imports')
    return {'imported': len(archive.infolist())}
```

Expected findings:

- No compressed/uncompressed size ratio or total extracted size limit.
- No entry count, nesting depth, or extraction timeout.
- No canonical path check to keep entries inside the workspace.
- No rejection of absolute paths, `..` traversal, symlinks, device entries, or overwrite attempts.
