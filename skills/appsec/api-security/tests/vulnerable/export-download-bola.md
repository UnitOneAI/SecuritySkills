# Vulnerable: export download BOLA and long-lived signed URL

```python
@app.get('/api/v1/reports/export/<job_id>/download')
@require_auth
def download_export(job_id):
    # Any authenticated user who learns a job_id can receive a signed URL for
    # another tenant's export file. The URL is reusable for 24 hours.
    job = ExportJob.get(job_id)
    return redirect(storage.presign(job.object_key, expires_in=86400))
```

Expected skill behavior:

- Flag as API1:2023 Broken Object Level Authorization.
- Flag signed URL lifecycle weakness when sensitive exports are long-lived, reusable, or not revoked after authorization changes.
- Require export evidence for create, status, download, signed URL, storage isolation, cleanup, and audit phases.
