# Benign: scoped export download with short-lived signed URL

```python
@app.get('/api/v1/reports/export/<job_id>/download')
@require_auth
def download_export(job_id):
    job = ExportJob.query.filter_by(
        id=job_id,
        tenant_id=current_user.tenant_id,
        requested_by=current_user.id,
    ).one_or_none()
    if not job or not current_user.can("report.export.download"):
        return jsonify({"error": "Not found"}), 404

    audit_log.record(
        actor=current_user.id,
        tenant=current_user.tenant_id,
        job_id=job.id,
        object_count=job.object_count,
        bytes=job.byte_size,
    )
    return redirect(storage.presign(job.object_key, expires_in=300))
```

Expected skill behavior:

- Do not flag the workflow as BOLA when job ownership, tenant scope, function permission, private storage, short TTL, and audit evidence are present.
- Continue checking row, byte, concurrency, retention, and cleanup controls for API4 coverage.
