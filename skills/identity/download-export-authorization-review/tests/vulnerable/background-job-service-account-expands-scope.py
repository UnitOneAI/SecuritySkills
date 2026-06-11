def enqueue_account_export(user, request, queue):
    # Vulnerable: the job records a report id but not the actor's authorized
    # tenant, row filter, field scope, or policy version.
    queue.push(
        "account-export",
        {
            "job_id": request["job_id"],
            "report_id": request["report_id"],
            "requested_by": user.id,
        },
    )


def run_account_export_job(job, db, object_store):
    # The worker runs with broad service credentials and expands report_id into
    # all matching accounts, including rows the requester may not view.
    report = db.reports.get(job["report_id"])
    rows = db.accounts.search(report.saved_query)
    csv_body = render_csv(rows, include_internal_fields=True)
    object_store.put(f"exports/{job['job_id']}.csv", csv_body)


def render_csv(rows, include_internal_fields=False):
    return "\n".join(str(row) for row in rows)
