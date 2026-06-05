resource "google_service_account" "deploy" {
  account_id = "prod-deploy"
}

resource "google_service_account_iam_binding" "github_deploy" {
  service_account_id = google_service_account.deploy.name
  role               = "roles/iam.workloadIdentityUser"
  members = [
    "principalSet://iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/ci/attribute.repository/my-org/prod-deploy"
  ]

  condition {
    title       = "prod-main-only"
    description = "Only the production deploy workflow on main can impersonate this account."
    expression  = "assertion.repository == 'my-org/prod-deploy' && assertion.ref == 'refs/heads/main' && assertion.aud == '//iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/ci/providers/github'"
  }
}
