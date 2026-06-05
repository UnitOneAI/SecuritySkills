variable "project_id" {
  type = string
}

resource "google_service_account" "deploy" {
  account_id   = "deploy-prod"
  display_name = "Production deployment service account"
}

resource "google_service_account_iam_binding" "ci_token_creator" {
  service_account_id = google_service_account.deploy.name
  role               = "roles/iam.serviceAccountTokenCreator"

  members = [
    "principalSet://iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/ci/attribute.repository/my-org/prod-deploy"
  ]

  condition {
    title       = "prod-deploy-main-only"
    description = "Only the production deployment workflow on the main branch can mint deploy credentials."
    expression  = "assertion.repository == 'my-org/prod-deploy' && assertion.ref == 'refs/heads/main' && assertion.aud == 'deploy-prod'"
  }
}

resource "google_project_iam_member" "deploy_limited_role" {
  project = var.project_id
  role    = "roles/run.developer"
  member  = "serviceAccount:${google_service_account.deploy.email}"
}
