resource "google_iam_workload_identity_pool_provider" "github" {
  workload_identity_pool_id = "ci-pool"

  oidc {
    issuer_uri = "https://token.actions.githubusercontent.com"
  }

  attribute_mapping = {
    "google.subject"       = "assertion.sub"
    "attribute.repository" = "assertion.repository"
  }
}

resource "google_service_account_iam_member" "deploy" {
  service_account_id = "projects/example/serviceAccounts/deploy@example.iam.gserviceaccount.com"
  role               = "roles/iam.workloadIdentityUser"
  member             = "principalSet://iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/ci-pool/*"
}
