resource "google_iam_workload_identity_pool_provider" "github" {
  workload_identity_pool_id = "ci-pool"

  oidc {
    issuer_uri        = "https://token.actions.githubusercontent.com"
    allowed_audiences = ["//iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/ci-pool/providers/github"]
  }

  attribute_mapping = {
    "google.subject"        = "assertion.sub"
    "attribute.repository"  = "assertion.repository"
    "attribute.ref"         = "assertion.ref"
    "attribute.workflow"    = "assertion.workflow"
    "attribute.environment" = "assertion.environment"
  }

  attribute_condition = "assertion.repository == 'org/app' && assertion.ref == 'refs/heads/main' && assertion.workflow == 'deploy.yml' && assertion.environment == 'production'"
}

resource "google_service_account_iam_member" "deploy" {
  service_account_id = "projects/example/serviceAccounts/deploy@example.iam.gserviceaccount.com"
  role               = "roles/iam.workloadIdentityUser"
  member             = "principalSet://iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/ci-pool/attribute.repository/org/app"
}
