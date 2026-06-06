resource "google_service_account_iam_member" "ci_can_token_create_bridge" {
  service_account_id = "projects/example/serviceAccounts/bridge@example.iam.gserviceaccount.com"
  role               = "roles/iam.serviceAccountTokenCreator"
  member             = "principalSet://iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/ci-pool/*"
}

resource "google_service_account_iam_member" "bridge_can_token_create_prod" {
  service_account_id = "projects/example/serviceAccounts/prod-deploy@example.iam.gserviceaccount.com"
  role               = "roles/iam.serviceAccountTokenCreator"
  member             = "serviceAccount:bridge@example.iam.gserviceaccount.com"
}
