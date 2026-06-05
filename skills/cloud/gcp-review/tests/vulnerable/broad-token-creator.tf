resource "google_service_account" "deploy" {
  account_id   = "prod-deploy"
  display_name = "Production deploy account"
}

resource "google_project_iam_member" "deploy_owner" {
  project = var.project_id
  role    = "roles/owner"
  member  = "serviceAccount:${google_service_account.deploy.email}"
}

resource "google_project_iam_member" "contractor_token_creator" {
  project = var.project_id
  role    = "roles/iam.serviceAccountTokenCreator"
  member  = "group:contractors@example.com"
}
