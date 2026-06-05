variable "project_id" {
  type = string
}

resource "google_service_account" "deploy_prod" {
  account_id   = "deploy-prod"
  display_name = "Production deployment service account"
}

resource "google_project_iam_member" "deploy_sa_editor" {
  project = var.project_id
  role    = "roles/editor"
  member  = "serviceAccount:${google_service_account.deploy_prod.email}"
}

resource "google_project_iam_member" "contractor_token_creator" {
  project = var.project_id
  role    = "roles/iam.serviceAccountTokenCreator"
  member  = "group:contractors@example.com"
}

resource "google_project_iam_member" "contractor_service_account_user" {
  project = var.project_id
  role    = "roles/iam.serviceAccountUser"
  member  = "group:contractors@example.com"
}
