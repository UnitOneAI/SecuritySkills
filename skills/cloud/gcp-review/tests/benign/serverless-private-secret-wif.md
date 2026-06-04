# Benign Case: Private Serverless API With Scoped Secrets and WIF

## Scenario

A checkout API runs on Cloud Run behind an internal load balancer. Runtime secrets come from Secret Manager, and CI/CD uses Workload Identity Federation constrained to a single GitHub repository.

## Evidence

```hcl
resource "google_service_account" "runtime" {
  account_id = "checkout-runtime"
}

resource "google_secret_manager_secret" "payment_api_key" {
  secret_id = "payment-api-key"

  replication {
    auto {}
  }
}

resource "google_secret_manager_secret_iam_member" "runtime_can_read_key" {
  secret_id = google_secret_manager_secret.payment_api_key.id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.runtime.email}"
}

resource "google_cloud_run_v2_service" "checkout_api" {
  name     = "checkout-api"
  location = "us-central1"
  ingress  = "INGRESS_TRAFFIC_INTERNAL_LOAD_BALANCER"

  template {
    service_account = google_service_account.runtime.email

    containers {
      image = "us-docker.pkg.dev/example/checkout/api:2026-06-04"

      env {
        name = "PAYMENT_API_KEY"
        value_source {
          secret_key_ref {
            secret  = google_secret_manager_secret.payment_api_key.secret_id
            version = "2"
          }
        }
      }
    }
  }
}

resource "google_cloud_run_service_iam_member" "private_invoker" {
  service  = google_cloud_run_v2_service.checkout_api.name
  location = google_cloud_run_v2_service.checkout_api.location
  role     = "roles/run.invoker"
  member   = "serviceAccount:edge-proxy@example.iam.gserviceaccount.com"
}

resource "google_iam_workload_identity_pool_provider" "github" {
  workload_identity_pool_id          = google_iam_workload_identity_pool.cicd.workload_identity_pool_id
  workload_identity_pool_provider_id = "github"

  oidc {
    issuer_uri = "https://token.actions.githubusercontent.com"
  }

  attribute_mapping = {
    "google.subject"       = "assertion.sub"
    "attribute.repository" = "assertion.repository"
  }

  attribute_condition = "attribute.repository == 'example/checkout-api'"
}
```

## Expected Skill Result

Do not flag this as a plaintext serverless secret or public serverless API. The review can mark the serverless checks **PASS** when evidence confirms:

- Cloud Run ingress is internal-load-balancer scoped.
- Invoker IAM is restricted to a named service account.
- Runtime identity is a dedicated non-default service account.
- Secret source is Secret Manager with a pinned version and scoped runtime accessor binding.
- WIF provider constrains the trusted external identity with an attribute condition.
