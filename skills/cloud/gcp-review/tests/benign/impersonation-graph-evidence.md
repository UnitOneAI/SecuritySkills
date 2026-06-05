# Impersonation Graph Evidence Fixture

This fixture represents acceptable evidence for a constrained workload identity
federation path.

| Principal | Grant Source | Resource Level | Target Service Account | Target SA Roles | Condition | Risk |
|---|---|---|---|---|---|---|
| `principalSet://.../attribute.repository/my-org/prod-deploy` | `google_service_account_iam_binding.github_deploy` | service-account | `prod-deploy@project.iam.gserviceaccount.com` | narrow deploy role | repository, ref, and audience constrained | Pass |

Decision: no broad human/group Token Creator path is present, the federated
principal is repository-scoped, and the IAM Condition binds repository, branch,
and audience.
