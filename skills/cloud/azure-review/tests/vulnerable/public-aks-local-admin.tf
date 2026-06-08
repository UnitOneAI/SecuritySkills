resource "azurerm_kubernetes_cluster" "admin" {
  name                = "admin-prod"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
  dns_prefix          = "admin-prod"

  private_cluster_enabled           = false
  api_server_authorized_ip_ranges   = ["0.0.0.0/0"]
  role_based_access_control_enabled = false
  local_account_disabled            = false
  oidc_issuer_enabled               = false
  workload_identity_enabled         = false
  azure_policy_enabled              = false

  default_node_pool {
    name       = "system"
    vm_size    = "Standard_D4s_v5"
    node_count = 3
  }

  service_principal {
    client_id     = var.legacy_client_id
    client_secret = var.legacy_client_secret
  }

  network_profile {
    network_plugin = "kubenet"
  }
}
