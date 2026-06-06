resource "azurerm_container_registry" "prod" {
  name                          = "prodacr"
  resource_group_name           = azurerm_resource_group.prod.name
  location                      = azurerm_resource_group.prod.location
  sku                           = "Premium"
  admin_enabled                 = false
  public_network_access_enabled = false
  network_rule_bypass_option    = "AzureServices"
}

resource "azurerm_private_endpoint" "acr" {
  name                = "prod-acr-pe"
  resource_group_name = azurerm_resource_group.prod.name
  location            = azurerm_resource_group.prod.location
  subnet_id           = azurerm_subnet.private_endpoints.id

  private_service_connection {
    name                           = "prod-acr"
    is_manual_connection           = false
    private_connection_resource_id = azurerm_container_registry.prod.id
    subresource_names              = ["registry"]
  }
}

resource "azurerm_role_assignment" "aks_can_pull_acr" {
  scope                = azurerm_container_registry.prod.id
  role_definition_name = "AcrPull"
  principal_id         = azurerm_user_assigned_identity.aks_pull.principal_id
}
