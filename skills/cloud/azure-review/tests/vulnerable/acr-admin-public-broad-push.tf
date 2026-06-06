resource "azurerm_container_registry" "prod" {
  name                          = "prodacr"
  resource_group_name           = azurerm_resource_group.prod.name
  location                      = azurerm_resource_group.prod.location
  sku                           = "Premium"
  admin_enabled                 = true
  public_network_access_enabled = true
}

resource "azurerm_role_assignment" "ci_push_all" {
  scope                = azurerm_resource_group.prod.id
  role_definition_name = "AcrPush"
  principal_id         = azuread_service_principal.ci.object_id
}
