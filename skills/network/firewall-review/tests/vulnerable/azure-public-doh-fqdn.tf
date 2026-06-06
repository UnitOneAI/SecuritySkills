resource "azurerm_firewall_application_rule_collection" "public_doh" {
  name                = "public-doh-exception"
  azure_firewall_name = azurerm_firewall.main.name
  resource_group_name = azurerm_resource_group.rg.name
  priority            = 200
  action              = "Allow"

  rule {
    name             = "allow-public-doh"
    source_addresses = ["10.20.0.0/16"]
    target_fqdns     = ["cloudflare-dns.com", "dns.google"]

    protocol {
      type = "Https"
      port = 443
    }
  }
}
