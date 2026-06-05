param adminPassword string

resource vm 'Microsoft.Compute/virtualMachines@2025-04-01' = {
  name: 'unsafe-vm'
  location: resourceGroup().location
  properties: {
    osProfile: {
      computerName: 'unsafe-vm'
      adminUsername: 'azureuser'
      adminPassword: adminPassword
    }
  }
}

resource storage 'Microsoft.Storage/storageAccounts@2023-05-01' existing = {
  name: 'prodsa'
}

output primaryKey string = storage.listKeys().keys[0].value
