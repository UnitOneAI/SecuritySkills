@secure()
param adminPassword string

resource vm 'Microsoft.Compute/virtualMachines@2025-04-01' = {
  name: 'safe-vm'
  location: resourceGroup().location
  properties: {
    osProfile: {
      computerName: 'safe-vm'
      adminUsername: 'azureuser'
      adminPassword: adminPassword
    }
  }
}
