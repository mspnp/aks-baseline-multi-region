targetScope = 'resourceGroup'

/*** PARAMETERS ***/

@description('The AKS Control Plane Principal Id to be given with Network Contributor Role in different spoke subnets, so it can join VMSS and load balancers resources to them.')
@minLength(36)
@maxLength(36)
param kubeletIdentityObjectId string

/*** EXISTING SUBSCRIPTION RESOURCES ***/

resource virtualMachineContributorRole 'Microsoft.Authorization/roleDefinitions@2022-05-01-preview' existing = {
  name: '9980e02c-c2be-4d73-94e8-173b1dc7cf3c'
  scope: subscription()
}

/*** RESOURCES ***/

// It is required to grant the AKS cluster with Virtual Machine Contributor role permissions over the cluster infrastructure resource group to work with Managed Identities.
resource id 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(resourceGroup().id, virtualMachineContributorRole.id, kubeletIdentityObjectId)
  properties: {
    roleDefinitionId: virtualMachineContributorRole.id
    principalId: kubeletIdentityObjectId
    principalType: 'ServicePrincipal'
  }
}
