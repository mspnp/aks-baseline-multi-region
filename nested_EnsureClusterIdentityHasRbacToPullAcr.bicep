targetScope = 'resourceGroup'

/*** PARAMETERS ***/

@description('The shared resources resource group name.')
param sharedResourceGroupName string

@description('The shared acr resource name.')
param acrName string

@description('The AKS Id to be given with ACR Pull Role permissions, so it can pull images into the cluster.')
param clusterId string

@description('The AKS Managed Identity Id to be given with ACR Pull Role permissions, so it can pull images into the cluster.')
@minLength(36)
@maxLength(36)
param miClusterControlPlaneObjectId string

/*** EXISTING SUBSCRIPTION RESOURCES ***/

// Built-in Azure RBAC role that can be applied to an Azure Container Registry to grant the authority pull container images. Granted to the AKS cluster's kubelet identity.
resource acrPullRole 'Microsoft.Authorization/roleDefinitions@2018-01-01-preview' existing = {
  name: '7f951dda-4ed3-4680-a7ca-43fe172d538d'
  scope: subscription()
}

/*** EXISTING RESOURCE GROUP RESOURCES ***/

// Shared resource group
resource sharedResourceGroup 'Microsoft.Resources/resourceGroups@2021-04-01' existing = {
  scope: subscription()
  name: sharedResourceGroupName
}

// Azure Container Registry
resource acr 'Microsoft.ContainerRegistry/registries@2021-12-01-preview' existing = {
  name: acrName
}

/*** RESOURCES ***/

resource acrKubeletAcrPullRole_roleAssignment 'Microsoft.Authorization/roleAssignments@2020-10-01-preview' = {
  scope: acr
  name: guid(clusterId, acrPullRole.id)
  properties: {
    roleDefinitionId: acrPullRole.id
    description: 'Allows AKS to pull container images from this ACR instance.'
    principalId: miClusterControlPlaneObjectId
    principalType: 'ServicePrincipal'
  }
}
