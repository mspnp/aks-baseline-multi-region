targetScope = 'resourceGroup'

/*** PARAMETERS ***/

@description('The shared acr resource name.')
param acrName string

@description('The AKS Id to be given with ACR Pull Role permissions, so it can pull images into the cluster.')
param clusterId string

@description('The AKS Managed Identity Id to be given with ACR Pull Role permissions, so it can pull images into the cluster.')
@minLength(36)
@maxLength(36)
param kubeletidentityObjectId string

/*** EXISTING SUBSCRIPTION RESOURCES ***/

// Built-in Azure RBAC role that can be applied to an Azure Container Registry to grant the authority pull container images. Granted to the AKS cluster's kubelet identity.
resource acrPullRole 'Microsoft.Authorization/roleDefinitions@2022-05-01-preview' existing = {
  name: '7f951dda-4ed3-4680-a7ca-43fe172d538d'
  scope: subscription()
}

/*** EXISTING RESOURCE GROUP RESOURCES ***/

// Azure Container Registry
resource acr 'Microsoft.ContainerRegistry/registries@2023-11-01-preview' existing = {
  name: acrName
}

/*** RESOURCES ***/

resource acrKubeletAcrPullRole_roleAssignment 'Microsoft.Authorization/roleAssignments@2020-10-01-preview' = {
  scope: acr
  name: guid(clusterId, acrPullRole.id)
  properties: {
    roleDefinitionId: acrPullRole.id
    description: 'Allows AKS to pull container images from this ACR instance.'
    principalId: kubeletidentityObjectId
    principalType: 'ServicePrincipal'
  }
}
