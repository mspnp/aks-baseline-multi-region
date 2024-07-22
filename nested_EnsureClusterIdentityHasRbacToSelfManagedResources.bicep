targetScope = 'resourceGroup'

/*** PARAMETERS ***/


@description('The AKS Control Plane Principal Id to be given with Network Contributor Role in different spoke subnets, so it can join VMSS and load balancers resources to them.')
@minLength(36)
@maxLength(36)
param miClusterControlPlanePrincipalId string

@description('The regional network spoke VNet Resource name that the cluster is being joined to, so it can be used to discover subnets during role assignments.')
@minLength(1)
param targetVirtualNetworkName string

/*** EXISTING SUBSCRIPTION RESOURCES ***/

resource networkContributorRole 'Microsoft.Authorization/roleDefinitions@2022-05-01-preview' existing = {
  name: '4d97b98b-1d4f-4787-a291-c67834d212e7'
  scope: subscription()
}

/*** EXISTING SPOKE RESOURCES ***/

resource targetVirtualNetwork 'Microsoft.Network/virtualNetworks@2023-11-01' existing = {
  name: targetVirtualNetworkName

  resource snetClusterNodes 'subnets' existing = {
    name: 'snet-clusternodes'
  }
  
  resource snetClusterIngress 'subnets' existing = {
    name: 'snet-clusteringressservices'
  }
}

/*** RESOURCES ***/

resource snetClusterNodesMiClusterControlPlaneNetworkContributorRole_roleAssignment 'Microsoft.Authorization/roleAssignments@2020-10-01-preview' = {
  scope: targetVirtualNetwork::snetClusterNodes
  name: guid(targetVirtualNetwork::snetClusterNodes.id, networkContributorRole.id, miClusterControlPlanePrincipalId)
  properties: {
    roleDefinitionId: networkContributorRole.id
    description: 'Allows cluster identity to join the nodepool vmss resources to this subnet.'
    principalId: miClusterControlPlanePrincipalId
    principalType: 'ServicePrincipal'
  }
}

resource snetClusterIngressServicesMiClusterControlPlaneSecretsUserRole_roleAssignment 'Microsoft.Authorization/roleAssignments@2020-10-01-preview' = {
  scope: targetVirtualNetwork::snetClusterIngress
  name: guid(targetVirtualNetwork::snetClusterIngress.id, networkContributorRole.id, miClusterControlPlanePrincipalId)
  properties: {
    roleDefinitionId: networkContributorRole.id
    description: 'Allows cluster identity to join load balancers (ingress resources) to this subnet.'
    principalId: miClusterControlPlanePrincipalId
    principalType: 'ServicePrincipal'
  }
}
