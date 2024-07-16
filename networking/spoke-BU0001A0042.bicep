targetScope = 'resourceGroup'

/*** PARAMETERS ***/

@description('The application instance id helps to generate a unique application instance identifier for multiple instances of the same application. This number is also going to be used to derive its adjacent resources details when needed')
@allowed([
  '03'
  '04'
])
param appInstanceId string

@description('The AKS cluster Virtual Network address prefix. All the subnets within the cluster-related will partially allocate address ranges from this space')
param clusterVNetAddressPrefix string

@description('The AKS cluster nodes subnet address prefix. This prefix belongs to the address space passed as part of the clusterVNetAddressPrefix parameter value')
param clusterNodesSubnetAddressPrefix string

@description('The AKS cluster ingress services subnet address prefix. This prefix belongs to the address space passed as part of the clusterVNetAddressPrefix parameter value')
param clusterIngressServicesSubnetAddressPrefix string

@description('The AKS cluster ingress services subnet address prefix. This prefix belongs to the address space passed as part of the clusterVNetAddressPrefix parameter value')
param applicationGatewaySubnetAddressPrefix string

@description('The regional hub network to which this regional spoke will peer to.')
param hubVnetResourceId string

@description('The spokes\'s regional affinity, must be the same as the hub\'s location. All resources tied to this spoke will also be homed in this region. The network team maintains this approved regional list which is a subset of regions with Availability Zone support.')
@allowed([
  'australiaeast'
  'canadacentral'
  'centralus'
  'eastus'
  'eastus2'
  'westus2'
  'francecentral'
  'germanywestcentral'
  'northeurope'
  'southafricanorth'
  'southcentralus'
  'uksouth'
  'westeurope'
  'japaneast'
  'southeastasia'
  'brazilsouth'
  'southcentralus'
])
param location string

@description('Flow Logs are enabled by default, if for some reason they cause conflicts with flow log policies already in place in your subscription, you can disable them by passing \'false\' to this parameter.')
param deployFlowLogResources bool = true

/*** VARIABLES ***/

var appId = 'BU0001A0042-${appInstanceId}'
var clusterVNetName = 'vnet-hub-spoke-${appId}'

var routeTableName = 'route-to-${location}-hub-fw'
var hubRgName = split(hubVnetResourceId, '/')[4]
var hubNetworkName = split(hubVnetResourceId, '/')[8]

var hubFwResourceId = resourceId(hubRgName, 'Microsoft.Network/azureFirewalls', 'fw-${location}')
var hubLaWorkspaceName = 'la-hub-${location}-${uniqueString(hubVnetResourceId)}'
var hubLaWorkspaceResourceId = resourceId(hubRgName, 'Microsoft.OperationalInsights/workspaces', hubLaWorkspaceName)
var toHubPeeringName = 'spoke-to-${hubNetworkName}'

var primaryClusterPipName = 'pip-${appId}'
var subdomainName = 'region${uniqueString(resourceId(hubRgName,'Microsoft.Network/publicIpAddresses',primaryClusterPipName))}'
var sharedFlowlogStorageAccountName = take(
  'stnfl${location}${uniqueString(subscriptionResourceId('Microsoft.Resources/resourceGroups',hubRgName))}',
  24
)

/*** EXISTING HUB RESOURCES ***/

// This is 'rg-enterprise-networking-hubs-$region' if using the default values in the walkthrough
resource hubResourceGroup 'Microsoft.Resources/resourceGroups@2021-04-01' existing = {
  scope: subscription()
  name: hubRgName
}

resource hubVirtualNetwork 'Microsoft.Network/virtualNetworks@2021-05-01' existing = {
  scope: hubResourceGroup
  name: hubNetworkName
}

resource sharedStorageAccount 'Microsoft.Storage/storageAccounts@2021-02-01' existing = {
  scope: hubResourceGroup
  name: sharedFlowlogStorageAccountName
}

resource hubLa 'Microsoft.OperationalInsights/workspaces@2023-09-01' existing = {
  scope: hubResourceGroup
  name: hubLaWorkspaceName
}

/*** RESOURCES ***/

resource routeTable 'Microsoft.Network/routeTables@2020-07-01' = {
  name: routeTableName
  location: location
  properties: {
    routes: [
      {
        name: 'r-nexthop-to-fw'
        properties: {
          nextHopType: 'VirtualAppliance'
          addressPrefix: '0.0.0.0/0'
          nextHopIpAddress: reference(hubFwResourceId, '2020-05-01').ipConfigurations[0].properties.privateIpAddress
        }
      }
    ]
  }
}

resource nsg_clusterVNetName_nodepools 'Microsoft.Network/networkSecurityGroups@2020-05-01' = {
  name: 'nsg-${clusterVNetName}-nodepools'
  location: location
  properties: {
    securityRules: []
  }
}

resource nsg_clusterVNetName_nodepools_Microsoft_Insights_toHub 'Microsoft.Network/networkSecurityGroups/providers/diagnosticSettings@2017-05-01-preview' = {
  name: 'nsg-${clusterVNetName}-nodepools/Microsoft.Insights/toHub'
  properties: {
    workspaceId: hubLaWorkspaceResourceId
    logs: [
      {
        category: 'NetworkSecurityGroupEvent'
        enabled: true
      }
      {
        category: 'NetworkSecurityGroupRuleCounter'
        enabled: true
      }
    ]
  }
  dependsOn: [
    nsg_clusterVNetName_nodepools
  ]
}

resource nsg_clusterVNetName_aksilbs 'Microsoft.Network/networkSecurityGroups@2020-05-01' = {
  name: 'nsg-${clusterVNetName}-aksilbs'
  location: location
  properties: {
    securityRules: []
  }
}

resource nsg_clusterVNetName_aksilbs_Microsoft_Insights_toHub 'Microsoft.Network/networkSecurityGroups/providers/diagnosticSettings@2017-05-01-preview' = {
  name: 'nsg-${clusterVNetName}-aksilbs/Microsoft.Insights/toHub'
  properties: {
    workspaceId: hubLaWorkspaceResourceId
    logs: [
      {
        category: 'NetworkSecurityGroupEvent'
        enabled: true
      }
      {
        category: 'NetworkSecurityGroupRuleCounter'
        enabled: true
      }
    ]
  }
  dependsOn: [
    nsg_clusterVNetName_aksilbs
  ]
}

resource nsg_clusterVNetName_appgw 'Microsoft.Network/networkSecurityGroups@2020-05-01' = {
  name: 'nsg-${clusterVNetName}-appgw'
  location: location
  properties: {
    securityRules: [
      {
        name: 'AllowOnlyFrontDoor'
        properties: {
          description: 'Allow only Front Door Access. (If you wanted to allow-list specific IPs, this is where you\'d list them.)'
          protocol: 'Tcp'
          sourcePortRange: '*'
          sourceAddressPrefix: 'AzureFrontDoor.Backend'
          destinationPortRange: '443'
          destinationAddressPrefix: 'VirtualNetwork'
          access: 'Allow'
          priority: 100
          direction: 'Inbound'
        }
      }
      {
        name: 'AllowControlPlaneInBound'
        properties: {
          description: 'Allow Azure Control Plane in. (https://learn.microsoft.com/azure/application-gateway/configuration-infrastructure#network-security-groups)'
          protocol: '*'
          sourcePortRange: '*'
          sourceAddressPrefix: '*'
          destinationPortRange: '65200-65535'
          destinationAddressPrefix: '*'
          access: 'Allow'
          priority: 110
          direction: 'Inbound'
        }
      }
      {
        name: 'AllowHealthProbesInBound'
        properties: {
          description: 'Allow Azure Application Gateway Health Probes in. (https://learn.microsoft.com/azure/application-gateway/configuration-infrastructure#network-security-groups)'
          protocol: '*'
          sourcePortRange: '*'
          sourceAddressPrefix: 'AzureLoadBalancer'
          destinationPortRange: '*'
          destinationAddressPrefix: 'VirtualNetwork'
          access: 'Allow'
          priority: 120
          direction: 'Inbound'
        }
      }
      {
        name: 'DenyAllInBound'
        properties: {
          protocol: '*'
          sourcePortRange: '*'
          sourceAddressPrefix: '*'
          destinationPortRange: '*'
          destinationAddressPrefix: '*'
          access: 'Deny'
          priority: 1000
          direction: 'Inbound'
        }
      }
      {
        name: 'AllowAllOutBound'
        properties: {
          protocol: '*'
          sourcePortRange: '*'
          sourceAddressPrefix: '*'
          destinationPortRange: '*'
          destinationAddressPrefix: '*'
          access: 'Allow'
          priority: 1000
          direction: 'Outbound'
        }
      }
    ]
  }
}

resource nsg_clusterVNetName_appgw_Microsoft_Insights_toHub 'Microsoft.Network/networkSecurityGroups/providers/diagnosticSettings@2017-05-01-preview' = {
  name: 'nsg-${clusterVNetName}-appgw/Microsoft.Insights/toHub'
  properties: {
    workspaceId: hubLaWorkspaceResourceId
    logs: [
      {
        category: 'NetworkSecurityGroupEvent'
        enabled: true
      }
      {
        category: 'NetworkSecurityGroupRuleCounter'
        enabled: true
      }
    ]
  }
  dependsOn: [
    nsg_clusterVNetName_appgw
  ]
}

resource vnetSpoke 'Microsoft.Network/virtualNetworks@2020-07-01' = {
  name: clusterVNetName
  location: location
  properties: {
    addressSpace: {
      addressPrefixes: [
        clusterVNetAddressPrefix
      ]
    }
    subnets: [
      {
        name: 'snet-clusternodes'
        properties: {
          addressPrefix: clusterNodesSubnetAddressPrefix
          routeTable: {
            id: routeTable.id
          }
          networkSecurityGroup: {
            id: nsg_clusterVNetName_nodepools.id
          }
          privateEndpointNetworkPolicies: 'Disabled'
          privateLinkServiceNetworkPolicies: 'Enabled'
        }
      }
      {
        name: 'snet-clusteringressservices'
        properties: {
          addressPrefix: clusterIngressServicesSubnetAddressPrefix
          routeTable: {
            id: routeTable.id
          }
          networkSecurityGroup: {
            id: nsg_clusterVNetName_aksilbs.id
          }
          privateEndpointNetworkPolicies: 'Disabled'
          privateLinkServiceNetworkPolicies: 'Disabled'
        }
      }
      {
        name: 'snet-applicationgateway'
        properties: {
          addressPrefix: applicationGatewaySubnetAddressPrefix
          networkSecurityGroup: {
            id: nsg_clusterVNetName_appgw.id
          }
          privateEndpointNetworkPolicies: 'Disabled'
          privateLinkServiceNetworkPolicies: 'Disabled'
        }
      }
    ]
  }
}

resource clusterVNetName_Microsoft_Insights_toHub 'Microsoft.Network/virtualNetworks/providers/diagnosticSettings@2017-05-01-preview' = {
  name: '${clusterVNetName}/Microsoft.Insights/toHub'
  properties: {
    workspaceId: hubLaWorkspaceResourceId
    metrics: [
      {
        category: 'AllMetrics'
        enabled: true
      }
    ]
  }
  dependsOn: [
    vnetSpoke
  ]
}

// Peer to regional hub
module peeringSpokeToHub './virtualNetworkPeering.bicep' = {
  name: toHubPeeringName
  params: {
    remoteVirtualNetworkId: hubVirtualNetwork.id
    localVnetName: vnetSpoke.name
  }
}

// Connect regional hub back to this spoke, this could also be handled via the
// hub template or via Azure Policy or Portal. How virtual networks are peered
// may vary from organization to organization. This example simply does it in
// the most direct way.
module peeringHubToSpoke './virtualNetworkPeering.bicep' = {
  name: take('Peer-${hubVirtualNetwork.name}To${vnetSpoke.name}', 64)
  dependsOn: [
    peeringSpokeToHub
  ]
  scope: hubResourceGroup
  params: {
    remoteVirtualNetworkId: vnetSpoke.id
    localVnetName: hubVirtualNetwork.name
  }
}

resource primaryClusterPip 'Microsoft.Network/publicIpAddresses@2020-07-01' = {
  name: primaryClusterPipName
  location: location
  sku: {
    name: 'Standard'
  }
  properties: {
    publicIPAllocationMethod: 'Static'
    idleTimeoutInMinutes: 4
    publicIPAddressVersion: 'IPv4'
    dnsSettings: {
      domainNameLabel: subdomainName
      fqdn: '${subdomainName}.${location}.cloudapp.azure.com'
    }
  }
}

module flowLogsNsgSpoke './virtualNetworkFlowlogs.bicep' = if (deployFlowLogResources) {
  name: 'nsgSpokeFlowlogs'
  scope: resourceGroup('networkWatcherRG')
  params: {
    nsgId: nsg_clusterVNetName_nodepools.id
    flowlogStorageAccountId: sharedStorageAccount.id
    laId: hubLa.id
    location: location
  }
  dependsOn: []
}

module flowLogsNsgIlbs './virtualNetworkFlowlogs.bicep' = if (deployFlowLogResources) {
  name: 'nsgIlbsFlowlogs'
  scope: resourceGroup('networkWatcherRG')
  params: {
    nsgId: resourceId(
      resourceGroup().name,
      'Microsoft.Network/networkSecurityGroups',
      'nsg-${clusterVNetName}-aksilbs'
    )
    flowlogStorageAccountId: sharedStorageAccount.id
    laId: hubLa.id
    location: location
  }
  dependsOn: []
}

module flowLogsNsgAppgw './virtualNetworkFlowlogs.bicep' = if (deployFlowLogResources) {
  name: 'nsgAppgwFlowlogs'
  scope: resourceGroup('networkWatcherRG')
  params: {
    nsgId: resourceId(
      resourceGroup().name,
      'Microsoft.Network/networkSecurityGroups',
      'nsg-${clusterVNetName}-appgw'
    )
    flowlogStorageAccountId: sharedStorageAccount.id
    laId: hubLa.id
    location: location
  }
  dependsOn: []
}

/*** OUTPUTS ***/

output clusterSpokeVnetName string = vnetSpoke.name
output nodepoolSubnetResourceIds array = [
  resourceId('Microsoft.Network/virtualNetworks/subnets', vnetSpoke.name, 'snet-clusternodes')
]
output appGwFqdn string = primaryClusterPip.properties.dnsSettings.fqdn
output subdomainName string = subdomainName
output appGatewayPublicIp string = primaryClusterPip.id
