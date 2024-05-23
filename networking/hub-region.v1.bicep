targetScope = 'resourceGroup'

/*** PARAMETERS ***/

@description('The hub\'s regional affinity. All resources tied to this hub will also be homed in this region.  The network team maintains this approved regional list which is a subset of zones with Availability Zone support.')
@allowed(
  [
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
  ]
)
param location string

@description('A /24 to contain the regional firewall, management, and gateway subnet')
@minLength(10)
@maxLength(18)
param hubVnetAddressSpace string = '10.200.0.0/24'

@description('A /26 under the VNet Address Space for the regional Azure Firewall')
@minLength(10)
@maxLength(18)
param azureFirewallSubnetAddressSpace string = '10.200.0.0/26'

@description('A /27 under the VNet Address Space for our regional On-Prem Gateway')
@minLength(10)
@maxLength(18)
param azureGatewaySubnetAddressSpace string = '10.200.0.64/27'

@description('A /27 under the VNet Address Space for regional Azure Bastion')
@minLength(10)
@maxLength(18)
param azureBastionSubnetAddressSpace string = '10.200.0.96/27'

@description('The Azure Base Policy resource id')
param baseFirewallPoliciesId string

@description('The Azure Base Policy location that will be used for the children policies')
param firewallPolicyLocation string

@description('Flow Logs are enabled by default, if for some reason they cause conflicts with flow log policies already in place in your subscription, you can disable them by passing \'false\' to this parameter.')
param deployFlowLogResources bool = true

/*** VARIABLES ***/

var baseFwPipName = 'pip-fw-${location}'
var hubFwPipNames = [
  '${baseFwPipName}-default'
  '${baseFwPipName}-01'
  '${baseFwPipName}-02'
]
var hubFwName = 'fw-${location}'
var hubVNetName = 'vnet-${location}-hub'
var bastionNetworkNsgName = 'nsg-${location}-bastion'
var hubLaName = 'la-hub-${location}-${uniqueString(hubVnet.id)}'
var fwPoliciesName = 'fw-policies-${location}'
var regionFlowLowStorageAccountName = take(
  'stnfl${location}${uniqueString(resourceGroup().id)}',
  24
)

/*** RESOURCES ***/

resource hubLa 'Microsoft.OperationalInsights/workspaces@2023-09-01' = {
  name: hubLaName
  location: location
  properties: {
    sku: {
      name: 'PerGB2018'
    }
    retentionInDays: 30
    publicNetworkAccessForIngestion: 'Enabled'
    publicNetworkAccessForQuery: 'Enabled'
  }
}

resource bastionNetworkNsg 'Microsoft.Network/networkSecurityGroups@2020-05-01' = {
  name: bastionNetworkNsgName
  location: location
  properties: {
    securityRules: [
      {
        name: 'AllowWebExperienceInBound'
        properties: {
          description: 'Allow our users in. Update this to be as restrictive as possible.'
          protocol: 'Tcp'
          sourcePortRange: '*'
          sourceAddressPrefix: 'Internet'
          destinationPortRange: '443'
          destinationAddressPrefix: '*'
          access: 'Allow'
          priority: 100
          direction: 'Inbound'
        }
      }
      {
        name: 'AllowControlPlaneInBound'
        properties: {
          description: 'Service Requirement. Allow control plane access. Regional Tag not yet supported.'
          protocol: 'Tcp'
          sourcePortRange: '*'
          sourceAddressPrefix: 'GatewayManager'
          destinationPortRange: '443'
          destinationAddressPrefix: '*'
          access: 'Allow'
          priority: 110
          direction: 'Inbound'
        }
      }
      {
        name: 'AllowHealthProbesInBound'
        properties: {
          description: 'Service Requirement. Allow Health Probes.'
          protocol: 'Tcp'
          sourcePortRange: '*'
          sourceAddressPrefix: 'AzureLoadBalancer'
          destinationPortRange: '443'
          destinationAddressPrefix: '*'
          access: 'Allow'
          priority: 120
          direction: 'Inbound'
        }
      }
      {
        name: 'AllowBastionHostToHostInBound'
        properties: {
          description: 'Service Requirement. Allow Required Host to Host Communication.'
          protocol: '*'
          sourcePortRange: '*'
          sourceAddressPrefix: 'VirtualNetwork'
          destinationPortRanges: ['8080', '5701']
          destinationAddressPrefix: 'VirtualNetwork'
          access: 'Allow'
          priority: 130
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
        name: 'AllowSshToVnetOutBound'
        properties: {
          description: 'Allow SSH out to the VNet'
          protocol: 'Tcp'
          sourcePortRange: '*'
          sourceAddressPrefix: '*'
          destinationPortRange: '22'
          destinationAddressPrefix: 'VirtualNetwork'
          access: 'Allow'
          priority: 100
          direction: 'Outbound'
        }
      }
      {
        name: 'AllowRdpToVnetOutBound'
        properties: {
          protocol: 'Tcp'
          description: 'Allow RDP out to the VNet'
          sourcePortRange: '*'
          sourceAddressPrefix: '*'
          destinationPortRange: '3389'
          destinationAddressPrefix: 'VirtualNetwork'
          access: 'Allow'
          priority: 110
          direction: 'Outbound'
        }
      }
      {
        name: 'AllowControlPlaneOutBound'
        properties: {
          description: 'Required for control plane outbound. Regional prefix not yet supported'
          protocol: 'Tcp'
          sourcePortRange: '*'
          sourceAddressPrefix: '*'
          destinationPortRange: '443'
          destinationAddressPrefix: 'AzureCloud'
          access: 'Allow'
          priority: 120
          direction: 'Outbound'
        }
      }
      {
        name: 'AllowBastionHostToHostOutBound'
        properties: {
          description: 'Service Requirement. Allow Required Host to Host Communication.'
          protocol: '*'
          sourcePortRange: '*'
          sourceAddressPrefix: 'VirtualNetwork'
          destinationPortRanges: ['8080', '5701']
          destinationAddressPrefix: 'VirtualNetwork'
          access: 'Allow'
          priority: 130
          direction: 'Outbound'
        }
      }
      {
        name: 'AllowBastionCertificateValidationOutBound'
        properties: {
          description: 'Service Requirement. Allow Required Session and Certificate Validation.'
          protocol: '*'
          sourcePortRange: '*'
          sourceAddressPrefix: '*'
          destinationPortRange: '80'
          destinationAddressPrefix: 'Internet'
          access: 'Allow'
          priority: 140
          direction: 'Outbound'
        }
      }
      {
        name: 'DenyAllOutBound'
        properties: {
          protocol: '*'
          sourcePortRange: '*'
          sourceAddressPrefix: '*'
          destinationPortRange: '*'
          destinationAddressPrefix: '*'
          access: 'Deny'
          priority: 1000
          direction: 'Outbound'
        }
      }
    ]
  }
}

resource bastionNetworkNsgName_Microsoft_Insights_default 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  name: 'default'
  scope: bastionNetworkNsg
  properties: {
    workspaceId: hubLa.id
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
  dependsOn: []
}

resource hubVnet 'Microsoft.Network/virtualNetworks@2020-05-01' = {
  name: hubVNetName
  location: location
  properties: {
    addressSpace: {
      addressPrefixes: [hubVnetAddressSpace]
    }
    subnets: [
      {
        name: 'AzureFirewallSubnet'
        properties: {
          addressPrefix: azureFirewallSubnetAddressSpace
        }
      }
      {
        name: 'GatewaySubnet'
        properties: {
          addressPrefix: azureGatewaySubnetAddressSpace
        }
      }
      {
        name: 'AzureBastionSubnet'
        properties: {
          addressPrefix: azureBastionSubnetAddressSpace
          networkSecurityGroup: {
            id: bastionNetworkNsg.id
          }
        }
      }
    ]
  }
}

resource hubVnetName_Microsoft_Insights_default 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  name: 'default'
  scope: hubVnet
  properties: {
    workspaceId: hubLa.id
    metrics: [
      {
        category: 'AllMetrics'
        enabled: true
      }
    ]
  }
  dependsOn: []
}

resource hubFwPips 'Microsoft.Network/publicIpAddresses@2020-05-01' = [
  for item in hubFwPipNames: {
    name: item
    location: location
    sku: {
      name: 'Standard'
    }
    properties: {
      publicIPAllocationMethod: 'Static'
      idleTimeoutInMinutes: 4
      publicIPAddressVersion: 'IPv4'
    }
  }
]

resource fwPolicies 'Microsoft.Network/firewallPolicies@2020-11-01' = {
  name: fwPoliciesName
  location: firewallPolicyLocation
  properties: {
    basePolicy: {
      id: baseFirewallPoliciesId
    }
    sku: {
      tier: 'Standard'
    }
    threatIntelMode: 'Deny'
    threatIntelWhitelist: {
      ipAddresses: []
    }
    dnsSettings: {
      servers: []
      enableProxy: true
    }
  }
}

resource fwPoliciesName_DefaultDnatRuleCollectionGroup 'Microsoft.Network/firewallPolicies/ruleCollectionGroups@2020-11-01' = {
  parent: fwPolicies
  name: 'DefaultDnatRuleCollectionGroup'
  location: location
  properties: {
    priority: 100
    ruleCollections: []
  }
}

resource fwPoliciesName_DefaultApplicationRuleCollectionGroup 'Microsoft.Network/firewallPolicies/ruleCollectionGroups@2020-11-01' = {
  parent: fwPolicies
  name: 'DefaultApplicationRuleCollectionGroup'
  location: location
  properties: {
    priority: 300
    ruleCollections: []
  }
  dependsOn: [fwPoliciesName_DefaultDnatRuleCollectionGroup]
}

resource fwPoliciesName_DefaultNetworkRuleCollectionGroup 'Microsoft.Network/firewallPolicies/ruleCollectionGroups@2020-11-01' = {
  parent: fwPolicies
  name: 'DefaultNetworkRuleCollectionGroup'
  location: location
  properties: {
    priority: 200
    ruleCollections: []
  }
  dependsOn: [fwPoliciesName_DefaultApplicationRuleCollectionGroup]
}

resource hubFw 'Microsoft.Network/azureFirewalls@2020-11-01' = {
  name: hubFwName
  location: location
  zones: ['1', '2', '3']
  properties: {
    additionalProperties: {}
    sku: {
      name: 'AZFW_VNet'
      tier: 'Standard'
    }
    threatIntelMode: 'Deny'
    ipConfigurations: [
      {
        name: hubFwPipNames[0]
        properties: {
          subnet: {
            id: resourceId(
              'Microsoft.Network/virtualNetworks/subnets',
              hubVNetName,
              'AzureFirewallSubnet'
            )
          }
          publicIPAddress: {
            id: resourceId(
              'Microsoft.Network/publicIpAddresses',
              hubFwPipNames[0]
            )
          }
        }
      }
      {
        name: hubFwPipNames[1]
        properties: {
          publicIPAddress: {
            id: resourceId(
              'Microsoft.Network/publicIpAddresses',
              hubFwPipNames[1]
            )
          }
        }
      }
      {
        name: hubFwPipNames[2]
        properties: {
          publicIPAddress: {
            id: resourceId(
              'Microsoft.Network/publicIpAddresses',
              hubFwPipNames[2]
            )
          }
        }
      }
    ]
    natRuleCollections: []
    networkRuleCollections: []
    applicationRuleCollections: []
    firewallPolicy: {
      id: fwPolicies.id
    }
  }
  dependsOn: [
    hubFwPips
    hubVnet
    fwPoliciesName_DefaultNetworkRuleCollectionGroup
  ]
}

resource hubFwName_Microsoft_Insights_default 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  name: 'default'
  scope: hubFw
  properties: {
    workspaceId: hubLa.id
    logs: [
      {
        categoryGroup: 'allLogs'
        enabled: true
      }
    ]
    metrics: [
      {
        category: 'AllMetrics'
        enabled: true
      }
    ]
  }
  dependsOn: []
}

resource regionFlowLowStorageAccount 'Microsoft.Storage/storageAccounts@2021-02-01' = {
  name: regionFlowLowStorageAccountName
  location: location
  sku: {
    name: 'standard_LRS'
  }
  kind: 'StorageV2'
  properties: {
    accessTier: 'Hot'
    minimumTlsVersion: 'TLS1_2'
    supportsHttpsTrafficOnly: true
    allowBlobPublicAccess: false
    allowSharedKeyAccess: false
    networkAcls: {
      bypass: 'AzureServices'
      defaultAction: 'Deny'
      ipRules: []
    }
  }
}

resource regionFlowLowStorageAccountName_default_Microsoft_Insights_default 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  name: 'default'
  scope: regionFlowLowStorageAccount
  properties: {
    workspaceId: hubLa.id
    metrics: [
      {
        category: 'Transaction'
        enabled: true
      }
    ]
  }
  dependsOn: []
}

module flowLogsNsgBastion './virtualNetworkFlowlogs.bicep' = if (deployFlowLogResources) {
  name: 'nsgBastionFlowlogs'
  scope: resourceGroup('networkWatcherRG')
  params: {
    nsgId: bastionNetworkNsg.id
    flowlogStorageAccountId: regionFlowLowStorageAccount.id
    laId: hubLa.id
    location: location
  }
  dependsOn: []
}

/*** OUTPUTS ***/

output hubVnetId string = hubVnet.id
