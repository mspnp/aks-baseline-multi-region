targetScope = 'resourceGroup'

/*** PARAMETERS ***/

@description('Subnet resource Ids for all AKS clusters nodepools in all attached spokes to allow necessary outbound traffic through the firewall')
param nodepoolSubnetResourceIds array

@description('The hub\'s regional affinity. All resources tied to this hub will also be homed in this region.  The network team maintains this approved regional list which is a subset of zones with Availability Zone support.')
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
param location string = 'eastus2'

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

var aksIpGroupName = 'ipg-${location}-AksNodepools'
var baseFwPipName = 'pip-fw-${location}'
var hubFwPipNames_var = [
  '${baseFwPipName}-default'
  '${baseFwPipName}-01'
  '${baseFwPipName}-02'
]
var hubFwName = 'fw-${location}'
var hubVNetName = 'vnet-${location}-hub'
var bastionNetworkNsgName = 'nsg-${location}-bastion'
var hubLaName = 'la-hub-${location}-${uniqueString(hubVnet.id)}'
var fwPoliciesName = 'fw-policies-${location}'
var regionFlowLowStorageAccountName = take('stnfl${location}${uniqueString(resourceGroup().id)}', 24)

/*** RESOURCES ***/

resource hubLa 'Microsoft.OperationalInsights/workspaces@2020-08-01' = {
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
          destinationPortRanges: [
            '8080'
            '5701'
          ]
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
          destinationPortRanges: [
            '8080'
            '5701'
          ]
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

resource bastionNetworkNsgName_Microsoft_Insights_default 'Microsoft.Network/networkSecurityGroups/providers/diagnosticSettings@2017-05-01-preview' = {
  name: '${bastionNetworkNsgName}/Microsoft.Insights/default'
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
  dependsOn: [
    bastionNetworkNsg
  ]
}

resource hubVnet 'Microsoft.Network/virtualNetworks@2020-05-01' = {
  name: hubVNetName
  location: location
  properties: {
    addressSpace: {
      addressPrefixes: [
        hubVnetAddressSpace
      ]
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

resource hubVnetName_Microsoft_Insights_default 'Microsoft.Network/virtualNetworks/providers/diagnosticSettings@2017-05-01-preview' = {
  name: '${hubVNetName}/Microsoft.Insights/default'
  properties: {
    workspaceId: hubLa.id
    metrics: [
      {
        category: 'AllMetrics'
        enabled: true
      }
    ]
  }
  dependsOn: [
    hubVnet
  ]
}

resource hubFwPipNames 'Microsoft.Network/publicIpAddresses@2020-05-01' = [
  for item in hubFwPipNames_var: {
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

resource aksIpGroup 'Microsoft.Network/ipGroups@2020-05-01' = {
  name: aksIpGroupName
  location: location
  properties: {
    ipAddresses: [for item in nodepoolSubnetResourceIds: reference(item, '2020-05-01').addressPrefix]
  }
}

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
    ruleCollections: [
      {
        ruleCollectionType: 'FirewallPolicyFilterRuleCollection'
        action: {
          type: 'Allow'
        }
        rules: [
          {
            ruleType: 'ApplicationRule'
            name: 'nodes-to-api-server'
            protocols: [
              {
                protocolType: 'Https'
                port: 443
              }
            ]
            fqdnTags: []
            webCategories: []
            targetFqdns: [
              '*.hcp.eastus2.azmk8s.io'
            ]
            targetUrls: []
            terminateTLS: false
            sourceAddresses: []
            destinationAddresses: []
            sourceIpGroups: [
              aksIpGroup.id
            ]
          }
          {
            ruleType: 'ApplicationRule'
            name: 'microsoft-container-registry'
            protocols: [
              {
                protocolType: 'Https'
                port: 443
              }
            ]
            fqdnTags: []
            webCategories: []
            targetFqdns: [
              'mcr.microsoft.com'
              '*.data.mcr.microsoft.com'
            ]
            targetUrls: []
            terminateTLS: false
            sourceAddresses: []
            destinationAddresses: []
            sourceIpGroups: [
              aksIpGroup.id
            ]
          }
          {
            ruleType: 'ApplicationRule'
            name: 'management-plane'
            protocols: [
              {
                protocolType: 'Https'
                port: 443
              }
            ]
            fqdnTags: [
              'AzureKubernetesService'
            ]
            webCategories: []
            targetFqdns: []
            targetUrls: []
            terminateTLS: false
            sourceAddresses: []
            destinationAddresses: []
            sourceIpGroups: [
              aksIpGroup.id
            ]
          }
          {
            ruleType: 'ApplicationRule'
            name: 'entra-id-auth'
            protocols: [
              {
                protocolType: 'Https'
                port: 443
              }
            ]
            fqdnTags: []
            webCategories: []
            targetFqdns: [
              'login.microsoftonline.com'
            ]
            targetUrls: []
            terminateTLS: false
            sourceAddresses: []
            destinationAddresses: []
            sourceIpGroups: [
              aksIpGroup.id
            ]
          }
          {
            ruleType: 'ApplicationRule'
            name: 'apt-get'
            protocols: [
              {
                protocolType: 'Https'
                port: 443
              }
            ]
            fqdnTags: []
            webCategories: []
            targetFqdns: [
              'packages.microsoft.com'
            ]
            targetUrls: []
            terminateTLS: false
            sourceAddresses: []
            destinationAddresses: []
            sourceIpGroups: [
              aksIpGroup.id
            ]
          }
          {
            ruleType: 'ApplicationRule'
            name: 'cluster-binaries'
            protocols: [
              {
                protocolType: 'Https'
                port: 443
              }
            ]
            fqdnTags: []
            webCategories: []
            targetFqdns: [
              'acs-mirror.azureedge.net'
            ]
            targetUrls: []
            terminateTLS: false
            sourceAddresses: []
            destinationAddresses: []
            sourceIpGroups: [
              aksIpGroup.id
            ]
          }
          {
            ruleType: 'ApplicationRule'
            name: 'ubuntu-security-patches'
            protocols: [
              {
                protocolType: 'Http'
                port: 80
              }
            ]
            fqdnTags: []
            webCategories: []
            targetFqdns: [
              'security.ubuntu.com'
              'azure.archive.ubuntu.com'
              'changelogs.ubuntu.com'
            ]
            targetUrls: []
            terminateTLS: false
            sourceAddresses: []
            destinationAddresses: []
            sourceIpGroups: [
              aksIpGroup.id
            ]
          }
          {
            ruleType: 'ApplicationRule'
            name: 'azure-monitor-addon'
            protocols: [
              {
                protocolType: 'Https'
                port: 443
              }
            ]
            fqdnTags: []
            webCategories: []
            targetFqdns: [
              '*.ods.opinsights.azure.com'
              '*.oms.opinsights.azure.com'
              'eastus2.monitoring.azure.com'
            ]
            targetUrls: []
            terminateTLS: false
            sourceAddresses: []
            destinationAddresses: []
            sourceIpGroups: [
              aksIpGroup.id
            ]
          }
          {
            ruleType: 'ApplicationRule'
            name: 'azure-policy-addon'
            protocols: [
              {
                protocolType: 'Https'
                port: 443
              }
            ]
            fqdnTags: []
            webCategories: []
            targetFqdns: [
              'data.policy.core.windows.net'
              'store.policy.core.windows.net'
            ]
            targetUrls: []
            terminateTLS: false
            sourceAddresses: []
            destinationAddresses: []
            sourceIpGroups: [
              aksIpGroup.id
            ]
          }
        ]
        name: 'AKS-Global-Requirements'
        priority: 200
      }
      {
        ruleCollectionType: 'FirewallPolicyFilterRuleCollection'
        action: {
          type: 'Allow'
        }
        rules: [
          {
            ruleType: 'ApplicationRule'
            name: 'flux-to-github'
            protocols: [
              {
                protocolType: 'Https'
                port: 443
              }
            ]
            fqdnTags: []
            webCategories: []
            targetFqdns: [
              'github.com'
              'api.github.com'
            ]
            targetUrls: []
            terminateTLS: false
            sourceAddresses: []
            destinationAddresses: []
            sourceIpGroups: [
              aksIpGroup.id
            ]
          }
        ]
        name: 'Flux-Requirements'
        priority: 300
      }
    ]
  }
  dependsOn: [
    fwPoliciesName_DefaultDnatRuleCollectionGroup
  ]
}

resource fwPoliciesName_DefaultNetworkRuleCollectionGroup 'Microsoft.Network/firewallPolicies/ruleCollectionGroups@2020-11-01' = {
  parent: fwPolicies
  name: 'DefaultNetworkRuleCollectionGroup'
  location: location
  properties: {
    priority: 200
    ruleCollections: [
      {
        ruleCollectionType: 'FirewallPolicyFilterRuleCollection'
        action: {
          type: 'Allow'
        }
        rules: [
          {
            ruleType: 'NetworkRule'
            name: 'pod-to-api-server'
            ipProtocols: [
              'TCP'
            ]
            sourceAddresses: []
            sourceIpGroups: [
              aksIpGroup.id
            ]
            destinationAddresses: [
              'AzureCloud.${location}'
            ]
            destinationIpGroups: []
            destinationFqdns: []
            destinationPorts: [
              '443'
            ]
          }
        ]
        name: 'AKS-Global-Requirements'
        priority: 200
      }
    ]
  }
  dependsOn: [
    fwPoliciesName_DefaultApplicationRuleCollectionGroup
  ]
}

resource hubFw 'Microsoft.Network/azureFirewalls@2020-11-01' = {
  name: hubFwName
  location: location
  zones: [
    '1'
    '2'
    '3'
  ]
  properties: {
    additionalProperties: {}
    sku: {
      name: 'AZFW_VNet'
      tier: 'Standard'
    }
    threatIntelMode: 'Deny'
    ipConfigurations: [
      {
        name: hubFwPipNames_var[0]
        properties: {
          subnet: {
            id: resourceId('Microsoft.Network/virtualNetworks/subnets', hubVNetName, 'AzureFirewallSubnet')
          }
          publicIPAddress: {
            id: resourceId('Microsoft.Network/publicIpAddresses', hubFwPipNames_var[0])
          }
        }
      }
      {
        name: hubFwPipNames_var[1]
        properties: {
          publicIPAddress: {
            id: resourceId('Microsoft.Network/publicIpAddresses', hubFwPipNames_var[1])
          }
        }
      }
      {
        name: hubFwPipNames_var[2]
        properties: {
          publicIPAddress: {
            id: resourceId('Microsoft.Network/publicIpAddresses', hubFwPipNames_var[2])
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
    hubFwPipNames
    hubVnet
    fwPoliciesName_DefaultNetworkRuleCollectionGroup
  ]
}

resource hubFwName_Microsoft_Insights_default 'Microsoft.Network/azureFirewalls/providers/diagnosticSettings@2021-05-01-preview' = {
  name: '${hubFwName}/Microsoft.Insights/default'
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
  dependsOn: [
    hubFw
  ]
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

resource regionFlowLowStorageAccountName_Microsoft_Insights_default 'Microsoft.Storage/storageAccounts/providers/diagnosticSettings@2017-05-01-preview' = {
  name: '${regionFlowLowStorageAccountName}/Microsoft.Insights/default'
  properties: {
    workspaceId: hubLa.id
    logs: []
    metrics: [
      {
        category: 'Transaction'
        enabled: true
      }
    ]
  }
  dependsOn: [
    regionFlowLowStorageAccount
  ]
}

resource regionFlowLowStorageAccountName_default_Microsoft_Insights_default 'Microsoft.Storage/storageAccounts/blobServices/providers/diagnosticsettings@2017-05-01-preview' = {
  name: '${regionFlowLowStorageAccountName}/default/Microsoft.Insights/default'
  properties: {
    workspaceId: hubLa.id
    metrics: [
      {
        category: 'Transaction'
        enabled: true
      }
    ]
  }
  dependsOn: [
    regionFlowLowStorageAccount
  ]
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
