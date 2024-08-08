targetScope = 'resourceGroup'

/*** PARAMETERS ***/

@description('Subnet resource Ids for all AKS clusters nodepools in all attached spokes to allow necessary outbound traffic through the firewall')
param nodepoolSubnetResourceIds array

@description('The hub\'s regional affinity. All resources tied to this hub will also be homed in this region.  The network team maintains this approved regional list which is a subset of regions with Availability Zone support.')
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

/*** RESOURCES ***/

resource laHub 'Microsoft.OperationalInsights/workspaces@2020-08-01' = {
  name: 'la-hub-${location}-${uniqueString(vnetHub.id)}'
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

resource nsgBastionSubnet 'Microsoft.Network/networkSecurityGroups@2020-05-01' = {
  name: 'nsg-${location}-bastion'
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

resource nsgBastionSubnet_diagnosticSettings 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  name: 'default'
  scope: nsgBastionSubnet
  properties: {
    workspaceId: laHub.id
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

resource vnetHub 'Microsoft.Network/virtualNetworks@2020-05-01' = {
  name: 'vnet-${location}-hub'
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
            id: nsgBastionSubnet.id
          }
        }
      }
    ]
  }

  resource azureFirewallSubnet 'subnets' existing = {
    name: 'AzureFirewallSubnet'
  }
}

resource vnetHub_diagnosticSettings 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  name: 'default'
  scope: vnetHub
  properties: {
    workspaceId: laHub.id
    metrics: [
      {
        category: 'AllMetrics'
        enabled: true
      }
    ]
  }
  dependsOn: []
}

var numFirewallIpAddressesToAssign = 3
resource pipsAzureFirewall 'Microsoft.Network/publicIpAddresses@2020-05-01' = [for i in range(0, numFirewallIpAddressesToAssign): {
    name: 'pip-fw-${location}-${padLeft(i, 2, '0')}'
    location: location
    sku: {
      name: 'Standard'
    }
    properties: {
      publicIPAllocationMethod: 'Static'
      idleTimeoutInMinutes: 4
      publicIPAddressVersion: 'IPv4'
    }
}]

resource pipAzureFirewall_diagnosticSetting 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = [for i in range(0, numFirewallIpAddressesToAssign): {
  name: 'default'
  scope: pipsAzureFirewall[i]
  properties: {
    workspaceId: laHub.id
    logs: [
      {
        categoryGroup: 'audit'
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
}]

resource ipgNodepoolSubnet 'Microsoft.Network/ipGroups@2023-11-01' = {
  name: 'ipg-${location}-AksNodepools'
  location: location
  properties: {
    ipAddresses: [for item in nodepoolSubnetResourceIds: reference(item, '2020-05-01').addressPrefix]
  }
}

resource fwPolicy 'Microsoft.Network/firewallPolicies@2024-01-01' = {
  name: 'fw-policies-${location}'
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

  resource defaultDnaRuleCollectionGroup 'ruleCollectionGroups' = {
    name: 'DefaultDnatRuleCollectionGroup'
    properties: {
      priority: 100
      ruleCollections: []
    }
    dependsOn: [
      hubFirewall
    ]
  }

  resource defaultNetworkRuleCollectionGroup 'ruleCollectionGroups' = {  
    name: 'DefaultNetworkRuleCollectionGroup'
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
                ipgNodepoolSubnet.id
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
      hubFirewall
      defaultDnaRuleCollectionGroup
    ]
  }

  resource defaultApplicationRuleCollectionGroup 'ruleCollectionGroups' = {
    name: 'DefaultApplicationRuleCollectionGroup'
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
                '*.hcp.${location}.azmk8s.io'
              ]
              targetUrls: []
              terminateTLS: false
              sourceAddresses: []
              destinationAddresses: []
              sourceIpGroups: [
                ipgNodepoolSubnet.id
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
                ipgNodepoolSubnet.id
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
                ipgNodepoolSubnet.id
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
                #disable-next-line no-hardcoded-env-urls // Disabling this rule because we explicitly want to allow Microsoft Entra ID authentication for the application, and this scenario is specific to the public Azure cloud.
                'login.microsoftonline.com'
              ]
              targetUrls: []
              terminateTLS: false
              sourceAddresses: []
              destinationAddresses: []
              sourceIpGroups: [
                ipgNodepoolSubnet.id
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
                ipgNodepoolSubnet.id
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
                ipgNodepoolSubnet.id
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
                ipgNodepoolSubnet.id
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
                ipgNodepoolSubnet.id
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
                #disable-next-line no-hardcoded-env-urls // Disabling this rule because these specific FQDNs should be allowed (https://learn.microsoft.com/azure/aks/outbound-rules-control-egress#required-fqdn--application-rules-3).
                'data.policy.core.windows.net'
                #disable-next-line no-hardcoded-env-urls
                'store.policy.core.windows.net'
              ]
              targetUrls: []
              terminateTLS: false
              sourceAddresses: []
              destinationAddresses: []
              sourceIpGroups: [
                ipgNodepoolSubnet.id
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
                ipgNodepoolSubnet.id
              ]
            }
          ]
          name: 'Flux-Requirements'
          priority: 300
        }
      ]
    }
    dependsOn: [
      hubFirewall
      defaultNetworkRuleCollectionGroup
    ]
  }
}

resource hubFirewall 'Microsoft.Network/azureFirewalls@2020-11-01' = {
  name: 'fw-${location}'
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
    ipConfigurations: [for i in range(0, numFirewallIpAddressesToAssign): {
      name: pipsAzureFirewall[i].name
      properties: {
        subnet: (0 == i) ? {
          id: vnetHub::azureFirewallSubnet.id
        } : null
        publicIPAddress: {
          id: pipsAzureFirewall[i].id
        }
      }
    }]
    natRuleCollections: []
    networkRuleCollections: []
    applicationRuleCollections: []
    firewallPolicy: {
      id: fwPolicy.id
    }
  }
  dependsOn: [
    pipsAzureFirewall
  ]
}

resource hubFirewall_diagnosticSettings 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  name: 'default'
  scope: hubFirewall
  properties: {
    workspaceId: laHub.id
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
  name: take('stnfl${location}${uniqueString(resourceGroup().id)}', 24)
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

resource regionFlowLowStorageAccount_diagnosticSettings 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  name: 'default'
  scope: regionFlowLowStorageAccount
  properties: {
    workspaceId: laHub.id
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
    nsgId: nsgBastionSubnet.id
    flowlogStorageAccountId: regionFlowLowStorageAccount.id
    laId: laHub.id
    location: location
  }
  dependsOn: []
}

/*** OUTPUTS ***/

output hubVnetId string = vnetHub.id
