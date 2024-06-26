targetScope = 'resourceGroup'

/*** PARAMETERS ***/

@description('Region for this implementation\'s resources that are directly used by all deployment stamps. Should be the same as the resource group location for added reliability. This region must support availability zones.')
@minLength(4)
param location string = resourceGroup().location

@description('For Azure resources that support native geo-redunancy, provide the location the redundant service will have its secondary. Should be different than the location parameter and ideally should be a paired region - https://learn.microsoft.com/azure/reliability/cross-region-replication-azure#azure-paired-regions. This region does not need to support availability zones.')
@minLength(4)
param geoRedundancyLocation string = 'centralus'

@description('Your GitHub account where you\'ve forked the repo.')
@minLength(1)
param gitHubAccountName string

@description('The branch used to run your workflow. For Jobs not tied to an environment, include the ref path for branch/tag based on the ref path used for triggering the workflow: repo:< Organization/Repository >:ref:< ref path>')
@minLength(1)
param gitHubRepoBranch string = 'main'

/*** VARIABLES ***/

var subRgUniqueString = uniqueString('aks', subscription().subscriptionId, resourceGroup().id)
var frontDoorName = 'bicycle${subRgUniqueString}'

/*** EXISTING RESOURCES ***/

/*** RESOURCES ***/

@description('Azure Firewall policies used in each region.')
resource fwPoliciesBase 'Microsoft.Network/firewallPolicies@2023-09-01' = {
  name: 'fw-policies-base'
  location: location
  properties: {
    sku: {
      tier: 'Standard'
    }
    threatIntelMode: 'Deny'
    threatIntelWhitelist: {
      ipAddresses: []
      fqdns: []
    }
    dnsSettings: {
      servers: []
      enableProxy: true
    }
  }

  resource fwPoliciesBaseName_DefaultNetworkRuleCollectionGroup 'ruleCollectionGroups' = {
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
              name: 'DNS'
              ipProtocols: [
                'UDP'
              ]
              sourceAddresses: [
                '*'
              ]
              sourceIpGroups: []
              destinationAddresses: [
                '*'
              ]
              destinationIpGroups: []
              destinationFqdns: []
              destinationPorts: [
                '53'
              ]
            }
          ]
          name: 'org-wide-allowed'
          priority: 100
        }
      ]
    }
  }
}

@description('Common logging sink for all resources.')
resource logAnalyticsWorkspace 'Microsoft.OperationalInsights/workspaces@2023-09-01' = {
  name: 'la-${subRgUniqueString}'
  location: location
  properties: {
    sku: {
      name: 'PerGB2018'
    }
    retentionInDays: 30
  }

  resource allPrometheus 'savedSearches@2020-08-01' = {
    name: 'AllPrometheus'
    properties: {
      eTag: '*'
      category: 'Prometheus'
      displayName: 'All collected Prometheus information'
      query: 'InsightsMetrics | where Namespace == "prometheus"'
      version: 1
    }
  }

  resource forbiddenReponsesOnIngress 'savedSearches@2020-08-01' = {
    name: 'ForbiddenReponsesOnIngress'
    properties: {
      eTag: '*'
      category: 'Prometheus'
      displayName: 'Increase number of forbidden response on the Ingress Controller'
      query: 'let value = toscalar(InsightsMetrics | where Namespace == "prometheus" and Name == "traefik_entrypoint_requests_total" | where parse_json(Tags).code == 403 | summarize Value = avg(Val) by bin(TimeGenerated, 5m) | summarize min = min(Value)); InsightsMetrics | where Namespace == "prometheus" and Name == "traefik_entrypoint_requests_total" | where parse_json(Tags).code == 403 | summarize AggregatedValue = avg(Val)-value by bin(TimeGenerated, 5m) | order by TimeGenerated | render barchart'
      version: 1
    }
  }

}

@description('Container Insights solution for our log sink.')
resource containerInsights 'Microsoft.OperationsManagement/solutions@2015-11-01-preview' = {
  name: 'ContainerInsights(${logAnalyticsWorkspace.name})'
  location: location
  properties: {
    workspaceResourceId: logAnalyticsWorkspace.id
  }
  plan: {
    name: 'ContainerInsights(${logAnalyticsWorkspace.name})'
    product: 'OMSGallery/ContainerInsights'
    promotionCode: ''
    publisher: 'Microsoft'
  }
}

@description('Key Vault solution for our log sink.')
resource keyVaultAnalytics 'Microsoft.OperationsManagement/solutions@2015-11-01-preview' = {
  name: 'KeyVaultAnalytics(${logAnalyticsWorkspace.name})'
  location: location
  properties: {
    workspaceResourceId: logAnalyticsWorkspace.id
  }
  plan: {
    name: 'KeyVaultAnalytics(${logAnalyticsWorkspace.name})'
    product: 'OMSGallery/KeyVaultAnalytics'
    promotionCode: ''
    publisher: 'Microsoft'
  }
}

@description('Container Registry used by all clusters in this solution. Replicated to a second region.')
resource commonAcr 'Microsoft.ContainerRegistry/registries@2023-11-01-preview' = {
  name: 'acraks${subRgUniqueString}'
  location: location
  sku: {
    name: 'Premium'
  }
  properties: {
    adminUserEnabled: false
    networkRuleSet: {
      defaultAction: 'Deny'
      ipRules: []
    }
    policies: {
      quarantinePolicy: {
        status: 'disabled'
      }
      trustPolicy: {
        type: 'Notary'
        status: 'disabled'
      }
      retentionPolicy: {
        days: 15
        status: 'enabled'
      }
    }
    publicNetworkAccess: 'Disabled'
    encryption: {
      status: 'disabled'
    }
    dataEndpointEnabled: true
    anonymousPullEnabled: false
    metadataSearch: 'Disabled'
    networkRuleBypassOptions: 'AzureServices'
    zoneRedundancy: 'Enabled'
  }

  resource geoRedundancyLocationA 'replications' = {
    name: geoRedundancyLocation
    location: geoRedundancyLocation
    properties: {}
  }
}

resource acrAzureDiagnostics 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  name: 'default'
  scope: commonAcr
  properties: {
    workspaceId: logAnalyticsWorkspace.id
    metrics: [
      {
        timeGrain: 'PT1M'
        category: 'AllMetrics'
        enabled: true
      }
    ]
    logs: [
      {
        categoryGroup: 'allLogs'
        enabled: true
      }
    ]
  }
}

@description('Saved query to detect failed pods.')
resource PodFailedScheduledQuery 'Microsoft.Insights/scheduledQueryRules@2023-03-15-preview' = {
  name: 'PodFailedScheduledQuery'
  location: location
  tags: {}
  properties: {
    description: 'Example from: https://learn.microsoft.com/azure/azure-monitor/containers/container-insights-log-alerts'
    severity: 3
    enabled: true
    evaluationFrequency: 'PT5M'
    scopes: [
      subscription().id
    ]
    windowSize: 'PT5M'
    overrideQueryTimeRange: 'P2D'
    criteria: {
      allOf: [
        {
          query: 'let trendBinSize = 1m;\r\nKubePodInventory\r\n| distinct ClusterName, TimeGenerated, _ResourceId\r\n| summarize ClusterSnapshotCount = count() by bin(TimeGenerated, trendBinSize), ClusterName, _ResourceId\r\n| join hint.strategy=broadcast (\r\nKubePodInventory\r\n| distinct ClusterName, Computer, PodUid, TimeGenerated, PodStatus\r\n| summarize TotalCount = count(),\r\nPendingCount = sumif(1, PodStatus =~ "Pending"),\r\nRunningCount = sumif(1, PodStatus =~ "Running"),\r\nSucceededCount = sumif(1, PodStatus =~ "Succeeded"),\r\nFailedCount = sumif(1, PodStatus =~ "Failed")\r\nby ClusterName, bin(TimeGenerated, trendBinSize)\r\n)\r\non ClusterName, TimeGenerated\r\n| extend UnknownCount = TotalCount - PendingCount - RunningCount - SucceededCount - FailedCount\r\n| project TimeGenerated,\r\nClusterName,\r\n_ResourceId,\r\nTotalCount = todouble(TotalCount) / ClusterSnapshotCount,\r\nPendingCount = todouble(PendingCount) / ClusterSnapshotCount,\r\nRunningCount = todouble(RunningCount) / ClusterSnapshotCount,\r\nSucceededCount = todouble(SucceededCount) / ClusterSnapshotCount,\r\nFailedCount = todouble(FailedCount) / ClusterSnapshotCount,\r\nUnknownCount = todouble(UnknownCount) / ClusterSnapshotCount'
          timeAggregation: 'Average'
          metricMeasureColumn: 'FailedCount'
          dimensions: [
            {
              name: 'ClusterName'
              operator: 'Include'
              values: [
                '*'
              ]
            }
          ]
          resourceIdColumn: '_ResourceId'
          operator: 'GreaterThan'
          threshold: 3
          failingPeriods: {
            numberOfEvaluationPeriods: 1
            minFailingPeriodsToAlert: 1
          }
        }
      ]
    }
  }
}

@description('Saved alert for any Azure Advisor notices.')
resource AllAzureAdvisorAlert 'Microsoft.Insights/activityLogAlerts@2020-10-01' = {
  name: 'AllAzureAdvisorAlert'
  location: 'global'
  properties: {
    scopes: [
      subscription().id
    ]
    condition: {
      allOf: [
        {
          field: 'category'
          equals: 'Recommendation'
        }
        {
          field: 'operationName'
          equals: 'Microsoft.Advisor/recommendations/available/action'
        }
      ]
    }
    actions: {
      actionGroups: []
    }
    enabled: true
    description: 'All Azure Advisor alerts'
  }
}

@description('WAF policy for Front Door (Premium).')
resource frontDoorWafPolicy 'Microsoft.Network/FrontDoorWebApplicationFirewallPolicies@2024-02-01' = {
  name: 'policyfd${subRgUniqueString}'
  location: 'global'
  sku: {
    name: 'Premium_AzureFrontDoor'
  }
  properties: {
    policySettings: {
      enabledState: 'Enabled'
      mode: 'Prevention'
      customBlockResponseStatusCode: 403
    }
    customRules: {
      rules: []
    }
    managedRules: {
      managedRuleSets: [
        {
          ruleSetType: 'DefaultRuleSet'
          ruleSetVersion: '1.0'
          ruleGroupOverrides: []
          exclusions: []
        }
      ]
    }
  }
}

@description('Front Door Profile (Premium) to be our global router. We use the premium SKU for its support of Private Link and managed WAF rules.')
resource frontDoorProfile 'Microsoft.Cdn/profiles@2024-02-01' = {
  name: 'afd-profile'
  location: 'global'
  sku: {
    name: 'Premium_AzureFrontDoor'
  }

  resource secPolicies 'securityPolicies' ={
    name: 'afd-sec-policies'
    properties: {
      parameters: {
        type: 'WebApplicationFirewall'
        wafPolicy: {
          id: frontDoorWafPolicy.id
        }
        associations: [
          {
            domains: [
              {
                id: endpoint.id
              }
            ]
            patternsToMatch: [
              '/*'
            ]
          }
        ]
      }
    }
  }

  resource endpoint 'afdEndpoints' = {
    name: frontDoorName
    location: 'global'
    properties: {
      autoGeneratedDomainNameLabelScope: 'TenantReuse'
      enabledState: 'Enabled'
    }

    resource frontDoorRoute 'routes' = {
      name: '${frontDoorName}-route'
      dependsOn: [
        frontDoorOriginGroup::frontDoorOrigin
      ]
      properties: {
        originGroup: {
          id: frontDoorOriginGroup.id
        }
        supportedProtocols: [
          'Https'
        ]
        patternsToMatch: [
          '/*'
        ]
        forwardingProtocol: 'HttpsOnly'
        linkToDefaultDomain: 'Enabled'
        httpsRedirect: 'Enabled'
        enabledState: 'Enabled'
      }
    }
  }

  resource frontDoorOriginGroup 'originGroups' = {
    name: 'afd-origingroup'
    properties: {
      loadBalancingSettings: {
        sampleSize: 4
        successfulSamplesRequired: 2
      }
      healthProbeSettings: {
        probePath: '/favicon.ico'
        probeRequestType: 'HEAD'
        probeProtocol: 'Https'
        probeIntervalInSeconds: 30
      }
    }

    resource frontDoorOrigin 'origins' = {
      name: 'afd-origin'
      properties: {
        hostName: 'bicycle.cloudapp.azure.com'
        originHostHeader: 'bicycle.cloudapp.azure.com'        
        httpPort: 80
        httpsPort: 443
        priority: 1
        weight: 50
        enabledState: 'Enabled'
      }
    }
  }
}

@description('WAF policies logs for Azure Front Door (Premium).')
resource afdWafPolicies_diagnosticSettings 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  name: 'default'
  scope: frontDoorProfile
  properties: {
    workspaceId: logAnalyticsWorkspace.id
    logs: [
      {
        category: 'FrontDoorWebApplicationFirewallLog'
        enabled: true
        retentionPolicy: {
          days: 0
          enabled: true
        }
      }
    ]
  }
}

@description('Create the Azure credentials for the GitHub CD workflow')
resource ghActionFederatedIdentity 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-07-31-preview' = {
  name: 'ghActionFederatedIdentity'
  location: location

  resource federatedCredentials 'federatedIdentityCredentials' = {
    name: 'ghActionFederatedIdentity'
    properties: {
      audiences: [
        'api://AzureADTokenExchange'
      ]
      issuer: 'https://token.actions.githubusercontent.com'
      subject: 'repo:${gitHubAccountName}/aks-baseline-multi-region:ref:refs/heads/${gitHubRepoBranch}'
    }
  }
}

/*** OUTPUTS ***/

output logAnalyticsWorkspaceId string = logAnalyticsWorkspace.id
output containerRegistryId string = commonAcr.id
output containerRegistryName string = commonAcr.name
output fqdn string = frontDoorProfile::endpoint.properties.hostName
output frontDoorName string = frontDoorProfile.name
output frontDoorBackendPoolName string = 'MultiClusterBackendPool'
output baseFirewallPoliciesId string = fwPoliciesBase.id
output githubFederatedIdentityClientId string = ghActionFederatedIdentity.properties.clientId
output githubFederatedIdentityPrincipalId string = ghActionFederatedIdentity.properties.principalId
