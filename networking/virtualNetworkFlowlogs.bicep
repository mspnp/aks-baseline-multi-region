targetScope = 'resourceGroup'

/*** PARAMETERS ***/

param nsgId string
param flowlogStorageAccountId string
param laId string
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

/*** VARIABLES ***/

/*** RESOURCES ***/

resource flowLogs 'Microsoft.Network/networkWatchers/flowLogs@2020-05-01' = {
  name: 'NetworkWatcher_${location}/fl${guid(nsgId)}'
  location: location
  properties: {
    targetResourceId: nsgId
    storageId: flowlogStorageAccountId
    enabled: true
    format: {
      version: 2
    }
    flowAnalyticsConfiguration: {
      networkWatcherFlowAnalyticsConfiguration: {
        enabled: true
        workspaceResourceId: laId
        trafficAnalyticsInterval: 10
      }
    }
    retentionPolicy: {
      days: 365
      enabled: true
    }
  }
}

/*** OUTPUTS ***/
