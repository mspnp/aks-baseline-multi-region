targetScope = 'resourceGroup'

/*** PARAMETERS ***/

@description('The shared Log Analytics workspace Id')
param logAnalyticsWorkspaceId string

@description('The shared Azure Container Registry Id')
param containerRegistryId string

@description('The application instance id helps to generate a unique application instance identifier for multiple instances of the same application. This number is also going to be used to derive its adjacent resources details when needed')
@allowed([
  '03'
  '04'
])
param appInstanceId string

@description('The AKS cluster Internal Load Balancer IP Address')
param clusterInternalLoadBalancerIpAddress string

@description('The regional network spoke VNet Resource ID that the cluster will be joined to')
@minLength(79)
param targetVnetResourceId string

@description('Microsoft Entra group in the identified tenant that will be granted the highly privileged cluster-admin role.')
param clusterAdminEntraGroupObjectId string

@description('Your AKS control plane Cluster API authentication tenant')
param k8sControlPlaneAuthorizationTenantId string

@description('The certificate data for app gateway TLS termination. It is base64')
param appGatewayListenerCertificate string

@description('The Base64 encoded AKS Ingress Controller public certificate (as .crt or .cer) to be stored in Azure Key Vault as secret and referenced by Azure Application Gateway as a trusted root certificate.')
param aksIngressControllerCertificate string

@description('IP ranges authorized to contact the Kubernetes API server. Passing an empty array will result in no IP restrictions. If any are provided, remember to also provide the public IP of the egress Azure Firewall otherwise your nodes will not be able to talk to the API server (e.g. Flux).')
param clusterAuthorizedIPRanges array = []

@description('AKS Service, Node Pool, and supporting services (Key Vault, App Gateway, etc) region. This needs to be the same region as the vnet provided in these parameters.')
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
])
param location string = 'eastus2'
param kubernetesVersion string = '1.29'

@description('Your cluster will be bootstrapped from this git repo.')
param gitOpsBootstrappingRepoHttpsUrl string = 'https://github.com/mspnp/aks-baseline-multiregion'

@description('Your cluster will be bootstrapped from this branch in the identified git repo.')
param gitOpsBootstrappingRepoBranch string = 'main'

@description('Your cluster will be bootstrapped from this directory under cluster-manifests.')
param gitOpsBootstrappingRepoDirectoryName string = 'region1'

@description('Domain name to use for App Gateway and AKS ingress.')
param domainName string = 'contoso.com'

/*** VARIABLES ***/
var orgAppId = 'BU0001A0042'
var appId = '${orgAppId}-${appInstanceId}'

var subRgUniqueString = uniqueString('aks', subscription().subscriptionId, resourceGroup().id)
var clusterName = 'aks-${subRgUniqueString}'
var agwName = 'apw-${clusterName}'

var aksIngressDomainName = 'aks-ingress.${domainName}'
var aksBackendDomainName = '${toLower(appId)}.${aksIngressDomainName}'

/*** EXISTING TENANT RESOURCES ***/

// Built-in 'Kubernetes cluster pod security restricted standards for Linux-based workloads' Azure Policy for Kubernetes initiative definition
var policyResourceIdAKSLinuxRestrictive = tenantResourceId('Microsoft.Authorization/policySetDefinitions', '42b8ef37-b724-4e24-bbc8-7a7708edfe00')

// Built-in 'Kubernetes clusters should be accessible only over HTTPS' Azure Policy for Kubernetes policy definition
var policyResourceIdEnforceHttpsIngress = tenantResourceId('Microsoft.Authorization/policyDefinitions', '1a5b4dca-0b6f-4cf5-907c-56316bc1bf3d')

// Built-in 'Kubernetes clusters should use internal load balancers' Azure Policy for Kubernetes policy definition
var policyResourceIdEnforceInternalLoadBalancers = tenantResourceId('Microsoft.Authorization/policyDefinitions', '3fc4dc25-5baf-40d8-9b05-7fe74c1bc64e')

// Built-in 'Kubernetes cluster containers should run with a read only root file system' Azure Policy for Kubernetes policy definition
var policyResourceIdRoRootFilesystem = tenantResourceId('Microsoft.Authorization/policyDefinitions', 'df49d893-a74c-421d-bc95-c663042e5b80')

// Built-in 'AKS container CPU and memory resource limits should not exceed the specified limits' Azure Policy for Kubernetes policy definition
var policyResourceIdEnforceResourceLimits = tenantResourceId('Microsoft.Authorization/policyDefinitions', 'e345eecc-fa47-480f-9e88-67dcc122b164')

// Built-in 'AKS containers should only use allowed images' Azure Policy for Kubernetes policy definition
var policyResourceIdEnforceImageSource = tenantResourceId('Microsoft.Authorization/policyDefinitions', 'febd0533-8e55-448f-b837-bd0e06f16469')

/*** EXISTING SUBSCRIPTION RESOURCES ***/

// Built-in Azure RBAC role that is applied to a cluster to grant its monitoring agent's identity with publishing metrics and push alerts permissions.
resource monitoringMetricsPublisherRole 'Microsoft.Authorization/roleDefinitions@2022-05-01-preview' existing = {
  name: '3913510d-42f4-4e42-8a64-420c390055eb'
  scope: subscription()
}

// Built-in Azure RBAC role that is applied a Key Vault to grant with metadata, certificates, keys and secrets read privileges.  Granted to App Gateway's managed identity.
resource keyVaultReaderRole 'Microsoft.Authorization/roleDefinitions@2022-05-01-preview' existing = {
  name: 'acdd72a7-3385-48ef-bd42-f606fba81ae7'
  scope: subscription()
}

// Built-in Azure RBAC role that is applied to a Key Vault to grant with secrets content read privileges. Granted to both Key Vault and our workload's identity.
resource keyVaultSecretsUserRole 'Microsoft.Authorization/roleDefinitions@2018-01-01-preview' existing = {
  name: '4633458b-17de-408a-b874-0445c86b69e6'
  scope: subscription()
}

resource nodeResourceGroup 'Microsoft.Resources/resourceGroups@2024-03-01' existing = {
  name: 'rg-${clusterName}-nodepools'
  scope: subscription()
}

// Shared resources resource group
resource sharedResourceGroup 'Microsoft.Resources/resourceGroups@2024-03-01' existing = {
  scope: subscription()
  name: split(containerRegistryId, '/')[4]
}

/*** EXISTING SHARED RESOURCES ***/

// Azure Container Registry
resource acr 'Microsoft.ContainerRegistry/registries@2023-11-01-preview' existing = {
  scope: sharedResourceGroup
  name: split(containerRegistryId, '/')[8]
}

// Log Analytics Workspace
resource la 'Microsoft.OperationalInsights/workspaces@2023-09-01' existing = {
  scope: sharedResourceGroup
  name: split(logAnalyticsWorkspaceId, '/')[8]
}

resource sci 'Microsoft.OperationsManagement/solutions@2015-11-01-preview' existing = {
  scope: sharedResourceGroup
  name: 'ContainerInsights(${la.name})'
}

/*** EXISTING SPOKE RESOURCES ***/

// Spoke resource group
resource targetResourceGroup 'Microsoft.Resources/resourceGroups@2024-03-01' existing = {
  scope: subscription()
  name: split(targetVnetResourceId, '/')[4]
}

// Spoke virtual network
resource targetVirtualNetwork 'Microsoft.Network/virtualNetworks@2023-11-01' existing = {
  scope: targetResourceGroup
  name: last(split(targetVnetResourceId, '/'))

  // Spoke virutual network's subnet for the cluster nodes
  resource snetClusterNodes 'subnets' existing = {
    name: 'snet-clusternodes'
  }

  // Spoke virutual network's subnet for the internal load balancers
  resource snetPrivatelinkendpoints 'subnets' existing = {
    name: 'snet-clusteringressservices'
  }

  // Spoke virutual network's subnet for application gateway
  resource snetApplicationGateway 'subnets' existing = {
    name: 'snet-applicationgateway'
  }
}

/*** RESOURCES ***/

// The control plane identity used by the cluster. Used for networking access (VNET joining and DNS updating)
resource miClusterControlPlane 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-07-31-preview' = {
  name: 'mi-${clusterName}-controlplane'
  location: location
}

// User Managed Identity that App Gateway is assigned. Used for Azure Key Vault Access.
resource miAppGatewayFrontend 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-07-31-preview' = {
  name: 'mi-appgateway-frontend'
  location: location
}

// User Managed Identity for the cluster's ingress controller pods via Workload Identity. Used for Azure Key Vault Access.
resource podmiIngressController 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-07-31-preview' = {
  name: 'podmi-ingress-controller'
  location: location
}

resource ficIngressController 'Microsoft.ManagedIdentity/userAssignedIdentities/federatedIdentityCredentials@2023-07-31-preview' = {
  parent: podmiIngressController
  name: 'ingress-controller'
  properties: {
    issuer: mc.properties.oidcIssuerProfile.issuerURL
    subject: 'system:serviceaccount:a0042:traefik-ingress-controller'
    audiences: [
      'api://AzureADTokenExchange'
    ]
  }
}

resource kv 'Microsoft.KeyVault/vaults@2023-07-01' = {
  name: 'kv-${clusterName}'
  location: location
  properties: {
    accessPolicies: [
      {
        tenantId: miAppGatewayFrontend.properties.tenantId
        objectId: miAppGatewayFrontend.properties.principalId
        permissions: {
          secrets: [
            'get'
          ]
          certificates: [
            'get'
          ]
          keys: []
        }
      }
      {
        tenantId: podmiIngressController.properties.tenantId
        objectId: podmiIngressController.properties.principalId
        permissions: {
          secrets: [
            'get'
          ]
          certificates: [
            'get'
          ]
          keys: []
        }
      }
    ]
    sku: {
      family: 'A'
      name: 'standard'
    }
    tenantId: subscription().tenantId
    networkAcls: {
      bypass: 'AzureServices'
      defaultAction: 'Allow'
      ipRules: []
      virtualNetworkRules: []
    }
    enabledForDeployment: false
    enabledForDiskEncryption: false
    enabledForTemplateDeployment: false
    enableSoftDelete: true
  }

  resource kvsGatewayExternalCert 'secrets@2023-07-01' = {
    name: 'gateway-external-pfx-cert'
    properties: {
      value: appGatewayListenerCertificate
    }
  }
  
  resource kvsAppGwIngressInternalAksIngressTls 'secrets@2023-07-01' = {
    name: 'appgw-ingress-internal-aks-ingress-tls'
    properties: {
      value: aksIngressControllerCertificate
    }
  }
  
}

resource kv_diagnosticSettings 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  scope: kv
  name: 'default'
  properties: {
    workspaceId: la.id
    logs: [
      {
        category: 'AuditEvent'
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
}

// Grant the Azure Application Gateway managed identity with key vault reader role permissions; this allows pulling frontend and backend certificates.
resource kvMiAppGatewayFrontendSecretsUserRole_roleAssignment 'Microsoft.Authorization/roleAssignments@2020-10-01-preview' = {
  scope: kv
  name: guid(resourceGroup().id, 'mi-appgateway-frontend', keyVaultSecretsUserRole.id)
  properties: {
    roleDefinitionId: keyVaultSecretsUserRole.id
    principalId: miAppGatewayFrontend.properties.principalId
    principalType: 'ServicePrincipal'
  }
}

// Grant the Azure Application Gateway managed identity with key vault reader role permissions; this allows pulling frontend and backend certificates.
resource kvMiAppGatewayFrontendKeyVaultReader_roleAssignment 'Microsoft.Authorization/roleAssignments@2020-10-01-preview' = {
  scope: kv
  name: guid(resourceGroup().id, 'mi-appgateway-frontend', keyVaultReaderRole.id)
  properties: {
    roleDefinitionId: keyVaultReaderRole.id
    principalId: miAppGatewayFrontend.properties.principalId
    principalType: 'ServicePrincipal'
  }
}

// Grant the AKS cluster ingress controller's managed workload identity with Key Vault reader role permissions; this allows our ingress controller to pull certificates.
resource kvPodMiIngressControllerSecretsUserRole_roleAssignment 'Microsoft.Authorization/roleAssignments@2020-10-01-preview' = {
  scope: kv
  name: guid(resourceGroup().id, 'podmi-ingress-controller', keyVaultSecretsUserRole.id)
  properties: {
    roleDefinitionId: keyVaultSecretsUserRole.id
    principalId: podmiIngressController.properties.principalId
    principalType: 'ServicePrincipal'
  }
}

// Grant the AKS cluster ingress controller's managed workload identity with Key Vault reader role permissions; this allows our ingress controller to pull certificates
resource kvPodMiIngressControllerKeyVaultReader_roleAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  scope: kv
  name: guid(resourceGroup().id, 'podmi-ingress-controller', keyVaultReaderRole.id)
  properties: {
    roleDefinitionId: keyVaultReaderRole.id
    principalId: podmiIngressController.properties.principalId
    principalType: 'ServicePrincipal'
  }
}

module ndEnsureClusterIdentityHasRbacToSelfManagedResources 'nested_EnsureClusterIdentityHasRbacToSelfManagedResources.bicep' = {
  name: 'EnsureClusterIdentityHasRbacToSelfManagedResources'
  scope: targetResourceGroup
  params: {
    miClusterControlPlanePrincipalId: miClusterControlPlane.properties.principalId
    clusterControlPlaneIdentityName: miClusterControlPlane.name
    targetVirtualNetworkName: targetVirtualNetwork.name
  }
}

resource pdzKv 'Microsoft.Network/privateDnsZones@2020-06-01' = {
  name: 'privatelink.vaultcore.azure.net'
  location: 'global'
  properties: {}

  // Enabling Azure Key Vault Private Link on cluster vnet.
  resource vnetlnk 'virtualNetworkLinks' = {
    name: 'to_${targetVirtualNetwork.name}'
    location: 'global'
    properties: {
      virtualNetwork: {
        id: targetVirtualNetwork.id
      }
      registrationEnabled: false
    }
  }
}

resource peKv 'Microsoft.Network/privateEndpoints@2023-11-01' = {
  name: 'pe-${kv.name}'
  location: location
  properties: {
    subnet: {
      id: targetVirtualNetwork::snetPrivatelinkendpoints.id
    }
    privateLinkServiceConnections: [
      {
        name: 'to_${targetVirtualNetwork.name}'
        properties: {
          privateLinkServiceId: kv.id
          groupIds: [
            'vault'
          ]
        }
      }
    ]
  }

  resource pdnszg 'privateDnsZoneGroups' = {
    name: 'default'
    properties: {
      privateDnsZoneConfigs: [
        {
          name: 'privatelink-akv-net'
          properties: {
            privateDnsZoneId: pdzKv.id
          }
        }
      ]
    }
  }
}

resource pdzAksIngress 'Microsoft.Network/privateDnsZones@2020-06-01' = {
  name: aksIngressDomainName
  location: 'global'

  resource aks_ingress_contoso_com_orgAppId 'A' = {
    name: toLower(orgAppId)
    properties: {
      ttl: 3600
      aRecords: [
        {
          ipv4Address: clusterInternalLoadBalancerIpAddress
        }
      ]
    }
  }

  resource vnetlnk 'virtualNetworkLinks' = {
    name: 'to_${targetVirtualNetwork.name}'
    location: 'global'
    properties: {
      virtualNetwork: {
        id: targetVnetResourceId
      }
      registrationEnabled: false
    }
  }  
}

resource mc 'Microsoft.ContainerService/managedClusters@2024-03-02-preview' = {
  name: clusterName
  location: location
  tags: {
    'Business unit': 'BU0001'
    'Application identifier': appId
  }
  properties: {
    kubernetesVersion: kubernetesVersion
    dnsPrefix: uniqueString(subscription().subscriptionId, resourceGroup().id, clusterName)
    agentPoolProfiles: [
      {
        name: 'npsystem'
        count: 3
        vmSize: 'Standard_DS2_v2'
        osDiskSizeGB: 80
        osDiskType: 'Ephemeral'
        osType: 'Linux'
        osSKU: 'AzureLinux'
        minCount: 3
        maxCount: 4
        vnetSubnetID: targetVirtualNetwork::snetClusterNodes.id
        enableAutoScaling: true
        enableCustomCATrust: false
        enableFIPS: false
        enableEncryptionAtHost: false
        type: 'VirtualMachineScaleSets'
        mode: 'System'
        scaleSetPriority: 'Regular'
        scaleSetEvictionPolicy: 'Delete'
        orchestratorVersion: kubernetesVersion
        enableNodePublicIP: false
        maxPods: 30
        availabilityZones: [
          '1'
          '2'
          '3'
        ]
        upgradeSettings: {
          maxSurge: '33%'
        }
        nodeTaints: [
          'CriticalAddonsOnly=true:NoSchedule'
        ]
      }
      {
        name: 'npuser01'
        count: 2
        vmSize: 'Standard_DS3_v2'
        osDiskSizeGB: 120
        osDiskType: 'Ephemeral'
        osType: 'Linux'
        osSKU: 'AzureLinux'
        minCount: 2
        maxCount: 5
        vnetSubnetID: targetVirtualNetwork::snetClusterNodes.id
        enableAutoScaling: true
        enableCustomCATrust: false
        enableFIPS: false
        enableEncryptionAtHost: false
        type: 'VirtualMachineScaleSets'
        mode: 'User'
        scaleSetPriority: 'Regular'
        scaleSetEvictionPolicy: 'Delete'
        orchestratorVersion: kubernetesVersion
        enableNodePublicIP: false
        maxPods: 30
        availabilityZones: [
          '1'
          '2'
          '3'
        ]
        upgradeSettings: {
          maxSurge: '33%'
        }
      }
    ]
    servicePrincipalProfile: {
      clientId: 'msi'
    }
    addonProfiles: {
      httpApplicationRouting: {
        enabled: false
      }
      ingressApplicationGateway: {
        enabled: false
      }
      omsagent: {
        enabled: true
        config: {
          logAnalyticsWorkspaceResourceId: la.id
        }
      }
      aciConnectorLinux: {
        enabled: false
      }
      azurepolicy: {
        enabled: true
        config: {
          version: 'v2'
        }
      }
      openServiceMesh: {
        enabled: false
      }
      kubeDashboard: {
        enabled: false
      }
      azureKeyvaultSecretsProvider: {
        enabled: true
        config: {
          enableSecretRotation: 'false'
        }
      }
    }
    nodeResourceGroup: nodeResourceGroup.name
    enableRBAC: true
    enablePodSecurityPolicy: false
    networkProfile: {
      networkPlugin: 'azure'
      networkPolicy: 'azure'
      networkDataplane: 'azure'
      outboundType: 'userDefinedRouting'
      loadBalancerSku: 'standard'
      loadBalancerProfile: {
        backendPoolType: 'nodeIPConfiguration'
      }
      serviceCidr: '172.16.0.0/16'
      dnsServiceIP: '172.16.0.10'
    }
    aadProfile: {
      managed: true
      enableAzureRBAC: false
      adminGroupObjectIDs: [
        clusterAdminEntraGroupObjectId
      ]
      tenantID: k8sControlPlaneAuthorizationTenantId
    }
    autoScalerProfile: {
      'balance-similar-node-groups': 'false'
      expander: 'random'
      'max-empty-bulk-delete': '10'
      'max-graceful-termination-sec': '600'
      'max-node-provision-time': '15m'
      'max-total-unready-percentage': '45'
      'new-pod-scale-up-delay': '0s'
      'ok-total-unready-count': '3'
      'scale-down-delay-after-add': '10m'
      'scale-down-delay-after-delete': '20s'
      'scale-down-delay-after-failure': '3m'
      'scale-down-unneeded-time': '10m'
      'scale-down-unready-time': '20m'
      'scale-down-utilization-threshold': '0.5'
      'scan-interval': '10s'
      'skip-nodes-with-local-storage': 'true'
      'skip-nodes-with-system-pods': 'true'
    }
    apiServerAccessProfile: {
      authorizedIPRanges: clusterAuthorizedIPRanges
      enablePrivateCluster: false
    }
    podIdentityProfile: {
      enabled: false
    }
    autoUpgradeProfile: {
      nodeOSUpgradeChannel: 'NodeImage'
      upgradeChannel: 'none'
    }
    disableLocalAccounts: true
    storageProfile: {  // By default, do not support native state storage, enable as needed to support workloads that require state
      blobCSIDriver: {
        enabled: false // Azure Blobs
      }
      diskCSIDriver: {
        enabled: false // Azure Disk
      }
      fileCSIDriver: {
        enabled: false // Azure Files
      }
      snapshotController: {
        enabled: false // CSI Snapshotter: https://github.com/kubernetes-csi/external-snapshotter
      }
    }
    securityProfile: {
      workloadIdentity: {
        enabled: false
      }
      imageCleaner: {
        enabled: false
        intervalHours: 120 // 5 days
      }
      azureKeyVaultKms: {
        enabled: false // Not enabled in the this deployment, as it is not used. Enable as needed.
      }
      nodeRestriction: {
        enabled: true // https://kubernetes.io/docs/reference/access-authn-authz/admission-controllers/#noderestriction
      }
      customCATrustCertificates: [] // Empty
      defender: {
        securityMonitoring: {
          enabled: false
        }
      }
    }
    oidcIssuerProfile: {
      enabled: true
    }
    enableNamespaceResources: false
    ingressProfile: {
      webAppRouting: {
        enabled: false
      }
    }
  }
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: {
      '${miClusterControlPlane.id}': {}
    }
  }
  sku: {
    name: 'Base'
    tier: 'Standard'
  }
  dependsOn: [
    paAKSLinuxRestrictive
    paEnforceHttpsIngress
    paEnforceImageSource
    paEnforceInternalLoadBalancers
    paEnforceResourceLimits
    paRoRootFilesystem
  ]

  resource os_maintenanceConfigurations 'maintenanceConfigurations' = {
    name: 'aksManagedNodeOSUpgradeSchedule'
    properties: {
      maintenanceWindow: {
        durationHours: 12
        schedule: {
          weekly: {
            dayOfWeek: 'Tuesday'
            intervalWeeks: 1
          }
        }
        startTime: '21:00'
      }
    }
  }
}

// Grant the Azure Monitor (fka as OMS) Agent's Managed Identity the metrics publisher role to push alerts
resource mcAmaAgentMonitoringMetricsPublisherRole_roleAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  scope: mc
  name: guid(mc.id, 'omsagent', monitoringMetricsPublisherRole.id)
  properties: {
    roleDefinitionId: monitoringMetricsPublisherRole.id
    principalId: mc.properties.addonProfiles.omsagent.identity.objectId
    principalType: 'ServicePrincipal'
  }
}

// Ensures that flux add-on (extension) is installed.
resource mc_diagnosticSettings 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  scope: mc
  name: 'default'
  properties: {
    workspaceId: la.id
    logs: [
      {
        category: 'cluster-autoscaler'
        enabled: true
      }
      {
        category: 'kube-controller-manager'
        enabled: true
      }
      {
        category: 'kube-audit-admin'
        enabled: true
      }
      {
        category: 'guard'
        enabled: true
      }
      {
        category: 'kube-scheduler'
        enabled: false // Only enable while tuning or triaging issues with scheduling. On a normally operating cluster there is minimal value, relative to the log capture cost, to keeping this always enabled.
      }
    ]
  }
}

resource mcFlux_extension 'Microsoft.KubernetesConfiguration/extensions@2023-05-01' = {
  scope: mc
  name: 'mcFlux_extension'
  properties: {
    extensionType: 'microsoft.flux'
    autoUpgradeMinorVersion: true
    releaseTrain: 'Stable'
    scope: {
      cluster: {
        releaseNamespace: 'flux-system'
      }
    }
    configurationSettings: {
      'helm-controller.enabled': 'false'
      'source-controller.enabled': 'true'
      'kustomize-controller.enabled': 'true'
      'notification-controller.enabled': 'false'
      'image-automation-controller.enabled': 'false'
      'image-reflector-controller.enabled': 'false'
    }
    configurationProtectedSettings: {}
  }
  dependsOn: [
    ensureClusterIdentityHasRbacToPullAcr
  ]
}

// Bootstraps your cluster using content from your repo.
resource mc_fluxConfiguration 'Microsoft.KubernetesConfiguration/fluxConfigurations@2024-04-01-preview' = {
  scope: mc
  name: 'bootstrap'
  properties: {
    scope: 'mc'
    namespace: 'flux-system'
    sourceKind: 'GitRepository'
    gitRepository: {
      url: gitOpsBootstrappingRepoHttpsUrl
      timeoutInSeconds: 180
      syncIntervalInSeconds: 300
      repositoryRef: {
        branch: gitOpsBootstrappingRepoBranch
      }
      sshKnownHosts: ''
      httpsUser: null
      httpsCACert: null
      localAuthRef: null
    }
    kustomizations: {
      unifed: {
        path: './cluster-manifests/${gitOpsBootstrappingRepoDirectoryName}'
        dependsOn: []
        timeoutInSeconds: 300
        syncIntervalInSeconds: 300
        retryIntervalInSeconds: 300
        prune: true
        force: false
      }
    }
  }
  dependsOn: [
    mcFlux_extension
    ensureClusterIdentityHasRbacToPullAcr
  ]
}

module ndEnsureClusterUserAssignedHasRbacToManageVMSS './nested_EnsureClusterUserAssignedHasRbacToManageVMSS.bicep' = {
  name: 'EnsureClusterUserAssignedHasRbacToManageVMSS'
  scope: nodeResourceGroup
  params: {
    kubeletidentityObjectId: mc.properties.identityProfile.kubeletidentity.objectId
  }
}

resource maHighNodeCPUUtilization 'Microsoft.Insights/metricAlerts@2018-03-01' = {
  name: 'Node CPU utilization high for ${clusterName} CI-1'
  location: 'global'
  properties: {
    autoMitigate: true
    scopes: [
      mc.id
    ]
    actions: []
    criteria: {
      allOf: [
        {
          criterionType: 'StaticThresholdCriterion'
          dimensions: [
            {
              name: 'host'
              operator: 'Include'
              values: [
                '*'
              ]
            }
          ]
          metricName: 'cpuUsagePercentage'
          metricNamespace: 'Insights.Container/nodes'
          name: 'Metric1'
          operator: 'GreaterThan'
          threshold: 80
          timeAggregation: 'Average'
          skipMetricValidation: true
        }
      ]
      'odata.type': 'Microsoft.Azure.Monitor.SingleResourceMultipleMetricCriteria'
    }
    description: 'Node CPU utilization across the mc.'
    enabled: true
    evaluationFrequency: 'PT1M'
    severity: 3
    targetResourceType: 'microsoft.containerservice/managedclusters'
    windowSize: 'PT5M'
  }
  dependsOn: [
    sci
  ]
}

resource maHighNodeWorkingSetMemoryUtilization 'Microsoft.Insights/metricAlerts@2018-03-01' = {
  name: 'Node working set memory utilization high for ${clusterName} CI-2'
  location: 'global'
  properties: {
    autoMitigate: true
    actions: []
    criteria: {
      allOf: [
        {
          criterionType: 'StaticThresholdCriterion'
          dimensions: [
            {
              name: 'host'
              operator: 'Include'
              values: [
                '*'
              ]
            }
          ]
          metricName: 'memoryWorkingSetPercentage'
          metricNamespace: 'Insights.Container/nodes'
          name: 'Metric1'
          operator: 'GreaterThan'
          threshold: 80
          timeAggregation: 'Average'
          skipMetricValidation: true
        }
      ]
      'odata.type': 'Microsoft.Azure.Monitor.SingleResourceMultipleMetricCriteria'
    }
    description: 'Node working set memory utilization across the mc.'
    enabled: true
    evaluationFrequency: 'PT1M'
    scopes: [
      mc.id
    ]
    severity: 3
    targetResourceType: 'microsoft.containerservice/managedclusters'
    windowSize: 'PT5M'
  }
}

resource maJobsCompletedMoreThan6HoursAgo 'Microsoft.Insights/metricAlerts@2018-03-01' = {
  name: 'Jobs completed more than 6 hours ago for ${clusterName} CI-11'
  location: 'global'
  properties: {
    autoMitigate: true
    actions: []
    criteria: {
      allOf: [
        {
          criterionType: 'StaticThresholdCriterion'
          dimensions: [
            {
              name: 'controllerName'
              operator: 'Include'
              values: [
                '*'
              ]
            }
            {
              name: 'kubernetes namespace'
              operator: 'Include'
              values: [
                '*'
              ]
            }
          ]
          metricName: 'completedJobsCount'
          metricNamespace: 'Insights.Container/pods'
          name: 'Metric1'
          operator: 'GreaterThan'
          threshold: 0
          timeAggregation: 'Average'
          skipMetricValidation: true
        }
      ]
      'odata.type': 'Microsoft.Azure.Monitor.SingleResourceMultipleMetricCriteria'
    }
    description: 'This alert monitors completed jobs (more than 6 hours ago).'
    enabled: true
    evaluationFrequency: 'PT1M'
    scopes: [
      mc.id
    ]
    severity: 3
    targetResourceType: 'microsoft.containerservice/managedclusters'
    windowSize: 'PT1M'
  }
  dependsOn: [
    sci
  ]
}

resource maHighContainerCPUUsage 'Microsoft.Insights/metricAlerts@2018-03-01' = {
  name: 'Container CPU usage violates the configured threshold for ${clusterName} CI-19'
  location: 'global'
  properties: {
    autoMitigate: true
    actions: []
    criteria: {
      allOf: [
        {
          criterionType: 'StaticThresholdCriterion'
          dimensions: [
            {
              name: 'controllerName'
              operator: 'Include'
              values: [
                '*'
              ]
            }
            {
              name: 'kubernetes namespace'
              operator: 'Include'
              values: [
                '*'
              ]
            }
          ]
          metricName: 'cpuThresholdViolated'
          metricNamespace: 'Insights.Container/containers'
          name: 'Metric1'
          operator: 'GreaterThan'
          threshold: 0  // This threshold is defined in the container-azm-ms-agentconfig.yaml file.
          timeAggregation: 'Average'
          skipMetricValidation: true
        }
      ]
      'odata.type': 'Microsoft.Azure.Monitor.SingleResourceMultipleMetricCriteria'
    }
    description: 'This alert monitors container CPU usage. It uses the threshold defined in the config map.'
    enabled: true
    evaluationFrequency: 'PT1M'
    scopes: [
      mc.id
    ]
    severity: 3
    targetResourceType: 'microsoft.containerservice/managedclusters'
    windowSize: 'PT5M'
  }
  dependsOn: [
    sci
  ]
}

resource maHighContainerWorkingSetMemoryUsage 'Microsoft.Insights/metricAlerts@2018-03-01' = {
  name: 'Container working set memory usage violates the configured threshold for ${clusterName} CI-20'
  location: 'global'
  properties: {
    autoMitigate: true
    actions: []
    criteria: {
      allOf: [
        {
          criterionType: 'StaticThresholdCriterion'
          dimensions: [
            {
              name: 'controllerName'
              operator: 'Include'
              values: [
                '*'
              ]
            }
            {
              name: 'kubernetes namespace'
              operator: 'Include'
              values: [
                '*'
              ]
            }
          ]
          metricName: 'memoryWorkingSetThresholdViolated'
          metricNamespace: 'Insights.Container/containers'
          name: 'Metric1'
          operator: 'GreaterThan'
          threshold: 0  // This threshold is defined in the container-azm-ms-agentconfig.yaml file.
          timeAggregation: 'Average'
          skipMetricValidation: true
        }
      ]
      'odata.type': 'Microsoft.Azure.Monitor.SingleResourceMultipleMetricCriteria'
    }
    description: 'This alert monitors container working set memory usage. It uses the threshold defined in the config map.'
    enabled: true
    evaluationFrequency: 'PT1M'
    scopes: [
      mc.id
    ]
    severity: 3
    targetResourceType: 'microsoft.containerservice/managedclusters'
    windowSize: 'PT5M'
  }
  dependsOn: [
    sci
  ]
}

resource maPodsInFailedState 'Microsoft.Insights/metricAlerts@2018-03-01' = {
  name: 'Pods in failed state for ${clusterName} CI-4'
  location: 'global'
  properties: {
    autoMitigate: true
    actions: []
    criteria: {
      allOf: [
        {
          criterionType: 'StaticThresholdCriterion'
          dimensions: [
            {
              name: 'phase'
              operator: 'Include'
              values: [
                'Failed'
              ]
            }
          ]
          metricName: 'podCount'
          metricNamespace: 'Insights.Container/pods'
          name: 'Metric1'
          operator: 'GreaterThan'
          threshold: 0
          timeAggregation: 'Average'
          skipMetricValidation: true
        }
      ]
      'odata.type': 'Microsoft.Azure.Monitor.SingleResourceMultipleMetricCriteria'
    }
    description: 'Pod status monitoring.'
    enabled: true
    evaluationFrequency: 'PT1M'
    scopes: [
      mc.id
    ]
    severity: 3
    targetResourceType: 'microsoft.containerservice/managedclusters'
    windowSize: 'PT5M'
  }
  dependsOn: [
    sci
  ]
}

resource maHighDiskUsage 'Microsoft.Insights/metricAlerts@2018-03-01' = {
  name: 'Disk usage high for ${clusterName} CI-5'
  location: 'global'
  properties: {
    autoMitigate: true
    actions: []
    criteria: {
      allOf: [
        {
          criterionType: 'StaticThresholdCriterion'
          dimensions: [
            {
              name: 'host'
              operator: 'Include'
              values: [
                '*'
              ]
            }
            {
              name: 'device'
              operator: 'Include'
              values: [
                '*'
              ]
            }
          ]
          metricName: 'DiskUsedPercentage'
          metricNamespace: 'Insights.Container/nodes'
          name: 'Metric1'
          operator: 'GreaterThan'
          threshold: 80
          timeAggregation: 'Average'
          skipMetricValidation: true
        }
      ]
      'odata.type': 'Microsoft.Azure.Monitor.SingleResourceMultipleMetricCriteria'
    }
    description: 'This alert monitors disk usage for all nodes and storage devices.'
    enabled: true
    evaluationFrequency: 'PT1M'
    scopes: [
      mc.id
    ]
    severity: 3
    targetResourceType: 'microsoft.containerservice/managedclusters'
    windowSize: 'PT5M'
  }
  dependsOn: [
    sci
  ]
}

resource maNodesInNotReadyStatus 'Microsoft.Insights/metricAlerts@2018-03-01' = {
  name: 'Nodes in not ready status for ${clusterName} CI-3'
  location: 'global'
  properties: {
    autoMitigate: true
    actions: []
    criteria: {
      allOf: [
        {
          criterionType: 'StaticThresholdCriterion'
          dimensions: [
            {
              name: 'status'
              operator: 'Include'
              values: [
                'NotReady'
              ]
            }
          ]
          metricName: 'nodesCount'
          metricNamespace: 'Insights.Container/nodes'
          name: 'Metric1'
          operator: 'GreaterThan'
          threshold: 0
          timeAggregation: 'Average'
          skipMetricValidation: true
        }
      ]
      'odata.type': 'Microsoft.Azure.Monitor.SingleResourceMultipleMetricCriteria'
    }
    description: 'Node status monitoring.'
    enabled: true
    evaluationFrequency: 'PT1M'
    scopes: [
      mc.id
    ]
    severity: 3
    targetResourceType: 'microsoft.containerservice/managedclusters'
    windowSize: 'PT5M'
  }
  dependsOn: [
    sci
  ]
}

resource maContainersGettingKilledOOM 'Microsoft.Insights/metricAlerts@2018-03-01' = {
  name: 'Containers getting OOM killed for ${clusterName} CI-6'
  location: 'global'
  properties: {
    autoMitigate: true
    actions: []
    criteria: {
      allOf: [
        {
          criterionType: 'StaticThresholdCriterion'
          dimensions: [
            {
              name: 'kubernetes namespace'
              operator: 'Include'
              values: [
                '*'
              ]
            }
            {
              name: 'controllerName'
              operator: 'Include'
              values: [
                '*'
              ]
            }
          ]
          metricName: 'oomKilledContainerCount'
          metricNamespace: 'Insights.Container/pods'
          name: 'Metric1'
          operator: 'GreaterThan'
          threshold: 0
          timeAggregation: 'Average'
          skipMetricValidation: true
        }
      ]
      'odata.type': 'Microsoft.Azure.Monitor.SingleResourceMultipleMetricCriteria'
    }
    description: 'This alert monitors number of containers killed due to out of memory (OOM) error.'
    enabled: true
    evaluationFrequency: 'PT1M'
    scopes: [
      mc.id
    ]
    severity: 3
    targetResourceType: 'microsoft.containerservice/managedclusters'
    windowSize: 'PT1M'
  }
  dependsOn: [
    sci
  ]
}

resource maHighPersistentVolumeUsage 'Microsoft.Insights/metricAlerts@2018-03-01' = {
  name: 'Persistent volume usage high for ${clusterName} CI-18'
  location: 'global'
  properties: {
    autoMitigate: true
    actions: []
    criteria: {
      allOf: [
        {
          criterionType: 'StaticThresholdCriterion'
          dimensions: [
            {
              name: 'podName'
              operator: 'Include'
              values: [
                '*'
              ]
            }
            {
              name: 'kubernetesNamespace'
              operator: 'Include'
              values: [
                '*'
              ]
            }
          ]
          metricName: 'pvUsageExceededPercentage'
          metricNamespace: 'Insights.Container/persistentvolumes'
          name: 'Metric1'
          operator: 'GreaterThan'
          threshold: 80
          timeAggregation: 'Average'
          skipMetricValidation: true
        }
      ]
      'odata.type': 'Microsoft.Azure.Monitor.SingleResourceMultipleMetricCriteria'
    }
    description: 'This alert monitors persistent volume utilization.'
    enabled: false
    evaluationFrequency: 'PT1M'
    scopes: [
      mc.id
    ]
    severity: 3
    targetResourceType: 'microsoft.containerservice/managedclusters'
    windowSize: 'PT5M'
  }
  dependsOn: [
    sci
  ]
}

resource maPodsNotInReadyState 'Microsoft.Insights/metricAlerts@2018-03-01' = {
  name: 'Pods not in ready state for ${clusterName} CI-8'
  location: 'global'
  properties: {
    autoMitigate: true
    actions: []
    criteria: {
      allOf: [
        {
          criterionType: 'StaticThresholdCriterion'
          dimensions: [
            {
              name: 'controllerName'
              operator: 'Include'
              values: [
                '*'
              ]
            }
            {
              name: 'kubernetes namespace'
              operator: 'Include'
              values: [
                '*'
              ]
            }
          ]
          metricName: 'PodReadyPercentage'
          metricNamespace: 'Insights.Container/pods'
          name: 'Metric1'
          operator: 'LessThan'
          threshold: 80
          timeAggregation: 'Average'
          skipMetricValidation: true
        }
      ]
      'odata.type': 'Microsoft.Azure.Monitor.SingleResourceMultipleMetricCriteria'
    }
    description: 'This alert monitors for excessive pods not in the ready state.'
    enabled: true
    evaluationFrequency: 'PT1M'
    scopes: [
      mc.id
    ]
    severity: 3
    targetResourceType: 'microsoft.containerservice/managedclusters'
    windowSize: 'PT5M'
  }
  dependsOn: [
    sci
  ]
}

resource maRestartingContainerCount 'Microsoft.Insights/metricAlerts@2018-03-01' = {
  name: 'Restarting container count for ${clusterName} CI-7'
  location: 'global'
  properties: {
    autoMitigate: true
    actions: []
    criteria: {
      allOf: [
        {
          criterionType: 'StaticThresholdCriterion'
          dimensions: [
            {
              name: 'kubernetes namespace'
              operator: 'Include'
              values: [
                '*'
              ]
            }
            {
              name: 'controllerName'
              operator: 'Include'
              values: [
                '*'
              ]
            }
          ]
          metricName: 'restartingContainerCount'
          metricNamespace: 'Insights.Container/pods'
          name: 'Metric1'
          operator: 'GreaterThan'
          threshold: 0
          timeAggregation: 'Average'
          skipMetricValidation: true
        }
      ]
      'odata.type': 'Microsoft.Azure.Monitor.SingleResourceMultipleMetricCriteria'
    }
    description: 'This alert monitors number of containers restarting across the cluster.'
    enabled: true
    evaluationFrequency: 'PT1M'
    scopes: [
      mc.id
    ]
    severity: 3
    targetResourceType: 'Microsoft.ContainerService/managedClusters'
    windowSize: 'PT1M'
  }
  dependsOn: [
    sci
  ]
}

resource paAKSLinuxRestrictive 'Microsoft.Authorization/policyAssignments@2024-04-01' = {
  name: guid(policyResourceIdAKSLinuxRestrictive, resourceGroup().id, clusterName)
  scope: resourceGroup()
  properties: {
    displayName: take('[${clusterName}] ${reference(policyResourceIdAKSLinuxRestrictive,'2021-06-01').displayName}', 120)
    description: reference(policyResourceIdAKSLinuxRestrictive, '2021-06-01').description
    policyDefinitionId: policyResourceIdAKSLinuxRestrictive
    parameters: {
      excludedNamespaces: {
        value: [
          'kube-system'
          'gatekeeper-system'
          'azure-arc'
          'flux-system'

          'cluster-baseline-settings'
        ]
      }
      effect: {
        value: 'Audit'
      }
    }
  }
}

resource paEnforceHttpsIngress 'Microsoft.Authorization/policyAssignments@2024-04-01' = {
  name: guid(policyResourceIdEnforceHttpsIngress, resourceGroup().id, clusterName)
  scope: resourceGroup()
  properties: {
    displayName: take('[${clusterName}] ${reference(policyResourceIdEnforceHttpsIngress,'2021-06-01').displayName}', 120)
    description: reference(policyResourceIdEnforceHttpsIngress, '2021-06-01').description
    policyDefinitionId: policyResourceIdEnforceHttpsIngress
    parameters: {
      excludedNamespaces: {
        value: []
      }
      effect: {
        value: 'Deny'
      }
    }
  }
}

resource paEnforceInternalLoadBalancers 'Microsoft.Authorization/policyAssignments@2024-04-01' = {
  name: guid(policyResourceIdEnforceInternalLoadBalancers, resourceGroup().id, clusterName)
  scope: resourceGroup()
  properties: {
    displayName: take('[${clusterName}] ${reference(policyResourceIdEnforceInternalLoadBalancers,'2021-06-01').displayName}', 120)
    description: reference(policyResourceIdEnforceInternalLoadBalancers, '2021-06-01').description
    policyDefinitionId: policyResourceIdEnforceInternalLoadBalancers
    parameters: {
      excludedNamespaces: {
        value: []
      }
      effect: {
        value: 'Deny'
      }
    }
  }
}

resource paRoRootFilesystem 'Microsoft.Authorization/policyAssignments@2024-04-01' = {
  name: guid(policyResourceIdRoRootFilesystem, resourceGroup().name, clusterName)
  scope: resourceGroup()
  properties: {
    displayName: take('[${clusterName}] ${reference(policyResourceIdRoRootFilesystem,'2021-06-01').displayName}', 120)
    description: reference(policyResourceIdRoRootFilesystem, '2021-06-01').description
    policyDefinitionId: policyResourceIdRoRootFilesystem
    parameters: {
      excludedNamespaces: {
        value: [
          'kube-system'
          'gatekeeper-system'
          'azure-arc'
          'flux-system'
        ]
      }
      effect: {
        value: 'Audit'
      }
    }
  }
}

resource paEnforceResourceLimits 'Microsoft.Authorization/policyAssignments@2024-04-01' = {
  name: guid(policyResourceIdEnforceResourceLimits, resourceGroup().id, clusterName)
  scope: resourceGroup()
  properties: {
    displayName: take('[${clusterName}] ${reference(policyResourceIdEnforceResourceLimits,'2021-06-01').displayName}', 120)
    description: reference(policyResourceIdEnforceResourceLimits, '2021-06-01').description
    policyDefinitionId: policyResourceIdEnforceResourceLimits
    parameters: {
      cpuLimit: {
        value: '1000m'
      }
      memoryLimit: {
        value: '512Mi'
      }
      excludedNamespaces: {
        value: [
          'kube-system'
          'gatekeeper-system'
          'azure-arc'
          'flux-system'
          'cluster-baseline-settings'
        ]
      }
      effect: {
        value: 'Deny'
      }
    }
  }
}

resource paEnforceImageSource 'Microsoft.Authorization/policyAssignments@2024-04-01' = {
  name: guid(
    policyResourceIdEnforceImageSource,
    resourceGroup().id,
    clusterName
  )
  scope: resourceGroup()
  properties: {
    displayName: take('[${clusterName}] ${reference(policyResourceIdEnforceImageSource,'2021-06-01').displayName}', 120)
    description: reference(policyResourceIdEnforceImageSource, '2021-06-01').description
    policyDefinitionId: policyResourceIdEnforceImageSource
    parameters: {
      allowedContainerImagesRegex: {
        value: '${acr.name}\\.azurecr\\.io\\/.+$|mcr\\.microsoft\\.com\\/.+$'
      }
      excludedNamespaces: {
        value: [
          'kube-system'
          'gatekeeper-system'
          'azure-arc'
          'flux-system'
        ]
      }
      effect: {
        value: 'Deny'
      }
    }
  }
}

resource st 'Microsoft.EventGrid/systemTopics@2021-12-01' = {
  name: clusterName
  location: location
  properties: {
    source: mc.id
    topicType: 'Microsoft.ContainerService.ManagedClusters'
  }
}

resource st_diagnosticSettings 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  scope: st
  name: 'default'
  properties: {
    workspaceId: la.id
    logs: [
      {
        category: 'DeliveryFailures'
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
}

resource wafPolicy 'Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies@2021-05-01' = {
  name: 'waf-${clusterName}'
  location: location
  properties: {
    policySettings: {
      fileUploadLimitInMb: 10
      state: 'Enabled'
      mode: 'Prevention'
    }
    managedRules: {
      managedRuleSets: [
        {
          ruleSetType: 'OWASP'
          ruleSetVersion: '3.2'
          ruleGroupOverrides: []
        }
        {
          ruleSetType: 'Microsoft_BotManagerRuleSet'
          ruleSetVersion: '1.0'
          ruleGroupOverrides: []
        }
      ]
    }
  }
}

resource agw 'Microsoft.Network/applicationGateways@2023-11-01' = {
  name: agwName
  location: location
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: {
      '${miAppGatewayFrontend.id}': {}
    }
  }
  zones: pickZones('Microsoft.Network', 'applicationGateways', location, 3)
  properties: {
    sku: {
      name: 'WAF_v2'
      tier: 'WAF_v2'
    }
    sslPolicy: {
      policyType: 'Custom'
      cipherSuites: [
        'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384'
        'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256'
      ]
      minProtocolVersion: 'TLSv1_2'
    }
    trustedRootCertificates: [
      {
        name: 'root-cert-wildcard-aks-ingress'
        properties: {
          keyVaultSecretId: kv::kvsAppGwIngressInternalAksIngressTls.properties.secretUri
        }
      }
    ]
    gatewayIPConfigurations: [
      {
        name: 'apw-ip-configuration'
        properties: {
          subnet: {
            id: targetVirtualNetwork::snetApplicationGateway.id
          }
        }
      }
    ]
    frontendIPConfigurations: [
      {
        name: 'apw-frontend-ip-configuration'
        properties: {
          publicIPAddress: {
            id: resourceId(subscription().subscriptionId, targetResourceGroup.name, 'Microsoft.Network/publicIpAddresses', 'pip-${appId}')
          }
        }
      }
    ]
    frontendPorts: [
      {
        name: 'port-443'
        properties: {
          port: 443
        }
      }
    ]
    autoscaleConfiguration: {
      minCapacity: 0
      maxCapacity: 10
    }
    firewallPolicy: {
      id: wafPolicy.id
    }
    enableHttp2: false
    sslCertificates: [
      {
        name: '${agwName}-ssl-certificate'
        properties: {
          keyVaultSecretId: kv::kvsGatewayExternalCert.properties.secretUri
        }
      }
    ]
    probes: [
      {
        name: 'probe-${aksBackendDomainName}'
        properties: {
          protocol: 'Https'
          path: '/favicon.ico'
          interval: 30
          timeout: 30
          unhealthyThreshold: 3
          pickHostNameFromBackendHttpSettings: true
          minServers: 0
          match: {}
        }
      }
    ]
    backendAddressPools: [
      {
        name: aksBackendDomainName
        properties: {
          backendAddresses: [
            {
              fqdn: aksBackendDomainName
            }
          ]
        }
      }
    ]
    backendHttpSettingsCollection: [
      {
        name: 'aks-ingress-backendpool-httpsettings'
        properties: {
          port: 443
          protocol: 'Https'
          cookieBasedAffinity: 'Disabled'
          pickHostNameFromBackendAddress: true
          requestTimeout: 20
          probe: {
            id: resourceId('Microsoft.Network/applicationGateways/probes', agwName, 'probe-${aksBackendDomainName}')
          }
          trustedRootCertificates: [
            {
              id: resourceId('Microsoft.Network/applicationGateways/trustedRootCertificates', agwName, 'root-cert-wildcard-aks-ingress')
            }
          ]
        }
      }
    ]
    httpListeners: [
      {
        name: 'listener-https'
        properties: {
          frontendIPConfiguration: {
            id: resourceId('Microsoft.Network/applicationGateways/frontendIPConfigurations', agwName, 'apw-frontend-ip-configuration')
          }
          frontendPort: {
            id: resourceId('Microsoft.Network/applicationGateways/frontendPorts', agwName, 'port-443')
          }
          protocol: 'Https'
          sslCertificate: {
            id: resourceId('Microsoft.Network/applicationGateways/sslCertificates', agwName, '${agwName}-ssl-certificate')
          }
          hostName: '${reference(resourceId(subscription().subscriptionId,targetResourceGroup.name,'Microsoft.Network/publicIpAddresses','pip-${appId}'),'2020-07-01','Full').properties.dnsSettings.domainNameLabel}.${location}.cloudapp.azure.com'
          hostNames: []
          requireServerNameIndication: true
        }
      }
    ]
    requestRoutingRules: [
      {
        name: 'apw-routing-rules'
        properties: {
          ruleType: 'Basic'
          priority: 1
          httpListener: {
            id: resourceId('Microsoft.Network/applicationGateways/httpListeners', agwName, 'listener-https')
          }
          backendAddressPool: {
            id: resourceId('Microsoft.Network/applicationGateways/backendAddressPools', agwName, aksBackendDomainName)
          }
          backendHttpSettings: {
            id: resourceId('Microsoft.Network/applicationGateways/backendHttpSettingsCollection', agwName, 'aks-ingress-backendpool-httpsettings')
          }
        }
      }
    ]
  }
  dependsOn: [
    peKv
    kvMiAppGatewayFrontendKeyVaultReader_roleAssignment
    kvMiAppGatewayFrontendSecretsUserRole_roleAssignment
  ]
}

resource agw_diagnosticSettings 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  scope: agw
  name: 'default'
  properties: {
    workspaceId: la.id
    logs: [
      {
        category: 'ApplicationGatewayAccessLog'
        enabled: true
      }
      {
        category: 'ApplicationGatewayPerformanceLog'
        enabled: true
      }
      {
        category: 'ApplicationGatewayFirewallLog'
        enabled: true
      }
    ]
  }
  dependsOn: []
}

module ensureClusterIdentityHasRbacToPullAcr './nested_EnsureClusterIdentityHasRbacToPullAcr.bicep' = {
  name: 'EnsureClusterIdentityHasRbacToPullAcr'
  scope: sharedResourceGroup
  params: {
    acrName: acr.name
    clusterId: mc.id
    kubeletidentityObjectId: mc.properties.identityProfile.kubeletidentity.objectId
  }
}

resource pdzAcr 'Microsoft.Network/privateDnsZones@2020-06-01' = {
  name: 'privatelink.azurecr.io'
  location: 'global'
  properties: {}

  resource vnetlnk 'virtualNetworkLinks' = {
    name: 'to_${targetVirtualNetwork.name}'
    location: 'global'
    properties: {
      virtualNetwork: {
        id: targetVirtualNetwork.id
      }
      registrationEnabled: false
    }
  }
}

resource peAcr 'Microsoft.Network/privateEndpoints@2023-11-01' = {
  name: 'pe-${acr.name}'
  location: location
  properties: {
    subnet: {
      id: targetVirtualNetwork::snetPrivatelinkendpoints.id
    }
    privateLinkServiceConnections: [
      {
        name: 'to_${targetVirtualNetwork.name}'
        properties: {
          privateLinkServiceId: acr.id
          groupIds: [
            'registry'
          ]
        }
      }
    ]
  }
  
  resource pdnszg 'privateDnsZoneGroups' = {
    name: 'default'
    properties: {
      privateDnsZoneConfigs: [
        {
          name: 'privatelink-azurecr-io'
          properties: {
            privateDnsZoneId: pdzAcr.id
          }
        }
      ]
    }
  }
}

/*** OUTPUTS ***/

output aksClusterName string = clusterName
output aksIngressControllerPodManagedIdentityClientId string = podmiIngressController.properties.clientId
output keyVaultName string = kv.name
output agwName string = agwName
