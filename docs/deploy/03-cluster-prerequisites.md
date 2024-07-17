# Deploy the AKS cluster prerequisites and shared services

In the prior step, you [prep for Microsoft Entra integration](./02-auth.md); now follows the next step in the [AKS baseline multicluster reference implementation](/README.md) which is deploying the shared service instances.

## Expected results

Following these steps will result in the provisioning of the shared Azure resources needed for an AKS multicluster solution.

| Object                          | Purpose                                                                                                                                                                                                                                                                                             |
|:------------------------------- |:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| NetworkWatcherRG Resource Group  | Contains regional Network Watchers. (Most subscriptions already have this.) |
| Azure Container Registry         | A single Azure Container Registry instance for those container images shared across multiple clusters |
| Azure Log Analytics Workspace    | A centralized Log Analytics workspace where all the logs are collected |
| Azure Front Door                 | Azure Front Door routes traffic to the fastest and available (healthy) backend. Public IP FQDNs emitted by the spoke network deployments are being configured in advance as Azure Front Door's backends. These regional public IPs are later assigned to the Azure Application Gateways frontend IP configuration. |
| Azure Firewall Policy base rules | Azure Firewall rules that apply at the entire organization level. These rules are typically cluster agnostic, so they can be shared by them all. |

## Steps

1. Login into the Azure subscription that you'll be deploying the Azure resources into.

   > :book: The networking team logins into the Azure subscription. At Contoso Bicycle, all of their regional hubs are in the same, centrally-managed subscription.

   ```bash
   az login -t $TENANTID_AZURERBAC_AKS_MRB
   ```

1. Check for a pre-existing resource group with the name NetworkWatcherRG, if it doesn't exist then create it.

    ```bash
    if [ $(az group exists --name NetworkWatcherRG) = false ]; then
    az group create --name NetworkWatcherRG --location centralus
    fi
    ```

    If your subscription is managed in such a way that Azure Network Watcher resources are found in a resource group other than the Azure default of `networkWatcherRG` or they do not use the Azure default `NetworkWatcher_<region>` naming convention, you will need to adjust the various ARM templates to compensate. Network Watchers are singletons (per region) in subscriptions, and organizations often manage them (and Flow Logs) via Azure Policy. This walkthrough assumes default naming conventions as set by Azure's [automatic deployment feature of Network Watchers](https://learn.microsoft.com/azure/network-watcher/network-watcher-create).

   If at any time during the deployment you get an error stating "**resource 'NetworkWatcher_\<region>' not found**", you will need to skip flow log creation by passing `false` to that ARM template's `deployFlowLogResources` parameter or you can manually create the required Network Watcher with that name.

1. Create the shared services resource group for your AKS clusters.

   > :book: The app team working on behalf of business unit 0001 (BU001) is about to deploy a new app (Application ID: 0042). This application needs to be deployed in a multiregion cluster infrastructure. But first the app team is required to assess the services that could be shared across the multiple clusters they are planning to create. To do this they are looking at global or regional but geo-replicated services that are not cluster but workload specific.
   >
   > They create a new resource group to contain all shared infrastructure resources.

   ```bash
   # The location you select here will be the location for all shared resources
   SHARED_RESOURCES_LOCATION=eastus2
   export SHARED_RESOURCE_GROUP_NAME_AKS_MRB="rg-bu0001a0042-shared-${SHARED_RESOURCES_LOCATION}"
   
   # [This takes less than one minute.]
   az group create --name $SHARED_RESOURCE_GROUP_NAME_AKS_MRB --location $SHARED_RESOURCES_LOCATION
   ```

1. Deploy the AKS cluster prerequisites and shared services.

   > :book: The app team is about to provision a few shared Azure resources. One is a non-regional and rest are regional, but more importantly they are deployed independently from their AKS clusters.
   >
   > | Azure Resource                                                                                                | Non-Regional | East US 2 | Central US |
   > |:------------------------------------------------------------------------------------------------------------- | :----------: | :-------: | :--------: |
   > | [Log Analytics in Azure Monitor](https://learn.microsoft.com/azure/azure-monitor/logs/log-analytics-overview) |              |     ✓     |            |
   > | [Azure Container Registry](https://learn.microsoft.com/azure/container-registry/)                             |              |     ✓     |     ✓      |
   > | [Azure Front Door (Premium)](https://learn.microsoft.com/azure/frontdoor/classic-overview)                    |      ✓       |           |            |
   > | [Azure Firewall Policy](https://learn.microsoft.com/azure/firewall-manager/policy-overview)                   |              |     ✓     |            |
   > | [Managed identity with GitHub federation](https://learn.microsoft.com/azure/developer/github/connect-from-azure) |              |     ✓     |            |

   > **Azure Monitor logs solution**
   >
   > The app team is creating multiple clusters for its new workload (Application ID: a0042). This array of clusters is a multiregion infrastructure solution composed by multiple Azure resources that regularly emit logs to Azure Monitor. All the collected data is stored in a [centralized Log Analytics workspace for the ease of operations](https://learn.microsoft.com/azure/azure-monitor/logs/workspace-design) after confirming there is no need to split workspaces due to scale. The app team estimates that the ingestion rate is going to be less than `6GB/minute`, so they expect not to be throttled as this is supported by the default rate limit. If it was required, they could grow by changing this setup eventually. In other words, the design decision is to create a single Azure Log Analytics workspace instance in the `eastus2` region, and that is going to be shared among their multiple clusters. Additionally, there is no business requirement for a consolidated cross business units view at this moment, so the centralization is great option for them. Something the app team also considered while making a final decision is the fact that migrating from a *centralized* solution to a *decentralized* one can be much easier than doing it the other way around. As a result, the single workspace being created is a workload specific workspace, and these are some of the Azure services sending data to it:
   >
   > - Azure Container Registry
   > - Azure Application Gateway
   > - Azure Key Vault
   >
   > In the future, the app team is considering to enforce the Azure resources to send their Azure Diagnostics logs with an Azure Policy as well as granting different users access rights to keep the data in isolation using Azure RBAC, something that is possible within a single workspace.
   >
   > :bulb: Azure Log Analytics can be modeled in different ways depending on your organizational needs. It can be *centralized* as in this reference implementation, or *decentralized* or a combination of both, which is known as *hybrid*. Azure Log Analytics workspaces are in a geographic location for Data Storage; consider, for higher availability, a distributed solution as the recommended approach instead. If you opt for a *centralized* solution, you need to be sure that the geo data residency is not going to be an issue, and be aware that cross-region data transfer costs will apply.

   > **Geo-Replicated Azure Container Registry**
   >
   > :book: The app team is starting to lay down the groundwork for multiregion availability, and they know that centralizing Azure resources might introduce single point of failures. Therefore, the app team is tasked to assess how the resources could be shared efficiently without losing reliability. When looking at the Azure container registry, it adds at least one additional complexity which is the proximity while pulling large container images. Based on this the team realizes that the *networking io* is going to be an important factor, so having presence in multiple regions looks promising. Although managing registry instances per region instead of shared a single one could mitigate the risk of having a region down and improve latency, this approach won't be falling back automatically nor replicating images by requiring in both cases manual intervention or additional procedures. That is the reason why, the team selected the **Premium** tier that offers [Geo-Replication](https://learn.microsoft.com/azure/container-registry/container-registry-geo-replication) as a built-in feature; giving them the ability to share a single registry, higher availability, and at same time reducing network latency. The app team plans to geo-replicate the registries to the same regions where their AKS clusters are going to be deployed (`East US 2` and `Central US`), as this is the recommendation to optimize the DNS resolution. They pay close attention to the replicated regions, as they want no more regions than needed since the business unit (bu0001) incurs Premium SKU registry fees for *each region* they geo-replicate to. Under this configuration, they will pay *two* times Premium per month to get region proximity and to ensure no extra network egress fees from distant regions.
   >
   > The app team is instructed to build the smallest container images they can. This is something they could achieve by following the [builder pattern](https://docs.docker.com/develop/develop-images/multistage-build/#before-multi-stage-builds) or the [mutli-stage builds](https://docs.docker.com/develop/develop-images/multistage-build/#use-multi-stage-builds). Both approaches will produce final smaller container images that are meant to be for runtime-only. This will be beneficial in many ways but mainly in the speed of replication as well as in the transfer costs. A key feature as part of Azure Container Registry's geo-replication is that it will only replicate unique layers, also further reducing data transfer across regions.
   >
   > In case of a region is down, the app team is now covered by the Azure Traffic Manager in the background that comes on the scene to help deriving traffic to the registry located in the region that is closest to their multiple clusters in terms of network latency.
   >
   > After this initial design decision at the Azure Container Registry level, the app team can also consider analyzing how they could tactically expand into [Availability Zones](https://learn.microsoft.com/azure/container-registry/zone-redundancy) as a way of being even more resilient.
   >
   > :bulb: Another benefit of having geo-replication is that permissions are now centralized in a single registry instance simplifying the security management a lot. Every AKS cluster owns a kubelet *System Managed Identity* by design, and that identity is the one being granted with permissions against this shared Azure Container Registry instance. At the same time, these identities can get individually assigned with role permissions in other Azure resources that are meant to be cluster-specific preventing them from cross pollination effects (i.e. Azure Key Vault). As things develop, the combination of [Availability Zones](https://learn.microsoft.com/azure/container-registry/zone-redundancy) for redundancy within a region, and geo-replication across multiple regions, is the recommendation when looking for the highest reliability and performance of a container registry.

   > **Azure Front Door**
   >
   > :book: The app team is about to deploy Azure Application instances in every region ahead of their corresponding cluster. It represents a new challenge for them as they need to globally manage the traffic from their clients, and route to the different regions to achieve enhanced reliability; aligning to the [Geode cloud design pattern](https://learn.microsoft.com/azure/architecture/patterns/geodes). They plan to have both regions initially active, and respond from the one which is closest to the client sending the HTTP requests. Therefore, it results in an active/active availability strategy, but they need to failover to a single region in case of a region outage. As a consequence of this last requirement, the load balancing can not be a simple round robin over the closest regions, but it also needs to be aware of the health of their backends, and derive the traffic accordingly. Two well known Azure services can perform multi-geo redundancy and closest region routing, they are: Azure Front Door and Azure Traffic Manager. To make final decision between these two, the Contoso organization is also seeing added benefits in Azure Front Door like better performance at the TLS negotiation, rate limiting capability and IP ACL-ing.

   ```bash
   # [This takes about two minutes.]
   az deployment group create -g $SHARED_RESOURCE_GROUP_NAME_AKS_MRB -f shared-svcs-stamp.bicep -p gitHubAccountName=$GITHUB_USERNAME_AKS_MRB
   ```

### Save your work in-progress

```bash
# run the saveenv.sh script at any time to save environment variables created above to aks_baseline.env
./saveenv.sh

# if your terminal session gets reset, you can source the file to reload the environment variables
# source aks_baseline.env
```

### Next step

:arrow_forward: [Deploy the hub-spoke network topology](./04-networking.md)
