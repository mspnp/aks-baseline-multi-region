# Deploy the AKS cluster prerequisites and shared services

Now that you've [prepared for Microsoft Entra integration](./02-auth.md), the next step in the [AKS baseline multicluster reference implementation](/README.md) is to deploy the shared service instances. For multi-region clusters, there are multiple shared services.

## Expected results

Following these steps will result in the provisioning of the shared Azure resources needed for an AKS multicluster solution.

| Object | Purpose |
|:- |:- |
| NetworkWatcherRG resource group | Contains regional Network Watchers. (Most subscriptions already have this.) |
| Azure Container Registry | A single Azure Container Registry instance for those container images shared across multiple clusters. |
| Azure Log Analytics workspace | A centralized Log Analytics workspace where all the logs are collected. |
| Azure Front Door | Azure Front Door routes traffic to the fastest and available (healthy) origin. Public IP FQDNs emitted by the spoke network deployments are being configured in advance as Azure Front Door's backends. These regional public IPs are later assigned to the Azure Application Gateways frontend IP configuration. |
| Azure Firewall Policy base rules | Azure Firewall rules that apply at the entire organization level. These rules are typically cluster-agnostic, so they can be shared by all of the clusters. |

## Steps

1. Sign into the Azure subscription that you'll be deploying the Azure resources to.

   > :book: The networking team logins into the Azure subscription. At Contoso Bicycle, all of their regional hubs are in the same, centrally-managed subscription.

   ```bash
   az login -t $TENANTID_AZURERBAC_AKS_MRB
   ```

1. Check for a pre-existing resource group with the name NetworkWatcherRG. If it doesn't exist then create it.

   ```bash
   if [ $(az group exists --name NetworkWatcherRG) = false ]; then
   az group create --name NetworkWatcherRG --location centralus
   fi
   ```

   If your subscription is managed in such a way that Azure Network Watcher resources are found in a resource group other than the Azure default of `NetworkWatcherRG` or they do not use the Azure default `NetworkWatcher_<region>` naming convention, you will need to adjust the Bicep files to compensate. Network watchers are singleton resources per region and subscription. Organizations often manage them, and Flow Logs, by using Azure Policy. This walkthrough assumes default naming conventions as set by Azure's [automatic deployment feature of Network Watchers](https://learn.microsoft.com/azure/network-watcher/network-watcher-create).

   If at any time during the deployment you get an error stating "**resource 'NetworkWatcher_\<region>' not found**", you need to skip flow log creation by passing `false` to that Bicep file's `deployFlowLogResources` parameter, or you can manually create the required network watcher with the same name.

1. Create the shared services resource group for your AKS clusters.

   > :book: The app team working on behalf of business unit 0001 (BU001) is about to deploy a new app (Application ID: 0042). This application needs to be deployed in a multiregion cluster infrastructure. But first the app team is required to assess the services that could be shared across the multiple clusters they are planning to create. To do this they are looking at global or regional services that are geo-replicated. These services are workload-specific, not cluster-specific.
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
   > | Azure Resource                                                                                                   | Non-Regional | East US 2 | Central US |
   > |:---------------------------------------------------------------------------------------------------------------- | :----------: | :-------: | :--------: |
   > | [Log Analytics in Azure Monitor](https://learn.microsoft.com/azure/azure-monitor/logs/log-analytics-overview)    |              |     ✓     |            |
   > | [Azure Container Registry](https://learn.microsoft.com/azure/container-registry/)                                |              |     ✓     |     ✓      |
   > | [Azure Front Door (premium)](https://learn.microsoft.com/azure/frontdoor/front-door-overview)                    |      ✓       |           |            |
   > | [Azure Firewall Policy](https://learn.microsoft.com/azure/firewall-manager/policy-overview)                      |              |     ✓     |            |
   > | [Managed identity with GitHub federation](https://learn.microsoft.com/azure/developer/github/connect-from-azure) |              |     ✓     |            |

   > **Azure Monitor logs solution**
   >
   > The app team is creating multiple clusters for its new workload (Application ID: a0042). This array of clusters is a multi-region infrastructure solution composed of  multiple Azure resources, each of which regularly emit logs to Azure Monitor. All the collected data is stored in a [centralized Log Analytics workspace for the ease of operations](https://learn.microsoft.com/azure/azure-monitor/logs/workspace-design).
   >
   > The app team confirmed there is no need to split workspaces due to scale. The app team estimates that the ingestion rate is going to be less than 6GB per minute, so they expect not to be throttled as this is supported by the default rate limit. If it was required, they could grow by changing this setup eventually. In other words, the design decision is to create a single Azure Log Analytics workspace instance in the `eastus2` region, and that is going to be shared among their multiple clusters. Additionally, there is no business requirement for a consolidated cross business units view at this moment, so the centralization is great option for them.
   >
   > Something the app team also considered while making a final decision is the fact that migrating from a *centralized* solution to a *decentralized* one can be much easier than doing it the other way around. As a result, the single workspace being created is a workload-specific workspace, and these are some of the Azure services sending data to it:
   >
   > - Azure Container Registry
   > - Azure Application Gateway
   > - Azure Key Vault
   >
   > In the future, the app team might consider using Azure Policy to require all of their Azure resources to their diagnostics logs. They might also use Azure RBAC to grant different users access rights to keep the data isolated, which is possible within a single workspace.
   >
   > :bulb: Azure Log Analytics can be modeled in different ways depending on your organizational needs. It can be *centralized* as in this reference implementation, or *decentralized*. You can also create a *hybrid* model, which is a combination of both approaches. Azure Log Analytics workspaces are deployed into a specific region, which is where the log data is stored. For high availability, a distributed solution is the recommended approach instead. If you opt for a *centralized* solution, you need to be sure that the geo data residency is not going to be an issue, and be aware that cross-region data transfer costs will apply.

   > **Geo-replicated Azure Container Registry**
   >
   > :book: The app team is starting to lay down the groundwork for multi-region availability, and they know that centralizing Azure resources might introduce single point of failures. Therefore, the app team is tasked with assessing how resources can be shared efficiently without losing reliability.
   >
   > When looking at the container registry, there is at least one additional complexity which is the proximity while pulling large container images. Based on this the team realizes that the *networking I/O* is going to be an important factor, so having presence in multiple regions looks promising. Managing a registry instance in each region instead of shared a single registry mitigates the risk of a regional outage and improves latency. However, this approach won't fail over automatically, nor does it automatically replicating container images between registries. Both of these functions require manual intervention or additional procedures. That is the reason why the team selected the **Premium** tier, which offers [geo-replication](https://learn.microsoft.com/azure/container-registry/container-registry-geo-replication) as a built-in feature. Geo-replication enables sharing a single registry across multiple regions, achieving higher availability and reducing network latency.
   >
   > The app team plans to geo-replicate the registry to the same regions where their AKS clusters are going to be deployed (`East US 2` and `Central US`). By using the same regions, they optimize the DNS resolution process. They pay close attention to the number of regions to replicate into, which helps them control their costs. *Each region* they geo-replicate to incurs additional costs to their business unit. Under this configuration, they pay *two* times the premium container registry fee, which gives them region proximity and also ensures no extra network egress fees from distant regions.
   >
   > The app team is instructed to build the smallest container images they can. This is something they could achieve by following the [builder pattern](https://docs.docker.com/develop/develop-images/multistage-build/#before-multi-stage-builds) or by using [mutli-stage builds](https://docs.docker.com/develop/develop-images/multistage-build/#use-multi-stage-builds). Both approaches produce smaller final container images that are meant to be for runtime only. This approach is beneficial in many ways, especially in the speed of replication as well as in the transfer costs. A key feature as part of Azure Container Registry's geo-replication is that it will only replicate unique layers, also further reducing data transfer across regions.
   >
   > In case of a region is down, the app team is now covered by the Azure Traffic Manager in the background that comes on the scene to help deriving traffic to the registry located in the region that is closest to their multiple clusters in terms of network latency.
   >
   > :bulb: Another benefit of geo-replication is that permissions are centralized in a single registry instance, which simplifies your security management. Every AKS cluster owns a kubelet *system managed identity* by design, and that identity is the one being granted permissions to access the shared container registry. At the same time, these identities can be assigned individual permissions to other Azure resources that are meant to be cluster-specific, preventing them from cross pollination effects (for example, Azure Key Vault).
   >
   > As things develop, the combination of [availability zones](https://learn.microsoft.com/azure/container-registry/zone-redundancy) for redundancy within a region, and geo-replication across multiple regions, is the recommendation when looking for the highest reliability and performance of a container registry.

   > **Azure Front Door**
   >
   > :book: The app team is about to deploy application instances in every region. Global traffic management represents a new challenge for them: they need to route requests from clients to the different regions to achieve enhanced reliability, aligning to the [Geode cloud design pattern](https://learn.microsoft.com/azure/architecture/patterns/geodes). They plan to treat both regions as active, and respond from the region that's closest to the client sending an HTTP request. This is an active/active availability strategy.
   >
   > They also need to fail over to a single region in case of a regional outage. This means that load balancing can't simply be implemented with a round-robin approach over the closest regions, but instead it needs to be aware of the health of each origin and dynamically route the traffic accordingly.
   >
   > Two well-known Azure services can perform multi-geo redundancy and closest region routing: Azure Front Door and Azure Traffic Manager. Azure Front Door also provides better performance through optimized TCP and TLS negotiation, rate limiting, IP address controls, and a web application firewall, so Contoso selected Azure Front Door for their needs.

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
