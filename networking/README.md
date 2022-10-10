# Networking Azure Resource Manager (ARM) Templates

> Note: This is part of the Azure Kubernetes Service (AKS) Baseline Cluster reference implementation. For more information check out the [readme file in the root](../README.md).

These files are the ARM templates used in the deployment of this reference implementation. This reference implementation uses a standard hub-spoke model.

## Files

* [`hub-default.json`](./hub-default.json) is a file that defines a generic regional hub.  All regional hubs can generally be considered a fork of this base template.
* [`hub-regionA.json`](./hub-regionA.json) is a file that defines a specific region's hub (for example, it might be named `hub-eastus2.json`).  This is the long-lived template that defines this specific region's hub.
* [`spoke-BU0001A0008.json`](./spoke-BU0001A0008.json) is a file that defines a specific spoke in the topology. A spoke, in our narrative, is create for each workload in a business unit, hence the naming pattern in the file name.

Your organization will likely have its own standards for their hub-spoke implementation. Be sure to follow your organizational guidelines.

## Network Watchers

Observability into your network is critical for reliability as it exposes issues in the system that can be immediately targeted and debugged before they produces failures in you applications. [Network Watcher](https://learn.microsoft.com/azure/network-watcher/network-watcher-monitoring-overview), combined with [Traffic Analytics](https://learn.microsoft.com/azure/network-watcher/traffic-analytics) will help provide a perspective into traffic traversing your networks. This reference implementation will _attempt_ to deploy NSG Flow Logs and Traffic Analytics. These features depend on a regional Network Watcher resource being installed on your subscription. Network Watchers are singletons in a subscription, and their creation is _usually_ automatic and  might exist in a resource group you do not have RBAC access to. We strongly encourage you to enable [NSG flow logs](https://learn.microsoft.com/azure/network-watcher/network-watcher-nsg-flow-logging-overview) on your AKS Cluster subnets, Azure Application Gateway, and other subnets that may be a source of traffic into and out of your cluster. Ensure you're sending your NSG Flow Logs to a **V2 Storage Account**.

In addition, Network Watcher is also a highly valuable network troubleshooting utility. As your network is private and heavy with flow restrictions, troubleshooting network flow issues can be time consuming. Network Watcher can help provide additional insight when other troubleshooting means are not sufficient.

## See also

* [Hub-spoke network topology in Azure](https://learn.microsoft.com/azure/architecture/reference-architectures/hybrid-networking/hub-spoke)
