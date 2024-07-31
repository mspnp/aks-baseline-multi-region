# Azure Kubernetes Service (AKS) for multiregion deployment

This reference implementation reviews some design decisions from the baseline, and incorporates new *recommended infrastructure options* for a multicluster (and multiregion) architecture. This implementation and document are meant to guide the multiple distinct teams introduced in the [AKS baseline](https://github.com/mspnp/aks-baseline) through the process of expanding from a single cluster to a multicluster solution. The fundamental driver for this reference architecture is **Reliability**, and it uses the [Geode cloud design pattern](https://learn.microsoft.com/azure/architecture/patterns/geodes).

> Note: This implementation does not use [AKS Fleet Manager capability](https://learn.microsoft.com/azure/kubernetes-fleet/) or any other automated cross-cluster management technologies, but instead represents a manual approach to combining multiple AKS clusters together. Operating fleets containing a large number of clusters is usually best performed with advanced and dedicated tooling. This implementation supports a small scale and introduces some of the core concepts that will be necessary regardless of your scale or tooling choices.

Throughout the reference implementation, you will see reference to _Contoso Bicycle_. They are a fictional, small, and fast-growing startup that provides online web services to its clientele on the east coast of the United States. This narrative provides grounding for some implementation details, naming conventions, etc. You should adapt as you see fit.

| 🎓 Foundational Understanding                                                                                                                                                                                                                                                                                                                                                                                                           |
| :-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **If you haven't familiarized yourself with the general-purpose [AKS baseline cluster](https://github.com/mspnp/aks-baseline) architecture, you should start there before continuing here.** The architecture rationalized and constructed in that implementation is the direct foundation of this body of work. This reference implementation avoids rearticulating points that are already addressed in the AKS baseline cluster, and we assume you've already read it before reading the guidance in this architecture. |

The Contoso Bicycle app team that owns the `a0042` workload app has deployed an AKS cluster strategically located in the East US 2 region, because this is where most of their customer base can be found. They have operated this single AKS cluster [following Microsoft's recommended baseline architecture](https://learn.microsoft.com/azure/architecture/reference-architectures/containers/aks/baseline-aks). They followed the guidance that AKS baseline clusters should be deployed across multiple *availability zones* within the same region.

However, now they realize that if the East US 2 region went fully down, availability zone coverage is not sufficient. Even though the SLAs are acceptable for their business continuity plan, they are starting to reconsider their options, and how their stateless application (Application ID: a0042) could increase its availability in case of a complete regional outage.

They started conversations with the business unit (BU0001) to increment the number of clusters by one. In other words, they are proposing to move to a multicluster infrastructure solution in which multiple instances of the same application could live in different Azure regions.

This architectural decision has multiple implications for the Contoso Bicycle organization. It isn't just about following the baseline twice, or adding another the region to get a twin infrastructure. They need to look for how they can efficiently share some of their Azure resources, as well as detect those that need to be added. They also need to consider how to deploy more than one cluster as well as operate them, and which specific regions they deploy to. There are many other factors that they need to consider while striving for higher availability.

## Azure Architecture Center guidance

This project has a companion article that describes some of the challenges, design patterns, and best practices for an AKS multi-region solution designed for high availability. You can find this article on the Azure Architecture Center at [Azure Kubernetes Service (AKS) baseline for multiregion clusters](https://aka.ms/architecture/aks-baseline-multi-region). If you haven't already reviewed it, we suggest you read it. It gives context to the considerations applied in this implementation. Ultimately, this implementation is the direct implementation of that specific architectural guidance.

## Architecture

**This architecture is infrastructure focused**, more so than on workload. It concentrates on two AKS clusters, including concerns like multiregion deployments, the desired state and bootstrapping of the clusters, geo-replication, network topologies, and more.

The implementation presented here, like in the baseline, is the *minimum recommended starting (baseline) for a multi-cluster AKS solution*. This implementation integrates with Azure services that deliver geo-replication, a centralized observability approach, a network topology that supports multiregional growth, and traffic balancing.

Finally, this implementation uses the [ASP.NET Docker samples](https://github.com/dotnet/dotnet-docker/tree/main/samples/aspnetapp) as an example workload. This workload is purposefully uninteresting, as it is here exclusively to help you experience the multicluster infrastructure.

### Core architecture components

#### Azure platform

- Azure Kubernetes Service (AKS) v1.29
- Azure virtual networks (hub-spoke)
- Azure Front Door (classic)
- Azure Application Gateway with web application firewall (WAF)
- Azure Container Registry
- Azure Monitor Log Analytics

#### In-cluster OSS components

- [Flux v2 GitOps Operator](https://fluxcd.io) *[AKS-managed extension]*
- [Traefik Ingress Controller](https://doc.traefik.io/traefik/v2.10/routing/providers/kubernetes-ingress/)
- [Azure Workload Identity](https://github.com/Azure/azure-workload-identity) *[AKS-managed add-on]*
- [Azure Key Vault Secret Store CSI Provider](https://github.com/Azure/secrets-store-csi-driver-provider-azure) *[AKS-managed add-on]*

![The federation diagram depicting the proposed cluster fleet topology running different instances of the same application from them.](./docs/deploy/images/aks-baseline-multi-cluster.png)

## Deploy the reference implementation

- [ ] Begin by ensuring you [install and meet the prerequisites](./docs/deploy/01-prerequisites.md)
- [ ] [Plan your Microsoft Entra integration](./docs/deploy/02-auth.md)
- [ ] [Deploy the shared services for your clusters](./docs/deploy/03-cluster-prerequisites.md)
- [ ] [Build the hub-spoke network](./docs/deploy/04-networking.md)
- [ ] [Procure client-facing and AKS ingress controller TLS certificates](./docs/deploy/05-ca-certificates.md)
- [ ] [Deploy the two AKS clusters and supporting services](./docs/deploy/06-aks-cluster.md)
- [ ] Just like the cluster, there are [workload prerequisites to address](./docs/deploy/07-workload-prerequisites.md)
- [ ] [Configure AKS ingress controller with Azure Key Vault integration](./docs/deploy/08-secret-managment-and-ingress-controller.md)
- [ ] [Deploy the workload](./docs/deploy/09-workload.md)
- [ ] [Perform end-to-end deployment validation](./docs/deploy/10-validation.md)

## :broom: Clean up resources

Most of the Azure resources deployed in the prior steps will incur ongoing charges unless removed.

- [ ] [Clean up all resources](./docs/deploy/11-cleanup.md)

## Cost considerations

The main costs of this reference implementation are (in order):

| Component | Approximate cost |
|-|-|
| Azure Firewall dedicated to control outbound traffic | ~35% |
| Node pool virtual machines used inside the cluster | ~30% |
| Application Gateway which controls the ingress traffic to the workload | ~15% |
| Log Analytics | ~10% |

Azure Firewall can be a shared resource, and maybe your company already has one and you can reuse in existing regional hubs.

The virtual machines are used to host the nodes for the AKS cluster. The cluster can be shared by several applications. You can analyze the size and the number of nodes. The reference implementation has the minimum recommended nodes for production environments. In a multicluster environment, you have at least two clusters and should choose a scale appropriate to your workload. You should perform traffic analysis and consider your failover strategy and autoscaling configuration when planning your virtual machine scaling strategy.

Keep an eye on Log Analytics data growth as time goes by and manage the information that it collects. The main cost is related to data ingestion into the Log Analytics workspace, and you can fine tune the data ingestion to remove low-value data.

There is WAF protection enabled on Application Gateway and Azure Front Door. The WAF rules on Azure Front Door have extra cost. You can disable these rules if you decide you don't need them. However, the consequence is that potentially malicious traffic will arrive at Application Gateway and into your cluster. Such requests can use resources instead of being eliminated as quickly as possible.

## Next Steps

This reference implementation intentionally does not cover all scenarios. If you are looking for other topics that are not addressed here, visit [AKS baseline for the complete list of covered scenarios around AKS](https://github.com/mspnp/aks-baseline#advanced-topics).

## Related documentation

- [Azure Kubernetes Service documentation](https://learn.microsoft.com/azure/aks/)
- [Microsoft Azure Well-Architected Framework](https://learn.microsoft.com/azure/well-architected/)
- [Microservices architecture on AKS](https://learn.microsoft.com/azure/architecture/reference-architectures/containers/aks-microservices/aks-microservices)
- [Mission-critical baseline architecture on Azure](https://learn.microsoft.com/azure/architecture/reference-architectures/containers/aks-mission-critical/mission-critical-intro)

## Contributions

Please see our [contributor guide](./CONTRIBUTING.md).

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/). For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or contact <opencode@microsoft.com> with any additional questions or comments.

With :heart: from Microsoft Patterns & Practices, [Azure Architecture Center](https://aka.ms/architecture).
