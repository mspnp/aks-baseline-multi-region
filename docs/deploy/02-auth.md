# Prep for Microsoft Entra Integration

Now that you have the [prerequisites](./01-prerequisites.md) met, follow these steps to prepare Microsoft Entra ID for Kubernetes role-based access control (RBAC). The steps ensure you have a Microsoft Entra security group and user assigned for group-based Kubernetes control plane access.

## Expected results

These steps will result in a Microsoft Entra configuration that will be used for Kubernetes control plane (Cluster API) authorization.

| Object                             | Purpose                                                                                  |
| ---------------------------------- | ---------------------------------------------------------------------------------------- |
| A Cluster Admin user               | Represents at least one break-glass cluster admin user.                                  |
| Two Cluster Admin security groups  | Will be mapped to `cluster-admin` Kubernetes role.                                       |
| Two Cluster Admin group membership | Association between the cluster admin user(s) and the two cluster admin security groups. |

These steps don't configure anything related to workload identity. This configuration is exclusively to set up RBAC access to perform cluster management.

## Steps

> :book: The Contoso Bicycle Microsoft Entra team requires all admin access to AKS clusters be security-group based. This applies to the two AKS clusters that are being created for Application ID a0042 under the BU001 business unit. Kubernetes RBAC will be Microsoft Entra ID-backed and access granted based on a user's identity or directory group membership.

1. Sign into your Azure subscription, and save your Azure subscription's tenant ID.

   ```bash
   az login
   export TENANTID_AZURERBAC_AKS_MRB=$(az account show --query tenantId -o tsv)
   echo TENANTID_AZURERBAC_AKS_MRB: $TENANTID_AZURERBAC_AKS_MRB
   TENANTS=$(az rest --method get --url https://management.azure.com/tenants?api-version=2020-01-01 --query 'value[].{TenantId:tenantId,Name:displayName}' -o table)
   ```

1. Validate your saved Azure subscription's tenant ID is correct.

   ```bash
   echo "${TENANTS}" | grep -z ${TENANTID_AZURERBAC_AKS_MRB}
   ```

   :warning: Do not proceed if the tenant highlighted in red is not correct. Start over by `az login` into the proper Azure subscription.

1. From the list of tenants printed in the previous step, select a Microsoft Entra tenant to associate your Kubernetes RBAC Cluster API authentication. Sign into that Microsoft Entra tenant.

   > :bulb: Skip this `az login` command if you plan to use your current user account's Microsoft Entra tenant for Kubernetes authorization.

   ```bash
   az login --allow-no-subscriptions -t <Replace-With-ClusterApi-AzureAD-TenantId>
   ```

1. Validate that the tenant ID that you just saved corresponds the correct tenant for Kubernetes Cluster API authorization.

   ```bash
   export TENANTID_K8SRBAC_AKS_MRB=$(az account show --query tenantId -o tsv)
   echo TENANTID_K8SRBAC_AKS_MRB: $TENANTID_K8SRBAC_AKS_MRB
   echo "${TENANTS}" | grep -z ${TENANTID_K8SRBAC_AKS_MRB}
   ```

   :warning: If the tenant highlighted in red is not correct, start over by signing into the correct Microsoft Entra ID tenant for Kubernetes cluster API authorization.

1. Create a single "break-glass" cluster administrator user for your AKS clusters, and add to both cluster admin security groups being created. That group will map to the [Kubernetes Cluster Admin](https://kubernetes.io/docs/reference/access-authn-authz/rbac/#user-facing-roles) role `cluster-admin`.

   :book: The app team requested a single admin user that needs to have access in both clusters. The Microsoft Entra Admin team creates two different groups, one per cluster to home the new admin.

   ```bash
   # Create a single admin for both clusters
   TENANTDOMAIN_K8SRBAC=$(az ad signed-in-user show --query 'userPrincipalName' -o tsv | cut -d '@' -f 2 | sed 's/\"//')
   OBJECTNAME_USER_CLUSTERADMIN=bu0001a0042-admin
   OBJECTID_USER_CLUSTERADMIN=$(az ad user create --display-name=${OBJECTNAME_USER_CLUSTERADMIN} --user-principal-name ${OBJECTNAME_USER_CLUSTERADMIN}@${TENANTDOMAIN_K8SRBAC} --force-change-password-next-sign-in --password ChangeMebu0001a0042AdminChangeMe --query id -o tsv)
   echo TENANTDOMAIN_K8SRBAC: $TENANTDOMAIN_K8SRBAC
   echo OBJECTNAME_USER_CLUSTERADMIN: $OBJECTNAME_USER_CLUSTERADMIN
   echo OBJECTID_USER_CLUSTERADMIN: $OBJECTID_USER_CLUSTERADMIN

   # Create the admin groups
   OBJECTNAME_GROUP_CLUSTERADMIN_BU0001A004203=cluster-admins-bu0001a0042-03
   OBJECTNAME_GROUP_CLUSTERADMIN_BU0001A004204=cluster-admins-bu0001a0042-04
   export OBJECTID_GROUP_CLUSTERADMIN_BU0001A004203_AKS_MRB=$(az ad group create --display-name $OBJECTNAME_GROUP_CLUSTERADMIN_BU0001A004203 --mail-nickname $OBJECTNAME_GROUP_CLUSTERADMIN_BU0001A004203 --description "Principals in this group are cluster admins in the bu0001a004203 cluster." --query id -o tsv)
   export OBJECTID_GROUP_CLUSTERADMIN_BU0001A004204_AKS_MRB=$(az ad group create --display-name $OBJECTNAME_GROUP_CLUSTERADMIN_BU0001A004204 --mail-nickname $OBJECTNAME_GROUP_CLUSTERADMIN_BU0001A004204 --description "Principals in this group are cluster admins in the bu0001a004204 cluster." --query id -o tsv)
   echo OBJECTNAME_GROUP_CLUSTERADMIN_BU0001A004203: $OBJECTNAME_GROUP_CLUSTERADMIN_BU0001A004203
   echo OBJECTNAME_GROUP_CLUSTERADMIN_BU0001A004204: $OBJECTNAME_GROUP_CLUSTERADMIN_BU0001A004204
   echo OBJECTID_GROUP_CLUSTERADMIN_BU0001A004203_AKS_MRB: $OBJECTID_GROUP_CLUSTERADMIN_BU0001A004203_AKS_MRB
   echo OBJECTID_GROUP_CLUSTERADMIN_BU0001A004204_AKS_MRB: $OBJECTID_GROUP_CLUSTERADMIN_BU0001A004204_AKS_MRB

   # Assign the admin as new member in both groups
   az ad group member add -g $OBJECTID_GROUP_CLUSTERADMIN_BU0001A004203_AKS_MRB --member-id $OBJECTID_USER_CLUSTERADMIN
   az ad group member add -g $OBJECTID_GROUP_CLUSTERADMIN_BU0001A004204_AKS_MRB --member-id $OBJECTID_USER_CLUSTERADMIN
   ```

   :bulb: For a better security segregation your organization might require you to create multiple admins. This reference implementation creates a single one for the sake of simplicity. The group object ID will be used later while creating the different clusters. This way, once the clusters gets deployed the new group will get the correct cluster role bindings in Kubernetes. For more information, refer to the [AKS baseline](https://github.com/mspnp/aks-baseline/blob/main/docs/deploy/03-microsoft-entra-id.md#kubernetes-rbac-backing-store).

### Save your work in-progress

```bash
# run the saveenv.sh script at any time to save environment variables created above to aks_baseline.env
./saveenv.sh

# if your terminal session gets reset, you can source the file to reload the environment variables
# source aks_baseline.env
```

### Next step

:arrow_forward: [Deploy shared resources](./03-cluster-prerequisites.md)
