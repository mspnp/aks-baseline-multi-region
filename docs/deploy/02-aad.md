# Prep for Azure Active Directory Integration

Now that you have the [prerequisites](./01-prerequisites.md) met, follow the steps below to prepare Azure AD for Kubernetes role-based access control (RBAC). This will ensure you have an Azure AD security group(s) and user(s) assigned for group-based Kubernetes control plane access.

## Expected results

Following the steps below you will result in an Azure AD configuration that will be used for Kubernetes control plane (Cluster API) authorization.

| Object                             | Purpose                                                                                                                  |
| ---------------------------------- | ------------------------------------------------------------------------------------------------------------------------ |
| A Cluster Admin User               | Represents at least one break-glass cluster admin user.                                                                  |
| Two Cluster Admin Security Groups  | Will be mapped to `cluster-admin` Kubernetes role.                                                                       |
| Two Cluster Admin Group Membership | Association between the Cluster Admin User(s) and the two Cluster Admin Security Groups.                                 |

This does not configure anything related to workload identity. This configuration is exclusively to set up RBAC access to perform cluster management.

## Steps

> :book: The Contoso Bicycle Azure AD team requires all admin access to AKS clusters be security-group based. This applies to the two AKS clusters that are being created for Application ID a0042 under the BU001 business unit. Kubernetes RBAC will be AAD-backed and access granted based on a user's identity or directory group membership.

1. Login into your Azure subscription, and save your Azure subscription's tenant id.

   ```bash
   az login
   export TENANTID_AZURERBAC_AKS_MRB=$(az account show --query tenantId -o tsv)
   TENANTS=$(az rest --method get --url https://management.azure.com/tenants?api-version=2020-01-01 --query 'value[].{TenantId:tenantId,Name:displayName}' -o table)
   ```

   > :bulb: The steps shown here and elsewhere in the reference implementation use Bash shell commands. On Windows, you can use the [Windows Subsystem for Linux](https://learn.microsoft.com/windows/wsl/about#what-is-wsl-2) to run Bash.

1. Validate your saved Azure subscription's tenant id is correct

   ```bash
   echo "${TENANTS}" | grep -z ${TENANTID_AZURERBAC_AKS_MRB}
   ```

   :warning: Do not procced if the tenant highlighted in red is not correct. Start over by `az login` into the proper Azure subscription.

1. From the list printed in the previous step, select an Azure AD tenant to associate your Kubernetes RBAC Cluster API authentication and login into.

   > :bulb: Skip this `az login` command if you plan to use your current user account's Azure AD tenant for Kubernetes authorization.

   ```bash
   az login --allow-no-subscriptions -t <Replace-With-ClusterApi-AzureAD-TenantId>
   ```

1. Validate that the new saved tenant id is correct one for Kubernetes Cluster API authorization

   ```bash
   export TENANTID_K8SRBAC_AKS_MRB=$(az account show --query tenantId -o tsv)
   echo "${TENANTS}" | grep -z ${TENANTID_K8SRBAC_AKS_MRB}
   ```

   :warning: If the tenant highlighted in red is not correct, start over by login into the proper Azure Directory Tenant for Kubernetes Cluster API authorization.

1. Create a single "break-glass" cluster administrator user for your AKS clusters, and add to both cluster admin security groups being created that are going to map to the [Kubernetes Cluster Admin](https://kubernetes.io/docs/reference/access-authn-authz/rbac/#user-facing-roles) role `cluster-admin`.

   :book: The app team requested a single admin user that needs to have access in both clusters. The Azure AD Admin team create two different groups, one per cluster to home the new admin.

   ```bash
   # create a single admin for both clusters
   TENANTDOMAIN_K8SRBAC=$(az ad signed-in-user show --query 'userPrincipalName' -o tsv | cut -d '@' -f 2 | sed 's/\"//')
   AADOBJECTNAME_USER_CLUSTERADMIN=bu0001a0042-admin
   AADOBJECTID_USER_CLUSTERADMIN=$(az ad user create --display-name=${AADOBJECTNAME_USER_CLUSTERADMIN} --user-principal-name ${AADOBJECTNAME_USER_CLUSTERADMIN}@${TENANTDOMAIN_K8SRBAC} --force-change-password-next-sign-in --password ChangeMebu0001a0042AdminChangeMe --query id -o tsv)

   # create the admin groups
   AADOBJECTNAME_GROUP_CLUSTERADMIN_BU0001A004203=cluster-admins-bu0001a0042-03
   AADOBJECTNAME_GROUP_CLUSTERADMIN_BU0001A004204=cluster-admins-bu0001a0042-04
   export AADOBJECTID_GROUP_CLUSTERADMIN_BU0001A004203_AKS_MRB=$(az ad group create --display-name $AADOBJECTNAME_GROUP_CLUSTERADMIN_BU0001A004203 --mail-nickname $AADOBJECTNAME_GROUP_CLUSTERADMIN_BU0001A004203 --description "Principals in this group are cluster admins in the bu0001a004203 cluster." --query id -o tsv)
   export AADOBJECTID_GROUP_CLUSTERADMIN_BU0001A004204_AKS_MRB=$(az ad group create --display-name $AADOBJECTNAME_GROUP_CLUSTERADMIN_BU0001A004204 --mail-nickname $AADOBJECTNAME_GROUP_CLUSTERADMIN_BU0001A004204 --description "Principals in this group are cluster admins in the bu0001a004204 cluster." --query id -o tsv)

   # assign the admin as new member in both groups
   az ad group member add -g $AADOBJECTID_GROUP_CLUSTERADMIN_BU0001A004203_AKS_MRB --member-id $AADOBJECTID_USER_CLUSTERADMIN
   az ad group member add -g $AADOBJECTID_GROUP_CLUSTERADMIN_BU0001A004204_AKS_MRB --member-id $AADOBJECTID_USER_CLUSTERADMIN
   ```

   :bulb: For a better security segregation your organization might require to create multiple admins. This reference implementation creates a single one for the sake of simplicity. The group object ID will be used later while creating the different clusters. This way, once the clusters gets deployed the new group will get the proper Cluster Role Bindings in Kubernetes. For more information, please refer to our [AKS baseline](https://github.com/mspnp/aks-baseline).

### Save your work in-progress

```bash
# run the saveenv.sh script at any time to save environment variables created above to aks_baseline.env
./saveenv.sh

# if your terminal session gets reset, you can source the file to reload the environment variables
# source aks_baseline.env
```

### Next step

:arrow_forward: [Deploy shared resources](./03-cluster-prerequisites.md)
