# Prerequisites

This is the starting point for the instructions on deploying the [AKS baseline multicluster reference implementation](/README.md). There is required access and tooling you'll need in order to accomplish this. Follow the instructions below and on the subsequent pages so that you can get your environment ready to proceed with the creation of the AKS clusters.

## Steps

> :bulb: The steps shown here and elsewhere in the reference implementation use Bash shell commands. On Windows, you can use the [Windows Subsystem for Linux](https://learn.microsoft.com/windows/wsl/about#what-is-wsl-2) to run Bash.

1. An Azure subscription.

   The subscription used in this deployment cannot be a [free account](https://azure.microsoft.com/free); it must be a standard EA, pay-as-you-go, or Visual Studio benefit subscription. This is because the resources deployed here are beyond the quotas of free subscriptions.

   > :warning: The user or service principal initiating the deployment process *must* have the following minimal set of Azure role-based access control (RBAC) roles:
   >
   > - [Contributor role](https://learn.microsoft.com/azure/role-based-access-control/built-in-roles#contributor) is *required* at the subscription level to have the ability to create resource groups and perform deployments.
   > - [User Access Administrator role](https://learn.microsoft.com/azure/role-based-access-control/built-in-roles#user-access-administrator) is *required* at the subscription level since you'll be performing role assignments to managed identities across various resource groups.
   
1. A Microsoft Entra tenant to associate your Kubernetes RBAC Cluster API authentication to.

   > :warning: The user or service principal initiating the deployment process *must* have the following minimal set of Microsoft Entra permissions assigned:
   >
   > - Microsoft Entra [User Administrator](https://learn.microsoft.com/entra/identity/role-based-access-control/permissions-reference#user-administrator-permissions) is *required* to create a "break glass" AKS admin Microsoft Entra security group and user. Alternatively, you could get your Microsoft Entra admin to create this for you when instructed to do so.
   >   - If you are not part of the User Administrator group in the tenant associated to your Azure subscription, consider [creating a new tenant](https://learn.microsoft.com/entra/fundamentals/create-new-tenant#create-a-new-tenant-for-your-organization) to use while evaluating this implementation. The Microsoft Entra tenant backing your cluster's API RBAC does NOT need to be the same tenant associated with your Azure subscription.

1. Install the latest [Azure CLI](https://learn.microsoft.com/cli/azure/install-azure-cli?view=azure-cli-latest) installed (must be at least 2.37), or you can perform this from Azure Cloud Shell by clicking below.

   [![Launch Azure Cloud Shell](https://learn.microsoft.com/azure/includes/media/cloud-shell-try-it/launchcloudshell.png)](https://shell.azure.com)

1. Install [Certbot](https://certbot.eff.org/instructions).

   Certbot is a open-source software tool for using Let's Encrypt certificates on manually-administrated websites to enable HTTPS. We'll use Certbot to generate a valid, non self-signed, TLS certificate for your Azure Application Gateway instances. We do this because Azure Front Door requires origins to use TLS certificates that have been issued by a recognized certification authority.

1. Ensure [OpenSSL is installed](https://github.com/openssl/openssl#download) on your local environment. We'll use OpenSSL to generate other self-signed certificates that are used in this implementation. *OpenSSL is already installed in Azure Cloud Shell.*

   > :warning: Some shells may have the `openssl` command aliased for LibreSSL. LibreSSL will not work with the instructions found here. You can check this by running `openssl version` and you should see output that says `OpenSSL <version>` and not `LibreSSL <version>`.

1. Install the latest [GitHub CLI](https://github.com/cli/cli/#installation). *The GitHub CLI is already installed in Azure Cloud Shell.*

1. Sign into the GitHub CLI.

   ```bash
   gh auth login -s "repo,admin:org"
   ```

1. Fork the repository and clone it.

   ```bash
   gh repo fork mspnp/aks-baseline-multi-region --clone=true --remote=false
   cd aks-baseline-multi-region
   git remote remove upstream
   ```

1. Get your GitHub username

   ```bash
   export GITHUB_USERNAME_AKS_MRB=$(gh api user -q '.login')
   echo GITHUB_USERNAME_AKS_MRB: $GITHUB_USERNAME_AKS_MRB
   ```

### Save your work in-progress

```bash
# run the saveenv.sh script at any time to save environment variables created above to aks_baseline.env
./saveenv.sh

# if your terminal session gets reset, you can source the file to reload the environment variables
# source aks_baseline.env
```

### Next step

:arrow_forward: [Prep for Microsoft Entra integration](./02-auth.md)
