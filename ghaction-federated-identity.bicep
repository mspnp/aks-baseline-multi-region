param location string = 'eastus2'

@description('Your git account where the repo is your cloned.')
@minLength(9)
param gitAccount string

@description('The branch used for run your workflow. For Jobs not tied to an environment, include the ref path for branch/tag based on the ref path used for triggering the workflow: repo:< Organization/Repository >:ref:< ref path>')
@minLength(1)
param gitRepoBranch string = 'main'

@description('Create the Azure Credentials for the GitHub CD workflow')
resource ghActionFederatedIdentity 'Microsoft.ManagedIdentity/userAssignedIdentities@2022-01-31-preview' = {
  name: 'ghActionFederatedIdentity'
  location: location
  
  resource federatedCreds 'federatedIdentityCredentials@2022-01-31-preview' = {
    name: 'ghActionFederatedIdentity'
    properties: {
      audiences: [
        'api://AzureADTokenExchange'
      ]
      issuer: 'https://token.actions.githubusercontent.com'
      subject: 'repo:${gitAccount}/aks-baseline-multi-region:ref:refs/heads/${gitRepoBranch}'
    }
  }
}

output clientId string = ghActionFederatedIdentity.properties.clientId
