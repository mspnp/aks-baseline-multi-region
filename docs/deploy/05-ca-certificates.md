# Generate your Client-Facing and AKS Ingress Controller TLS Certificates

Now that the [hub-spoke network is provisioned](./03-networking.md), you can follow the steps below to create the TLS certificates for each region that Azure Application Gateway will serve for clients connecting to your web app as well as the AKS ingress controller. The following will describe using certs for instructive purposes only.

## Expected results

Following the steps below you will result the certificates needed for Azure Application Gateway and AKS ingress controller.

| Object                                     | Purpose                                                                                                                                          |
| ------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------ |
| Two Azure Application Gateway certificates | They are TLS certificates emitted by Let's Encrypt for the Public Ip FQDNs and served by the Azure Application Gateway instances in each region  |
| An AKS ingress controller certificate     | It is a self-signed wildcard cert for TLS on the cluster ingress controller.                                                            |

## Steps

1. Generate client-facing TLS certificates for each region.

   > :book: The Contoso Bicycle organization has an important policy that every internet-facing endpoint exposed over the Https protocol must use a trusted CA certificate, and it is not allowed to share a common wildcard certificate between them. Therefore, the organization needs to procure individual trusted CA certificates for all their Public IPs' FQDNs in the different regions. The Azure Application Gateway instances are going to be serving these certificates in front of every region they get deployed to.

   The following command sets up some temporary infrastructure and executes a script that will generate public CA certificates. Part of that transient process creates a storage account with anonymous, public blob container access to act as a web host for some generated static files required for domain ownership validation. **This step will terminally fail if your subscription has the _Storage account public access should be disallowed_ Azure Policy set to _deny_**, as that blocks the creation of Azure Blob storage containers with anonymous access. You'll need an exception to this policy for the transient resources groups prefixed with `rg-cert-let-encrypt-`. An alternative method will be developed to eliminate this requirement, but it is not yet available.

   ```bash
   # get the Public IP FQDNs, their subdomins, and resource IDs
   APPGW_FQDN_BU0001A0042_03=$(az deployment group show -g rg-enterprise-networking-spokes -n spoke-BU0001A0042-03 --query properties.outputs.appGwFqdn.value -o tsv)
   APPGW_FQDN_BU0001A0042_04=$(az deployment group show -g rg-enterprise-networking-spokes -n spoke-BU0001A0042-04 --query properties.outputs.appGwFqdn.value -o tsv)
   APPGW_SUBDOMAIN_BU0001A0042_03=$(az deployment group show -g rg-enterprise-networking-spokes -n spoke-BU0001A0042-03 --query properties.outputs.subdomainName.value -o tsv)
   APPGW_SUBDOMAIN_BU0001A0042_04=$(az deployment group show -g rg-enterprise-networking-spokes -n spoke-BU0001A0042-04 --query properties.outputs.subdomainName.value -o tsv)
   APPGW_IP_RESOURCE_ID_03=$(az deployment group show -g rg-enterprise-networking-spokes -n spoke-BU0001A0042-03 --query properties.outputs.appGatewayPublicIp.value -o tsv)
   APPGW_IP_RESOURCE_ID_04=$(az deployment group show -g rg-enterprise-networking-spokes -n spoke-BU0001A0042-04 --query properties.outputs.appGatewayPublicIp.value -o tsv)

   # call the Let's Encrypt certificate generation script for both PIP FQDNs
   # [Generating the following certificates takes about ten minutes to run.]
   sudo chmod +x ./certs/letsencrypt-pip-cert-generation.sh
   sudo chmod +x ./certs/authenticator.sh
   ./certs/letsencrypt-pip-cert-generation.sh $APPGW_SUBDOMAIN_BU0001A0042_03 $APPGW_FQDN_BU0001A0042_03 $APPGW_IP_RESOURCE_ID_03 eastus2
   ./certs/letsencrypt-pip-cert-generation.sh $APPGW_SUBDOMAIN_BU0001A0042_04 $APPGW_FQDN_BU0001A0042_04 $APPGW_IP_RESOURCE_ID_04 centralus
   ```

   :bulb: EV certificates are mostly recommended for user-facing endpoints, which is not the case in this multi region reference implementation. The Azure Application Gateways instances are going to be just the regional backend servers for a globally distributed load balancer. For more information on how these certificates are being generated, please refer to [Certificate Generation for an Azure Public IP with your DNS Prefix](https://github.com/mspnp/letsencrypt-pip-cert-generation).

1. Base64 encode the client-facing certificate.

   :bulb: No matter if you used a certificate from your organization or you generated one from above, you'll need the certificate (as `.pfx`) to be Base64 encoded for proper storage in Key Vault later.

   ```bash
   APP_GATEWAY_LISTENER_REGION1_CERTIFICATE_BASE64=$(cat ${APPGW_SUBDOMAIN_BU0001A0042_03}.pfx | base64 | tr -d '\n')
   APP_GATEWAY_LISTENER_REGION2_CERTIFICATE_BASE64=$(cat ${APPGW_SUBDOMAIN_BU0001A0042_04}.pfx | base64 | tr -d '\n')
   ```

1. Generate the wildcard certificate for the AKS ingress controller.

   > :book: Contoso Bicycle will also procure another TLS certificate, a standard cert, to be used with the AKS ingress controller. This one is not EV, as it will not be user facing. Finally the app team decides to use a wildcard certificate of `*.aks-ingress.contoso.com` for the ingress controller. As this is not an internet-facing endpoint; using a wildcard certificate is a valid option.

   ```bash
   openssl req -x509 -nodes -days 365 -newkey rsa:2048 -out traefik-ingress-internal-aks-ingress-contoso-com-tls.crt -keyout traefik-ingress-internal-aks-ingress-contoso-com-tls.key -subj "/CN=*.aks-ingress.contoso.com/O=Contoso Aks Ingress"

   # Combined as PEM structure (required by Azure Application Gateway for backend pools)
   cat traefik-ingress-internal-aks-ingress-contoso-com-tls.crt traefik-ingress-internal-aks-ingress-contoso-com-tls.key > traefik-ingress-internal-aks-ingress-contoso-com-tls.pem
   ```

1. Base64 encode the AKS ingress controller certificate.

   :bulb: No matter if you used a certificate from your organization or you generated one from above, you'll need the public certificate (as `.crt` or `.cer`) to be Base64 encoded for proper storage in Key Vault later.

   ```bash
   AKS_INGRESS_CONTROLLER_CERTIFICATE_BASE64=$(cat traefik-ingress-internal-aks-ingress-contoso-com-tls.crt | base64 | tr -d '\n')
   ```

### Next step

:arrow_forward: [Deploy the AKS clusters](./06-aks-cluster.md)
