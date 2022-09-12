# Generate your Client-Facing and AKS Ingress Controller TLS Certificates

Now that the [hub-spoke network is provisioned](./03-networking.md), you can follow the steps below to create the TLS certificates for each region that Azure Application Gateway will serve for clients connecting to your web app as well as the AKS ingress controller. The following will describe using certs for instructive purposes only.

## Expected results

Following the steps below you will result the certificates needed for Azure Application Gateway and AKS ingress controller.

| Object                                     | Purpose                                                                                                                                          |
| ------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------ |
| Two Azure Application Gateway certificates | They are TLS certificates emitted by Let's Encrypt for the Public IP FQDNs and served by the Azure Application Gateway instances in each region. |
| An AKS ingress controller certificate      | It is a self-signed wildcard cert for TLS on the cluster ingress controller.                                                                     |

## Steps

1. Generate client-facing TLS certificates for each region.

   > :book: The Contoso Bicycle organization has an important policy that every internet-facing endpoint exposed over the Https protocol must use a trusted CA certificate, and it is not allowed to share a common wildcard certificate between them. Therefore, the organization needs to procure individual trusted CA certificates for all their Public IPs' FQDNs in the different regions. The Azure Application Gateway instances are going to be serving these certificates in front of every region they get deployed to.

   ```bash
   # call the Let's Encrypt certificate generation script for both PIPs' FQDNs
   # [Generating the certificates takes about twenty minutes to run.]
   chmod +x ./certs/letsencrypt-pip-cert-generation.sh ./certs/authenticator.sh
   ./certs/letsencrypt-pip-cert-generation.sh $(az deployment group show -g rg-enterprise-networking-spokes -n spoke-BU0001A0042-03 --query properties.outputs.appGatewayPublicIp.value -o tsv)
   ./certs/letsencrypt-pip-cert-generation.sh $(az deployment group show -g rg-enterprise-networking-spokes -n spoke-BU0001A0042-04 --query properties.outputs.appGatewayPublicIp.value -o tsv)
   ```

   :bulb: EV certificates are mostly recommended for user-facing endpoints, which is not the case in this multi region reference implementation. The Azure Application Gateways instances are going to be just the regional backend servers for a globally distributed load balancer. For more information on how these certificates are being generated, please refer to [Certificate Generation for an Azure Public IP with your DNS Prefix](https://github.com/mspnp/letsencrypt-pip-cert-generation).

1. Base64 encode the client-facing certificate.

   :bulb: No matter if you used a certificate from your organization or you generated one from above, you'll need the certificate (as `.pfx`) to be Base64 encoded for proper storage in Key Vault later.

   ```bash
   # get the Public IP subdomins
   APPGW_SUBDOMAIN_BU0001A0042_03=$(az deployment group show -g rg-enterprise-networking-spokes -n spoke-BU0001A0042-03 --query properties.outputs.subdomainName.value -o tsv)
   APPGW_SUBDOMAIN_BU0001A0042_04=$(az deployment group show -g rg-enterprise-networking-spokes -n spoke-BU0001A0042-04 --query properties.outputs.subdomainName.value -o tsv)

   export APP_GATEWAY_LISTENER_REGION1_CERTIFICATE_BASE64_AKS_MRB=$(cat ${APPGW_SUBDOMAIN_BU0001A0042_03}.pfx | base64 | tr -d '\n')
   export APP_GATEWAY_LISTENER_REGION2_CERTIFICATE_BASE64_AKS_MRB=$(cat ${APPGW_SUBDOMAIN_BU0001A0042_04}.pfx | base64 | tr -d '\n')
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
   export AKS_INGRESS_CONTROLLER_CERTIFICATE_BASE64_AKS_MRB=$(cat traefik-ingress-internal-aks-ingress-contoso-com-tls.crt | base64 | tr -d '\n')
   ```

### Save your work in-progress

```bash
# run the saveenv.sh script at any time to save environment variables created above to aks_baseline.env
./saveenv.sh

# if your terminal session gets reset, you can source the file to reload the environment variables
# source aks_baseline.env
```

### Next step

:arrow_forward: [Deploy the AKS clusters](./06-aks-cluster.md)
