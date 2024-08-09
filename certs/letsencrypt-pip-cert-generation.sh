#!/bin/bash -x
set -e

IP_RESOURCE_ID=$1

LOCATION=$(az network public-ip show --ids $IP_RESOURCE_ID --query location -o tsv)
RGNAME="rg-lets-encrypt-cert-validator-${LOCATION}"
FQDN=$(az network public-ip show --ids $IP_RESOURCE_ID --query dnsSettings.fqdn -o tsv)
SUBDOMAIN=$(az network public-ip show --ids $IP_RESOURCE_ID --query dnsSettings.domainNameLabel -o tsv)
USER_PRINCIPAL_ID=$(az ad signed-in-user show --query id --output tsv)
CURRENT_IP_ADDRESS=$(curl -s -4 https://ifconfig.io)

echo "Location: $LOCATION"
echo "DNS Prefix: $SUBDOMAIN"
echo "FQDN: $FQDN"
echo "Existing IP Resource ID: $IP_RESOURCE_ID"
echo "User Principal ID: $USER_PRINCIPAL_ID"
echo "Current IP Address: $CURRENT_IP_ADDRESS"

echo "Creating temporary Resource Group $RGNAME"
az group create -n $RGNAME -l $LOCATION

echo "Deploying Azure resources used in validation; this may take 20 minutes."
az deployment group create -g $RGNAME -f ./certs/resources-stamp.bicep -n $SUBDOMAIN -p location=${LOCATION} subdomainName=${SUBDOMAIN} ipResourceId=${IP_RESOURCE_ID} userPrincipalId=${USER_PRINCIPAL_ID} currentIPAddress=${CURRENT_IP_ADDRESS}

STORAGE_ACCOUNT_NAME=$(az deployment group show -g $RGNAME -n $SUBDOMAIN --query properties.outputs.storageAccountName.value -o tsv)

echo "Enabling web hosting on $STORAGE_ACCOUNT_NAME"
az storage blob service-properties update --account-name $STORAGE_ACCOUNT_NAME --static-website true --auth-mode login

echo "Uploading placeholder to storage"
echo pong>ping.txt
az storage blob upload --account-name $STORAGE_ACCOUNT_NAME -c \$web -n ping -f ./ping.txt --auth-mode login

echo "Waiting for website to be ready"
curl --retry 10 --retry-delay 10 -s -4 http://$FQDN/ping

echo "Starting cert generation and validation"
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
certbot certonly --manual --manual-auth-hook "${DIR}/authenticator.sh ${STORAGE_ACCOUNT_NAME}" -d $FQDN --config-dir ./certs/output/etc/letsencrypt --work-dir ./certs/output/var/lib/letsencrypt --logs-dir ./certs/output/var/log/letsencrypt

echo "Converting cert to pfx"
openssl pkcs12 -export -out ${SUBDOMAIN}.pfx -inkey ./certs/etc/letsencrypt/live/${FQDN}/privkey.pem -in ./certs/etc/letsencrypt/live/${FQDN}/cert.pem -certfile ./certs/etc/letsencrypt/live/${FQDN}/chain.pem -passout pass:

echo "Deleting Azure resources"
az group delete -n $RGNAME --yes --no-wait

echo "Deleting temporary local files"
rm -rf ./certs/output ./ping.txt

echo "Your certificate: ${SUBDOMAIN}.pfx"
