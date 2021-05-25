#!/bin/bash -x

SUBDOMAIN=$1
FQDN=$2
IP_RESOURCE_ID=$3
LOCATION=$4

RGNAME="rg-cert-let-encrypt-${LOCATION}"

az group create --name ${RGNAME} --location ${LOCATION}

az deployment group create -g "${RGNAME}" --template-uri "https://raw.githubusercontent.com/mspnp/letsencrypt-pip-cert-generation/0b981f882b473f0e6a01d5fe1153d75fa80ed56a/resources-stamp.json" --name ca-cert-generation -p location=$LOCATION subdomainName=$SUBDOMAIN ipResourceId=$IP_RESOURCE_ID

STORAGE_ACCOUNT_NAME=$(az deployment group show -g $RGNAME -n ca-cert-generation --query properties.outputs.storageAccountName.value -o tsv)
STORAGE_CONNECTION_STRING=$(az storage account show-connection-string -g $RGNAME -n $STORAGE_ACCOUNT_NAME --query "connectionString")

echo Storage Account: $STORAGE_ACCOUNT_NAME
az storage container create --account-name $STORAGE_ACCOUNT_NAME --name verificationdata --auth-mode login --public-access container

echo "${SUBDOMAIN}" > test.txt
az storage blob upload \
 --connection-string $STORAGE_CONNECTION_STRING \
 --account-name $STORAGE_ACCOUNT_NAME \
 --container-name verificationdata \
 --name test.txt \
 --file ./test.txt \
 --auth-mode key

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
certbot certonly --manual --manual-auth-hook "${DIR}/authenticator.sh $STORAGE_ACCOUNT_NAME $STORAGE_CONNECTION_STRING" -d $FQDN --config-dir ./certs/output/etc/letsencrypt --work-dir ./certs/output/var/lib/letsencrypt --logs-dir ./certs/output/var/log/letsencrypt

openssl pkcs12 -export -out $SUBDOMAIN.pfx -inkey ./certs/output/etc/letsencrypt/live/$FQDN/privkey.pem -in ./certs/output/etc/letsencrypt/live/$FQDN/cert.pem -certfile ./certs/output/etc/letsencrypt/live/$FQDN/chain.pem -passout pass:

echo "Deleting resources"
az group delete -n $RGNAME --yes
rm -rf ./certs/output ./test.txt
