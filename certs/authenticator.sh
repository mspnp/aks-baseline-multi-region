#!/bin/bash

STORAGE_ACCOUNT_NAME=$1

echo $CERTBOT_VALIDATION>${CERTBOT_TOKEN}.txt

echo "Uploading validation token to $STORAGE_ACCOUNT_NAME"

az storage blob upload --account-name $STORAGE_ACCOUNT_NAME -c \$web -n "${CERTBOT_TOKEN}" -f "./${CERTBOT_TOKEN}.txt" --auth-mode key --only-show-errors

rm ${CERTBOT_TOKEN}.txt