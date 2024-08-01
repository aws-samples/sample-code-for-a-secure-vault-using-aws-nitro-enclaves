#!/bin/bash

set -euo pipefail

export $(grep -v '^#' .env | xargs -0)

STACK_PREFIX=nitro-vault
VPC_STACK_NAME="${STACK_PREFIX}-vpc"
KEY_STACK_NAME="${STACK_PREFIX}-key"
CI_STACK_NAME="${STACK_PREFIX}-ci"
VAULT_STACK_NAME="${CI_STACK_NAME}-vault"
API_STACK_NAME="${CI_STACK_NAME}-api"
CANARY_STACK_NAME="${CI_STACK_NAME}-canary"

printf "[!] Deleting ${CANARY_STACK_NAME} CloudFormation Stack..."
aws cloudformation delete-stack --stack-name "${CANARY_STACK_NAME}"

printf "\n[!] Deleting ${API_STACK_NAME} CloudFormation Stack..."
aws cloudformation delete-stack --stack-name "${API_STACK_NAME}"

printf "\n[!] Deleting ${VAULT_STACK_NAME} CloudFormation Stack..."
aws cloudformation delete-stack --stack-name "${VAULT_STACK_NAME}"

printf "\n[!] Waiting for ${VAULT_STACK_NAME} stack to be deleted..."
aws cloudformation wait stack-delete-complete --stack-name "${VAULT_STACK_NAME}"
printf "\n[-] Deleted ${VAULT_STACK_NAME}.\n"

printf "\n[!] Waiting for ${API_STACK_NAME} stack to be deleted..."
aws cloudformation wait stack-delete-complete --stack-name "${API_STACK_NAME}"
printf "\n[-] Deleted ${API_STACK_NAME}.\n"

printf "\n[!] Waiting for ${CANARY_STACK_NAME} stack to be deleted..."
aws cloudformation wait stack-delete-complete --stack-name "${CANARY_STACK_NAME}"
printf "\n[-] Deleted ${CANARY_STACK_NAME}.\n"

BUCKET_NAME=$(aws cloudformation describe-stacks --stack-name "${CI_STACK_NAME}" --query "Stacks[0].Outputs[?OutputKey=='oArtifactBucketName'].OutputValue" --output text)

printf "\n[!] Deleting ${KEY_STACK_NAME} CloudFormation Stack..."
aws cloudformation delete-stack --stack-name "${KEY_STACK_NAME}"
printf "\n[!] Waiting for ${KEY_STACK_NAME} stack to be deleted..."
aws cloudformation wait stack-delete-complete --stack-name "${KEY_STACK_NAME}"
printf "\n[-] Deleted ${KEY_STACK_NAME}.\n"

printf "\n[!] Deleting ${CI_STACK_NAME} CloudFormation Stack..."
aws cloudformation delete-stack --stack-name "${CI_STACK_NAME}"
printf "\n[!] Waiting for ${CI_STACK_NAME} stack to be deleted..."
aws cloudformation wait stack-delete-complete --stack-name "${CI_STACK_NAME}"
printf "\n[-] Deleted ${CI_STACK_NAME}.\n"

printf "\n[!] Deleting ${VPC_STACK_NAME} CloudFormation Stack..."
aws cloudformation delete-stack --stack-name "${VPC_STACK_NAME}"
printf "\n[!] Waiting for ${VPC_STACK_NAME} stack to be deleted..."
aws cloudformation wait stack-delete-complete --stack-name "${VPC_STACK_NAME}"
printf "\n[-] Deleted ${VPC_STACK_NAME}.\n"

printf "\n[!] Please empty the ${BUCKET_NAME} S3 bucket and delete it to finish deleting all resources."

printf "\n[-] Nitro Vault Successfully Uninstalled"
exit 0
