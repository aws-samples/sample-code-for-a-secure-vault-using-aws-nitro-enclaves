#!/bin/bash

set -euo pipefail

HOSTED_ZONE_ID=
DOMAIN_NAME=
GITHUB_REPO=
GITHUB_BRANCH=main

export $(grep -v '^#' .env | xargs -0)

if [[ -z "${HOSTED_ZONE_ID}" ]]; then
    read -p "[?] Hosted Zone ID: " HOSTED_ZONE_ID
fi

if [[ -z "${DOMAIN_NAME}" ]]; then
    read -p "[?] Domain Name: " DOMAIN_NAME
fi

if [[ -z "${GITHUB_REPO}" ]]; then
    read -p "[?] GitHub Repository (ex. \"aws-samples/sample-code-for-a-secure-vault-using-aws-nitro-enclaves\"): " GITHUB_REPO
fi

printf "\n#################################################################################"
printf "\n## Please ensure the IAM principal (IAM User or Role) you are using to execute ##"
printf "\n## this installation script includes a \"dp:exclude:network\" tag key with a     ##"
printf "\n## tag value of \"true\" or the installation will fail.                          ##"
printf "\n#################################################################################\n\n"

STACK_PREFIX=nitro-vault
VPC_STACK_NAME="${STACK_PREFIX}-vpc"
KEY_STACK_NAME="${STACK_PREFIX}-key"
CI_STACK_NAME="${STACK_PREFIX}-ci"
VAULT_STACK_NAME="${CI_STACK_NAME}-vault"
API_STACK_NAME="${CI_STACK_NAME}-api"

get-output () {
  local output=$(aws cloudformation describe-stacks --stack-name "$1" --query "Stacks[0].Outputs[?OutputKey=='$2'].OutputValue" --output text)
  echo "${output}"
}

printf "[!] Deploying ${VPC_STACK_NAME} stack..."
aws cloudformation deploy --stack-name "${VPC_STACK_NAME}" --template-file vpc_template.yml \
  --parameter-overrides \
    "pDomainName=${DOMAIN_NAME}" \
  --tags "AppManagerCFNStackKey=${VPC_STACK_NAME}"

VPC_ID=$(get-output "${VPC_STACK_NAME}" "oVpcId")
VPC_CIDR=$(get-output "${VPC_STACK_NAME}" "oVpcCidrBlock")
VPC_API_SUBNET_IDS=$(get-output "${VPC_STACK_NAME}" "oApiSubnetIds")
VPC_VAULT_SUBNET_IDS=$(get-output "${VPC_STACK_NAME}" "oInstanceSubnetIds")

printf "\n[!] Deploying ${KEY_STACK_NAME} stack..."

aws cloudformation deploy --stack-name "${KEY_STACK_NAME}" --template-file kms_template.yml \
  --parameter-overrides \
    "pVpcId=${VPC_ID}" \
  --tags "AppManagerCFNStackKey=${KEY_STACK_NAME}"

KEY_ARN=$(get-output "${KEY_STACK_NAME}" "oEncryptionKeyArn")

printf "\n[!] Deploying ${CI_STACK_NAME} stack..."

aws cloudformation deploy --stack-name "${CI_STACK_NAME}" --template-file ci_template.yml \
  --parameter-overrides \
    "pVpcId=${VPC_ID}" \
    "pVpcCidr=${VPC_CIDR}" \
    "pApiSubnetIds=${VPC_API_SUBNET_IDS}" \
    "pInstanceSubnetIds=${VPC_VAULT_SUBNET_IDS}" \
    "pEncryptionKeyArn=${KEY_ARN}" \
    "pHostedZoneId=${HOSTED_ZONE_ID}" \
    "pDomainName=${DOMAIN_NAME}" \
    "pRepositoryId=${GITHUB_REPO}" \
    "pBranchName=${GITHUB_BRANCH}" \
    "pKmsCloudFormationStackName=${KEY_STACK_NAME}" \
  --capabilities CAPABILITY_IAM CAPABILITY_NAMED_IAM \
  --tags "AppManagerCFNStackKey=${CI_STACK_NAME}"

PIPELINE_NAME=$(get-output "${CI_STACK_NAME}" "oCodePipelineName")

while true; do
  read -p "[?] Do you want to create a new private signing key for AWS Nitro Enclaves? (y/n) " yn
  case $yn in
    [Yy]*)
      SIGNING_SECRET_ARN=$(get-output "${CI_STACK_NAME}" "oSigningSecretArn")
      printf "\n[+] Updating secret in AWS SecretsManager with private signing key..."
      aws secretsmanager update-secret --secret-id "${SIGNING_SECRET_ARN}" --secret-string "$(openssl ecparam -name secp384r1 -genkey)"
      break
      ;;
    *)
      printf "\n[!] Not updating secret in AWS SecretsManager.\n\n"
      break
      ;;
  esac
done

PIPELINE_STATUS=$(aws codepipeline list-pipeline-executions --pipeline-name "${PIPELINE_NAME}" --query "pipelineExecutionSummaries[0].status")

if [ "$PIPELINE_STATUS" = '"Failed"' ]; then
  printf "\n[+] Opening AWS Console to complete set up AWS CodeConnections to GitHub..."
  printf "\n[+] Launching URL: https://${AWS_REGION}.console.aws.amazon.com/codesuite/settings/connections?region=${AWS_REGION}"
  printf "\n[?] Select the radio button next to ${CI_STACK_NAME} and then click on \"Update pending connection\"\n\n"

  open "https://${AWS_REGION}.console.aws.amazon.com/codesuite/settings/connections?region=${AWS_REGION}"

  read -s -n 1 -p "Press any key to start the pipeline..."

  aws codepipeline start-pipeline-execution --name "${PIPELINE_NAME}"
fi

printf "\n[!] Waiting for pipeline to complete...\n\n"

# Loop until pipeline completes
while :
do
  PIPELINE_STATUS=$(aws codepipeline list-pipeline-executions --pipeline-name "${PIPELINE_NAME}" --query "pipelineExecutionSummaries[0].status")

  case $PIPELINE_STATUS in
    '"InProgress"')
      printf "\n[!] Pipeline in progress, sleeping 5 seconds..."
      sleep 5
      ;;
    '"Succeeded"')
      printf "\n[+] Pipeline finished successfully."
      break
      ;;
    '"Failed"')
      printf "\n[X] Pipeline failed."
      break
      ;;
    *)
      printf "\n[X] Unknown pipeline status: ${PIPELINE_STATUS}"
      break
      ;;
  esac
done

SWAGGER_URL=$(get-output "${API_STACK_NAME}" "oSwaggerUrl")

printf "\n[+] Opening Swagger UI at ${SWAGGER_URL}..."

open "${SWAGGER_URL}"

printf "\n[+] Done!"
exit 0
