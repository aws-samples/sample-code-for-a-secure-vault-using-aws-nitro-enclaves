# Post Deployment

Follow these steps after completing deployment to create a vault.

## Creating a Vault

To create a vault and add some initial data, you can use a script such as:

```shell
#!/bin/bash

set -euox pipefail

API_STACK_NAME="nitro-vault-ci-api"

ENDPOINT_URL=$(aws cloudformation describe-stacks --stack-name "${API_STACK_NAME}" --query "Stacks[0].Outputs[?OutputKey=='oApiUrl'].OutputValue" --output text)

curl \
  -H "Content-Type: application/json" \
  -d '{"first_name":"Test", "last_name":"User", "ssn9":"123456789", "dob":"2000-01-01"}' \
  -v \
  "${ENDPOINT_URL}/vaults"
```

To send an `HTTP POST` request to the `/vaults` endpoint.

The fields in the request payload must be present and conform to the schema defined in the [VaultSchema](https://github.com/aws-samples/sample-code-for-a-secure-vault-using-aws-nitro-enclaves/blob/main/api/src/app/models.py#L51-L68) within the API Python codebase.

## Next Steps

Follow the [User Guide](./user-guide.md) for how to interact with the vault API.

## Clean Up

The [uninstall.sh](https://github.com/aws-samples/sample-code-for-a-secure-vault-using-aws-nitro-enclaves/tree/main/uninstall.sh) script will remove each CloudFormation Stack and clean up all the resources

```shell
./uninstall.sh
```

You'll need to manually empty and remove the `nitro-vault-ci-XXXX` S3 bucket for the CodePipeline artifacts.
