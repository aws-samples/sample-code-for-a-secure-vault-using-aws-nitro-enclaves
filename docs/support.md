# Support

Best effort support is available through [GitHub Issues](https://github.com/aws-samples/sample-code-for-a-secure-vault-using-aws-nitro-enclaves/issues) or by emailing [aws-nitro-enclaves-vault-solution@amazon.com](mailto:aws-nitro-enclaves-vault-solution@amazon.com).

## Roadmap

Unordered list of future improvement ideas.

- [ ] [api,enclave] Replace the existing hex-encoding encrypted data storage scheme with something else (such as [Amazon Ion](https://amazon-ion.github.io/ion-docs/))

---

## Known Issues

1. The [VPC template](https://github.com/aws-samples/sample-code-for-a-secure-vault-using-aws-nitro-enclaves/blob/main/vpc_template.yml) has a CloudFormation parameter called `pEnableVpcEndpoints` that will provision the VPC with VPC Interface Endpoints instead of public subnets and NAT Gateways. VPC Interface Endpoints are currently not supported due to [aws-nitro-enclaves-acm#130](https://github.com/aws/aws-nitro-enclaves-acm/pull/130) (GitHub Issue)

2. The [KMS template](https://github.com/aws-samples/sample-code-for-a-secure-vault-using-aws-nitro-enclaves/blob/main/kms_template.yml) has a CloudFormation parameter called `pPrimaryKeyArn` that will provision a replica KMS key in another region referencing the primary key. DynamoDB is also configured as a [global table](https://aws.amazon.com/dynamodb/global-tables/) to support multi-region workloads. A multi-region configuration hasn't been tested, but should be supported using the chosen services.

3. The [CI template](https://github.com/aws-samples/sample-code-for-a-secure-vault-using-aws-nitro-enclaves/blob/main/ci_template.yml) has a CloudFormation parameter called `pUseCodeBuildFleet` that will provision two [reserved capacity](https://docs.aws.amazon.com/codebuild/latest/userguide/fleets.html) AWS CodeBuild compute instances for the builds. This will dramatically speed up the `BuildParent` and `BuildEnclave` projects as the Docker images will now be cached between runs. CodeBuild Fleets are more expensive than on-demand CodeBuild compute, so they are not enabled by default.

4. The [API template](https://github.com/aws-samples/sample-code-for-a-secure-vault-using-aws-nitro-enclaves/blob/main/api/template.yml) has a CloudFormation parameter called `pVpcEndpointIds` that will provision a [private api](https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-private-apis.html) in Amazon API Gateway if [VPC Interface Endpoints](https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-vpc-endpoint-policies.html) for API Gateway are provided.

---

## Troubleshooting

1. Unable to delete `nitro-vault-ci-api` or `nitro-vault-ci-vault` CloudFormation stacks due to `Role arn:aws:iam::123456789012:role/nitro-vault-ci-rCloudFormationRole-XXXXXXXXX is invalid or cannot be assumed`

    This can occur if the `nitro-vault-ci` stack is deleted first that removes the `CloudFormationRole` IAM role used by both of these stacks. You can create a new IAM role named the same as the missing role and temporarily grant it to the `AdministratorAccess` policy to clean up the remaining stacks, then delete the role.

2. API returns "Unable to decrypt values" when calling POST /v1/vaults/:vault_id/decrypt

    First check the CloudWatch Logs for the Lambda function in the `/aws/lambda/nitro-vault-ci-api` Log Group to see if there are any errors coming from the Lambda function itself. The logs will say whether it received an invalid response from the vault API or not.

    Next, go to the EC2 console, and connect to the instance using AWS Systems Manager and use `sudo` to become root by running `sudo su -`.

      1. `cat /var/log/user-data.log` - this should show a successful execution of the user data script
      2. `ps auwx | grep nginx` - should show a running `nginx` process
      3. `ps auwx | grep parent` - should show a running `parent` process listening on localhost
      4. `journal -xe -u nitro-vault-server -f` - should show any logs coming from the parent process.

3. Resource handler returned message: "A policy called nitro-vault-ci-boundary already exists. Duplicate names are not allowed.

    Delete any existing `nitro-vault-ci-boundary` IAM policies and re-run the `nitro-vault-ci` CloudFormation stack.
