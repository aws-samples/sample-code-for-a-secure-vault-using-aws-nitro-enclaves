# Frequently Asked Questions

1. Does this solution use the [AWS Encryption SDK](https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/introduction.html)?

    No. The AWS Encryption SDK currently does not support the Rust programming language which is used by the application running within the Nitro Enclave.

2. Why doesn't this solution provide an encryption context when generating a data key pair from KMS?

    Providing an [encryption context](https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#encrypt_context) is a [best practice](https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/best-practices.html) but unfortunately the `kmstool-enclave-cli` tool [does not support](https://github.com/aws/aws-nitro-enclaves-sdk-c/issues/35) (GitHub aws-nitro-enclaves-sdk-c#35) providing an encryption context when calling the [KMS Decrypt API](https://docs.aws.amazon.com/kms/latest/APIReference/API_Decrypt.html).

    Additional authenticated data (AAD) is provided when data is encrypted and decrypted and not referenced with the stored encrypted data.
