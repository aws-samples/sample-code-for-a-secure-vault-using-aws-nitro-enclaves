# About the AWS Nitro Enclaves Vault

Welcome to the AWS Nitro Enclaves Vault documentation.

## Overview

This repository contains a sample secure vault solution built using [AWS Nitro Enclaves](https://docs.aws.amazon.com/enclaves/latest/user/nitro-enclave.html), a feature available exclusively through the [AWS Nitro System](https://aws.amazon.com/ec2/nitro/) hypervisor on supported [Amazon EC2](https://aws.amazon.com/ec2/) instances.

A vault solution is useful when you need to ensure sensitive data (such as [Protected Health Information](https://en.wikipedia.org/wiki/Protected_health_information) (PHI)/[Personally Identifiable Information](https://en.wikipedia.org/wiki/Personal_data) (PII)) is properly secured at rest and can only be decrypted through approved channels.

AWS Nitro Enclaves is an Amazon EC2 feature that allows you to create isolated execution environments, called enclaves, from Amazon EC2 instances. Enclaves are separate, hardened, and highly-constrained virtual machines. They provide only secure local socket connectivity with their parent instance. They have no persistent storage, interactive access, or external networking. Users cannot SSH into an enclave, and the data and applications inside the enclave cannot be accessed by the processes, applications, or users (root or admin) of the parent instance.

## Key Features

* **Flexible Data Model**: Additional fields can be supported in the vault by modifying the [existing schema](https://github.com/aws-samples/sample-code-for-a-secure-vault-using-aws-nitro-enclaves/blob/main/api/src/app/models.py#L51-L68).

* **Standardized Security**: Implements [RFC 9180](https://www.rfc-editor.org/rfc/rfc9180.html) Hybrid Public Key Encryption (HPKE) using `DHKEM(P-384, HKDF-SHA384)` for key encapsulation (KEM), `HKDF-SHA384` as a key derivation function (KDF), and `AES-256-GCM` as an authenticated encryption with associated data (AEAD) function. The backing symmetric key is securely stored using the [AWS Key Management Service](https://aws.amazon.com/kms/) (AWS KMS).
