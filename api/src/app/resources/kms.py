#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
* Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
* SPDX-License-Identifier: MIT-0
*
* Permission is hereby granted, free of charge, to any person obtaining a copy of this
* software and associated documentation files (the "Software"), to deal in the Software
* without restriction, including without limitation the rights to use, copy, modify,
* merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
* permit persons to whom the Software is furnished to do so.
*
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
* INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
* PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
* HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
* OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
* SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
"""

import os
from typing import TYPE_CHECKING, Optional

import boto3
import botocore
from aws_lambda_powertools import Logger

if TYPE_CHECKING:
    from mypy_boto3_kms import KMSClient

from app import constants, models

__all__ = ["KMS"]

logger = Logger(child=True)


class KMS:
    def __init__(self, session: Optional[boto3.Session] = None, key_id: Optional[str] = None) -> None:
        if not session:
            session = boto3._get_default_session()

        if not key_id:
            key_id = os.getenv(constants.ENV_KEY_ARN)
            if not key_id:
                logger.warning(f"{constants.ENV_KEY_ARN} environment variable is not defined")

        self.client: KMSClient = session.client("kms", config=constants.BOTO3_CONFIG)
        self.key_id = key_id

    def generate_data_key_pair_without_plaintext(
        self, key_pair_spec: str, vault_id: Optional[str] = None
    ) -> models.KeyPair:
        params = {
            "KeyId": self.key_id,
            "KeyPairSpec": key_pair_spec,
        }

        # @see https://github.com/aws/aws-nitro-enclaves-sdk-c/issues/35, custom encryption context
        # is not currently supported in Nitro Enclaves
        # if vault_id:
        #    params["EncryptionContext"] = {"vault_id": vault_id}

        try:
            response = self.client.generate_data_key_pair_without_plaintext(**params)
        except botocore.exceptions.ClientError:
            logger.exception("Unable to generate data key pair")
            raise

        # Public key is a DER-encoded PKCS8 SubjectPublicKeyInfo as in RFC5280
        public_key: bytes = response["PublicKey"]

        # Private key is a DER-encoded PKCS8 PrivateKeyInfo as in RFC5208
        encrypted_private_key: bytes = response["PrivateKeyCiphertextBlob"]

        return models.KeyPair(public_key=public_key, encrypted_private_key=encrypted_private_key)
