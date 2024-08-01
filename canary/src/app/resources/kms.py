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

from typing import TYPE_CHECKING, Optional

import boto3
from aws_lambda_powertools import Logger

if TYPE_CHECKING:
    from mypy_boto3_kms import KMSClient

from app import constants

__all__ = ["KMS"]

logger = Logger(child=True)


class KMS:
    def __init__(self, session: Optional[boto3.Session] = None) -> None:
        if not session:
            session = boto3._get_default_session()
        self.client: KMSClient = session.client("kms", config=constants.BOTO3_CONFIG)

    def decrypt(self, ciphertext: bytes) -> bool:
        params = {
            "CiphertextBlob": ciphertext,
            "DryRun": True,
        }

        try:
            self.client.decrypt(**params)
        except self.client.exceptions.DryRunOperationException:
            logger.warning("Dry run operation succeeded")
            return True
        except:
            logger.exception("Unable to decrypt")
            # ignore all other exceptions
            pass
        return False
