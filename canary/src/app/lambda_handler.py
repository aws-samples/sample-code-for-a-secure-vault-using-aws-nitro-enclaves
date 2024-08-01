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

from typing import Dict, Any

from aws_lambda_powertools import Metrics, Logger
from aws_lambda_powertools.metrics import MetricUnit
from aws_lambda_powertools.utilities.typing import LambdaContext

from app import resources
import boto3

logger = Logger(use_rfc3339=True, utc=True)
metrics = Metrics()

session = boto3.Session()
kms = resources.KMS(session)
dynamodb = resources.DynamoDB(session)


@metrics.log_metrics(capture_cold_start_metric=False, raise_on_empty_metrics=True)
@logger.inject_lambda_context(log_event=False)
def handler(event: Dict[str, Any], context: LambdaContext) -> Dict[str, Any]:
    try:
        ciphertext = dynamodb.maybe_get_secret_key()
        if ciphertext:
            result = kms.decrypt(ciphertext)
        else:
            logger.info("No secret key found")
            result = False
    except:
        result = False
    finally:
        metrics.add_metric(name="DecryptSuccess", unit=MetricUnit.Count, value=int(result))
