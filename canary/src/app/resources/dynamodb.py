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
from typing import TYPE_CHECKING, Optional, Dict, Any, List

import boto3
from boto3.dynamodb.transform import TypeDeserializer
from boto3.dynamodb.types import Binary
import botocore
from aws_lambda_powertools import Logger

if TYPE_CHECKING:
    from mypy_boto3_dynamodb import DynamoDBClient, ScanPaginator

from app import constants

__all__ = ["DynamoDB"]

logger = Logger(child=True)
deserializer = TypeDeserializer()


class DynamoDB:
    def __init__(self, session: Optional[boto3.Session] = None, table_name: Optional[str] = None) -> None:
        if not session:
            session = boto3._get_default_session()

        if not table_name:
            table_name = os.getenv(constants.ENV_TABLE_NAME)
            if not table_name:
                logger.warning(f"{constants.ENV_TABLE_NAME} environment variable is not defined")

        self.client: DynamoDBClient = session.client("dynamodb", config=constants.BOTO3_CONFIG)
        self.table_name = table_name

    def maybe_get_secret_key(self) -> Optional[bytes]:
        params = {
            "ExpressionAttributeNames": {
                "#pk": constants.ATTR_PK,
                "#sk": constants.ATTR_SECRET_KEY,
            },
            "ExpressionAttributeValues": {
                ":pk": {
                    "S": "VAULT",
                },
            },
            "FilterExpression": "begins_with(#pk, :pk)",
            "Limit": constants.SCAN_LIMIT,
            "ProjectionExpression": "#sk",
            "Select": "SPECIFIC_ATTRIBUTES",
            "TableName": self.table_name,
        }

        paginator: ScanPaginator = self.client.get_paginator("scan")

        try:
            page_iterator = paginator.paginate(**params)
            for page in page_iterator:
                items: List[Dict[str, Any]] = page.get("Items", [])
                if not items:
                    return None

                for item in items:
                    item = deserializer.deserialize({"M": item})
                    sk: Optional[Binary] = item.get(constants.ATTR_SECRET_KEY)
                    if sk:
                        return bytes(sk)

        except botocore.exceptions.ClientError:
            logger.exception("Unable to scan table")

        return None
