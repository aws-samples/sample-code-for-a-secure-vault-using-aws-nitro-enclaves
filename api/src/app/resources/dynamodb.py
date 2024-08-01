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
from boto3.dynamodb.types import TypeDeserializer, TypeSerializer
import botocore
from aws_lambda_powertools import Logger

if TYPE_CHECKING:
    from mypy_boto3_dynamodb import DynamoDBClient

from app import constants, exceptions

__all__ = ["DynamoDB", "TransactionWriter"]

logger = Logger(child=True)


class TransactionWriter:
    def __init__(
        self,
        dynamodb: "DynamoDB",
        flush_amount: int = constants.MAX_TRANSACTION_WRITE_SIZE,
        partition_key: str = constants.ATTR_PK,
        sort_key: str = constants.ATTR_SK,
    ) -> None:
        self._dynamodb = dynamodb
        self._client = dynamodb._client
        self._table_name = dynamodb._table_name
        self._flush_amount = flush_amount
        self._items_buffer: List[Dict[str, Any]] = []
        self._partition_key = partition_key
        self._sort_key = sort_key

    @property
    def dynamodb(self) -> "DynamoDB":
        """
        Used by DataStore to get an instance back to DynamoDB
        """
        return self._dynamodb

    def put_item(self, item: Dict[str, Any], unique: bool = False) -> None:

        item = DynamoDB.serialize(item)

        action = {
            "TableName": self._table_name,
            "Item": item,
        }
        if unique:
            action |= {
                "ConditionExpression": "attribute_not_exists(#pk) and attribute_not_exists(#sk)",
                "ExpressionAttributeNames": {
                    "#pk": self._partition_key,
                    "#sk": self._sort_key,
                },
            }
        self._add_request_and_process({"Put": action})

    def update_item(
        self,
        key: Dict[str, Any],
        update_item: Optional[Dict[str, Any]] = None,
        remove_attributes: Optional[List[str]] = None,
    ) -> None:
        action = {
            "TableName": self._table_name,
            "Key": DynamoDB.serialize(key),
        }

        names: Dict[str, str] = {}
        values: Dict[str, Dict[str, Any]] = {}
        update_set: List[str] = []
        remove_set: List[str] = []
        update_expression: List[str] = []

        if update_item:
            index = 0
            for k, v in update_item.items():
                names[f"#a{index}"] = k
                values[f":a{index}"] = DynamoDB.serialize(v)
                update_set.append(f"#a{index} = :a{index}")
                index += 1

        if remove_attributes:
            for index, attribute in enumerate(remove_attributes):
                names[f"#r{index}"] = attribute
                remove_set.append(f"#r{index}")

        if update_set:
            update_expression.append("SET " + ", ".join(update_set))
        if remove_set:
            update_expression.append("REMOVE " + ", ".join(remove_set))

        if update_expression:
            action["UpdateExpression"] = " ".join(update_expression)
        if names:
            action["ExpressionAttributeNames"] = names
        if values:
            action["ExpressionAttributeValues"] = values

        self._add_request_and_process({"Update": action})

    def delete_item(self, key: Dict[str, Any]) -> None:
        action = {
            "TableName": self._table_name,
            "Key": DynamoDB.serialize(key),
        }
        self._add_request_and_process({"Delete": action})

    def check_item(self, key: Dict[str, Any], exists: Optional[bool] = None) -> None:
        action = {
            "TableName": self._table_name,
            "Key": DynamoDB.serialize(key),
        }
        if exists is True:
            action |= {
                "ConditionExpression": "attribute_exists(#pk) and attribute_exists(#sk)",
                "ExpressionAttributeNames": {
                    "#pk": self._partition_key,
                    "#sk": self._sort_key,
                },
            }
        elif exists is False:
            action |= {
                "ConditionExpression": "attribute_not_exists(#pk) and attribute_not_exists(#sk)",
                "ExpressionAttributeNames": {
                    "#pk": self._partition_key,
                    "#sk": self._sort_key,
                },
            }
        self._add_request_and_process({"ConditionCheck": action})

    def _add_request_and_process(self, request: Dict[str, Any]) -> None:
        self._items_buffer.append(request)
        self._flush_if_needed()

    def _flush_if_needed(self) -> None:
        if len(self._items_buffer) >= self._flush_amount:
            self._flush()

    def _flush(self) -> None:
        items_to_send = self._items_buffer[: self._flush_amount]
        self._items_buffer = self._items_buffer[self._flush_amount :]

        logger.debug("transact_write_items", TransactItems=items_to_send)

        try:
            self._client.transact_write_items(TransactItems=items_to_send)  # type: ignore
        except self._client.exceptions.TransactionCanceledException as ex:
            reasons = ex.response.get("CancellationReasons", [])
            logger.exception(f"Transaction canceled: {reasons}")
            raise exceptions.ConflictException("Transaction canceled")

        logger.debug(f"Transaction write sent {len(items_to_send)}, unprocessed: {len(self._items_buffer)}")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        while self._items_buffer:
            self._flush()


class DynamoDB:
    _deserializer = TypeDeserializer()
    _serializer = TypeSerializer()

    def __init__(self, session: Optional[boto3.Session] = None, table_name: Optional[str] = None) -> None:
        if not session:
            session = boto3._get_default_session()

        if not table_name:
            table_name = os.getenv(constants.ENV_TABLE_NAME)
            if not table_name:
                logger.warning(f"{constants.ENV_TABLE_NAME} environment variable is not defined")

        self._session = session
        self._table_name = table_name
        self._client: DynamoDBClient = session.client("dynamodb", config=constants.BOTO3_CONFIG)

    @property
    def session(self) -> boto3.Session:
        return self._session

    def transaction_writer(self) -> TransactionWriter:
        return TransactionWriter(self)

    def get_item(self, key: Dict[str, Any], attributes: Optional[List[str]] = None) -> Dict[str, Any]:
        params = {
            "Key": DynamoDB.serialize(key),
            "TableName": self._table_name,
        }
        if attributes:
            names: Dict[str, str] = {}
            projection_expression: List[str] = []
            for index, attribute in enumerate(attributes):
                names[f"#a{index}"] = attribute
                projection_expression.append(f"#a{index}")

            params["ProjectionExpression"] = ",".join(projection_expression)
            params["ExpressionAttributeNames"] = names

        logger.debug(f"Getting item", params=params)

        try:
            response = self._client.get_item(**params)
        except botocore.exceptions.ClientError:
            logger.exception("Unable to get item")
            raise exceptions.InternalServerError("Unable to get item")

        item: Dict[str, Any] = response.get("Item", {})
        if not item:
            raise exceptions.NotFoundException("Item not found")

        return self.deserialize(item)

    @classmethod
    def deserialize(cls, item: Any) -> Any:
        if not item:
            return item

        if isinstance(item, dict) and "M" not in item:
            item = {"M": item}

        return cls._deserializer.deserialize(item)

    @classmethod
    def serialize(cls, obj: Any, strip_wrapper: bool = True) -> Dict[str, Any]:
        result = cls._serializer.serialize(obj)
        if strip_wrapper and "M" in result:
            result: Dict[str, Any] = result["M"]
        return result
