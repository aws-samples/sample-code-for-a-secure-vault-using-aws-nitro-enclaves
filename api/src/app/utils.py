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

import base64
import datetime
import json
import time
from typing import Any, Union
import uuid

from aws_lambda_powertools.event_handler import Response, content_types
from aws_lambda_powertools.shared.json_encoder import Encoder
from boto3.dynamodb.types import Binary
from pksuid import PKSUID

from app import constants

__all__ = [
    "json_dumps",
    "generate_id",
    "error_response",
    "now_micros",
    "build_key",
    "b64_encode",
]


class CustomEncoder(Encoder):
    """
    JSONEncoder subclass that knows how to encode date/time, decimal types, and
    UUIDs.
    """

    def default(self, obj):
        # See "Date Time String Format" in the ECMA-262 specification.
        if isinstance(obj, datetime.datetime):
            return obj.replace(microsecond=0).isoformat().replace("+00:00", "Z")
        elif isinstance(obj, datetime.date):
            return obj.isoformat()
        elif isinstance(obj, uuid.UUID):
            return str(obj)
        else:
            return super().default(obj)


def json_dumps(obj: Any) -> str:
    """
    Compact JSON encoder
    """
    return json.dumps(obj, indent=None, separators=(",", ":"), sort_keys=True, cls=CustomEncoder)


def generate_id(prefix: str) -> str:
    """
    Return a unique ID
    """

    id = PKSUID(prefix)
    return str(id)


def error_response(status_code: int, message: str) -> Response:
    """
    Return an error response
    """

    data = {"statusCode": status_code, "message": message}

    return Response(
        status_code=status_code,
        content_type=content_types.APPLICATION_JSON,
        body=json_dumps(data),
    )


def now_micros() -> int:
    """
    Return the current time in microseconds
    """
    return time.time_ns() // 1000


def build_key(*args: str) -> str:
    """
    Build a key from a list of arguments
    """
    return constants.KEY_SEPARATOR.join(args)


def b64_encode(value: Union[bytes, Binary]) -> str:
    return base64.standard_b64encode(bytes(value)).decode()
