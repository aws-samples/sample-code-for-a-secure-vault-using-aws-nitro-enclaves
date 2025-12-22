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

from botocore.config import Config

from app import enums

ATTR_PK = "pk"
ATTR_SK = "sk"
ATTR_ID = "_id"
ATTR_HPKE_SUITE_ID = "_hs"
ATTR_SECRET_KEY = "_sk"
ATTR_PUBLIC_KEY = "_pk"
ATTR_CREATED_AT = "_ct"
ATTR_MODIFIED_AT = "_mt"
ATTR_EVENT = "_e"
ATTR_REASON = "_r"
ATTR_FIELDS = "_f"
ATTR_SSN9 = "ssn9"
ATTR_SSN4 = "ssn4"
ATTR_VERSION = "_v"
BOTO3_CONFIG = Config(
    connect_timeout=1.0,
    read_timeout=1.0,
    retries={
        "max_attempts": 15,
        "mode": "standard",
    },
    tcp_keepalive=True,
)
ENV_AWS_REGION = "AWS_REGION"
ENV_KEY_ARN = "KEY_ARN"
ENV_TABLE_NAME = "TABLE_NAME"
ENV_VAULT_URL = "VAULT_URL"
DEFAULT_VERSION = "v0"
DEFAULT_ENCODING = enums.EncodingVersion.BINARY
KEY_SEPARATOR = "##"
PACK_SEPARATOR = "#"
MAX_TRANSACTION_WRITE_SIZE = 100
VAULT_TIMEOUT_SECS = 5

EXAMPLE_CREATE = {
    "email": "test@example.com",
    "phone_number": "+15554443333",
    "first_name": "Test",
    "last_name": "User",
    "address1": "123 Main St",
    "city": "Anytown",
    "state": "CA",
    "postal_code": "12345",
    "country": "US",
    "ssn9": "123456789",
    "dob": "2000-07-04",
}

EXAMPLE_DELETE = {
    "delete_all": False,
    "fields": ["first_name"],
}

EXAMPLE_UPDATE = {
    "first_name": "Updated First Name",
    "last_name": "Updated Last Name",
}

EXAMPLE_DECRYPT = {
    "fields": [
        "first_name",
        "last_name",
        "email",
        "phone_number",
        "address1",
        "city",
        "state",
        "postal_code",
        "country",
        "dob",
        "ssn9",
        "ssn4",
    ],
    "reason": "TESTING - API test through Swagger UI",
    "expressions": {
        "age": "date(dob).age()",
        "ssn9_sha256": "sha256(ssn9)",
        "ssn9_base64": "base64_encode(ssn9)",
    },
}
