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

import abc
from typing import Optional, List, Dict, NamedTuple

from aws_lambda_powertools.shared.types import Annotated
from aws_lambda_powertools.utilities.parser import BaseModel, Field


class KeyPair(NamedTuple):
    public_key: bytes
    encrypted_private_key: bytes


class EncryptedData(NamedTuple):
    encapped_key: bytes
    ciphertext: bytes


class VaultBaseModel(BaseModel, abc.ABC):
    class Config:
        anystr_strip_whitespace = True
        extra = "forbid"
        frozen = True


class VaultSchema(VaultBaseModel):
    email: Annotated[str, Field(description="Primary email address", max_length=1024)] = None
    first_name: Annotated[str, Field(max_length=1024)] = None
    middle_name: Annotated[str, Field(max_length=1024)] = None
    last_name: Annotated[str, Field(max_length=1024)] = None
    phone_number: Annotated[str, Field(description="Primary phone number", regex=r"^\+[1-9]\d{1,14}$")] = None
    ssn9: Annotated[str, Field(description="9-digit string", regex=r"^\d{9}$", min_length=9, max_length=9)] = None
    ssn4: Annotated[str, Field(description="Last four of the SSN", regex=r"^\d{4}$", min_length=4, max_length=4)] = None
    dob: Annotated[
        str, Field(description="Date of birth", regex=r"^\d{4}-\d{2}-\d{2}$", min_length=10, max_length=10)
    ] = None
    address1: Annotated[str, Field(description="First address line", max_length=1024)] = None
    address2: Annotated[str, Field(description="Second Address Line 2", max_length=1024)] = None
    address3: Annotated[str, Field(description="Address Line 3", max_length=1024)] = None
    city: Annotated[str, Field(max_length=1024)] = None
    state: Annotated[str, Field(max_length=1024)] = None
    postal_code: Annotated[str, Field(regex=r"^([A-Za-z0-9\- ]*)$")] = None
    country: Annotated[str, Field(min_length=2, max_length=2, regex=r"^[A-Za-z]{2}$")] = None


class CreateVaultRequest(VaultSchema):
    pass


class CreateVaultResponse(VaultBaseModel):
    id_: str = Field(alias="id")


class UpdateVaultRequest(VaultSchema):
    pass


class DeleteVaultRequest(VaultBaseModel):
    delete_all: Optional[bool] = Field(title="If true, will remove all fields", default=None)
    fields: Optional[List[str]] = Field(title="Fields to delete", default=None)


class DecryptVaultRequest(VaultBaseModel):
    fields: List[str] = Field(title="Fields to decrypt")
    reason: str = Field(title="Reason for decryption")
    expressions: Optional[Dict[str, str]] = Field(title="field and CEL expressions", default_factory=dict)
