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
from warnings import deprecated

from app import models, constants

__all__ = ["HexEncoder"]


class BaseEncoder(abc.ABC):
    @abc.abstractmethod
    def encode(self, data: models.EncryptedData) -> str | bytes:
        raise NotImplementedError


class HexEncoder(BaseEncoder):
    @deprecated("HexEncoder is deprecated, use BinaryEncoder instead")
    def encode(self, data: models.EncryptedData) -> str:
        return f"{data.encapped_key.hex()}{constants.PACK_SEPARATOR}{data.ciphertext.hex()}"


class BinaryEncoder(BaseEncoder):
    def encode(self, data: models.EncryptedData) -> bytes:
        print(f"encapped_key: {len(data.encapped_key)}, ciphertext: {len(data.ciphertext)}")
        return data.encapped_key + data.ciphertext
