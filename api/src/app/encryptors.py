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
import struct
from typing import Dict, Any, Optional

from aws_lambda_powertools import Logger
import boto3
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
import app.hpke as hpke

from app import constants, models, encoders, resources

__all__ = ["HpkeAdapter"]

logger = Logger(child=True)


class BaseAdapter(abc.ABC):
    KEY_PAIR_SPEC: str

    def __init__(self, session: Optional[boto3.Session] = None) -> None:
        self.kms = resources.KMS(session)

    def generate_data_key_pair_without_plaintext(self, vault_id: Optional[str] = None) -> models.KeyPair:
        return self.kms.generate_data_key_pair_without_plaintext(self.KEY_PAIR_SPEC, vault_id)

    @abc.abstractmethod
    def encrypt_values(
        self, public_key: bytes, plaintext_values: Dict[str, Any], vault_id: Optional[str] = None
    ) -> Dict[str, str]:
        raise NotImplementedError


class HpkeAdapter(BaseAdapter):
    KEY_PAIR_SPEC = "ECC_NIST_P384"
    SUITE = hpke.Suite__DHKEM_P384_HKDF_SHA384__HKDF_SHA384__AES_256_GCM()

    def get_suite_id(self) -> bytes:
        suite_id = b"HPKE" + struct.pack(">HHH", self.SUITE.KEM.ID, self.SUITE.KDF.ID, self.SUITE.AEAD.ID)
        return suite_id

    def _encrypt_value(self, public_key: bytes, field: str, info: bytes, plaintext: bytes) -> models.EncryptedData:
        aad: bytes = field.strip().lower().encode()

        encap, ciphertext = self.SUITE.seal(peer_pubkey=public_key, info=info, aad=aad, message=plaintext)

        return models.EncryptedData(encapped_key=encap, ciphertext=ciphertext)

    def encrypt_values(
        self, public_key: bytes, plaintext_values: Dict[str, Any], vault_id: Optional[str] = None
    ) -> Dict[str, str]:
        if not public_key:
            return plaintext_values
        if not plaintext_values:
            return {}

        pk: ec.EllipticCurvePublicKey = serialization.load_der_public_key(public_key)

        info = vault_id.encode()
        encoder = encoders.HexEncoder()

        encrypted_values: Dict[str, str] = {}

        for field, value in plaintext_values.items():
            data = self._encrypt_value(
                public_key=pk,
                field=field,
                info=info,
                plaintext=str(value).encode(),
            )
            encrypted_values[field] = encoder.encode(data)

            # encrypt last 4 digits of SSN separately from full SSN
            if field == constants.ATTR_SSN9:

                last_four_ssn = str(value)[-4:]  # strip off last 4 digits

                data = self._encrypt_value(
                    public_key=pk,
                    field=constants.ATTR_SSN4,
                    info=info,
                    plaintext=last_four_ssn.encode(),
                )
                encrypted_values[constants.ATTR_SSN4] = encoder.encode(data)

        del plaintext_values

        return encrypted_values
