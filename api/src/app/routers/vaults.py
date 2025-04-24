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

from typing import Dict, Any, Optional, List, Annotated

from aws_lambda_powertools import Logger, Tracer, Metrics
from aws_lambda_powertools.event_handler.api_gateway import Router
from aws_lambda_powertools.event_handler.exceptions import (
    NotFoundError,
    InternalServerError,
)
from aws_lambda_powertools.metrics import MetricUnit
from aws_lambda_powertools.event_handler.openapi.params import Body, Query, Path

from app import resources, vault, exceptions, utils, constants, models

__all__ = ["router"]


tracer = Tracer()
logger = Logger(child=True)
metrics = Metrics()
router = Router()

ALLOWED_KEYS: List[str] = list(models.VaultSchema.model_fields.keys())


@router.post("/", summary="Create a vault")
@tracer.capture_method(capture_response=False)
def create_vault(
    body: Annotated[models.CreateVaultRequest, Body(embed=False, example=constants.EXAMPLE_CREATE)],
) -> Dict[str, Any]:
    txn: Optional[resources.TransactionWriter] = router.context.get("txn")
    if not txn:
        metrics.add_metric(name="TransactionNotFound", unit=MetricUnit.Count, value=1)
        logger.error("Transaction not found")
        raise InternalServerError("Transaction not found")

    vault_id = vault.create_vault(txn, body.model_dump(by_alias=True, exclude_none=True))

    metrics.add_metric(name="VaultCreate", unit=MetricUnit.Count, value=1)

    response = {"id": vault_id}
    return response


@router.get("/<vault_id>", summary="Get a vault")
@tracer.capture_method(capture_response=False)
def get_vault(
    vault_id: Annotated[str, Path(title="Vault ID")],
    fields: Annotated[
        Optional[str], Query(title="Fields to get", max_length=1024, example="first_name,last_name,dob")
    ] = None,
) -> Dict[str, Any]:

    tracer.put_annotation(key="vault_id", value=vault_id)
    logger.append_keys(vault_id=vault_id)

    txn: Optional[resources.TransactionWriter] = router.context.get("txn")
    if not txn:
        metrics.add_metric(name="TransactionNotFound", unit=MetricUnit.Count, value=1)
        logger.error("Transaction not found")
        raise InternalServerError("Transaction not found")

    if fields:
        attributes = [field.strip().lower() for field in fields.split(",")]
    else:
        attributes: List[str] = []

    attributes.append(constants.ATTR_PK)

    try:
        item = vault.get_vault(txn, vault_id, attributes)
    except exceptions.InternalServerError:
        raise InternalServerError("Unable to get vault")
    except exceptions.NotFoundException:
        raise NotFoundError("Vault not found")

    response = {}

    for key in attributes:
        if key not in ALLOWED_KEYS:
            continue
        response[key] = bool(key in item)

    return response


@router.delete("/<vault_id>", summary="Delete a vault")
@tracer.capture_method(capture_response=False)
def delete_vault(
    vault_id: Annotated[str, Path(title="Vault ID")],
    body: Annotated[models.DeleteVaultRequest, Body(embed=False, example=constants.EXAMPLE_DELETE)],
) -> Dict[str, Any]:

    tracer.put_annotation(key="vault_id", value=vault_id)
    logger.append_keys(vault_id=vault_id)

    txn: Optional[resources.TransactionWriter] = router.context.get("txn")
    if not txn:
        metrics.add_metric(name="TransactionNotFound", unit=MetricUnit.Count, value=1)
        logger.error("Transaction not found")
        raise InternalServerError("Transaction not found")

    vault.delete_vault(txn, vault_id, body.fields, body.delete_all)

    metrics.add_metric(name="VaultDelete", unit=MetricUnit.Count, value=1)

    return {}


@router.patch("/<vault_id>", summary="Update a vault")
@tracer.capture_method(capture_response=False)
def update_vault(
    vault_id: Annotated[str, Path(title="Vault ID")],
    body: Annotated[models.UpdateVaultRequest, Body(embed=False, example=constants.EXAMPLE_UPDATE)],
) -> Dict[str, Any]:

    tracer.put_annotation(key="vault_id", value=vault_id)
    logger.append_keys(vault_id=vault_id)

    txn: Optional[resources.TransactionWriter] = router.context.get("txn")
    if not txn:
        metrics.add_metric(name="TransactionNotFound", unit=MetricUnit.Count, value=1)
        logger.error("Transaction not found")
        raise InternalServerError("Transaction not found")

    try:
        vault.update_vault(txn, vault_id, body.model_dump(by_alias=True, exclude_none=True))
    except exceptions.InternalServerError:
        raise InternalServerError("Unable to update vault")
    except exceptions.NotFoundException:
        raise NotFoundError("Vault not found")

    metrics.add_metric(name="VaultUpdate", unit=MetricUnit.Count, value=1)

    return {}


@router.post("/<vault_id>/decrypt", summary="Decrypt data from a vault")
@tracer.capture_method(capture_response=False)
def decrypt_vault(
    vault_id: Annotated[str, Path(title="Vault ID")],
    body: Annotated[models.DecryptVaultRequest, Body(embed=False, example=constants.EXAMPLE_DECRYPT)],
) -> Dict[str, Any]:

    txn: Optional[resources.TransactionWriter] = router.context.get("txn")
    if not txn:
        metrics.add_metric(name="TransactionNotFound", unit=MetricUnit.Count, value=1)
        logger.error("Transaction not found")
        raise InternalServerError("Transaction not found")

    try:
        data = vault.decrypt_vault(txn, vault_id, body.fields, body.expressions)
    except exceptions.InternalServerError:
        raise InternalServerError("Unable to decrypt values")
    except exceptions.NotFoundException:
        raise NotFoundError("Vault not found")

    metrics.add_metric(name="VaultDecrypt", unit=MetricUnit.Count, value=1)

    now = utils.now_micros()

    log = {
        constants.ATTR_PK: utils.build_key("LOG", vault_id),
        constants.ATTR_SK: str(now),
        constants.ATTR_EVENT: "DecryptVault",
        constants.ATTR_REASON: body.reason,
        constants.ATTR_FIELDS: body.fields,
        constants.ATTR_ID: vault_id,
        constants.ATTR_CREATED_AT: now,
    }

    txn.put_item(log)

    response = {
        "data": data.get("fields", {}),
    }
    if "errors" in data:
        response["errors"] = data.get("errors", [])

    return response
