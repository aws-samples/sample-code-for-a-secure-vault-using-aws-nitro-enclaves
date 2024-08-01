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

from aws_lambda_powertools import Logger, Tracer, Metrics
from aws_lambda_powertools.event_handler import APIGatewayRestResolver
from aws_lambda_powertools.event_handler.openapi.exceptions import RequestValidationError
from aws_lambda_powertools.event_handler.openapi.models import License
from aws_lambda_powertools.utilities.typing import LambdaContext
from aws_lambda_powertools.logging import correlation_paths

from app import middlewares, routers, utils

logger = Logger(use_rfc3339=True, utc=True)
tracer = Tracer()
metrics = Metrics()

resolver = APIGatewayRestResolver(enable_validation=True)
resolver.include_router(routers.vaults_router, prefix="/vaults")
resolver.use(
    middlewares=[
        middlewares.txn_middleware,
        middlewares.headers_middleware,
    ]
)
resolver.enable_swagger(
    path="/swagger",
    title="Nitro Vault API",
    version="0.1.0",
    summary="API to securely store PII/PHI data",
    description="This API implements CRUD operations for the vault application",
    license_info=License(name="MIT-0", identifier="MIT-0"),
)


@resolver.exception_handler(RequestValidationError)
def handle_invalid_schema(ex: RequestValidationError):
    metadata = {
        "path": resolver.current_event.path,
        "query_strings": resolver.current_event.query_string_parameters,
        "errors": ex.errors(),
    }
    logger.error("Request failed validation", extra=metadata)

    return utils.error_response(422, "Invalid request data")


@metrics.log_metrics(capture_cold_start_metric=False)
@logger.inject_lambda_context(log_event=False, correlation_id_path=correlation_paths.API_GATEWAY_REST)
@tracer.capture_lambda_handler(capture_response=False)
def handler(event: Dict[str, Any], context: LambdaContext) -> Dict[str, Any]:
    return resolver.resolve(event, context)
