/*******************************************************************************
 * Copyright 2018 The MIT Internet Trust Consortium
 *
 * Portions copyright 2011-2013 The MITRE Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.mitre.openid.connect.client.service

import io.ktor.server.request.*
import io.ktor.util.*
import org.mitre.openid.connect.client.model.IssuerServiceResponse

/**
 *
 * Gets an issuer for the given request. Might do dynamic discovery, or might be statically configured.
 *
 * @author jricher
 */
interface IssuerService {
    suspend fun getIssuer(requestParams: Map<String, List<String>>, requestUrl: String): IssuerServiceResponse?
}

suspend fun IssuerService.getIssuer(params: StringValues, requestUrl: String): IssuerServiceResponse? {
    return getIssuer(params.toMap(), requestUrl)
}

suspend fun IssuerService.getIssuer(request: ApplicationRequest): IssuerServiceResponse? {
    return getIssuer(request.queryParameters.toMap(), request.uri)
}
