/*******************************************************************************
 * Copyright 2018 The MIT Internet Trust Consortium
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
package org.mitre.uma.view

import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.response.*
import io.ktor.util.pipeline.*
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.json.addAll
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import org.mitre.uma.model.ResourceSet
import org.mitre.util.getLogger
import org.mitre.web.util.config
import java.io.IOException


suspend fun PipelineContext<Unit, ApplicationCall>.resourceEntitySetView(
    rs: ResourceSet,
    location: String? = null,
    code: HttpStatusCode= HttpStatusCode.OK,
) {
    if (location != null) {
        call.response.header(HttpHeaders.Location, location)
    }

    try {

        val jsonObj = buildJsonObject {
            put("_id", rs.id?.toString())
            put("user_access_policy_uri", "${config.safeIssuer}manage/resource/${rs.id}")
            put("name", rs.name)
            put("uri", rs.uri)
            put("type", rs.type)
            @OptIn(ExperimentalSerializationApi::class)
            putJsonArray("scopes") { addAll(rs.scopes) }
            put("icon_uri", rs.iconUri)
        }
        call.respondText(jsonObj.toString(), contentType = ContentType.Application.Json, status = code)
    } catch (e: IOException) {
        logger.error("IOException in ResourceSetEntityView.java: ", e)
    }

}

private val logger = getLogger("jsonEntityView")
