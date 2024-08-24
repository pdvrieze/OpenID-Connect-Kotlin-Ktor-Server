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

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.addAll
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.encodeToStream
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import org.mitre.openid.connect.config.ConfigurationPropertiesBean
import org.mitre.openid.connect.view.JsonEntityView
import org.mitre.uma.model.ResourceSet
import org.mitre.util.GsonUtils.getAsArray
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.http.HttpHeaders
import org.springframework.http.HttpStatus
import org.springframework.stereotype.Component
import org.springframework.validation.BeanPropertyBindingResult
import org.springframework.web.servlet.view.AbstractView
import java.io.IOException
import java.io.OutputStream
import java.io.Writer
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

@Component(ResourceSetEntityView.VIEWNAME)
class ResourceSetEntityView : AbstractView() {
    @Autowired
    private lateinit var config: ConfigurationPropertiesBean

    override fun renderMergedOutputModel(
        model: Map<String, Any>,
        request: HttpServletRequest,
        response: HttpServletResponse
    ) {
        response.contentType = "application/json"


        var code = model["code"] as HttpStatus?
        if (code == null) {
            code = HttpStatus.OK // default to 200
        }

        response.setStatus(code.value())

        val location = model["location"] as String?
        if (!location.isNullOrEmpty()) {
            response.setHeader(HttpHeaders.LOCATION, location)
        }

        try {
            val out: OutputStream = response.outputStream
            val rs = model["entity"] as ResourceSet?

            Json.encodeToStream(buildJsonObject {
                put("_id", rs!!.id.toString())
                put("user_access_policy_uri", config.issuer + "manage/resource/" + rs.id)
                put("name", rs.name)
                put("uri", rs.uri)
                put("type", rs.type)
                putJsonArray("scopes") { addAll(rs.scopes) }
                put("icon_uri", rs.iconUri)
            }, out)
        } catch (e: IOException) {
            Companion.logger.error("IOException in ResourceSetEntityView.java: ", e)
        }
    }

    companion object {
        private val logger: Logger = LoggerFactory.getLogger(JsonEntityView::class.java)

        const val VIEWNAME: String = "resourceSetEntityView"
    }
}
