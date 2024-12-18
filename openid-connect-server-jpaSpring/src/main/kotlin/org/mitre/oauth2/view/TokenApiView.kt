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
package org.mitre.oauth2.view

import kotlinx.serialization.InternalSerializationApi
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.encodeToStream
import kotlinx.serialization.serializer
import org.mitre.openid.connect.view.HttpCodeView
import org.mitre.openid.connect.view.JsonEntityView
import org.mitre.util.getLogger
import org.mitre.util.oidJson
import org.springframework.http.HttpStatus
import org.springframework.http.MediaType
import org.springframework.stereotype.Component
import org.springframework.web.servlet.view.AbstractView
import java.io.IOException
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

@Component(TokenApiView.VIEWNAME)
class TokenApiView : AbstractView() {

    override fun renderMergedOutputModel(
        model: Map<String, Any>,
        request: HttpServletRequest,
        response: HttpServletResponse
    ) {
        response.contentType = MediaType.APPLICATION_JSON_VALUE

        // default to 200
        val code = model[HttpCodeView.CODE] as HttpStatus? ?: HttpStatus.OK

        response.setStatus(code.value())

        try {
            // TODO this is very bad, but the whole model approach is not good enough.
            val obj = model[JsonEntityView.ENTITY]
            @OptIn(InternalSerializationApi::class)
            val ser = obj!!.javaClass.kotlin.serializer()
            oidJson.encodeToStream(ser, obj, response.outputStream)
        } catch (e: IOException) {
            Companion.logger.error("IOException in JsonEntityView.java: ", e)
        }
    }

    companion object {
        const val VIEWNAME: String = "tokenApiView"

        /**
         * Logger for this class
         */
        private val logger = getLogger<TokenApiView>()
    }
}
