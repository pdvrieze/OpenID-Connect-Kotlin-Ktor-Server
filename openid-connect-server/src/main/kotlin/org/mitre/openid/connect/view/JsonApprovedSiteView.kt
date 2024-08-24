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
package org.mitre.openid.connect.view

import kotlinx.serialization.InternalSerializationApi
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.encodeToStream
import kotlinx.serialization.serializer
import org.mitre.oauth2.model.OAuth2AccessTokenEntity
import org.mitre.openid.connect.model.WhitelistedSite
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import org.springframework.http.HttpStatus
import org.springframework.http.MediaType
import org.springframework.stereotype.Component
import org.springframework.validation.BeanPropertyBindingResult
import org.springframework.web.servlet.view.AbstractView
import java.io.IOException
import java.io.Writer
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

/**
 * @author jricher
 */
@Component(JsonApprovedSiteView.VIEWNAME)
class JsonApprovedSiteView : AbstractView() {

    override fun renderMergedOutputModel(
        model: Map<String, Any>,
        request: HttpServletRequest,
        response: HttpServletResponse
    ) {
        response.contentType = MediaType.APPLICATION_JSON_VALUE


        val code = model[HttpCodeView.CODE] as HttpStatus? ?: HttpStatus.OK

        response.setStatus(code.value())

        try {
            // TODO this is very bad, but the whole model approach is not good enough.
            val obj = model[JsonEntityView.ENTITY]
            @OptIn(InternalSerializationApi::class)
            val ser = obj!!.javaClass.kotlin.serializer()!!
            Json.encodeToStream(ser, obj, response.outputStream)
        } catch (e: IOException) {
            Companion.logger.error("IOException in JsonEntityView.java: ", e)
        }
    }

    companion object {
        /**
         * Logger for this class
         */
        private val logger: Logger = LoggerFactory.getLogger(JsonApprovedSiteView::class.java)

        const val VIEWNAME: String = "jsonApprovedSiteView"
    }
}
