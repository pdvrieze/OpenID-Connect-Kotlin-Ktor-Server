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

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.encodeToStream
import kotlinx.serialization.json.put
import org.mitre.util.getLogger
import org.mitre.util.oidJson
import org.springframework.http.HttpStatus
import org.springframework.http.MediaType
import org.springframework.stereotype.Component
import org.springframework.web.servlet.view.AbstractView
import java.io.IOException
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

/**
 * @author aanganes, jricher
 */
@Component(JsonErrorView.VIEWNAME)
class JsonErrorView : AbstractView() {

    override fun renderMergedOutputModel(
        model: Map<String, Any>,
        request: HttpServletRequest,
        response: HttpServletResponse
    ) {
        response.contentType = MediaType.APPLICATION_JSON_VALUE


        var code = model[HttpCodeView.CODE] as HttpStatus?
        if (code == null) {
            code = HttpStatus.INTERNAL_SERVER_ERROR // default to 500
        }

        response.setStatus(code.value())

        try {
            var errorTitle = model[ERROR] as String?
            if (errorTitle.isNullOrEmpty()) {
                errorTitle = "mitreid_error"
            }
            val errorMessage = model[ERROR_MESSAGE] as String?
            val obj = buildJsonObject {
                put("error", errorTitle)
                put("error_description", errorMessage)

            }
            oidJson.encodeToStream(obj, response.outputStream)
        } catch (e: IOException) {
            Companion.logger.error("IOException in JsonErrorView.java: ", e)
        }
    }

    companion object {
        const val ERROR_MESSAGE: String = "errorMessage"


        const val ERROR: String = "error"

        /**
         * Logger for this class
         */
        private val logger = getLogger<JsonErrorView>()

        const val VIEWNAME: String = "jsonErrorView"
    }
}
