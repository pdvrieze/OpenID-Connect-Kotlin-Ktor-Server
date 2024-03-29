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

import com.google.common.base.Strings
import com.google.gson.ExclusionStrategy
import com.google.gson.FieldAttributes
import com.google.gson.Gson
import com.google.gson.GsonBuilder
import com.google.gson.JsonObject
import org.mitre.openid.connect.view.JsonErrorView
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
 * @author aanganes, jricher
 */
@Component(JsonErrorView.VIEWNAME)
class JsonErrorView : AbstractView() {
    private val gson: Gson = GsonBuilder()
        .setExclusionStrategies(object : ExclusionStrategy {
            override fun shouldSkipField(f: FieldAttributes): Boolean {
                return false
            }

            override fun shouldSkipClass(clazz: Class<*>): Boolean {
                // skip the JPA binding wrapper
                if (clazz == BeanPropertyBindingResult::class.java) {
                    return true
                }
                return false
            }
        })
        .serializeNulls()
        .setDateFormat("yyyy-MM-dd'T'HH:mm:ssZ")
        .create()

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
            val out: Writer = response.writer

            var errorTitle = model[ERROR] as String?
            if (Strings.isNullOrEmpty(errorTitle)) {
                errorTitle = "mitreid_error"
            }
            val errorMessage = model[ERROR_MESSAGE] as String?
            val obj = JsonObject()
            obj.addProperty("error", errorTitle)
            obj.addProperty("error_description", errorMessage)
            gson.toJson(obj, out)
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
        private val logger: Logger = LoggerFactory.getLogger(JsonErrorView::class.java)

        const val VIEWNAME: String = "jsonErrorView"
    }
}
