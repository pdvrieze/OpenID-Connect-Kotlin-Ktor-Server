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

import com.google.gson.ExclusionStrategy
import com.google.gson.Gson
import com.google.gson.GsonBuilder
import com.google.gson.JsonParser
import com.google.gson.JsonPrimitive
import com.google.gson.JsonSerializer
import com.nimbusds.jose.EncryptionMethod
import com.nimbusds.jose.JWEAlgorithm
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jwt.JWT
import org.mitre.oauth2.model.PKCEAlgorithm
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import org.springframework.http.HttpStatus
import org.springframework.http.MediaType
import org.springframework.web.servlet.view.AbstractView
import java.io.IOException
import java.io.Writer
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

/**
 *
 * Abstract superclass for client entity view, used with the ClientApi.
 *
 * @see ClientEntityViewForUsers
 *
 * @see ClientEntityViewForAdmins
 *
 *
 * @author jricher
 */
abstract class AbstractClientEntityView : AbstractView() {
    private val parser = JsonParser()

    private val gson: Gson = GsonBuilder()
        .setExclusionStrategies(exclusionStrategy)
        .registerTypeAdapter(JWSAlgorithm::class.java, JsonSerializer<JWSAlgorithm?> { src, typeOfSrc, context ->
            src?.let { JsonPrimitive(it.name) }
        })
        .registerTypeAdapter(JWEAlgorithm::class.java, JsonSerializer<JWEAlgorithm?> { src, typeOfSrc, context ->
            src?.let { JsonPrimitive(it.name) }
        })
        .registerTypeAdapter(EncryptionMethod::class.java, JsonSerializer<EncryptionMethod?> { src, typeOfSrc, context ->
            src?.let { JsonPrimitive(it.name) }
        })
        .registerTypeAdapter(JWKSet::class.java, JsonSerializer<JWKSet?> { src, typeOfSrc, context ->
            src?.let { parser.parse(it.toString()) }
        })
        .registerTypeAdapter(JWT::class.java, JsonSerializer<JWT?> { src, typeOfSrc, context ->
            src?.let { JsonPrimitive(it.serialize()) }
        })
        .registerTypeAdapter(PKCEAlgorithm::class.java, JsonSerializer<PKCEAlgorithm?> { src, typeOfSrc, context ->
            src?.let { JsonPrimitive(it.name) }
        })
        .serializeNulls()
        .setDateFormat("yyyy-MM-dd'T'HH:mm:ssZ")
        .create()


    protected abstract val exclusionStrategy: ExclusionStrategy?


    override fun renderMergedOutputModel(
        model: Map<String, Any>,
        request: HttpServletRequest,
        response: HttpServletResponse
    ) {
        response.contentType = MediaType.APPLICATION_JSON_VALUE


        val code = (model[HttpCodeView.CODE] as HttpStatus?) ?: HttpStatus.OK

        response.setStatus(code.value())

        try {
            val out: Writer = response.writer
            val obj = model[JsonEntityView.ENTITY]
            gson.toJson(obj, out)
        } catch (e: IOException) {
            Companion.logger.error("IOException in JsonEntityView.java: ", e)
        }
    }

    companion object {
        /**
         * Logger for this class
         */
        private val logger: Logger = LoggerFactory.getLogger(AbstractClientEntityView::class.java)
    }
}
