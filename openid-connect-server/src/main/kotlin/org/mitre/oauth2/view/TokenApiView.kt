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

import com.google.gson.ExclusionStrategy
import com.google.gson.FieldAttributes
import com.google.gson.Gson
import com.google.gson.GsonBuilder
import com.google.gson.JsonSerializer
import org.mitre.oauth2.model.OAuth2AccessTokenEntity
import org.mitre.oauth2.model.OAuth2RefreshTokenEntity
import org.mitre.oauth2.view.TokenApiView
import org.mitre.openid.connect.view.HttpCodeView
import org.mitre.openid.connect.view.JsonEntityView
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
import com.google.gson.JsonObject as GsonObject

@Component(TokenApiView.VIEWNAME)
class TokenApiView : AbstractView() {
    private val gson: Gson = GsonBuilder()
        .setExclusionStrategies(object : ExclusionStrategy {
            override fun shouldSkipField(f: FieldAttributes): Boolean {
                return false
            }

            override fun shouldSkipClass(clazz: Class<*>): Boolean {
                // skip the JPA binding wrapper
                return clazz == BeanPropertyBindingResult::class.java
            }
        })
        .registerTypeAdapter(OAuth2AccessTokenEntity::class.java, JsonSerializer<OAuth2AccessTokenEntity> { src, typeOfSrc, context ->
            val o = GsonObject()
            o.addProperty("value", src.value)
            o.addProperty("id", src.id)
            o.addProperty("refreshTokenId", if (src.refreshToken != null) src.refreshToken!!.id else null)

            o.add("scopes", context.serialize(src.scope))

            o.addProperty("clientId", src.client!!.clientId)
            o.addProperty("userId", src.authenticationHolder.authentication.name)

            o.add("expiration", context.serialize(src.expiration))
            o
        })
        .registerTypeAdapter(OAuth2RefreshTokenEntity::class.java, JsonSerializer<OAuth2RefreshTokenEntity> { src, typeOfSrc, context ->
            val o = GsonObject()
            o.addProperty("value", src.value)
            o.addProperty("id", src.id)

            o.add("scopes", context.serialize(src.authenticationHolder.authentication.oAuth2Request.scope))

            o.addProperty("clientId", src.client!!.clientId)
            o.addProperty("userId", src.authenticationHolder.authentication.name)

            o.add("expiration", context.serialize(src.expiration))
            o
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

        // default to 200
        val code = model[HttpCodeView.CODE] as HttpStatus? ?: HttpStatus.OK

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
        const val VIEWNAME: String = "tokenApiView"

        /**
         * Logger for this class
         */
        private val logger: Logger = LoggerFactory.getLogger(TokenApiView::class.java)
    }
}
