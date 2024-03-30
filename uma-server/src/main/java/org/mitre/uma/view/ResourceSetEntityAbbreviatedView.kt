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

import com.google.common.base.Strings
import com.google.gson.ExclusionStrategy
import com.google.gson.FieldAttributes
import com.google.gson.Gson
import com.google.gson.GsonBuilder
import com.google.gson.JsonObject
import com.google.gson.LongSerializationPolicy
import org.mitre.openid.connect.config.ConfigurationPropertiesBean
import org.mitre.openid.connect.view.HttpCodeView
import org.mitre.openid.connect.view.JsonEntityView
import org.mitre.uma.model.ResourceSet
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.http.HttpHeaders
import org.springframework.http.HttpStatus
import org.springframework.stereotype.Component
import org.springframework.validation.BeanPropertyBindingResult
import org.springframework.web.servlet.view.AbstractView
import java.io.IOException
import java.io.Writer
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

@Component(ResourceSetEntityAbbreviatedView.VIEWNAME)
class ResourceSetEntityAbbreviatedView : AbstractView() {
    @Autowired
    private lateinit var config: ConfigurationPropertiesBean

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
        .setLongSerializationPolicy(LongSerializationPolicy.STRING)
        .create()

    override fun renderMergedOutputModel(
        model: Map<String, Any>,
        request: HttpServletRequest,
        response: HttpServletResponse
    ) {
        response.contentType = "application/json"


        var code = model[HttpCodeView.CODE] as HttpStatus?
        if (code == null) {
            code = HttpStatus.OK // default to 200
        }

        response.setStatus(code.value())

        val location = model[LOCATION] as String?
        if (!Strings.isNullOrEmpty(location)) {
            response.setHeader(HttpHeaders.LOCATION, location)
        }

        try {
            val out: Writer = response.writer
            val rs = model[JsonEntityView.ENTITY] as ResourceSet

            val o = JsonObject()

            o.addProperty("_id", rs.id.toString()) // set the ID to a string
            o.addProperty("user_access_policy_uri", "${config.issuer}manage/user/policy/${rs.id}")


            gson.toJson(o, out)
        } catch (e: IOException) {
            Companion.logger.error("IOException in ResourceSetEntityView.java: ", e)
        }
    }

    companion object {
        private val logger: Logger = LoggerFactory.getLogger(JsonEntityView::class.java)

        const val VIEWNAME: String = "resourceSetEntityAbbreviatedView"

        const val LOCATION: String = "location"
    }
}
