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
import com.google.gson.FieldAttributes
import com.google.gson.Gson
import com.google.gson.GsonBuilder
import com.google.gson.JsonObject
import com.google.gson.JsonParser
import org.mitre.openid.connect.model.UserInfo
import org.mitre.openid.connect.service.ScopeClaimTranslationService
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.http.MediaType
import org.springframework.stereotype.Component
import org.springframework.validation.BeanPropertyBindingResult
import org.springframework.web.servlet.view.AbstractView
import java.io.IOException
import java.io.Writer
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

@Component(UserInfoView.VIEWNAME)
class UserInfoView : AbstractView() {
    @Autowired
    private lateinit var translator: ScopeClaimTranslationService

    protected var gson: Gson = GsonBuilder().setExclusionStrategies(object : ExclusionStrategy {
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
    }).create()

    /*
	 * (non-Javadoc)
	 *
	 * @see
	 * org.springframework.web.servlet.view.AbstractView#renderMergedOutputModel
	 * (java.util.Map, javax.servlet.http.HttpServletRequest,
	 * javax.servlet.http.HttpServletResponse)
	 */
    override fun renderMergedOutputModel(
        model: Map<String, Any>,
        request: HttpServletRequest,
        response: HttpServletResponse
    ) {
        val userInfo = model[USER_INFO] as UserInfo?

        val scope = model[SCOPE] as Set<String>

        response.contentType = MediaType.APPLICATION_JSON_VALUE
        response.characterEncoding = "UTF-8"


        var authorizedClaims: JsonObject? = null
        var requestedClaims: JsonObject? = null
        if (model[AUTHORIZED_CLAIMS] != null) {
            authorizedClaims = jsonParser.parse(model[AUTHORIZED_CLAIMS] as String?).asJsonObject
        }
        if (model[REQUESTED_CLAIMS] != null) {
            requestedClaims = jsonParser.parse(model[REQUESTED_CLAIMS] as String?).asJsonObject
        }
        val json = toJsonFromRequestObj(userInfo, scope, authorizedClaims, requestedClaims)

        writeOut(json, model, request, response)
    }

    protected fun writeOut(
        json: JsonObject?,
        model: Map<String, Any>,
        request: HttpServletRequest?,
        response: HttpServletResponse
    ) {
        try {
            val out: Writer = response.writer
            gson.toJson(json, out)
        } catch (e: IOException) {
            Companion.logger.error("IOException in UserInfoView.java: ", e)
        }
    }

    /**
     * Build a JSON response according to the request object received.
     *
     * Claims requested in requestObj.userinfo.claims are added to any
     * claims corresponding to requested scopes, if any.
     *
     * @param ui the UserInfo to filter
     * @param scope the allowed scopes to filter by
     * @param authorizedClaims the claims authorized by the client or user
     * @param requestedClaims the claims requested in the RequestObject
     * @return the filtered JsonObject result
     */
    private fun toJsonFromRequestObj(
        ui: UserInfo?,
        scope: Set<String>,
        authorizedClaims: JsonObject?,
        requestedClaims: JsonObject?
    ): JsonObject {
        // get the base object

        val obj = ui!!.toJson()

        val allowedByScope = translator.getClaimsForScopeSet(scope)
        val authorizedByClaims = extractUserInfoClaimsIntoSet(authorizedClaims)
        val requestedByClaims = extractUserInfoClaimsIntoSet(requestedClaims)

        // Filter claims by performing a manual intersection of claims that are allowed by the given scope, requested, and authorized.
        // We cannot use Sets.intersection() or similar because Entry<> objects will evaluate to being unequal if their values are
        // different, whereas we are only interested in matching the Entry<>'s key values.
        val result = JsonObject()
        for ((key, value) in obj!!.entrySet()) {
            if (allowedByScope!!.contains(key)
                || authorizedByClaims.contains(key)
            ) {
                // it's allowed either by scope or by the authorized claims (either way is fine with us)

                if (requestedByClaims.isEmpty() || requestedByClaims.contains(key)) {
                    // the requested claims are empty (so we allow all), or they're not empty and this claim was specifically asked for
                    result.add(key, value)
                } // otherwise there were specific claims requested and this wasn't one of them
            }
        }

        return result
    }

    /**
     * Pull the claims that have been targeted into a set for processing.
     * Returns an empty set if the input is null.
     * @param claims the claims request to process
     */
    private fun extractUserInfoClaimsIntoSet(claims: JsonObject?): Set<String> {
        val target: MutableSet<String> = HashSet()
        if (claims != null) {
            val userinfoAuthorized = claims.getAsJsonObject("userinfo")
            if (userinfoAuthorized != null) {
                for ((key) in userinfoAuthorized.entrySet()) {
                    target.add(key)
                }
            }
        }
        return target
    }

    companion object {
        const val REQUESTED_CLAIMS: String = "requestedClaims"
        const val AUTHORIZED_CLAIMS: String = "authorizedClaims"
        const val SCOPE: String = "scope"
        const val USER_INFO: String = "userInfo"

        const val VIEWNAME: String = "userInfoView"

        private val jsonParser = JsonParser()

        /**
         * Logger for this class
         */
        private val logger: Logger = LoggerFactory.getLogger(UserInfoView::class.java)
    }
}