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

import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.encodeToStream
import org.mitre.openid.connect.model.UserInfo
import org.mitre.openid.connect.service.ScopeClaimTranslationService
import org.mitre.util.getLogger
import org.mitre.util.oidJson
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.http.MediaType
import org.springframework.stereotype.Component
import org.springframework.web.servlet.view.AbstractView
import java.io.IOException
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

@Component(UserInfoView.VIEWNAME)
class UserInfoView : AbstractView() {
    @Autowired
    private lateinit var translator: ScopeClaimTranslationService

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
            authorizedClaims = (model[AUTHORIZED_CLAIMS] as String?)
                ?.let { oidJson.parseToJsonElement(it) as? JsonObject }
        }
        if (model[REQUESTED_CLAIMS] != null) {
            requestedClaims = (model[REQUESTED_CLAIMS] as String?)
                ?.let { oidJson.parseToJsonElement(it) as? JsonObject }
        }
        val json = toJsonFromRequestObj(userInfo, scope, authorizedClaims, requestedClaims)

        writeOut(json, model, request, response)
    }

    @OptIn(ExperimentalSerializationApi::class)
    protected fun writeOut(
        json: JsonObject,
        model: Map<String, Any>,
        request: HttpServletRequest?,
        response: HttpServletResponse
    ) {
        try {
            oidJson.encodeToStream(JsonElement.serializer(), json, response.outputStream)
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
        val result = mutableMapOf<String, JsonElement>()
        for ((key, value) in obj.entries) {
            if (allowedByScope.contains(key)
                || authorizedByClaims.contains(key)
            ) {
                // it's allowed either by scope or by the authorized claims (either way is fine with us)

                if (requestedByClaims.isEmpty() || requestedByClaims.contains(key)) {
                    // the requested claims are empty (so we allow all), or they're not empty and this claim was specifically asked for
                    result.put(key, value)
                } // otherwise there were specific claims requested and this wasn't one of them
            }
        }

        return JsonObject(result)
    }

    /**
     * Pull the claims that have been targeted into a set for processing.
     * Returns an empty set if the input is null.
     * @param claims the claims request to process
     */
    private fun extractUserInfoClaimsIntoSet(claims: JsonObject?): Set<String> {
        val target: MutableSet<String> = HashSet()
        if (claims != null) {
            val userinfoAuthorized = claims["userinfo"] as? JsonObject
            if (userinfoAuthorized != null) {
                for (key in userinfoAuthorized.keys) {
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

        /**
         * Logger for this class
         */
        private val logger = getLogger<UserInfoView>()
    }
}
