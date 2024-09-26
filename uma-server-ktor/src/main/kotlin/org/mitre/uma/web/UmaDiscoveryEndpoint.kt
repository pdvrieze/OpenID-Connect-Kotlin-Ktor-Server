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
package org.mitre.uma.web

import io.ktor.server.application.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import io.ktor.util.pipeline.*
import kotlinx.serialization.json.addAll
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import org.mitre.oauth2.view.respondJson
import org.mitre.oauth2.web.IntrospectionEndpoint
import org.mitre.openid.connect.config.ConfigurationPropertiesBean
import org.mitre.openid.connect.view.JsonEntityView
import org.mitre.openid.connect.web.DynamicClientRegistrationEndpoint
import org.mitre.web.util.KtorEndpoint
import org.mitre.web.util.config

/**
 * @author jricher
 */
//@Controller
class UmaDiscoveryEndpoint : KtorEndpoint {

    override fun Route.addRoutes() {
        get("/.well-known/uma-configuration") { umaConfiguration()}
    }

    //    @RequestMapping(".well-known/uma-configuration")
    suspend fun PipelineContext<Unit, ApplicationCall>.umaConfiguration() {
        val config = config
        val issuer = config.issuer
        val tokenProfiles = setOf("bearer")
        val grantTypes =
            listOf("authorization_code", "implicit", "urn:ietf:params:oauth:grant-type:jwt-bearer", "client_credentials", "urn:ietf:params:oauth:grant_type:redelegate")

        val m = buildJsonObject {
            put("version", "1.0")
            put("issuer", issuer)
            putJsonArray("pat_profiles_supported") { addAll(tokenProfiles) }
            putJsonArray("aat_profiles_supported") { addAll(tokenProfiles) }
            putJsonArray("rpt_profiles_supported") { addAll(tokenProfiles) }
            putJsonArray("pat_grant_types_supported") { addAll(grantTypes) }
            putJsonArray("aat_grant_types_supported") { addAll(grantTypes) }
            putJsonArray("claim_token_profiles_supported") { }
            putJsonArray("uma_profiles_supported") { }
            put("dynamic_client_endpoint", "$issuer${DynamicClientRegistrationEndpoint.URL}")
            put("token_endpoint", "${issuer}token")
            put("authorization_endpoint", "${issuer}authorize")
            put("requesting_party_claims_endpoint", "$issuer${ClaimsCollectionEndpoint.URL}")
            put("introspection_endpoint", issuer + IntrospectionEndpoint.URL)
            put("resource_set_registration_endpoint", "$issuer${ResourceSetRegistrationEndpoint.DISCOVERY_URL}")
            put("permission_registration_endpoint", "$issuer${PermissionRegistrationEndpoint.URL}")
            put("rpt_endpoint", issuer + AuthorizationRequestEndpoint.URL)
        }
        return call.respondJson(m)
    }
}
