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

import org.mitre.oauth2.web.IntrospectionEndpoint
import org.mitre.openid.connect.config.ConfigurationPropertiesBean
import org.mitre.openid.connect.view.JsonEntityView
import org.mitre.openid.connect.web.DynamicClientRegistrationEndpoint
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.stereotype.Controller
import org.springframework.ui.Model
import org.springframework.web.bind.annotation.RequestMapping

/**
 * @author jricher
 */
@Controller
class UmaDiscoveryEndpoint {
    @Autowired
    private lateinit var config: ConfigurationPropertiesBean

    @RequestMapping(".well-known/uma-configuration")
    fun umaConfiguration(model: Model): String {

        val issuer = config.issuer
        val tokenProfiles = setOf("bearer")
        val grantTypes =
            listOf("authorization_code", "implicit", "urn:ietf:params:oauth:grant-type:jwt-bearer", "client_credentials", "urn:ietf:params:oauth:grant_type:redelegate")

        val m = mapOf(
            "version" to "1.0",
            "issuer" to issuer,
            "pat_profiles_supported" to tokenProfiles,
            "aat_profiles_supported" to tokenProfiles,
            "rpt_profiles_supported" to tokenProfiles,
            "pat_grant_types_supported" to grantTypes,
            "aat_grant_types_supported" to grantTypes,
            "claim_token_profiles_supported" to setOf<Any>(),
            "uma_profiles_supported" to setOf<Any>(),
            "dynamic_client_endpoint" to "$issuer${DynamicClientRegistrationEndpoint.URL}",
            "token_endpoint" to "${issuer}token",
            "authorization_endpoint" to "${issuer}authorize",
            "requesting_party_claims_endpoint" to "$issuer${ClaimsCollectionEndpoint.URL}",
            "introspection_endpoint" to issuer + IntrospectionEndpoint.URL,
            "resource_set_registration_endpoint" to "${issuer}resource_set",
            "permission_registration_endpoint" to "$issuer${PermissionRegistrationEndpoint.URL}",
            "rpt_endpoint" to issuer + AuthorizationRequestEndpoint.URL,
        )


        model.addAttribute("entity", m)
        return JsonEntityView.VIEWNAME
    }
}
