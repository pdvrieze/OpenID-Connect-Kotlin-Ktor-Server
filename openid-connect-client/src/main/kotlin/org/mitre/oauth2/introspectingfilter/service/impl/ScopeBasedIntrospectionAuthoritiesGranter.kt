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
package org.mitre.oauth2.introspectingfilter.service.impl

import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import org.mitre.oauth2.introspectingfilter.service.IntrospectionAuthorityGranter
import org.mitre.util.asString
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.authority.AuthorityUtils
import org.springframework.security.core.authority.SimpleGrantedAuthority

/**
 * @author jricher
 */
class ScopeBasedIntrospectionAuthoritiesGranter : IntrospectionAuthorityGranter {
    var authorities: List<GrantedAuthority> = AuthorityUtils.createAuthorityList("ROLE_API")

    override fun getAuthorities(introspectionResponse: JsonObject): List<GrantedAuthority> {
        return when (val scope = introspectionResponse["scope"]) {
            is JsonPrimitive -> scope.asString().splitToSequence(' ')
                .filterNot { it.isEmpty() }
                .mapTo(authorities.toMutableList()) { SimpleGrantedAuthority("OAUTH_SCOPE_$it") }

            else -> authorities.toList()
        }

    }
}
