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
import org.mitre.oauth2.introspectingfilter.IntrospectionResponse
import org.mitre.oauth2.introspectingfilter.service.IntrospectionAuthorityGranter
import org.mitre.oauth2.model.GrantedAuthority
import org.mitre.oauth2.model.ScopeAuthority
import org.mitre.util.asString

/**
 * @author jricher
 */
class ScopeBasedIntrospectionAuthoritiesGranter : IntrospectionAuthorityGranter {
    var authorities: List<GrantedAuthority> = listOf(GrantedAuthority.ROLE_API)

    override fun getAuthorities(introspectionResponse: IntrospectionResponse): List<GrantedAuthority> {
        val scope = introspectionResponse.scopes
        return when  {
            scope.isEmpty() -> authorities.toList()
            else -> scope.mapTo(authorities.toMutableList()) { ScopeAuthority(it) }
        }

    }
}
