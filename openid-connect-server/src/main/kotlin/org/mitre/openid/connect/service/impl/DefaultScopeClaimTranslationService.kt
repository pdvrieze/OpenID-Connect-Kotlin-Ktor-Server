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
package org.mitre.openid.connect.service.impl

import org.mitre.openid.connect.service.ScopeClaimTranslationService

/**
 * Service to map scopes to claims, and claims to Java field names
 *
 * @author Amanda Anganes
 */
class DefaultScopeClaimTranslationService : ScopeClaimTranslationService {
    private val scopesToClaims: Map<String, Set<String>> = buildMap {
        put("openId", setOf("sub"))
        put("profile", setOf(
            "name",
            "preferred_username",
            "given_name",
            "family_name",
            "middle_name",
            "nickname",
            "profile",
            "picture",
            "website",
            "gender",
            "zoneinfo",
            "locale",
            "updated_at",
            "birthdate",
        ))

        put("email", setOf("email", "email_verified"))

        put("phone", setOf("phone_number", "phone_number_verified"))

        put("address", setOf("address"))
    }

    /* (non-Javadoc)
	 * @see org.mitre.openid.connect.service.ScopeClaimTranslationService#getClaimsForScope(java.lang.String)
	 */
    override fun getClaimsForScope(scope: String): Set<String> {
        return scopesToClaims[scope] ?: emptySet()
    }

    /* (non-Javadoc)
	 * @see org.mitre.openid.connect.service.ScopeClaimTranslationService#getClaimsForScopeSet(java.util.Set)
	 */
    override fun getClaimsForScopeSet(scopes: Set<String>): Set<String> {
        return scopes.flatMapTo(HashSet()) { getClaimsForScope(it) }
    }
}
