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

import com.google.common.collect.HashMultimap
import com.google.common.collect.SetMultimap
import org.mitre.openid.connect.service.ScopeClaimTranslationService
import org.springframework.stereotype.Service

/**
 * Service to map scopes to claims, and claims to Java field names
 *
 * @author Amanda Anganes
 */
@Service("scopeClaimTranslator")
class DefaultScopeClaimTranslationService : ScopeClaimTranslationService {
    private val scopesToClaims: SetMultimap<String, String> = HashMultimap.create<String?, String?>().apply {
        put("openid", "sub")

        put("profile", "name")
        put("profile", "preferred_username")
        put("profile", "given_name")
        put("profile", "family_name")
        put("profile", "middle_name")
        put("profile", "nickname")
        put("profile", "profile")
        put("profile", "picture")
        put("profile", "website")
        put("profile", "gender")
        put("profile", "zoneinfo")
        put("profile", "locale")
        put("profile", "updated_at")
        put("profile", "birthdate")

        put("email", "email")
        put("email", "email_verified")

        put("phone", "phone_number")
        put("phone", "phone_number_verified")

        put("address", "address")
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
