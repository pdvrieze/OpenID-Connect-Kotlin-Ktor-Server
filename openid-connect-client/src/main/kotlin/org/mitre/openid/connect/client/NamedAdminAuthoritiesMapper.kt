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
package org.mitre.openid.connect.client

import com.nimbusds.jwt.JWT
import org.mitre.openid.connect.model.UserInfo
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.authority.SimpleGrantedAuthority
import java.text.ParseException

/**
 *
 * Simple mapper that adds ROLE_USER to the authorities map for all queries,
 * plus adds ROLE_ADMIN if the subject and issuer pair are found in the
 * configurable "admins" set.
 *
 * @author jricher
 */
class NamedAdminAuthoritiesMapper : OIDCAuthoritiesMapper {
    var admins: Set<SubjectIssuerGrantedAuthority> = HashSet()

    override fun mapAuthorities(idToken: JWT, userInfo: UserInfo?): Collection<GrantedAuthority> {
        val out: MutableSet<GrantedAuthority> = HashSet()
        try {
            val claims = idToken.jwtClaimsSet

            val authority = SubjectIssuerGrantedAuthority(claims.subject, claims.issuer)
            out.add(authority)

            if (admins.contains(authority)) {
                out.add(ROLE_ADMIN)
            }

            // everybody's a user by default
            out.add(ROLE_USER)
        } catch (e: ParseException) {
            logger.error("Unable to parse ID Token inside of authorities mapper (huh?)")
        }
        return out
    }

    companion object {
        private val logger: Logger = LoggerFactory.getLogger(NamedAdminAuthoritiesMapper::class.java)

        private val ROLE_ADMIN = SimpleGrantedAuthority("ROLE_ADMIN")
        private val ROLE_USER = SimpleGrantedAuthority("ROLE_USER")
    }
}
