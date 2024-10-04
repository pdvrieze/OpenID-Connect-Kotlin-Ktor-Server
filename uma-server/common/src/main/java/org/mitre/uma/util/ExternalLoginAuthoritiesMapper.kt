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
package org.mitre.uma.util

import com.nimbusds.jwt.JWT
import org.mitre.oauth2.model.GrantedAuthority
import org.mitre.openid.connect.client.OIDCAuthoritiesMapper
import org.mitre.openid.connect.model.UserInfo

/**
 * Utility class to map all external logins to the ROLE_EXTERNAL_USER authority
 * to prevent them from accessing other parts of the server.
 *
 * @author jricher
 */
class ExternalLoginAuthoritiesMapper : OIDCAuthoritiesMapper {
    override fun mapAuthorities(idToken: JWT, userInfo: UserInfo?): Collection<GrantedAuthority> {
        return setOf(ROLE_EXTERNAL_USER)
    }

    companion object {
        private val ROLE_EXTERNAL_USER: GrantedAuthority = GrantedAuthority.ROLE_EXTERNAL_USER
    }
}
