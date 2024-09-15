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
package org.mitre.oauth2.service.impl

import org.mitre.oauth2.model.GrantedAuthority
import org.mitre.oauth2.service.ClientDetailsEntityService
import org.mitre.openid.connect.config.ConfigurationPropertiesBean

/**
 * Loads client details based on URI encoding as passed in from basic auth.
 *
 * Should only get called if non-encoded provider fails.
 *
 * @author AANGANES
 */
class UriEncodedClientUserDetailsService {
    lateinit var clientDetailsService: ClientDetailsEntityService
        protected set

    private lateinit var config: ConfigurationPropertiesBean

    fun loadUserByUsername(clientId: String): Nothing /*UserDetails*/ {
        TODO("Not implemented, seems unneeded in this form")
/*
        try {
            val decodedClientId = UriUtils.decode(clientId, "UTF-8")

            val client = clientDetailsService.loadClientByClientId(decodedClientId)
                ?: throw UsernameNotFoundException("Client not found: $clientId")

            var encodedPassword = UriUtils.encodePathSegment((client.getClientSecret() ?: ""), "UTF-8")

            if (config.isHeartMode ||  // if we're running HEART mode turn off all client secrets
                (client.tokenEndpointAuthMethod != null &&
                        (client.tokenEndpointAuthMethod == AuthMethod.PRIVATE_KEY || client.tokenEndpointAuthMethod == AuthMethod.SECRET_JWT))
            ) {
                // Issue a random password each time to prevent password auth from being used (or skipped)
                // for private key or shared key clients, see #715

                encodedPassword = BigInteger(512, SecureRandom()).toString(16)
            }

            val enabled = true
            val accountNonExpired = true
            val credentialsNonExpired = true
            val accountNonLocked = true
            val authorities: MutableCollection<GrantedAuthority> = HashSet(client.getAuthorities())
            authorities.add(ROLE_CLIENT)

            return User(decodedClientId, encodedPassword, enabled, accountNonExpired, credentialsNonExpired, accountNonLocked, authorities)
        } catch (e: InvalidClientException) {
            throw UsernameNotFoundException("Client not found: $clientId")
        }
*/
    }

    companion object {
        private val ROLE_CLIENT: GrantedAuthority = GrantedAuthority("ROLE_CLIENT")
    }
}
