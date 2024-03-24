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
package org.mitre.openid.connect.service

import com.nimbusds.jwt.JWT
import org.mitre.oauth2.model.ClientDetailsEntity
import org.mitre.oauth2.model.OAuth2AccessTokenEntity
import org.springframework.security.oauth2.provider.OAuth2Request
import java.util.*

/**
 * Service to create specialty OpenID Connect tokens.
 *
 * @author Amanda Anganes
 */
interface OIDCTokenService {
    /**
     * Create an id token with the information provided.
     */
    fun createIdToken(
        client: ClientDetailsEntity, request: OAuth2Request?, issueTime: Date?,
        sub: String?, accessToken: OAuth2AccessTokenEntity?
    ): JWT?

    /**
     * Create a registration access token for the given client.
     */
    fun createRegistrationAccessToken(client: ClientDetailsEntity): OAuth2AccessTokenEntity?

    /**
     * Create a resource access token for the given client (protected resource).
     */
    fun createResourceAccessToken(client: ClientDetailsEntity): OAuth2AccessTokenEntity?

    /**
     * Rotate the registration or resource token for a client
     */
    fun rotateRegistrationAccessTokenForClient(client: ClientDetailsEntity): OAuth2AccessTokenEntity?
}
