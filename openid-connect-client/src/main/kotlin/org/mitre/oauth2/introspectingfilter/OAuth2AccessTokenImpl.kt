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
package org.mitre.oauth2.introspectingfilter

import com.nimbusds.jwt.JWT
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.long
import org.mitre.oauth2.model.AuthenticationHolderEntity
import org.mitre.oauth2.model.OAuth2AccessToken
import org.mitre.util.asString
import java.time.Instant
import java.util.*

class OAuth2AccessTokenImpl(introspectionResponse: JsonObject, tokenString: String) : OAuth2AccessToken {
    override val value: String = tokenString
    override val scope: Set<String> = introspectionResponse["scope"]
        ?.run { asString().splitToSequence(' ').toHashSet() }
        ?: emptySet()

    override val expirationInstant: Instant =
        introspectionResponse["exp"]?.run { Instant.ofEpochSecond(jsonPrimitive.long) } ?: Instant.MIN

    override val refreshToken: Nothing? get() = null

    override val tokenType: String get() = OAuth2AccessToken.BEARER_TYPE

    override val isExpired: Boolean
        get() = expirationInstant.isBefore(Instant.now())

    override val client: Nothing? get() = null
    override val authenticationHolder: AuthenticationHolderEntity =
        AuthenticationHolderEntity()

    override fun builder(): OAuth2AccessToken.Builder {
        return Builder(this)
    }

    private class Builder(
        override var jwt: JWT? = null,
        var expirationInstant: Instant? = null,
        var idTokenJWT: JWT? = null,
    ) : OAuth2AccessToken.Builder {

        override var expiration: Date?
            get() = expirationInstant?.let { Date.from(it) }
            set(value) { expirationInstant = value?.toInstant()}

        override fun setIdToken(idToken: JWT?) {
            idTokenJWT = idToken
        }

        constructor(base: OAuth2AccessTokenImpl) : this(
            jwt = base.jwt,
            expirationInstant = base.expirationInstant,
        )
    }
}
