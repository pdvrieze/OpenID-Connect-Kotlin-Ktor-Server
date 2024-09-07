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
package org.mitre.openid.connect.model

import com.nimbusds.jwt.JWT
import com.nimbusds.jwt.JWTParser
import org.mitre.oauth2.model.Authentication
import org.mitre.oauth2.model.GrantedAuthority
import java.io.IOException
import java.io.ObjectInputStream
import java.io.ObjectOutputStream
import java.text.ParseException

/**
 * @constructor Constructs OIDCAuthenticationToken with a full set of authorities, marking this as authenticated.
 * @property sub user id (parsed from the id token)
 * @property issuer issuer URL (parsed from the id token)
 * @property userInfo user info container
 * @property idToken
 * @property accessTokenValue string representation of the access token
 * @property refreshTokenValue string representation of the refresh token
 *
 * @author Michael Walsh, Justin Richer
 */
class OIDCAuthenticationToken(
    val sub: String,
    val issuer: String,
    val userInfo: UserInfo?,
    authorities: Collection<GrantedAuthority>?,
    @field:Transient var idToken: JWT?,
    val accessTokenValue: String,
    val refreshTokenValue: String,
) : Authentication {

    override val authorities: Collection<GrantedAuthority> = authorities?.requireNoNulls()?.toHashSet() ?: emptySet()
    /**
     * Constructs a Principal out of the subject and issuer.
     */
    private val principal: Map<String, String> = mapOf("sub" to sub, "iss" to issuer)

    override var isAuthenticated: Boolean = true
        private set

    override val name: String
        get() = principal.toString()

    fun getCredentials(): Any {
        return accessTokenValue
    }

    fun getPrincipal(): Any {
        return principal
    }

    /**
     * Custom serialization to handle the JSON object
     */
    @Throws(IOException::class)
    private fun writeObject(out: ObjectOutputStream) {
        out.defaultWriteObject()
        out.writeObject(idToken?.serialize())
    }

    @Throws(IOException::class, ClassNotFoundException::class, ParseException::class)
    private fun readObject(inStream: ObjectInputStream) {
        inStream.defaultReadObject()
        val o = inStream.readObject()
        if (o != null) {
            idToken = JWTParser.parse(o as String)
        }
    }

    companion object {
        private const val serialVersionUID = 22100073066377804L
    }
}
