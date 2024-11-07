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
package org.mitre.openid.connect.model

import com.nimbusds.jwt.JWT
import com.nimbusds.jwt.JWTParser
import org.mitre.oauth2.model.Authentication
import org.mitre.oauth2.model.GrantedAuthority
import org.mitre.openid.connect.config.ServerConfiguration
import java.io.IOException
import java.io.ObjectInputStream
import java.io.ObjectOutputStream
import java.text.ParseException

/**
 * AuthenticationToken for use as a data shuttle from the filter to the auth provider.
 *
 * @constructor Constructs OIDCAuthenticationToken for use as a data shuttle from the filter to the auth provider.
 *              Constructs a Principal out of the subject and issuer.
 * @property sub user id (parsed from the id token)
 * @property issuer issuer URL (parsed from the id token)
 * @property serverConfiguration  server configuration used to fulfill this token
 * @property accessTokenValue string representation of the access token
 * @property refreshTokenValue string representation of the refresh token
 *
 * @author jricher
 */
class PendingOIDCAuthenticationToken(//
    val sub: String,
    val issuer: String,

    /*
     * server configuration used to fulfill this token, don't serialize it
     */
    @field:Transient val serverConfiguration: ServerConfiguration?,

    @field:Transient var idToken: JWT?,

    val accessTokenValue: String,
    val refreshTokenValue: String,
) : Authentication {
    private val principal: Map<String, String> =
        mapOf("sub" to sub, "iss" to issuer)

    override val authorities: Set<GrantedAuthority>
        get() = emptySet()

    override val isAuthenticated: Boolean
        get() = false

    fun getCredentials(): Any {
        return accessTokenValue
    }

    override val name: String
        get() = principal.toString()

    /**
     * Get the principal of this object, an immutable map of the subject and issuer.
     */
    fun getPrincipal(): Any {
        return principal
    }

    /*
	 * Custom serialization to handle the JSON object
	 */
    @Throws(IOException::class)
    private fun writeObject(out: ObjectOutputStream) {
        out.defaultWriteObject()
        if (idToken == null) {
            out.writeObject(null)
        } else {
            out.writeObject(idToken!!.serialize())
        }
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
