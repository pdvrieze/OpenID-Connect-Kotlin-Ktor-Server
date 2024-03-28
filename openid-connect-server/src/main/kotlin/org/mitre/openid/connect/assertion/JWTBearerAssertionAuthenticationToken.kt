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
package org.mitre.openid.connect.assertion

import com.nimbusds.jwt.JWT
import org.springframework.security.authentication.AbstractAuthenticationToken
import org.springframework.security.core.GrantedAuthority
import java.text.ParseException

/**
 * @author jricher
 */
class JWTBearerAssertionAuthenticationToken(var jwt: JWT?, authorities: Collection<GrantedAuthority>?) : AbstractAuthenticationToken(authorities) {
    private var subject: String? = jwt?.jwtClaimsSet?.subject
    init {
        isAuthenticated = authorities!=null
    }


    /**
     * Create an unauthenticated token with the given subject and jwt
     */
    constructor(jwt: JWT) : this(jwt, null) {
        try {
            // save the subject of the JWT in case the credentials get erased later
            this.subject = jwt.jwtClaimsSet.subject
        } catch (e: ParseException) {
            // TODO Auto-generated catch block
            e.printStackTrace()
        }
        isAuthenticated = false
    }

//    /**
//     * Create an authenticated token with the given clientID, jwt, and authorities set
//     */
//    constructor(jwt: JWT, dummy: Boolean,  authorities: Collection<GrantedAuthority>) : this(jwt, authorities) {
//        try {
//            // save the subject of the JWT in case the credentials get erased later
//            this.subject = jwt.jwtClaimsSet.subject
//        } catch (e: ParseException) {
//            // TODO Auto-generated catch block
//            e.printStackTrace()
//        }
//        this.jwt = jwt
//        isAuthenticated = true
//    }

    /* (non-Javadoc)
	 * @see org.springframework.security.core.Authentication#getCredentials()
	 */
    override fun getCredentials(): Any {
        return jwt!!
    }

    /* (non-Javadoc)
	 * @see org.springframework.security.core.Authentication#getPrincipal()
	 */
    override fun getPrincipal(): Any {
        return subject!!
    }

    /**
     * Clear out the JWT that this token holds.
     */
    override fun eraseCredentials() {
        super.eraseCredentials()
        jwt = null
    }


    companion object {
        private const val serialVersionUID = -3138213539914074617L
    }
}
