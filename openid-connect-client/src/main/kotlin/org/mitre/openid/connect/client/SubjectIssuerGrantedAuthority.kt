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
package org.mitre.openid.connect.client

import org.springframework.security.core.GrantedAuthority

/**
 *
 * Simple authority representing a user at an issuer.
 *
 * @author jricher
 */
class SubjectIssuerGrantedAuthority(subject: String?, issuer: String?) : GrantedAuthority {
    val subject: String
    val issuer: String

    init {
        require(!(subject.isNullOrEmpty() || issuer.isNullOrEmpty())) {
            "Neither subject nor issuer may be null or empty"
        }
        this.subject = subject
        this.issuer = issuer
    }

    /**
     * Returns a string formed by concatenating the subject with the issuer, separated by _ and prepended with OIDC_
     *
     * For example, the user "bob" from issuer "http://id.example.com/" would return the authority string of:
     *
     * OIDC_bob_http://id.example.com/
     */
    override fun getAuthority(): String {
        return "OIDC_" + subject + "_" + issuer
    }

    override fun toString(): String {
        return authority
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as SubjectIssuerGrantedAuthority

        if (subject != other.subject) return false
        if (issuer != other.issuer) return false

        return true
    }

    override fun hashCode(): Int {
        var result = subject.hashCode()
        result = 31 * result + issuer.hashCode()
        return result
    }

    companion object {
        private const val serialVersionUID = 5584978219226664794L
    }
}
