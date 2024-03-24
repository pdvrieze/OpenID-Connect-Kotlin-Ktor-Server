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
package org.mitre.openid.connect.client.model

/**
 *
 * Data container to facilitate returns from the IssuerService API.
 *
 * @author jricher
 */
class IssuerServiceResponse {
    var issuer: String?
    var loginHint: String?
    var targetLinkUri: String?
    var redirectUrl: String?


    constructor(issuer: String?, loginHint: String?, targetLinkUri: String?) {
        this.issuer = issuer
        this.loginHint = loginHint
        this.targetLinkUri = targetLinkUri
        this.redirectUrl = null
    }


    constructor(redirectUrl: String?) {
        this.redirectUrl = redirectUrl
        this.issuer = null
        this.loginHint = null
        this.targetLinkUri = null
    }

    /**
     * If the redirect url has been set, then we should send a redirect using it instead of processing things.
     */
    fun shouldRedirect(): Boolean {
        return redirectUrl != null
    }
}
