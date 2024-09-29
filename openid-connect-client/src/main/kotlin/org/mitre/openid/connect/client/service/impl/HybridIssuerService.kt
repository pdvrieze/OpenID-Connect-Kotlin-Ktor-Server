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
package org.mitre.openid.connect.client.service.impl

import io.ktor.http.*
import org.mitre.openid.connect.client.model.IssuerServiceResponse
import org.mitre.openid.connect.client.service.IssuerService

/**
 *
 * Issuer service that tries to parse input from the inputs from a third-party
 * account chooser service (if possible), but falls back to webfinger discovery
 * if not.
 *
 * @author jricher
 */
class HybridIssuerService(accountChooserUrl: String) : IssuerService {
    var accountChooserUrl: String
        get() = thirdPartyIssuerService.accountChooserUrl
        set(accountChooserUrl) {
            thirdPartyIssuerService.accountChooserUrl = accountChooserUrl
        }

    /**
     * @see org.mitre.openid.connect.client.service.impl.WebfingerIssuerService.isForceHttps
     */
    var isForceHttps: Boolean
        get() = webfingerIssuerService.isForceHttps
        set(forceHttps) {
            webfingerIssuerService.isForceHttps = forceHttps
        }

    private val thirdPartyIssuerService = ThirdPartyIssuerService(accountChooserUrl)
    private val webfingerIssuerService = WebfingerIssuerService()

    override fun getIssuer(requestParams: Parameters, requestUrl: String): IssuerServiceResponse? {
        val resp = thirdPartyIssuerService.getIssuer(requestParams, requestUrl)
            // if it wants us to redirect, try the webfinger approach first
        return if (resp?.shouldRedirect() == true) {
            webfingerIssuerService.getIssuer(requestParams, requestUrl)
        } else {
            resp
        }
    }

    var whitelist: Set<String>
        get() = thirdPartyIssuerService.whitelist + webfingerIssuerService.whitelist
        set(whitelist) {
            thirdPartyIssuerService.whitelist = whitelist
            webfingerIssuerService.whitelist = whitelist
        }

    var blacklist: Set<String>
        get() = thirdPartyIssuerService.blacklist + webfingerIssuerService.whitelist
        set(blacklist) {
            thirdPartyIssuerService.blacklist = blacklist
            webfingerIssuerService.blacklist = blacklist
        }

    var parameterName: String?
        get() = webfingerIssuerService.parameterName
        set(parameterName) {
            webfingerIssuerService.parameterName = parameterName!!
        }

    var loginPageUrl: String?
        get() = webfingerIssuerService.loginPageUrl
        set(loginPageUrl) {
            webfingerIssuerService.loginPageUrl = loginPageUrl
            thirdPartyIssuerService.accountChooserUrl =
                loginPageUrl!! // set the same URL on both, but this one gets ignored
        }
}
