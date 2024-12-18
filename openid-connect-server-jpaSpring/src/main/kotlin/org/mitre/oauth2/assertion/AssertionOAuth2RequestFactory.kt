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
package org.mitre.oauth2.assertion

import com.nimbusds.jwt.JWT
import org.springframework.security.oauth2.provider.ClientDetails
import org.springframework.security.oauth2.provider.OAuth2Request
import org.springframework.security.oauth2.provider.TokenRequest

/**
 * Take in an assertion and token request and generate an OAuth2Request from it, including scopes and other important components
 *
 * @author jricher
 */
interface AssertionOAuth2RequestFactory {
    fun createOAuth2Request(client: ClientDetails, tokenRequest: TokenRequest, assertion: JWT): OAuth2Request?
}
