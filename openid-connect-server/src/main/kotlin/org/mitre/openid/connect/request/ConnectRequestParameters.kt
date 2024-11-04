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
package org.mitre.openid.connect.request

object ConnectRequestParameters {
    const val CLIENT_ID: String = "client_id"
    const val RESPONSE_TYPE: String = "response_type"
    const val REDIRECT_URI: String = "redirect_uri"
    const val STATE: String = "state"
    const val DISPLAY: String = "display"
    const val REQUEST: String = "request"
    const val LOGIN_HINT: String = "login_hint"
    const val MAX_AGE: String = "max_age"
    const val CLAIMS: String = "claims"
    const val SCOPE: String = "scope"
    const val NONCE: String = "nonce"
    const val PROMPT: String = "prompt"

    // prompt values
    val PROMPT_LOGIN: Prompt = Prompt.LOGIN
    val PROMPT_NONE: Prompt = Prompt.NONE
    val PROMPT_CONSENT: Prompt = Prompt.CONSENT
    val PROMPT_SELECT_ACCOUNT: Prompt = Prompt.SELECT_ACCOUNT
    const val PROMPT_SEPARATOR: String = " "

    // extensions
    const val APPROVED_SITE: String = "approved_site"

    // responses
    const val ERROR: String = "error"
    const val LOGIN_REQUIRED: String = "login_required"

    // audience
    const val AUD: String = "aud"

    // PKCE
    const val CODE_CHALLENGE: String = "code_challenge"
    const val CODE_CHALLENGE_METHOD: String = "code_challenge_method"
    const val CODE_VERIFIER: String = "code_verifier"
}
