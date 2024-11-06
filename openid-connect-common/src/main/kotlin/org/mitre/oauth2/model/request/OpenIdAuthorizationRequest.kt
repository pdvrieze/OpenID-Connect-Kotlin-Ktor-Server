package org.mitre.oauth2.model.request

import org.mitre.openid.connect.request.Prompt

interface OpenIdAuthorizationRequest : AuthorizationRequest {

    val codeChallenge: CodeChallenge?
    val audience: String?
    val maxAge: Long?
    val approvedSiteId: Long?
    val loginHint: String?
    val prompts: Set<Prompt>?
    val idToken: String? //idtoken
    val nonce: String?

    override fun builder(): Builder


    class Builder : AuthorizationRequest.Builder {
        constructor(clientId: String) : super(clientId)

        var codeChallenge: CodeChallenge? = null
        var audience: String? = null
        var maxAge: Long? = null
        var approvedSiteId: Long? = null
        var loginHint: String? = null
        var prompts: Set<Prompt>? = null
        var idToken: String? = null //idtoken
        var nonce: String? = null
        var extensions: Map<String, String>? = null
            private set

        constructor(orig: AuthorizationRequest) : super(orig) {
            if (orig is OpenIdAuthorizationRequest) {
                codeChallenge = orig.codeChallenge
                audience = orig.audience
                maxAge = orig.maxAge
                approvedSiteId = orig.approvedSiteId
                loginHint = orig.loginHint
                prompts = orig.prompts
                idToken = orig.idToken
                nonce = orig.nonce
            }
        }

        override fun build(): OpenIdAuthorizationRequest {
            return OpenIdAuthorizationRequestImpl(this)
        }

        override fun setFromExtensions(extensions: Map<String, String>) {
            extensions["code_challenge"]?.let { codeChallenge = CodeChallenge(it, extensions["code_challenge_method"]!!) }
            extensions["aud"]?.let { audience = it }
            extensions["max_age"]?.let { maxAge = it.toLong() }
            extensions["approved_site"]?.let { approvedSiteId = it.toLong() }
            extensions["login_hint"]?.let { loginHint = it }
            extensions["prompt"]?.let { prompts = Prompt.parseSet(it) }
            extensions["idtoken"]?.let { idToken = it }
            extensions["nonce"]?.let { nonce = it }
            this.extensions = extensions.takeIf { it.isNotEmpty() }
        }
    }

}
