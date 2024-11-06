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
            val extCpy = HashMap(extensions)
            extCpy.remove("code_challenge")?.let { codeChallenge = CodeChallenge(it, extensions["code_challenge_method"]!!) }
            extCpy.remove("aud")?.let { audience = it }
            extCpy.remove("max_age")?.let { maxAge = it.toLong() }
            extCpy.remove("approved_site")?.let { approvedSiteId = it.toLong() }
            extCpy.remove("login_hint")?.let { loginHint = it }
            extCpy.remove("prompt")?.let { prompts = Prompt.parseSet(it) }
            extCpy.remove("idtoken")?.let { idToken = it }
            extCpy.remove("nonce")?.let { nonce = it }
            this.extensions = extCpy.takeIf { it.isNotEmpty() }
        }
    }

}
