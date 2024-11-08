package org.mitre.oauth2.model.request

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject
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
    val requestedClaims: JsonObject?
    val display: String?
    val responseMode: ResponseMode

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
        var requestedClaims: JsonObject? = null
        var display: String? = null
        var responseMode: ResponseMode = ResponseMode.DEFAULT
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
                display = orig.display
                requestedClaims = orig.requestedClaims
                responseMode = orig.responseMode
            }
        }

        override fun build(): OpenIdAuthorizationRequest {
            return OpenIdAuthorizationRequestImpl(this)
        }

        @InternalForStorage
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
            extCpy.remove("display")?.let { display = it }
            extCpy.remove("claims")?.let { requestedClaims = Json.parseToJsonElement(it).jsonObject }
            extCpy.remove("response_mode").let { responseMode = ResponseMode.from(it) }
            this.extensions = extCpy.takeIf { it.isNotEmpty() }
        }
    }

    enum class ResponseMode(val value: String?) {
        DEFAULT(null),
        QUERY("query"),
        FRAGMENT("fragment");

        companion object {
            fun from(value: String?): ResponseMode = when (value) {
                null -> DEFAULT
                "query" -> QUERY
                "fragment" -> FRAGMENT
                else -> throw IllegalArgumentException("Unexpexted response mode: '$value'")
            }
        }
    }

}
