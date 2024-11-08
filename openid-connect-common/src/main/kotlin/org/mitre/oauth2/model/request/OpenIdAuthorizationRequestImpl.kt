package org.mitre.oauth2.model.request

import kotlinx.serialization.json.JsonObject
import org.mitre.oauth2.model.GrantedAuthority
import org.mitre.openid.connect.model.convert.ISOInstant
import org.mitre.openid.connect.request.Prompt

class OpenIdAuthorizationRequestImpl internal constructor(
    builder: OpenIdAuthorizationRequest.Builder,
) : OpenIdAuthorizationRequest {
    @InternalForStorage
    override val requestParameters: Map<String, String> = builder.requestParameters
    override val clientId: String = builder.clientId
    override val authorities: Set<GrantedAuthority> = builder.authorities.toHashSet()
    override val approval: AuthorizationRequest.Approval? = builder.approval
    override val scope: Set<String> = builder.scope.toHashSet()
    override val resourceIds: Set<String>? = builder.resourceIds?.toHashSet()
    override val redirectUri: String? = builder.redirectUri
    override val responseTypes: Set<String>? = builder.responseTypes?.toHashSet()
    override val state: String? = builder.state
    override val requestTime: ISOInstant? = builder.requestTime
    override val codeChallenge: CodeChallenge? = builder.codeChallenge
    override val audience: String? = builder.audience
    override val maxAge: Long? = builder.maxAge
    override val approvedSiteId: Long? = builder.approvedSiteId

    override val loginHint: String? = builder.loginHint
    override val prompts: Set<Prompt>? = builder.prompts
    override val idToken: String? = builder.idToken
    override val nonce: String? = builder.nonce
    override val display: String? = builder.display
    override val responseMode: OpenIdAuthorizationRequest.ResponseMode = builder.responseMode
    override val requestedClaims: JsonObject? = builder.requestedClaims

    val extensions: Map<String, String>? = builder.extensions?.toMap()

    @InternalForStorage
    override val authHolderExtensions: Map<String, String> get() {
        return buildMap {
            extensions?.let { putAll(it) }
            approval?.let {
                put("AUTHZ_TIMESTAMP", it.approvalTime.epochSecond.toString())
                it.approvedSiteId?.let { s -> put("approved_site", s.toString()) }
            }
            codeChallenge?.let {
                put("code_challenge", it.challenge)
                put("code_challenge_Method", it.method)
            }
            audience?.let { put("aud", it) }
            maxAge?.let { put("max_age", it.toString()) }
            approvedSiteId?.let { put("approved_site", it.toString()) }
            loginHint?.let { put("login_hint", it) }
            prompts?.let { put("prompt", it.joinToString(" ", transform = Prompt::value)) }
            idToken?.let { put("idtoken", it) }
            nonce?.let { put("nonce", it) }
            display?.let { put("display", it) }
            requestedClaims?.let { s -> put("claims", s.toString()) }
            responseMode.value?.let { put("response_mode", it) }
        }
    }

    override fun builder(): OpenIdAuthorizationRequest.Builder {
        return OpenIdAuthorizationRequest.Builder(this)
    }

}
