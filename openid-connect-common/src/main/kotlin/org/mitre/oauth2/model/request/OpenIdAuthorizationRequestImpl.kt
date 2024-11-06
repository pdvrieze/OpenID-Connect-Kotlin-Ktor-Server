package org.mitre.oauth2.model.request

import org.mitre.oauth2.model.GrantedAuthority
import org.mitre.openid.connect.model.convert.ISOInstant
import org.mitre.openid.connect.request.Prompt

class OpenIdAuthorizationRequestImpl internal constructor(
    builder: OpenIdAuthorizationRequest.Builder,
) : OpenIdAuthorizationRequest {
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

    val extensions: Map<String, String>? = builder.extensions?.toMap()

    override val authHolderExtensions: Map<String, String> get() {
        return buildMap {
            extensions?.let { putAll(it) }
            approval?.let {
                put("AUTHZ_TIMESTAMP", it.approvalTime.epochSecond.toString())
                it.approvedSiteId?.let { s -> put("approved_site", s.toString()) }
            }
        }
    }

    override fun builder(): OpenIdAuthorizationRequest.Builder {
        return OpenIdAuthorizationRequest.Builder(this)
    }

}
