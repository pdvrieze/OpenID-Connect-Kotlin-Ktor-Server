package org.mitre.oauth2.model.request

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import org.mitre.oauth2.model.GrantedAuthority
import org.mitre.oauth2.service.SystemScopeService
import org.mitre.openid.connect.model.convert.ISOInstant
import java.time.Instant

/**
 * Object representing a request for authorization (in the authorization endpoint).
 * This request does not have authentication information present.
 */
@Serializable
class PlainAuthorizationRequest @InternalForStorage constructor(
    @SerialName("authorizationParameters")
    @property:InternalForStorage
    override val requestParameters: Map<String, String> = emptyMap(),
    override val clientId: String,
    override val authorities: Set<GrantedAuthority> = emptySet(),
    @SerialName("approved")
    override val approval: AuthorizationRequest.Approval? = null,
    override val scope: Set<String> = emptySet(),
    override val resourceIds: Set<String>? = null,
    override val redirectUri: String? = null,
    override val responseTypes: Set<String>? = null,
    override val state: String? = null,
    override val requestTime: ISOInstant? = null,
    override val codeChallenge: CodeChallenge? = null,
    @property:InternalForStorage
    val extensions: Map<String, String> = emptyMap(),
) : AuthorizationRequest {

    val isOpenId get() = SystemScopeService.OPENID_SCOPE in scope

    @OptIn(InternalForStorage::class)
    constructor(
        clientId: String,
        authorities: Set<GrantedAuthority> = emptySet(),
        approval: AuthorizationRequest.Approval? = null,
        scope: Set<String> = emptySet(),
        resourceIds: Set<String>? = null,
        redirectUri: String? = null,
        responseTypes: Set<String>? = null,
        state: String? = null,
        requestTime: ISOInstant? = null,
        codeChallenge: CodeChallenge? = null,
    ) : this(emptyMap(), clientId, authorities, approval, scope, resourceIds, redirectUri, responseTypes, state, requestTime, codeChallenge)

    @InternalForStorage
    override val authHolderExtensions: Map<String, String> = buildMap {
        approval?.let {
            put("AUTHZ_TIMESTAMP", it.approvalTime.epochSecond.toString())
            it.approvedSiteId?.let { s -> put("approved_site", s.toString()) }
        }
        codeChallenge?.let { ch ->
            put("code_challenge", ch.challenge)
            ch.method?.let { m -> put("code_challenge_method", m) }
        }
    }


    override fun builder(): Builder {
        return Builder(this)
    }

    class Builder(clientId: String): AuthorizationRequest.Builder(clientId) {
        @OptIn(InternalForStorage::class)
        constructor(orig: PlainAuthorizationRequest) : this(orig.clientId) {
            requestParameters = orig.requestParameters
            authorities = orig.authorities
            approval = orig.approval
            scope = orig.scope
            resourceIds = orig.resourceIds
            redirectUri = orig.redirectUri
            responseTypes = orig.responseTypes
            state = orig.state
            requestTime = orig.requestTime
            codeChallenge = orig.codeChallenge
        }

        @OptIn(InternalForStorage::class)
        override fun build(): PlainAuthorizationRequest {
            return PlainAuthorizationRequest(requestParameters, clientId, authorities, approval, scope, resourceIds, redirectUri, responseTypes, state, requestTime, codeChallenge)
        }

        @InternalForStorage
        override fun setFromExtensions(extensions: Map<String, String>) {
            if (extensions.isNotEmpty()) {
                val extCpy = HashMap(extensions)
                extCpy.remove("AUTHZ_TIMESTAMP")?.let {
                    approval = AuthorizationRequest.Approval(
                        extCpy.remove("approved_site")?.toLong(),
                        Instant.ofEpochSecond(it.toLong()),
                    )
                }
                extCpy.remove("code_challenge")
                    ?.let { codeChallenge = CodeChallenge(it, extCpy.remove("code_challenge_method")) }


                require(extCpy.isEmpty()) { "No extensions expected: ${extCpy.entries.joinToString { "${it.key}: ${it.value}" }}" }
            }

        }
    }
}
