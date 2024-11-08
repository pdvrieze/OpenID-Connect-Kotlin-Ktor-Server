package org.mitre.openid.connect.request

import org.mitre.oauth2.model.OAuthClientDetails
import org.mitre.oauth2.model.request.AuthorizationRequest
import org.mitre.oauth2.model.request.InternalForStorage
import org.mitre.oauth2.model.request.PlainAuthorizationRequest
import org.mitre.oauth2.service.ClientDetailsEntityService
import org.mitre.util.getLogger
import java.time.Instant

open class KtorOAuth2RequestFactory(
    protected val clientDetailsService: ClientDetailsEntityService,
) : OAuth2RequestFactory {

    override suspend fun createAuthorizationRequest(inputParams: Map<String, String>): AuthorizationRequest {
        val clientId = inputParams["client_id"]!!
        val client = clientDetailsService.loadClientByClientId(clientId)!!
        return createAuthorizationRequest(inputParams, client)
    }

    override suspend fun createAuthorizationRequest(inputParams: Map<String, String>, client: OAuthClientDetails): AuthorizationRequest {
        val scopes: Set<String> = inputParams["scope"]?.run {
            splitToSequence(' ').filterNotTo(HashSet()) { it.isBlank() }
        } ?: emptySet()

        val responseTypes = inputParams["response_type"]?.let { str ->
            str.splitToSequence(' ').filterNotTo(HashSet()) { it.isBlank() }
        }

        @OptIn(InternalForStorage::class)
        return PlainAuthorizationRequest.Builder(clientId = client.clientId).also { b ->
            b.requestParameters = inputParams.toMap()
            b.clientId = client.clientId
            b.authorities = client.authorities
            b.approval = null
            b.scope = scopes
            b.resourceIds = client.resourceIds
            b.redirectUri = inputParams["redirect_uri"]
            b.responseTypes = responseTypes
            b.state = inputParams["state"]
            b.requestTime = Instant.now()
        }.build()
    }



    companion object {
        /**
         * Logger for this class
         */
        private val logger = getLogger<KtorOAuth2RequestFactory>()
    }
}
