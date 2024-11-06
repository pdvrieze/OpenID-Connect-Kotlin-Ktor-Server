package org.mitre.openid.connect.request

import io.ktor.http.*
import org.mitre.oauth2.model.OAuthClientDetails
import org.mitre.oauth2.model.request.AuthorizationRequest
import org.mitre.oauth2.model.request.PlainAuthorizationRequest
import org.mitre.oauth2.service.ClientDetailsEntityService
import org.mitre.util.getLogger
import java.time.Instant

open class KtorOAuth2RequestFactory(
    protected val clientDetailsService: ClientDetailsEntityService,
) : OAuth2RequestFactory {

    override suspend fun createAuthorizationRequest(inputParams: Parameters): AuthorizationRequest {
        val clientId = inputParams["client_id"]!!
        val client = clientDetailsService.loadClientByClientId(clientId)!!
        return createAuthorizationRequest(inputParams, client)
    }

    override suspend fun createAuthorizationRequest(inputParams: Parameters, client: OAuthClientDetails): AuthorizationRequest {
        val scopes: Set<String> = inputParams.getAll("scope")?.flatMapTo(HashSet()) { str ->
            str.splitToSequence(' ').filterNot { it.isBlank() }
        } ?: emptySet()

        val responseTypes = inputParams.getAll("response_type")?.flatMapTo(HashSet()) { str ->
            str.splitToSequence(' ').filterNot { it.isBlank() }
        }

        return PlainAuthorizationRequest.Builder(clientId = client.clientId).also { b ->
            b.requestParameters = inputParams.entries().associate { (k, v) -> k to v.first() }
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
