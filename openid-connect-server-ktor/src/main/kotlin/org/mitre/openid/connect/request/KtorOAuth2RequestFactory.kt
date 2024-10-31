package org.mitre.openid.connect.request

import io.ktor.http.*
import org.mitre.oauth2.model.OAuthClientDetails
import org.mitre.oauth2.model.convert.AuthorizationRequest
import org.mitre.oauth2.service.ClientDetailsEntityService
import org.mitre.util.getLogger
import java.time.Instant

open class KtorOAuth2RequestFactory constructor(
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

        return AuthorizationRequest(
            requestParameters = inputParams.entries().associate { (k, v) -> k to v.first() },
            clientId = client.clientId!!,
            authorities = client.authorities,
            isApproved = false,
            scope = scopes,
            resourceIds = client.resourceIds,
            redirectUri = inputParams["redirect_uri"],
            responseTypes = responseTypes,
            requestTime = Instant.now(),
            state = inputParams["state"],
        )
    }



    companion object {
        /**
         * Logger for this class
         */
        private val logger = getLogger<KtorOAuth2RequestFactory>()
    }
}
