package org.mitre.openid.connect.request

import io.ktor.http.*
import org.mitre.oauth2.model.convert.OAuth2Request
import org.mitre.oauth2.service.ClientDetailsEntityService
import org.mitre.util.getLogger

open class KtorOAuth2RequestFactory constructor(
    protected val clientDetailsService: ClientDetailsEntityService,
) : OAuth2RequestFactory {

    override suspend fun createAuthorizationRequest(inputParams: Parameters): OAuth2Request {
        val scopes: Set<String> = inputParams.getAll("scope")?.flatMapTo(HashSet()) { str ->
            str.splitToSequence(' ').filterNot { it.isBlank() }
        } ?: emptySet()

        val responseTypes = inputParams.getAll("response_type")?.flatMapTo(HashSet()) { str ->
            str.splitToSequence(' ').filterNot { it.isBlank() }
        }

        val clientId = inputParams["client_id"]!!
        val client = clientDetailsService.loadClientByClientId(clientId)!!

        return OAuth2Request(
            requestParameters = inputParams.entries().associate { (k, v) -> k to v.first() },
            clientId = clientId,
            authorities = client.authorities,
            isApproved = false,
            scope = scopes,
            resourceIds = client.resourceIds,
            redirectUri = inputParams["redirect_uri"],
            responseTypes = responseTypes,
        )
    }



    companion object {
        /**
         * Logger for this class
         */
        private val logger = getLogger<KtorOAuth2RequestFactory>()
    }
}
