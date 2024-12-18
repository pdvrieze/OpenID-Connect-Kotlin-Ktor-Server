package org.mitre.oauth2.assertion.impl

import com.nimbusds.jwt.JWT
import io.ktor.util.*
import org.mitre.oauth2.assertion.AssertionOAuth2RequestFactory
import org.mitre.oauth2.model.OAuthClientDetails
import org.mitre.oauth2.model.request.AuthorizationRequest
import org.mitre.oauth2.model.request.InternalForStorage
import org.mitre.oauth2.model.request.PlainAuthorizationRequest
import org.mitre.oauth2.token.TokenRequest
import java.text.ParseException
import java.time.Instant

/**
 * Takes an assertion from a trusted source, looks for the fields:
 *
 * - scope, space-separated list of strings
 * - aud, array of audience IDs
 *
 * @author jricher
 */
class DirectCopyRequestFactory : AssertionOAuth2RequestFactory {
    override fun createOAuth2Request(
        client: OAuthClientDetails,
        tokenRequest: TokenRequest,
        assertion: JWT,
    ): AuthorizationRequest? {
        try {
            val claims = assertion.jwtClaimsSet
            val scope = claims.getStringClaim("scope")?.splitToSequence(' ')?.filterNotTo(HashSet()) { it.isBlank() }
                ?: emptySet()

            val resources = claims.audience.toSet()

            val now = Instant.now()

            @OptIn(InternalForStorage::class)
            return PlainAuthorizationRequest.Builder(clientId = client.clientId).also { b ->
                b.requestParameters = tokenRequest.requestParameters.toMap().mapValues { it.value.first() }
                b.requestTime = now
                b.authorities = client.authorities
                b.approval = AuthorizationRequest.Approval(now)
                b.scope = scope
                b.resourceIds = resources
                b.requestTime = now
            }.build()
        } catch (e: ParseException) {
            return null
        }
    }
}
