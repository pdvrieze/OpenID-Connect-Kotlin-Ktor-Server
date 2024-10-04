package org.mitre.oauth2.token

import com.nimbusds.jwt.JWTParser
import org.mitre.jwt.assertion.AssertionValidator
import org.mitre.oauth2.assertion.AssertionOAuth2RequestFactory
import org.mitre.oauth2.model.ClientDetailsEntity
import org.mitre.oauth2.model.OAuth2AccessToken
import org.mitre.oauth2.model.OAuth2RequestAuthentication
import org.mitre.oauth2.model.OAuthClientDetails
import org.mitre.oauth2.model.SavedUserAuthentication
import org.mitre.oauth2.model.convert.OAuth2Request
import org.mitre.oauth2.service.ClientDetailsEntityService
import org.mitre.oauth2.service.OAuth2TokenEntityService
import org.mitre.openid.connect.assertion.JWTBearerAssertionAuthenticationToken
import org.mitre.openid.connect.request.OAuth2RequestFactory
import java.text.ParseException

/**
 * @author jricher
 */
class JWTAssertionTokenGranter constructor(
    tokenServices: OAuth2TokenEntityService,
    clientDetailsService: ClientDetailsEntityService?,
    requestFactory: OAuth2RequestFactory,
    private val validator: AssertionValidator,
    private val assertionFactory: AssertionOAuth2RequestFactory
) : AbstractTokenGranter(tokenServices, clientDetailsService, requestFactory, grantType) {

    override suspend fun getOAuth2Authentication(
        client: OAuthClientDetails,
        tokenRequest: TokenRequest,
    ): OAuth2RequestAuthentication? {
        // read and load up the existing token
        try {
            val incomingAssertionValue = tokenRequest.requestParameters["assertion"]
            val assertion = JWTParser.parse(incomingAssertionValue)

            if (validator.isValid(assertion)) {
                // our validator says it's OK, time to make a token from it
                // the real work happens in the assertion factory and the token services

                val req: OAuth2Request = assertionFactory.createOAuth2Request(client, tokenRequest, assertion)!!
                val userAuthentication: SavedUserAuthentication =
                    SavedUserAuthentication.from(JWTBearerAssertionAuthenticationToken(assertion, client.authorities))


                return OAuth2RequestAuthentication(
                    req,
                    userAuthentication
                )
            } else {
                logger.warn("Incoming assertion did not pass validator, rejecting")
                return null
            }
        } catch (e: ParseException) {
            logger.warn("Unable to parse incoming assertion")
        }

        // if we had made a token, we'd have returned it by now, so return null here to close out with no created token
        return null
    }

    override suspend fun getAccessToken(client: ClientDetailsEntity, tokenRequest: TokenRequest): OAuth2AccessToken {
        val auth: OAuth2RequestAuthentication = getOAuth2Authentication(client, tokenRequest)!!
        return tokenServices.createAccessToken(auth)
    }


    companion object {
        val logger = org.mitre.util.getLogger<JWTAssertionTokenGranter>()
        private const val grantType = "urn:ietf:params:oauth:grant-type:jwt-bearer"
    }
}
