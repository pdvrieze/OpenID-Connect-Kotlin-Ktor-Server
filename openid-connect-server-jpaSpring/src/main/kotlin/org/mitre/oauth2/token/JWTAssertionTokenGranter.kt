package org.mitre.oauth2.token

import com.nimbusds.jwt.JWTParser
import io.github.pdvrieze.openid.spring.fromSpring
import io.github.pdvrieze.openid.spring.toSpring
import kotlinx.coroutines.runBlocking
import org.mitre.jwt.assertion.AssertionValidator
import org.mitre.oauth2.assertion.AssertionOAuth2RequestFactory
import org.mitre.oauth2.model.LocalGrantedAuthority
import org.mitre.oauth2.model.OAuth2RequestAuthentication
import org.mitre.oauth2.service.ClientDetailsEntityService
import org.mitre.oauth2.service.OAuth2TokenEntityService
import org.mitre.openid.connect.assertion.JWTBearerAssertionAuthenticationToken
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.beans.factory.annotation.Qualifier
import org.springframework.security.core.AuthenticationException
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException
import org.springframework.security.oauth2.provider.ClientDetails
import org.springframework.security.oauth2.provider.ClientDetailsService
import org.springframework.security.oauth2.provider.OAuth2RequestFactory
import org.springframework.security.oauth2.provider.TokenRequest
import org.springframework.security.oauth2.provider.token.AbstractTokenGranter
import org.springframework.stereotype.Component
import java.text.ParseException
import org.springframework.security.oauth2.common.OAuth2AccessToken as SpringOAuth2AccessToken
import org.springframework.security.oauth2.provider.OAuth2Authentication as SpringOAuth2Authentication

/**
 * @author jricher
 */
@Component("jwtAssertionTokenGranter")
class JWTAssertionTokenGranter @Autowired constructor(
    private val tokenServices: OAuth2TokenEntityService,
    clientDetailsService: ClientDetailsEntityService?,
    requestFactory: OAuth2RequestFactory?
    // TODO Remove need for casting/spring
) : AbstractTokenGranter(null, clientDetailsService as ClientDetailsService, requestFactory, grantType) {
    @Autowired
    @Qualifier("jwtAssertionValidator")
    private lateinit var validator: AssertionValidator

    @Autowired
    private lateinit var assertionFactory: AssertionOAuth2RequestFactory

    /* (non-Javadoc)
	 * @see org.springframework.security.oauth2.provider.token.AbstractTokenGranter#getOAuth2Authentication(org.springframework.security.oauth2.provider.AuthorizationRequest)
	 */
    @Throws(AuthenticationException::class, InvalidTokenException::class)
    override fun getOAuth2Authentication(client: ClientDetails, tokenRequest: TokenRequest): SpringOAuth2Authentication? {
        // read and load up the existing token
        try {
            val incomingAssertionValue = tokenRequest.requestParameters["assertion"]
            val assertion = JWTParser.parse(incomingAssertionValue)

            return runBlocking {
                if (validator.isValid(assertion)) {
                    // our validator says it's OK, time to make a token from it
                    // the real work happens in the assertion factory and the token services

                    SpringOAuth2Authentication(
                        assertionFactory.createOAuth2Request(client, tokenRequest, assertion),
                        JWTBearerAssertionAuthenticationToken(assertion, client.authorities?.map { LocalGrantedAuthority(it.authority) })
                    )
                } else {
                    logger.warn("Incoming assertion did not pass validator, rejecting")
                    null
                }
            }
        } catch (e: ParseException) {
            logger.warn("Unable to parse incoming assertion")
            return null
        // if we had made a token, we'd have returned it by now, so return null here to close out with no created token
        }

    }

    override fun getAccessToken(client: ClientDetails, tokenRequest: TokenRequest): SpringOAuth2AccessToken {
        val auth: OAuth2RequestAuthentication = getOAuth2Authentication(client, tokenRequest)!!.fromSpring()
        return runBlocking { tokenServices.createAccessToken(auth).toSpring() }
    }


    companion object {
        private const val grantType = "urn:ietf:params:oauth:grant-type:jwt-bearer"
    }
}
