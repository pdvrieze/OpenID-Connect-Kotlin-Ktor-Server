/*******************************************************************************
 * Copyright 2018 The MIT Internet Trust Consortium
 *
 * Portions copyright 2011-2013 The MITRE Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.mitre.oauth2.service.impl

import com.nimbusds.jose.util.Base64URL
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.PlainJWT
import org.mitre.data.AbstractPageOperationTemplate
import org.mitre.data.DefaultPageCriteria
import org.mitre.oauth2.TokenEnhancer
import org.mitre.oauth2.exception.InvalidClientException
import org.mitre.oauth2.exception.InvalidRequestException
import org.mitre.oauth2.exception.InvalidScopeException
import org.mitre.oauth2.exception.InvalidTokenException
import org.mitre.oauth2.model.AuthenticationHolderEntity
import org.mitre.oauth2.model.OAuth2AccessToken
import org.mitre.oauth2.model.OAuth2AccessTokenEntity
import org.mitre.oauth2.model.OAuth2Authentication
import org.mitre.oauth2.model.OAuth2RefreshTokenEntity
import org.mitre.oauth2.model.OAuthClientDetails
import org.mitre.oauth2.model.PKCEAlgorithm
import org.mitre.oauth2.model.PKCEAlgorithm.Companion.parse
import org.mitre.oauth2.model.SystemScope
import org.mitre.oauth2.model.convert.OAuth2Request
import org.mitre.oauth2.repository.AuthenticationHolderRepository
import org.mitre.oauth2.repository.OAuth2TokenRepository
import org.mitre.oauth2.service.ClientDetailsEntityService
import org.mitre.oauth2.service.OAuth2TokenEntityService
import org.mitre.oauth2.service.SystemScopeService
import org.mitre.openid.connect.request.ConnectRequestParameters
import org.mitre.openid.connect.service.ApprovedSiteService
import org.mitre.util.getLogger
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.security.NoSuchAlgorithmException
import java.util.*

/**
 * @author jricher
 */
class DefaultOAuth2ProviderTokenService(
    private val tokenRepository: OAuth2TokenRepository,
    private val authenticationHolderRepository: AuthenticationHolderRepository,
    private val clientDetailsService: ClientDetailsEntityService,
    val tokenEnhancer: TokenEnhancer,
    private val scopeService: SystemScopeService,
    private val approvedSiteService: ApprovedSiteService,
) : OAuth2TokenEntityService {

    override fun getAllAccessTokensForUser(name: String): Set<OAuth2AccessTokenEntity> {
        return tokenRepository.getAccessTokensByUserName(name)
    }

    override fun getAllRefreshTokensForUser(userName: String): Set<OAuth2RefreshTokenEntity> {
        return tokenRepository.getRefreshTokensByUserName(userName)
    }

    override fun getAccessTokenById(id: Long): OAuth2AccessTokenEntity? {
        return clearExpiredAccessToken(tokenRepository.getAccessTokenById(id))
    }

    override fun getRefreshTokenById(id: Long): OAuth2RefreshTokenEntity? {
        return clearExpiredRefreshToken(tokenRepository.getRefreshTokenById(id))
    }

    /**
     * Utility function to delete an access token that's expired before returning it.
     * @param token the token to check
     * @return null if the token is null or expired, the input token (unchanged) if it hasn't
     */
    private fun clearExpiredAccessToken(token: OAuth2AccessTokenEntity?): OAuth2AccessTokenEntity? {
        if (token == null) {
            return null
        } else if (token.isExpired) {
            // immediately revoke expired token
            logger.debug("Clearing expired access token: ${token.value}")
            revokeAccessToken(token)
            return null
        } else {
            return token
        }
    }

    /**
     * Utility function to delete a refresh token that's expired before returning it.
     * @param token the token to check
     * @return null if the token is null or expired, the input token (unchanged) if it hasn't
     */
    private fun clearExpiredRefreshToken(token: OAuth2RefreshTokenEntity?): OAuth2RefreshTokenEntity? {
        if (token == null) {
            return null
        } else if (token.isExpired) {
            // immediately revoke expired token
            logger.debug("Clearing expired refresh token: ${token.value}")
            revokeRefreshToken(token)
            return null
        } else {
            return token
        }
    }


    override fun createAccessToken(authentication: OAuth2Authentication): OAuth2AccessToken {
        // look up our client
        val request = authentication.oAuth2Request

        val client: OAuthClientDetails = clientDetailsService.loadClientByClientId(request.clientId)
            ?: throw InvalidClientException("Client not found: " + request.clientId)

        // handle the PKCE code challenge if present
        if (request.extensionStrings?.containsKey(ConnectRequestParameters.CODE_CHALLENGE) == true) {
            val challenge = request.extensionStrings!![ConnectRequestParameters.CODE_CHALLENGE]
            val alg = parse(request.extensionStrings!![ConnectRequestParameters.CODE_CHALLENGE_METHOD]!!)

            val verifier = request.requestParameters[ConnectRequestParameters.CODE_VERIFIER]

            if (alg == PKCEAlgorithm.plain) {
                // do a direct string comparison
                if (challenge != verifier) {
                    throw InvalidRequestException("Code challenge and verifier do not match")
                }
            } else if (alg == PKCEAlgorithm.S256) {
                // hash the verifier
                try {
                    val digest = MessageDigest.getInstance("SHA-256")
                    val hash = Base64URL.encode(digest.digest(verifier!!.toByteArray(StandardCharsets.US_ASCII)))
                        .toString()
                    if (challenge != hash) {
                        throw InvalidRequestException("Code challenge and verifier do not match")
                    }
                } catch (e: NoSuchAlgorithmException) {
                    logger.error("Unknown algorithm for PKCE digest", e)
                }
            }
        }

        val tokenBuilder = OAuth2AccessTokenEntity.Builder() //accessTokenFactory.createNewAccessToken();

        // attach the client
        tokenBuilder.setClient(client)

        // inherit the scope from the auth, but make a new set so it is
        //not unmodifiable. Unmodifiables don't play nicely with Eclipselink, which
        //wants to use the clone operation.
        val scopes = scopeService.fromStrings(request.scope)?.let {
            // remove any of the special system scopes
            scopeService.removeReservedScopes(it)
        }

        val scope = scopeService.toStrings(scopes) ?: emptySet()

        val atvsecs = client.accessTokenValiditySeconds
        // make it expire if necessary
        if (atvsecs != null && atvsecs > 0) {
            val expiration = Date(System.currentTimeMillis() + (atvsecs * 1000L))
            tokenBuilder.expiration = expiration
        }

        // attach the authorization so that we can look it up later
        var authHolder = AuthenticationHolderEntity()
        authHolder.authentication = authentication
        authHolder = authenticationHolderRepository.save(authHolder)

        tokenBuilder.setAuthenticationHolder(authHolder)

        // attach a refresh token, if this client is allowed to request them and the user gets the offline scope
        if (client.isAllowRefresh && SystemScopeService.OFFLINE_ACCESS in scope) {
            val savedRefreshToken = createRefreshToken(client, authHolder)

            tokenBuilder.setRefreshToken(savedRefreshToken)
        }

        tokenBuilder.scope = scope

        //Add approved site reference, if any
        val originalAuthRequest = authHolder.authentication.oAuth2Request

        if (originalAuthRequest.extensionStrings?.containsKey("approved_site") == true) {
            val apId = (originalAuthRequest.extensionStrings!!["approved_site"] as String).toLong()
            val ap = approvedSiteService.getById(apId)

            tokenBuilder.approvedSite = ap
        }

        tokenEnhancer.enhance(tokenBuilder, authentication)

        val token = tokenBuilder.build(clientDetailsService, authenticationHolderRepository, tokenRepository)

//        val enhancedToken = TODO()/*tokenEnhancer.enhance(token, authentication)*/ as OAuth2AccessTokenEntity

        val savedToken = saveAccessToken(token)

        if (savedToken.refreshToken != null) {
            tokenRepository.saveRefreshToken(savedToken.refreshToken!!) // make sure we save any changes that might have been enhanced
        }

        return savedToken
    }


    private fun createRefreshToken(
        client: OAuthClientDetails,
        authHolder: AuthenticationHolderEntity
    ): OAuth2RefreshTokenEntity {
        val refreshToken = OAuth2RefreshTokenEntity() //refreshTokenFactory.createNewRefreshToken();
        val refreshClaims = JWTClaimsSet.Builder()


        val rtvalSecs = client.refreshTokenValiditySeconds
        // make it expire if necessary
        if (rtvalSecs != null) {
            val expiration = Date(System.currentTimeMillis() + (rtvalSecs * 1000L))
            refreshToken.expiration = expiration
            refreshClaims.expirationTime(expiration)
        }

        // set a random identifier
        refreshClaims.jwtID(UUID.randomUUID().toString())

        // TODO: add issuer fields, signature to JWT
        val refreshJwt = PlainJWT(refreshClaims.build())
        refreshToken.jwt = refreshJwt

        //Add the authentication
        refreshToken.authenticationHolder = authHolder
        refreshToken.client = client

        // save the token first so that we can set it to a member of the access token (NOTE: is this step necessary?)
        val savedRefreshToken = tokenRepository.saveRefreshToken(refreshToken)
        return savedRefreshToken
    }

    override fun refreshAccessToken(refreshTokenValue: String, authRequest: OAuth2Request): OAuth2AccessToken {
        // throw an invalid token exception if there's no refresh token value at all
        require(refreshTokenValue.isNotBlank()) { "Invalid refresh token: $refreshTokenValue" }

        // throw an invalid token exception if we couldn't find the token
        val refreshToken = clearExpiredRefreshToken(tokenRepository.getRefreshTokenByValue(refreshTokenValue))
            ?: throw InvalidTokenException("Invalid refresh token: $refreshTokenValue")


        val client = refreshToken.client

        val authHolder = refreshToken.authenticationHolder

        // make sure that the client requesting the token is the one who owns the refresh token
        val requestingClient = clientDetailsService.loadClientByClientId(authRequest.clientId)!!
        if (client!!.clientId != requestingClient.clientId) {
            tokenRepository.removeRefreshToken(refreshToken)
            throw InvalidClientException("Client does not own the presented refresh token")
        }

        //Make sure this client allows access token refreshing
        if (!client.isAllowRefresh) {
            throw InvalidClientException("Client does not allow refreshing access token!")
        }

        // clear out any access tokens
        if (client.isClearAccessTokensOnRefresh) {
            tokenRepository.clearAccessTokensForRefreshToken(refreshToken)
        }

        if (refreshToken.isExpired) {
            tokenRepository.removeRefreshToken(refreshToken)
            throw InvalidTokenException("Expired refresh token: $refreshTokenValue")
        }

        val tokenBuilder = OAuth2AccessTokenEntity.Builder()

        // get the stored scopes from the authentication holder's authorization request; these are the scopes associated with the refresh token
        val refreshScopesRequested: Set<String> =
            HashSet(refreshToken.authenticationHolder.authentication.oAuth2Request.scope)
        val refreshScopes: Set<SystemScope>? = scopeService.fromStrings(refreshScopesRequested)?.let {
            // remove any of the special system scopes
            scopeService.removeReservedScopes(it)
        }

        val scopeRequested: Set<String> = if (authRequest.scope == null) HashSet() else HashSet(authRequest.scope)
        val scope: Set<SystemScope>? = scopeService.fromStrings(scopeRequested)?.let {
            // remove any of the special system scopes
            scopeService.removeReservedScopes(it)
        }

        when {
            // otherwise inherit the scope of the refresh token (if it's there -- this can return a null scope set)
            scope.isNullOrEmpty() -> tokenBuilder.scope = scopeService.toStrings(refreshScopes)

            // ensure a proper subset of scopes
            // set the scope of the new access token if requested
            refreshScopes != null && refreshScopes.containsAll(scope) ->
                tokenBuilder.scope = scopeService.toStrings(scope)

            else -> {
                val errorMsg = "Up-scoping is not allowed."
                logger.error(errorMsg)
                throw InvalidScopeException(errorMsg)
            }
        }

        tokenBuilder.setClient(client)

        val accessTokenValiditySeconds = client.accessTokenValiditySeconds
        if (accessTokenValiditySeconds != null) {
            val expiration = Date(System.currentTimeMillis() + (accessTokenValiditySeconds * 1000L))
            tokenBuilder.expiration = expiration
        }

        if (client.isReuseRefreshToken) {
            // if the client re-uses refresh tokens, do that
            tokenBuilder.setRefreshToken(refreshToken)
        } else {
            // otherwise, make a new refresh token
            val newRefresh = createRefreshToken(client, authHolder)
            tokenBuilder.setRefreshToken(newRefresh)

            // clean up the old refresh token
            tokenRepository.removeRefreshToken(refreshToken)
        }

        tokenBuilder.setAuthenticationHolder(authHolder)

        tokenEnhancer.enhance(tokenBuilder, authHolder.authentication)

        val token = tokenBuilder.build(clientDetailsService, authenticationHolderRepository, tokenRepository)

        tokenRepository.saveAccessToken(token)

        return token
    }

    override fun loadAuthentication(accessTokenValue: String): OAuth2Authentication {
        val accessToken = clearExpiredAccessToken(tokenRepository.getAccessTokenByValue(accessTokenValue))

        if (accessToken == null) {
            throw InvalidTokenException("Invalid access token: $accessTokenValue")
        } else {
            return accessToken.authenticationHolder.authentication
        }
    }


    /**
     * Get an access token from its token value.
     */
    override fun readAccessToken(accessTokenValue: String): OAuth2AccessTokenEntity {
        val accessToken = clearExpiredAccessToken(tokenRepository.getAccessTokenByValue(accessTokenValue))
            ?: throw InvalidTokenException("Access token for value $accessTokenValue was not found")

        return accessToken
    }

    /**
     * Get an access token by its authentication object.
     */
    override fun getAccessToken(authentication: OAuth2Authentication): OAuth2AccessToken {
        // TODO: implement this against the new service (#825)
        throw UnsupportedOperationException("Unable to look up access token from authentication object.")
    }

    /**
     * Get a refresh token by its token value.
     */
    override fun getRefreshToken(refreshTokenValue: String): OAuth2RefreshTokenEntity {
        val refreshToken = tokenRepository.getRefreshTokenByValue(refreshTokenValue)
            ?: throw InvalidTokenException("Refresh token for value $refreshTokenValue was not found")
        return refreshToken
    }

    /**
     * Revoke a refresh token and all access tokens issued to it.
     */
    override fun revokeRefreshToken(refreshToken: OAuth2RefreshTokenEntity) {
        tokenRepository.clearAccessTokensForRefreshToken(refreshToken)
        tokenRepository.removeRefreshToken(refreshToken)
    }

    /**
     * Revoke an access token.
     */
    override fun revokeAccessToken(accessToken: OAuth2AccessTokenEntity) {
        tokenRepository.removeAccessToken(accessToken)
    }

    override fun getAccessTokensForClient(client: OAuthClientDetails): List<OAuth2AccessTokenEntity> {
        return tokenRepository.getAccessTokensForClient(client)
    }

    override fun getRefreshTokensForClient(client: OAuthClientDetails): List<OAuth2RefreshTokenEntity> {
        return tokenRepository.getRefreshTokensForClient(client)
    }

    /**
     * Clears out expired tokens and any abandoned authentication objects
     */
    override fun clearExpiredTokens() {
        logger.debug("Cleaning out all expired tokens")

        object : AbstractPageOperationTemplate<OAuth2AccessTokenEntity>("clearExpiredAccessTokens") {
            override fun fetchPage(): Collection<OAuth2AccessTokenEntity> {
                return tokenRepository.getAllExpiredAccessTokens(DefaultPageCriteria())
            }

            override fun doOperation(item: OAuth2AccessTokenEntity) {
                revokeAccessToken(item)
            }
        }.execute()

        object : AbstractPageOperationTemplate<OAuth2RefreshTokenEntity>("clearExpiredRefreshTokens") {
            override fun fetchPage(): Collection<OAuth2RefreshTokenEntity> {
                return tokenRepository.getAllExpiredRefreshTokens(DefaultPageCriteria())
            }

            override fun doOperation(item: OAuth2RefreshTokenEntity) {
                revokeRefreshToken(item)
            }
        }.execute()

        object : AbstractPageOperationTemplate<AuthenticationHolderEntity>("clearExpiredAuthenticationHolders") {
            override fun fetchPage(): Collection<AuthenticationHolderEntity> {
                return authenticationHolderRepository.getOrphanedAuthenticationHolders(DefaultPageCriteria())
            }

            override fun doOperation(item: AuthenticationHolderEntity) {
                authenticationHolderRepository.remove(item)
            }
        }.execute()
    }

    /* (non-Javadoc)
	 * @see org.mitre.oauth2.service.OAuth2TokenEntityService#saveAccessToken(org.mitre.oauth2.model.OAuth2AccessTokenEntity)
	 */
    override fun saveAccessToken(accessToken: OAuth2AccessTokenEntity): OAuth2AccessTokenEntity {
        val newToken = tokenRepository.saveAccessToken(accessToken)

        // if the old token has any additional information for the return from the token endpoint, carry it through here after save
        val additionalInformation = accessToken.getAdditionalInformation()
        if (additionalInformation.isNotEmpty()) {
            // known to be not null as it is a copy of the saved token
            newToken.getAdditionalInformation().putAll(additionalInformation)
        }

        return newToken
    }

    /* (non-Javadoc)
	 * @see org.mitre.oauth2.service.OAuth2TokenEntityService#saveRefreshToken(org.mitre.oauth2.model.OAuth2RefreshTokenEntity)
	 */
    override fun saveRefreshToken(refreshToken: OAuth2RefreshTokenEntity): OAuth2RefreshTokenEntity {
        return tokenRepository.saveRefreshToken(refreshToken)
    }

    override fun getRegistrationAccessTokenForClient(client: OAuthClientDetails): OAuth2AccessTokenEntity? {
        val allTokens = getAccessTokensForClient(client)

        for (token in allTokens) {

            // if it only has the registration scope, then it's a registration token
            when (token.scope.singleOrNull()) {
                SystemScopeService.REGISTRATION_TOKEN_SCOPE,
                    SystemScopeService.RESOURCE_TOKEN_SCOPE -> return token
            }
        }

        return null
    }

    companion object {
        /**
         * Logger for this class
         */
        private val logger = getLogger<DefaultOAuth2ProviderTokenService>()
    }
}
