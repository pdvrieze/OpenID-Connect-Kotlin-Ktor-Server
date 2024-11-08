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

import org.mitre.data.AbstractPageOperationTemplate
import org.mitre.oauth2.exception.InvalidGrantException
import org.mitre.oauth2.model.AuthenticatedAuthorizationRequest
import org.mitre.oauth2.model.AuthorizationCodeEntity
import org.mitre.oauth2.model.KtorAuthenticationHolder
import org.mitre.oauth2.repository.AuthenticationHolderRepository
import org.mitre.oauth2.repository.AuthorizationCodeRepository
import org.mitre.oauth2.service.OAuth2AuthorizationCodeService
import org.mitre.oauth2.util.RandomStringGenerator
import org.mitre.util.getLogger
import java.time.Duration
import java.time.Instant
import java.util.*

/**
 * Database-backed, random-value authorization code service implementation.
 *
 * @author aanganes
 */
class DefaultOAuth2AuthorizationCodeService(
    private val authcodeRepository: AuthorizationCodeRepository,
    private val authenticationHolderRepository: AuthenticationHolderRepository,
    private val authCodeExpirationSeconds: Duration = Duration.ofMinutes(5) // expire in 5 minutes by default
) : OAuth2AuthorizationCodeService {

    private val generator = RandomStringGenerator(22)

    /**
     * Generate a random authorization code and create an AuthorizationCodeEntity,
     * which will be stored in the repository.
     *
     * @param authentication    the authentication of the current user, to be retrieved when the
     * code is consumed
     * @return                    the authorization code
     */
    override fun createAuthorizationCode(authentication: AuthenticatedAuthorizationRequest): String {
        val code = generator.generate()

        // attach the authorization so that we can look it up later
        val authHolder = authenticationHolderRepository.save(KtorAuthenticationHolder(authentication))

        // set the auth code to expire
        val expiration = Date.from(Instant.now()+ authCodeExpirationSeconds)

        val entity = AuthorizationCodeEntity(code = code, authenticationHolder = authHolder, expiration = expiration)
        authcodeRepository.save(entity)

        return code
    }

    /**
     * Consume a given authorization code.
     * Match the provided string to an AuthorizationCodeEntity. If one is found, return
     * the authentication associated with the code. If one is not found, throw an
     * InvalidGrantException.
     *
     * @param code        the authorization code
     * @return            the authentication that made the original request
     * @throws            InvalidGrantException, if an AuthorizationCodeEntity is not found with the given value
     */
    override fun consumeAuthorizationCode(code: String): AuthenticatedAuthorizationRequest {
        // XXX when a past code is used, this should revoke existing authorization codes.
        val result = authcodeRepository.getByCode(code)
            ?: throw InvalidGrantException("AuthorizationCodeRepository: no authorization code found for value $code")

        val auth = result.authenticationHolder!!

        authcodeRepository.remove(result)

        return auth
    }

    /**
     * Find and remove all expired auth codes.
     */
    override fun clearExpiredAuthorizationCodes() {
        object : AbstractPageOperationTemplate<AuthorizationCodeEntity>("clearExpiredAuthorizationCodes") {
            override fun fetchPage(): Collection<AuthorizationCodeEntity> {
                return authcodeRepository.expiredCodes
            }

            override fun doOperation(item: AuthorizationCodeEntity) {
                authcodeRepository.remove(item)
            }
        }.execute()
    }

    companion object {
        // Logger for this class
        private val logger = getLogger<DefaultOAuth2AuthorizationCodeService>()
    }
}
