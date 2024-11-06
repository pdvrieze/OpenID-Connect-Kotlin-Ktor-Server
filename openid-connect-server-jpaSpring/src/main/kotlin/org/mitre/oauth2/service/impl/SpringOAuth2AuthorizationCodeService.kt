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

import io.github.pdvrieze.openid.spring.fromSpring
import io.github.pdvrieze.openid.spring.toSpring
import org.mitre.data.AbstractPageOperationTemplate
import org.mitre.oauth2.model.AuthorizationCodeEntity
import org.mitre.oauth2.model.jpa.AuthenticationHolderEntity
import org.mitre.oauth2.repository.AuthenticationHolderRepository
import org.mitre.oauth2.repository.AuthorizationCodeRepository
import org.mitre.util.getLogger
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.security.oauth2.common.exceptions.InvalidGrantException
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator
import org.springframework.security.oauth2.provider.code.AuthorizationCodeServices
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional
import java.util.*
import org.springframework.security.oauth2.provider.OAuth2Authentication as SpringOAuth2Authentication

/**
 * Database-backed, random-value authorization code service implementation.
 *
 * @author aanganes
 */
@Service("defaultOAuth2AuthorizationCodeService")
class SpringOAuth2AuthorizationCodeService : AuthorizationCodeServices {
    @Autowired
    lateinit var repository: AuthorizationCodeRepository

    @Autowired
    private lateinit var authenticationHolderRepository: AuthenticationHolderRepository

    var authCodeExpirationSeconds: Int = 60 * 5 // expire in 5 minutes by default

    private val generator = RandomValueStringGenerator(22)

    /**
     * Generate a random authorization code and create an AuthorizationCodeEntity,
     * which will be stored in the repository.
     *
     * @param authentication    the authentication of the current user, to be retrieved when the
     * code is consumed
     * @return                    the authorization code
     */
    @Transactional(value = "defaultTransactionManager")
    override fun createAuthorizationCode(authentication: SpringOAuth2Authentication): String {
        val code = generator.generate()

        // attach the authorization so that we can look it up later
        val authHolder = authenticationHolderRepository.save(AuthenticationHolderEntity(authentication.fromSpring()))

        // set the auth code to expire
        val expiration = Date(System.currentTimeMillis() + (authCodeExpirationSeconds * 1000L))

        val entity = AuthorizationCodeEntity(code = code, authenticationHolder = authHolder, expiration = expiration)
        repository.save(entity)

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
    @Throws(InvalidGrantException::class)
    override fun consumeAuthorizationCode(code: String): SpringOAuth2Authentication {
        val result = repository.getByCode(code)
            ?: throw InvalidGrantException("JpaAuthorizationCodeRepository: no authorization code found for value $code")

        val auth = result.authenticationHolder!!.authenticatedAuthorizationRequest

        repository.remove(result)

        return auth.toSpring()
    }

    /**
     * Find and remove all expired auth codes.
     */
    @Transactional(value = "defaultTransactionManager")
    fun clearExpiredAuthorizationCodes() {
        object : AbstractPageOperationTemplate<AuthorizationCodeEntity>("clearExpiredAuthorizationCodes") {
            override fun fetchPage(): Collection<AuthorizationCodeEntity> {
                return repository.expiredCodes
            }

            override fun doOperation(item: AuthorizationCodeEntity) {
                repository.remove(item)
            }
        }.execute()
    }

    companion object {
        // Logger for this class
        private val logger = getLogger<SpringOAuth2AuthorizationCodeService>()
    }
}
