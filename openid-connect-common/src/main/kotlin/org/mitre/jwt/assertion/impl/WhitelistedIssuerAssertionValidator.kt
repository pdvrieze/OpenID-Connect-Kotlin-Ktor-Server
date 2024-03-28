/*******************************************************************************
 * Copyright 2018 The MIT Internet Trust Consortium
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
package org.mitre.jwt.assertion.impl

import com.google.common.base.Strings
import com.nimbusds.jwt.JWT
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import org.mitre.jwt.assertion.AssertionValidator
import org.mitre.jwt.signer.service.impl.JWKSetCacheService
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.stereotype.Component
import java.text.ParseException

/**
 * Checks to see if the assertion was signed by a particular authority available from a whitelist
 * @author jricher
 */
@Component("whitelistedIssuerAssertionValidator")
class WhitelistedIssuerAssertionValidator : AssertionValidator {
    /**
     * Whitelist map of issuer -> JWKSetUri
     */
    var whitelist: Map<String, String> = HashMap()

    @Autowired
    private lateinit var jwkCache: JWKSetCacheService

    override fun isValid(assertion: JWT): Boolean {
        if (assertion !is SignedJWT) {
            // unsigned assertion
            return false
        }

        val claims: JWTClaimsSet =
        try {
            assertion.getJWTClaimsSet()
        } catch (e: ParseException) {
            logger.debug("Invalid assertion claims")
            return false
        }

        if (Strings.isNullOrEmpty(claims.issuer)) {
            logger.debug("No issuer for assertion, rejecting")
            return false
        }

        if (!whitelist.containsKey(claims.issuer)) {
            logger.debug("Issuer is not in whitelist, rejecting")
            return false
        }

        val jwksUri = whitelist[claims.issuer] ?: run {
            logger.debug("no jwk uri found")
            return false
        }

        val validator = jwkCache.getValidator(jwksUri) ?: return false

        return if (validator.validateSignature(assertion)) {
            true
        } else {
            false
        }
    }

    companion object {
        private val logger: Logger = LoggerFactory.getLogger(WhitelistedIssuerAssertionValidator::class.java)
    }
}