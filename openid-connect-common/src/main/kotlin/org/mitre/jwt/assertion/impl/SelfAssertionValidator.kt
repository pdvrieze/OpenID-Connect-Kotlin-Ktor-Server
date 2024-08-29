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

import com.nimbusds.jwt.JWT
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import org.mitre.jwt.assertion.AssertionValidator
import org.mitre.jwt.signer.service.JWTSigningAndValidationService
import org.mitre.openid.connect.config.ConfigurationPropertiesBean
import org.mitre.util.getLogger
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.stereotype.Component
import java.text.ParseException

/**
 * Validates all assertions generated by this server
 *
 * @author jricher
 */
@Component("selfAssertionValidator")
class SelfAssertionValidator : AssertionValidator {
    @Autowired
    private lateinit var config: ConfigurationPropertiesBean

    @Autowired
    private lateinit var jwtService: JWTSigningAndValidationService

    override fun isValid(assertion: JWT): Boolean {
        if (assertion !is SignedJWT) {
            // unsigned assertion
            return false
        }

        val claims: JWTClaimsSet = try {
            assertion.getJWTClaimsSet()
        } catch (e: ParseException) {
            logger.debug("Invalid assertion claims")
            return false
        }

        // make sure the issuer exists
        if (claims.issuer.isNullOrEmpty()) {
            logger.debug("No issuer for assertion, rejecting")
            return false
        }

        // make sure the issuer is us
        if (claims.issuer != config.issuer) {
            logger.debug("Issuer is not the same as this server, rejecting")
            return false
        }

        // validate the signature based on our public key
        return jwtService.validateSignature(assertion)
    }

    companion object {
        private val logger = getLogger<SelfAssertionValidator>()
    }
}
