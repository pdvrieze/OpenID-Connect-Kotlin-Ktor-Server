package org.mitre.jwt.assertion.impl

import com.nimbusds.jwt.JWT
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import org.mitre.jwt.assertion.AssertionValidator
import org.mitre.jwt.signer.service.JWKSetCacheService
import org.mitre.util.getLogger
import java.text.ParseException

/**
 * Checks to see if the assertion was signed by a particular authority available from a whitelist
 * @author jricher
 */
class WhitelistedIssuerAssertionValidator : AssertionValidator {
    /**
     * Whitelist map of issuer -> JWKSetUri
     */
    var whitelist: Map<String, String> = HashMap()

//    @Autowired
    private lateinit var jwkCache: JWKSetCacheService

    override suspend fun isValid(assertion: JWT): Boolean {
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

        if (claims.issuer.isNullOrEmpty()) {
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

        return validator.validateSignature(assertion)
    }

    companion object {
        private val logger = getLogger<WhitelistedIssuerAssertionValidator>()
    }
}
