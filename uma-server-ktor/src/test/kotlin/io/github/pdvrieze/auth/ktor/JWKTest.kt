package io.github.pdvrieze.auth.ktor

import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.JWKSet
import io.ktor.client.statement.*
import org.junit.Assert.assertFalse
import org.mitre.openid.connect.web.JWKSetPublishingEndpoint
import kotlin.test.Test
import kotlin.test.assertEquals

class JWKTest : ApiTest(JWKSetPublishingEndpoint) {

    @Test
    fun testGetJWK() {
        testEndpoint {
            val jwksResp = getUnAuth("/jwk").bodyAsText()
            val set = JWKSet.parse(jwksResp)
            val jwk = set.keys.single()

            assertFalse(jwk.isPrivate)

            assertEquals(JWK.parse(SIGNING_KEY).toPublicJWK(), jwk)

        }
    }

}
