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
/**
 *
 */
package org.mitre.openid.connect.config

import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.Test

/**
 * @author jricher
 */
class ServerConfigurationTest {
    /**
     * Test getters and setters for server configuration bean
     */
    @Test
    fun testServerConfiguration() {
        val authorizationEndpointUri = "http://localhost:8080/openid-connect-server/authorize"
        val tokenEndpointUri = "http://localhost:8080/openid-connect-server/token"
        val registrationEndpointUri = "http://localhost:8080/openid-connect-server/register"
        val issuer = "http://localhost:8080/openid-connect-server/"
        val jwksUri = "http://localhost:8080/openid-connect-server/jwk"
        val userInfoUri = "http://localhost:8080/openid-connect-server/userinfo"

        val sc = ServerConfiguration()
        sc.authorizationEndpointUri = authorizationEndpointUri
        sc.tokenEndpointUri = tokenEndpointUri
        sc.registrationEndpointUri = registrationEndpointUri
        sc.issuer = issuer
        sc.jwksUri = jwksUri
        sc.userInfoUri = userInfoUri

        Assertions.assertEquals(authorizationEndpointUri, sc.authorizationEndpointUri)
        Assertions.assertEquals(tokenEndpointUri, sc.tokenEndpointUri)
        Assertions.assertEquals(registrationEndpointUri, sc.registrationEndpointUri)
        Assertions.assertEquals(issuer, sc.issuer)
        Assertions.assertEquals(jwksUri, sc.jwksUri)
        Assertions.assertEquals(userInfoUri, sc.userInfoUri)
    }


    /**
     * Test method for [org.mitre.openid.connect.config.ServerConfiguration.equals].
     */
    @Test
    fun testEqualsObject() {
        val authorizationEndpointUri = "http://localhost:8080/openid-connect-server/authorize"
        val tokenEndpointUri = "http://localhost:8080/openid-connect-server/token"
        val registrationEndpointUri = "http://localhost:8080/openid-connect-server/register"
        val issuer = "http://localhost:8080/openid-connect-server/"
        val jwksUri = "http://localhost:8080/openid-connect-server/jwk"
        val userInfoUri = "http://localhost:8080/openid-connect-server/userinfo"

        val sc1 = ServerConfiguration()
        sc1.authorizationEndpointUri = authorizationEndpointUri
        sc1.tokenEndpointUri = tokenEndpointUri
        sc1.registrationEndpointUri = registrationEndpointUri
        sc1.issuer = issuer
        sc1.jwksUri = jwksUri
        sc1.userInfoUri = userInfoUri

        val sc2 = ServerConfiguration()
        sc2.authorizationEndpointUri = authorizationEndpointUri
        sc2.tokenEndpointUri = tokenEndpointUri
        sc2.registrationEndpointUri = registrationEndpointUri
        sc2.issuer = issuer
        sc2.jwksUri = jwksUri
        sc2.userInfoUri = userInfoUri

        Assertions.assertTrue(sc1.equals(sc2))
    }
}
