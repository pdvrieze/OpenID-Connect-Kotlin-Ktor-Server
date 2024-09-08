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
package io.github.pdvrieze.auth.service.impl

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.junit.jupiter.api.extension.ExtendWith
import org.mitre.oauth2.exception.InvalidClientException
import org.mitre.oauth2.model.ClientDetailsEntity
import org.mitre.oauth2.model.OAuthClientDetails
import org.mitre.oauth2.model.OAuthClientDetails.AuthMethod
import org.mitre.oauth2.model.SystemScope
import org.mitre.oauth2.repository.OAuth2ClientRepository
import org.mitre.oauth2.repository.OAuth2TokenRepository
import org.mitre.oauth2.service.SystemScopeService
import org.mitre.oauth2.service.impl.DefaultOAuth2ClientDetailsEntityService
import org.mitre.openid.connect.config.ConfigurationPropertiesBean
import org.mitre.openid.connect.model.WhitelistedSite
import org.mitre.openid.connect.service.ApprovedSiteService
import org.mitre.openid.connect.service.BlacklistedSiteService
import org.mitre.openid.connect.service.StatsService
import org.mitre.openid.connect.service.WhitelistedSiteService
import org.mitre.uma.service.ResourceSetService
import org.mockito.AdditionalAnswers
import org.mockito.ArgumentMatchers
import org.mockito.InjectMocks
import org.mockito.Mock
import org.mockito.junit.jupiter.MockitoExtension
import org.mockito.junit.jupiter.MockitoSettings
import org.mockito.kotlin.atLeastOnce
import org.mockito.kotlin.doReturn
import org.mockito.kotlin.isA
import org.mockito.kotlin.mock
import org.mockito.kotlin.reset
import org.mockito.kotlin.verify
import org.mockito.kotlin.whenever
import org.mockito.quality.Strictness

/**
 * @author wkim
 */
@ExtendWith(MockitoExtension::class)
@MockitoSettings(strictness = Strictness.WARN)
class TestDefaultOAuth2ClientDetailsEntityService {
    @Mock
    private lateinit var clientRepository: OAuth2ClientRepository

    @Mock
    private lateinit var tokenRepository: OAuth2TokenRepository

    @Mock
    private lateinit var approvedSiteService: ApprovedSiteService

    @Mock
    private lateinit var whitelistedSiteService: WhitelistedSiteService

    @Mock
    private lateinit var blacklistedSiteService: BlacklistedSiteService

    @Mock
    private lateinit var scopeService: SystemScopeService

    @Mock
    private lateinit var resourceSetService: ResourceSetService

    @Mock
    private lateinit var statsService: StatsService

    @Mock
    private lateinit var config: ConfigurationPropertiesBean

    @InjectMocks
    private lateinit var service: DefaultOAuth2ClientDetailsEntityService

    @BeforeEach
    fun prepare() {
        reset(clientRepository, tokenRepository, approvedSiteService, whitelistedSiteService, blacklistedSiteService, scopeService, statsService)

        whenever(clientRepository.saveClient(isA()))
            .thenAnswer { invocation ->
                val args = invocation.arguments
                args[0] as ClientDetailsEntity
            }

        whenever(clientRepository.updateClient(isA(), isA()))
            .thenAnswer { invocation ->
                val args = invocation.arguments
                args[1] as ClientDetailsEntity
            }

        whenever(scopeService.fromStrings(ArgumentMatchers.anySet())).thenAnswer { invocation ->
            val input = invocation.arguments[0] as Set<String>
            input.mapTo(HashSet()) { SystemScope(it) }
        }

        whenever(scopeService.toStrings(ArgumentMatchers.anySet())).thenAnswer { invocation ->
            val input = invocation.arguments[0] as Set<SystemScope>
            input.mapTo(HashSet()) { it.value }
        }

        // we're not testing reserved scopes here, just pass through when it's called
        whenever(scopeService.removeReservedScopes(ArgumentMatchers.anySet()))
            .then(AdditionalAnswers.returnsFirstArg<Any>())

        whenever(config.isHeartMode) doReturn (false)
    }

    /**
     * Failure case of existing client id.
     */
    @Test
    fun saveNewClient_badId() {
        // Set up a mock client.

        val client = mock<ClientDetailsEntity>()
        whenever(client.id) doReturn (12345L) // any non-null ID will work

        assertThrows<IllegalArgumentException> {
            service.saveNewClient(client)
        }
    }

    /**
     * Failure case of blacklisted client uri.
     */
    @Test
    fun saveNewClient_blacklisted() {
        val client = mock<ClientDetailsEntity>()
        whenever(client.id) doReturn (null)

        val badUri = "badplace.xxx"

        whenever(blacklistedSiteService.isBlacklisted(badUri)) doReturn (true)
        whenever(client.getRegisteredRedirectUri()) doReturn (hashSetOf(badUri))

        assertThrows<IllegalArgumentException> {
            service.saveNewClient(client)
        }
    }

    @Test
    fun saveNewClient_idWasAssigned() {
        // Set up a mock client.

        val client = mock<ClientDetailsEntity>()
        whenever(client.id) doReturn (null)

        service.saveNewClient(client)

        verify(client).setClientId(ArgumentMatchers.anyString())
    }

    /**
     * Makes sure client has offline access granted scope if allowed refresh tokens.
     */
    @Test
    fun saveNewClient_yesOfflineAccess() {
        val client = ClientDetailsEntity().apply {
            grantTypes = hashSetOf("refresh_token")
        }.let { service.saveNewClient(it) }

        assertTrue(SystemScopeService.OFFLINE_ACCESS in client.getScope())
    }

    /**
     * Makes sure client does not have offline access if not allowed to have refresh tokens.
     */
    @Test
    fun saveNewClient_noOfflineAccess() {

        val client = service.saveNewClient(ClientDetailsEntity())

        verify(scopeService, atLeastOnce()).removeReservedScopes(ArgumentMatchers.anySet())

        assertFalse(SystemScopeService.OFFLINE_ACCESS in client.getScope())
    }

    @Test
    fun loadClientByClientId_badId() {
        // empty id
        assertThrows<IllegalArgumentException> {
            service.loadClientByClientId("")
        }

        // id not found
        val clientId = "b00g3r"
        whenever(clientRepository.getClientByClientId(clientId)) doReturn (null)
        assertThrows<InvalidClientException> {
            service.loadClientByClientId(clientId)
        }
    }

    @Test
    fun deleteClient_badId() {
        val id = 12345L
        val client = mock<ClientDetailsEntity>()
        whenever(client.id) doReturn (id)
        whenever(clientRepository.getById(id)) doReturn (null)

        assertThrows<InvalidClientException> {
            service.deleteClient(client)
        }
    }

    @Test
    fun deleteClient() {
        val id = 12345L
        val clientId = "b00g3r"

        val client = mock<ClientDetailsEntity>()
        whenever(client.id) doReturn (id)
        whenever(client.getClientId()) doReturn (clientId)

        whenever(clientRepository.getById(id)) doReturn (client)

        val site = mock<WhitelistedSite>()
        whenever(whitelistedSiteService.getByClientId(clientId)) doReturn (site)

        whenever(resourceSetService.getAllForClient(client)) doReturn (HashSet())

        service.deleteClient(client)

        verify(tokenRepository).clearTokensForClient(client)
        verify(approvedSiteService).clearApprovedSitesForClient(client)
        verify(whitelistedSiteService).remove(site)
        verify(clientRepository).deleteClient(client)
    }

    @Test
    fun updateClient_blacklistedUri() {
        val oldClient = mock<ClientDetailsEntity>()
        val newClient = mock<ClientDetailsEntity>()

        val badSite = "badsite.xxx"

        whenever(newClient.getRegisteredRedirectUri()) doReturn (hashSetOf(badSite))
        whenever(blacklistedSiteService.isBlacklisted(badSite)) doReturn (true)

        assertThrows<IllegalArgumentException> {
            service.updateClient(oldClient, newClient)
        }
    }

    @Test
    fun updateClient_yesOfflineAccess() {
        val oldClient = ClientDetailsEntity()
        oldClient.id = 1L // Needs a hard-coded id as there is no jpa
        val grantTypes: MutableSet<String> = hashSetOf("refresh_token")
        var client: OAuthClientDetails = ClientDetailsEntity(grantTypes = grantTypes)

        client = service.updateClient(oldClient, client)

        verify(scopeService, atLeastOnce()).removeReservedScopes(ArgumentMatchers.anySet())

        assertTrue(SystemScopeService.OFFLINE_ACCESS in client.getScope())
    }

    @Test
    fun updateClient_noOfflineAccess() {
        val oldClient = ClientDetailsEntity()
        oldClient.id = 1L // Needs a hard-coded id as there is no jpa

        oldClient.getScope().add(SystemScopeService.OFFLINE_ACCESS)

        val client = service.updateClient(oldClient, ClientDetailsEntity())

        verify(scopeService, atLeastOnce()).removeReservedScopes(ArgumentMatchers.anySet())

        assertFalse(SystemScopeService.OFFLINE_ACCESS in client.getScope())
    }

    @Test
    fun heartMode_authcode_invalidGrants() {
        whenever(config.isHeartMode) doReturn true

        val client = ClientDetailsEntity().apply {
            grantTypes = hashSetOf(
                "authorization_code",
                "implicit",
                "client_credentials",
            )

            tokenEndpointAuthMethod = AuthMethod.PRIVATE_KEY

            redirectUris = hashSetOf("https://foo.bar/")

            jwksUri = "https://foo.bar/jwks"
        }


        assertThrows<IllegalArgumentException> {
            service.saveNewClient(client)
        }
    }

    @Test
    fun heartMode_implicit_invalidGrants() {
        whenever(config.isHeartMode) doReturn (true)

        val client = ClientDetailsEntity().apply {
            grantTypes = hashSetOf(
                "implicit",
                "authorization_code",
                "client_credentials",
            )

            tokenEndpointAuthMethod = AuthMethod.NONE

            redirectUris = hashSetOf("https://foo.bar/")

            jwksUri = "https://foo.bar/jwks"
        }

        assertThrows<IllegalArgumentException> {
            service.saveNewClient(client)
        }
    }

    @Test
    fun heartMode_clientcreds_invalidGrants() {
        whenever(config.isHeartMode) doReturn (true)

        val client = ClientDetailsEntity().apply {
            grantTypes = hashSetOf(
                "client_credentials",
                "authorization_code",
                "implicit",
            )

            tokenEndpointAuthMethod = AuthMethod.PRIVATE_KEY

            jwksUri = "https://foo.bar/jwks"
        }

        assertThrows<IllegalArgumentException> {
            service.saveNewClient(client)
        }
    }

    @Test
    fun heartMode_authcode_authMethod() {
        whenever(config.isHeartMode) doReturn (true)

        val client = ClientDetailsEntity().apply {
            grantTypes = hashSetOf("authorization_code")

            tokenEndpointAuthMethod = AuthMethod.SECRET_POST

            redirectUris = hashSetOf("https://foo.bar/")

            jwksUri = "https://foo.bar/jwks"
        }

        assertThrows<IllegalArgumentException> {
            service.saveNewClient(client)
        }
    }

    @Test
    fun heartMode_implicit_authMethod() {
        whenever(config.isHeartMode) doReturn (true)

        val client = ClientDetailsEntity().apply {
            grantTypes = mutableSetOf("implicit")

            tokenEndpointAuthMethod = AuthMethod.PRIVATE_KEY

            redirectUris = hashSetOf("https://foo.bar/")

            jwksUri = "https://foo.bar/jwks"
        }

        assertThrows<IllegalArgumentException> {
            service.saveNewClient(client)
        }
    }

    @Test
    fun heartMode_clientcreds_authMethod() {
        whenever(config.isHeartMode) doReturn (true)

        val client = ClientDetailsEntity().apply {
            grantTypes = hashSetOf("client_credentials")

            tokenEndpointAuthMethod = AuthMethod.SECRET_BASIC

            redirectUris = hashSetOf("https://foo.bar/")

            jwksUri = "https://foo.bar/jwks"
        }

        assertThrows<IllegalArgumentException> {
            service.saveNewClient(client)
        }
    }

    @Test
    fun heartMode_authcode_redirectUris() {
        whenever(config.isHeartMode) doReturn (true)

        val client = ClientDetailsEntity().apply {
            grantTypes = hashSetOf("authorization_code")

            tokenEndpointAuthMethod = AuthMethod.PRIVATE_KEY
        }

        assertThrows<IllegalArgumentException> {
            service.saveNewClient(client)
        }
    }

    @Test
    fun heartMode_implicit_redirectUris() {
        whenever(config.isHeartMode) doReturn (true)

        val client = ClientDetailsEntity().apply {
            grantTypes = mutableSetOf("implicit")

            tokenEndpointAuthMethod = AuthMethod.NONE
        }

        assertThrows<IllegalArgumentException> {
            service.saveNewClient(client)
        }
    }

    @Test
    fun heartMode_clientcreds_redirectUris() {
        whenever(config.isHeartMode) doReturn true

        val client = ClientDetailsEntity().apply {
            grantTypes = hashSetOf("client_credentials")

            tokenEndpointAuthMethod = AuthMethod.PRIVATE_KEY

            redirectUris = hashSetOf("http://foo.bar/")
        }

        assertThrows<IllegalArgumentException> {
            service.saveNewClient(client)
        }
    }

    @Test
    fun heartMode_clientSecret() {
        whenever(config.isHeartMode) doReturn (true)

        val client = ClientDetailsEntity()
        client.grantTypes = hashSetOf("authorization_code")

        client.tokenEndpointAuthMethod = AuthMethod.PRIVATE_KEY

        client.redirectUris = hashSetOf("http://foo.bar/")

        client.setClientSecret("secret!")

        assertThrows<IllegalArgumentException> {
            service.saveNewClient(client)
        }
    }

    @Test
    fun heartMode_noJwks() {
        whenever(config.isHeartMode) doReturn (true)

        val client = ClientDetailsEntity()
        val grantTypes: MutableSet<String> = hashSetOf("authorization_code")
        client.grantTypes = grantTypes

        client.tokenEndpointAuthMethod = AuthMethod.PRIVATE_KEY

        client.redirectUris = hashSetOf("https://foo.bar/")

        client.jwks = null
        client.jwksUri = null

        assertThrows<IllegalArgumentException> {
            service.saveNewClient(client)
        }
    }

    @Test
    fun heartMode_validAuthcodeClient() {
        whenever(config.isHeartMode) doReturn (true)

        val client = ClientDetailsEntity().apply {
            grantTypes = hashSetOf(
                "authorization_code",
                "refresh_token",
            )

            tokenEndpointAuthMethod = AuthMethod.PRIVATE_KEY

            redirectUris = hashSetOf("https://foo.bar/")

            jwksUri = "https://foo.bar/jwks"
        }

        service.saveNewClient(client)

        assertNotNull(client.getClientId())
        assertNull(client.getClientSecret())
    }

    @Test
    fun heartMode_nonLocalHttpRedirect() {
        whenever(config.isHeartMode) doReturn (true)

        val client = ClientDetailsEntity()
        val grantTypes: MutableSet<String> = LinkedHashSet()
        grantTypes.add("authorization_code")
        grantTypes.add("refresh_token")
        client.grantTypes = grantTypes

        client.tokenEndpointAuthMethod = AuthMethod.PRIVATE_KEY

        client.redirectUris = hashSetOf("http://foo.bar/")

        client.jwksUri = "https://foo.bar/jwks"

        assertThrows<IllegalArgumentException> {
            service.saveNewClient(client)
        }
    }

    @Test
    fun heartMode_multipleRedirectClass() {
        whenever(config.isHeartMode) doReturn (true)

        val client = ClientDetailsEntity()
        val grantTypes: MutableSet<String> = LinkedHashSet()
        grantTypes.add("authorization_code")
        grantTypes.add("refresh_token")
        client.grantTypes = grantTypes

        client.tokenEndpointAuthMethod = AuthMethod.PRIVATE_KEY

        client.redirectUris = hashSetOf("http://localhost/", "https://foo.bar", "foo://bar")

        client.jwksUri = "https://foo.bar/jwks"

        assertThrows<IllegalArgumentException> {
            service.saveNewClient(client)
        }
    }
}
