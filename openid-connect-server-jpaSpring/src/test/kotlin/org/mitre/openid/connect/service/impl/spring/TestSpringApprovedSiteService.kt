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
package org.mitre.openid.connect.service.impl.spring

import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.extension.ExtendWith
import org.mitre.oauth2.model.ClientDetailsEntity
import org.mitre.oauth2.model.OAuthClientDetails
import org.mitre.oauth2.repository.OAuth2TokenRepository
import org.mitre.openid.connect.model.ApprovedSite
import org.mitre.openid.connect.repository.ApprovedSiteRepository
import org.mitre.openid.connect.service.ApprovedSiteService
import org.mitre.openid.connect.service.StatsService
import org.mockito.InjectMocks
import org.mockito.Mock
import org.mockito.junit.jupiter.MockitoExtension
import org.mockito.kotlin.isA
import org.mockito.kotlin.never
import org.mockito.kotlin.reset
import org.mockito.kotlin.times
import org.mockito.kotlin.verify
import org.mockito.kotlin.whenever
import org.springframework.test.annotation.Rollback

@ExtendWith(MockitoExtension::class)
class TestSpringApprovedSiteService {
    private lateinit var site1: ApprovedSite
    private lateinit var site2: ApprovedSite
    private lateinit var site3: ApprovedSite

    private lateinit var client: OAuthClientDetails

    @Mock
    private lateinit var repository: ApprovedSiteRepository

    @Mock
    private lateinit var tokenRepository: OAuth2TokenRepository

    @Mock
    private lateinit var statsService: StatsService

    @InjectMocks
    private val service: ApprovedSiteService = SpringApprovedSiteService()


    /**
     * Initialize the service and repository mock. Initialize a client and
     * several ApprovedSite objects for use in unit tests.
     */
    @BeforeEach
    fun prepare() {
        client = ClientDetailsEntity.Builder(clientId = clientId).build()

        site1 = ApprovedSite(
            id = 1L,
            userId = "user1",
            clientId = "other",
        )

        site2 = ApprovedSite(
            id = 2L,
            userId = "user1",
            clientId = clientId,
        )

        site3 = ApprovedSite(
            id = 3L,
            userId = "user2",
            clientId = clientId,
        )

        reset(repository, statsService)
    }

    /**
     * Test clearing approved sites for a client that has 2 stored approved sites.
     * Ensure that the repository's remove() method is called twice.
     */
    @Test
    fun clearApprovedSitesForClient_success() {
        whenever(repository.getByClientId(client.clientId!!))
            .thenReturn(setOf(site2, site3))

        whenever(tokenRepository.getAccessTokensForApprovedSite(isA<ApprovedSite>()))
            .thenReturn(emptyList())

        service.clearApprovedSitesForClient(client)

        verify(repository, times(2)).remove(isA<ApprovedSite>())
    }

    /**
     * Test clearing approved sites for a client that doesn't have any stored approved
     * sites. Ensure that the repository's remove() method is never called in this case.
     */
    @Test
    @Rollback
    fun clearApprovedSitesForClient_null() {
        val otherId = "a different id"
        (client as ClientDetailsEntity).setClientId(otherId)
        service.clearApprovedSitesForClient(client)
        // unused by mockito (causs unnecessary stubbing exception
//		whenever(repository.getByClientId(otherId)).thenReturn(new HashSet<ApprovedSite>());
        verify(repository, never()).remove(isA<ApprovedSite>())
    }

    companion object {
        private val clientId = "client"
    }
}
