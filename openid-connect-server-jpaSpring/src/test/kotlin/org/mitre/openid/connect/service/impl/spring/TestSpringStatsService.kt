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

import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.extension.ExtendWith
import org.mitre.oauth2.model.ClientDetailsEntity
import org.mitre.openid.connect.model.ApprovedSite
import org.mitre.openid.connect.service.ApprovedSiteService
import org.mockito.InjectMocks
import org.mockito.Mock
import org.mockito.junit.jupiter.MockitoExtension
import org.mockito.junit.jupiter.MockitoSettings
import org.mockito.kotlin.mock
import org.mockito.kotlin.reset
import org.mockito.kotlin.whenever
import org.mockito.quality.Strictness

/**
 * @author wkim
 */
@ExtendWith(MockitoExtension::class)
@MockitoSettings(strictness = Strictness.WARN)
class TestSpringStatsService {

    private val ap1: ApprovedSite = mock()
    private val ap2: ApprovedSite = mock()
    private val ap3: ApprovedSite = mock()
    private val ap4: ApprovedSite = mock()
    private val ap5: ApprovedSite = mock()
    private val ap6: ApprovedSite = mock()

    private val client1: ClientDetailsEntity = mock()
    private val client2: ClientDetailsEntity = mock()
    private val client3: ClientDetailsEntity = mock()
    private val client4: ClientDetailsEntity = mock()

    @Mock
    private lateinit var approvedSiteService: ApprovedSiteService

    @InjectMocks
    private val service = SpringStatsService()

    /**
     * Prepares a collection of ApprovedSite mocks to be returned from the approvedSiteService
     * and a collection of ClientDetailEntity mocks to be returned from the clientService.
     */
    @BeforeEach
    fun prepare() {
        reset(approvedSiteService)

        whenever(ap1.userId).thenReturn(userId1)
        whenever(ap1.clientId).thenReturn(clientId1)

        whenever(ap2.userId).thenReturn(userId1)
        whenever(ap2.clientId).thenReturn(clientId1)

        whenever(ap3.userId).thenReturn(userId2)
        whenever(ap3.clientId).thenReturn(clientId2)

        whenever(ap4.userId).thenReturn(userId2)
        whenever(ap4.clientId).thenReturn(clientId3)

        whenever(ap5.userId).thenReturn(userId2)
        whenever(ap5.clientId).thenReturn(clientId1)

        whenever(ap6.userId).thenReturn(userId1)
        whenever(ap6.clientId).thenReturn(clientId4)

        whenever(approvedSiteService.all).thenReturn(setOf(ap1, ap2, ap3, ap4))

        // unused by mockito (causs unnecessary stubbing exception
//		whenever(client1.getId()).thenReturn(1L);
//		whenever(client2.getId()).thenReturn(2L);
//		whenever(client3.getId()).thenReturn(3L);
//		whenever(client4.getId()).thenReturn(4L);
        whenever(approvedSiteService.getByClientId(clientId1)).thenReturn(setOf(ap1, ap2))
        whenever(approvedSiteService.getByClientId(clientId2)).thenReturn(setOf(ap3))
        whenever(approvedSiteService.getByClientId(clientId3)).thenReturn(setOf(ap4))
        whenever(approvedSiteService.getByClientId(clientId4)).thenReturn(emptySet())
    }

    @Test
    fun calculateSummaryStats_empty() {
        whenever(approvedSiteService.all).thenReturn(HashSet())

        val stats = service.summaryStats

        Assertions.assertEquals(0, stats["approvalCount"])
        Assertions.assertEquals(0, stats["userCount"])
        Assertions.assertEquals(0, stats["clientCount"])
    }

    @Test
    fun calculateSummaryStats() {
        val stats = service.summaryStats

        Assertions.assertEquals(4, stats["approvalCount"])
        Assertions.assertEquals(2, stats["userCount"])
        Assertions.assertEquals(3, stats["clientCount"])
    }

    @Test
    fun countForClientId() {
        // stats for ap1..ap4
        Assertions.assertEquals(2, service.getCountForClientId(clientId1)!!.approvedSiteCount)
        Assertions.assertEquals(1, service.getCountForClientId(clientId2)!!.approvedSiteCount)
        Assertions.assertEquals(1, service.getCountForClientId(clientId3)!!.approvedSiteCount)
        Assertions.assertEquals(0, service.getCountForClientId(clientId4)!!.approvedSiteCount)
    }

    @Test
    fun cacheAndReset() {
        val stats = service.summaryStats

        Assertions.assertEquals(4, stats["approvalCount"])
        Assertions.assertEquals(2, stats["userCount"])
        Assertions.assertEquals(3, stats["clientCount"])

        whenever(approvedSiteService.all).thenReturn(setOf(ap1, ap2, ap3, ap4, ap5, ap6))

        val stats2 = service.summaryStats

        // cache should remain the same due to memoized functions
        Assertions.assertEquals(4, stats2["approvalCount"])
        Assertions.assertEquals(2, stats2["userCount"])
        Assertions.assertEquals(3, stats2["clientCount"])

        // reset the cache and make sure the count goes up
        service.resetCache()

        val stats3 = service.summaryStats

        Assertions.assertEquals(6, stats3["approvalCount"])
        Assertions.assertEquals(2, stats3["userCount"])
        Assertions.assertEquals(4, stats3["clientCount"])
    }

    companion object {
        // Test fixtures:
        // Currently tests 4 approved sites with a total of 2 users and 3 clients for those sites.
        // There is an extra client in the system to make sure the stats only count for approved sites.
        private val userId1 = "batman"
        private val userId2 = "alfred"
        private val clientId1 = "bar"
        private val clientId2 = "pawnshop"
        private val clientId3 = "pizzastore"
        private val clientId4 = "gasstation"
    }
}
