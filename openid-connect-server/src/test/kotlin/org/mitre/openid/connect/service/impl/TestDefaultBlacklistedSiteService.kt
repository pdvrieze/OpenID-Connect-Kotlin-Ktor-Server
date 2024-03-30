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
package org.mitre.openid.connect.service.impl

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.mitre.openid.connect.model.BlacklistedSite
import org.mitre.openid.connect.repository.BlacklistedSiteRepository
import org.mockito.InjectMocks
import org.mockito.Mock
import org.mockito.junit.MockitoJUnitRunner
import org.mockito.kotlin.times
import org.mockito.kotlin.verify
import org.mockito.kotlin.whenever

/**
 * @author wkim
 */
@RunWith(MockitoJUnitRunner::class)
class TestDefaultBlacklistedSiteService {
    private lateinit var site1: BlacklistedSite
    private lateinit var site2: BlacklistedSite

    private lateinit var blackListedSitesSet: Set<BlacklistedSite>

    @Mock
    private lateinit var mockRepository: BlacklistedSiteRepository

    @InjectMocks
    private val service = DefaultBlacklistedSiteService()

    /**
     * @throws java.lang.Exception
     */
    @Before
    @Throws(Exception::class)
    fun prepare() {
        site1 = BlacklistedSite().apply { uri = uri1 }
        site2 = BlacklistedSite().apply { uri = uri2 }

        blackListedSitesSet = setOf(site1, site2)
    }

    @Test
    fun isBlacklisted_yes(): Unit {
        whenever(mockRepository.all).thenReturn(blackListedSitesSet)

        assertTrue(service.isBlacklisted(uri1))
        assertTrue(service.isBlacklisted(uri2))

        verify(mockRepository, times(2)).all
    }

    @Test
    fun isBlacklisted_no(): Unit {
        whenever(mockRepository.all).thenReturn(blackListedSitesSet)

        assertFalse(service.isBlacklisted(uri3))

        verify(mockRepository).all
    }

    companion object {
        private val uri1 = "black1"
        private val uri2 = "black2"
        private val uri3 = "not-black"
    }
}
