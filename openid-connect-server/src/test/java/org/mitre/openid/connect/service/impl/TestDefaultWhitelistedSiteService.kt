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

import org.hamcrest.CoreMatchers
import org.junit.Assert
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.mitre.openid.connect.model.WhitelistedSite
import org.mitre.openid.connect.repository.WhitelistedSiteRepository
import org.mockito.InjectMocks
import org.mockito.Mock
import org.mockito.Mockito
import org.mockito.Mockito.mock
import org.mockito.junit.MockitoJUnitRunner
import org.mockito.kotlin.verify
import org.mockito.kotlin.whenever

/**
 * @author wkim
 */
@RunWith(MockitoJUnitRunner::class)
class TestDefaultWhitelistedSiteService {
    @Mock
    private lateinit var repository: WhitelistedSiteRepository

    @InjectMocks
    private lateinit var service: DefaultWhitelistedSiteService

    @Before
    fun prepare() {
        Mockito.reset(repository)
    }

    @Test(expected = IllegalArgumentException::class)
    fun saveNew_notNullId() {
        val site = mock<WhitelistedSite>()
        whenever(site.id).thenReturn(12345L) // arbitrary long value

        service.saveNew(site)
    }

    @Test
    fun saveNew_success() {
        val site = mock<WhitelistedSite>()
        whenever(site.id).thenReturn(null)

        service.saveNew(site)

        verify(repository).save(site)
    }

    @Test
    fun update_nullSites() {
        val oldSite = mock<WhitelistedSite>()
        val newSite = mock<WhitelistedSite>()

        // old client null
        try {
            service.update(null as WhitelistedSite, newSite)
            Assert.fail("Old site input is null. Expected a IllegalArgumentException.")
        } catch (e: NullPointerException) {
            Assert.assertThat<RuntimeException>(e, CoreMatchers.`is`(CoreMatchers.notNullValue()))
        } catch (e: IllegalArgumentException) {
            Assert.assertThat<RuntimeException>(e, CoreMatchers.`is`(CoreMatchers.notNullValue()))
        }

        // new client null
        try {
            service.update(oldSite, null as WhitelistedSite)
            Assert.fail("New site input is null. Expected a IllegalArgumentException.")
        } catch (e: NullPointerException) {
            Assert.assertThat<RuntimeException>(e, CoreMatchers.`is`(CoreMatchers.notNullValue()))
        } catch (e: IllegalArgumentException) {
            Assert.assertThat<RuntimeException>(e, CoreMatchers.`is`(CoreMatchers.notNullValue()))
        }

        // both clients null
        try {
            service.update(null as WhitelistedSite, null as WhitelistedSite)
            Assert.fail("Both site inputs are null. Expected a IllegalArgumentException.")
        } catch (e: NullPointerException) {
            Assert.assertThat<RuntimeException>(e, CoreMatchers.`is`(CoreMatchers.notNullValue()))
        } catch (e: IllegalArgumentException) {
            Assert.assertThat<RuntimeException>(e, CoreMatchers.`is`(CoreMatchers.notNullValue()))
        }
    }

    @Test
    fun update_success() {
        val oldSite = mock<WhitelistedSite>()
        val newSite = mock<WhitelistedSite>()

        service.update(oldSite, newSite)

        Mockito.verify(repository).update(oldSite, newSite)
    }
}
