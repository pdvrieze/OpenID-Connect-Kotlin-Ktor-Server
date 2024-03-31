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

import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.junit.jupiter.api.extension.ExtendWith
import org.mitre.openid.connect.model.WhitelistedSite
import org.mitre.openid.connect.repository.WhitelistedSiteRepository
import org.mockito.InjectMocks
import org.mockito.Mock
import org.mockito.junit.jupiter.MockitoExtension
import org.mockito.kotlin.mock
import org.mockito.kotlin.reset
import org.mockito.kotlin.verify
import org.mockito.kotlin.whenever

/**
 * @author wkim
 */
@ExtendWith(MockitoExtension::class)
class TestDefaultWhitelistedSiteService {
    @Mock
    private lateinit var repository: WhitelistedSiteRepository

    @InjectMocks
    private lateinit var service: DefaultWhitelistedSiteService

    @BeforeEach
    fun prepare() {
        reset(repository)
    }

    @Test
    fun saveNew_notNullId() {
        val site = mock<WhitelistedSite>()
        whenever(site.id).thenReturn(12345L) // arbitrary long value

        assertThrows<IllegalArgumentException> {
            service.saveNew(site)
        }
    }

    @Test
    fun saveNew_success() {
        val site = mock<WhitelistedSite>()
        whenever(site.id).thenReturn(null)

        service.saveNew(site)

        verify(repository).save(site)
    }

    @Test
    fun update_success() {
        val oldSite = mock<WhitelistedSite>()
        val newSite = mock<WhitelistedSite>()

        service.update(oldSite, newSite)

        verify(repository).update(oldSite, newSite)
    }
}
