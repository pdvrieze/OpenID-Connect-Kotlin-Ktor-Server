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
package org.mitre.uma.service.impl

import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.junit.jupiter.api.extension.ExtendWith
import org.mitre.oauth2.repository.OAuth2TokenRepository
import org.mitre.uma.model.ResourceSet
import org.mitre.uma.repository.PermissionRepository
import org.mitre.uma.repository.ResourceSetRepository
import org.mockito.InjectMocks
import org.mockito.Mock
import org.mockito.junit.jupiter.MockitoExtension

/**
 * @author jricher
 */
@ExtendWith(MockitoExtension::class)
class TestDefaultResourceSetService {
    @Mock
    private lateinit var repository: ResourceSetRepository

    @Mock
    private lateinit var tokenRepository: OAuth2TokenRepository

    @Mock
    private lateinit var ticketRepository: PermissionRepository

    @InjectMocks
    private lateinit var resourceSetService: DefaultResourceSetService

    /**
     * @throws java.lang.Exception
     */
    @BeforeEach
    @Throws(Exception::class)
    fun setUp() {
        // unused by mockito (causs unnecessary stubbing exception
//		when(repository.save(any(ResourceSet.class))).then(AdditionalAnswers.returnsFirstArg());
    }

    /**
     * Test method for [ResourceSetService.saveNew].
     */
    @Test
    fun testSaveNew_hasId() {
        val rs = ResourceSet(id = 1L, name = "testSet")
        rs.id = 1L

        assertThrows<IllegalArgumentException> {
            resourceSetService.saveNew(rs)
        }
    }

    @Test
    fun testUpdate_nullId() {
        val rs = ResourceSet(id = 1L, name = "testSet")

        val rs2 = ResourceSet(name = "testSet2")

        assertThrows<IllegalArgumentException> {
            resourceSetService.update(rs, rs2)
        }
    }

    @Test
    fun testUpdate_nullId2() {
        val rs = ResourceSet(name = "rs1")

        val rs2 = ResourceSet(id = 1L, name="rs2")

        assertThrows<IllegalArgumentException> {
            resourceSetService.update(rs, rs2)
        }
    }

    @Test
    fun testUpdate_mismatchedIds() {
        val rs = ResourceSet(id = 1L, name = "testSet")

        val rs2 = ResourceSet(id = 2L, name = "testSet2")

        assertThrows<IllegalArgumentException> {
            resourceSetService.update(rs, rs2)
        }
    }
}
