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

import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.mitre.uma.model.ResourceSet
import org.mitre.uma.repository.ResourceSetRepository
import org.mockito.InjectMocks
import org.mockito.Mock
import org.mockito.junit.MockitoJUnitRunner

/**
 * @author jricher
 */
@RunWith(MockitoJUnitRunner::class)
class TestDefaultResourceSetService {
    @Mock
    private lateinit var repository: ResourceSetRepository

    @InjectMocks
    private lateinit var resourceSetService: DefaultResourceSetService

    /**
     * @throws java.lang.Exception
     */
    @Before
    @Throws(Exception::class)
    fun setUp() {
        // unused by mockito (causs unnecessary stubbing exception
//		when(repository.save(any(ResourceSet.class))).then(AdditionalAnswers.returnsFirstArg());
    }

    /**
     * Test method for [ResourceSetService.saveNew].
     */
    @Test(expected = IllegalArgumentException::class)
    fun testSaveNew_hasId() {
        val rs = ResourceSet()
        rs.id = 1L

        resourceSetService.saveNew(rs)
    }

    @Test(expected = IllegalArgumentException::class)
    fun testUpdate_nullId() {
        val rs = ResourceSet().apply { id = 1L }

        val rs2 = ResourceSet()

        resourceSetService.update(rs, rs2)
    }

    @Test(expected = IllegalArgumentException::class)
    fun testUpdate_nullId2() {
        val rs = ResourceSet()

        val rs2 = ResourceSet().apply { id = 1L }

        resourceSetService.update(rs, rs2)
    }

    @Test(expected = IllegalArgumentException::class)
    fun testUpdate_mismatchedIds() {
        val rs = ResourceSet().apply { id = 1L }

        val rs2 = ResourceSet().apply { id = 2L }

        resourceSetService.update(rs, rs2)
    }
}
