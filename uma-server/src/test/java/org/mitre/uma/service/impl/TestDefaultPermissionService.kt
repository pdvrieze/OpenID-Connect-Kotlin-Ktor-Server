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

import org.hamcrest.CoreMatchers
import org.hamcrest.MatcherAssert.assertThat
import org.junit.Before
import org.junit.Test
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.runner.RunWith
import org.mitre.oauth2.service.SystemScopeService
import org.mitre.uma.model.PermissionTicket
import org.mitre.uma.model.ResourceSet
import org.mitre.uma.repository.PermissionRepository
import org.mockito.AdditionalAnswers.returnsFirstArg
import org.mockito.ArgumentMatchers.anySet
import org.mockito.InjectMocks
import org.mockito.Mock
import org.mockito.junit.MockitoJUnitRunner
import org.mockito.kotlin.isA
import org.mockito.kotlin.whenever
import org.springframework.security.oauth2.common.exceptions.InsufficientScopeException
import java.util.*

/**
 * @author jricher
 */
@RunWith(MockitoJUnitRunner::class)
class TestDefaultPermissionService {
    @Mock
    private lateinit var permissionRepository: PermissionRepository

    @Mock
    private lateinit var scopeService: SystemScopeService

    @InjectMocks
    private lateinit var permissionService: DefaultPermissionService

    private val scopes1: Set<String> = setOf("foo", "bar", "baz")
    private val scopes2: Set<String> = setOf("alpha", "beta", "betest")

    private lateinit var rs1: ResourceSet
    private lateinit var rs2: ResourceSet

    private val rs1Name = "resource set 1"
    private val rs1Owner = "resource set owner 1"
    private val rs1Id = 1L

    private val rs2Name = "resource set 2"
    private val rs2Owner = "resource set owner 2"
    private val rs2Id = 2L


    @Before
    fun prepare() {
        rs1 = ResourceSet()
        rs1.name = rs1Name
        rs1.owner = rs1Owner
        rs1.id = rs1Id
        rs1.scopes = scopes1

        rs2 = ResourceSet()
        rs2.name = rs2Name
        rs2.owner = rs2Owner
        rs2.id = rs2Id
        rs2.scopes = scopes2

        // have the repository just pass the argument through
        whenever(permissionRepository.save(isA<PermissionTicket>()))
            .then(returnsFirstArg<Any>())

        whenever(scopeService.scopesMatch(anySet(), anySet()))
            .then { invocation ->
                val arguments = invocation.arguments
                val expected = arguments[0] as Set<String>
                val actual = arguments[1] as Set<String>
                expected.containsAll(actual)
            }
    }


    /**
     * Test method for [org.mitre.uma.service.PermissionService.createTicket].
     */
    @Test
    fun testCreate_ticket() {
        val perm = permissionService.createTicket(rs1, scopes1)!!

        // we want there to be a non-null ticket
        assertNotNull(perm.ticket)
    }

    @Test
    fun testCreate_uuid() {
        val perm = permissionService.createTicket(rs1, scopes1)!!

        // we expect this to be a UUID
        val uuid = UUID.fromString(perm.ticket)

        assertNotNull(uuid)
    }

    @Test
    fun testCreate_differentTicketsSameClient() {
        val perm1 = permissionService.createTicket(rs1, scopes1)!!
        val perm2 = permissionService.createTicket(rs1, scopes1)!!

        assertNotNull(perm1.ticket)
        assertNotNull(perm2.ticket)

        // make sure these are different from each other
        assertThat(perm1.ticket, CoreMatchers.not(CoreMatchers.equalTo(perm2.ticket)))
    }

    @Test
    fun testCreate_differentTicketsDifferentClient() {
        val perm1 = permissionService.createTicket(rs1, scopes1)!!
        val perm2 = permissionService.createTicket(rs2, scopes2)!!

        assertNotNull(perm1.ticket)
        assertNotNull(perm2.ticket)

        // make sure these are different from each other
        assertThat(perm1.ticket, CoreMatchers.not(CoreMatchers.equalTo(perm2.ticket)))
    }

    @Test(expected = InsufficientScopeException::class)
    fun testCreate_scopeMismatch() {
        // try to get scopes outside of what we're allowed to do, this should throw an exception
        permissionService.createTicket(rs1, scopes2)
    }
}
