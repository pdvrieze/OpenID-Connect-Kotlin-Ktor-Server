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

import org.junit.jupiter.api.Assertions.assertNotEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.junit.jupiter.api.extension.ExtendWith
import org.mitre.uma.model.PermissionTicket
import org.mitre.uma.model.ResourceSet
import org.mockito.AdditionalAnswers.returnsFirstArg
import org.mockito.ArgumentMatchers.anySet
import org.mockito.InjectMocks
import org.mockito.Mock
import org.mockito.junit.jupiter.MockitoExtension
import org.mockito.kotlin.isA
import org.mockito.kotlin.whenever
import org.springframework.security.oauth2.common.exceptions.InsufficientScopeException
import java.util.*

/**
 * @author jricher
 */
@ExtendWith(MockitoExtension::class)
class TestDefaultPermissionService {
    @Mock
    private lateinit var permissionRepository: org.mitre.uma.repository.PermissionRepository

    @Mock
    private lateinit var scopeService: org.mitre.oauth2.service.SystemScopeService

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


    @BeforeEach
    fun prepare() {
        rs1 = ResourceSet(
            name = rs1Name,
            owner = rs1Owner,
            id = rs1Id,
            scopes = scopes1,
        )

        rs2 = ResourceSet(
            name = rs2Name,
            owner = rs2Owner,
            id = rs2Id,
            scopes = scopes2,
        )
    }

    private fun mocks() {
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
        mocks()

        val perm = permissionService.createTicket(rs1, scopes1)!!

        // we want there to be a non-null ticket
        assertNotNull(perm.ticket)
    }

    @Test
    fun testCreate_uuid() {
        mocks()

        val perm = permissionService.createTicket(rs1, scopes1)!!

        // we expect this to be a UUID
        val uuid = UUID.fromString(perm.ticket)

        assertNotNull(uuid)
    }

    @Test
    fun testCreate_differentTicketsSameClient() {
        mocks()

        val perm1 = permissionService.createTicket(rs1, scopes1)!!
        val perm2 = permissionService.createTicket(rs1, scopes1)!!

        assertNotNull(perm1.ticket)
        assertNotNull(perm2.ticket)

        // make sure these are different from each other
        assertNotEquals(perm2.ticket, perm1.ticket)
    }

    @Test
    fun testCreate_differentTicketsDifferentClient() {
        mocks()

        val perm1 = permissionService.createTicket(rs1, scopes1)!!
        val perm2 = permissionService.createTicket(rs2, scopes2)!!

        assertNotNull(perm1.ticket)
        assertNotNull(perm2.ticket)

        // make sure these are different from each other
        assertNotEquals(perm2.ticket, perm1.ticket)
    }

    @Test
    fun testCreate_scopeMismatch() {
        // have the repository just pass the argument through
        whenever(scopeService.scopesMatch(anySet(), anySet()))
            .then { invocation ->
                val arguments = invocation.arguments
                val expected = arguments[0] as Set<String>
                val actual = arguments[1] as Set<String>
                expected.containsAll(actual)
            }

        // try to get scopes outside of what we're allowed to do, this should throw an exception
        assertThrows<InsufficientScopeException> {
            permissionService.createTicket(rs1, scopes2)
        }
    }
}
