package org.mitre.uma.service.impl.ktor

import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.junit.jupiter.api.extension.ExtendWith
import org.mitre.oauth2.exception.InsufficientScopeException
import org.mitre.uma.model.PermissionTicket
import org.mitre.uma.model.ResourceSet
import org.mitre.uma.service.impl.DefaultPermissionService
import org.mockito.AdditionalAnswers
import org.mockito.ArgumentMatchers
import org.mockito.Mock
import org.mockito.junit.jupiter.MockitoExtension
import org.mockito.kotlin.isA
import org.mockito.kotlin.whenever
import java.util.*

/**
 * @author jricher
 */
@ExtendWith(MockitoExtension::class)
class TestKtorDefaultPermissionService {
    @Mock
    private lateinit var permissionRepository: org.mitre.uma.repository.PermissionRepository

    @Mock
    private lateinit var scopeService: org.mitre.oauth2.service.SystemScopeService

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
        permissionService = DefaultPermissionService(permissionRepository, scopeService)

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
            .then(AdditionalAnswers.returnsFirstArg<Any>())

        whenever(scopeService.scopesMatch(ArgumentMatchers.anySet(), ArgumentMatchers.anySet()))
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
        Assertions.assertNotNull(perm.ticket)
    }

    @Test
    fun testCreate_uuid() {
        mocks()

        val perm = permissionService.createTicket(rs1, scopes1)!!

        // we expect this to be a UUID
        val uuid = UUID.fromString(perm.ticket)

        Assertions.assertNotNull(uuid)
    }

    @Test
    fun testCreate_differentTicketsSameClient() {
        mocks()

        val perm1 = permissionService.createTicket(rs1, scopes1)!!
        val perm2 = permissionService.createTicket(rs1, scopes1)!!

        Assertions.assertNotNull(perm1.ticket)
        Assertions.assertNotNull(perm2.ticket)

        // make sure these are different from each other
        Assertions.assertNotEquals(perm2.ticket, perm1.ticket)
    }

    @Test
    fun testCreate_differentTicketsDifferentClient() {
        mocks()

        val perm1 = permissionService.createTicket(rs1, scopes1)!!
        val perm2 = permissionService.createTicket(rs2, scopes2)!!

        Assertions.assertNotNull(perm1.ticket)
        Assertions.assertNotNull(perm2.ticket)

        // make sure these are different from each other
        Assertions.assertNotEquals(perm2.ticket, perm1.ticket)
    }

    @Test
    fun testCreate_scopeMismatch() {
        // have the repository just pass the argument through
        whenever(scopeService.scopesMatch(ArgumentMatchers.anySet(), ArgumentMatchers.anySet()))
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
