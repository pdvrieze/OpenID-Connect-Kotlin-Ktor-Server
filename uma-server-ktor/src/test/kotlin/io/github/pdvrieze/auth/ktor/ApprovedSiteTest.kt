package io.github.pdvrieze.auth.ktor

import io.github.pdvrieze.auth.repository.exposed.ApprovedSiteScopes
import io.github.pdvrieze.auth.repository.exposed.ApprovedSites
import io.github.pdvrieze.auth.repository.exposed.ClientClaimsRedirectUris
import io.github.pdvrieze.auth.repository.exposed.ClientDetails
import io.github.pdvrieze.auth.repository.exposed.ClientGrantTypes
import io.github.pdvrieze.auth.repository.exposed.ClientRedirectUris
import io.github.pdvrieze.auth.repository.exposed.ClientScopes
import io.ktor.client.statement.*
import org.jetbrains.exposed.sql.Table
import org.jetbrains.exposed.sql.batchInsert
import org.jetbrains.exposed.sql.insert
import org.jetbrains.exposed.sql.transactions.transaction
import org.mitre.oauth2.model.ClientDetailsEntity
import org.mitre.openid.connect.model.ApprovedSite
import org.mitre.openid.connect.web.ApprovedSiteAPI
import org.mitre.util.oidJson
import java.time.Instant
import java.time.temporal.ChronoUnit
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class ApprovedSiteTest : ApiTest(ApprovedSiteAPI) {
    var site1Id: Long = -1L
    var site2Id: Long = -1L

    lateinit var client2Id: String

    override val deletableTables: List<Table>
        get() = listOf(
            ApprovedSiteScopes, ApprovedSites,
            ClientGrantTypes, ClientClaimsRedirectUris, ClientRedirectUris, ClientScopes, ClientDetails,
        )

    override fun setUp() {
        super.setUp()
        val n = Instant.now()

        transaction(testContext.database) {

            site1Id = ApprovedSites.insert { s ->
                s[userId] = "user"
                s[clientId] = this@ApprovedSiteTest.clientId
                s[creationDate] = n
                s[this.timeoutDate] = n.plus(1L, ChronoUnit.HOURS)
            }.get(ApprovedSites.id).value
            ApprovedSiteScopes.batchInsert(listOf("scope1", "scope2")) { scope ->
                this[ApprovedSiteScopes.scope] = scope
                this[ApprovedSiteScopes.ownerId] = site1Id
            }

            val client2builder = ClientDetailsEntity.Builder(
                clientId = "client2",
                scope = mutableSetOf("scope3", "scope4", "offline_access"),
            )
            val client2 = testContext.clientDetailsService.saveNewClient(client2builder)
            client2Id = client2.clientId

            site2Id = ApprovedSites.insert { s ->
                s[userId] = "user"
                s[clientId] = client2.clientId
                s[creationDate] = n
                s[this.timeoutDate] = n.plus(1L, ChronoUnit.HOURS)
            }.get(ApprovedSites.id).value
            ApprovedSiteScopes.batchInsert(listOf("scope3", "scope4")) { scope ->
                this[ApprovedSiteScopes.scope] = scope
                this[ApprovedSiteScopes.ownerId] = site2Id
            }
        }
    }

    @Test
    fun testGetAllSites() {
        testEndpoint {
            val approvedSites: List<ApprovedSite.SerialDelegate> = oidJson.decodeFromString(getUser("/api/approved").bodyAsText())

            assertEquals(2, approvedSites.size)
            val site1 = approvedSites.single { it.clientId == clientId }
            val site2 = approvedSites.single { it.clientId == client2Id }

            assertEquals("user", site1.userId)
            assertEquals(site1Id, site1.currentId)
            assertNotNull(site1.creationDate)
            assertNotNull(site1.timeoutDate)
            val n = Instant.now()
            assertTrue(n.isAfter(site1.creationDate))
            assertTrue(n.isBefore(site1.timeoutDate))
            assertEquals(setOf("scope1", "scope2"), site1.allowedScopes)

            assertEquals("user", site2.userId)
            assertEquals(site2Id, site2.currentId)
            assertNotNull(site2.creationDate)
            assertNotNull(site2.timeoutDate)
            assertTrue(n.isAfter(site2.creationDate))
            assertTrue(n.isBefore(site2.timeoutDate))
            assertEquals(setOf("scope3", "scope4"), site2.allowedScopes)
        }
    }

    @Test
    fun testGetSite1() {
        testEndpoint {
            val site1: ApprovedSite.SerialDelegate = oidJson.decodeFromString(getUser("/api/approved/$site1Id").bodyAsText())

            assertEquals(clientId, site1.clientId)

            assertEquals("user", site1.userId)
            assertEquals(site1Id, site1.currentId)
            assertNotNull(site1.creationDate)
            assertNotNull(site1.timeoutDate)
            val n = Instant.now()
            assertTrue(n.isAfter(site1.creationDate))
            assertTrue(n.isBefore(site1.timeoutDate))
            assertEquals(setOf("scope1", "scope2"), site1.allowedScopes)
        }
    }

    @Test
    fun testGetSite2() {
        testEndpoint {
            val site2: ApprovedSite.SerialDelegate = oidJson.decodeFromString(getUser("/api/approved/$site2Id").bodyAsText())

            assertEquals(client2Id, site2.clientId)

            assertEquals("user", site2.userId)
            assertEquals(site2Id, site2.currentId)
            assertNotNull(site2.creationDate)
            assertNotNull(site2.timeoutDate)
            val n = Instant.now()
            assertTrue(n.isAfter(site2.creationDate))
            assertTrue(n.isBefore(site2.timeoutDate))
            assertEquals(setOf("scope3", "scope4"), site2.allowedScopes)
        }
    }

    @Test
    fun testDeleteSite2() {
        testEndpoint {
            assertEquals(2, testContext.approvedSiteService.all.size)

            val r = deleteUser("/api/approved/$site2Id")
            assertEquals(1, testContext.approvedSiteService.all.size)
        }
    }

}
