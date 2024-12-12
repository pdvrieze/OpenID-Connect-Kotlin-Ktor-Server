package org.mitre.oauth2.introspectingfilter.service.impl

import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.mitre.oauth2.introspectingfilter.IntrospectionResponse
import org.mitre.oauth2.model.GrantedAuthority
import org.mitre.oauth2.model.ScopeAuthority

/**
 * @author jricher
 */
class TestScopeBasedIntrospectionAuthoritiesGranter {
    private lateinit var introspectionResponse: IntrospectionResponse

    private val granter = ScopeBasedIntrospectionAuthoritiesGranter()

    /**
     * @throws java.lang.Exception
     */
    @BeforeEach
    @Throws(Exception::class)
    fun setUp() {
        introspectionResponse = IntrospectionResponse(false)
    }

    /**
     * Test method for [org.mitre.oauth2.introspectingfilter.service.impl.ScopeBasedIntrospectionAuthoritiesGranter.getAuthorities].
     */
    @Test
    fun testGetAuthoritiesJsonObject_withScopes() {
        introspectionResponse = IntrospectionResponse(false, scopeString = "foo bar baz batman")

        val expected = listOf(
            GrantedAuthority.ROLE_API,
            ScopeAuthority("foo"),
            ScopeAuthority("bar"),
            ScopeAuthority("baz"),
            ScopeAuthority("batman"),
        )

        val authorities = granter.getAuthorities(introspectionResponse)

        assertTrue(authorities.containsAll(expected))
        assertTrue(expected.containsAll(authorities))
    }

    /**
     * Test method for [org.mitre.oauth2.introspectingfilter.service.impl.ScopeBasedIntrospectionAuthoritiesGranter.getAuthorities].
     */
    @Test
    fun testGetAuthoritiesJsonObject_withoutScopes() {
        val expected = listOf(GrantedAuthority.ROLE_API)

        val authorities = granter.getAuthorities(introspectionResponse)

        assertTrue(authorities.containsAll(expected))
        assertTrue(expected.containsAll(authorities))
    }
}
