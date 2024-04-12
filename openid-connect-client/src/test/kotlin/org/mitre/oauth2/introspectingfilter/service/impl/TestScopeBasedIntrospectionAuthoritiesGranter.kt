package org.mitre.oauth2.introspectingfilter.service.impl

import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.authority.SimpleGrantedAuthority

/**
 * @author jricher
 */
class TestScopeBasedIntrospectionAuthoritiesGranter {
    private lateinit var introspectionResponse: JsonObject

    private val granter = ScopeBasedIntrospectionAuthoritiesGranter()

    /**
     * @throws java.lang.Exception
     */
    @BeforeEach
    @Throws(Exception::class)
    fun setUp() {
        introspectionResponse = JsonObject(emptyMap())
    }

    /**
     * Test method for [org.mitre.oauth2.introspectingfilter.service.impl.ScopeBasedIntrospectionAuthoritiesGranter.getAuthorities].
     */
    @Test
    fun testGetAuthoritiesJsonObject_withScopes() {
        introspectionResponse = JsonObject(mapOf("scope" to JsonPrimitive("foo bar baz batman")))

        val expected: MutableList<GrantedAuthority> = ArrayList()
        expected.add(SimpleGrantedAuthority("ROLE_API"))
        expected.add(SimpleGrantedAuthority("OAUTH_SCOPE_foo"))
        expected.add(SimpleGrantedAuthority("OAUTH_SCOPE_bar"))
        expected.add(SimpleGrantedAuthority("OAUTH_SCOPE_baz"))
        expected.add(SimpleGrantedAuthority("OAUTH_SCOPE_batman"))

        val authorities = granter.getAuthorities(introspectionResponse)

        Assertions.assertTrue(authorities.containsAll(expected))
        Assertions.assertTrue(expected.containsAll(authorities))
    }

    /**
     * Test method for [org.mitre.oauth2.introspectingfilter.service.impl.ScopeBasedIntrospectionAuthoritiesGranter.getAuthorities].
     */
    @Test
    fun testGetAuthoritiesJsonObject_withoutScopes() {
        val expected: MutableList<GrantedAuthority> = ArrayList()
        expected.add(SimpleGrantedAuthority("ROLE_API"))

        val authorities = granter.getAuthorities(introspectionResponse)

        Assertions.assertTrue(authorities.containsAll(expected))
        Assertions.assertTrue(expected.containsAll(authorities))
    }
}
