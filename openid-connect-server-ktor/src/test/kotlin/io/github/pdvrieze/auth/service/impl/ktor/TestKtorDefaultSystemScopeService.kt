package io.github.pdvrieze.auth.service.impl.ktor

import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.extension.ExtendWith
import org.mitre.oauth2.model.SystemScope
import org.mitre.oauth2.repository.SystemScopeRepository
import org.mitre.oauth2.service.impl.DefaultSystemScopeService
import org.mockito.InjectMocks
import org.mockito.Mock
import org.mockito.junit.jupiter.MockitoExtension
import org.mockito.junit.jupiter.MockitoSettings
import org.mockito.kotlin.doReturn
import org.mockito.kotlin.reset
import org.mockito.kotlin.whenever
import org.mockito.quality.Strictness

/**
 * @author wkim
 */
@ExtendWith(MockitoExtension::class)
@MockitoSettings(strictness = Strictness.WARN)
class TestKtorDefaultSystemScopeService {
    // test fixture
    private lateinit var defaultDynScope1: SystemScope
    private lateinit var defaultDynScope2: SystemScope
    private lateinit var defaultScope1: SystemScope
    private lateinit var defaultScope2: SystemScope
    private lateinit var dynScope1: SystemScope
    private lateinit var restrictedScope1: SystemScope

    private lateinit var allScopes: Set<SystemScope>
    private lateinit var allScopeStrings: Set<String>
    private lateinit var allScopesWithValue: Set<SystemScope>
    private lateinit var allScopeStringsWithValue: Set<String>

    @Mock
    private lateinit var repository: SystemScopeRepository

    @InjectMocks
    private lateinit var service: DefaultSystemScopeService

    /**
     * Assumes these SystemScope defaults: isDefaultScope=false and isAllowDynReg=false.
     */
    @BeforeEach
    fun prepare() {
        reset(repository)

        // two default and dynamically registerable scopes (unrestricted)
        defaultDynScope1 = SystemScope(defaultDynScope1String)
        defaultDynScope2 = SystemScope(defaultDynScope2String)
        defaultDynScope1.isDefaultScope = true
        defaultDynScope2.isDefaultScope = true

        // two strictly default scopes (restricted)
        defaultScope1 = SystemScope(defaultScope1String)
        defaultScope2 = SystemScope(defaultScope2String)
        defaultScope1.isRestricted = true
        defaultScope2.isRestricted = true
        defaultScope1.isDefaultScope = true
        defaultScope2.isDefaultScope = true

        // one strictly dynamically registerable scope (isDefault false)
        dynScope1 = SystemScope(dynScope1String)

        // extraScope1 : extra scope that is neither restricted nor default (defaults to false/false)
        restrictedScope1 = SystemScope(restrictedScope1String)
        restrictedScope1.isRestricted = true


        allScopes =
            hashSetOf(defaultDynScope1, defaultDynScope2, defaultScope1, defaultScope2, dynScope1, restrictedScope1)
        allScopeStrings =
            hashSetOf(defaultDynScope1String, defaultDynScope2String, defaultScope1String, defaultScope2String, dynScope1String, restrictedScope1String)

        allScopesWithValue =
            hashSetOf(defaultDynScope1, defaultDynScope2, defaultScope1, defaultScope2, dynScope1, restrictedScope1)
        allScopeStringsWithValue =
            hashSetOf(defaultDynScope1String, defaultDynScope2String, defaultScope1String, defaultScope2String, dynScope1String, restrictedScope1String)

        whenever(repository.getByValue(defaultDynScope1String)).doReturn(defaultDynScope1)
        whenever(repository.getByValue(defaultDynScope2String)).doReturn(defaultDynScope2)
        whenever(repository.getByValue(defaultScope1String)).doReturn(defaultScope1)
        whenever(repository.getByValue(defaultScope2String)).doReturn(defaultScope2)
        whenever(repository.getByValue(dynScope1String)).doReturn(dynScope1)
        whenever(repository.getByValue(restrictedScope1String)).doReturn(restrictedScope1)

        whenever(repository.all).doReturn(allScopes)
    }

    @Test
    fun getAll(): Unit {
        Assertions.assertEquals(allScopes, service.all)
    }

    @Test
    fun getDefaults() {
        val defaults: Set<SystemScope?> =
            hashSetOf(defaultDynScope1, defaultDynScope2, defaultScope1, defaultScope2)

        Assertions.assertEquals(defaults, service.defaults)
    }

    @Test
    fun getUnrestricted() {
        val unrestricted: Set<SystemScope?> = hashSetOf(defaultDynScope1, defaultDynScope2, dynScope1)

        Assertions.assertEquals(unrestricted, service.unrestricted)
    }

    @Test
    fun getRestricted() {
        val restricted: Set<SystemScope?> = hashSetOf(defaultScope1, defaultScope2, restrictedScope1)

        Assertions.assertEquals(restricted, service.restricted)
    }

    @Test
    fun fromStrings() {
        // check null condition

        Assertions.assertNull(service.fromStrings(null))

        Assertions.assertEquals(allScopes, service.fromStrings(allScopeStrings))

        Assertions.assertEquals(allScopesWithValue, service.fromStrings(allScopeStringsWithValue))
    }

    @Test
    fun toStrings() {
        // check null condition

        Assertions.assertNull(service.toStrings(null))

        Assertions.assertEquals(allScopeStrings, service.toStrings(allScopes))

        Assertions.assertEquals(allScopeStringsWithValue, service.toStrings(allScopesWithValue))
    }

    @Test
    fun scopesMatch() {
        val expected: Set<String> = hashSetOf("foo", "bar", "baz")
        val actualGood: Set<String> = hashSetOf("foo", "baz", "bar")
        val actualGood2: Set<String> = hashSetOf("foo", "bar")
        val actualBad: Set<String> = hashSetOf("foo", "bob", "bar")

        // same scopes, different order
        Assertions.assertTrue(service.scopesMatch(expected, actualGood))

        // subset
        Assertions.assertTrue(service.scopesMatch(expected, actualGood2))

        // extra scope (fail)
        Assertions.assertFalse(service.scopesMatch(expected, actualBad))
    }

    companion object {
        private const val defaultDynScope1String = "defaultDynScope1"
        private const val defaultDynScope2String = "defaultDynScope2"
        private const val defaultScope1String = "defaultScope1"
        private const val defaultScope2String = "defaultScope2"
        private const val dynScope1String = "dynScope1"
        private const val restrictedScope1String = "restrictedScope1"
    }
}
