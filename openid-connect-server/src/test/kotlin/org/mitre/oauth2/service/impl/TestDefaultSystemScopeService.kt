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
package org.mitre.oauth2.service.impl

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.extension.ExtendWith
import org.mitre.oauth2.model.SystemScope
import org.mitre.oauth2.repository.SystemScopeRepository
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
class TestDefaultSystemScopeService {
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
        assertEquals(allScopes, service.all)
    }

    @Test
    fun getDefaults() {
        val defaults: Set<SystemScope?> =
            hashSetOf(defaultDynScope1, defaultDynScope2, defaultScope1, defaultScope2)

        assertEquals(defaults, service.defaults)
    }

    @Test
    fun getUnrestricted() {
        val unrestricted: Set<SystemScope?> = hashSetOf(defaultDynScope1, defaultDynScope2, dynScope1)

        assertEquals(unrestricted, service.unrestricted)
    }

    @Test
    fun getRestricted() {
        val restricted: Set<SystemScope?> = hashSetOf(defaultScope1, defaultScope2, restrictedScope1)

        assertEquals(restricted, service.restricted)
    }

    @Test
    fun fromStrings() {
        // check null condition

        assertNull(service.fromStrings(null))

        assertEquals(allScopes, service.fromStrings(allScopeStrings))

        assertEquals(allScopesWithValue, service.fromStrings(allScopeStringsWithValue))
    }

    @Test
    fun toStrings() {
        // check null condition

        assertNull(service.toStrings(null))

        assertEquals(allScopeStrings, service.toStrings(allScopes))

        assertEquals(allScopeStringsWithValue, service.toStrings(allScopesWithValue))
    }

    @Test
    fun scopesMatch() {
        val expected: Set<String> = hashSetOf("foo", "bar", "baz")
        val actualGood: Set<String> = hashSetOf("foo", "baz", "bar")
        val actualGood2: Set<String> = hashSetOf("foo", "bar")
        val actualBad: Set<String> = hashSetOf("foo", "bob", "bar")

        // same scopes, different order
        assertTrue(service.scopesMatch(expected, actualGood))

        // subset
        assertTrue(service.scopesMatch(expected, actualGood2))

        // extra scope (fail)
        assertFalse(service.scopesMatch(expected, actualBad))
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
