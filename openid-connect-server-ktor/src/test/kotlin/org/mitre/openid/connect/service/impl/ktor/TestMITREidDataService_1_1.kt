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
package org.mitre.openid.connect.service.impl.ktor

import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.junit.jupiter.api.extension.ExtendWith
import org.mitre.oauth2.model.OAuth2AccessTokenEntity
import org.mitre.oauth2.model.OAuth2RefreshTokenEntity
import org.mockito.ArgumentCaptor
import org.mockito.Captor
import org.mockito.junit.jupiter.MockitoExtension
import org.mockito.junit.jupiter.MockitoSettings
import org.mockito.quality.Strictness
import java.io.IOException
import java.text.ParseException

@ExtendWith(MockitoExtension::class)
@MockitoSettings(strictness = Strictness.WARN)
class TestMITREidDataService_1_1 : TestMITREiDDataServiceBase<MITREidDataService_1_1>() {
    @Captor
    private lateinit var capturedRefreshTokens: ArgumentCaptor<OAuth2RefreshTokenEntity>

    @Captor
    private lateinit var capturedAccessTokens: ArgumentCaptor<OAuth2AccessTokenEntity>

    override lateinit var dataService: MITREidDataService_1_1

    @BeforeEach
    fun prepare() {
        dataService = MITREidDataService_1_1(clientRepository, approvedSiteRepository, wlSiteRepository, blSiteRepository, authHolderRepository, tokenRepository, sysScopeRepository)
        commonPrepare(MITREidDataService_1_1::class)
    }

    @Test
    override fun testImportRefreshTokens() {
        super.testImportRefreshTokens()
    }

    @Test
    override fun testImportAccessTokens() {
        super.testImportAccessTokens()
    }


    //several new client fields added in 1.1, perhaps additional tests for these should be added
    @Test
    override fun testImportClients() {
        super.testImportClients()
    }

    @Test
    override fun testImportBlacklistedSites() {
        super.testImportBlacklistedSites()
    }

    @Test
    override fun testImportWhitelistedSites() {
        super.testImportWhitelistedSites()
    }

    @Test
    override fun testImportGrants() {
        super.testImportGrants()
    }

    @Test
    fun testImportAuthenticationHolders() {
        testImportAuthenticationHolders(true)
    }

    @Test
    fun testImportSystemScopes() {
        super.testImportSystemScopes(false)
    }

    @Test
    @Throws(IOException::class, ParseException::class)
    fun testFixRefreshTokenAuthHolderReferencesOnImport() {
        testFixRefreshTokenAuthHolderReferencesOnImport(0)
    }

    @Test
    fun testExportDisabled() {
        assertThrows<UnsupportedOperationException> {
            dataService.exportData()
        }
    }
}
