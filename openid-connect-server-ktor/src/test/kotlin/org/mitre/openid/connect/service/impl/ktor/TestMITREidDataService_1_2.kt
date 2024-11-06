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
package org.mitre.openid.connect.service.impl.ktor

import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.extension.ExtendWith
import org.mitre.oauth2.model.OAuth2RefreshTokenEntity
import org.mitre.util.getLogger
import org.mockito.junit.jupiter.MockitoExtension
import org.mockito.junit.jupiter.MockitoSettings
import org.mockito.quality.Strictness
import java.io.IOException
import java.text.ParseException
import java.util.*

@ExtendWith(MockitoExtension::class)
@MockitoSettings(strictness = Strictness.WARN)
class TestMITREidDataService_1_2 : TestMITREiDDataServiceBase<KtorIdDataService_1_2>() {

    override lateinit var dataService: KtorIdDataService_1_2

    @BeforeEach
    fun prepare() {
        dataService = KtorIdDataService_1_2(clientRepository, approvedSiteRepository, wlSiteRepository, blSiteRepository, authHolderRepository, tokenRepository, sysScopeRepository)
        commonPrepare(KtorIdDataService_1_2::class)
    }

    private inner class refreshTokenIdComparator : Comparator<OAuth2RefreshTokenEntity> {
        override fun compare(entity1: OAuth2RefreshTokenEntity, entity2: OAuth2RefreshTokenEntity): Int {
            return entity1.id!!.compareTo(entity2.id!!)
        }
    }


    @Test
    override fun testImportRefreshTokens() {
        super.testImportRefreshTokens()
    }

    @Test
    override fun testImportAccessTokens() {
        super.testImportAccessTokens()
    }

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
        testImportAuthenticationHolders(false)
    }

    @Test
    @Throws(IOException::class)
    fun testImportSystemScopes() {
        super.testImportSystemScopes(false)
    }

    @Test
    @Throws(IOException::class, ParseException::class)
    fun testFixRefreshTokenAuthHolderReferencesOnImport() {
        testFixRefreshTokenAuthHolderReferencesOnImport(1)
    }

    companion object {
        private val logger = getLogger<TestMITREidDataService_1_2>()
    }
}
