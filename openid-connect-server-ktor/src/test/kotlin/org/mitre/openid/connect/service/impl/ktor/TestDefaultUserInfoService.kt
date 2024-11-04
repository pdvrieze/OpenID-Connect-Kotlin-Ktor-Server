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

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.extension.ExtendWith
import org.mitre.oauth2.model.ClientDetailsEntity
import org.mitre.oauth2.model.OAuthClientDetails.SubjectType
import org.mitre.oauth2.service.ClientDetailsEntityService
import org.mitre.openid.connect.model.DefaultUserInfo
import org.mitre.openid.connect.model.UserInfo
import org.mitre.openid.connect.repository.UserInfoRepository
import org.mitre.openid.connect.service.PairwiseIdentifierService
import org.mockito.Mockito.mock
import org.mockito.junit.jupiter.MockitoExtension
import org.mockito.kotlin.isA
import org.mockito.kotlin.never
import org.mockito.kotlin.verify
import org.mockito.kotlin.whenever

/**
 * @author jricher
 */
@ExtendWith(MockitoExtension::class)
class TestKtorUserInfoService {

    private val userInfoRepository = mock<UserInfoRepository>()
    private val clientDetailsEntityService = mock<ClientDetailsEntityService>()
    private val pairwiseIdentiferService = mock<PairwiseIdentifierService>()

    private val service = DefaultUserInfoService(userInfoRepository, clientDetailsEntityService, pairwiseIdentiferService)

    private lateinit var userInfoAdmin: UserInfo
    private lateinit var userInfoRegular: UserInfo

    private lateinit var publicClient1: ClientDetailsEntity
    private lateinit var publicClient2: ClientDetailsEntity
    private lateinit var pairwiseClient1: ClientDetailsEntity
    private lateinit var pairwiseClient2: ClientDetailsEntity
    private lateinit var pairwiseClient3: ClientDetailsEntity
    private lateinit var pairwiseClient4: ClientDetailsEntity



    /**
     * Initialize the service and the mocked repository.
     * Initialize 2 users, one of them an admin, for use in unit tests.
     */
    @BeforeEach
    fun prepare() {
        userInfoAdmin = DefaultUserInfo(
            subject = adminSub,
            preferredUsername = adminUsername,
        )

        userInfoRegular = DefaultUserInfo(
            preferredUsername = regularUsername,
            subject = regularSub,
        )

        publicClient1 = ClientDetailsEntity.Builder(clientId = publicClientId1).build()

        publicClient2 = ClientDetailsEntity.Builder(
            clientId = publicClientId2,
            subjectType = SubjectType.PUBLIC
        ).build()

        // pairwise set 1
        pairwiseClient1 = ClientDetailsEntity.Builder(
            clientId = pairwiseClientId1,
            subjectType = SubjectType.PAIRWISE,
            sectorIdentifierUri = sectorIdentifier1,
        ).build()

        pairwiseClient2 = ClientDetailsEntity.Builder(
            clientId = pairwiseClientId2,
            subjectType = SubjectType.PAIRWISE,
            sectorIdentifierUri = sectorIdentifier2,
        ).build()

        // pairwise set 2
        pairwiseClient3 = ClientDetailsEntity.Builder(
            clientId = pairwiseClientId3,
            subjectType = SubjectType.PAIRWISE,
            sectorIdentifierUri = sectorIdentifier3,
        ).build()

        // pairwise with null sector
        pairwiseClient4 = ClientDetailsEntity.Builder(
            clientId = pairwiseClientId4,
            subjectType = SubjectType.PAIRWISE
        ).build()
    }

    /**
     * Test loading an admin user, ensuring that the UserDetails object returned
     * has both the ROLE_USER and ROLE_ADMIN authorities.
     */
    @Test
    fun loadByUsername_admin_success() {
        whenever(userInfoRepository.getByUsername(adminUsername)).thenReturn(userInfoAdmin)
        val user = service.getByUsername(adminUsername)!!
        assertEquals(user.subject, adminSub)
    }

    /**
     * Test loading a regular, non-admin user, ensuring that the returned UserDetails
     * object has ROLE_USER but *not* ROLE_ADMIN.
     */
    @Test
    fun loadByUsername_regular_success() {
        whenever(userInfoRepository.getByUsername(regularUsername)).thenReturn(userInfoRegular)
        val user = service.getByUsername(regularUsername)!!
        assertEquals(user.subject, regularSub)
    }

    /**
     * If a user is not found, the loadByUsername method should throw an exception.
     */
    @Test
    fun loadByUsername_nullUser() {
        whenever(userInfoRepository.getByUsername(adminUsername)).thenReturn(null)
        val user = service.getByUsername(adminUsername)

        assertNull(user)
    }

    @Test
    fun getByUsernameAndClientId_publicClients() {
        whenever(clientDetailsEntityService.loadClientByClientId(publicClientId1)).thenReturn(publicClient1)
        whenever(clientDetailsEntityService.loadClientByClientId(publicClientId2)).thenReturn(publicClient2)

        whenever(userInfoRepository.getByUsername(regularUsername)).thenReturn(userInfoRegular)

        verify(pairwiseIdentiferService, never())
            .getIdentifier(isA<UserInfo>(), isA<ClientDetailsEntity>())

        val user1 = service.getByUsernameAndClientId(regularUsername, publicClientId1)!!
        val user2 = service.getByUsernameAndClientId(regularUsername, publicClientId2)!!

        assertEquals(regularSub, user1.subject)
        assertEquals(regularSub, user2.subject)
    }

    @Test
    fun getByUsernameAndClientId_pairwiseClients() {
        whenever(clientDetailsEntityService.loadClientByClientId(pairwiseClientId1))
            .thenReturn(pairwiseClient1)
        whenever(clientDetailsEntityService.loadClientByClientId(pairwiseClientId2))
            .thenReturn(pairwiseClient2)
        whenever(clientDetailsEntityService.loadClientByClientId(pairwiseClientId3))
            .thenReturn(pairwiseClient3)
        whenever(clientDetailsEntityService.loadClientByClientId(pairwiseClientId4))
            .thenReturn(pairwiseClient4)

        whenever(userInfoRepository.getByUsername(regularUsername)).thenAnswer {
            DefaultUserInfo(
                preferredUsername = regularUsername,
                subject = regularSub,
            )
        }

        whenever(pairwiseIdentiferService.getIdentifier(userInfoRegular, pairwiseClient1))
            .thenReturn(pairwiseSub12)
        whenever(pairwiseIdentiferService.getIdentifier(userInfoRegular, pairwiseClient2))
            .thenReturn(pairwiseSub12)
        whenever(pairwiseIdentiferService.getIdentifier(userInfoRegular, pairwiseClient3))
            .thenReturn(pairwiseSub3)
        whenever(pairwiseIdentiferService.getIdentifier(userInfoRegular, pairwiseClient4))
            .thenReturn(pairwiseSub4)

        val user1 = service.getByUsernameAndClientId(regularUsername, pairwiseClientId1)
        val user2 = service.getByUsernameAndClientId(regularUsername, pairwiseClientId2)
        val user3 = service.getByUsernameAndClientId(regularUsername, pairwiseClientId3)
        val user4 = service.getByUsernameAndClientId(regularUsername, pairwiseClientId4)

        assertEquals(pairwiseSub12, user1!!.subject)
        assertEquals(pairwiseSub12, user2!!.subject)
        assertEquals(pairwiseSub3, user3!!.subject)
        assertEquals(pairwiseSub4, user4!!.subject)
    }
    
    
    companion object {
        private const val adminUsername = "username"
        private const val regularUsername = "regular"
        private const val adminSub = "adminSub12d3a1f34a2"
        private const val regularSub = "regularSub652ha23b"

        private const val pairwiseSub12 = "regularPairwise-12-31ijoef"
        private const val pairwiseSub3 = "regularPairwise-3-1ojadsio"
        private const val pairwiseSub4 = "regularPairwise-4-1ojadsio"

        private const val publicClientId1 = "publicClient-1-313124"
        private const val publicClientId2 = "publicClient-2-4109312"
        private const val pairwiseClientId1 = "pairwiseClient-1-2312"
        private const val pairwiseClientId2 = "pairwiseClient-2-324416"
        private const val pairwiseClientId3 = "pairwiseClient-3-154157"
        private const val pairwiseClientId4 = "pairwiseClient-4-4589723"

        private const val sectorIdentifier1 = "https://sector-identifier-12/url"
        private const val sectorIdentifier2 = "https://sector-identifier-12/url2"
        private const val sectorIdentifier3 = "https://sector-identifier-3/url"

    }
}
