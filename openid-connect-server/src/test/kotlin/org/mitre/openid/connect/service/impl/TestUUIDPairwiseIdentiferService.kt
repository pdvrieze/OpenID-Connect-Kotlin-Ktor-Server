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
package org.mitre.openid.connect.service.impl

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotSame
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.junit.jupiter.api.extension.ExtendWith
import org.mitre.oauth2.model.ClientDetailsEntity
import org.mitre.oauth2.model.ClientDetailsEntity.SubjectType
import org.mitre.openid.connect.model.DefaultUserInfo
import org.mitre.openid.connect.model.PairwiseIdentifier
import org.mitre.openid.connect.model.UserInfo
import org.mitre.openid.connect.repository.PairwiseIdentifierRepository
import org.mitre.openid.connect.service.PairwiseIdentiferService
import org.mockito.InjectMocks
import org.mockito.Mock
import org.mockito.junit.jupiter.MockitoExtension
import org.mockito.kotlin.any
import org.mockito.kotlin.atLeast
import org.mockito.kotlin.verify
import org.mockito.kotlin.whenever
import java.util.*

/**
 * @author jricher
 */
@ExtendWith(MockitoExtension::class)
class TestUUIDPairwiseIdentiferService {
    @Mock
    private lateinit var pairwiseIdentifierRepository: PairwiseIdentifierRepository

    @InjectMocks
    private lateinit var service: UUIDPairwiseIdentiferService

    private lateinit var userInfoRegular: UserInfo

    private lateinit var pairwiseClient1: ClientDetailsEntity
    private lateinit var pairwiseClient2: ClientDetailsEntity
    private lateinit var pairwiseClient3: ClientDetailsEntity
    private lateinit var pairwiseClient4: ClientDetailsEntity
    private lateinit var pairwiseClient5: ClientDetailsEntity


    private lateinit var savedPairwiseIdentifier: PairwiseIdentifier

    @BeforeEach
    fun prepare() {
        userInfoRegular = DefaultUserInfo()
        userInfoRegular.preferredUsername = regularUsername
        userInfoRegular.sub = regularSub

        // pairwise set 1
        pairwiseClient1 = ClientDetailsEntity()
        pairwiseClient1.clientId = pairwiseClientId1
        pairwiseClient1.subjectType = SubjectType.PAIRWISE
        pairwiseClient1.sectorIdentifierUri = sectorIdentifier1

        pairwiseClient2 = ClientDetailsEntity()
        pairwiseClient2.clientId = pairwiseClientId2
        pairwiseClient2.subjectType = SubjectType.PAIRWISE
        pairwiseClient2.sectorIdentifierUri = sectorIdentifier2

        // pairwise set 2
        pairwiseClient3 = ClientDetailsEntity()
        pairwiseClient3.clientId = pairwiseClientId3
        pairwiseClient3.subjectType = SubjectType.PAIRWISE
        pairwiseClient3.sectorIdentifierUri = sectorIdentifier3
        pairwiseClient3.redirectUris = pairwiseClient3RedirectUris

        // pairwise with null sector
        pairwiseClient4 = ClientDetailsEntity()
        pairwiseClient4.clientId = pairwiseClientId4
        pairwiseClient4.subjectType = SubjectType.PAIRWISE
        pairwiseClient4.redirectUris = pairwiseClient4RedirectUris

        // pairwise with multiple redirects and no sector (error)
        pairwiseClient5 = ClientDetailsEntity()
        pairwiseClient5.clientId = pairwiseClientId5
        pairwiseClient5.subjectType = SubjectType.PAIRWISE
        pairwiseClient5.redirectUris = pairwiseClient5RedirectUris

        // saved pairwise identifier from repository
        savedPairwiseIdentifier = PairwiseIdentifier()
        savedPairwiseIdentifier.userSub = regularSub
        savedPairwiseIdentifier.identifier = pairwiseSub
        savedPairwiseIdentifier.sectorIdentifier = sectorHost12
    }

    /**
     * Test method for [PairwiseIdentiferService.getIdentifier].
     */
    @Test
    fun testGetIdentifier_existingEqual() {
        whenever(pairwiseIdentifierRepository.getBySectorIdentifier(regularSub, sectorHost12))
            .thenReturn(savedPairwiseIdentifier)

        val pairwise1 = service.getIdentifier(userInfoRegular, pairwiseClient1)
        val pairwise2 = service.getIdentifier(userInfoRegular, pairwiseClient2)

        assertEquals(pairwiseSub, pairwise1)
        assertEquals(pairwiseSub, pairwise2)
    }

    @Test
    fun testGetIdentifier_newEqual() {
        val pairwise1 = service.getIdentifier(userInfoRegular, pairwiseClient1)
        verify(pairwiseIdentifierRepository, atLeast(1))
            .save(any<PairwiseIdentifier>())

        val pairwiseId = PairwiseIdentifier()
        pairwiseId.userSub = regularSub
        pairwiseId.identifier = pairwise1
        pairwiseId.sectorIdentifier = sectorHost12

        whenever(pairwiseIdentifierRepository.getBySectorIdentifier(regularSub, sectorHost12))
            .thenReturn(pairwiseId)

        val pairwise2 = service.getIdentifier(userInfoRegular, pairwiseClient2)

        assertNotSame(pairwiseSub, pairwise1)
        assertNotSame(pairwiseSub, pairwise2)

        assertEquals(pairwise1, pairwise2)

        // see if the pairwise ids are actual UUIDs
        UUID.fromString(pairwise1)
        UUID.fromString(pairwise2)
    }

    @Test
    fun testGetIdentifer_unique() {
        val pairwise1 = service.getIdentifier(userInfoRegular, pairwiseClient1)
        val pairwise3 = service.getIdentifier(userInfoRegular, pairwiseClient3)
        val pairwise4 = service.getIdentifier(userInfoRegular, pairwiseClient4)

        // make sure nothing's equal
        assertNotSame(pairwise1, pairwise3)
        assertNotSame(pairwise1, pairwise4)
        assertNotSame(pairwise3, pairwise4)

        // see if the pairwise ids are actual UUIDs
        UUID.fromString(pairwise1)
        UUID.fromString(pairwise3)
        UUID.fromString(pairwise4)
    }

    @Test
    fun testGetIdentifier_multipleRedirectError() {
        assertThrows<IllegalArgumentException> {
            service.getIdentifier(userInfoRegular, pairwiseClient5)
        }
    }

    @Suppress("ConstPropertyName")
    companion object {
        private const val regularUsername = "regular"
        private const val regularSub = "regularSub652ha23b"
        private const val pairwiseSub = "pairwise-12-regular-user"

        private const val pairwiseClientId1 = "pairwiseClient-1-2312"
        private const val pairwiseClientId2 = "pairwiseClient-2-324416"
        private const val pairwiseClientId3 = "pairwiseClient-3-154157"
        private const val pairwiseClientId4 = "pairwiseClient-4-4589723"
        private const val pairwiseClientId5 = "pairwiseClient-5-34908713"

        private const val sectorHost12 = "sector-identifier-12"
        private const val sectorHost3 = "sector-identifier-3"
        private const val clientHost4 = "client-redirect-4"
        private const val clientHost5 = "client-redirect-5"

        private const val sectorIdentifier1 = "https://$sectorHost12/url"
        private const val sectorIdentifier2 = "https://$sectorHost12/url2"
        private const val sectorIdentifier3 = "https://$sectorHost3/url"

        private val pairwiseClient3RedirectUris: Set<String> =
            setOf("https://$sectorHost3/oauth", "https://$sectorHost3/other")
        private val pairwiseClient4RedirectUris: Set<String> = setOf("https://$clientHost4/oauth")
        private val pairwiseClient5RedirectUris: Set<String> =
            setOf("https://$clientHost5/oauth", "https://$clientHost5/other")

    }

}
