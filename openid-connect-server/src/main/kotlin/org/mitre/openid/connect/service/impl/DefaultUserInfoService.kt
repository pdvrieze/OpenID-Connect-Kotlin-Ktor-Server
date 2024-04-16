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

import org.mitre.oauth2.model.OAuthClientDetails.SubjectType
import org.mitre.oauth2.service.ClientDetailsEntityService
import org.mitre.openid.connect.model.UserInfo
import org.mitre.openid.connect.repository.UserInfoRepository
import org.mitre.openid.connect.service.PairwiseIdentiferService
import org.mitre.openid.connect.service.UserInfoService
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.stereotype.Service

/**
 * Implementation of the UserInfoService
 *
 * @author Michael Joseph Walsh, jricher
 */
@Service
class DefaultUserInfoService : UserInfoService {
    @Autowired
    private lateinit var userInfoRepository: UserInfoRepository

    @Autowired
    private lateinit var clientService: ClientDetailsEntityService

    @Autowired
    private lateinit var pairwiseIdentifierService: PairwiseIdentiferService

    @Deprecated("Use constructor that doesn't rely on autowiring")
    constructor()

    constructor(
        userInfoRepository: UserInfoRepository,
        clientService: ClientDetailsEntityService,
        pairwiseIdentifierService: PairwiseIdentiferService,
    ) {
        this.userInfoRepository = userInfoRepository
        this.clientService = clientService
        this.pairwiseIdentifierService = pairwiseIdentifierService
    }

    override fun getByUsername(username: String): UserInfo? {
        return userInfoRepository.getByUsername(username)
    }

    override fun getByUsernameAndClientId(username: String, clientId: String): UserInfo? {
        val client = clientService.loadClientByClientId(clientId) ?: return null

        val userInfo = getByUsername(username) ?: return null

        if (SubjectType.PAIRWISE == client.subjectType) {
            val pairwiseSub = pairwiseIdentifierService.getIdentifier(userInfo, client)
            userInfo.sub = pairwiseSub
        }

        return userInfo
    }

    override fun getByEmailAddress(email: String): UserInfo? {
        return userInfoRepository.getByEmailAddress(email)
    }
}
