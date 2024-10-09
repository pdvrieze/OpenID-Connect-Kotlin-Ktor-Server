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
import org.mitre.openid.connect.model.DefaultUserInfo
import org.mitre.openid.connect.model.UserInfo
import org.mitre.openid.connect.repository.UserInfoRepository
import org.mitre.openid.connect.service.PairwiseIdentifierService
import org.mitre.openid.connect.service.UserInfoService

/**
 * Implementation of the UserInfoService
 *
 * @author Michael Joseph Walsh, jricher
 */
abstract class AbstractUserInfoService : UserInfoService {
    protected abstract val userInfoRepository: UserInfoRepository

    protected abstract val clientService: ClientDetailsEntityService

    protected abstract val pairwiseIdentifierService: PairwiseIdentifierService

    override fun getByUsername(username: String): UserInfo? {
        return userInfoRepository.getByUsername(username)
    }

    override fun getByUsernameAndClientId(username: String, clientId: String): UserInfo? {
        val client = clientService.loadClientByClientId(clientId) ?: return null

        val userInfo = getByUsername(username)?.let{ DefaultUserInfo.from(it) } ?: return null

        if (SubjectType.PAIRWISE == client.subjectType) {
            val pairwiseSub = pairwiseIdentifierService.getIdentifier(userInfo, client) ?: return null // pairwise not found
            userInfo.subject = pairwiseSub
        }

        return userInfo
    }

    override fun getByEmailAddress(email: String): UserInfo? {
        return userInfoRepository.getByEmailAddress(email)
    }
}
