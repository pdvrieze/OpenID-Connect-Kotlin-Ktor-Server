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
package org.mitre.openid.connect.repository.impl

import org.mitre.openid.connect.model.DefaultUserInfo
import org.mitre.openid.connect.model.UserInfo
import org.mitre.openid.connect.repository.UserInfoRepository
import org.mitre.util.jpa.JpaUtil.getSingleResult
import org.springframework.stereotype.Repository
import javax.persistence.EntityManager
import javax.persistence.PersistenceContext

/**
 * JPA UserInfo repository implementation
 *
 * @author Michael Joseph Walsh
 */
@Repository("jpaUserInfoRepository")
class JpaUserInfoRepository : UserInfoRepository {
    @PersistenceContext(unitName = "defaultPersistenceUnit")
    private lateinit var manager: EntityManager

    /**
     * Get a single UserInfo object by its username
     */
    override fun getByUsername(username: String): UserInfo? {
        val query = manager.createNamedQuery(DefaultUserInfo.QUERY_BY_USERNAME, DefaultUserInfo::class.java)
        query.setParameter(DefaultUserInfo.PARAM_USERNAME, username)

        return getSingleResult(query.resultList)
    }

    /**
     * Get a single UserInfo object by its email address
     */
    override fun getByEmailAddress(email: String): UserInfo? {
        val query = manager.createNamedQuery(DefaultUserInfo.QUERY_BY_EMAIL, DefaultUserInfo::class.java)
        query.setParameter(DefaultUserInfo.PARAM_EMAIL, email)

        return getSingleResult(query.resultList)
    }
}
