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
package org.mitre.oauth2.repository.impl

import com.nimbusds.jwt.JWT
import com.nimbusds.jwt.JWTParser
import org.mitre.data.DefaultPageCriteria
import org.mitre.data.PageCriteria
import org.mitre.oauth2.model.OAuth2AccessTokenEntity
import org.mitre.oauth2.model.OAuth2RefreshTokenEntity
import org.mitre.oauth2.model.OAuthClientDetails
import org.mitre.oauth2.repository.OAuth2TokenRepository
import org.mitre.openid.connect.model.ApprovedSite
import org.mitre.uma.model.ResourceSet
import org.mitre.util.getLogger
import org.mitre.util.jpa.JpaUtil.getResultPage
import org.mitre.util.jpa.JpaUtil.getSingleResult
import org.mitre.util.jpa.JpaUtil.saveOrUpdate
import org.springframework.stereotype.Repository
import org.springframework.transaction.annotation.Transactional
import java.text.ParseException
import java.util.*
import javax.persistence.EntityManager
import javax.persistence.PersistenceContext

@Repository
class JpaOAuth2TokenRepository : OAuth2TokenRepository {
    @PersistenceContext(unitName = "defaultPersistenceUnit")
    private lateinit var manager: EntityManager

    override val allAccessTokens: Set<OAuth2AccessTokenEntity>
        get() {
            val query = manager.createNamedQuery(OAuth2AccessTokenEntity.QUERY_ALL, OAuth2AccessTokenEntity::class.java)
            return LinkedHashSet(query.resultList)
        }

    override val allRefreshTokens: Set<OAuth2RefreshTokenEntity>
        get() {
            val query =
                manager.createNamedQuery(OAuth2RefreshTokenEntity.QUERY_ALL, OAuth2RefreshTokenEntity::class.java)
            return LinkedHashSet(query.resultList)
        }


    override fun getAccessTokenByValue(accessTokenValue: String): OAuth2AccessTokenEntity? {
        try {
            val jwt = JWTParser.parse(accessTokenValue)
            val query =
                manager.createNamedQuery(OAuth2AccessTokenEntity.QUERY_BY_TOKEN_VALUE, OAuth2AccessTokenEntity::class.java)
            query.setParameter(OAuth2AccessTokenEntity.PARAM_TOKEN_VALUE, jwt)
            return getSingleResult(query.resultList)
        } catch (e: ParseException) {
            return null
        }
    }

    override fun getAccessTokenById(id: Long): OAuth2AccessTokenEntity? {
        return manager.find(OAuth2AccessTokenEntity::class.java, id)
    }

    @Transactional(value = "defaultTransactionManager")
    override fun saveAccessToken(token: OAuth2AccessTokenEntity): OAuth2AccessTokenEntity {
        return saveOrUpdate(token.id, manager, token)
    }

    @Transactional(value = "defaultTransactionManager")
    override fun removeAccessToken(accessToken: OAuth2AccessTokenEntity) {
        val id = requireNotNull(accessToken.id) { "missing id in access token" }
        val found = getAccessTokenById(id)
        if (found != null) {
            manager.remove(found)
        } else {
            throw IllegalArgumentException("Access token not found: $accessToken")
        }
    }

    @Transactional(value = "defaultTransactionManager")
    override fun clearAccessTokensForRefreshToken(refreshToken: OAuth2RefreshTokenEntity) {
        val query =
            manager.createNamedQuery(OAuth2AccessTokenEntity.QUERY_BY_REFRESH_TOKEN, OAuth2AccessTokenEntity::class.java)
        query.setParameter(OAuth2AccessTokenEntity.PARAM_REFRESH_TOKEN, refreshToken)
        val accessTokens = query.resultList
        for (accessToken in accessTokens) {
            removeAccessToken(accessToken)
        }
    }

    override fun getRefreshTokenByValue(refreshTokenValue: String): OAuth2RefreshTokenEntity? {
        try {
            val jwt = JWTParser.parse(refreshTokenValue)
            val query =
                manager.createNamedQuery(OAuth2RefreshTokenEntity.QUERY_BY_TOKEN_VALUE, OAuth2RefreshTokenEntity::class.java)
            query.setParameter(OAuth2RefreshTokenEntity.PARAM_TOKEN_VALUE, jwt)
            return getSingleResult(query.resultList)
        } catch (e: ParseException) {
            return null
        }
    }

    override fun getRefreshTokenById(id: Long): OAuth2RefreshTokenEntity? {
        return manager.find(OAuth2RefreshTokenEntity::class.java, id)
    }

    @Transactional(value = "defaultTransactionManager")
    override fun saveRefreshToken(refreshToken: OAuth2RefreshTokenEntity): OAuth2RefreshTokenEntity {
        return saveOrUpdate(refreshToken.id, manager, refreshToken)
    }

    @Transactional(value = "defaultTransactionManager")
    override fun removeRefreshToken(refreshToken: OAuth2RefreshTokenEntity) {
        val id = requireNotNull(refreshToken.id) { "Missing id in refresh token" }
        val found = getRefreshTokenById(id)
        if (found != null) {
            manager.remove(found)
        } else {
            throw IllegalArgumentException("Refresh token not found: $refreshToken")
        }
    }

    @Transactional(value = "defaultTransactionManager")
    override fun clearTokensForClient(client: OAuthClientDetails) {
        val queryA =
            manager.createNamedQuery(OAuth2AccessTokenEntity.QUERY_BY_CLIENT, OAuth2AccessTokenEntity::class.java)
        queryA.setParameter(OAuth2AccessTokenEntity.PARAM_CLIENT, client)
        val accessTokens = queryA.resultList
        for (accessToken in accessTokens) {
            removeAccessToken(accessToken)
        }
        val queryR =
            manager.createNamedQuery(OAuth2RefreshTokenEntity.QUERY_BY_CLIENT, OAuth2RefreshTokenEntity::class.java)
        queryR.setParameter(OAuth2RefreshTokenEntity.PARAM_CLIENT, client)
        val refreshTokens = queryR.resultList
        for (refreshToken in refreshTokens) {
            removeRefreshToken(refreshToken)
        }
    }

    override fun getAccessTokensForClient(client: OAuthClientDetails): List<OAuth2AccessTokenEntity> {
        val queryA =
            manager.createNamedQuery(OAuth2AccessTokenEntity.QUERY_BY_CLIENT, OAuth2AccessTokenEntity::class.java)
        queryA.setParameter(OAuth2AccessTokenEntity.PARAM_CLIENT, client)
        val accessTokens = queryA.resultList
        return accessTokens
    }

    override fun getRefreshTokensForClient(client: OAuthClientDetails): List<OAuth2RefreshTokenEntity> {
        val queryR =
            manager.createNamedQuery(OAuth2RefreshTokenEntity.QUERY_BY_CLIENT, OAuth2RefreshTokenEntity::class.java)
        queryR.setParameter(OAuth2RefreshTokenEntity.PARAM_CLIENT, client)
        val refreshTokens = queryR.resultList
        return refreshTokens
    }

    override fun getAccessTokensByUserName(name: String): Set<OAuth2AccessTokenEntity> {
        val query = manager.createNamedQuery(OAuth2AccessTokenEntity.QUERY_BY_NAME, OAuth2AccessTokenEntity::class.java)
        query.setParameter(OAuth2AccessTokenEntity.PARAM_NAME, name)
        val results = query.resultList
        return if (results != null) HashSet(results) else HashSet()
    }

    override fun getRefreshTokensByUserName(name: String): Set<OAuth2RefreshTokenEntity> {
        val query =
            manager.createNamedQuery(OAuth2RefreshTokenEntity.QUERY_BY_NAME, OAuth2RefreshTokenEntity::class.java)
        query.setParameter(OAuth2RefreshTokenEntity.PARAM_NAME, name)
        val results = query.resultList
        return if (results != null) HashSet(results) else HashSet()
    }

    override val allExpiredAccessTokens: Set<OAuth2AccessTokenEntity>
        get() {
            val pageCriteria = DefaultPageCriteria(0, MAXEXPIREDRESULTS)
            return getAllExpiredAccessTokens(pageCriteria)
        }

    override fun getAllExpiredAccessTokens(pageCriteria: PageCriteria): Set<OAuth2AccessTokenEntity> {
        val query =
            manager.createNamedQuery(OAuth2AccessTokenEntity.QUERY_EXPIRED_BY_DATE, OAuth2AccessTokenEntity::class.java)
        query.setParameter(OAuth2AccessTokenEntity.PARAM_DATE, Date())
        return LinkedHashSet(getResultPage(query, pageCriteria))
    }

    override val allExpiredRefreshTokens: Set<OAuth2RefreshTokenEntity>
        get() {
            val pageCriteria = DefaultPageCriteria(0, MAXEXPIREDRESULTS)
            return getAllExpiredRefreshTokens(pageCriteria)
        }

    override fun getAllExpiredRefreshTokens(pageCriteria: PageCriteria): Set<OAuth2RefreshTokenEntity> {
        val query =
            manager.createNamedQuery(OAuth2RefreshTokenEntity.QUERY_EXPIRED_BY_DATE, OAuth2RefreshTokenEntity::class.java)
        query.setParameter(OAuth2AccessTokenEntity.PARAM_DATE, Date())
        return LinkedHashSet(getResultPage(query, pageCriteria))
    }

    override fun getAccessTokensForResourceSet(rs: ResourceSet): Set<OAuth2AccessTokenEntity> {
        val query =
            manager.createNamedQuery(OAuth2AccessTokenEntity.QUERY_BY_RESOURCE_SET, OAuth2AccessTokenEntity::class.java)
        query.setParameter(OAuth2AccessTokenEntity.PARAM_RESOURCE_SET_ID, rs.id)
        return LinkedHashSet(query.resultList)
    }

    @Transactional(value = "defaultTransactionManager")
    override fun clearDuplicateAccessTokens() {
        val query =
            manager.createQuery("select a.jwt, count(1) as c from OAuth2AccessTokenEntity a GROUP BY a.jwt HAVING count(1) > 1")
        val resultList: List<Array<Any>> = query.resultList as List<Array<Any>>
        val values: MutableList<JWT?> = ArrayList()
        for (r in resultList) {
            logger.warn("Found duplicate access tokens: {}, {}", (r[0] as JWT).serialize(), r[1])
            values.add(r[0] as JWT)
        }
        if (values.isNotEmpty()) {
            val cb = manager.criteriaBuilder
            val criteriaDelete = cb.createCriteriaDelete(OAuth2AccessTokenEntity::class.java)
            val root = criteriaDelete.from(OAuth2AccessTokenEntity::class.java)
            criteriaDelete.where(root.get<Any>("jwt").`in`(values))
            val result = manager.createQuery(criteriaDelete).executeUpdate()
            logger.warn("Deleted {} duplicate access tokens", result)
        }
    }

    @Transactional(value = "defaultTransactionManager")
    override fun clearDuplicateRefreshTokens() {
        val query =
            manager.createQuery("select a.jwt, count(1) as c from OAuth2RefreshTokenEntity a GROUP BY a.jwt HAVING count(1) > 1")
        val resultList: List<Array<Any>> = query.resultList as List<Array<Any>>
        val values: MutableList<JWT?> = ArrayList()
        for (r in resultList) {
            logger.warn("Found duplicate refresh tokens: {}, {}", (r[0] as JWT).serialize(), r[1])
            values.add(r[0] as JWT)
        }
        if (values.size > 0) {
            val cb = manager.criteriaBuilder
            val criteriaDelete = cb.createCriteriaDelete(OAuth2RefreshTokenEntity::class.java)
            val root = criteriaDelete.from(OAuth2RefreshTokenEntity::class.java)
            criteriaDelete.where(root.get<Any>("jwt").`in`(values))
            val result = manager.createQuery(criteriaDelete).executeUpdate()
            logger.warn("Deleted {} duplicate refresh tokens", result)
        }
    }

    override fun getAccessTokensForApprovedSite(approvedSite: ApprovedSite): List<OAuth2AccessTokenEntity> {
        val queryA =
            manager.createNamedQuery(OAuth2AccessTokenEntity.QUERY_BY_APPROVED_SITE, OAuth2AccessTokenEntity::class.java)
        queryA.setParameter(OAuth2AccessTokenEntity.PARAM_APPROVED_SITE, approvedSite)
        val accessTokens = queryA.resultList
        return accessTokens
    }

    companion object {
        private const val MAXEXPIREDRESULTS = 1000

        private val logger = getLogger<JpaOAuth2TokenRepository>()
    }
}
