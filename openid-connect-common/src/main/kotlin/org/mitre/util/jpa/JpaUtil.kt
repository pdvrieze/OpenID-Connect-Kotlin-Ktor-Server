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
package org.mitre.util.jpa

import org.mitre.data.PageCriteria
import javax.persistence.EntityManager
import javax.persistence.TypedQuery

/**
 * @author mfranklin
 * Date: 4/28/11
 * Time: 2:13 PM
 */
object JpaUtil {
    @JvmStatic
    fun <T> getSingleResult(list: List<T>): T? {
        return when (list.size) {
            0 -> null
            1 -> list[0]
            else -> throw IllegalStateException("Expected single result, got " + list.size)
        }
    }


    /**
     * Get a page of results from the specified TypedQuery
     * by using the given PageCriteria to limit the query
     * results. The PageCriteria will override any size or
     * offset already specified on the query.
     *
     * @param T  the type parameter
     * @param query the query
     * @param pageCriteria the page criteria
     */
    @JvmStatic
    fun <T> getResultPage(query: TypedQuery<T>, pageCriteria: PageCriteria): List<T> {
        query.setMaxResults(pageCriteria.pageSize)
        query.setFirstResult(pageCriteria.pageNumber * pageCriteria.pageSize)

        return query.resultList
    }

    @JvmStatic
    fun <T, I> saveOrUpdate(id: I, entityManager: EntityManager, entity: T): T {
        val tmp = entityManager.merge(entity)
        entityManager.flush()
        return tmp
    }
}
