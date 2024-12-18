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
package org.mitre.openid.connect.service

import org.mitre.openid.connect.model.ClientStat

/**
 * @author jricher
 */
interface StatsService {
    /**
     * Calculate summary statistics
     * approvalCount: total approved sites
     * userCount: unique users
     * clientCount: unique clients
     */
    val summaryStats: Map<String, Int>

    /**
     * Calculate the usage count for a single client
     *
     * @param clientId the id of the client to search on
     */
    fun getCountForClientId(clientId: String): ClientStat?

    /**
     * Trigger the stats to be recalculated upon next update.
     */
    fun resetCache()
}
