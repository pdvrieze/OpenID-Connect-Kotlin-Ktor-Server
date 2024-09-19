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
package org.mitre.openid.connect.service

/**
 * @author jricher
 */
class MITREidDataServiceMaps {
    val accessTokenOldToNewIdMap: MutableMap<Long, Long> = HashMap()

    val accessTokenToAuthHolderRefs: MutableMap<Long, Long> = HashMap()

    val accessTokenToClientRefs: MutableMap<Long, String> = HashMap()

    val accessTokenToRefreshTokenRefs: MutableMap<Long, Long> = HashMap()

    val authHolderOldToNewIdMap: MutableMap<Long, Long> = HashMap()

    val grantOldToNewIdMap: MutableMap<Long, Long> = HashMap()

    val grantToAccessTokensRefs: MutableMap<Long, Set<Long>> = HashMap()

    val refreshTokenOldToNewIdMap: MutableMap<Long, Long> = HashMap()

    val refreshTokenToAuthHolderRefs: MutableMap<Long, Long> = HashMap()

    val refreshTokenToClientRefs: MutableMap<Long, String> = HashMap()

    val whitelistedSiteOldToNewIdMap: MutableMap<Long, Long> = HashMap()

    fun clearAll() {
        refreshTokenToClientRefs.clear()
        refreshTokenToAuthHolderRefs.clear()
        accessTokenToClientRefs.clear()
        accessTokenToAuthHolderRefs.clear()
        accessTokenToRefreshTokenRefs.clear()
        authHolderOldToNewIdMap.clear()
        refreshTokenOldToNewIdMap.clear()
        accessTokenOldToNewIdMap.clear()
        grantOldToNewIdMap.clear()
        grantToAccessTokensRefs.clear()
        whitelistedSiteOldToNewIdMap.clear()
    }
}