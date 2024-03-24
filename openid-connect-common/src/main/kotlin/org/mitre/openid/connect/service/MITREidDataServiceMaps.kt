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
    private val _accessTokenOldToNewIdMap: MutableMap<Long, Long> = HashMap()
    val accessTokenOldToNewIdMap: Map<Long, Long> get() = _accessTokenOldToNewIdMap

    private val _accessTokenToAuthHolderRefs: MutableMap<Long, Long> = HashMap()
    val accessTokenToAuthHolderRefs: Map<Long, Long> get() = _accessTokenToAuthHolderRefs

    private val _accessTokenToClientRefs: MutableMap<Long, String> = HashMap()
    val accessTokenToClientRefs: Map<Long, String> get() = _accessTokenToClientRefs

    private val _accessTokenToRefreshTokenRefs: MutableMap<Long, Long> = HashMap()
    val accessTokenToRefreshTokenRefs: Map<Long, Long> get() = _accessTokenToRefreshTokenRefs

    private val _authHolderOldToNewIdMap: MutableMap<Long, Long> = HashMap()
    val authHolderOldToNewIdMap: Map<Long, Long> get() = _authHolderOldToNewIdMap

    private val _grantOldToNewIdMap: MutableMap<Long, Long> = HashMap()
    val grantOldToNewIdMap: Map<Long, Long> get() = _grantOldToNewIdMap

    val grantToAccessTokensRefs: Map<Long, Set<Long>> = HashMap()

    private val _refreshTokenOldToNewIdMap: MutableMap<Long, Long> = HashMap()
    val refreshTokenOldToNewIdMap: Map<Long, Long> get() = _refreshTokenOldToNewIdMap

    private val _refreshTokenToAuthHolderRefs: MutableMap<Long, Long> = HashMap()
    val refreshTokenToAuthHolderRefs: Map<Long, Long> get() = _refreshTokenToAuthHolderRefs

    private val _refreshTokenToClientRefs: MutableMap<Long, String> = HashMap()
    val refreshTokenToClientRefs: Map<Long, String> get() = _refreshTokenToClientRefs

    private val _whitelistedSiteOldToNewIdMap: MutableMap<Long, Long> = HashMap()
    val whitelistedSiteOldToNewIdMap: Map<Long, Long> get() = HashMap()

    fun clearAll() {
        _refreshTokenToClientRefs.clear()
        _refreshTokenToAuthHolderRefs.clear()
        _accessTokenToClientRefs.clear()
        _accessTokenToAuthHolderRefs.clear()
        _accessTokenToRefreshTokenRefs.clear()
        _refreshTokenOldToNewIdMap.clear()
        _accessTokenOldToNewIdMap.clear()
        _grantOldToNewIdMap.clear()
    }
}
