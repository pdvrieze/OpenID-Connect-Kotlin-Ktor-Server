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

import org.mitre.openid.connect.model.BlacklistedSite

/**
 * @author jricher
 */
interface BlacklistedSiteService {
    val all: Collection<BlacklistedSite>?

    fun getById(id: java.lang.Long): BlacklistedSite?

    fun remove(blacklistedSite: BlacklistedSite)

    fun saveNew(blacklistedSite: BlacklistedSite): BlacklistedSite

    fun update(oldBlacklistedSite: BlacklistedSite, blacklistedSite: BlacklistedSite): BlacklistedSite

    fun isBlacklisted(uri: String): Boolean
}