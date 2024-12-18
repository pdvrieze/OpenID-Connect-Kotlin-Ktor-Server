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

import org.mitre.openid.connect.model.UserInfo

/**
 * Interface for UserInfo service
 *
 * @author Michael Joseph Walsh
 */
interface UserInfoService {
    /**
     * Get the UserInfo for the given username (usually maps to the
     * preferredUsername field).
     */
    fun getByUsername(username: String): UserInfo?

    /**
     * Get the UserInfo for the given username (usually maps to the
     * preferredUsername field) and clientId. This allows pairwise
     * client identifiers where appropriate.
     */
    fun getByUsernameAndClientId(username: String, clientId: String): UserInfo?

    /**
     * Get the user registered at this server with the given email address.
     */
    fun getByEmailAddress(email: String): UserInfo?
}
