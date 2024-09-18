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
package org.mitre.oauth2.service

import org.mitre.oauth2.exception.DeviceCodeCreationException
import org.mitre.oauth2.model.DeviceCode
import org.mitre.oauth2.model.OAuth2Authentication
import org.mitre.oauth2.model.OAuthClientDetails

/**
 * @author jricher
 */
interface DeviceCodeService {
    fun lookUpByUserCode(userCode: String): DeviceCode?

    fun approveDeviceCode(dc: DeviceCode, o2Auth: OAuth2Authentication): DeviceCode?

    fun findDeviceCode(deviceCode: String, client: OAuthClientDetails): DeviceCode?


    fun clearDeviceCode(deviceCode: String, client: OAuthClientDetails)

    @Throws(DeviceCodeCreationException::class)
    fun createNewDeviceCode(
        requestedScopes: Set<String>,
        client: OAuthClientDetails,
        parameters: Map<String, String>?
    ): DeviceCode


    fun clearExpiredDeviceCodes()
}
