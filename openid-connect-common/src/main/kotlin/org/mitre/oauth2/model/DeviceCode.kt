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
package org.mitre.oauth2.model

import java.util.*

/**
 * @author jricher
 *
 * @property authenticationHolder The authentication in place when this token was created.
 */
//@NamedQueries(NamedQuery(name = DeviceCode.QUERY_BY_USER_CODE, query = "select d from DeviceCode d where d.userCode = :" + DeviceCode.PARAM_USER_CODE),
//              NamedQuery(name = DeviceCode.QUERY_BY_DEVICE_CODE, query = "select d from DeviceCode d where d.deviceCode = :" + DeviceCode.PARAM_DEVICE_CODE),
//              NamedQuery(name = DeviceCode.QUERY_EXPIRED_BY_DATE, query = "select d from DeviceCode d where d.expiration <= :" + DeviceCode.PARAM_DATE))
class DeviceCode(
    var id: Long? = null,
    var deviceCode: String? = null,
    var userCode: String? = null,
    var scope: Set<String>? = null,
    var expiration: Date? = null,
    var clientId: String? = null,
    var requestParameters: Map<String, String>? = null,
    var isApproved: Boolean? = false,
    var authenticationHolder: AuthenticationHolderEntity? = null,
) {

    constructor(
        id: Long? = null,
        deviceCode: String? = null,
        userCode: String? = null,
        expiration: Date? = null,
        scope: Set<String>? = null,
        clientId: String? = null,
        approved: Boolean? = null,
        authenticationHolder: AuthenticationHolderEntity? = null,
        params: Map<String, String>? = null,
    ) : this(
        id = id,
        deviceCode = deviceCode,
        userCode = userCode,
        scope = scope,
        expiration = expiration,
        clientId = clientId,
        requestParameters = params,
        isApproved = approved,
        authenticationHolder = authenticationHolder,
    ) {
        this.deviceCode = deviceCode
        this.userCode = userCode
        this.expiration = expiration
        this.scope = scope
        this.clientId = clientId
        this.isApproved = approved
        this.requestParameters = params
        this.authenticationHolder = authenticationHolder
    }

    fun copy(
        id: Long? = this.id,
        deviceCode: String? = this.deviceCode,
        userCode: String? = this.userCode,
        expiration: Date? = this.expiration,
        scope: Set<String>? = this.scope,
        clientId: String? = this.clientId,
        approved: Boolean? = this.isApproved,
        authenticationHolder: AuthenticationHolderEntity? = this.authenticationHolder,
        params: Map<String, String>? = this.requestParameters,
    ): DeviceCode {
        return DeviceCode(id, deviceCode, userCode, expiration, scope, clientId, approved, authenticationHolder, params)
    }


    companion object {
        const val QUERY_BY_USER_CODE: String = "DeviceCode.queryByUserCode"
        const val QUERY_BY_DEVICE_CODE: String = "DeviceCode.queryByDeviceCode"
        const val QUERY_EXPIRED_BY_DATE: String = "DeviceCode.queryExpiredByDate"

        const val PARAM_USER_CODE: String = "userCode"
        const val PARAM_DEVICE_CODE: String = "deviceCode"
        const val PARAM_DATE: String = "date"
    }
}
