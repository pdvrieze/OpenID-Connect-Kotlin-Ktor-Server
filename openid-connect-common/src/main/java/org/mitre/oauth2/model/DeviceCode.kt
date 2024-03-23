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
import javax.persistence.*

/**
 * @author jricher
 */
@Entity
@Table(name = "device_code")
@NamedQueries(NamedQuery(name = DeviceCode.QUERY_BY_USER_CODE, query = "select d from DeviceCode d where d.userCode = :" + DeviceCode.PARAM_USER_CODE), NamedQuery(name = DeviceCode.QUERY_BY_DEVICE_CODE, query = "select d from DeviceCode d where d.deviceCode = :" + DeviceCode.PARAM_DEVICE_CODE), NamedQuery(name = DeviceCode.QUERY_EXPIRED_BY_DATE, query = "select d from DeviceCode d where d.expiration <= :" + DeviceCode.PARAM_DATE))
class DeviceCode {
	@get:Column(name = "id")
    @get:GeneratedValue(strategy = GenerationType.IDENTITY)
    @get:Id
    var id: Long? = null

	@get:Column(name = "device_code")
    @get:Basic
    var deviceCode: String? = null

	@get:Column(name = "user_code")
    @get:Basic
    var userCode: String? = null

	@get:Column(name = "scope")
    @get:CollectionTable(name = "device_code_scope", joinColumns = [JoinColumn(name = "owner_id")])
    @get:ElementCollection(fetch = FetchType.EAGER)
    var scope: Set<String>? = null

	@get:Column(name = "expiration")
    @get:Temporal(TemporalType.TIMESTAMP)
    @get:Basic
    var expiration: Date? = null

	@get:Column(name = "client_id")
    @get:Basic
    var clientId: String? = null

	@get:MapKeyColumn(name = "param")
    @get:Column(name = "val")
    @get:CollectionTable(name = "device_code_request_parameter", joinColumns = [JoinColumn(name = "owner_id")])
    @get:ElementCollection(fetch = FetchType.EAGER)
    var requestParameters: Map<String, String>? = null

    @get:Column(name = "approved")
    @get:Basic
    var isApproved: Boolean = false

    /**
     * The authentication in place when this token was created.
     */
	@get:JoinColumn(name = "auth_holder_id")
    @get:ManyToOne
    var authenticationHolder: AuthenticationHolderEntity? = null

    @JvmOverloads
    constructor(
        deviceCode: String? = null,
        userCode: String? = null,
        scope: Set<String>? = null,
        clientId: String? = null,
        params: Map<String, String>? = null
    ) {
        this.deviceCode = deviceCode
        this.userCode = userCode
        this.scope = scope
        this.clientId = clientId
        this.requestParameters = params
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
