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
package org.mitre.oauth2.service.impl

import org.mitre.data.AbstractPageOperationTemplate
import org.mitre.oauth2.model.AuthenticatedAuthorizationRequest
import org.mitre.oauth2.model.DeviceCode
import org.mitre.oauth2.model.OAuthClientDetails
import org.mitre.oauth2.model.jpa.AuthenticationHolderEntity
import org.mitre.oauth2.repository.DeviceCodeRepository
import org.mitre.oauth2.service.DeviceCodeService
import org.mitre.oauth2.util.requireId
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional
import java.util.*

/**
 * @author jricher
 */
@Service("defaultDeviceCodeService")
class SpringDeviceCodeService : DeviceCodeService {
    @Autowired
    private lateinit var repository: DeviceCodeRepository

    private val randomGenerator = RandomValueStringGenerator()

    /* (non-Javadoc)
	 * @see org.mitre.oauth2.service.DeviceCodeService#save(org.mitre.oauth2.model.DeviceCode)
	 */
    override fun createNewDeviceCode(
        requestedScopes: Set<String>,
        client: OAuthClientDetails,
        parameters: Map<String, String>?
    ): DeviceCode {
        // create a device code, should be big and random

        val deviceCode = UUID.randomUUID().toString()

        // create a user code, should be random but small and typable, and always uppercase (lookup is case insensitive)
        val userCode = randomGenerator.generate().uppercase(Locale.getDefault())

        val dc = DeviceCode(
            deviceCode = deviceCode,
            userCode = userCode,
            scope = requestedScopes,
            clientId = client.clientId,
            params = parameters
        )

        if (client.deviceCodeValiditySeconds != null) {
            dc.expiration = Date(System.currentTimeMillis() + client.deviceCodeValiditySeconds!! * 1000L)
        }

        dc.isApproved = false

        return repository.save(dc)
    }

    /* (non-Javadoc)
	 * @see org.mitre.oauth2.service.DeviceCodeService#lookUpByUserCode(java.lang.String)
	 */
    override fun lookUpByUserCode(userCode: String): DeviceCode? {
        // always up-case the code for lookup
        return repository.getByUserCode(userCode.uppercase(Locale.getDefault()))
    }


    override fun approveDeviceCode(dc: DeviceCode, o2Auth: AuthenticatedAuthorizationRequest): DeviceCode? {
        val found = requireNotNull(repository.getById(dc.id.requireId())) { "No device code found"}

        found.isApproved = true

        val authHolder = AuthenticationHolderEntity(o2Auth)

        found.authenticationHolder = authHolder

        return repository.save(found)
    }

    /* (non-Javadoc)
	 * @see org.mitre.oauth2.service.DeviceCodeService#consumeDeviceCode(java.lang.String, org.springframework.security.oauth2.provider.ClientDetails)
	 */
    override fun findDeviceCode(deviceCode: String, client: OAuthClientDetails): DeviceCode? {
        val found = repository.getByDeviceCode(deviceCode)

        return when {
            // didn't find the code, return null
            found == null -> null

            // make sure the client matches, if so, we're good
            found.clientId == client.clientId -> found

            // if the clients don't match, pretend the code wasn't found
            else -> null
        }
    }


    /* (non-Javadoc)
	 * @see org.mitre.oauth2.service.DeviceCodeService#clearExpiredDeviceCodes()
	 */
    @Transactional(value = "defaultTransactionManager")
    override fun clearExpiredDeviceCodes() {
        object : AbstractPageOperationTemplate<DeviceCode>("clearExpiredDeviceCodes") {
            override fun fetchPage(): Collection<DeviceCode> {
                return repository.expiredCodes
            }

            override fun doOperation(item: DeviceCode) {
                repository.remove(item)
            }
        }.execute()
    }

    /* (non-Javadoc)
	 * @see org.mitre.oauth2.service.DeviceCodeService#clearDeviceCode(java.lang.String, org.springframework.security.oauth2.provider.ClientDetails)
	 */
    override fun clearDeviceCode(deviceCode: String, client: OAuthClientDetails) {
        findDeviceCode(deviceCode, client)?.let {
            // make sure it's not used twice
            repository.remove(it)
        }
    }
}
