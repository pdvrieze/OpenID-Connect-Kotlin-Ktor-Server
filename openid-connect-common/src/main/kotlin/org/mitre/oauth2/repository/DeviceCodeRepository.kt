package org.mitre.oauth2.repository

import org.mitre.oauth2.model.DeviceCode

/**
 * @author jricher
 */
interface DeviceCodeRepository {
    val expiredCodes: Collection<DeviceCode>

    fun getById(id: Long): DeviceCode?

    fun getByDeviceCode(deviceCode: String): DeviceCode?

    fun remove(code: DeviceCode)

    fun save(code: DeviceCode): DeviceCode

    fun getByUserCode(userCode: String): DeviceCode?
}
