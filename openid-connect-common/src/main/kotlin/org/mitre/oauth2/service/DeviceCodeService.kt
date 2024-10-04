package org.mitre.oauth2.service

import org.mitre.oauth2.exception.DeviceCodeCreationException
import org.mitre.oauth2.model.DeviceCode
import org.mitre.oauth2.model.OAuth2RequestAuthentication
import org.mitre.oauth2.model.OAuthClientDetails

/**
 * @author jricher
 */
interface DeviceCodeService {
    fun lookUpByUserCode(userCode: String): DeviceCode?

    fun approveDeviceCode(dc: DeviceCode, o2Auth: OAuth2RequestAuthentication): DeviceCode?

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
