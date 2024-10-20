package org.mitre.oauth2.token

import org.mitre.oauth2.resolver.ClientResolver
import org.mitre.oauth2.service.DeviceCodeService
import org.mitre.oauth2.service.OAuth2TokenEntityService
import org.mitre.openid.connect.request.OAuth2RequestFactory
import java.util.*

/**
 * Implements https://tools.ietf.org/html/draft-ietf-oauth-device-flow
 *
 * @see DeviceEndpoint
 *
 *
 * @author jricher
 */
class DeviceTokenGranter protected constructor(
    tokenServices: OAuth2TokenEntityService,
    clientDetailsService: ClientResolver,
    requestFactory: OAuth2RequestFactory,
    private val deviceCodeService: DeviceCodeService,
) : AbstractTokenGranter(tokenServices, clientDetailsService, requestFactory, GRANT_TYPE) {
    override val isGrantAllowsRefresh: Boolean get() = true

    companion object {
        const val GRANT_TYPE: String = "urn:ietf:params:oauth:grant-type:device_code"
    }
}
