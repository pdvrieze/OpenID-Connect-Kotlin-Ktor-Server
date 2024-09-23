package org.mitre.openid.connect.token

import org.mitre.jwt.signer.service.JWTSigningAndValidationService
import org.mitre.oauth2.service.ClientDetailsEntityService
import org.mitre.openid.connect.config.ConfigurationPropertiesBean
import org.mitre.openid.connect.service.OIDCTokenService
import org.mitre.openid.connect.service.UserInfoService

open class ConnectTokenEnhancerImpl(
    override val clientService: ClientDetailsEntityService,
    override val configBean: ConfigurationPropertiesBean,
    override val jwtService: JWTSigningAndValidationService,
    override val userInfoService: UserInfoService,
    connectTokenServiceProvider: () -> OIDCTokenService
) : ConnectTokenEnhancer() {

    override val connectTokenService: OIDCTokenService by lazy(connectTokenServiceProvider)
}
