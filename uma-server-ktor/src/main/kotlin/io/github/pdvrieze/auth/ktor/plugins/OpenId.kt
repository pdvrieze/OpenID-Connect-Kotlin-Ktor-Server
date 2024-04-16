package io.github.pdvrieze.auth.ktor.plugins

import io.ktor.server.application.*
import org.mitre.jwt.encryption.service.JWTEncryptionAndDecryptionService
import org.mitre.jwt.signer.service.JWTSigningAndValidationService
import org.mitre.oauth2.service.SystemScopeService
import org.mitre.openid.connect.config.ConfigurationPropertiesBean
import org.mitre.openid.connect.service.UserInfoService

fun Application.openIdContext(issuer: String, config: OpenIdConfig = OpenIdConfig(issuer), configure: OpenIdContext.() -> Unit = {}) {
    OpenIdContextImpl(this, config).configure()
}

interface OpenIdContext {
    val config: ConfigurationPropertiesBean
    val scopeService: SystemScopeService
    val signService: JWTSigningAndValidationService
    val encryptionService: JWTEncryptionAndDecryptionService
    val userService: UserInfoService

    val application: Application
}

interface OpenIdContextExt : OpenIdContext {
    val openIdContext: OpenIdContext

    override val application: Application get() = openIdContext.application
    override val config: ConfigurationPropertiesBean get() = openIdContext.config
    override val scopeService: SystemScopeService get() = openIdContext.scopeService
    override val signService: JWTSigningAndValidationService get() = openIdContext.signService
    override val encryptionService: JWTEncryptionAndDecryptionService get() = openIdContext.encryptionService
    override val userService: UserInfoService get() = openIdContext.userService
}

private class OpenIdContextImpl(
    override val application: Application,
    override val config: ConfigurationPropertiesBean,
    override val scopeService: SystemScopeService,
    override val signService: JWTSigningAndValidationService,
    override val encryptionService: JWTEncryptionAndDecryptionService,
    override val userService: UserInfoService,
) : OpenIdContext {

    constructor(
        application: Application,
        config: OpenIdConfig
    ): this(application, config.resolveDefault())

    constructor(
        application: Application,
        r: OpenIdConfig.Resolved,
    ) : this(
        application,
        config = r.config,
        scopeService = r.scopeService,
        signService = r.signService,
        encryptionService = r.encryptionService,
        userService = r.userService,
    )

}
