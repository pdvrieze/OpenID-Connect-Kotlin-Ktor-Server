package io.github.pdvrieze.auth.ktor.plugins

import com.nimbusds.jose.jwk.JWK
import io.github.pdvrieze.auth.exposed.ExposedSystemScopeRepository
import io.github.pdvrieze.auth.exposed.ExposedUserInfoRepository
import org.jetbrains.exposed.sql.Database
import org.mitre.jwt.encryption.service.JWTEncryptionAndDecryptionService
import org.mitre.jwt.encryption.service.impl.DefaultJWTEncryptionAndDecryptionService
import org.mitre.jwt.signer.service.JWTSigningAndValidationService
import org.mitre.jwt.signer.service.impl.DefaultJWTSigningAndValidationService
import org.mitre.oauth2.repository.OAuth2ClientRepository
import org.mitre.oauth2.repository.SystemScopeRepository
import org.mitre.oauth2.service.ClientDetailsEntityService
import org.mitre.oauth2.service.SystemScopeService
import org.mitre.oauth2.service.impl.DefaultOAuth2ClientDetailsEntityService
import org.mitre.oauth2.service.impl.DefaultSystemScopeService
import org.mitre.openid.connect.config.ConfigurationPropertiesBean
import org.mitre.openid.connect.repository.UserInfoRepository
import org.mitre.openid.connect.service.PairwiseIdentiferService
import org.mitre.openid.connect.service.UserInfoService
import org.mitre.openid.connect.service.impl.DefaultUserInfoService

data class OpenIdConfig(
    var issuer: String,
    var database: Database = Database.connect(
        url = "jdbc:h2:mem:test;DB_CLOSE_DELAY=-1",
        user = "root",
        driver = "org.h2.Driver",
    ),
) {

    private var encryptionKeySet: Map<String, JWK> = emptyMap()
    private var signingKeySet: Map<String, JWK> = emptyMap()

    fun resolveDefault(): Resolved = ResolvedImpl(this)

    interface Resolved {
        val config: ConfigurationPropertiesBean
        val scopeRepository: SystemScopeRepository
        val scopeService: SystemScopeService
        val signService: JWTSigningAndValidationService
        val encryptionService: JWTEncryptionAndDecryptionService
        val userInfoRepository: UserInfoRepository
        val clientService: ClientDetailsEntityService
        val pairwiseIdentifierService: PairwiseIdentiferService
        val userService: UserInfoService
        val clientRepository: OAuth2ClientRepository
    }

    private class ResolvedImpl(config: OpenIdConfig) : Resolved {
        override val config: ConfigurationPropertiesBean = ConfigurationPropertiesBean(config.issuer)

        override val scopeRepository: SystemScopeRepository = ExposedSystemScopeRepository(config.database)

        override val scopeService: SystemScopeService = DefaultSystemScopeService(scopeRepository)

        override val signService: JWTSigningAndValidationService =
            DefaultJWTSigningAndValidationService(config.signingKeySet)

        override val encryptionService: JWTEncryptionAndDecryptionService =
            DefaultJWTEncryptionAndDecryptionService(config.encryptionKeySet)

        override val userInfoRepository: UserInfoRepository = ExposedUserInfoRepository(config.database)

        override val pairwiseIdentifierService: PairwiseIdentiferService = TODO()

        override val userService: UserInfoService =
            DefaultUserInfoService(userInfoRepository, clientService, pairwiseIdentifierService)

        override val clientRepository: OAuth2ClientRepository = TODO()

        override val clientService: ClientDetailsEntityService = DefaultOAuth2ClientDetailsEntityService(
            clientRepository = clientRepository,
            tokenRepository = TODO(),
            approvedSiteService = TODO(),
            whitelistedSiteService = TODO(),
            blacklistedSiteService = TODO(),
            scopeService = TODO(),
            statsService = TODO(),
            resourceSetService = TODO(),
            config = this.config,
        )
    }
}
