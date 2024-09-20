package io.github.pdvrieze.auth.ktor.plugins

import com.nimbusds.jose.jwk.JWK
import io.github.pdvrieze.auth.repository.exposed.ExposedAuthenticationHolderRepository
import io.github.pdvrieze.auth.repository.exposed.ExposedOauth2ClientRepository
import io.github.pdvrieze.auth.repository.exposed.ExposedOauth2TokenRepository
import io.github.pdvrieze.auth.repository.exposed.ExposedSystemScopeRepository
import io.github.pdvrieze.auth.service.impl.DefaultIntrospectionResultAssembler
import io.github.pdvrieze.auth.uma.repository.exposed.ExposedApprovedSiteRepository
import io.github.pdvrieze.auth.uma.repository.exposed.ExposedBlacklistedSiteRepository
import io.github.pdvrieze.auth.uma.repository.exposed.ExposedPairwiseIdentifierRepository
import io.github.pdvrieze.auth.uma.repository.exposed.ExposedPermissionRepository
import io.github.pdvrieze.auth.uma.repository.exposed.ExposedResourceSetRepository
import io.github.pdvrieze.auth.uma.repository.exposed.ExposedUserInfoRepository
import io.github.pdvrieze.auth.uma.repository.exposed.ExposedWhitelistedSiteRepository
import org.jetbrains.exposed.sql.Database
import org.mitre.jwt.encryption.service.JWTEncryptionAndDecryptionService
import org.mitre.jwt.encryption.service.impl.DefaultJWTEncryptionAndDecryptionService
import org.mitre.jwt.signer.service.JWTSigningAndValidationService
import org.mitre.jwt.signer.service.impl.DefaultJWTSigningAndValidationService
import org.mitre.oauth2.TokenEnhancer
import org.mitre.oauth2.repository.AuthenticationHolderRepository
import org.mitre.oauth2.repository.OAuth2ClientRepository
import org.mitre.oauth2.repository.OAuth2TokenRepository
import org.mitre.oauth2.repository.SystemScopeRepository
import org.mitre.oauth2.service.ClientDetailsEntityService
import org.mitre.oauth2.service.DeviceCodeService
import org.mitre.oauth2.service.JsonIntrospectionResultAssembler
import org.mitre.oauth2.service.OAuth2TokenEntityService
import org.mitre.oauth2.service.SystemScopeService
import org.mitre.oauth2.service.impl.DefaultDeviceCodeService
import org.mitre.oauth2.service.impl.DefaultOAuth2ClientDetailsEntityService
import org.mitre.oauth2.service.impl.DefaultOAuth2ProviderTokenService
import org.mitre.oauth2.service.impl.DefaultSystemScopeService
import org.mitre.openid.connect.config.ConfigurationPropertiesBean
import org.mitre.openid.connect.repository.ApprovedSiteRepository
import org.mitre.openid.connect.repository.BlacklistedSiteRepository
import org.mitre.openid.connect.repository.PairwiseIdentifierRepository
import org.mitre.openid.connect.repository.UserInfoRepository
import org.mitre.openid.connect.repository.WhitelistedSiteRepository
import org.mitre.openid.connect.service.ApprovedSiteService
import org.mitre.openid.connect.service.BlacklistedSiteService
import org.mitre.openid.connect.service.OIDCTokenService
import org.mitre.openid.connect.service.PairwiseIdentifierService
import org.mitre.openid.connect.service.StatsService
import org.mitre.openid.connect.service.UserInfoService
import org.mitre.openid.connect.service.WhitelistedSiteService
import org.mitre.openid.connect.service.impl.DefaultApprovedSiteService
import org.mitre.openid.connect.service.impl.DefaultBlacklistedSiteService
import org.mitre.openid.connect.service.impl.DefaultOIDCTokenService
import org.mitre.openid.connect.service.impl.DefaultUserInfoService
import org.mitre.openid.connect.service.impl.DefaultWhitelistedSiteService
import org.mitre.openid.connect.service.impl.UUIDPairwiseIdentiferService
import org.mitre.openid.connect.token.ConnectTokenEnhancerImpl
import org.mitre.uma.repository.PermissionRepository
import org.mitre.uma.repository.ResourceSetRepository
import org.mitre.uma.service.ResourceSetService
import org.mitre.uma.service.impl.DefaultResourceSetService
import org.mitre.web.util.OpenIdContext

data class OpenIdConfigurator(
    var issuer: String,
    var database: Database = Database.connect(
        url = "jdbc:h2:mem:test;DB_CLOSE_DELAY=-1",
        user = "root",
        driver = "org.h2.Driver",
    ),
) {

    private var encryptionKeySet: Map<String, JWK> = emptyMap()
    private var signingKeySet: Map<String, JWK> = emptyMap()

    fun resolveDefault(): OpenIdContext = ResolvedImpl(this)

    private class ResolvedImpl(configurator: OpenIdConfigurator) : OpenIdContext {
        @Deprecated("Hopefully not needed")
        val database = configurator.database

        override val config: ConfigurationPropertiesBean = ConfigurationPropertiesBean(configurator.issuer)

        override val scopeRepository: SystemScopeRepository = ExposedSystemScopeRepository(configurator.database)

        override val scopeService: SystemScopeService = DefaultSystemScopeService(scopeRepository)

        override val signService: JWTSigningAndValidationService =
            DefaultJWTSigningAndValidationService(configurator.signingKeySet)

        override val encryptionService: JWTEncryptionAndDecryptionService =
            DefaultJWTEncryptionAndDecryptionService(configurator.encryptionKeySet)

        override val userInfoRepository: UserInfoRepository = ExposedUserInfoRepository(configurator.database)

        val pairwiseIdentiferRepository: PairwiseIdentifierRepository = ExposedPairwiseIdentifierRepository(configurator.database)

        override val pairwiseIdentifierService: PairwiseIdentifierService = UUIDPairwiseIdentiferService(pairwiseIdentiferRepository)

        override val clientRepository: OAuth2ClientRepository = ExposedOauth2ClientRepository(configurator.database)

        val authenticationHolderRepository: AuthenticationHolderRepository = ExposedAuthenticationHolderRepository(configurator.database)

        override val tokenRepository: OAuth2TokenRepository = ExposedOauth2TokenRepository(
            database = configurator.database,
            authenticationHolderRepository = authenticationHolderRepository,
            clientRepository = clientRepository
        )

        val approvedSiteRepository: ApprovedSiteRepository = ExposedApprovedSiteRepository(configurator.database)

        override val approvedSiteService : ApprovedSiteService = DefaultApprovedSiteService(
            approvedSiteRepository = approvedSiteRepository,
            tokenRepository = tokenRepository,
        )

        val statsService: StatsService = (approvedSiteService as DefaultApprovedSiteService).getStatsService()

        val whitelistedSiteRepository: WhitelistedSiteRepository = ExposedWhitelistedSiteRepository(configurator.database)

        val whitelistedSiteService: WhitelistedSiteService = DefaultWhitelistedSiteService(whitelistedSiteRepository)

        val blacklistedSiteRepository: BlacklistedSiteRepository = ExposedBlacklistedSiteRepository(configurator.database)

        val blacklistedSiteService: BlacklistedSiteService = DefaultBlacklistedSiteService(blacklistedSiteRepository)

        val resourceSetRepository: ResourceSetRepository = ExposedResourceSetRepository(configurator.database)

        val ticketRepository: PermissionRepository = ExposedPermissionRepository(configurator.database, resourceSetRepository)

        override val resourceSetService: ResourceSetService = DefaultResourceSetService(
            repository = resourceSetRepository,
            tokenRepository = tokenRepository,
            ticketRepository = ticketRepository,
        )

        override val clientService: ClientDetailsEntityService = DefaultOAuth2ClientDetailsEntityService(
            clientRepository = clientRepository,
            tokenRepository = tokenRepository,
            approvedSiteService = approvedSiteService,
            whitelistedSiteService = whitelistedSiteService,
            blacklistedSiteService = blacklistedSiteService,
            scopeService = scopeService,
            statsService = statsService,
            resourceSetService = resourceSetService,
            config = this.config,
        )

        override val introspectionResultAssembler: JsonIntrospectionResultAssembler =
            DefaultIntrospectionResultAssembler()

        override val userInfoService: UserInfoService = DefaultUserInfoService(
            userInfoRepository, clientService, pairwiseIdentifierService
        )

        val routeSetService: ResourceSetService = DefaultResourceSetService(resourceSetRepository, tokenRepository, ticketRepository)

        val clientDetailsService: ClientDetailsEntityService = DefaultOAuth2ClientDetailsEntityService(
            clientRepository,
            tokenRepository,
            approvedSiteService,
            whitelistedSiteService,
            blacklistedSiteService,
            scopeService,
            statsService,
            routeSetService,
            this.config
        )

        val jwtService: JWTSigningAndValidationService = DefaultJWTSigningAndValidationService(configurator.signingKeySet)

        val oidTokenService: OIDCTokenService = DefaultOIDCTokenService()


        override val deviceCodeService: DeviceCodeService = DefaultDeviceCodeService()

        override val userService: UserInfoService =
            DefaultUserInfoService(userInfoRepository, clientService, pairwiseIdentifierService)

        val tokenEnhancer: TokenEnhancer  = ConnectTokenEnhancerImpl(clientDetailsService, config, jwtService, userService, oidTokenService)

        override val tokenService: OAuth2TokenEntityService = DefaultOAuth2ProviderTokenService(
            tokenRepository, authenticationHolderRepository, clientDetailsService, tokenEnhancer, scopeService, approvedSiteService
        )

    }
}
