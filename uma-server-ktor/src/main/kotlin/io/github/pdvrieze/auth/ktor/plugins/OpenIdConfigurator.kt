package io.github.pdvrieze.auth.ktor.plugins

import com.nimbusds.jose.jwk.JWK
import io.github.pdvrieze.auth.repository.exposed.ExposedAuthenticationHolderRepository
import io.github.pdvrieze.auth.repository.exposed.ExposedOauth2ClientRepository
import io.github.pdvrieze.auth.repository.exposed.ExposedOauth2TokenRepository
import io.github.pdvrieze.auth.repository.exposed.ExposedSystemScopeRepository
import io.github.pdvrieze.auth.service.impl.BlacklistAwareRedirectResolver
import io.github.pdvrieze.auth.service.impl.DefaultIntrospectionResultAssembler
import io.github.pdvrieze.auth.uma.repository.exposed.ExposedApprovedSiteRepository
import io.github.pdvrieze.auth.uma.repository.exposed.ExposedBlacklistedSiteRepository
import io.github.pdvrieze.auth.uma.repository.exposed.ExposedPairwiseIdentifierRepository
import io.github.pdvrieze.auth.uma.repository.exposed.ExposedPermissionRepository
import io.github.pdvrieze.auth.uma.repository.exposed.ExposedResourceSetRepository
import io.github.pdvrieze.auth.uma.repository.exposed.ExposedUserInfoRepository
import io.github.pdvrieze.auth.uma.repository.exposed.ExposedWhitelistedSiteRepository
import io.github.pdvrieze.openid.web.views.DefaultHtmlViews
import io.ktor.client.*
import io.ktor.client.engine.java.*
import io.ktor.server.application.*
import io.ktor.server.auth.*
import io.ktor.util.*
import org.jetbrains.exposed.sql.Database
import org.mitre.jwt.encryption.service.JWTEncryptionAndDecryptionService
import org.mitre.jwt.encryption.service.impl.DefaultJWTEncryptionAndDecryptionService
import org.mitre.jwt.signer.service.ClientKeyCacheService
import org.mitre.jwt.signer.service.JWTSigningAndValidationService
import org.mitre.jwt.signer.service.impl.DefaultClientKeyCacheService
import org.mitre.jwt.signer.service.impl.DefaultJWTSigningAndValidationService
import org.mitre.jwt.signer.service.impl.SymmetricKeyJWTValidatorCacheService
import org.mitre.jwt.signer.service.impl.ktor.KtorJWKSetCacheService
import org.mitre.oauth2.TokenEnhancer
import org.mitre.oauth2.model.Authentication
import org.mitre.oauth2.model.GrantedAuthority
import org.mitre.oauth2.repository.AuthenticationHolderRepository
import org.mitre.oauth2.repository.OAuth2ClientRepository
import org.mitre.oauth2.repository.OAuth2TokenRepository
import org.mitre.oauth2.repository.SystemScopeRepository
import org.mitre.oauth2.service.ClientDetailsEntityService
import org.mitre.oauth2.service.DeviceCodeService
import org.mitre.oauth2.service.JsonIntrospectionResultAssembler
import org.mitre.oauth2.service.OAuth2TokenEntityService
import org.mitre.oauth2.service.RedirectResolver
import org.mitre.oauth2.service.SystemScopeService
import org.mitre.oauth2.service.impl.DefaultDeviceCodeService
import org.mitre.oauth2.service.impl.DefaultOAuth2ClientDetailsEntityService
import org.mitre.oauth2.service.impl.DefaultOAuth2ProviderTokenService
import org.mitre.oauth2.service.impl.DefaultSystemScopeService
import org.mitre.openid.connect.config.ConfigurationPropertiesBean
import org.mitre.openid.connect.config.JsonMessageSource
import org.mitre.openid.connect.repository.ApprovedSiteRepository
import org.mitre.openid.connect.repository.BlacklistedSiteRepository
import org.mitre.openid.connect.repository.PairwiseIdentifierRepository
import org.mitre.openid.connect.repository.UserInfoRepository
import org.mitre.openid.connect.repository.WhitelistedSiteRepository
import org.mitre.openid.connect.request.KtorConnectOAuth2RequestFactory
import org.mitre.openid.connect.request.KtorOAuth2RequestFactory
import org.mitre.openid.connect.service.BlacklistedSiteService
import org.mitre.openid.connect.service.OIDCTokenService
import org.mitre.openid.connect.service.PairwiseIdentifierService
import org.mitre.openid.connect.service.ScopeClaimTranslationService
import org.mitre.openid.connect.service.StatsService
import org.mitre.openid.connect.service.UserInfoService
import org.mitre.openid.connect.service.WhitelistedSiteService
import org.mitre.openid.connect.service.impl.DefaultScopeClaimTranslationService
import org.mitre.openid.connect.service.impl.DefaultWhitelistedSiteService
import org.mitre.openid.connect.service.impl.KtorOIDCTokenService
import org.mitre.openid.connect.service.impl.UUIDPairwiseIdentiferService
import org.mitre.openid.connect.service.impl.ktor.DefaultApprovedSiteService
import org.mitre.openid.connect.service.impl.ktor.DefaultBlacklistedSiteService
import org.mitre.openid.connect.service.impl.ktor.DefaultUserInfoService
import org.mitre.openid.connect.token.ConnectTokenEnhancerImpl
import org.mitre.uma.repository.PermissionRepository
import org.mitre.uma.repository.ResourceSetRepository
import org.mitre.uma.service.ClaimsProcessingService
import org.mitre.uma.service.PermissionService
import org.mitre.uma.service.ResourceSetService
import org.mitre.uma.service.SavedRegisteredClientService
import org.mitre.uma.service.UmaTokenService
import org.mitre.uma.service.impl.DefaultPermissionService
import org.mitre.uma.service.impl.DefaultResourceSetService
import org.mitre.uma.service.impl.MatchAllClaimsOnAnyPolicy
import org.mitre.uma.service.impl.ktor.KtorRegisteredClientService
import org.mitre.util.UserIdPrincipalAuthentication
import org.mitre.web.HtmlViews
import org.mitre.web.util.OpenIdContext

data class OpenIdConfigurator(
    var issuer: String,
    var database: Database = Database.connect(
        url = "jdbc:h2:mem:test;DB_CLOSE_DELAY=-1",
        user = "root",
        driver = "org.h2.Driver",
    ),
    var httpClient: HttpClient = HttpClient(Java),
) {

    private var topBarTitle: String = "Ktor OpenId provider"
    private var encryptionKeySet: Map<String, JWK> = emptyMap()
    private var signingKeySet: Map<String, JWK> = emptyMap()

    fun resolveDefault(): OpenIdContext = ResolvedImpl(this)

    private class ResolvedImpl(configurator: OpenIdConfigurator) : OpenIdContext {
        @Deprecated("Hopefully not needed. Use configurator.database")
        val database = configurator.database

        override val config: ConfigurationPropertiesBean = ConfigurationPropertiesBean(configurator.issuer, configurator.topBarTitle)

        override val scopeRepository: SystemScopeRepository = ExposedSystemScopeRepository(configurator.database)

        override val scopeService: SystemScopeService = DefaultSystemScopeService(scopeRepository)

        override val signService: JWTSigningAndValidationService =
            DefaultJWTSigningAndValidationService(configurator.signingKeySet)

        override val encryptionService: JWTEncryptionAndDecryptionService =
            DefaultJWTEncryptionAndDecryptionService(configurator.encryptionKeySet)

        override val userInfoRepository: UserInfoRepository = ExposedUserInfoRepository(configurator.database)

        val pairwiseIdentiferRepository: PairwiseIdentifierRepository =
            ExposedPairwiseIdentifierRepository(configurator.database)

        override val pairwiseIdentifierService: PairwiseIdentifierService =
            UUIDPairwiseIdentiferService(pairwiseIdentiferRepository)

        override val clientRepository: OAuth2ClientRepository = ExposedOauth2ClientRepository(configurator.database)

        override val authenticationHolderRepository: AuthenticationHolderRepository =
            ExposedAuthenticationHolderRepository(configurator.database)

        override val tokenRepository: OAuth2TokenRepository = ExposedOauth2TokenRepository(
            database = configurator.database,
            authenticationHolderRepository = authenticationHolderRepository,
            clientRepository = clientRepository
        )

        override val approvedSiteRepository: ApprovedSiteRepository =
            ExposedApprovedSiteRepository(configurator.database)

        override val approvedSiteService: DefaultApprovedSiteService = DefaultApprovedSiteService(
            approvedSiteRepository = approvedSiteRepository,
            tokenRepository = tokenRepository,
        )

        override val statsService: StatsService = approvedSiteService.getStatsService()

        override val whitelistedSiteRepository: WhitelistedSiteRepository =
            ExposedWhitelistedSiteRepository(configurator.database)

        override val whitelistedSiteService: WhitelistedSiteService =
            DefaultWhitelistedSiteService(whitelistedSiteRepository)

        override val blacklistedSiteRepository: BlacklistedSiteRepository =
            ExposedBlacklistedSiteRepository(configurator.database)

        override val blacklistedSiteService: BlacklistedSiteService =
            DefaultBlacklistedSiteService(blacklistedSiteRepository)

        override val redirectResolver: RedirectResolver = BlacklistAwareRedirectResolver(blacklistedSiteService, config)

        override val resourceSetRepository: ResourceSetRepository = ExposedResourceSetRepository(configurator.database)

        override val ticketRepository: PermissionRepository =
            ExposedPermissionRepository(configurator.database, resourceSetRepository)

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

        override val routeSetService: ResourceSetService =
            DefaultResourceSetService(resourceSetRepository, tokenRepository, ticketRepository)

        override val clientDetailsService: ClientDetailsEntityService = DefaultOAuth2ClientDetailsEntityService(
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

        override val jwtService: JWTSigningAndValidationService =
            DefaultJWTSigningAndValidationService(configurator.signingKeySet)

        override val deviceCodeService: DeviceCodeService = DefaultDeviceCodeService()

        override val tokenEnhancer: TokenEnhancer =
            ConnectTokenEnhancerImpl(clientDetailsService, config, jwtService, userInfoService, { oidcTokenService })

        override val tokenService: OAuth2TokenEntityService = DefaultOAuth2ProviderTokenService(
            tokenRepository, authenticationHolderRepository, clientDetailsService, tokenEnhancer, scopeService, approvedSiteService
        )

        override val symetricCacheService: SymmetricKeyJWTValidatorCacheService =
            SymmetricKeyJWTValidatorCacheService()

        override val encyptersService: ClientKeyCacheService =
            DefaultClientKeyCacheService(KtorJWKSetCacheService(configurator.httpClient))

        override val oidcTokenService: OIDCTokenService = KtorOIDCTokenService(
            jwtService, authenticationHolderRepository, config, encyptersService, symetricCacheService, tokenService
        )

        override val scopeClaimTranslationService: ScopeClaimTranslationService =
            DefaultScopeClaimTranslationService()

        override val authRequestFactory: KtorOAuth2RequestFactory =
            KtorConnectOAuth2RequestFactory(clientDetailsService, encyptersService, encryptionService)

        // TODO (make this configurable, and not use the insane policy)
        override val claimsProcessingService: ClaimsProcessingService = MatchAllClaimsOnAnyPolicy()

        val permissionRepository = ExposedPermissionRepository(configurator.database, resourceSetRepository)

        override val permissionService: PermissionService = DefaultPermissionService(
            permissionRepository,
            scopeService,
        )

        override val savedRegisteredClientService: SavedRegisteredClientService =
            KtorRegisteredClientService(configurator.database)

        override val umaTokenService: UmaTokenService
            get() = TODO("not implemented")
        override val htmlViews: HtmlViews = DefaultHtmlViews()

        override val messageSource: JsonMessageSource = JsonMessageSource("/js/locale/", config)

        override fun resolveAuthenticatedUser(applicationCall: ApplicationCall): Authentication? {
            applicationCall.attributes.getOrNull(KEY_AUTHENTICATION)?.let { return it }

            val result = applicationCall.principal<UserIdPrincipal>()
                ?.let { UserIdPrincipalAuthentication(it, resolveAuthServiceAuthorities(it.name)) }
                ?: return null

            applicationCall.attributes.put(KEY_AUTHENTICATION, result)

            return result
        }

        // TODO Do something more sane
        private fun resolveAuthServiceAuthorities(name: String): Collection<GrantedAuthority> = when (name) {
            "admin" -> listOf(GrantedAuthority.ROLE_ADMIN, GrantedAuthority.ROLE_CLIENT)
            else -> listOf(GrantedAuthority.ROLE_CLIENT)
        }
    }

    companion object {
        private val KEY_AUTHENTICATION: AttributeKey<Authentication> = AttributeKey("authentication")
    }
}
