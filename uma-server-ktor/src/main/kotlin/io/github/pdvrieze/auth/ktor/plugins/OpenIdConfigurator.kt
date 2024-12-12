package io.github.pdvrieze.auth.ktor.plugins

import com.nimbusds.jose.jwk.JWK
import io.github.pdvrieze.auth.UserAuthentication
import io.github.pdvrieze.auth.UserService
import io.github.pdvrieze.auth.impl.UserServiceImpl
import io.github.pdvrieze.auth.ktor.KtorOpenIdContext
import io.github.pdvrieze.auth.repository.exposed.ExposedAuthenticationHolderRepository
import io.github.pdvrieze.auth.repository.exposed.ExposedAuthorizationCodeRepository
import io.github.pdvrieze.auth.repository.exposed.ExposedDeviceCodeRepository
import io.github.pdvrieze.auth.repository.exposed.ExposedOauth2ClientRepository
import io.github.pdvrieze.auth.repository.exposed.ExposedOauth2TokenRepository
import io.github.pdvrieze.auth.repository.exposed.ExposedOpenIdContext
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
import org.mitre.jwt.assertion.AssertionValidator
import org.mitre.jwt.assertion.impl.SelfAssertionValidator
import org.mitre.jwt.encryption.service.JWTEncryptionAndDecryptionService
import org.mitre.jwt.encryption.service.impl.DefaultJWTEncryptionAndDecryptionService
import org.mitre.jwt.signer.service.ClientKeyCacheService
import org.mitre.jwt.signer.service.JWTSigningAndValidationService
import org.mitre.jwt.signer.service.impl.DefaultClientKeyCacheService
import org.mitre.jwt.signer.service.impl.DefaultJWTSigningAndValidationService
import org.mitre.jwt.signer.service.impl.SymmetricKeyJWTValidatorCacheService
import org.mitre.jwt.signer.service.impl.ktor.KtorJWKSetCacheService
import org.mitre.oauth2.TokenEnhancer
import org.mitre.oauth2.assertion.AssertionOAuth2RequestFactory
import org.mitre.oauth2.assertion.impl.DirectCopyRequestFactory
import org.mitre.oauth2.model.OldAuthentication
import org.mitre.oauth2.model.GrantedAuthority
import org.mitre.oauth2.repository.AuthenticationHolderRepository
import org.mitre.oauth2.repository.OAuth2ClientRepository
import org.mitre.oauth2.repository.OAuth2TokenRepository
import org.mitre.oauth2.repository.SystemScopeRepository
import org.mitre.oauth2.repository.ktor.KtorAuthorizationCodeRepository
import org.mitre.oauth2.service.ClientDetailsEntityService
import org.mitre.oauth2.service.DeviceCodeService
import org.mitre.oauth2.service.JsonIntrospectionResultAssembler
import org.mitre.oauth2.service.OAuth2AuthorizationCodeService
import org.mitre.oauth2.service.OAuth2TokenEntityService
import org.mitre.oauth2.service.RedirectResolver
import org.mitre.oauth2.service.SystemScopeService
import org.mitre.oauth2.service.impl.DefaultDeviceCodeService
import org.mitre.oauth2.service.impl.DefaultOAuth2AuthorizationCodeService
import org.mitre.oauth2.service.impl.DefaultOAuth2ClientDetailsEntityService
import org.mitre.oauth2.service.impl.DefaultOAuth2ProviderTokenService
import org.mitre.oauth2.service.impl.DefaultSystemScopeService
import org.mitre.oauth2.token.AuthorizationCodeTokenGranter
import org.mitre.oauth2.token.ClientTokenGranter
import org.mitre.oauth2.token.DeviceTokenGranter
import org.mitre.oauth2.token.ImplicitTokenGranter
import org.mitre.oauth2.token.RefreshTokenGranter
import org.mitre.oauth2.token.TokenGranter
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
import org.mitre.openid.connect.service.ClientLogoLoadingService
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
import org.mitre.openid.connect.service.impl.ktor.KtorInMemoryClientLogoLoadingService
import org.mitre.openid.connect.token.ConnectTokenEnhancerImpl
import org.mitre.openid.connect.token.KtorTofuUserApprovalHandler
import org.mitre.uma.repository.PermissionRepository
import org.mitre.uma.repository.ResourceSetRepository
import org.mitre.uma.service.ClaimsProcessingService
import org.mitre.uma.service.PermissionService
import org.mitre.uma.service.ResourceSetService
import org.mitre.uma.service.SavedRegisteredClientService
import org.mitre.uma.service.UmaTokenService
import org.mitre.uma.service.impl.DefaultPermissionService
import org.mitre.uma.service.impl.DefaultResourceSetService
import org.mitre.uma.service.impl.DefaultUmaTokenService
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
    var verifyCredential: (UserPasswordCredential) -> Boolean = { false },
) {

    var topBarTitle: String = "Ktor OpenId provider"
    var encryptionKeySet: Map<String, JWK> = emptyMap()

    var defaultSigningKeyId: String? = null
        set(value) {
            if (signingKeySet.isNotEmpty()) {
                require(signingKeySet.containsKey(value)) { "The keyId specified does not exist in a non-empty key set" }
            }

            field = value
        }

    var signingKeySet: Map<String, JWK> = emptyMap()
        set(value) {
            when {
                value.isEmpty() -> defaultSigningKeyId = null
                else -> {
                    value.keys.singleOrNull()?.let { key -> defaultSigningKeyId = key }
                }
            }

            field = value
        }

    fun resolveDefault(): KtorOpenIdContext = DefaultContext(this)

    open class DefaultContext(configurator: OpenIdConfigurator) : KtorOpenIdContext, ExposedOpenIdContext {
        @Deprecated("Hopefully not needed. Use configurator.database")
        override val database = configurator.database
        private val credentialVerifier = configurator.verifyCredential

        override val config: ConfigurationPropertiesBean = ConfigurationPropertiesBean(configurator.issuer, configurator.topBarTitle).apply {
            jsFiles = setOf(
                "resources/js/client.js",
                "resources/js/grant.js",
                "resources/js/scope.js",
                "resources/js/whitelist.js",
                "resources/js/dynreg.js",
                "resources/js/rsreg.js",
                "resources/js/token.js",
                "resources/js/blacklist.js",
                "resources/js/profile.js",
            )
        }

        override val scopeRepository: SystemScopeRepository = ExposedSystemScopeRepository(configurator.database)

        override val scopeService: SystemScopeService = DefaultSystemScopeService(scopeRepository)

        override val signService: JWTSigningAndValidationService =
            DefaultJWTSigningAndValidationService(configurator.signingKeySet, requireNotNull(configurator.defaultSigningKeyId) { "Default signing keyid not defined" })

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

        override val clientDetailsService: ClientDetailsEntityService = DefaultOAuth2ClientDetailsEntityService(
            clientRepository,
            tokenRepository,
            approvedSiteService,
            whitelistedSiteService,
            blacklistedSiteService,
            scopeService,
            statsService,
            resourceSetService,
            this.config
        )

        override val introspectionResultAssembler: JsonIntrospectionResultAssembler =
            DefaultIntrospectionResultAssembler()

        override val userInfoService: UserInfoService = DefaultUserInfoService(
            userInfoRepository, clientDetailsService, pairwiseIdentifierService
        )

        val deviceCodeRepository = ExposedDeviceCodeRepository(configurator.database, clientRepository, authenticationHolderRepository)

        override val deviceCodeService: DeviceCodeService = DefaultDeviceCodeService(deviceCodeRepository)

        override val tokenEnhancer: TokenEnhancer =
            ConnectTokenEnhancerImpl(clientDetailsService, config, signService, userInfoService, { oidcTokenService })

        final override val tokenService: OAuth2TokenEntityService = DefaultOAuth2ProviderTokenService(
            tokenRepository, authenticationHolderRepository, clientDetailsService, tokenEnhancer, scopeService, approvedSiteService
        )

        override val symetricCacheService: SymmetricKeyJWTValidatorCacheService =
            SymmetricKeyJWTValidatorCacheService()

        override val encyptersService: ClientKeyCacheService =
            DefaultClientKeyCacheService(KtorJWKSetCacheService(configurator.httpClient))

        override val oidcTokenService: OIDCTokenService = KtorOIDCTokenService(
            signService, authenticationHolderRepository, config, encyptersService, symetricCacheService, tokenService
        )

        override val scopeClaimTranslationService: ScopeClaimTranslationService =
            DefaultScopeClaimTranslationService()

        val authorizationCodeRepository: KtorAuthorizationCodeRepository =
            ExposedAuthorizationCodeRepository(configurator.database, authenticationHolderRepository)

        override val authcodeService: OAuth2AuthorizationCodeService = DefaultOAuth2AuthorizationCodeService(
            authorizationCodeRepository, authenticationHolderRepository, config.authCodeExpirationSeconds
        )

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

        override val umaTokenService: UmaTokenService =
            DefaultUmaTokenService(authenticationHolderRepository, tokenService, clientDetailsService, config, signService)

        override val userService: UserService =
            UserServiceImpl { u, p -> configurator.verifyCredential(UserPasswordCredential(u, p)) }
        override val clientLogoLoadingService: ClientLogoLoadingService =
            KtorInMemoryClientLogoLoadingService()

        override val assertionValidator: AssertionValidator =
            SelfAssertionValidator(config, signService)

        override val assertionFactory: AssertionOAuth2RequestFactory =
            DirectCopyRequestFactory()

        override val userApprovalHandler: KtorTofuUserApprovalHandler =
            KtorTofuUserApprovalHandler(approvedSiteService, whitelistedSiteService, clientDetailsService, scopeService)

        // TODO: create password grant, but don't enable by default
        override val tokenGranters: Map<String, TokenGranter> =
            listOf(
                AuthorizationCodeTokenGranter(tokenService, authcodeService, clientDetailsService, authRequestFactory),
                ImplicitTokenGranter(tokenService, clientDetailsService, authRequestFactory),
                ClientTokenGranter(tokenService, clientDetailsService, authRequestFactory),
                RefreshTokenGranter(tokenService, clientDetailsService, authRequestFactory),
                DeviceTokenGranter(tokenService, clientDetailsService, authRequestFactory, deviceCodeService),
            ).associateBy { it.grantType }

        override val htmlViews: HtmlViews = DefaultHtmlViews()

        override val messageSource: JsonMessageSource = JsonMessageSource("/js/locale/", config)

        override fun resolveAuthenticatedUser(applicationCall: ApplicationCall): UserAuthentication? {
            applicationCall.attributes.getOrNull(KEY_AUTHENTICATION)?.let { return it }

            val result = applicationCall.principal<Authentication>() as? UserAuthentication ?: return null

            applicationCall.attributes.put(KEY_AUTHENTICATION, result)

            return result
        }

        override fun checkCredential(credential: UserPasswordCredential): Boolean {
            return credentialVerifier(credential)
        }

        // TODO Do something more sane
        protected open fun resolveAuthServiceAuthorities(name: String): Set<GrantedAuthority> = when (name) {
            "admin" -> setOf(GrantedAuthority.ROLE_ADMIN, GrantedAuthority.ROLE_USER, GrantedAuthority.ROLE_ADMIN)
            else -> setOf(GrantedAuthority.ROLE_USER)
        }
    }

    companion object {
        private val KEY_AUTHENTICATION: AttributeKey<UserAuthentication> = AttributeKey("authentication")
    }
}
