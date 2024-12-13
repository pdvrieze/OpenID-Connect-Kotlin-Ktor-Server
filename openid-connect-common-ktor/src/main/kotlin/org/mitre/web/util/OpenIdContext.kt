package org.mitre.web.util

import io.github.pdvrieze.auth.Authentication
import io.github.pdvrieze.auth.UserAuthentication
import io.github.pdvrieze.auth.ktor.KtorOpenIdContext
import io.ktor.server.application.*
import io.ktor.server.auth.*
import io.ktor.server.routing.*
import io.ktor.util.*
import org.mitre.jwt.assertion.AssertionValidator
import org.mitre.jwt.encryption.service.JWTEncryptionAndDecryptionService
import org.mitre.jwt.signer.service.ClientKeyCacheService
import org.mitre.jwt.signer.service.JWTSigningAndValidationService
import org.mitre.jwt.signer.service.impl.SymmetricKeyJWTValidatorCacheService
import org.mitre.oauth2.TokenEnhancer
import org.mitre.oauth2.assertion.AssertionOAuth2RequestFactory
import org.mitre.oauth2.model.OldAuthentication
import org.mitre.oauth2.repository.AuthenticationHolderRepository
import org.mitre.oauth2.repository.OAuth2ClientRepository
import org.mitre.oauth2.repository.OAuth2TokenRepository
import org.mitre.oauth2.repository.SystemScopeRepository
import org.mitre.oauth2.service.ClientDetailsEntityService
import org.mitre.oauth2.service.DeviceCodeService
import org.mitre.oauth2.service.JsonIntrospectionResultAssembler
import org.mitre.oauth2.service.OAuth2AuthorizationCodeService
import org.mitre.oauth2.service.OAuth2TokenEntityService
import org.mitre.oauth2.service.RedirectResolver
import org.mitre.oauth2.service.SystemScopeService
import org.mitre.oauth2.token.TokenGranter
import org.mitre.openid.connect.config.ConfigurationPropertiesBean
import org.mitre.openid.connect.config.MessageSource
import org.mitre.openid.connect.repository.ApprovedSiteRepository
import org.mitre.openid.connect.repository.BlacklistedSiteRepository
import org.mitre.openid.connect.repository.UserInfoRepository
import org.mitre.openid.connect.repository.WhitelistedSiteRepository
import org.mitre.openid.connect.request.OAuth2RequestFactory
import org.mitre.openid.connect.service.ApprovedSiteService
import org.mitre.openid.connect.service.BlacklistedSiteService
import org.mitre.openid.connect.service.ClientLogoLoadingService
import org.mitre.openid.connect.service.OIDCTokenService
import org.mitre.openid.connect.service.PairwiseIdentifierService
import org.mitre.openid.connect.service.ScopeClaimTranslationService
import org.mitre.openid.connect.service.StatsService
import org.mitre.openid.connect.service.UserInfoService
import org.mitre.openid.connect.service.WhitelistedSiteService
import org.mitre.openid.connect.token.UserApprovalHandler
import org.mitre.uma.repository.PermissionRepository
import org.mitre.uma.repository.ResourceSetRepository
import org.mitre.uma.service.ClaimsProcessingService
import org.mitre.uma.service.PermissionService
import org.mitre.uma.service.ResourceSetService
import org.mitre.uma.service.SavedRegisteredClientService
import org.mitre.uma.service.UmaTokenService
import org.mitre.web.HtmlViews

interface OpenIdContext {
    fun resolveAuthenticatedUser(authenticationContext: ApplicationCall): Authentication?

    fun checkCredential(credential: UserPasswordCredential): Boolean

    //region Regular services
    val authRequestFactory: OAuth2RequestFactory
    val approvedSiteService: ApprovedSiteService
    val blacklistedSiteService: BlacklistedSiteService
    val clientDetailsService: ClientDetailsEntityService
    val config: ConfigurationPropertiesBean
    val deviceCodeService: DeviceCodeService
    val encryptionService: JWTEncryptionAndDecryptionService
    val introspectionResultAssembler: JsonIntrospectionResultAssembler
    val messageSource: MessageSource
    val oidcTokenService: OIDCTokenService
    val pairwiseIdentifierService: PairwiseIdentifierService
    val redirectResolver: RedirectResolver
    val scopeClaimTranslationService: ScopeClaimTranslationService
    val scopeService: SystemScopeService
    val signService: JWTSigningAndValidationService
    val statsService: StatsService
    val tokenEnhancer: TokenEnhancer
    val tokenService: OAuth2TokenEntityService

    @Deprecated("Use tokenService", ReplaceWith("tokenService"))
    val tokenServices: OAuth2TokenEntityService get() = tokenService
    val userInfoService: UserInfoService
    val whitelistedSiteService: WhitelistedSiteService
    val authcodeService: OAuth2AuthorizationCodeService

    val symetricCacheService: SymmetricKeyJWTValidatorCacheService
    val encyptersService: ClientKeyCacheService
    val clientLogoLoadingService: ClientLogoLoadingService
    val assertionValidator: AssertionValidator
    val tokenGranters: Map<String, TokenGranter>

    val userApprovalHandler: UserApprovalHandler
    //endregion

    //region Regular repositories
    val approvedSiteRepository: ApprovedSiteRepository
    val authenticationHolderRepository: AuthenticationHolderRepository
    val blacklistedSiteRepository: BlacklistedSiteRepository
    val clientRepository: OAuth2ClientRepository
    val resourceSetRepository: ResourceSetRepository
    val scopeRepository: SystemScopeRepository
    val ticketRepository: PermissionRepository
    val tokenRepository: OAuth2TokenRepository
    val userInfoRepository: UserInfoRepository
    val whitelistedSiteRepository: WhitelistedSiteRepository
    //endregion

    //region Uma Services
    val claimsProcessingService: ClaimsProcessingService
    val permissionService: PermissionService
    val resourceSetService: ResourceSetService
    val savedRegisteredClientService: SavedRegisteredClientService
    val umaTokenService: UmaTokenService
    //endregion

    //region Access to the html views
    val htmlViews: HtmlViews

    //endregion
    val assertionFactory: AssertionOAuth2RequestFactory
}


//  PipelineContext<Unit, ApplicationCall>
val RoutingContext.openIdContext: KtorOpenIdContext
    get() = call.application.plugin(OpenIdContextPlugin).context

val ApplicationCall.openIdContext: KtorOpenIdContext
    get() = application.plugin(OpenIdContextPlugin).context

fun RoutingContext.resolveAuthenticatedUser(): Authentication? {
    return openIdContext.resolveAuthenticatedUser(call)
}

//region Direct accessors to regular services
val RoutingContext.authRequestFactory: OAuth2RequestFactory
    get() = openIdContext.authRequestFactory
val RoutingContext.approvedSiteService: ApprovedSiteService
    get() = openIdContext.approvedSiteService
val RoutingContext.blacklistedSiteService: BlacklistedSiteService
    get() = openIdContext.blacklistedSiteService
val RoutingContext.clientDetailsService: ClientDetailsEntityService
    get() = openIdContext.clientDetailsService
val RoutingContext.config: ConfigurationPropertiesBean
    get() = openIdContext.config
val RoutingContext.deviceCodeService: DeviceCodeService
    get() = openIdContext.deviceCodeService
val RoutingContext.encryptionService: JWTEncryptionAndDecryptionService
    get() = openIdContext.encryptionService
val RoutingContext.introspectionResultAssembler: JsonIntrospectionResultAssembler
    get() = openIdContext.introspectionResultAssembler
val RoutingContext.oidcTokenService: OIDCTokenService
    get() = openIdContext.oidcTokenService
val RoutingContext.pairwiseIdentifierService: PairwiseIdentifierService
    get() = openIdContext.pairwiseIdentifierService
val RoutingContext.redirectResolver: RedirectResolver
    get() = openIdContext.redirectResolver
val RoutingContext.scopeClaimTranslationService: ScopeClaimTranslationService
    get() = openIdContext.scopeClaimTranslationService
val RoutingContext.scopeService: SystemScopeService
    get() = openIdContext.scopeService
val RoutingContext.signService: JWTSigningAndValidationService
    get() = openIdContext.signService
val RoutingContext.statsService: StatsService
    get() = openIdContext.statsService
val RoutingContext.tokenEnhancer: TokenEnhancer
    get() = openIdContext.tokenEnhancer
val RoutingContext.tokenService: OAuth2TokenEntityService
    get() = openIdContext.tokenService
val RoutingContext.authcodeService: OAuth2AuthorizationCodeService
    get() = openIdContext.authcodeService
val RoutingContext.userInfoService: UserInfoService
    get() = openIdContext.userInfoService
val RoutingContext.whitelistedSiteService: WhitelistedSiteService
    get() = openIdContext.whitelistedSiteService

val RoutingContext.symetricCacheService: SymmetricKeyJWTValidatorCacheService
    get() = openIdContext.symetricCacheService
val RoutingContext.encryptersService: ClientKeyCacheService
    get() = openIdContext.encyptersService

val RoutingContext.clientLogoLoadingService: ClientLogoLoadingService
    get() = openIdContext.clientLogoLoadingService

val RoutingContext.assertionValidator: AssertionValidator
    get() = openIdContext.assertionValidator

val RoutingContext.tokenGranters: Map<String, TokenGranter>
    get() = openIdContext.tokenGranters

val RoutingContext.userApprovalHandler: UserApprovalHandler
    get() = openIdContext.userApprovalHandler

//endregion

//region Direct access to UMA services
val RoutingContext.claimsProcessingService: ClaimsProcessingService
    get() = openIdContext.claimsProcessingService
val RoutingContext.permissionService: PermissionService
    get() = openIdContext.permissionService
val RoutingContext.resourceSetService: ResourceSetService
    get() = openIdContext.resourceSetService
val RoutingContext.savedRegisteredClientService: SavedRegisteredClientService
    get() = openIdContext.savedRegisteredClientService
val RoutingContext.umaTokenService: UmaTokenService
    get() = openIdContext.umaTokenService
//endregion

//region direct access to regular repositories
val RoutingContext.approvedSiteRepository: ApprovedSiteRepository
    get() = openIdContext.approvedSiteRepository
val RoutingContext.authenticationHolderRepository: AuthenticationHolderRepository
    get() = openIdContext.authenticationHolderRepository
val RoutingContext.blacklistedSiteRepository: BlacklistedSiteRepository
    get() = openIdContext.blacklistedSiteRepository
val RoutingContext.clientRepository: OAuth2ClientRepository
    get() = openIdContext.clientRepository
val RoutingContext.resourceSetRepository: ResourceSetRepository
    get() = openIdContext.resourceSetRepository
val RoutingContext.scopeRepository: SystemScopeRepository
    get() = openIdContext.scopeRepository
val RoutingContext.ticketRepository: PermissionRepository
    get() = openIdContext.ticketRepository
val RoutingContext.tokenRepository: OAuth2TokenRepository
    get() = openIdContext.tokenRepository
val RoutingContext.userInfoRepository: UserInfoRepository
    get() = openIdContext.userInfoRepository
val RoutingContext.whitelistedSiteRepository: WhitelistedSiteRepository
    get() = openIdContext.whitelistedSiteRepository
//endregion

class OpenIdContextPlugin(val context: KtorOpenIdContext) {

    private val configuration: ConfigurationImpl = ConfigurationImpl()

    companion object :
        BaseApplicationPlugin<ApplicationCallPipeline, Configuration, OpenIdContextPlugin> {

        override val key = AttributeKey<OpenIdContextPlugin>("openid-context")

        override fun install(
            pipeline: ApplicationCallPipeline,
            configure: Configuration.() -> Unit
        ): OpenIdContextPlugin {
            val configuration = ConfigurationImpl()
            configuration.apply(configure)
            val context =
                checkNotNull(configuration.context) { "The OpenIdContext plugin must set the context parameter" }
            val plugin = OpenIdContextPlugin(context)
            return plugin
        }

    }

    interface Configuration {
        var context: KtorOpenIdContext?
    }

    private class ConfigurationImpl : Configuration {
        override var context: KtorOpenIdContext? = null
    }
}
