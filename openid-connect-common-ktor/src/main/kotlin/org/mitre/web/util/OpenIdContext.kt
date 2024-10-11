package org.mitre.web.util

import io.ktor.server.application.*
import io.ktor.server.auth.*
import io.ktor.util.*
import io.ktor.util.pipeline.*
import org.mitre.jwt.assertion.AssertionValidator
import org.mitre.jwt.encryption.service.JWTEncryptionAndDecryptionService
import org.mitre.jwt.signer.service.ClientKeyCacheService
import org.mitre.jwt.signer.service.JWTSigningAndValidationService
import org.mitre.jwt.signer.service.impl.SymmetricKeyJWTValidatorCacheService
import org.mitre.oauth2.TokenEnhancer
import org.mitre.oauth2.model.Authentication
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
    fun checkCredential(credential: Credential): Boolean

    //region Regular services
    val authRequestFactory: OAuth2RequestFactory
    val approvedSiteService: ApprovedSiteService
    val blacklistedSiteService: BlacklistedSiteService
    val clientDetailsService: ClientDetailsEntityService
    val clientService: ClientDetailsEntityService
    val config: ConfigurationPropertiesBean
    val deviceCodeService: DeviceCodeService
    val encryptionService: JWTEncryptionAndDecryptionService
    val introspectionResultAssembler: JsonIntrospectionResultAssembler
    val messageSource: MessageSource
    val jwtService: JWTSigningAndValidationService
    val oidcTokenService: OIDCTokenService
    val pairwiseIdentifierService: PairwiseIdentifierService
    val redirectResolver: RedirectResolver
    val routeSetService: ResourceSetService
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

    val symetricCacheService: SymmetricKeyJWTValidatorCacheService
    val encyptersService: ClientKeyCacheService
    val clientLogoLoadingService: ClientLogoLoadingService
    val assertionValidator: AssertionValidator
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
}


//  PipelineContext<Unit, ApplicationCall>
val PipelineContext<*, ApplicationCall>.openIdContext: OpenIdContext
    get() = call.application.plugin(OpenIdContextPlugin).context

val ApplicationCall.openIdContext: OpenIdContext
    get() = application.plugin(OpenIdContextPlugin).context

fun PipelineContext<*, ApplicationCall>.resolveAuthenticatedUser(): Authentication? {
    return openIdContext.resolveAuthenticatedUser(call)
}

//region Direct accessors to regular services
val PipelineContext<*, ApplicationCall>.approvedSiteService: ApprovedSiteService
    get() = openIdContext.approvedSiteService
val PipelineContext<*, ApplicationCall>.blacklistedSiteService: BlacklistedSiteService
    get() = openIdContext.blacklistedSiteService
val PipelineContext<*, ApplicationCall>.clientDetailsService: ClientDetailsEntityService
    get() = openIdContext.clientDetailsService
val PipelineContext<*, ApplicationCall>.clientService: ClientDetailsEntityService
    get() = openIdContext.clientService
val PipelineContext<*, ApplicationCall>.config: ConfigurationPropertiesBean
    get() = openIdContext.config
val PipelineContext<*, ApplicationCall>.deviceCodeService: DeviceCodeService
    get() = openIdContext.deviceCodeService
val PipelineContext<*, ApplicationCall>.encryptionService: JWTEncryptionAndDecryptionService
    get() = openIdContext.encryptionService
val PipelineContext<*, ApplicationCall>.introspectionResultAssembler: JsonIntrospectionResultAssembler
    get() = openIdContext.introspectionResultAssembler
val PipelineContext<*, ApplicationCall>.jwtService: JWTSigningAndValidationService
    get() = openIdContext.jwtService
val PipelineContext<*, ApplicationCall>.oidcTokenService: OIDCTokenService
    get() = openIdContext.oidcTokenService
val PipelineContext<*, ApplicationCall>.pairwiseIdentifierService: PairwiseIdentifierService
    get() = openIdContext.pairwiseIdentifierService
val PipelineContext<*, ApplicationCall>.redirectResolver: RedirectResolver
    get() = openIdContext.redirectResolver
val PipelineContext<*, ApplicationCall>.routeSetService: ResourceSetService
    get() = openIdContext.routeSetService
val PipelineContext<*, ApplicationCall>.scopeClaimTranslationService: ScopeClaimTranslationService
    get() = openIdContext.scopeClaimTranslationService
val PipelineContext<*, ApplicationCall>.scopeService: SystemScopeService
    get() = openIdContext.scopeService
val PipelineContext<*, ApplicationCall>.signService: JWTSigningAndValidationService
    get() = openIdContext.signService
val PipelineContext<*, ApplicationCall>.statsService: StatsService
    get() = openIdContext.statsService
val PipelineContext<*, ApplicationCall>.tokenEnhancer: TokenEnhancer
    get() = openIdContext.tokenEnhancer
val PipelineContext<*, ApplicationCall>.tokenService: OAuth2TokenEntityService
    get() = openIdContext.tokenService
val PipelineContext<*, ApplicationCall>.userInfoService: UserInfoService
    get() = openIdContext.userInfoService
val PipelineContext<*, ApplicationCall>.whitelistedSiteService: WhitelistedSiteService
    get() = openIdContext.whitelistedSiteService

val PipelineContext<*, ApplicationCall>.symetricCacheService: SymmetricKeyJWTValidatorCacheService
    get() = openIdContext.symetricCacheService
val PipelineContext<*, ApplicationCall>.encryptersService: ClientKeyCacheService
    get() = openIdContext.encyptersService

val PipelineContext<*, ApplicationCall>.clientLogoLoadingService: ClientLogoLoadingService
    get()  = openIdContext.clientLogoLoadingService

val PipelineContext<*, ApplicationCall>.assertionValidator: AssertionValidator
    get()  = openIdContext.assertionValidator
//endregion

//region Direct access to UMA services
val PipelineContext<*, ApplicationCall>.claimsProcessingService: ClaimsProcessingService
    get() = openIdContext.claimsProcessingService
val PipelineContext<*, ApplicationCall>.permissionService: PermissionService
    get() = openIdContext.permissionService
val PipelineContext<*, ApplicationCall>.resourceSetService: ResourceSetService
    get() = openIdContext.resourceSetService
val PipelineContext<*, ApplicationCall>.savedRegisteredClientService: SavedRegisteredClientService
    get() = openIdContext.savedRegisteredClientService
val PipelineContext<*, ApplicationCall>.umaTokenService: UmaTokenService
    get() = openIdContext.umaTokenService
//endregion

//region direct access to regular repositories
val PipelineContext<*, ApplicationCall>.approvedSiteRepository: ApprovedSiteRepository
    get() = openIdContext.approvedSiteRepository
val PipelineContext<*, ApplicationCall>.authenticationHolderRepository: AuthenticationHolderRepository
    get() = openIdContext.authenticationHolderRepository
val PipelineContext<*, ApplicationCall>.blacklistedSiteRepository: BlacklistedSiteRepository
    get() = openIdContext.blacklistedSiteRepository
val PipelineContext<*, ApplicationCall>.clientRepository: OAuth2ClientRepository
    get() = openIdContext.clientRepository
val PipelineContext<*, ApplicationCall>.resourceSetRepository: ResourceSetRepository
    get() = openIdContext.resourceSetRepository
val PipelineContext<*, ApplicationCall>.scopeRepository: SystemScopeRepository
    get() = openIdContext.scopeRepository
val PipelineContext<*, ApplicationCall>.ticketRepository: PermissionRepository
    get() = openIdContext.ticketRepository
val PipelineContext<*, ApplicationCall>.tokenRepository: OAuth2TokenRepository
    get() = openIdContext.tokenRepository
val PipelineContext<*, ApplicationCall>.userInfoRepository: UserInfoRepository
    get() = openIdContext.userInfoRepository
val PipelineContext<*, ApplicationCall>.whitelistedSiteRepository: WhitelistedSiteRepository
    get() = openIdContext.whitelistedSiteRepository
//endregion

class OpenIdContextPlugin(val context: OpenIdContext) {

    private val configuration: ConfigurationImpl = ConfigurationImpl()

    companion object :
        BaseApplicationPlugin<ApplicationCallPipeline, OpenIdContextPlugin.Configuration, OpenIdContextPlugin> {

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
        var context: OpenIdContext?
    }

    private class ConfigurationImpl : Configuration {
        override var context: OpenIdContext? = null
    }
}
