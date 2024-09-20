package org.mitre.web.util

import io.ktor.server.application.*
import io.ktor.util.*
import io.ktor.util.pipeline.*
import org.mitre.jwt.encryption.service.JWTEncryptionAndDecryptionService
import org.mitre.jwt.signer.service.JWTSigningAndValidationService
import org.mitre.oauth2.repository.OAuth2ClientRepository
import org.mitre.oauth2.repository.OAuth2TokenRepository
import org.mitre.oauth2.repository.SystemScopeRepository
import org.mitre.oauth2.service.ClientDetailsEntityService
import org.mitre.oauth2.service.DeviceCodeService
import org.mitre.oauth2.service.JsonIntrospectionResultAssembler
import org.mitre.oauth2.service.OAuth2TokenEntityService
import org.mitre.oauth2.service.SystemScopeService
import org.mitre.openid.connect.config.ConfigurationPropertiesBean
import org.mitre.openid.connect.repository.UserInfoRepository
import org.mitre.openid.connect.service.ApprovedSiteService
import org.mitre.openid.connect.service.PairwiseIdentifierService
import org.mitre.openid.connect.service.UserInfoService
import org.mitre.uma.service.ResourceSetService

interface OpenIdContext {
    val introspectionResultAssembler: JsonIntrospectionResultAssembler
    val userInfoService: UserInfoService
    val tokenService: OAuth2TokenEntityService
    @Deprecated("Use tokenService", ReplaceWith("tokenService"))
    val tokenServices: OAuth2TokenEntityService get() = tokenService
    val deviceCodeService: DeviceCodeService
    val config: ConfigurationPropertiesBean
    val scopeRepository: SystemScopeRepository
    val scopeService: SystemScopeService
    val signService: JWTSigningAndValidationService
    val encryptionService: JWTEncryptionAndDecryptionService
    val clientService: ClientDetailsEntityService
    val pairwiseIdentifierService: PairwiseIdentifierService
    val userService: UserInfoService
    val approvedSiteService: ApprovedSiteService
    val resourceSetService: ResourceSetService

    val userInfoRepository: UserInfoRepository
    val clientRepository: OAuth2ClientRepository
    val tokenRepository: OAuth2TokenRepository
}


//  PipelineContext<Unit, ApplicationCall>
val PipelineContext<*, ApplicationCall>.openIdContext: OpenIdContext
    get() = call.application.plugin(OpenIdContextPlugin).context

val ApplicationCall.openIdContext: OpenIdContext
    get() = application.plugin(OpenIdContextPlugin).context


val PipelineContext<*, ApplicationCall>.userInfoService: UserInfoService
    get() = openIdContext.userInfoService
val PipelineContext<*, ApplicationCall>.tokenService: OAuth2TokenEntityService
    get() = openIdContext.tokenService
val PipelineContext<*, ApplicationCall>.deviceCodeService: DeviceCodeService
    get() = openIdContext.deviceCodeService
val PipelineContext<*, ApplicationCall>.scopeRepository: SystemScopeRepository
    get() = openIdContext.scopeRepository
val PipelineContext<*, ApplicationCall>.scopeService: SystemScopeService
    get() = openIdContext.scopeService
val PipelineContext<*, ApplicationCall>.signService: JWTSigningAndValidationService
    get() = openIdContext.signService
val PipelineContext<*, ApplicationCall>.encryptionService: JWTEncryptionAndDecryptionService
    get() = openIdContext.encryptionService
val PipelineContext<*, ApplicationCall>.userInfoRepository: UserInfoRepository
    get() = openIdContext.userInfoRepository
val PipelineContext<*, ApplicationCall>.clientService: ClientDetailsEntityService
    get() = openIdContext.clientService
val PipelineContext<*, ApplicationCall>.pairwiseIdentifierService: PairwiseIdentifierService
    get() = openIdContext.pairwiseIdentifierService
val PipelineContext<*, ApplicationCall>.userService: UserInfoService
    get() = openIdContext.userService
val PipelineContext<*, ApplicationCall>.clientRepository: OAuth2ClientRepository
    get() = openIdContext.clientRepository
val PipelineContext<*, ApplicationCall>.tokenRepository: OAuth2TokenRepository
    get() = openIdContext.tokenRepository
val PipelineContext<*, ApplicationCall>.approvedSiteService: ApprovedSiteService
    get() = openIdContext.approvedSiteService
val PipelineContext<*, ApplicationCall>.resourceSetService: ResourceSetService
    get() = openIdContext.resourceSetService

class OpenIdContextPlugin(val context: OpenIdContext) {

    private val configuration: ConfigurationImpl = ConfigurationImpl()

    companion object : BaseApplicationPlugin<ApplicationCallPipeline, OpenIdContextPlugin.Configuration, OpenIdContextPlugin> {

        override val key = AttributeKey<OpenIdContextPlugin>("openid-context")

        override fun install(
            pipeline: ApplicationCallPipeline,
            configure: Configuration.() -> Unit
        ): OpenIdContextPlugin {
            val configuration = ConfigurationImpl()
            configuration.apply(configure)
            val context = checkNotNull(configuration.context) { "The OpenIdContext plugin must set the context parameter" }
            val plugin = OpenIdContextPlugin(context)
            return plugin
        }

    }

    interface Configuration {
        var context: OpenIdContext?
    }

    private class ConfigurationImpl : Configuration {
        override var context : OpenIdContext? = null
    }
}
