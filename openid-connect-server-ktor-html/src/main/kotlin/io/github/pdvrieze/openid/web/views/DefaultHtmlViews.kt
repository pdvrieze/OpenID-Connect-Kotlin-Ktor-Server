package io.github.pdvrieze.openid.web.views

import io.github.pdvrieze.openid.web.Intl
import io.github.pdvrieze.openid.web.WebContext
import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.html.*
import io.ktor.server.request.*
import io.ktor.server.routing.*
import io.ktor.server.sessions.*
import kotlinx.html.HTML
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonArray
import org.mitre.oauth2.exception.OAuth2Exception
import org.mitre.oauth2.exception.OAuthErrorCode
import org.mitre.oauth2.model.Authentication
import org.mitre.oauth2.model.DeviceCode
import org.mitre.oauth2.model.OAuthClientDetails
import org.mitre.oauth2.model.SystemScope
import org.mitre.oauth2.model.request.AuthorizationRequest
import org.mitre.openid.connect.config.ConfigurationPropertiesBean
import org.mitre.openid.connect.config.UIConfiguration
import org.mitre.openid.connect.model.DefaultUserInfo
import org.mitre.openid.connect.model.UserInfo
import org.mitre.web.HtmlViews
import org.mitre.web.OpenIdSessionStorage
import org.mitre.web.util.OpenIdContext
import org.mitre.web.util.openIdContext
import java.util.*

class DefaultHtmlViews : HtmlViews {

    private fun RoutingContext.createContext(): WebContext {
        return DefaultWebContext(call)
    }

    suspend fun RoutingContext.respondOID(status: HttpStatusCode = HttpStatusCode.OK, block: HTML.(WebContext) -> Unit) {
        return call.respondHtml(status) {
            val ctx = createContext()
            block(ctx)
            if (ctx is DefaultWebContext && ctx.requiresSession) {
                call.sessions.getOrSet { OpenIdSessionStorage() } // set it only if not yet set
            }
        }
    }

    override suspend fun RoutingContext.about() {
        call.respondHtml {
            about(createContext())
        }
    }

    override suspend fun RoutingContext.approve(
        authRequest: AuthorizationRequest?,
        client: OAuthClientDetails,
        redirectUri: String?,
        scopes: Set<SystemScope>,
        claims: Map<String?, Map<String, String>>,
        count: Int,
        isGras: Boolean,
        contacts: String?,
        consent: Boolean,
        authenticationException: OAuth2Exception?,
    ) {
        call.respondHtml {
            approve(createContext(), authRequest, client, redirectUri, scopes, claims, count,
                    contacts, isGras, consent, authenticationException)
        }
    }

    override suspend fun RoutingContext.approveDevice(
        client: OAuthClientDetails,
        scopes: Set<SystemScope>,
        deviceCode: DeviceCode,
        claims: Map<String?, Map<String, String>>,
        exception: OAuth2Exception?,
        count: Int,
        isGras: Boolean,
        contacts: String?,
    ) {
        call.respondHtml {
            approveDevice(createContext(), client, scopes, deviceCode, claims, exception, count, isGras, contacts)
        }
    }

    override suspend fun RoutingContext.contact() {
        call.respondHtml {
            contact(createContext())
        }
    }

    override suspend fun RoutingContext.deviceApproved(
        client: OAuthClientDetails,
        isApproved: Boolean,
    ) {
        call.respondHtml {
            deviceApproved(createContext(), client, isApproved)
        }
    }

    @Deprecated("Avoid errors without any context")
    override suspend fun RoutingContext.error() {
        call.respondHtml {
            error(createContext())
        }
    }

    override suspend fun RoutingContext.error(error: OAuth2Exception, statusCode: HttpStatusCode) {
        call.respondHtml(statusCode) {
            error(createContext(), error)
        }
    }

    override suspend fun RoutingContext.error(
        errorCode: OAuthErrorCode,
        errorMessage: String,
        statusCode: HttpStatusCode
    ) {
        call.respondHtml(statusCode) {
            error(createContext(), errorCode, errorMessage)
        }
    }

    override suspend fun RoutingContext.error(errorCodeString: String, errorMessage: String, statusCode: HttpStatusCode) {
        call.respondHtml(statusCode) {
            error(createContext(), errorCodeString, errorMessage)
        }
    }

    override suspend fun RoutingContext.home() {
        call.respondHtml {
            home(createContext())
        }
    }

    override suspend fun RoutingContext.login(
        loginActionUrl: String,
        loginHint: String?,
        paramError: String?,
        redirectUri: String?,
        status: HttpStatusCode,
    ) {
        call.respondHtml(status) {
            login(createContext(), loginActionUrl, loginHint, paramError, redirectUri)
        }
    }

    override suspend fun RoutingContext.logoutConfirmation(client: OAuthClientDetails?) {
        call.respondHtml {
            logoutConfirmation(createContext(), client)
        }
    }

    override suspend fun RoutingContext.manage() {
        call.respondHtml {
            manage(createContext())
        }
    }

    override suspend fun RoutingContext.postLogout() {
        call.respondHtml {
            postLogout(createContext())
        }

    }

    override suspend fun RoutingContext.requestUserCode(error: String?) {
        call.respondHtml {
            requestUserCode(createContext(), error)
        }
    }

    override suspend fun RoutingContext.stats(statsSummary: Map<String, Int>) {
        call.respondHtml {
            stats(createContext(), statsSummary)
        }
    }

    private class DefaultWebContext(
        private val openIdContext: OpenIdContext,
        applicationCall: ApplicationCall,
    ) : WebContext {

        var requiresSession: Boolean = false

        constructor(applicationCall: ApplicationCall) :
                this(applicationCall.openIdContext, applicationCall)

        override val csrf: WebContext.ICsrf = object : WebContext.ICsrf {
            override val parameterName: String get() = "SDFHLK_CSRF"

            override fun requireSession() {
                requiresSession = true
            }

            /** CSRF_TOKEN */
            override val token: String get() {
                applicationCall.sessions.getOrSet { OpenIdSessionStorage() }

                error("Sessions are used for CSRF instead")
            }
        }

        override val authentication: Authentication? by lazy { openIdContext.resolveAuthenticatedUser(applicationCall) }

        override val userInfo: UserInfo? by lazy {
            authentication?.let { DefaultUserInfo(it.name) }
        }

        override val userAuthorities: String?
            get() {
                val a = authentication?.authorities ?: return null
                return buildJsonArray {
                    for (entry in a) { add(JsonPrimitive(entry.authority)) }
                }.toString()
            }

        override val lang: String by lazy {
            applicationCall.request.acceptLanguageItems()
                .firstOrNull { it.value in openIdContext.config.languageNamespaces }?.value
                ?: openIdContext.config.locale.language
        }

        override val intl: Intl = object : Intl {
            override fun messageText(key: String): String {
                return openIdContext.messageSource.resolveCode(key, Locale(lang))?.format(null) ?: key
            }

            override fun messageText(key: String, vararg args: Any?): String {
                val format = openIdContext.messageSource.resolveCode(key, Locale(lang))
                    ?: return key
                return format.format(args)
            }
        }

        override val config: ConfigurationPropertiesBean
            get() = openIdContext.config
        override val ui: UIConfiguration
            get() = UIConfiguration(config.jsFiles)
    }
}
