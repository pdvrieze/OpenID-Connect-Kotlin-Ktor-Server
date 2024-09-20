package io.github.pdvrieze.openid.web.views

import io.github.pdvrieze.openid.web.Intl
import io.github.pdvrieze.openid.web.WebContext
import io.ktor.server.application.*
import io.ktor.server.html.*
import io.ktor.server.request.*
import io.ktor.util.pipeline.*
import org.mitre.oauth2.exception.ErrorCodes
import org.mitre.oauth2.exception.OAuth2Exception
import org.mitre.oauth2.model.Authentication
import org.mitre.oauth2.model.OAuthClientDetails
import org.mitre.oauth2.model.SystemScope
import org.mitre.oauth2.model.convert.OAuth2Request
import org.mitre.openid.connect.config.ConfigurationPropertiesBean
import org.mitre.openid.connect.config.UIConfiguration
import org.mitre.openid.connect.model.DefaultUserInfo
import org.mitre.openid.connect.model.UserInfo
import org.mitre.web.HtmlViews
import org.mitre.web.util.OpenIdContext
import org.mitre.web.util.openIdContext
import java.net.URI
import java.util.*

class DefaultHtmlViews(): HtmlViews {

    private fun PipelineContext<*, ApplicationCall>.createContext(): WebContext {
        return DefaultWebContext(call)
    }

    override suspend fun PipelineContext<*, ApplicationCall>.about() {
        call.respondHtml {
            about(createContext())
        }
    }

    override suspend fun PipelineContext<*, ApplicationCall>.approve(
        authRequest: OAuth2Request?,
        client: OAuthClientDetails,
        redirectUri: URI,
        scopes: Set<SystemScope>,
        claims:  Map<String?, Map<String, String>>,
        count: Int,
        contacts: String?,
        isGras: Boolean,
        consent: Boolean,
        authenticationException: OAuth2Exception?,
    ) {
        call.respondHtml {
            approve(createContext(), authRequest, client, redirectUri, scopes, claims, count,
                    contacts, isGras, consent, authenticationException)
        }
    }

    override suspend fun PipelineContext<*, ApplicationCall>.approveDevice(
        client: OAuthClientDetails,
        scopes: Set<SystemScope>,
        claims:  Map<String?, Map<String, String>>,
        exception: OAuth2Exception?,
        count:Int,
        isGras: Boolean,
        contacts: String?,
    ) {
        call.respondHtml {
            approveDevice(createContext(), client, scopes, claims, exception, count, isGras, contacts)
        }
    }

    override suspend fun PipelineContext<*, ApplicationCall>.contact() {
        call.respondHtml {
            contact(createContext())
        }
    }

    override suspend fun PipelineContext<*, ApplicationCall>.deviceApproved(
        client: OAuthClientDetails,
        isApproved: Boolean,
    ) {
        call.respondHtml {
            deviceApproved(createContext(), client, isApproved)
        }
    }

    @Deprecated("Avoid errors without any context")
    override suspend fun PipelineContext<*, ApplicationCall>.error() {
        call.respondHtml {
            error(createContext())
        }
    }

    override suspend fun PipelineContext<*, ApplicationCall>.error(error: OAuth2Exception) {
        call.respondHtml {
            error(createContext(), error)
        }
    }

    override suspend fun PipelineContext<*, ApplicationCall>.error(errorCode: ErrorCodes, errorMessage: String) {
        call.respondHtml {
            error(createContext(), errorCode, errorMessage)
        }
    }

    override suspend fun PipelineContext<*, ApplicationCall>.error(errorCodeString: String, errorMessage: String) {
        call.respondHtml {
            error(createContext(), errorCodeString, errorMessage)
        }
    }

    override suspend fun PipelineContext<*, ApplicationCall>.home() {
        call.respondHtml {
            home(createContext())
        }
    }

    override suspend fun PipelineContext<*, ApplicationCall>.login(
        loginHint: String?,
        paramError: String?,
    ) {
        call.respondHtml {
            login(createContext(), loginHint, paramError)
        }
    }

    override suspend fun PipelineContext<*, ApplicationCall>.logoutConfirmation(client: OAuthClientDetails?) {
        call.respondHtml {
            logoutConfirmation(createContext(), client)
        }
    }

    override suspend fun PipelineContext<*, ApplicationCall>.manage() {
        call.respondHtml {
            manage(createContext())
        }
    }

    override suspend fun PipelineContext<*, ApplicationCall>.postLogout() {
        call.respondHtml {
            postLogout(createContext())
        }

    }

    override suspend fun PipelineContext<*, ApplicationCall>.requestUserCode(error: String?) {
        call.respondHtml {
            requestUserCode(createContext(), error)
        }
    }

    override suspend fun PipelineContext<*, ApplicationCall>.stats(statsSummary: Map<String, String>) {
        call.respondHtml {
            stats(createContext(), statsSummary)
        }
    }

    private class DefaultWebContext(private val openIdContext: OpenIdContext, applicationCall: ApplicationCall) : WebContext {

        constructor(applicationCall: ApplicationCall) : this(applicationCall.openIdContext, applicationCall)

        override val csrf: WebContext.ICsrf = object : WebContext.ICsrf {
            override val parameterName: String get() = "SDFHLK_CSRF"

            /** CSRF_TOKEN */
            override val token: String get() = "DUMMY_TOKEN"
        }

        override val authentication: Authentication? = openIdContext.resolveAuthenticatedUser(applicationCall)

        override val userInfo: UserInfo? by lazy {
            authentication?.let { DefaultUserInfo(it.name) }
        }

        override val userAuthorities: String?
            get() = authentication?.authorities?.joinToString(separator = " ") { it.authority }

        override val lang: String by lazy {
            applicationCall.request.acceptLanguageItems()
                .firstOrNull { it.value in openIdContext.config.languageNamespaces }?.value
                ?: openIdContext.config.defaultLanguageNamespace
        }

        override val intl: Intl = object : Intl {

            override fun messageText(key: String, vararg args: Any?): String {
                val format = openIdContext.messageSource.resolveCode(key, Locale(lang))
                    ?: return key
                return format.format(args)
            }
        }

        override val config: ConfigurationPropertiesBean
            get() = TODO("not implemented")
        override val ui: UIConfiguration
            get() = TODO("not implemented")
    }
}
