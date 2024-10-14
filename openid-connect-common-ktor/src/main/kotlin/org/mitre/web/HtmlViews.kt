package org.mitre.web

import io.ktor.http.*
import io.ktor.server.routing.*
import org.mitre.oauth2.exception.OAuth2Exception
import org.mitre.oauth2.exception.OAuthErrorCode
import org.mitre.oauth2.model.OAuthClientDetails
import org.mitre.oauth2.model.SystemScope
import org.mitre.oauth2.model.convert.OAuth2Request

interface HtmlViews {
    suspend fun RoutingContext.about()
    suspend fun RoutingContext.approve(
        authRequest: OAuth2Request?,
        client: OAuthClientDetails,
        redirectUri: String?,
        scopes: Set<SystemScope>,
        claims:  Map<String?, Map<String, String>>,
        count: Int,
        contacts: String? = null,
        isGras: Boolean,
        consent: Boolean = true,
        authenticationException: OAuth2Exception? = null,
    )

    suspend fun RoutingContext.approveDevice(
        client: OAuthClientDetails,
        scopes: Set<SystemScope>,
        claims:  Map<String?, Map<String, String>>,
        exception: OAuth2Exception?,
        count:Int = 0,
        gras: Boolean = false,
        contacts: String? = null,
    )

    suspend fun RoutingContext.contact()

    suspend fun RoutingContext.deviceApproved(
        client: OAuthClientDetails,
        isApproved: Boolean,
    )

    @Deprecated("Avoid errors without any context")
    suspend fun RoutingContext.error()
    suspend fun RoutingContext.error(
        error: OAuth2Exception
    )

    suspend fun RoutingContext.error(
        errorCode: OAuthErrorCode,
        errorMessage: String,
    )

    suspend fun RoutingContext.error(
        errorCodeString: String,
        errorMessage: String,
    )

    suspend fun RoutingContext.home()

    suspend fun RoutingContext.login(
        loginHint: String?,
        paramError: String?,
        redirectUri: String?,
        status: HttpStatusCode = HttpStatusCode.OK,
    )

    suspend fun RoutingContext.logoutConfirmation(client: OAuthClientDetails?)
    suspend fun RoutingContext.manage()
    suspend fun RoutingContext.postLogout()
    suspend fun RoutingContext.requestUserCode(error: String? = null)
    suspend fun RoutingContext.stats(statsSummary: Map<String, Int>)
}
