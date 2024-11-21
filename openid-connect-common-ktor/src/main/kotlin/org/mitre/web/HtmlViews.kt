package org.mitre.web

import io.ktor.http.*
import io.ktor.server.routing.*
import org.mitre.oauth2.exception.OAuth2Exception
import org.mitre.oauth2.exception.OAuthErrorCode
import org.mitre.oauth2.model.DeviceCode
import org.mitre.oauth2.model.OAuthClientDetails
import org.mitre.oauth2.model.SystemScope
import org.mitre.oauth2.model.request.AuthorizationRequest

interface HtmlViews {
    suspend fun RoutingContext.about()
    suspend fun RoutingContext.approve(
        authRequest: AuthorizationRequest?,
        client: OAuthClientDetails,
        redirectUri: String?,
        scopes: Set<SystemScope>,
        claims: Map<String?, Map<String, String>>,
        count: Int,
        isGras: Boolean,
        contacts: String? = null,
        consent: Boolean = true,
        authenticationException: OAuth2Exception? = null,
    )

    suspend fun RoutingContext.approveDevice(
        client: OAuthClientDetails,
        scopes: Set<SystemScope>,
        deviceCode: DeviceCode,
        claims: Map<String?, Map<String, String>>,
        exception: OAuth2Exception? = null,
        count: Int = 0,
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
        error: OAuth2Exception,
        statusCode: HttpStatusCode = HttpStatusCode.InternalServerError,
    )

    suspend fun RoutingContext.error(
        errorCode: OAuthErrorCode,
        errorMessage: String,
        statusCode: HttpStatusCode = errorCode.rawHttpCode?.let { HttpStatusCode.fromValue(it) } ?: HttpStatusCode.OK,
    )

    suspend fun RoutingContext.error(
        errorCodeString: String,
        errorMessage: String,
        statusCode: HttpStatusCode = HttpStatusCode.OK,
    )

    suspend fun RoutingContext.home()

    suspend fun RoutingContext.login(
        loginActionUrl: String,
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
