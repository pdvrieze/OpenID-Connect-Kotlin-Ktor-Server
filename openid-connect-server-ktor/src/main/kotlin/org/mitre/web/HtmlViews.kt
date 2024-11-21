package org.mitre.web

import io.ktor.http.*
import io.ktor.server.routing.*
import org.mitre.oauth2.exception.OAuth2Exception
import org.mitre.oauth2.exception.OAuthErrorCode
import org.mitre.oauth2.exception.httpCode
import org.mitre.oauth2.model.DeviceCode
import org.mitre.oauth2.model.OAuthClientDetails
import org.mitre.oauth2.model.SystemScope
import org.mitre.oauth2.model.request.AuthorizationRequest
import org.mitre.web.util.openIdContext

suspend fun RoutingContext.htmlAboutView() {
    with(openIdContext.htmlViews) { about() }
}

suspend fun RoutingContext.htmlApproveView(
    authRequest: AuthorizationRequest?,
    client: OAuthClientDetails,
    redirectUri: String?,
    scopes: Set<SystemScope>,
    claims: Map<String?, Map<String, String>>,
    approvedSiteCount: Int,
    isGras: Boolean,
    contacts: String? = null,
    consent: Boolean = true,
    authenticationException: OAuth2Exception? = null,
) {
    with(openIdContext.htmlViews) {
        approve(
            authRequest, client, redirectUri, scopes, claims, approvedSiteCount, isGras,
            contacts, consent, authenticationException,
        )
    }
}

suspend fun RoutingContext.htmlApproveDeviceView(
    client: OAuthClientDetails,
    scopes: Set<SystemScope>,
    deviceCode: DeviceCode,
    claims: Map<String?, Map<String, String>> = emptyMap(),
    exception: OAuth2Exception? = null,
    count: Int = 0,
    gras: Boolean = false,
    contacts: String? = null,
) {
    with(openIdContext.htmlViews) { approveDevice(client, scopes, deviceCode, claims, exception, count, gras, contacts) }
}

suspend fun RoutingContext.htmlContactView() {
    with(openIdContext.htmlViews) { contact() }
}

suspend fun RoutingContext.htmlDeviceApprovedView(
    client: OAuthClientDetails,
    isApproved: Boolean,
) {
    with(openIdContext.htmlViews) { deviceApproved(client, isApproved) }
}

@Deprecated("Avoid errors without any context")
suspend fun RoutingContext.htmlErrorView() {
    with(openIdContext.htmlViews) {
        @Suppress("DEPRECATION")
        error()
    }
}

suspend fun RoutingContext.htmlErrorView(
    error: OAuth2Exception,
    statusCode: HttpStatusCode = HttpStatusCode.InternalServerError
) {
    with(openIdContext.htmlViews) { error(error, statusCode) }
}

suspend fun RoutingContext.htmlErrorView(
    errorCode: OAuthErrorCode,
    errorMessage: String,
    statusCode: HttpStatusCode = errorCode.httpCode ?: HttpStatusCode.OK,
) {
    with(openIdContext.htmlViews) { error(errorCode, errorMessage, statusCode) }
}

suspend fun RoutingContext.htmlErrorView(
    errorCodeString: String,
    errorMessage: String,
    statusCode: HttpStatusCode = HttpStatusCode.OK,
) {
    with(openIdContext.htmlViews) { error(errorCodeString, errorMessage, statusCode) }
}

suspend fun RoutingContext.htmlHomeView() {
    with(openIdContext.htmlViews) { home() }
}

suspend fun RoutingContext.htmlLoginView(
    loginActionUrl: String,
    loginHint: String?,
    paramError: String?,
    redirectUri: String?,
    status: HttpStatusCode = HttpStatusCode.OK,
) {
    with(openIdContext.htmlViews) { login(loginActionUrl, loginHint, paramError, redirectUri, status,) }
}

suspend fun RoutingContext.htmlLogoutConfirmationView(client: OAuthClientDetails?) {
    with(openIdContext.htmlViews) { logoutConfirmation(client) }
}

suspend fun RoutingContext.htmlManageView() {
    with(openIdContext.htmlViews) { manage() }
}

suspend fun RoutingContext.htmlPostLogoutView() {
    with(openIdContext.htmlViews) { postLogout() }
}

suspend fun RoutingContext.htmlRequestUserCodeView(error: String? = null) {
    with(openIdContext.htmlViews) { requestUserCode(error) }
}

suspend fun RoutingContext.htmlStatsView(statsSummary: Map<String, Int>) {
    with(openIdContext.htmlViews) { stats(statsSummary) }
}
