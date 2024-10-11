package org.mitre.web

import io.ktor.server.application.*
import io.ktor.util.pipeline.*
import org.mitre.oauth2.exception.OAuth2Exception
import org.mitre.oauth2.exception.OAuthErrorCode
import org.mitre.oauth2.model.OAuthClientDetails
import org.mitre.oauth2.model.SystemScope
import org.mitre.oauth2.model.convert.OAuth2Request
import org.mitre.web.util.openIdContext

suspend fun PipelineContext<Unit, ApplicationCall>.htmlAboutView() {
    with(openIdContext.htmlViews) { about() }
}

suspend fun PipelineContext<Unit, ApplicationCall>.htmlApproveView(
    authRequest: OAuth2Request?,
    client: OAuthClientDetails,
    redirectUri: String?,
    scopes: Set<SystemScope>,
    claims:  Map<String?, Map<String, String>>,
    approvedSiteCount: Int,
    contacts: String? = null,
    isGras: Boolean,
    consent: Boolean = true,
    authenticationException: OAuth2Exception? = null,
) {
    with(openIdContext.htmlViews) {
        approve(
            authRequest, client, redirectUri, scopes, claims, approvedSiteCount,
            contacts, isGras, consent, authenticationException
        )
    }
}

suspend fun PipelineContext<Unit, ApplicationCall>.htmlApproveDeviceView(
    client: OAuthClientDetails,
    scopes: Set<SystemScope>,
    claims:  Map<String?, Map<String, String>> = emptyMap(),
    exception: OAuth2Exception? = null,
    count:Int = 0,
    gras: Boolean = false,
    contacts: String? = null,
) {
    with(openIdContext.htmlViews) { approveDevice(client, scopes, claims, exception, count, gras, contacts) }
}

suspend fun PipelineContext<Unit, ApplicationCall>.htmlContactView() {
    with(openIdContext.htmlViews) { contact() }
}

suspend fun PipelineContext<Unit, ApplicationCall>.htmlDeviceApprovedView(
    client: OAuthClientDetails,
    isApproved: Boolean,
) {
    with(openIdContext.htmlViews) { deviceApproved(client, isApproved) }
}

@Deprecated("Avoid errors without any context")
suspend fun PipelineContext<Unit, ApplicationCall>.htmlErrorView() {
    with(openIdContext.htmlViews) {
        @Suppress("DEPRECATION")
        error()
    }
}

suspend fun PipelineContext<Unit, ApplicationCall>.htmlErrorView(
        error: OAuth2Exception
) {
    with(openIdContext.htmlViews) { error(error) }
}

suspend fun PipelineContext<Unit, ApplicationCall>.htmlErrorView(
    errorCode: OAuthErrorCode,
    errorMessage: String,
) {
    with(openIdContext.htmlViews) { error(errorCode, errorMessage) }
}

suspend fun PipelineContext<Unit, ApplicationCall>.htmlErrorView(
        errorCodeString: String,
        errorMessage: String,
) {
    with(openIdContext.htmlViews) { error(errorCodeString, errorMessage) }
}

suspend fun PipelineContext<Unit, ApplicationCall>.htmlHomeView() {
    with(openIdContext.htmlViews) { home() }
}

suspend fun PipelineContext<Unit, ApplicationCall>.htmlLoginView(
    loginHint: String?,
    paramError: String?,
    redirectUri: String?,
) {
    with(openIdContext.htmlViews) { login(loginHint, paramError, redirectUri) }
}

suspend fun PipelineContext<Unit, ApplicationCall>.htmlLogoutConfirmationView(client: OAuthClientDetails?) {
    with(openIdContext.htmlViews) { logoutConfirmation(client) }
}

suspend fun PipelineContext<Unit, ApplicationCall>.htmlManageView() {
    with(openIdContext.htmlViews) { manage() }
}

suspend fun PipelineContext<Unit, ApplicationCall>.htmlPostLogoutView() {
    with(openIdContext.htmlViews) { postLogout() }
}

suspend fun PipelineContext<Unit, ApplicationCall>.htmlRequestUserCodeView(error: String? = null) {
    with(openIdContext.htmlViews) { requestUserCode(error) }
}

suspend fun PipelineContext<Unit, ApplicationCall>.htmlStatsView(statsSummary: Map<String, Int>) {
    with(openIdContext.htmlViews) { stats(statsSummary) }
}
