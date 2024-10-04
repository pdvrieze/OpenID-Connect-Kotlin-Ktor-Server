package org.mitre.web

import io.ktor.server.application.*
import io.ktor.util.pipeline.*
import org.mitre.oauth2.exception.OAuth2Exception
import org.mitre.oauth2.exception.OAuthErrorCode
import org.mitre.oauth2.model.OAuthClientDetails
import org.mitre.oauth2.model.SystemScope
import org.mitre.oauth2.model.convert.OAuth2Request

interface HtmlViews {
    suspend fun PipelineContext<*, ApplicationCall>.about()
    suspend fun PipelineContext<*, ApplicationCall>.approve(
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

    suspend fun PipelineContext<*, ApplicationCall>.approveDevice(
        client: OAuthClientDetails,
        scopes: Set<SystemScope>,
        claims:  Map<String?, Map<String, String>>,
        exception: OAuth2Exception?,
        count:Int = 0,
        gras: Boolean = false,
        contacts: String? = null,
    )

    suspend fun PipelineContext<*, ApplicationCall>.contact()

    suspend fun PipelineContext<*, ApplicationCall>.deviceApproved(
        client: OAuthClientDetails,
        isApproved: Boolean,
    )

    @Deprecated("Avoid errors without any context")
    suspend fun PipelineContext<*, ApplicationCall>.error()
    suspend fun PipelineContext<*, ApplicationCall>.error(
        error: OAuth2Exception
    )

    suspend fun PipelineContext<*, ApplicationCall>.error(
        errorCode: OAuthErrorCode,
        errorMessage: String,
    )

    suspend fun PipelineContext<*, ApplicationCall>.error(
        errorCodeString: String,
        errorMessage: String,
    )

    suspend fun PipelineContext<*, ApplicationCall>.home()

    suspend fun PipelineContext<*, ApplicationCall>.login(
        loginHint: String?,
        paramError: String?,
    )

    suspend fun PipelineContext<*, ApplicationCall>.logoutConfirmation(client: OAuthClientDetails?)
    suspend fun PipelineContext<*, ApplicationCall>.manage()
    suspend fun PipelineContext<*, ApplicationCall>.postLogout()
    suspend fun PipelineContext<*, ApplicationCall>.requestUserCode(error: String? = null)
    suspend fun PipelineContext<*, ApplicationCall>.stats(statsSummary: Map<String, Int>)
}
