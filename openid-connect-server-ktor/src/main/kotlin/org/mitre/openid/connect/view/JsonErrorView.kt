package org.mitre.openid.connect.view

import io.ktor.http.*
import io.ktor.server.routing.*
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import org.mitre.oauth2.exception.OAuthErrorCode
import org.mitre.oauth2.exception.httpCode
import org.mitre.oauth2.view.respondJson
import org.mitre.web.JsonErrorException

suspend fun RoutingContext.jsonErrorView(
    errorTitle: String,
    errorMessage: String ? = null,
    code: HttpStatusCode = HttpStatusCode.InternalServerError,
) = call.respondJson(
    buildJsonObject {
        put("error", errorTitle)
        if (errorMessage != null) put("error_description", errorMessage)
    },
    code
)

suspend fun RoutingContext.jsonErrorView(
    exception: JsonErrorException,
    code: HttpStatusCode = exception.httpStatus,
) = call.respondJson(
    buildJsonObject {
        put("error", exception.errorCode)
        val errorMessage = exception.errorMessage
        if (errorMessage != null) put("error_description", errorMessage)
    },
    code
)

suspend fun RoutingContext.jsonErrorView(
    errorCode: OAuthErrorCode,
    code: HttpStatusCode = errorCode.httpCode ?: HttpStatusCode.BadRequest,
    errorMessage: String? = null,
) = call.respondJson(
    OAuthError(errorCode, errorMessage),
    code
)

suspend fun RoutingContext.jsonErrorView(
    errorCode: OAuthErrorCode,
    errorMessage: String? = null,
) = jsonErrorView(errorCode, errorCode.httpCode ?: HttpStatusCode.BadRequest, errorMessage)

/**
 * @author aanganes, jricher
 */
object JsonErrorView {
    const val ERROR_MESSAGE: String = "errorMessage"
    const val ERROR: String = "error"
    const val VIEWNAME: String = "jsonErrorView"
}

@Serializable
data class OAuthError(
    @SerialName("error") val errorCode: String,
    @SerialName("error_description") val errorDescription: String? = null,
) {
    constructor(errorCode: OAuthErrorCode, errorDescription: String? = null) : this(errorCode.code, errorDescription)

    override fun toString(): String = buildString {
        append("OAuth error(").append(errorCode)
        if (errorDescription != null) append(": ").append(errorDescription)
        append(')')
    }
}
