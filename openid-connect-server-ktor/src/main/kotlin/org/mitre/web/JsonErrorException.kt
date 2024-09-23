package org.mitre.web

import io.ktor.http.*
import org.mitre.oauth2.exception.OAuthErrorCode
import org.mitre.oauth2.exception.httpCode

open class JsonErrorException private constructor (
    errorCode: String?,
    val errorMessage: String?,
    val oAuthErrorCode: OAuthErrorCode?,
    val httpStatus: HttpStatusCode,
) : Exception("${errorCode?:oAuthErrorCode?.code}: $errorMessage") {

    private val _errorCode = errorCode
    val errorCode: String = _errorCode ?: oAuthErrorCode?.code ?: "server_error"

    constructor(
        error: OAuthErrorCode,
        message: String?,
        httpStatus: HttpStatusCode = error.httpCode ?: HttpStatusCode.InternalServerError,
    ) : this(null, message, error, httpStatus)

    constructor(
        code: String,
        message: String?,
        httpStatus: HttpStatusCode = HttpStatusCode.InternalServerError,
    ) : this(null, message, null, httpStatus)

}

